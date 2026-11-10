#include "compress.h"
#include "hash.h"
#include <cmath>
#include <algorithm>

namespace cu {

namespace {

const int kWindow = 32768;
const int kMaxMatch = 258;
const int kMinMatch = 3;

const uint16_t kLenBase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const uint8_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const uint16_t kDistBase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
const uint8_t kClOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

struct Tables {
    uint8_t lenSym[kMaxMatch + 1];
    Tables() {
        for (int s = 0; s < 29; s++) {
            int lo = kLenBase[s];
            int hi = s == 28 ? 258 : kLenBase[s + 1] - 1;
            for (int l = lo; l <= hi; l++) lenSym[l] = (uint8_t)s;
        }
        lenSym[258] = 28;
    }
};

const Tables& tables() {
    static Tables t;
    return t;
}

inline int distSym(int d) {
    if (d <= 4) return d - 1;
    int nb = 31 - __builtin_clz((unsigned)(d - 1));
    return (nb << 1) | (((d - 1) >> (nb - 1)) & 1);
}

struct BitOut {
    Bytes buf;
    uint64_t acc = 0;
    int cnt = 0;
    void put(uint32_t v, int bits) {
        acc |= (uint64_t)v << cnt;
        cnt += bits;
        while (cnt >= 8) {
            buf.push_back((uint8_t)acc);
            acc >>= 8;
            cnt -= 8;
        }
    }
    void align() {
        if (cnt > 0) {
            buf.push_back((uint8_t)acc);
            acc = 0;
            cnt = 0;
        }
    }
    uint64_t bitSize() const { return (uint64_t)buf.size() * 8 + (uint64_t)cnt; }
};

uint32_t revBits(uint32_t v, int n) {
    uint32_t r = 0;
    for (int i = 0; i < n; i++) {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    return r;
}

void limitedLengths(const uint32_t* freq, int n, int maxLen, uint8_t* len) {
    struct Node { uint64_t w; int l, r; };
    std::vector<Node> nodes;
    std::vector<int> heap;
    for (int i = 0; i < n; i++) len[i] = 0;
    for (int i = 0; i < n; i++) {
        if (freq[i]) {
            nodes.push_back({freq[i], -1, -(i + 2)});
            heap.push_back((int)nodes.size() - 1);
        }
    }
    if (heap.empty()) return;
    if (heap.size() == 1) {
        len[-(nodes[0].r) - 2] = 1;
        return;
    }
    auto cmp = [&](int a, int b) { return nodes[a].w > nodes[b].w || (nodes[a].w == nodes[b].w && a > b); };
    std::make_heap(heap.begin(), heap.end(), cmp);
    while (heap.size() > 1) {
        std::pop_heap(heap.begin(), heap.end(), cmp);
        int a = heap.back();
        heap.pop_back();
        std::pop_heap(heap.begin(), heap.end(), cmp);
        int b = heap.back();
        heap.pop_back();
        nodes.push_back({nodes[a].w + nodes[b].w, a, b});
        heap.push_back((int)nodes.size() - 1);
        std::push_heap(heap.begin(), heap.end(), cmp);
    }
    std::vector<std::pair<int, int>> st;
    st.push_back({heap[0], 0});
    std::vector<int> leafLen(n, 0);
    while (!st.empty()) {
        auto cur = st.back();
        st.pop_back();
        const Node& nd = nodes[cur.first];
        if (nd.l < 0) {
            leafLen[-(nd.r) - 2] = std::max(1, cur.second);
            continue;
        }
        st.push_back({nd.l, cur.second + 1});
        st.push_back({nd.r, cur.second + 1});
    }
    for (int i = 0; i < n; i++) len[i] = (uint8_t)std::min(leafLen[i], 255);
    bool over = false;
    for (int i = 0; i < n; i++) if (len[i] > maxLen) over = true;
    if (!over) return;
    for (int i = 0; i < n; i++) if (len[i] > maxLen) len[i] = (uint8_t)maxLen;
    auto kraft = [&]() {
        uint64_t k = 0;
        for (int i = 0; i < n; i++) if (len[i]) k += (uint64_t)1 << (maxLen - len[i]);
        return k;
    };
    uint64_t limit = (uint64_t)1 << maxLen;
    while (kraft() > limit) {
        int pick = -1;
        for (int i = 0; i < n; i++) {
            if (len[i] && len[i] < maxLen) {
                if (pick < 0 || len[i] > len[pick] || (len[i] == len[pick] && freq[i] < freq[pick])) pick = i;
            }
        }
        if (pick < 0) break;
        len[pick]++;
    }
    for (;;) {
        bool changed = false;
        std::vector<int> order;
        for (int i = 0; i < n; i++) if (len[i] > 1) order.push_back(i);
        std::sort(order.begin(), order.end(), [&](int a, int b) { return freq[a] > freq[b]; });
        for (int i : order) {
            uint64_t k = kraft();
            uint64_t gain = (uint64_t)1 << (maxLen - len[i]);
            if (k + gain <= limit) {
                len[i]--;
                changed = true;
            }
        }
        if (!changed) break;
    }
}

void makeCodes(const uint8_t* len, int n, uint16_t* code) {
    uint32_t blCount[16] = {0};
    for (int i = 0; i < n; i++) blCount[len[i]]++;
    blCount[0] = 0;
    uint32_t next[16];
    uint32_t c = 0;
    for (int b = 1; b <= 15; b++) {
        c = (c + blCount[b - 1]) << 1;
        next[b] = c;
    }
    for (int i = 0; i < n; i++) {
        if (len[i]) code[i] = (uint16_t)revBits(next[len[i]]++, len[i]);
        else code[i] = 0;
    }
}

struct Token {
    uint16_t len;
    uint16_t dist;
};

struct Rle {
    std::vector<uint8_t> sym;
    std::vector<uint8_t> extra;
};

void rleLengths(const uint8_t* lens, int total, bool use16, bool use17, Rle& r) {
    r.sym.clear();
    r.extra.clear();
    int i = 0;
    while (i < total) {
        int v = lens[i];
        int run = 1;
        while (i + run < total && lens[i + run] == v) run++;
        int left = run;
        if (v == 0 && use17) {
            while (left >= 11) {
                int c = std::min(left, 138);
                r.sym.push_back(18);
                r.extra.push_back((uint8_t)(c - 11));
                left -= c;
            }
            if (left >= 3) {
                r.sym.push_back(17);
                r.extra.push_back((uint8_t)(left - 3));
                left = 0;
            }
        }
        if (v != 0 && use16 && left >= 4) {
            r.sym.push_back((uint8_t)v);
            r.extra.push_back(0);
            left--;
            while (left >= 3) {
                int c = std::min(left, 6);
                r.sym.push_back(16);
                r.extra.push_back((uint8_t)(c - 3));
                left -= c;
            }
        }
        while (left > 0) {
            r.sym.push_back((uint8_t)v);
            r.extra.push_back(0);
            left--;
        }
        i += run;
    }
}

struct BlockPlan {
    uint8_t litLen[288];
    uint8_t distLen[30];
    uint16_t litCode[288];
    uint16_t distCode[30];
    Rle rle;
    uint8_t clLen[19];
    uint16_t clCode[19];
    int hlit = 257, hdist = 1, hclen = 4;
    uint64_t headerBits = 0;
    uint64_t dataBits = 0;
};

uint64_t dataCost(const BlockPlan& bp, const uint32_t* litFreq, const uint32_t* distFreq) {
    uint64_t bits = 0;
    for (int i = 0; i < 286; i++) {
        if (!litFreq[i]) continue;
        bits += (uint64_t)litFreq[i] * bp.litLen[i];
        if (i >= 257) bits += (uint64_t)litFreq[i] * kLenExtra[i - 257];
    }
    for (int i = 0; i < 30; i++) {
        if (!distFreq[i]) continue;
        bits += (uint64_t)distFreq[i] * (bp.distLen[i] + kDistExtra[i]);
    }
    return bits;
}

void planDynamic(const uint32_t* litFreq, const uint32_t* distFreq, BlockPlan& bp) {
    limitedLengths(litFreq, 286, 15, bp.litLen);
    for (int i = 286; i < 288; i++) bp.litLen[i] = 0;
    uint32_t df[30];
    for (int i = 0; i < 30; i++) df[i] = distFreq[i];
    int used = 0;
    for (int i = 0; i < 30; i++) if (df[i]) used++;
    if (used == 0) df[0] = 1;
    if (used == 1) {
        for (int i = 0; i < 30; i++) {
            if (df[i]) {
                df[i == 0 ? 1 : 0] = 1;
                break;
            }
        }
    }
    limitedLengths(df, 30, 15, bp.distLen);
    makeCodes(bp.litLen, 288, bp.litCode);
    makeCodes(bp.distLen, 30, bp.distCode);
    int hlit = 286;
    while (hlit > 257 && bp.litLen[hlit - 1] == 0) hlit--;
    int hdist = 30;
    while (hdist > 1 && bp.distLen[hdist - 1] == 0) hdist--;
    uint8_t all[320];
    for (int i = 0; i < hlit; i++) all[i] = bp.litLen[i];
    for (int i = 0; i < hdist; i++) all[hlit + i] = bp.distLen[i];
    uint64_t bestBits = ~(uint64_t)0;
    for (int variant = 0; variant < 4; variant++) {
        Rle r;
        rleLengths(all, hlit + hdist, variant & 1, variant & 2, r);
        uint32_t cf[19] = {0};
        for (uint8_t s : r.sym) cf[s]++;
        uint8_t cl[19];
        limitedLengths(cf, 19, 7, cl);
        int hclen = 19;
        while (hclen > 4 && cl[kClOrder[hclen - 1]] == 0) hclen--;
        uint64_t bits = 14 + (uint64_t)hclen * 3;
        for (size_t k = 0; k < r.sym.size(); k++) {
            bits += cl[r.sym[k]];
            if (r.sym[k] == 16) bits += 2;
            else if (r.sym[k] == 17) bits += 3;
            else if (r.sym[k] == 18) bits += 7;
        }
        if (bits < bestBits) {
            bestBits = bits;
            bp.rle = r;
            memcpy(bp.clLen, cl, 19);
            bp.hclen = hclen;
        }
    }
    bp.hlit = hlit;
    bp.hdist = hdist;
    makeCodes(bp.clLen, 19, bp.clCode);
    bp.headerBits = bestBits;
    bp.dataBits = dataCost(bp, litFreq, distFreq);
}

uint64_t fixedCost(const uint32_t* litFreq, const uint32_t* distFreq) {
    uint64_t bits = 0;
    for (int i = 0; i < 286; i++) {
        if (!litFreq[i]) continue;
        int l = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
        bits += (uint64_t)litFreq[i] * l;
        if (i >= 257) bits += (uint64_t)litFreq[i] * kLenExtra[i - 257];
    }
    for (int i = 0; i < 30; i++) bits += (uint64_t)distFreq[i] * (5 + kDistExtra[i]);
    return bits;
}

class OptDeflate {
public:
    OptDeflate(const uint8_t* d, size_t n) : d_(d), n_(n) {
        head_.assign((size_t)1 << 17, kNone);
        prev_.assign(kWindow, kNone);
        depth_ = n <= ((size_t)16 << 20) ? 512 : 96;
        iters_ = n <= ((size_t)4 << 20) ? 5 : (n <= ((size_t)16 << 20) ? 4 : 2);
        blockSize_ = 1 << 17;
    }

    void run(BitOut& bo, Sink& sink) {
        size_t pos = 0;
        if (n_ == 0) {
            bo.put(1, 1);
            bo.put(1, 2);
            bo.put(0, 7);
            flushTo(bo, sink, true);
            return;
        }
        while (pos < n_) {
            size_t end = std::min(n_, pos + blockSize_);
            bool last = end == n_;
            block(pos, end, last, bo);
            flushTo(bo, sink, false);
            pos = end;
            subProgress((int)(pos * 100 / n_));
            checkCancel();
        }
        flushTo(bo, sink, true);
    }

private:
    static constexpr uint32_t kNone = 0xFFFFFFFFu;
    const uint8_t* d_;
    size_t n_;
    std::vector<uint32_t> head_, prev_;
    int depth_, iters_;
    size_t blockSize_;
    size_t inserted_ = 0;
    std::vector<uint32_t> mOff_;
    std::vector<uint16_t> mLen_, mDist_;
    std::vector<float> cost_;
    std::vector<uint32_t> from_;
    std::vector<Token> tokens_, bestTokens_;
    float litCost_[286], distCost_[30], lenCost_[kMaxMatch + 1];

    void flushTo(BitOut& bo, Sink& sink, bool fin) {
        if (fin) bo.align();
        if (!bo.buf.empty() && (fin || bo.buf.size() >= (1u << 16))) {
            sink.write(bo.buf.data(), bo.buf.size());
            bo.buf.clear();
        }
    }

    uint32_t hash3(size_t p) const {
        uint32_t v = d_[p] | (d_[p + 1] << 8) | ((uint32_t)d_[p + 2] << 16);
        return (v * 2654435761u) >> 15;
    }
    void insertUpTo(size_t p) {
        while (inserted_ < p) {
            if (inserted_ + 3 <= n_) {
                uint32_t h = hash3(inserted_);
                prev_[inserted_ & (kWindow - 1)] = head_[h];
                head_[h] = (uint32_t)inserted_;
            }
            inserted_++;
        }
    }

    void findAll(size_t p, size_t maxLen, std::vector<uint16_t>& L, std::vector<uint16_t>& D) {
        if (maxLen < kMinMatch || p + 3 > n_) return;
        uint32_t cand = head_[hash3(p)];
        while (cand != kNone && cand >= p) {
            uint32_t nx = prev_[cand & (kWindow - 1)];
            if (nx >= cand) { cand = kNone; break; }
            cand = nx;
        }
        size_t lim = p > (size_t)kWindow ? p - kWindow : 0;
        size_t best = kMinMatch - 1;
        int depth = depth_;
        size_t count = 0;
        while (cand != kNone && cand >= lim && cand < p && depth-- > 0) {
            if (d_[cand + best] == d_[p + best]) {
                size_t l = 0;
                while (l < maxLen && d_[cand + l] == d_[p + l]) l++;
                if (l > best) {
                    if (count < 48) {
                        L.push_back((uint16_t)l);
                        D.push_back((uint16_t)(p - cand));
                        count++;
                    } else {
                        L.back() = (uint16_t)l;
                        D.back() = (uint16_t)(p - cand);
                    }
                    best = l;
                    if (l >= maxLen) break;
                }
            }
            uint32_t nx = prev_[cand & (kWindow - 1)];
            if (nx >= cand) break;
            cand = nx;
        }
    }

    void setCostsFrom(const uint32_t* lf, const uint32_t* df) {
        uint64_t lt = 0, dt = 0;
        for (int i = 0; i < 286; i++) lt += lf[i];
        for (int i = 0; i < 30; i++) dt += df[i];
        if (!lt) lt = 1;
        if (!dt) dt = 1;
        for (int i = 0; i < 286; i++) litCost_[i] = lf[i] ? (float)std::log2((double)lt / lf[i]) : (float)std::log2((double)lt) + 2.0f;
        for (int i = 0; i < 30; i++) distCost_[i] = df[i] ? (float)std::log2((double)dt / df[i]) : (float)std::log2((double)dt) + 2.0f;
        const Tables& t = tables();
        for (int l = kMinMatch; l <= kMaxMatch; l++) {
            int s = t.lenSym[l];
            lenCost_[l] = litCost_[257 + s] + kLenExtra[s];
        }
    }

    void parse(size_t bs, size_t be) {
        size_t m = be - bs;
        cost_.assign(m + 1, 1e30f);
        from_.assign(m + 1, 0);
        cost_[0] = 0;
        for (size_t i = 0; i < m; i++) {
            float c0 = cost_[i];
            size_t p = bs + i;
            float lc = c0 + litCost_[d_[p]];
            if (lc < cost_[i + 1]) {
                cost_[i + 1] = lc;
                from_[i + 1] = 1;
            }
            uint32_t a = mOff_[i], b = mOff_[i + 1];
            uint32_t prevLen = kMinMatch - 1;
            size_t room = m - i;
            for (uint32_t k = a; k < b; k++) {
                uint32_t ml = mLen_[k];
                uint32_t md = mDist_[k];
                float dc = distCost_[distSym((int)md)] + kDistExtra[distSym((int)md)];
                size_t lim = std::min<size_t>(ml, room);
                if (ml >= (uint32_t)kMaxMatch && k + 1 == b) {
                    size_t L = lim;
                    if (L >= (size_t)kMinMatch) {
                        float c = c0 + lenCost_[L] + dc;
                        if (c < cost_[i + L]) {
                            cost_[i + L] = c;
                            from_[i + L] = (uint32_t)L | ((uint32_t)md << 9);
                        }
                    }
                    for (size_t L2 = std::max<size_t>(prevLen + 1, kMinMatch); L2 < L && L2 <= prevLen + 8; L2++) {
                        float c = c0 + lenCost_[L2] + dc;
                        if (c < cost_[i + L2]) {
                            cost_[i + L2] = c;
                            from_[i + L2] = (uint32_t)L2 | ((uint32_t)md << 9);
                        }
                    }
                } else {
                    for (size_t L = std::max<size_t>(prevLen + 1, kMinMatch); L <= lim; L++) {
                        float c = c0 + lenCost_[L] + dc;
                        if (c < cost_[i + L]) {
                            cost_[i + L] = c;
                            from_[i + L] = (uint32_t)L | ((uint32_t)md << 9);
                        }
                    }
                }
                prevLen = ml;
            }
        }
        tokens_.clear();
        size_t j = m;
        while (j > 0) {
            uint32_t f = from_[j];
            Token t;
            if (f == 1) {
                t.len = 1;
                t.dist = 0;
                j -= 1;
            } else {
                t.len = (uint16_t)(f & 511);
                t.dist = (uint16_t)(f >> 9);
                j -= t.len;
            }
            tokens_.push_back(t);
        }
        std::reverse(tokens_.begin(), tokens_.end());
    }

    void count(size_t bs, uint32_t* lf, uint32_t* df) const {
        memset(lf, 0, 286 * sizeof(uint32_t));
        memset(df, 0, 30 * sizeof(uint32_t));
        const Tables& t = tables();
        size_t p = bs;
        for (const Token& tk : tokens_) {
            if (tk.len == 1) {
                lf[d_[p]]++;
                p++;
            } else {
                lf[257 + t.lenSym[tk.len]]++;
                df[distSym(tk.dist)]++;
                p += tk.len;
            }
        }
        lf[256]++;
    }

    void block(size_t bs, size_t be, bool last, BitOut& bo) {
        size_t m = be - bs;
        insertUpTo(bs);
        mOff_.assign(m + 1, 0);
        mLen_.clear();
        mDist_.clear();
        for (size_t i = 0; i < m; i++) {
            size_t p = bs + i;
            insertUpTo(p);
            mOff_[i] = (uint32_t)mLen_.size();
            findAll(p, std::min<size_t>(kMaxMatch, n_ - p), mLen_, mDist_);
            if ((i & 0xFFFF) == 0xFFFF) checkCancel();
        }
        mOff_[m] = (uint32_t)mLen_.size();

        uint32_t lf[286], df[30];
        {
            uint32_t lf0[286], df0[30];
            memset(lf0, 0, sizeof(lf0));
            memset(df0, 0, sizeof(df0));
            const Tables& t = tables();
            size_t i = 0;
            while (i < m) {
                uint32_t a = mOff_[i], b = mOff_[i + 1];
                if (b > a) {
                    uint32_t ml = std::min<size_t>(mLen_[b - 1], m - i);
                    if (ml >= kMinMatch) {
                        lf0[257 + t.lenSym[ml]]++;
                        df0[distSym(mDist_[b - 1])]++;
                        i += ml;
                        continue;
                    }
                }
                lf0[d_[bs + i]]++;
                i++;
            }
            lf0[256] = 1;
            for (int k = 0; k < 286; k++) lf0[k] += 1;
            for (int k = 0; k < 30; k++) df0[k] += 1;
            setCostsFrom(lf0, df0);
        }
        uint64_t bestBits = ~(uint64_t)0;
        BlockPlan bestPlan;
        uint32_t bestLf[286], bestDf[30];
        for (int it = 0; it < iters_; it++) {
            parse(bs, be);
            count(bs, lf, df);
            BlockPlan bp;
            planDynamic(lf, df, bp);
            uint64_t bits = bp.headerBits + bp.dataBits;
            if (bits < bestBits) {
                bestBits = bits;
                bestTokens_ = tokens_;
                bestPlan = bp;
                memcpy(bestLf, lf, sizeof(lf));
                memcpy(bestDf, df, sizeof(df));
            }
            uint32_t lf2[286], df2[30];
            for (int k = 0; k < 286; k++) lf2[k] = lf[k];
            for (int k = 0; k < 30; k++) df2[k] = df[k];
            setCostsFrom(lf2, df2);
            checkCancel();
        }
        uint64_t fixedBits = fixedCost(bestLf, bestDf);
        uint64_t storedBits = (uint64_t)m * 8 + (uint64_t)((m + 65534) / 65535) * 40;
        uint64_t dynBits = bestBits + 3;
        uint64_t fixBits = fixedBits + 3;
        if (storedBits <= dynBits && storedBits <= fixBits) {
            size_t off = bs;
            while (off < be) {
                size_t c = std::min<size_t>(65535, be - off);
                bool lastChunk = last && off + c == be;
                bo.put(lastChunk ? 1 : 0, 1);
                bo.put(0, 2);
                bo.align();
                bo.put((uint32_t)c, 16);
                bo.put((uint32_t)(~c & 0xFFFF), 16);
                for (size_t k = 0; k < c; k++) bo.put(d_[off + k], 8);
                off += c;
            }
            return;
        }
        const Tables& t = tables();
        if (fixBits <= dynBits) {
            uint8_t ll[288], dl[30];
            for (int i = 0; i < 144; i++) ll[i] = 8;
            for (int i = 144; i < 256; i++) ll[i] = 9;
            for (int i = 256; i < 280; i++) ll[i] = 7;
            for (int i = 280; i < 288; i++) ll[i] = 8;
            for (int i = 0; i < 30; i++) dl[i] = 5;
            uint16_t lc[288], dc[30];
            makeCodes(ll, 288, lc);
            makeCodes(dl, 30, dc);
            bo.put(last ? 1 : 0, 1);
            bo.put(1, 2);
            emitTokens(bs, bestTokens_, ll, lc, dl, dc, bo, t);
            return;
        }
        bo.put(last ? 1 : 0, 1);
        bo.put(2, 2);
        bo.put((uint32_t)(bestPlan.hlit - 257), 5);
        bo.put((uint32_t)(bestPlan.hdist - 1), 5);
        bo.put((uint32_t)(bestPlan.hclen - 4), 4);
        for (int i = 0; i < bestPlan.hclen; i++) bo.put(bestPlan.clLen[kClOrder[i]], 3);
        for (size_t k = 0; k < bestPlan.rle.sym.size(); k++) {
            uint8_t s = bestPlan.rle.sym[k];
            bo.put(bestPlan.clCode[s], bestPlan.clLen[s]);
            if (s == 16) bo.put(bestPlan.rle.extra[k], 2);
            else if (s == 17) bo.put(bestPlan.rle.extra[k], 3);
            else if (s == 18) bo.put(bestPlan.rle.extra[k], 7);
        }
        emitTokens(bs, bestTokens_, bestPlan.litLen, bestPlan.litCode, bestPlan.distLen, bestPlan.distCode, bo, t);
    }

    void emitTokens(size_t bs, const std::vector<Token>& toks, const uint8_t* ll, const uint16_t* lc, const uint8_t* dl,
                    const uint16_t* dc, BitOut& bo, const Tables& t) {
        size_t p = bs;
        for (const Token& tk : toks) {
            if (tk.len == 1) {
                bo.put(lc[d_[p]], ll[d_[p]]);
                p++;
            } else {
                int s = t.lenSym[tk.len];
                bo.put(lc[257 + s], ll[257 + s]);
                if (kLenExtra[s]) bo.put((uint32_t)(tk.len - kLenBase[s]), kLenExtra[s]);
                int ds = distSym(tk.dist);
                bo.put(dc[ds], dl[ds]);
                if (kDistExtra[ds]) bo.put((uint32_t)(tk.dist - kDistBase[ds]), kDistExtra[ds]);
                p += tk.len;
            }
        }
        bo.put(lc[256], ll[256]);
    }
};

}

bool gzipCompressOpt(View in, Sink& out) {
    VecSink body;
    {
        BitOut bo;
        OptDeflate enc(in.p, in.size());
        enc.run(bo, body);
    }
    uint8_t hdr[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3};
    out.write(hdr, 10);
    out.write(body.v.data(), body.v.size());
    uint8_t tr[8];
    wr32(tr, crc32(in.p, in.size()));
    wr32(tr + 4, (uint32_t)in.size());
    out.write(tr, 8);
    return true;
}

}
