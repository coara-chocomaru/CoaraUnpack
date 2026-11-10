#include "compress.h"
#include "hash.h"

namespace cu {

namespace {

uint32_t g_bzcrc[256];
bool g_bzcrc_init = false;

void bzcrcInit() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i << 24;
        for (int k = 0; k < 8; k++) c = (c & 0x80000000u) ? (c << 1) ^ 0x04C11DB7u : (c << 1);
        g_bzcrc[i] = c;
    }
    g_bzcrc_init = true;
}

inline uint32_t bzcrcUpdate(uint32_t crc, uint8_t b) { return (crc << 8) ^ g_bzcrc[(crc >> 24) ^ b]; }

struct BitReader {
    const uint8_t* p;
    size_t n, pos = 0;
    uint64_t buf = 0;
    int cnt = 0;
    BitReader(const uint8_t* b, size_t len) : p(b), n(len) {}
    uint32_t get(int bits) {
        while (cnt < bits) {
            if (pos >= n) throw Error("bzip2のデータが途中で切れてるよ");
            buf = (buf << 8) | p[pos++];
            cnt += 8;
        }
        uint32_t r = (uint32_t)((buf >> (cnt - bits)) & ((1ull << bits) - 1));
        cnt -= bits;
        return r;
    }
    int bit() { return (int)get(1); }
    void alignByte() { cnt -= cnt % 8; }
    bool atEnd() const { return pos >= n && cnt < 8; }
};

}

void bzip2Decompress(View in, Sink& out) {
    if (!g_bzcrc_init) bzcrcInit();
    size_t base = 0;
    int streams = 0;
    while (base + 4 <= in.size() && in.p[base] == 'B' && in.p[base + 1] == 'Z' && in.p[base + 2] == 'h') {
        streams++;
        int level = in.p[base + 3] - '0';
        if (level < 1 || level > 9) throw Error("bzip2のヘッダが変だよ");
        size_t blockMax = (size_t)level * 100000;
        BitReader br(in.p + base + 4, in.size() - base - 4);
        std::vector<uint32_t> tt(blockMax);
        std::vector<uint8_t> blk(blockMax);
        uint32_t combined = 0;
        while (true) {
            uint32_t m1 = br.get(24), m2 = br.get(24);
            if (m1 == 0x177245 && m2 == 0x385090) {
                uint32_t stored = br.get(32);
                if (stored != combined) logf("! bzip2の全体CRCが合わなかったよ(続けるね)");
                br.alignByte();
                break;
            }
            if (m1 != 0x314159 || m2 != 0x265359) throw Error("bzip2のブロックが壊れてるよ");
            uint32_t blockCrc = br.get(32);
            if (br.bit()) throw Error("このbzip2(randomised)は未対応だよ");
            uint32_t origPtr = br.get(24);
            uint8_t used[256];
            int nUsed = 0;
            uint32_t ranges = br.get(16);
            for (int i = 0; i < 16; i++) {
                if (ranges & (0x8000u >> i)) {
                    uint32_t bits = br.get(16);
                    for (int j = 0; j < 16; j++)
                        if (bits & (0x8000u >> j)) used[nUsed++] = (uint8_t)(i * 16 + j);
                }
            }
            if (nUsed == 0) throw Error("bzip2のブロックが壊れてるよ");
            int alpha = nUsed + 2;
            int nGroups = (int)br.get(3);
            if (nGroups < 2 || nGroups > 6) throw Error("bzip2のブロックが壊れてるよ");
            int nSel = (int)br.get(15);
            if (nSel < 1) throw Error("bzip2のブロックが壊れてるよ");
            std::vector<uint8_t> sel(nSel);
            uint8_t mtfg[6] = {0, 1, 2, 3, 4, 5};
            for (int i = 0; i < nSel; i++) {
                int j = 0;
                while (br.bit()) {
                    j++;
                    if (j >= nGroups) throw Error("bzip2のブロックが壊れてるよ");
                }
                uint8_t v = mtfg[j];
                for (; j > 0; j--) mtfg[j] = mtfg[j - 1];
                mtfg[0] = v;
                sel[i] = v;
            }
            struct Tab { int limit[22], base[22], perm[258], minLen, maxLen; } tabs[6];
            for (int t = 0; t < nGroups; t++) {
                uint8_t len[258];
                int cur = (int)br.get(5);
                for (int i = 0; i < alpha; i++) {
                    while (true) {
                        if (cur < 1 || cur > 20) throw Error("bzip2のブロックが壊れてるよ");
                        if (!br.bit()) break;
                        if (br.bit()) cur--; else cur++;
                    }
                    len[i] = (uint8_t)cur;
                }
                Tab& T = tabs[t];
                int mn = 32, mx = 0;
                for (int i = 0; i < alpha; i++) { mn = std::min<int>(mn, len[i]); mx = std::max<int>(mx, len[i]); }
                T.minLen = mn; T.maxLen = mx;
                int pp = 0;
                for (int l = mn; l <= mx; l++)
                    for (int i = 0; i < alpha; i++)
                        if (len[i] == l) T.perm[pp++] = i;
                int cnt[23] = {0};
                for (int i = 0; i < alpha; i++) cnt[len[i]]++;
                int code = 0, idx = 0;
                for (int l = mn; l <= mx; l++) {
                    T.base[l] = idx - code;
                    code += cnt[l];
                    idx += cnt[l];
                    T.limit[l] = code - 1;
                    code <<= 1;
                }
            }

            int cntByte[256] = {0};
            uint8_t mtf[256];
            for (int i = 0; i < nUsed; i++) mtf[i] = used[i];
            size_t nblock = 0;
            int selIdx = 0, grpLeft = 0;
            Tab* T = nullptr;
            int runLen = 0, runBit = 1;
            int eob = nUsed + 1;
            while (true) {
                if (grpLeft == 0) {
                    if (selIdx >= nSel) throw Error("bzip2のブロックが壊れてるよ");
                    T = &tabs[sel[selIdx++]];
                    grpLeft = 50;
                }
                grpLeft--;
                int l = T->minLen;
                int code = (int)br.get(l);
                while (code > T->limit[l]) {
                    l++;
                    if (l > T->maxLen) throw Error("bzip2のブロックが壊れてるよ");
                    code = (code << 1) | br.bit();
                }
                int sym = T->perm[code + T->base[l]];
                if (sym <= 1) {
                    runLen += runBit << sym;
                    runBit <<= 1;
                    if (runLen > (int)blockMax * 2) throw Error("bzip2のブロックが壊れてるよ");
                    continue;
                }
                if (runLen) {
                    if (nblock + runLen > blockMax) throw Error("bzip2のブロックが壊れてるよ");
                    uint8_t b = mtf[0];
                    cntByte[b] += runLen;
                    memset(&blk[nblock], b, runLen);
                    nblock += runLen;
                    runLen = 0;
                    runBit = 1;
                }
                if (sym == eob) break;
                if (nblock >= blockMax) throw Error("bzip2のブロックが壊れてるよ");
                int k = sym - 1;
                uint8_t v = mtf[k];
                memmove(mtf + 1, mtf, k);
                mtf[0] = v;
                cntByte[v]++;
                blk[nblock++] = v;
            }
            if (origPtr >= nblock) throw Error("bzip2のブロックが壊れてるよ");

            int cum[256];
            int s = 0;
            for (int i = 0; i < 256; i++) { cum[i] = s; s += cntByte[i]; }
            for (size_t i = 0; i < nblock; i++) {
                uint8_t b = blk[i];
                tt[cum[b]++] = (uint32_t)i;
            }
            uint32_t tPos = tt[origPtr];

            uint32_t crc = 0xFFFFFFFFu;
            Bytes obuf;
            obuf.reserve(1 << 16);
            int last = -1, rep = 0;
            for (size_t i = 0; i < nblock; i++) {
                uint8_t b = blk[tPos];
                tPos = tt[tPos];
                if (rep == 4) {
                    for (int r = 0; r < b; r++) { obuf.push_back((uint8_t)last); crc = bzcrcUpdate(crc, (uint8_t)last); }
                    rep = 0;
                    last = -1;
                } else {
                    if (b == last) rep++;
                    else { rep = 1; last = b; }
                    obuf.push_back(b);
                    crc = bzcrcUpdate(crc, b);
                }
                if (obuf.size() >= (1 << 16)) {
                    out.write(obuf.data(), obuf.size());
                    obuf.clear();
                }
            }
            if (!obuf.empty()) out.write(obuf.data(), obuf.size());
            crc = ~crc;
            if (crc != blockCrc) throw Error("bzip2のブロックCRCが合わないよ");
            combined = ((combined << 1) | (combined >> 31)) ^ crc;
            checkCancel();
        }
        base += 4 + br.pos;

        while (base < in.size() && in.p[base] == 0) base++;
    }
    if (streams == 0) throw Error("bzip2じゃないみたい");
}

namespace {

struct BitWriter {
    Sink& s;
    uint64_t acc = 0;
    int cnt = 0;
    Bytes buf;
    explicit BitWriter(Sink& o) : s(o) {}
    void put(uint32_t v, int bits) {
        acc = (acc << bits) | (v & (bits == 32 ? 0xFFFFFFFFu : ((1u << bits) - 1)));
        cnt += bits;
        while (cnt >= 8) {
            buf.push_back((uint8_t)(acc >> (cnt - 8)));
            cnt -= 8;
        }
        if (buf.size() >= 65536) flush();
    }
    void flush() {
        if (!buf.empty()) { s.write(buf.data(), buf.size()); buf.clear(); }
    }
    void finish() {
        if (cnt) put(0, 8 - cnt);
        flush();
    }
};

void bwtCyclic(const uint8_t* t, int n, std::vector<int>& sa) {
    std::vector<int> rank(n), tmp(n), sa2(n);
    sa.resize(n);
    int K = std::max(n, 256) + 1;
    std::vector<int> cnt(K);
    for (int i = 0; i < n; i++) rank[i] = t[i];
    std::fill(cnt.begin(), cnt.end(), 0);
    for (int i = 0; i < n; i++) cnt[rank[i]]++;
    for (int i = 1; i < K; i++) cnt[i] += cnt[i - 1];
    for (int i = n - 1; i >= 0; i--) sa[--cnt[rank[i]]] = i;

    {
        int r = 0;
        tmp[sa[0]] = 0;
        for (int i = 1; i < n; i++) {
            if (t[sa[i]] != t[sa[i - 1]]) r++;
            tmp[sa[i]] = r;
        }
        rank = tmp;
        if (r == n - 1) return;
    }
    for (int k = 1; k < n; k <<= 1) {
        for (int j = 0; j < n; j++) {
            int v = sa[j] - k;
            if (v < 0) v += n;
            sa2[j] = v;
        }
        std::fill(cnt.begin(), cnt.end(), 0);
        for (int i = 0; i < n; i++) cnt[rank[i]]++;
        for (int i = 1; i < K; i++) cnt[i] += cnt[i - 1];
        for (int j = n - 1; j >= 0; j--) sa[--cnt[rank[sa2[j]]]] = sa2[j];
        int r = 0;
        tmp[sa[0]] = 0;
        for (int i = 1; i < n; i++) {
            int a = sa[i], b = sa[i - 1];
            int a2 = a + k >= n ? a + k - n : a + k;
            int b2 = b + k >= n ? b + k - n : b + k;
            if (rank[a] != rank[b] || rank[a2] != rank[b2]) r++;
            tmp[a] = r;
        }
        rank.swap(tmp);
        checkCancel();
        if (r == n - 1) break;
    }
}

void huffLengths(const uint32_t* freq, int n, uint8_t* len, int maxLen) {
    std::vector<uint32_t> w(n);
    for (int i = 0; i < n; i++) w[i] = freq[i] ? freq[i] : 1;
    while (true) {
        struct Node { uint64_t w; int l, r; };
        std::vector<Node> nodes;
        std::vector<int> heap;
        for (int i = 0; i < n; i++) { nodes.push_back({w[i], -1, -1}); }
        auto cmp = [&](int a, int b) { return nodes[a].w > nodes[b].w; };
        for (int i = 0; i < n; i++) heap.push_back(i);
        std::make_heap(heap.begin(), heap.end(), cmp);
        while (heap.size() > 1) {
            std::pop_heap(heap.begin(), heap.end(), cmp);
            int a = heap.back(); heap.pop_back();
            std::pop_heap(heap.begin(), heap.end(), cmp);
            int b = heap.back(); heap.pop_back();
            nodes.push_back({nodes[a].w + nodes[b].w, a, b});
            heap.push_back((int)nodes.size() - 1);
            std::push_heap(heap.begin(), heap.end(), cmp);
        }
        std::vector<int> depth(nodes.size(), 0);
        int root = heap[0];
        std::vector<int> stack = {root};
        int mx = 0;
        while (!stack.empty()) {
            int x = stack.back(); stack.pop_back();
            if (nodes[x].l < 0) { len[x] = (uint8_t)std::max(1, depth[x]); mx = std::max(mx, (int)len[x]); continue; }
            depth[nodes[x].l] = depth[x] + 1;
            depth[nodes[x].r] = depth[x] + 1;
            stack.push_back(nodes[x].l);
            stack.push_back(nodes[x].r);
        }
        if (mx <= maxLen) return;
        for (int i = 0; i < n; i++) w[i] = 1 + w[i] / 2;
    }
}

}

void bzip2Compress(View in, Sink& out) {
    if (!g_bzcrc_init) bzcrcInit();
    const int level = 9;
    const size_t blockMax = (size_t)level * 100000 - 19;
    BitWriter bw(out);
    bw.put('B', 8); bw.put('Z', 8); bw.put('h', 8); bw.put('0' + level, 8);
    const uint8_t* src = in.p;
    size_t n = in.size(), ip = 0;
    uint32_t combined = 0;
    std::vector<uint8_t> blk;
    blk.reserve(blockMax + 8);
    std::vector<int> sa;
    while (ip < n) {
        blk.clear();
        uint32_t crc = 0xFFFFFFFFu;

        while (ip < n && blk.size() + 5 <= blockMax) {
            uint8_t b = src[ip];
            size_t run = 1;
            while (ip + run < n && src[ip + run] == b && run < 255 + 4) run++;
            for (size_t i = 0; i < run; i++) crc = bzcrcUpdate(crc, b);
            if (run >= 4) {
                for (int i = 0; i < 4; i++) blk.push_back(b);
                blk.push_back((uint8_t)(run - 4));
            } else {
                for (size_t i = 0; i < run; i++) blk.push_back(b);
            }
            ip += run;
        }
        crc = ~crc;
        combined = ((combined << 1) | (combined >> 31)) ^ crc;
        int nb = (int)blk.size();
        bwtCyclic(blk.data(), nb, sa);
        int origPtr = 0;
        std::vector<uint8_t> last(nb);
        for (int j = 0; j < nb; j++) {
            if (sa[j] == 0) origPtr = j;
            last[j] = blk[sa[j] == 0 ? nb - 1 : sa[j] - 1];
        }
        bool inUse[256] = {false};
        for (int i = 0; i < nb; i++) inUse[blk[i]] = true;
        uint8_t map[256];
        int nUsed = 0;
        for (int i = 0; i < 256; i++) if (inUse[i]) map[i] = (uint8_t)nUsed++;
        int alpha = nUsed + 2, eob = nUsed + 1;

        std::vector<uint16_t> syms;
        syms.reserve(nb + 8);
        uint8_t mtf[256];
        for (int i = 0; i < nUsed; i++) mtf[i] = (uint8_t)i;
        uint32_t freq[258] = {0};
        int zrun = 0;
        auto flushRun = [&]() {
            if (!zrun) return;
            int r = zrun;
            while (r > 0) {
                r--;
                int bit = r & 1;
                syms.push_back((uint16_t)bit);
                freq[bit]++;
                r >>= 1;
            }
            zrun = 0;
        };
        for (int i = 0; i < nb; i++) {
            uint8_t v = map[last[i]];
            int k = 0;
            while (mtf[k] != v) k++;
            if (k == 0) { zrun++; continue; }
            flushRun();
            for (int j = k; j > 0; j--) mtf[j] = mtf[j - 1];
            mtf[0] = v;
            syms.push_back((uint16_t)(k + 1));
            freq[k + 1]++;
        }
        flushRun();
        syms.push_back((uint16_t)eob);
        freq[eob]++;
        const int nSyms = (int)syms.size();
        int nGroups = nSyms < 200 ? 2 : nSyms < 600 ? 3 : nSyms < 1200 ? 4 : nSyms < 2400 ? 5 : 6;
        const int nSel = (nSyms + 49) / 50;
        uint8_t len[6][258];
        {
            int gs = 0;
            uint32_t remF = (uint32_t)nSyms;
            for (int t = 0, left = nGroups; left > 0; t++, left--) {
                uint32_t tFreq = remF / (uint32_t)left;
                int ge = gs - 1;
                uint32_t aFreq = 0;
                while (aFreq < tFreq && ge < alpha - 1) aFreq += freq[++ge];
                if (ge > gs && left != nGroups && left != 1 && ((nGroups - left) & 1)) aFreq -= freq[ge--];
                for (int v = 0; v < alpha; v++) len[t][v] = (v >= gs && v <= ge) ? 0 : 15;
                gs = ge + 1;
                remF -= aFreq;
            }
        }
        std::vector<uint8_t> sel((size_t)nSel);
        for (int iter = 0; iter < 4; iter++) {
            uint32_t rfreq[6][258];
            memset(rfreq, 0, sizeof(rfreq));
            for (int g = 0; g < nSel; g++) {
                int lo = g * 50, hi = std::min(lo + 50, nSyms);
                uint32_t cost[6] = {0, 0, 0, 0, 0, 0};
                for (int i = lo; i < hi; i++)
                    for (int t = 0; t < nGroups; t++) cost[t] += len[t][syms[i]];
                int bt = 0;
                for (int t = 1; t < nGroups; t++) if (cost[t] < cost[bt]) bt = t;
                sel[g] = (uint8_t)bt;
                for (int i = lo; i < hi; i++) rfreq[bt][syms[i]]++;
            }
            for (int t = 0; t < nGroups; t++) huffLengths(rfreq[t], alpha, len[t], 17);
        }
        uint32_t code[6][258];
        for (int t = 0; t < nGroups; t++) {
            int mn = 32, mx = 0;
            for (int i = 0; i < alpha; i++) { mn = std::min<int>(mn, len[t][i]); mx = std::max<int>(mx, len[t][i]); }
            uint32_t vec = 0;
            for (int l = mn; l <= mx; l++) {
                for (int i = 0; i < alpha; i++) if (len[t][i] == l) code[t][i] = vec++;
                vec <<= 1;
            }
        }

        bw.put(0x314159, 24); bw.put(0x265359, 24);
        bw.put(crc, 32);
        bw.put(0, 1);
        bw.put((uint32_t)origPtr, 24);
        uint32_t ranges = 0;
        for (int i = 0; i < 16; i++) {
            bool any = false;
            for (int j = 0; j < 16; j++) if (inUse[i * 16 + j]) any = true;
            if (any) ranges |= 0x8000u >> i;
        }
        bw.put(ranges, 16);
        for (int i = 0; i < 16; i++) {
            if (!(ranges & (0x8000u >> i))) continue;
            uint32_t bits = 0;
            for (int j = 0; j < 16; j++) if (inUse[i * 16 + j]) bits |= 0x8000u >> j;
            bw.put(bits, 16);
        }
        bw.put((uint32_t)nGroups, 3);
        bw.put((uint32_t)nSel, 15);
        {
            uint8_t order[6] = {0, 1, 2, 3, 4, 5};
            for (int i = 0; i < nSel; i++) {
                uint8_t v = sel[i];
                int j = 0;
                while (order[j] != v) j++;
                for (int k = j; k > 0; k--) order[k] = order[k - 1];
                order[0] = v;
                for (int k = 0; k < j; k++) bw.put(1, 1);
                bw.put(0, 1);
            }
        }
        for (int t = 0; t < nGroups; t++) {
            int cur = len[t][0];
            bw.put((uint32_t)cur, 5);
            for (int i = 0; i < alpha; i++) {
                while (cur < len[t][i]) { bw.put(2, 2); cur++; }
                while (cur > len[t][i]) { bw.put(3, 2); cur--; }
                bw.put(0, 1);
            }
        }
        for (int i = 0; i < nSyms; i++) {
            int t = sel[i / 50];
            bw.put(code[t][syms[i]], len[t][syms[i]]);
        }
        subProgress((int)(ip * 100 / n));
        checkCancel();
    }
    bw.put(0x177245, 24); bw.put(0x385090, 24);
    bw.put(combined, 32);
    bw.finish();
}

}
