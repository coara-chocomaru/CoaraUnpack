#include "compress.h"
#include "hash.h"

namespace cu {

static const uint32_t LZ4_FRAME_MAGIC = 0x184D2204u;
static const uint32_t LZ4_LEGACY_MAGIC = 0x184C2102u;
static const size_t LZ4_LEGACY_BLOCK = 8u << 20;

size_t lz4CompressBound(size_t n) { return n + n / 255 + 16; }

void lz4BlockDecompress(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap, size_t& outLen) {

    size_t ip = 0, op = 0;
    while (true) {
        if (ip >= inLen) throw Error("LZ4のデータが途中で切れてるよ");
        uint8_t token = in[ip++];
        size_t lit = token >> 4;
        if (lit == 15) {
            uint8_t s;
            do {
                if (ip >= inLen) throw Error("LZ4のデータが途中で切れてるよ");
                s = in[ip++];
                lit += s;
            } while (s == 255);
        }
        if (lit > inLen - ip || lit > outCap - op) throw Error("LZ4のデータが壊れてるよ(literal)");
        memcpy(out + op, in + ip, lit);
        ip += lit;
        op += lit;
        if (ip >= inLen) break;
        if (ip + 2 > inLen) throw Error("LZ4のデータが途中で切れてるよ");
        size_t off = in[ip] | (in[ip + 1] << 8);
        ip += 2;
        if (off == 0) throw Error("LZ4のデータが壊れてるよ(offset)");
        size_t ml = token & 15;
        if (ml == 15) {
            uint8_t s;
            do {
                if (ip >= inLen) throw Error("LZ4のデータが途中で切れてるよ");
                s = in[ip++];
                ml += s;
            } while (s == 255);
        }
        ml += 4;
        if (ml > outCap - op) throw Error("LZ4のデータが壊れてるよ(長さ)");
        const uint8_t* src = out + op - off;
        if (off > op) throw Error("LZ4のデータが壊れてるよ(距離)");
        uint8_t* dst = out + op;
        if (off >= ml) {
            memcpy(dst, src, ml);
        } else {
            for (size_t i = 0; i < ml; i++) dst[i] = src[i];
        }
        op += ml;
    }
    outLen = op;
}

namespace {

struct Lz4Enc {
    const uint8_t* in;
    size_t n;
    uint8_t* out;
    size_t cap;
    size_t op = 0;
    std::vector<uint32_t> head;
    std::vector<uint32_t> chain;
    int maxDepth;

    Lz4Enc(const uint8_t* i, size_t len, uint8_t* o, size_t c)
        : in(i), n(len), out(o), cap(c), maxDepth(len <= ((size_t)24 << 20) ? 1024 : 320) {
        head.assign(1 << 16, 0xFFFFFFFFu);
        chain.assign(1 << 16, 0);
    }
    static uint32_t h4(const uint8_t* p) { return (rd32(p) * 2654435761u) >> 16; }
    void ins(size_t p) {
        uint32_t h = h4(in + p);
        chain[p & 0xFFFF] = head[h];
        head[h] = (uint32_t)p;
    }
    bool find(size_t p, size_t limit, uint32_t& len, uint32_t& off) {
        len = 0;
        off = 0;
        uint32_t cand = head[h4(in + p)];
        int depth = maxDepth;
        while (cand != 0xFFFFFFFFu && depth--) {
            if (cand >= p) break;
            size_t d = p - cand;
            if (d > 65535) break;
            if (in[cand + len] == in[p + len]) {
                size_t l = 0;
                size_t maxl = limit - p;
                while (l < maxl && in[cand + l] == in[p + l]) l++;
                if (l >= 4 && l > len) {
                    len = (uint32_t)l;
                    off = (uint32_t)d;
                    if (l >= 512 || l == maxl) break;
                }
            }
            uint32_t nx = chain[cand & 0xFFFF];
            if (nx >= cand) break;
            cand = nx;
        }
        return len >= 4;
    }
    void put(uint8_t b) {
        if (op >= cap) throw Error("LZ4の出力バッファが足りないよ");
        out[op++] = b;
    }
    void emit(size_t anchor, size_t lit, bool hasMatch, uint32_t ml, uint32_t off) {
        size_t tokpos = op;
        put(0);
        uint8_t tok = 0;
        if (lit >= 15) {
            tok = 15 << 4;
            size_t r = lit - 15;
            while (r >= 255) { put(255); r -= 255; }
            put((uint8_t)r);
        } else {
            tok = (uint8_t)(lit << 4);
        }
        if (op + lit > cap) throw Error("LZ4の出力バッファが足りないよ");
        memcpy(out + op, in + anchor, lit);
        op += lit;
        if (hasMatch) {
            put((uint8_t)off);
            put((uint8_t)(off >> 8));
            size_t m = ml - 4;
            if (m >= 15) {
                tok |= 15;
                m -= 15;
                while (m >= 255) { put(255); m -= 255; }
                put((uint8_t)m);
            } else {
                tok |= (uint8_t)m;
            }
        }
        out[tokpos] = tok;
    }
    size_t run() {
        const size_t MFLIMIT = 12, LASTLIT = 5, W = 4096, SUFF = 256;
        const uint32_t INF = 0xFFFFFFFFu;
        size_t anchor = 0, p = 0;
        if (n >= MFLIMIT + 1) {
            size_t matchLimit = n - LASTLIT;
            size_t startLimit = n - MFLIMIT;
            size_t inserted = 0;
            std::vector<uint32_t> cost(W + 1), ll(W + 1), offAt(W + 1);
            std::vector<uint32_t> pm(W + 1);
            while (p < startLimit) {
                size_t wn = std::min(W, startLimit - p);
                std::fill(cost.begin(), cost.begin() + wn + 1, INF);
                cost[0] = 0;
                ll[0] = (uint32_t)(p - anchor);
                pm[0] = 0;
                size_t i = 0;
                while (i < wn) {
                    if (cost[i] == INF) {
                        i++;
                        continue;
                    }
                    size_t pos = p + i;
                    while (inserted < pos) { ins(inserted); inserted++; }
                    uint32_t l1 = ll[i] + 1;
                    uint32_t cc = cost[i] + 1 + ((l1 >= 15 && (l1 - 15) % 255 == 0) ? 1 : 0);
                    if (cc < cost[i + 1]) {
                        cost[i + 1] = cc;
                        pm[i + 1] = 0;
                        ll[i + 1] = l1;
                    }
                    uint32_t len, off;
                    size_t step = 1;
                    if (find(pos, matchLimit, len, off)) {
                        size_t lmax = std::min<size_t>(len, wn - i);
                        offAt[i] = off;
                        for (size_t L = 4; L <= lmax; L++) {
                            uint32_t m = (uint32_t)(L - 4);
                            uint32_t c2 = cost[i] + 3 + (m >= 15 ? 1 + (m - 15) / 255 : 0);
                            if (c2 < cost[i + L]) {
                                cost[i + L] = c2;
                                pm[i + L] = (uint32_t)L;
                                ll[i + L] = 0;
                            }
                        }
                        if (lmax >= SUFF) step = lmax;
                    }
                    i += step;
                    if ((pos & 0xFFFFF) < step) checkCancel();
                }
                std::vector<uint32_t> ends;
                size_t j = wn;
                while (j > 0) {
                    if (pm[j] == 0) {
                        j--;
                    } else {
                        ends.push_back((uint32_t)j);
                        j -= pm[j];
                    }
                }
                for (size_t k = ends.size(); k-- > 0;) {
                    size_t e = ends[k];
                    size_t L = pm[e];
                    size_t st = e - L;
                    emit(anchor, p + st - anchor, true, (uint32_t)L, offAt[st]);
                    anchor = p + e;
                }
                p += wn;
            }
        }
        emit(anchor, n - anchor, false, 0, 0);
        return op;
    }
};

}

size_t lz4BlockCompress(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) {
    Lz4Enc e(in, inLen, out, outCap);
    return e.run();
}

static void legacyDecode(View in, Sink& out) {
    const uint8_t* b = in.p;
    size_t n = in.size();
    size_t pos = 0;
    std::unique_ptr<uint8_t[]> obuf(new uint8_t[LZ4_LEGACY_BLOCK + 64]);
    size_t maxComp = lz4CompressBound(LZ4_LEGACY_BLOCK);
    while (pos + 4 <= n) {
        uint32_t v = rd32(b + pos);
        pos += 4;
        if (v == LZ4_LEGACY_MAGIC) continue;
        if (v > maxComp) break;
        if (v > n - pos) throw Error("LZ4(legacy)が途中で切れてるよ");
        size_t olen = 0;
        lz4BlockDecompress(b + pos, v, obuf.get(), LZ4_LEGACY_BLOCK, olen);
        out.write(obuf.get(), olen);
        pos += v;
        checkCancel();
    }
}

static void frameDecode(View in, Sink& out) {
    const uint8_t* b = in.p;
    size_t n = in.size();
    size_t pos = 0;
    while (pos + 4 <= n) {
        uint32_t magic = rd32(b + pos);
        if ((magic & 0xFFFFFFF0u) == 0x184D2A50u) {
            if (pos + 8 > n) throw Error("LZ4が途中で切れてるよ");
            pos += 8 + rd32(b + pos + 4);
            continue;
        }
        if (magic != LZ4_FRAME_MAGIC) break;
        pos += 4;
        if (pos + 2 > n) throw Error("LZ4が途中で切れてるよ");
        uint8_t flg = b[pos], bd = b[pos + 1];
        if ((flg >> 6) != 1) throw Error("LZ4フレームのバージョンが未対応だよ");
        bool indep = flg & 0x20, bchk = flg & 0x10, hasSize = flg & 0x08, cchk = flg & 0x04, hasDict = flg & 0x01;
        size_t hlen = 2 + (hasSize ? 8 : 0) + (hasDict ? 4 : 0);
        if (pos + hlen + 1 > n) throw Error("LZ4が途中で切れてるよ");
        int bsz = (bd >> 4) & 7;
        if (bsz < 4) throw Error("LZ4フレームのブロックサイズが変だよ");
        size_t maxBlock = (size_t)1 << (8 + 2 * bsz);
        pos += hlen + 1;
        std::unique_ptr<uint8_t[]> win(new uint8_t[maxBlock + 65536 + 64]);
        size_t hist = 0;
        Bytes whole;
        (void)whole;
        while (true) {
            if (pos + 4 > n) throw Error("LZ4が途中で切れてるよ");
            uint32_t bs = rd32(b + pos);
            pos += 4;
            if (bs == 0) break;
            bool raw = bs & 0x80000000u;
            bs &= 0x7FFFFFFFu;
            if (bs > n - pos) throw Error("LZ4が途中で切れてるよ");
            size_t olen;
            uint8_t* dst = win.get() + hist;
            if (raw) {
                if (bs > maxBlock) throw Error("LZ4のブロックが大きすぎるよ");
                memcpy(dst, b + pos, bs);
                olen = bs;
            } else {

                size_t ip = 0, op = 0;
                const uint8_t* src = b + pos;
                while (true) {
                    if (ip >= bs) throw Error("LZ4のデータが途中で切れてるよ");
                    uint8_t token = src[ip++];
                    size_t lit = token >> 4;
                    if (lit == 15) {
                        uint8_t s;
                        do {
                            if (ip >= bs) throw Error("LZ4のデータが途中で切れてるよ");
                            s = src[ip++];
                            lit += s;
                        } while (s == 255);
                    }
                    if (lit > bs - ip || lit > maxBlock - op) throw Error("LZ4のデータが壊れてるよ");
                    memcpy(dst + op, src + ip, lit);
                    ip += lit;
                    op += lit;
                    if (ip >= bs) break;
                    if (ip + 2 > bs) throw Error("LZ4のデータが途中で切れてるよ");
                    size_t off = src[ip] | (src[ip + 1] << 8);
                    ip += 2;
                    if (off == 0 || off > op + hist) throw Error("LZ4のデータが壊れてるよ(offset)");
                    size_t ml = token & 15;
                    if (ml == 15) {
                        uint8_t s;
                        do {
                            if (ip >= bs) throw Error("LZ4のデータが途中で切れてるよ");
                            s = src[ip++];
                            ml += s;
                        } while (s == 255);
                    }
                    ml += 4;
                    if (ml > maxBlock - op) throw Error("LZ4のデータが壊れてるよ(長さ)");
                    const uint8_t* mp = dst + op - off;
                    for (size_t i = 0; i < ml; i++) dst[op + i] = mp[i];
                    op += ml;
                }
                olen = op;
            }
            pos += bs;
            if (bchk) pos += 4;
            out.write(dst, olen);
            if (!indep) {
                size_t total = hist + olen;
                if (total > 65536) {
                    memmove(win.get(), win.get() + total - 65536, 65536);
                    hist = 65536;
                } else {
                    hist = total;
                }
            } else {
                hist = 0;
            }
            checkCancel();
        }
        if (cchk) pos += 4;
    }
}

void lz4Decompress(Fmt f, View in, Sink& out) {
    if (f == F_LZ4) frameDecode(in, out);
    else legacyDecode(in, out);
}

void lz4Compress(Fmt f, View in, Sink& out) {
    const uint8_t* b = in.p;
    size_t n = in.size();
    if (f == F_LZ4) {
        uint8_t hdr[7];
        wr32(hdr, LZ4_FRAME_MAGIC);
        hdr[4] = 0x64;
        hdr[5] = 0x70;
        out.write(hdr, 6);
        uint8_t desc[2] = {0x64, 0x70};
        uint8_t hc = (uint8_t)((xxh32(desc, 2) >> 8) & 0xFF);
        out.write(&hc, 1);
        const size_t BS = 4u << 20;
        std::unique_ptr<uint8_t[]> tmp(new uint8_t[lz4CompressBound(BS)]);
        for (size_t off = 0; off < n; off += BS) {
            size_t c = std::min(BS, n - off);
            size_t cl = lz4BlockCompress(b + off, c, tmp.get(), lz4CompressBound(BS));
            uint8_t sz[4];
            if (cl >= c) {
                wr32(sz, (uint32_t)c | 0x80000000u);
                out.write(sz, 4);
                out.write(b + off, c);
            } else {
                wr32(sz, (uint32_t)cl);
                out.write(sz, 4);
                out.write(tmp.get(), cl);
            }
            subProgress((int)((off + c) * 100 / n));
        }
        uint8_t z[4] = {0, 0, 0, 0};
        out.write(z, 4);
        uint8_t cs[4];
        wr32(cs, xxh32(b, n));
        out.write(cs, 4);
        return;
    }
    uint8_t m[4];
    wr32(m, LZ4_LEGACY_MAGIC);
    out.write(m, 4);
    std::unique_ptr<uint8_t[]> tmp(new uint8_t[lz4CompressBound(LZ4_LEGACY_BLOCK)]);
    for (size_t off = 0; off < n; off += LZ4_LEGACY_BLOCK) {
        size_t c = std::min(LZ4_LEGACY_BLOCK, n - off);
        size_t cl = lz4BlockCompress(b + off, c, tmp.get(), lz4CompressBound(LZ4_LEGACY_BLOCK));
        uint8_t sz[4];
        wr32(sz, (uint32_t)cl);
        out.write(sz, 4);
        out.write(tmp.get(), cl);
        subProgress((int)((off + c) * 100 / n));
        checkCancel();
    }
    if (f == F_LZ4_LG) {
        uint8_t t[4];
        wr32(t, (uint32_t)n);
        out.write(t, 4);
    }
}

}
