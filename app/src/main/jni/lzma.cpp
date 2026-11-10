#include "compress.h"
#include "hash.h"
#include <cmath>

namespace cu {

namespace {

const int kNumStates = 12;
const int kPosStatesMax = 16;
const uint32_t kTop = 1u << 24;

struct LenProbs {
    uint16_t choice, choice2;
    uint16_t low[kPosStatesMax][8];
    uint16_t mid[kPosStatesMax][8];
    uint16_t high[256];
    void init() {
        choice = choice2 = 1024;
        for (auto& a : low) for (auto& b : a) b = 1024;
        for (auto& a : mid) for (auto& b : a) b = 1024;
        for (auto& b : high) b = 1024;
    }
};

struct Probs {
    uint16_t isMatch[kNumStates][kPosStatesMax];
    uint16_t isRep[kNumStates];
    uint16_t isRepG0[kNumStates];
    uint16_t isRepG1[kNumStates];
    uint16_t isRepG2[kNumStates];
    uint16_t isRep0Long[kNumStates][kPosStatesMax];
    uint16_t posSlot[4][64];
    uint16_t posSpecial[115];
    uint16_t align[16];
    LenProbs matchLen, repLen;
    std::vector<uint16_t> lit;
    void init(int lc, int lp) {
        for (auto& a : isMatch) for (auto& b : a) b = 1024;
        for (auto& b : isRep) b = 1024;
        for (auto& b : isRepG0) b = 1024;
        for (auto& b : isRepG1) b = 1024;
        for (auto& b : isRepG2) b = 1024;
        for (auto& a : isRep0Long) for (auto& b : a) b = 1024;
        for (auto& a : posSlot) for (auto& b : a) b = 1024;
        for (auto& b : posSpecial) b = 1024;
        for (auto& b : align) b = 1024;
        matchLen.init();
        repLen.init();
        lit.assign((size_t)0x300 << (lc + lp), 1024);
    }
};

struct RangeDec {
    const uint8_t* p = nullptr;
    const uint8_t* end = nullptr;
    uint32_t range = 0, code = 0;
    void init(const uint8_t* b, size_t n) {
        p = b;
        end = b + n;
        if (n < 5 || b[0] != 0) throw Error("LZMAのデータが壊れてるよ");
        code = rd32be(b + 1);
        range = 0xFFFFFFFFu;
        p += 5;
    }
    inline void norm() {
        if (range < kTop) {
            if (p >= end) throw Error("LZMAのデータが途中で切れてるよ");
            range <<= 8;
            code = (code << 8) | *p++;
        }
    }
    inline int bit(uint16_t& pr) {
        norm();
        uint32_t bound = (range >> 11) * pr;
        if (code < bound) {
            range = bound;
            pr += (2048 - pr) >> 5;
            return 0;
        }
        range -= bound;
        code -= bound;
        pr -= pr >> 5;
        return 1;
    }
    inline uint32_t direct(int n) {
        uint32_t r = 0;
        while (n--) {
            norm();
            range >>= 1;
            uint32_t t = 0 - (code >= range ? 1u : 0u);
            if (t) code -= range;
            r = (r << 1) | (t & 1);
        }
        return r;
    }
    inline uint32_t tree(uint16_t* pr, int bits) {
        uint32_t m = 1;
        for (int i = 0; i < bits; i++) m = (m << 1) | bit(pr[m]);
        return m - (1u << bits);
    }
    inline uint32_t rtree(uint16_t* pr, int bits) {
        uint32_t m = 1, r = 0;
        for (int i = 0; i < bits; i++) {
            int b = bit(pr[m]);
            m = (m << 1) | b;
            r |= (uint32_t)b << i;
        }
        return r;
    }
};

class LzmaDec {
public:
    LzmaDec(uint32_t dictSize, Sink& sink) : sink_(sink) {
        if (dictSize < 4096) dictSize = 4096;
        dsz_ = dictSize;
        dict_.reset(new uint8_t[dsz_]);
    }
    void setProps(int lc, int lp, int pb) {
        lc_ = lc; lp_ = lp; pb_ = pb;
        probs_.init(lc, lp);
        resetState();
    }
    void resetState() {
        probs_.init(lc_, lp_);
        state_ = 0;
        rep0_ = rep1_ = rep2_ = rep3_ = 0;
    }
    void dictReset() {
        flush();
        dpos_ = 0;
        flushed_ = 0;
        full_ = 0;
        processed_ = 0;
    }
    void flush() {
        if (dpos_ > flushed_) {
            sink_.write(dict_.get() + flushed_, dpos_ - flushed_);
            flushed_ = dpos_;
        }
    }
    void putByte(uint8_t b) {
        dict_[dpos_++] = b;
        processed_++;
        if (full_ < dsz_) full_++;
        if (dpos_ == dsz_) {
            flush();
            dpos_ = 0;
            flushed_ = 0;
        }
    }
    uint8_t getByte(uint32_t dist) const {
        size_t i = dpos_ >= dist ? dpos_ - dist : dpos_ + dsz_ - dist;
        return dict_[i];
    }
    void uncompressed(const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; i++) putByte(p[i]);
    }

    bool decode(const uint8_t* in, size_t inLen, uint64_t outLen, bool unknownSize) {
        RangeDec rc;
        rc.init(in, inLen);
        uint64_t remaining = outLen;
        uint32_t pbMask = (1u << pb_) - 1, lpMask = (1u << lp_) - 1;
        uint32_t st = state_;
        uint32_t r0 = rep0_, r1 = rep1_, r2 = rep2_, r3 = rep3_;
        bool eos = false;
        while (unknownSize || remaining > 0) {
            uint32_t posState = (uint32_t)processed_ & pbMask;
            if (!rc.bit(probs_.isMatch[st][posState])) {
                uint8_t prev = full_ ? getByte(1) : 0;
                uint32_t ls = (((uint32_t)processed_ & lpMask) << lc_) + (prev >> (8 - lc_));
                uint16_t* pr = &probs_.lit[(size_t)0x300 * ls];
                uint32_t sym = 1;
                if (st >= 7) {
                    if (full_ < r0 + 1u) throw Error("LZMAのデータが壊れてるよ(距離)");
                    uint32_t mb = getByte(r0 + 1);
                    uint32_t offs = 0x100;
                    do {
                        mb <<= 1;
                        uint32_t mbit = mb & offs;
                        int b = rc.bit(pr[offs + mbit + sym]);
                        sym = (sym << 1) | b;
                        if (b) offs &= mbit; else offs &= ~mbit;
                    } while (sym < 0x100);
                } else {
                    do { sym = (sym << 1) | rc.bit(pr[sym]); } while (sym < 0x100);
                }
                putByte((uint8_t)sym);
                st = st < 4 ? 0 : (st < 10 ? st - 3 : st - 6);
                if (remaining) remaining--;
                continue;
            }
            uint32_t len;
            if (rc.bit(probs_.isRep[st])) {
                if (full_ == 0) throw Error("LZMAのデータが壊れてるよ(rep)");
                if (!rc.bit(probs_.isRepG0[st])) {
                    if (!rc.bit(probs_.isRep0Long[st][posState])) {
                        if (full_ < r0 + 1u) throw Error("LZMAのデータが壊れてるよ(距離)");
                        st = st < 7 ? 9 : 11;
                        putByte(getByte(r0 + 1));
                        if (remaining) remaining--;
                        continue;
                    }
                } else {
                    uint32_t d;
                    if (!rc.bit(probs_.isRepG1[st])) {
                        d = r1;
                    } else {
                        if (!rc.bit(probs_.isRepG2[st])) {
                            d = r2;
                        } else {
                            d = r3;
                            r3 = r2;
                        }
                        r2 = r1;
                    }
                    r1 = r0;
                    r0 = d;
                }
                len = decLen(rc, probs_.repLen, posState);
                st = st < 7 ? 8 : 11;
            } else {
                r3 = r2; r2 = r1; r1 = r0;
                len = decLen(rc, probs_.matchLen, posState);
                st = st < 7 ? 7 : 10;
                uint32_t ls = len < 4 ? len : 3;
                uint32_t slot = rc.tree(probs_.posSlot[ls], 6);
                if (slot < 4) {
                    r0 = slot;
                } else {
                    int fb = (int)(slot >> 1) - 1;
                    uint32_t base = (2 | (slot & 1)) << fb;
                    if (slot < 14) {
                        r0 = base + rc.rtree(probs_.posSpecial + base - slot - 1, fb);
                    } else {
                        uint32_t hi = rc.direct(fb - 4) << 4;
                        r0 = base + hi + rc.rtree(probs_.align, 4);
                    }
                }
                if (r0 == 0xFFFFFFFFu) {
                    eos = true;
                    break;
                }
            }
            len += 2;
            if (full_ < r0 + 1u) throw Error("LZMAのデータが壊れてるよ(距離)");
            if (!unknownSize && len > remaining) throw Error("LZMAのデータが壊れてるよ(長さ)");
            for (uint32_t i = 0; i < len; i++) putByte(getByte(r0 + 1));
            if (remaining) remaining = remaining >= len ? remaining - len : 0;
        }
        state_ = st; rep0_ = r0; rep1_ = r1; rep2_ = r2; rep3_ = r3;
        return eos;
    }
    uint64_t processed() const { return processed_; }
private:
    uint32_t decLen(RangeDec& rc, LenProbs& lp, uint32_t posState) {
        if (!rc.bit(lp.choice)) return rc.tree(lp.low[posState], 3);
        if (!rc.bit(lp.choice2)) return 8 + rc.tree(lp.mid[posState], 3);
        return 16 + rc.tree(lp.high, 8);
    }
    Sink& sink_;
    std::unique_ptr<uint8_t[]> dict_;
    size_t dsz_ = 0, dpos_ = 0, flushed_ = 0, full_ = 0;
    uint64_t processed_ = 0;
    Probs probs_;
    int lc_ = 3, lp_ = 0, pb_ = 2;
    uint32_t state_ = 0, rep0_ = 0, rep1_ = 0, rep2_ = 0, rep3_ = 0;
};

void parseLcLpPb(uint8_t d, int& lc, int& lp, int& pb) {
    if (d >= 9 * 5 * 5) throw Error("LZMAのpropsが変だよ");
    lc = d % 9;
    d /= 9;
    lp = d % 5;
    pb = d / 5;
}

size_t lzma2Decode(const uint8_t* in, size_t inLen, uint32_t dictSize, Sink& out, uint64_t* outTotal) {
    LzmaDec dec(dictSize, out);
    size_t pos = 0;
    bool needDict = true, needProps = true;
    int lc = 3, lp = 0, pb = 2;
    while (true) {
        if (pos >= inLen) throw Error("LZMA2のデータが途中で切れてるよ");
        uint8_t ctl = in[pos++];
        if (ctl == 0) break;
        if (ctl < 0x80) {
            if (ctl > 2) throw Error("LZMA2のデータが壊れてるよ");
            if (pos + 2 > inLen) throw Error("LZMA2のデータが途中で切れてるよ");
            size_t sz = (((size_t)in[pos] << 8) | in[pos + 1]) + 1;
            pos += 2;
            if (ctl == 1) {
                dec.dictReset();
                needDict = false;
            } else if (needDict) {
                throw Error("LZMA2のデータが壊れてるよ(dict)");
            }
            if (pos + sz > inLen) throw Error("LZMA2のデータが途中で切れてるよ");
            dec.uncompressed(in + pos, sz);
            pos += sz;
            continue;
        }
        if (pos + 4 > inLen) throw Error("LZMA2のデータが途中で切れてるよ");
        size_t usz = ((((size_t)ctl & 0x1F) << 16) | ((size_t)in[pos] << 8) | in[pos + 1]) + 1;
        size_t csz = (((size_t)in[pos + 2] << 8) | in[pos + 3]) + 1;
        pos += 4;
        int mode = (ctl >> 5) & 3;
        if (mode == 3) {
            dec.dictReset();
            needDict = false;
        } else if (needDict) {
            throw Error("LZMA2のデータが壊れてるよ(dict)");
        }
        if (mode >= 2) {
            if (pos >= inLen) throw Error("LZMA2のデータが途中で切れてるよ");
            parseLcLpPb(in[pos++], lc, lp, pb);
            if (lc + lp > 4) throw Error("LZMA2のpropsが変だよ");
            dec.setProps(lc, lp, pb);
            needProps = false;
        } else if (needProps) {
            throw Error("LZMA2のデータが壊れてるよ(props)");
        } else if (mode == 1) {
            dec.resetState();
        }
        if (pos + csz > inLen) throw Error("LZMA2のデータが途中で切れてるよ");
        dec.decode(in + pos, csz, usz, false);
        pos += csz;
        checkCancel();
    }
    dec.flush();
    if (outTotal) *outTotal = dec.processed();
    return pos;
}

inline bool x86Msb(uint8_t b) { return b == 0x00 || b == 0xFF; }

void bcjX86(uint8_t* buf, size_t size) {
    static const bool allowed[8] = {true, true, true, false, true, false, false, false};
    static const uint8_t bitnum[8] = {0, 1, 2, 2, 3, 3, 3, 3};
    if (size <= 4) return;
    size_t prev_pos = (size_t)-1;
    uint32_t prev_mask = 0;
    size_t i;
    size_t lim = size - 4;
    for (i = 0; i < lim; i++) {
        if ((buf[i] & 0xFE) != 0xE8) continue;
        prev_pos = i - prev_pos;
        if (prev_pos > 3) {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << (prev_pos - 1)) & 7;
            if (prev_mask != 0) {
                uint8_t b = buf[i + 4 - bitnum[prev_mask]];
                if (!allowed[prev_mask] || x86Msb(b)) {
                    prev_pos = i;
                    prev_mask = (prev_mask << 1) | 1;
                    continue;
                }
            }
        }
        prev_pos = i;
        if (x86Msb(buf[i + 4])) {
            uint32_t src = rd32(buf + i + 1), dest;
            while (true) {
                dest = src - (uint32_t)(i + 5);
                if (prev_mask == 0) break;
                uint32_t j = bitnum[prev_mask] * 8u;
                uint8_t b = (uint8_t)(dest >> (24 - j));
                if (!x86Msb(b)) break;
                src = dest ^ ((1u << (32 - j)) - 1);
            }
            dest &= 0x01FFFFFF;
            dest |= 0u - (dest & 0x01000000);
            wr32(buf + i + 1, dest);
            i += 4;
        } else {
            prev_mask = (prev_mask << 1) | 1;
        }
    }
}

void bcjArm(uint8_t* buf, size_t size) {
    for (size_t i = 0; i + 4 <= size; i += 4) {
        if (buf[i + 3] == 0xEB) {
            uint32_t src = ((uint32_t)buf[i + 2] << 16) | ((uint32_t)buf[i + 1] << 8) | buf[i];
            src <<= 2;
            uint32_t dest = src - (uint32_t)(i + 8);
            dest >>= 2;
            buf[i + 2] = dest >> 16;
            buf[i + 1] = dest >> 8;
            buf[i] = dest;
        }
    }
}

void bcjArmThumb(uint8_t* buf, size_t size) {
    for (size_t i = 0; i + 4 <= size; i += 2) {
        if ((buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8) {
            uint32_t src = (((uint32_t)buf[i + 1] & 7) << 19) | ((uint32_t)buf[i] << 11) |
                           (((uint32_t)buf[i + 3] & 7) << 8) | buf[i + 2];
            src <<= 1;
            uint32_t dest = src - (uint32_t)(i + 4);
            dest >>= 1;
            buf[i + 1] = 0xF0 | ((dest >> 19) & 7);
            buf[i] = dest >> 11;
            buf[i + 3] = 0xF8 | ((dest >> 8) & 7);
            buf[i + 2] = dest;
            i += 2;
        }
    }
}

void bcjArm64(uint8_t* buf, size_t size) {
    for (size_t i = 0; i + 4 <= size; i += 4) {
        uint32_t instr = rd32(buf + i);
        if ((instr >> 26) == 0x25) {
            uint32_t src = instr;
            uint32_t pc = (uint32_t)i >> 2;
            uint32_t dest = src - pc;
            instr = 0x94000000u | (dest & 0x03FFFFFFu);
            wr32(buf + i, instr);
        } else if ((instr & 0x9F000000u) == 0x90000000u) {
            uint32_t src = ((instr >> 29) & 3) | ((instr >> 3) & 0x1FFFFC);
            if ((src + 0x20000) & 0x1C0000) continue;
            uint32_t pc = (uint32_t)i >> 12;
            uint32_t dest = src - pc;
            instr &= 0x9000001Fu;
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x03FFFC) << 3;
            instr |= (0u - (dest & 0x020000)) & 0xE00000;
            wr32(buf + i, instr);
        }
    }
}

void bcjPpc(uint8_t* buf, size_t size) {
    for (size_t i = 0; i + 4 <= size; i += 4) {
        if ((buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1) {
            uint32_t src = (((uint32_t)buf[i] & 3) << 24) | ((uint32_t)buf[i + 1] << 16) |
                           ((uint32_t)buf[i + 2] << 8) | ((uint32_t)buf[i + 3] & ~3u);
            uint32_t dest = src - (uint32_t)i;
            buf[i] = 0x48 | ((dest >> 24) & 3);
            buf[i + 1] = dest >> 16;
            buf[i + 2] = dest >> 8;
            buf[i + 3] &= 3;
            buf[i + 3] |= dest;
        }
    }
}

void bcjSparc(uint8_t* buf, size_t size) {
    for (size_t i = 0; i + 4 <= size; i += 4) {
        if ((buf[i] == 0x40 && (buf[i + 1] & 0xC0) == 0x00) || (buf[i] == 0x7F && (buf[i + 1] & 0xC0) == 0xC0)) {
            uint32_t src = rd32be(buf + i);
            src <<= 2;
            uint32_t dest = src - (uint32_t)i;
            dest >>= 2;
            dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3FFFFFFF) | (dest & 0x3FFFFF) | 0x40000000;
            wr32be(buf + i, dest);
        }
    }
}

void deltaDec(uint8_t* buf, size_t size, size_t dist) {
    for (size_t i = dist; i < size; i++) buf[i] = (uint8_t)(buf[i] + buf[i - dist]);
}

bool readVli(const uint8_t* p, size_t n, size_t& pos, uint64_t& v) {
    v = 0;
    for (int i = 0; i < 9; i++) {
        if (pos >= n) return false;
        uint8_t b = p[pos++];
        v |= (uint64_t)(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) return true;
    }
    return false;
}

}

void lzmaDecompressAlone(View in, Sink& out) {
    if (in.size() < 13) throw Error("LZMAが短すぎるよ");
    int lc, lp, pb;
    parseLcLpPb(in.p[0], lc, lp, pb);
    uint32_t dict = rd32(in.p + 1);
    uint64_t usize = rd64(in.p + 5);
    bool unknown = usize == ~(uint64_t)0;
    if (!unknown && usize < dict) {
        dict = (uint32_t)std::max<uint64_t>(usize, 4096);
    }
    if (dict > (1u << 30)) dict = 1u << 30;
    LzmaDec dec(dict, out);
    dec.setProps(lc, lp, pb);
    dec.decode(in.p + 13, in.size() - 13, unknown ? 0 : usize, unknown);
    dec.flush();
}

void xzDecompress(View in, Sink& out) {
    static const uint8_t MAGIC[6] = {0xFD, '7', 'z', 'X', 'Z', 0};
    const uint8_t* b = in.p;
    size_t n = in.size();
    size_t pos = 0;
    int streams = 0;
    while (pos + 12 <= n && memcmp(b + pos, MAGIC, 6) == 0) {
        streams++;
        if (crc32(b + pos + 6, 2) != rd32(b + pos + 8)) throw Error("XZのヘッダCRCが合わないよ");
        int checkId = b[pos + 7] & 0x0F;
        static const int checkSize[16] = {0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64};
        size_t csz = checkSize[checkId];
        pos += 12;
        while (true) {
            if (pos >= n) throw Error("XZが途中で切れてるよ");
            if (b[pos] == 0) break;
            size_t bstart = pos;
            size_t hsz = ((size_t)b[pos] + 1) * 4;
            if (pos + hsz > n) throw Error("XZが途中で切れてるよ");
            if (crc32(b + pos, hsz - 4) != rd32(b + pos + hsz - 4)) throw Error("XZのブロックヘッダCRCが合わないよ");
            uint8_t flags = b[pos + 1];
            size_t hp = pos + 2;
            uint64_t v, csize = 0, usize = 0;
            if (flags & 0x40) { if (!readVli(b, pos + hsz, hp, csize)) throw Error("XZが壊れてるよ"); }
            if (flags & 0x80) { if (!readVli(b, pos + hsz, hp, usize)) throw Error("XZが壊れてるよ"); }
            int nf = (flags & 3) + 1;
            struct Filt { uint64_t id; Bytes props; };
            std::vector<Filt> filts;
            for (int i = 0; i < nf; i++) {
                Filt f;
                uint64_t ps;
                if (!readVli(b, pos + hsz, hp, f.id) || !readVli(b, pos + hsz, hp, ps) || hp + ps > pos + hsz)
                    throw Error("XZが壊れてるよ");
                f.props.assign(b + hp, b + hp + ps);
                hp += ps;
                filts.push_back(f);
            }
            (void)v;
            if (filts.back().id != 0x21 || filts.back().props.size() != 1) throw Error("このXZのフィルタは未対応だよ");
            uint8_t db = filts.back().props[0];
            if (db > 40) throw Error("XZの辞書サイズが変だよ");
            uint64_t dsz = db == 40 ? 0xFFFFFFFFull : ((uint64_t)(2 | (db & 1)) << (db / 2 + 11));
            if (dsz > (1u << 30)) dsz = 1u << 30;
            if (flags & 0x80) { if (usize < dsz) dsz = std::max<uint64_t>(usize, 4096); }
            pos += hsz;
            bool plain = nf == 1;
            size_t used;
            if (plain) {
                uint64_t tot = 0;
                struct Chk : Sink {
                    Sink& o; uint32_t crc = 0;
                    explicit Chk(Sink& s) : o(s) {}
                    void write(const uint8_t* p, size_t n2) override { crc = crc32Update(crc, p, n2); o.write(p, n2); total_ += n2; }
                } chk(out);
                used = lzma2Decode(b + pos, n - pos, (uint32_t)dsz, chk, &tot);
                pos += used;
                size_t pad = (4 - ((pos - bstart) & 3)) & 3;
                pos += pad;
                if (pos + csz > n) throw Error("XZが途中で切れてるよ");
                if (checkId == 1 && chk.crc != rd32(b + pos))
                    logf("! XZのCRC32が合わなかったよ(続けるね)");
            } else {
                VecSink vs;
                vs.limit = (size_t)1 << 30;
                uint64_t tot = 0;
                used = lzma2Decode(b + pos, n - pos, (uint32_t)dsz, vs, &tot);
                pos += used;
                size_t pad = (4 - ((pos - bstart) & 3)) & 3;
                pos += pad;
                if (pos + csz > n) throw Error("XZが途中で切れてるよ");
                for (int i = nf - 2; i >= 0; i--) {
                    Filt& f = filts[i];
                    uint8_t* d = vs.v.data();
                    size_t sz = vs.v.size();
                    switch (f.id) {
                    case 0x03: deltaDec(d, sz, (f.props.empty() ? 0 : f.props[0]) + 1); break;
                    case 0x04: bcjX86(d, sz); break;
                    case 0x05: bcjPpc(d, sz); break;
                    case 0x07: bcjArm(d, sz); break;
                    case 0x08: bcjArmThumb(d, sz); break;
                    case 0x09: bcjSparc(d, sz); break;
                    case 0x0A: bcjArm64(d, sz); break;
                    default: throw Error("このXZのBCJフィルタは未対応だよ");
                    }
                }
                out.write(vs.v.data(), vs.v.size());
            }
            pos += csz;
            checkCancel();
        }

        size_t ip = pos + 1;
        uint64_t nrec;
        if (!readVli(b, n, ip, nrec)) throw Error("XZのindexが壊れてるよ");
        for (uint64_t i = 0; i < nrec; i++) {
            uint64_t a, c;
            if (!readVli(b, n, ip, a) || !readVli(b, n, ip, c)) throw Error("XZのindexが壊れてるよ");
        }
        ip = (ip + 3) & ~(size_t)3;
        ip += 4;
        ip += 12;
        if (ip > n) throw Error("XZが途中で切れてるよ");
        pos = ip;
        while (pos + 4 <= n && rd32(b + pos) == 0) pos += 4;
    }
    if (streams == 0) throw Error("XZじゃないみたい");
}

namespace {

struct RangeEnc {
    uint64_t low = 0;
    uint32_t range = 0xFFFFFFFFu;
    uint8_t cache = 0;
    uint64_t cacheSize = 1;
    Bytes out;
    void reset() {
        low = 0; range = 0xFFFFFFFFu; cache = 0; cacheSize = 1; out.clear();
    }
    void shiftLow() {
        if ((uint32_t)low < 0xFF000000u || (low >> 32) != 0) {
            uint8_t temp = cache;
            do {
                out.push_back((uint8_t)(temp + (uint8_t)(low >> 32)));
                temp = 0xFF;
            } while (--cacheSize != 0);
            cache = (uint8_t)(low >> 24);
        }
        cacheSize++;
        low = (low & 0x00FFFFFFu) << 8;
    }
    inline void bit(uint16_t& p, int b) {
        uint32_t bound = (range >> 11) * p;
        if (!b) {
            range = bound;
            p += (2048 - p) >> 5;
        } else {
            low += bound;
            range -= bound;
            p -= p >> 5;
        }
        while (range < kTop) {
            range <<= 8;
            shiftLow();
        }
    }
    void direct(uint32_t v, int n) {
        while (n--) {
            range >>= 1;
            if ((v >> n) & 1) low += range;
            while (range < kTop) {
                range <<= 8;
                shiftLow();
            }
        }
    }
    void tree(uint16_t* pr, int bits, uint32_t sym) {
        uint32_t m = 1;
        for (int i = bits - 1; i >= 0; i--) {
            int b = (sym >> i) & 1;
            bit(pr[m], b);
            m = (m << 1) | b;
        }
    }
    void rtree(uint16_t* pr, int bits, uint32_t sym) {
        uint32_t m = 1;
        for (int i = 0; i < bits; i++) {
            int b = sym & 1;
            sym >>= 1;
            bit(pr[m], b);
            m = (m << 1) | b;
        }
    }
    void flush() {
        for (int i = 0; i < 5; i++) shiftLow();
    }
    size_t pending() const { return out.size() + (size_t)cacheSize + 4; }
};

class LzmaEnc {
public:
    LzmaEnc(const uint8_t* data, size_t n, uint32_t dictSize) : d_(data), n_(n), dict_(dictSize) {
        wbits_ = 12;
        while (((size_t)1 << wbits_) < dictSize && wbits_ < 26) wbits_++;
        wmask_ = ((size_t)1 << wbits_) - 1;
        hbits_ = 18;
        if (n > (1u << 20)) hbits_ = 20;
        if (n > (8u << 20)) hbits_ = 22;
        head_.assign((size_t)1 << hbits_, kNone);
        head3_.assign((size_t)1 << 16, kNone);
        head2_.assign((size_t)1 << 16, kNone);
        chain_.assign((size_t)1 << wbits_, kNone);
        bool big = n > ((size_t)16 << 20);
        depth_ = big ? 48 : 192;
        nice_ = big ? 64 : 192;
        nodes_.resize(kWin + 1);
        probs_.init(lc_, lp_);
        initPriceTable();
    }
    void resetState() {
        probs_.init(lc_, lp_);
        state_ = 0;
        rep_[0] = rep_[1] = rep_[2] = rep_[3] = 0;
    }
    RangeEnc rc;

    size_t encode(size_t pos, size_t end, size_t compLimit) {
        size_t start = pos;
        while (pos < end) {
            if (rc.pending() >= compLimit) break;
            if (((pos - start) & 0xFFFF) < 4096 && pos != start) checkCancel();
            size_t W = std::min<size_t>(kWin, end - pos);
            refreshPrices();
            Node* nd = nodes_.data();
            nd[0].price = 0;
            nd[0].state = (uint8_t)state_;
            for (int k = 0; k < 4; k++) nd[0].reps[k] = rep_[k];
            for (size_t i = 1; i <= W; i++) nd[i].price = kInf;
            size_t endNode = W;
            for (size_t i = 0; i < endNode; i++) {
                if (nd[i].price == kInf) continue;
                size_t p = pos + i;
                size_t avail = end - p;
                size_t room = endNode - i;
                uint32_t ps = (uint32_t)p & 3;
                uint32_t st = nd[i].state;
                uint32_t base = nd[i].price;
                uint32_t isM1 = price1(probs_.isMatch[st][ps]);

                uint32_t lp0 = base + price0(probs_.isMatch[st][ps]) + litPrice(p, st, nd[i].reps[0]);
                relax(nd, i + 1, lp0, 1, 0, 0, st, nd[i].reps);

                uint32_t isRep1 = price1(probs_.isRep[st]);
                if (p > nd[i].reps[0] && d_[p] == d_[p - nd[i].reps[0] - 1]) {
                    uint32_t c = base + isM1 + isRep1 + price0(probs_.isRepG0[st]) + price0(probs_.isRep0Long[st][ps]);
                    relax(nd, i + 1, c, 1, 1, 0, st, nd[i].reps);
                }

                size_t maxLen = std::min<size_t>(273, avail);
                size_t bestRepLen = 0;
                uint32_t bestRepIdx = 0;
                for (uint32_t r = 0; r < 4; r++) {
                    size_t dist = (size_t)nd[i].reps[r] + 1;
                    if (dist > p || maxLen < 2) continue;
                    uint32_t l = matchLen(p, dist, maxLen);
                    if (l < 2) continue;
                    uint32_t head = base + isM1 + isRep1 + repSelPrice(st, ps, r);
                    size_t lim = std::min<size_t>(l, room);
                    for (size_t L = 2; L <= lim; L++) {
                        relax(nd, i + L, head + repLenPrice_[ps][L - 2], (uint32_t)L, 2, r, st, nd[i].reps);
                    }
                    if (lim == l) combo(nd, pos, i, lim, endNode, end, head + repLenPrice_[ps][lim - 2], 2, r);
                    if (l > bestRepLen) { bestRepLen = l; bestRepIdx = r; }
                }
                if (bestRepLen >= nice_) {
                    size_t L = std::min<size_t>(bestRepLen, room);
                    endNode = i + L;
                    (void)bestRepIdx;
                    break;
                }

                size_t nm = 0;
                if (maxLen >= 2) nm = findMatches(p, maxLen);
                if (nm) {
                    uint32_t head = base + isM1 + price0(probs_.isRep[st]);
                    uint32_t prevLen = 1;
                    for (size_t k = 0; k < nm; k++) {
                        uint32_t ml = mlen_[k], md = mdist_[k];
                        uint32_t dst = md - 1;
                        uint32_t dp[4];
                        for (uint32_t q = 0; q < 4; q++) dp[q] = distPrice(dst, q);
                        size_t lim = std::min<size_t>(ml, room);
                        for (size_t L = prevLen + 1; L <= lim; L++) {
                            uint32_t ls = L - 2 < 4 ? (uint32_t)(L - 2) : 3;
                            relax(nd, i + L, head + matchLenPrice_[ps][L - 2] + dp[ls], (uint32_t)L, 3, md, st, nd[i].reps);
                        }
                        if (lim == ml && lim >= 2) {
                            uint32_t lsl = lim - 2 < 4 ? (uint32_t)(lim - 2) : 3;
                            combo(nd, pos, i, lim, endNode, end, head + matchLenPrice_[ps][lim - 2] + dp[lsl], 3, md);
                        }
                        prevLen = ml;
                    }
                    if (mlen_[nm - 1] >= nice_) {
                        size_t L = std::min<size_t>(mlen_[nm - 1], room);
                        endNode = i + L;
                        break;
                    }
                }
            }
            size_t cut = endNode;
            if (endNode == W && pos + W < end && W > 2 * 273) cut = W - 273;
            steps_.clear();
            for (size_t j = endNode; j > 0; j -= nd[j].len) steps_.push_back((uint32_t)j);
            size_t cur = pos;
            for (size_t k = steps_.size(); k-- > 0;) {
                size_t j = steps_[k];
                const Node& s = nd[j];
                if (j > cut && cur > pos) break;
                if (rc.pending() >= compLimit && cur > pos) break;
                uint32_t ps = (uint32_t)cur & 3;
                switch (s.kind) {
                case 0:
                    encLit(cur, ps);
                    break;
                case 1:
                    rc.bit(probs_.isMatch[state_][ps], 1);
                    rc.bit(probs_.isRep[state_], 1);
                    rc.bit(probs_.isRepG0[state_], 0);
                    rc.bit(probs_.isRep0Long[state_][ps], 0);
                    state_ = state_ < 7 ? 9 : 11;
                    break;
                case 2:
                    encRep(cur, ps, s.aux, s.len);
                    break;
                case 3:
                    encMatch(ps, s.aux - 1, s.len);
                    break;
                default: {
                    if (s.kind1 == 2) encRep(cur, ps, s.aux1, s.len1);
                    else encMatch(ps, s.aux1 - 1, s.len1);
                    size_t q = cur + s.len1;
                    encLit(q, (uint32_t)q & 3);
                    size_t q2 = q + 1;
                    encRep(q2, (uint32_t)q2 & 3, 0, s.len3);
                    break;
                }
                }
                cur += s.len;
            }
            pos = cur;
            insertUpTo(pos);
        }
        return pos;
    }

    void encodeEos(size_t pos) {
        uint32_t posState = (uint32_t)pos & 3;
        rc.bit(probs_.isMatch[state_][posState], 1);
        rc.bit(probs_.isRep[state_], 0);
        state_ = state_ < 7 ? 7 : 10;
        encLen(probs_.matchLen, 0, posState);
        uint32_t dist = 0xFFFFFFFFu;
        encDist(dist, 0);
    }

    int lc_ = 3, lp_ = 0, pb_ = 2;
    uint8_t propsByte() const { return (uint8_t)((pb_ * 5 + lp_) * 9 + lc_); }

private:
    static constexpr uint32_t kNone = 0xFFFFFFFFu;
    static constexpr uint32_t kInf = 0xFFFFFFFFu;
    static constexpr size_t kWin = 4096;

    struct Node {
        uint32_t price;
        uint32_t aux;
        uint32_t len;
        uint32_t reps[4];
        uint32_t aux1;
        uint32_t len1;
        uint32_t len3;
        uint8_t kind;
        uint8_t kind1;
        uint8_t state;
    };

    uint32_t priceTab_[2049];

    void initPriceTable() {
        for (int i = 0; i <= 2048; i++) {
            double p = i ? (double)i / 2048.0 : 1.0 / 4096.0;
            priceTab_[i] = (uint32_t)(-std::log2(p) * 64.0 + 0.5);
        }
    }
    inline uint32_t price0(uint16_t p) const { return priceTab_[p]; }
    inline uint32_t price1(uint16_t p) const { return priceTab_[2048 - p]; }
    inline uint32_t priceBit(uint16_t p, int b) const { return b ? priceTab_[2048 - p] : priceTab_[p]; }
    uint32_t treePrice(const uint16_t* pr, int bits, uint32_t sym) const {
        uint32_t m = 1, c = 0;
        for (int i = bits - 1; i >= 0; i--) {
            int b = (sym >> i) & 1;
            c += priceBit(pr[m], b);
            m = (m << 1) | b;
        }
        return c;
    }
    uint32_t rtreePrice(const uint16_t* pr, int bits, uint32_t sym) const {
        uint32_t m = 1, c = 0;
        for (int i = 0; i < bits; i++) {
            int b = sym & 1;
            sym >>= 1;
            c += priceBit(pr[m], b);
            m = (m << 1) | b;
        }
        return c;
    }
    uint32_t lenPriceOf(const LenProbs& lp, uint32_t len, uint32_t ps) const {
        if (len < 8) return price0(lp.choice) + treePrice(lp.low[ps], 3, len);
        if (len < 16) return price1(lp.choice) + price0(lp.choice2) + treePrice(lp.mid[ps], 3, len - 8);
        return price1(lp.choice) + price1(lp.choice2) + treePrice(lp.high, 8, len - 16);
    }
    void refreshPrices() {
        for (uint32_t ps = 0; ps < 4; ps++) {
            for (uint32_t l = 0; l < 272; l++) {
                matchLenPrice_[ps][l] = lenPriceOf(probs_.matchLen, l, ps);
                repLenPrice_[ps][l] = lenPriceOf(probs_.repLen, l, ps);
            }
        }
        for (uint32_t ls = 0; ls < 4; ls++)
            for (uint32_t sl = 0; sl < 64; sl++) slotPrice_[ls][sl] = treePrice(probs_.posSlot[ls], 6, sl);
        for (uint32_t a = 0; a < 16; a++) alignPrice_[a] = rtreePrice(probs_.align, 4, a);
    }
    uint32_t distPrice(uint32_t dist, uint32_t ls) const {
        uint32_t slot;
        if (dist < 4) slot = dist;
        else {
            int nb = 31 - __builtin_clz(dist);
            slot = ((uint32_t)nb << 1) | ((dist >> (nb - 1)) & 1);
        }
        uint32_t c = slotPrice_[ls][slot];
        if (slot >= 4) {
            int fb = (int)(slot >> 1) - 1;
            uint32_t base = (2 | (slot & 1)) << fb;
            uint32_t red = dist - base;
            if (slot < 14) c += rtreePrice(probs_.posSpecial + base - slot - 1, fb, red);
            else c += (uint32_t)(fb - 4) * 64 + alignPrice_[red & 15];
        }
        return c;
    }
    uint32_t litPrice(size_t p, uint32_t st, uint32_t rep0) const {
        uint8_t prev = p ? d_[p - 1] : 0;
        uint32_t lpMask = (1u << lp_) - 1;
        uint32_t ls = (((uint32_t)p & lpMask) << lc_) + (prev >> (8 - lc_));
        const uint16_t* pr = &probs_.lit[(size_t)0x300 * ls];
        uint32_t sym = d_[p] | 0x100;
        uint32_t c = 0;
        if (st >= 7 && p > rep0) {
            uint32_t mb = d_[p - rep0 - 1];
            uint32_t offs = 0x100;
            do {
                mb <<= 1;
                c += priceBit(pr[offs + (mb & offs) + (sym >> 8)], (sym >> 7) & 1);
                sym <<= 1;
                offs &= ~(mb ^ sym);
            } while (sym < 0x10000);
        } else {
            uint32_t m = 1;
            for (int i = 7; i >= 0; i--) {
                int b = (d_[p] >> i) & 1;
                c += priceBit(pr[m], b);
                m = (m << 1) | b;
            }
        }
        return c;
    }
    uint32_t repSelPrice(uint32_t st, uint32_t ps, uint32_t r) const {
        if (r == 0) return price0(probs_.isRepG0[st]) + price1(probs_.isRep0Long[st][ps]);
        uint32_t c = price1(probs_.isRepG0[st]);
        if (r == 1) return c + price0(probs_.isRepG1[st]);
        return c + price1(probs_.isRepG1[st]) + priceBit(probs_.isRepG2[st], (int)r - 2);
    }
    static void applyEdge(uint8_t kind, uint32_t aux, uint32_t st, const uint32_t* reps, uint8_t& outSt, uint32_t* outReps) {
        switch (kind) {
        case 0:
            outSt = (uint8_t)(st < 4 ? 0 : (st < 10 ? st - 3 : st - 6));
            for (int k = 0; k < 4; k++) outReps[k] = reps[k];
            break;
        case 1:
            outSt = (uint8_t)(st < 7 ? 9 : 11);
            for (int k = 0; k < 4; k++) outReps[k] = reps[k];
            break;
        case 2: {
            outSt = (uint8_t)(st < 7 ? 8 : 11);
            uint32_t d = reps[aux];
            uint32_t n2[4] = {d, 0, 0, 0};
            int w = 1;
            for (uint32_t k = 0; k < 4; k++) if (k != aux) n2[w++] = reps[k];
            for (int k = 0; k < 4; k++) outReps[k] = n2[k];
            break;
        }
        default:
            outSt = (uint8_t)(st < 7 ? 7 : 10);
            outReps[0] = aux - 1;
            outReps[1] = reps[0];
            outReps[2] = reps[1];
            outReps[3] = reps[2];
            break;
        }
    }
    void relax(Node* nd, size_t j, uint32_t price, uint32_t len, uint8_t kind, uint32_t aux, uint32_t st, const uint32_t* reps) {
        Node& t = nd[j];
        if (price >= t.price) return;
        t.price = price;
        t.len = len;
        t.kind = kind;
        t.aux = aux;
        applyEdge(kind, aux, st, reps, t.state, t.reps);
    }
    void combo(Node* nd, size_t pos, size_t i, size_t L, size_t endNode, size_t end, uint32_t priceEdge, uint8_t kind1, uint32_t aux1) {
        const Node& n0 = nd[i];
        size_t q = pos + i + L;
        if (endNode < i + L + 3 || end < q + 3) return;
        uint8_t stE;
        uint32_t repsE[4];
        applyEdge(kind1, aux1, n0.state, n0.reps, stE, repsE);
        uint32_t D = repsE[0];
        if ((size_t)D > q) return;
        size_t maxL2 = std::min<size_t>(273, end - (q + 1));
        uint32_t l2 = matchLen(q + 1, (size_t)D + 1, maxL2);
        if (l2 < 2) return;
        uint32_t psq = (uint32_t)q & 3;
        uint32_t stL = stE < 4 ? 0 : (stE < 10 ? stE - 3 : stE - 6);
        uint32_t pl = priceEdge + price0(probs_.isMatch[stE][psq]) + litPrice(q, stE, D);
        uint32_t ps2 = (uint32_t)(q + 1) & 3;
        uint32_t head = pl + price1(probs_.isMatch[stL][ps2]) + price1(probs_.isRep[stL]) + price0(probs_.isRepG0[stL]) +
                        price1(probs_.isRep0Long[stL][ps2]);
        size_t lim2 = std::min<size_t>(l2, endNode - (i + L + 1));
        uint8_t stF = (uint8_t)(stL < 7 ? 8 : 11);
        for (size_t L2 = 2; L2 <= lim2; L2++) {
            size_t j = i + L + 1 + L2;
            uint32_t price = head + repLenPrice_[ps2][L2 - 2];
            Node& t = nd[j];
            if (price >= t.price) continue;
            t.price = price;
            t.len = (uint32_t)(L + 1 + L2);
            t.kind = 4;
            t.kind1 = kind1;
            t.aux1 = aux1;
            t.len1 = (uint32_t)L;
            t.len3 = (uint32_t)L2;
            t.state = stF;
            for (int k = 0; k < 4; k++) t.reps[k] = repsE[k];
        }
    }
    uint32_t matchLen(size_t pos, size_t dist, size_t maxLen) const {
        const uint8_t* a = d_ + pos;
        const uint8_t* b = d_ + pos - dist;
        size_t l = 0;
        while (l < maxLen && a[l] == b[l]) l++;
        return (uint32_t)l;
    }
    uint32_t hash4(size_t p) const {
        uint32_t v = d_[p] | (d_[p + 1] << 8) | ((uint32_t)d_[p + 2] << 16) | ((uint32_t)d_[p + 3] << 24);
        return (v * 2654435761u) >> (32 - hbits_);
    }
    uint32_t hash3(size_t p) const {
        uint32_t v = d_[p] | (d_[p + 1] << 8) | ((uint32_t)d_[p + 2] << 16);
        return (v * 2654435761u) >> 16;
    }
    uint32_t hash2(size_t p) const { return d_[p] | ((uint32_t)d_[p + 1] << 8); }
    void insertAt(size_t p) {
        if (p + 4 <= n_) {
            uint32_t h = hash4(p);
            chain_[p & wmask_] = head_[h];
            head_[h] = (uint32_t)p;
        }
        if (p + 3 <= n_) head3_[hash3(p)] = (uint32_t)p;
        if (p + 2 <= n_) head2_[hash2(p)] = (uint32_t)p;
    }
    void insertUpTo(size_t pos) {
        while (inserted_ < pos) insertAt(inserted_++);
    }
    size_t findMatches(size_t p, size_t maxLen) {
        bool fresh = inserted_ <= p;
        insertUpTo(p);
        uint32_t c2 = kNone, c3 = kNone;
        if (fresh) {
            if (p + 2 <= n_) c2 = head2_[hash2(p)];
            if (p + 3 <= n_) c3 = head3_[hash3(p)];
            ring2_[p & kRingMask] = c2;
            ring3_[p & kRingMask] = c3;
        } else {
            c2 = ring2_[p & kRingMask];
            c3 = ring3_[p & kRingMask];
        }
        size_t nm = 0;
        size_t lim = p > dict_ ? p - dict_ : 0;
        uint32_t best = 1;
        if (c2 != kNone && c2 >= lim && c2 < p) {
            uint32_t l = matchLen(p, p - c2, std::min<size_t>(maxLen, 2));
            if (l >= 2) {
                mlen_[nm] = 2;
                mdist_[nm++] = (uint32_t)(p - c2);
                best = 2;
            }
        }
        if (maxLen >= 3 && c3 != kNone && c3 >= lim && c3 < p) {
            uint32_t l = matchLen(p, p - c3, maxLen);
            if (l >= 3 && l > best) {
                mlen_[nm] = l;
                mdist_[nm++] = (uint32_t)(p - c3);
                best = l;
            }
        }
        if (maxLen >= 4 && p + 4 <= n_ && best < maxLen) {
            uint32_t cand = head_[hash4(p)];
            while (cand != kNone && cand >= p) {
                uint32_t nx = chain_[cand & wmask_];
                if (nx >= cand) { cand = kNone; break; }
                cand = nx;
            }
            int depth = depth_;
            while (cand != kNone && cand >= lim && cand < p && depth-- > 0) {
                if (d_[cand + best] == d_[p + best]) {
                    uint32_t l = matchLen(p, p - cand, maxLen);
                    if (l > best) {
                        if (nm < 270) {
                            mlen_[nm] = l;
                            mdist_[nm++] = (uint32_t)(p - cand);
                        } else {
                            mlen_[nm - 1] = l;
                            mdist_[nm - 1] = (uint32_t)(p - cand);
                        }
                        best = l;
                        if (l >= maxLen || l >= nice_) break;
                    }
                }
                uint32_t nx = chain_[cand & wmask_];
                if (nx >= cand) break;
                cand = nx;
            }
        }
        return nm;
    }

    void encLit(size_t pos, uint32_t posState) {
        (void)posState;
        rc.bit(probs_.isMatch[state_][(uint32_t)pos & 3], 0);
        uint8_t prev = pos ? d_[pos - 1] : 0;
        uint32_t lpMask = (1u << lp_) - 1;
        uint32_t ls = (((uint32_t)pos & lpMask) << lc_) + (prev >> (8 - lc_));
        uint16_t* pr = &probs_.lit[(size_t)0x300 * ls];
        uint32_t sym = d_[pos] | 0x100;
        if (state_ >= 7) {
            uint32_t mb = d_[pos - rep_[0] - 1];
            uint32_t offs = 0x100;
            do {
                mb <<= 1;
                rc.bit(pr[offs + (mb & offs) + (sym >> 8)], (sym >> 7) & 1);
                sym <<= 1;
                offs &= ~(mb ^ sym);
            } while (sym < 0x10000);
        } else {
            uint32_t m = 1;
            for (int i = 7; i >= 0; i--) {
                int b = (d_[pos] >> i) & 1;
                rc.bit(pr[m], b);
                m = (m << 1) | b;
            }
        }
        state_ = state_ < 4 ? 0 : (state_ < 10 ? state_ - 3 : state_ - 6);
    }
    void encLen(LenProbs& lp, uint32_t len, uint32_t posState) {
        if (len < 8) {
            rc.bit(lp.choice, 0);
            rc.tree(lp.low[posState], 3, len);
        } else if (len < 16) {
            rc.bit(lp.choice, 1);
            rc.bit(lp.choice2, 0);
            rc.tree(lp.mid[posState], 3, len - 8);
        } else {
            rc.bit(lp.choice, 1);
            rc.bit(lp.choice2, 1);
            rc.tree(lp.high, 8, len - 16);
        }
    }
    void encDist(uint32_t dist, uint32_t lenForState) {
        uint32_t ls = lenForState < 4 ? lenForState : 3;
        uint32_t slot;
        if (dist < 4) slot = dist;
        else {
            int nb = 31 - __builtin_clz(dist);
            slot = ((uint32_t)nb << 1) | ((dist >> (nb - 1)) & 1);
        }
        rc.tree(probs_.posSlot[ls], 6, slot);
        if (slot >= 4) {
            int fb = (int)(slot >> 1) - 1;
            uint32_t base = (2 | (slot & 1)) << fb;
            uint32_t red = dist - base;
            if (slot < 14) {
                rc.rtree(probs_.posSpecial + base - slot - 1, fb, red);
            } else {
                rc.direct(red >> 4, fb - 4);
                rc.rtree(probs_.align, 4, red & 15);
            }
        }
    }
    void encMatch(uint32_t posState, uint32_t dist0, uint32_t len) {
        rc.bit(probs_.isMatch[state_][posState], 1);
        rc.bit(probs_.isRep[state_], 0);
        encLen(probs_.matchLen, len - 2, posState);
        encDist(dist0, len - 2);
        rep_[3] = rep_[2]; rep_[2] = rep_[1]; rep_[1] = rep_[0]; rep_[0] = dist0;
        state_ = state_ < 7 ? 7 : 10;
    }
    void encRep(size_t pos, uint32_t posState, uint32_t idx, uint32_t len) {
        (void)pos;
        rc.bit(probs_.isMatch[state_][posState], 1);
        rc.bit(probs_.isRep[state_], 1);
        if (idx == 0) {
            rc.bit(probs_.isRepG0[state_], 0);
            rc.bit(probs_.isRep0Long[state_][posState], 1);
        } else {
            rc.bit(probs_.isRepG0[state_], 1);
            uint32_t d = rep_[idx];
            if (idx == 1) {
                rc.bit(probs_.isRepG1[state_], 0);
            } else {
                rc.bit(probs_.isRepG1[state_], 1);
                rc.bit(probs_.isRepG2[state_], idx - 2);
                if (idx == 3) rep_[3] = rep_[2];
            }

            for (uint32_t i = idx; i > 0; i--) rep_[i] = rep_[i - 1];
            rep_[0] = d;
        }
        encLen(probs_.repLen, len - 2, posState);
        state_ = state_ < 7 ? 8 : 11;
    }

    const uint8_t* d_;
    size_t n_;
    size_t dict_;
    int wbits_, hbits_;
    size_t wmask_;
    std::vector<uint32_t> head_, head3_, head2_, chain_;
    size_t inserted_ = 0;
    int depth_ = 256;
    size_t nice_ = 192;
    static constexpr size_t kRingMask = 8191;
    uint32_t ring2_[kRingMask + 1], ring3_[kRingMask + 1];
    std::vector<Node> nodes_;
    std::vector<uint32_t> steps_;
    uint32_t mlen_[272], mdist_[272];
    uint32_t matchLenPrice_[4][272], repLenPrice_[4][272];
    uint32_t slotPrice_[4][64], alignPrice_[16];
    Probs probs_;
    uint32_t state_ = 0;
    uint32_t rep_[4] = {0, 0, 0, 0};
};

uint32_t pickDict(size_t n) {
    uint32_t d = 1u << 12;
    while (d < n && d < (8u << 20)) d <<= 1;
    return d;
}

uint8_t xzDictByte(uint32_t dict) {
    int lg = 0;
    while (((uint32_t)1 << lg) < dict) lg++;
    return (uint8_t)(2 * (lg - 12));
}

void putVli(Bytes& b, uint64_t v) {
    while (v >= 0x80) {
        b.push_back((uint8_t)(v | 0x80));
        v >>= 7;
    }
    b.push_back((uint8_t)v);
}

}

void lzmaCompressAlone(View in, Sink& out) {
    uint32_t dict = pickDict(in.size());
    LzmaEnc enc(in.p, in.size(), dict);
    uint8_t hdr[13];
    hdr[0] = enc.propsByte();
    wr32(hdr + 1, dict);
    wr64(hdr + 5, ~(uint64_t)0);
    out.write(hdr, 13);
    size_t pos = 0;
    size_t n = in.size();
    while (pos < n) {
        size_t end = std::min(n, pos + ((size_t)1 << 22));
        pos = enc.encode(pos, end, (size_t)1 << 30);
        if (enc.rc.out.size() > (1u << 20)) {
            out.write(enc.rc.out.data(), enc.rc.out.size());
            enc.rc.out.clear();
        }
        subProgress((int)(pos * 100 / (n ? n : 1)));
    }
    enc.encodeEos(pos);
    enc.rc.flush();
    out.write(enc.rc.out.data(), enc.rc.out.size());
}

void xzCompress(View in, Sink& out) {
    const uint8_t* data = in.p;
    size_t n = in.size();
    uint32_t dict = pickDict(n);
    uint8_t sh[12] = {0xFD, '7', 'z', 'X', 'Z', 0, 0, 0x01, 0, 0, 0, 0};
    wr32(sh + 8, crc32(sh + 6, 2));
    out.write(sh, 12);
    uint64_t blockStart = out.total();
    Bytes bh;
    bh.push_back(0);
    bh.push_back(0x00);
    bh.push_back(0x21);
    bh.push_back(0x01);
    bh.push_back(xzDictByte(dict));
    while ((bh.size() + 4) % 4) bh.push_back(0);
    bh[0] = (uint8_t)((bh.size() + 4) / 4 - 1);
    uint32_t hc = crc32(bh.data(), bh.size());
    uint8_t hcb[4];
    wr32(hcb, hc);
    bh.insert(bh.end(), hcb, hcb + 4);
    out.write(bh.data(), bh.size());
    uint64_t dataStart = out.total();

    if (n) {
        LzmaEnc enc(data, n, dict);
        size_t pos = 0;
        bool dictReset = true, needProps = true, needState = true;
        while (pos < n) {
            size_t chunkMax = std::min(n, pos + ((size_t)(1 << 21) - 512));
            if (needState) enc.resetState();
            enc.rc.reset();
            size_t np = enc.encode(pos, chunkMax, 65000);
            enc.rc.flush();
            size_t usz = np - pos;
            size_t csz = enc.rc.out.size();
            if (usz == 0) throw Error("xz圧縮でエラー");
            if (csz > 65536 || csz >= usz + 3) {

                size_t off = pos;
                while (off < np) {
                    size_t c = std::min<size_t>(65536, np - off);
                    uint8_t h[3] = {(uint8_t)(dictReset ? 1 : 2), (uint8_t)((c - 1) >> 8), (uint8_t)(c - 1)};
                    out.write(h, 3);
                    out.write(data + off, c);
                    dictReset = false;
                    off += c;
                }
                needState = true;
            } else {
                uint8_t h[6];
                uint8_t ctrl = needProps ? (dictReset ? 0xE0 : 0xC0) : (needState ? 0xA0 : 0x80);
                h[0] = (uint8_t)(ctrl | ((usz - 1) >> 16));
                h[1] = (uint8_t)((usz - 1) >> 8);
                h[2] = (uint8_t)(usz - 1);
                h[3] = (uint8_t)((csz - 1) >> 8);
                h[4] = (uint8_t)(csz - 1);
                size_t hl = 5;
                if (needProps) h[hl++] = enc.propsByte();
                out.write(h, hl);
                out.write(enc.rc.out.data(), csz);
                dictReset = false;
                needProps = false;
                needState = false;
            }
            pos = np;
            subProgress((int)(pos * 100 / n));
        }
    }
    uint8_t endm = 0;
    out.write(&endm, 1);
    uint64_t comp = out.total() - dataStart;
    uint64_t pad = (4 - ((out.total() - blockStart) & 3)) & 3;
    uint8_t z[4] = {0, 0, 0, 0};
    if (pad) out.write(z, (size_t)pad);
    uint8_t cb[4];
    wr32(cb, crc32(data, n));
    out.write(cb, 4);
    uint64_t unpadded = bh.size() + comp + 4;
    Bytes idx;
    idx.push_back(0);
    putVli(idx, 1);
    putVli(idx, unpadded);
    putVli(idx, n);
    while (idx.size() % 4) idx.push_back(0);
    uint8_t ic[4];
    wr32(ic, crc32(idx.data(), idx.size()));
    idx.insert(idx.end(), ic, ic + 4);
    out.write(idx.data(), idx.size());
    uint8_t ft[12];
    wr32(ft + 4, (uint32_t)(idx.size() / 4 - 1));
    ft[8] = 0;
    ft[9] = 0x01;
    ft[10] = 'Y';
    ft[11] = 'Z';
    uint8_t tmp8[6];
    memcpy(tmp8, ft + 4, 4);
    tmp8[4] = 0;
    tmp8[5] = 1;
    wr32(ft, crc32(tmp8, 6));
    out.write(ft, 12);
}

}
