#include "zimage.h"

namespace cu {

namespace {

uint32_t ru32(const uint8_t* b, size_t n, size_t off) {
    if (off > n || n - off < 4) return 0;
    return rd32(b + off);
}

void wu32(Bytes& b, size_t off, uint32_t v) {
    if (off > b.size() || b.size() - off < 4) return;
    wr32(b.data() + off, v);
}

bool validPiggyEnd(size_t kernelLen, size_t hdrSz, size_t cand, size_t gotStart) {
    if (cand <= hdrSz + 4 || cand > kernelLen) return false;
    if (gotStart != 0 && ((cand + 3) & ~(size_t)3) != gotStart) return false;
    return true;
}

}

std::unique_ptr<ZImage> ZImage::parse(View z, View* piggyOut) {
    const uint8_t* zb = z.p;
    size_t zn = z.n;
    if (zn < 0x28) return nullptr;
    if (ru32(zb, zn, 0x24) != 0x016f2818u) return nullptr;
    uint32_t start = ru32(zb, zn, 0x28);
    uint32_t end = ru32(zb, zn, 0x2C);
    uint32_t tableMagic = ru32(zb, zn, 0x34);
    uint32_t tableOffset = ru32(zb, zn, 0x38);

    bool found = false;
    size_t piggyOff = 0;
    Fmt fmt = F_UNKNOWN;
    for (size_t cur = 0x28; cur < zn; cur += 4) {
        Fmt f = checkFmt(zb + cur, zn - cur);
        if (fmtCompressed(f)) { found = true; piggyOff = cur; fmt = f; break; }
    }
    if (!found) {
        for (size_t cur = 0x28; cur < zn; cur++) {
            Fmt f = checkFmt(zb + cur, zn - cur);
            if (fmtCompressed(f)) { found = true; piggyOff = cur; fmt = f; break; }
        }
    }
    if (!found) {
        logf("zImageのpiggyが見つからなかったよ(生のままで扱うね)");
        return nullptr;
    }
    size_t headLen = piggyOff;
    const uint8_t* head = zb;

    uint32_t offLc0 = 0;
    size_t gotStart = 0, gotEnd = 0;
    if (headLen >= 32) {
        for (size_t off = 0x20; off + 32 <= headLen; off += 4) {
            uint32_t p0 = ru32(head, headLen, off);
            if (p0 == (uint32_t)off + start) {
                uint32_t p1 = ru32(head, headLen, off + 4);
                uint32_t p2 = ru32(head, headLen, off + 8);
                if (p1 >= (uint32_t)headLen && p2 >= p1) {
                    offLc0 = (uint32_t)off;
                    uint32_t lc1 = ru32(head, headLen, off + 4);
                    uint32_t lc4 = ru32(head, headLen, off + 16);
                    uint32_t lc5 = ru32(head, headLen, off + 20);
                    uint32_t lc6 = ru32(head, headLen, off + 24);
                    if (lc5 <= lc6 && lc6 <= lc1 && lc5 > start) {
                        gotStart = lc5 - start;
                        gotEnd = lc6 - start;
                    } else if (lc4 <= lc5 && lc5 <= lc1 && lc4 > start) {
                        gotStart = lc4 - start;
                        gotEnd = lc5 - start;
                    }
                    break;
                }
            }
        }
    }
    size_t total = (end > start && (size_t)(end - start) <= zn) ? (size_t)(end - start) : zn;
    size_t piggyEnd = zn;
    uint32_t offTable = 0;

    if ((tableMagic == 0x45454545 || tableMagic == 0x45455358 || tableMagic == 0x20425444) && tableOffset > 0 &&
        (size_t)tableOffset < headLen) {
        size_t t = tableOffset;
        while (t + 8 <= headLen) {
            size_t numWords = ru32(head, headLen, t);
            if (numWords == 0) break;
            uint32_t tag = ru32(head, headLen, t + 4);
            if (tag == 0x5a534c4b && numWords >= 3 && t + numWords * 4 <= headLen) {
                uint32_t sizeAddr = ru32(head, headLen, t + 8);
                size_t cand = (size_t)(uint32_t)(sizeAddr - start + 4);
                if (validPiggyEnd(zn, headLen, cand, gotStart)) {
                    piggyEnd = cand;
                    offTable = (uint32_t)(t + 8);
                    break;
                }
            }
            t += numWords * 4;
        }
    }
    if (piggyEnd == zn) {
        size_t minEnd = total > 0x200 ? total - 0x200 : headLen;
        if (gotStart >= headLen && gotEnd <= total && gotStart <= gotEnd) {
            size_t lim = std::min(gotEnd, total >= 4 ? total - 4 : 0);
            for (size_t off = gotStart; off <= lim; off += 4) {
                size_t val = (size_t)(uint32_t)(ru32(zb, zn, off) - start);
                if (val > minEnd && val < total) { piggyEnd = val; break; }
            }
        }
        if (piggyEnd == zn && total > 64) {
            size_t minTail = total > 0xFF ? total - 0xFF : headLen;
            for (size_t i = 1; i <= 16; i++) {
                size_t off = total >= i * 4 ? total - i * 4 : 0;
                size_t val = (size_t)(uint32_t)(ru32(zb, zn, off) - start);
                if (val > minTail && val < total) { piggyEnd = val; break; }
            }
        }
    }
    uint32_t offInfl = 0;
    if (piggyEnd != zn && headLen >= 4) {
        for (size_t off = 0x20; off + 4 <= headLen; off += 4) {
            uint32_t val = ru32(head, headLen, off);
            if ((uint32_t)off + val + 4 == (uint32_t)piggyEnd) { offInfl = (uint32_t)off; break; }
        }
    }
    if (piggyEnd == zn || piggyEnd <= headLen) {
        logf("zImageのpiggy終端が見つからなかったよ(生のままで扱うね)");
        return nullptr;
    }
    size_t piggyLen = piggyEnd - headLen;
    uint32_t offLc1 = 0;
    if (headLen >= 8) {
        for (size_t off = 0x20; off + 8 <= headLen; off += 4) {
            uint32_t p1 = ru32(head, headLen, off + 4);
            if ((uint32_t)(p1 + (uint32_t)off + start) == end) { offLc1 = (uint32_t)off; break; }
        }
    }
    if (piggyLen == 0 || (fmt != F_GZIP && piggyLen < 4)) return nullptr;

    std::unique_ptr<ZImage> r(new ZImage());
    r->head.assign(zb, zb + headLen);
    r->tail.assign(zb + piggyEnd, zb + zn);
    r->piggyLen = piggyLen;
    r->fmt = fmt;
    r->offInflatedSize = offInfl;
    r->offLc0 = offLc0;
    r->offLc1 = offLc1;
    r->offTable = offTable;
    r->piggyOff = headLen;
    if (piggyOut) *piggyOut = View(zb + headLen, piggyLen);
    return r;
}

Bytes ZImage::newHead(size_t payloadSz) const {
    Bytes h = head;
    if (h.empty() || payloadSz == 0 || payloadSz == piggyLen) return h;
    uint32_t start = ru32(head.data(), head.size(), 0x28);
    uint32_t origEnd = (uint32_t)head.size() + (uint32_t)piggyLen + start;
    uint32_t origGot = (origEnd + 3) & ~3u;
    uint32_t newEnd = (uint32_t)head.size() + (uint32_t)payloadSz + start;
    uint32_t newGot = (newEnd + 3) & ~3u;
    uint32_t delta = newGot - origGot;
    uint32_t e = ru32(h.data(), h.size(), 0x2C);
    wu32(h, 0x2C, e + delta);
    if (offInflatedSize) {
        size_t o = offInflatedSize;
        wu32(h, o, ru32(h.data(), h.size(), o) + delta);
    }
    if (offLc0) {
        size_t o = offLc0;
        for (int i = 1; i < 8; i++) {
            size_t eo = o + i * 4;
            uint32_t v = ru32(h.data(), h.size(), eo);
            if (v == origEnd - 4) wu32(h, eo, newEnd - 4);
            else if (v >= (uint32_t)head.size() + start) wu32(h, eo, v + delta);
        }
    }
    if (offLc1) {
        size_t o = offLc1;
        uint32_t v0 = ru32(h.data(), h.size(), o), v1 = ru32(h.data(), h.size(), o + 4);
        wu32(h, o, v0 + delta);
        wu32(h, o + 4, v1 + delta);
    }
    if (offTable) {
        size_t o = offTable;
        wu32(h, o, ru32(h.data(), h.size(), o) + delta);
    }
    uint32_t gotStart = 0, gotEnd = 0;
    if (offLc0) {
        size_t o = offLc0;
        uint32_t lc1 = ru32(head.data(), head.size(), o + 4);
        uint32_t lc4 = ru32(head.data(), head.size(), o + 16);
        uint32_t lc5 = ru32(head.data(), head.size(), o + 20);
        uint32_t lc6 = ru32(head.data(), head.size(), o + 24);
        if (lc5 <= lc6 && lc6 <= lc1 && lc5 > start) { gotStart = lc5; gotEnd = lc6; }
        else if (lc4 <= lc5 && lc5 <= lc1 && lc4 > start) { gotStart = lc4; gotEnd = lc5; }
    }
    if (gotStart != 0 && gotEnd != 0 && h.size() >= 4) {
        for (size_t off = 0; off + 4 <= h.size(); off += 4) {
            uint32_t insn = ru32(h.data(), h.size(), off);
            if ((insn & 0x0fe00000) == 0x00800000 && ((insn >> 16) & 0xf) == 0xf) {
                uint32_t rm = insn & 0xf;
                size_t lookback = off > 128 ? off - 128 : 0;
                for (size_t prev = lookback; prev < off; prev += 4) {
                    uint32_t pi = ru32(h.data(), h.size(), prev);
                    if ((pi & 0x0f7f0000) == 0x051f0000) {
                        uint32_t rt = (pi >> 12) & 0xf;
                        if (rt == rm) {
                            bool u = ((pi >> 23) & 1) != 0;
                            size_t imm = pi & 0xfff;
                            size_t lit;
                            bool ok = true;
                            if (u) lit = prev + 8 + imm;
                            else if (prev + 8 >= imm) lit = prev + 8 - imm;
                            else { ok = false; lit = 0; }
                            if (ok && lit + 4 <= h.size()) {
                                uint32_t val = ru32(h.data(), h.size(), lit);
                                uint32_t target = (uint32_t)off + 8 + val + start;
                                uint32_t lo = gotStart > 0x20 ? gotStart - 0x20 : 0;
                                if (target >= lo && target <= gotEnd + 0x20) wu32(h, lit, val + delta);
                            }
                        }
                    }
                }
            }
        }
    }
    return h;
}

Bytes ZImage::newTail(size_t payloadSz) const {
    if (tail.empty() || payloadSz == 0 || payloadSz == piggyLen) return tail;
    uint32_t start = ru32(head.data(), head.size(), 0x28);
    uint32_t origEnd = (uint32_t)head.size() + (uint32_t)piggyLen + start;
    uint32_t origGot = (origEnd + 3) & ~3u;
    size_t origPad = origGot - origEnd;
    uint32_t newEnd = (uint32_t)head.size() + (uint32_t)payloadSz + start;
    uint32_t newGot = (newEnd + 3) & ~3u;
    size_t newPad = newGot - newEnd;
    uint32_t delta = newGot - origGot;
    Bytes r(newPad, 0);
    if (origPad < tail.size()) r.insert(r.end(), tail.begin() + origPad, tail.end());
    if (offLc0) {
        for (size_t i = newPad; i + 4 <= r.size(); i += 4) {
            uint32_t v = rd32(r.data() + i);
            if (v == origEnd) wr32(r.data() + i, newEnd);
            else if (v >= origGot - 4) wr32(r.data() + i, v + delta);
        }
    }
    return r;
}

}
