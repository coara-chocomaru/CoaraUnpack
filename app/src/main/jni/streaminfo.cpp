#include "streaminfo.h"
#include "unpacker.h"

namespace cu {

namespace {

struct Enough {};

class CapSink : public Sink {
public:
    Bytes head;
    void write(const uint8_t* p, size_t n) override {
        size_t take = std::min(n, (size_t)16 - head.size());
        head.insert(head.end(), p, p + take);
        total_ += n;
        if (head.size() >= 16) throw Enough();
    }
};

bool trialDecode(Fmt f, View v) {
    CapSink c;
    try {
        decompress(f, v.sub(0, std::min<size_t>(v.n, (size_t)16 << 20)), c);
    } catch (const Enough&) {
    } catch (const Canceled&) {
        throw;
    } catch (...) {
        return false;
    }
    return looksLikeCpio(c.head.data(), c.head.size());
}

bool lzmaPlausible(const uint8_t* p, size_t n) {
    if (n < 14 || p[0] >= 225) return false;
    uint32_t d = rd32(p + 1);
    if (d < 4096 || d > (1u << 31)) return false;
    uint64_t us = rd64(p + 5);
    if (us != ~0ull && us > ((uint64_t)1 << 36)) return false;
    return true;
}

std::string ext(const std::string& name) {
    size_t d = name.rfind('.');
    if (d == std::string::npos) return "";
    std::string e = name.substr(d + 1);
    for (auto& c : e) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return e;
}

Fmt fromExt(const std::string& e) {
    if (e == "gz" || e == "gzip") return F_GZIP;
    if (e == "xz") return F_XZ;
    if (e == "lzma") return F_LZMA;
    if (e == "bz2" || e == "bz" || e == "bzip2") return F_BZIP2;
    if (e == "lz4") return F_LZ4_LEGACY;
    return F_UNKNOWN;
}

uint64_t varint(const uint8_t* p, size_t n, size_t& i) {
    uint64_t r = 0;
    int sh = 0;
    while (i < n && sh < 63) {
        uint8_t b = p[i++];
        r |= (uint64_t)(b & 0x7f) << sh;
        if (!(b & 0x80)) break;
        sh += 7;
    }
    return r;
}

}

bool looksLikeCpio(const uint8_t* p, size_t n) {
    return n >= 6 && memcmp(p, "07070", 5) == 0 && (p[5] == '1' || p[5] == '2' || p[5] == '7');
}

std::string layersName(Fmt f) { return fmtCompressed(f) ? fmtName(f) : "raw"; }

void describeStream(Fmt f, View v, KvList& o) {
    const uint8_t* p = v.p;
    size_t n = v.n;
    auto add = [&](const std::string& k, const std::string& val) { o.push_back(std::make_pair(k, val)); };
    switch (f) {
    case F_GZIP:
        if (n >= 10) {
            add("gzip.method", p[2] == 8 ? "deflate" : "unknown");
            add("gzip.flags", fmtstr("0x%02x", p[3]));
            add("gzip.mtime", fmtstr("%u", rd32(p + 4)));
            add("gzip.xfl", p[8] == 2 ? "2(best)" : p[8] == 4 ? "4(fast)" : fmtstr("%u", p[8]));
            add("gzip.os", fmtstr("%u", p[9]));
            if (n >= 18) add("gzip.last_isize_mod32", fmtstr("%u", rd32(p + n - 4)));
        }
        break;
    case F_XZ:
        if (n >= 12) {
            static const char* chk[] = {"none", "crc32", "?", "?", "crc64", "?", "?", "?", "?", "?", "sha256"};
            int id = p[7] & 15;
            add("xz.check", id < 11 ? chk[id] : "?");
            size_t i = 12;
            if (i < n) {
                size_t hsz = ((size_t)p[i] + 1) * 4;
                if (hsz >= 8 && i + hsz <= n) {
                    uint8_t fl = p[i + 1];
                    size_t q = i + 2;
                    if (fl & 0x40) varint(p, i + hsz, q);
                    if (fl & 0x80) varint(p, i + hsz, q);
                    std::string filters;
                    for (int k = 0; k <= (fl & 3); k++) {
                        uint64_t fid = varint(p, i + hsz, q);
                        uint64_t ps = varint(p, i + hsz, q);
                        std::string nm = fid == 0x21 ? "lzma2" : fid == 0x03 ? "delta" : fid == 0x04 ? "x86" : fid == 0x05 ? "powerpc" :
                                         fid == 0x06 ? "ia64" : fid == 0x07 ? "arm" : fid == 0x08 ? "armthumb" : fid == 0x09 ? "sparc" :
                                         fid == 0x0a ? "arm64" : fmtstr("0x%llx", (unsigned long long)fid);
                        if (fid == 0x21 && ps >= 1 && q < n) {
                            uint8_t d = p[q];
                            if (d < 40) add("xz.dict_size", fmtstr("%llu", (unsigned long long)((uint64_t)(2 | (d & 1)) << (d / 2 + 11))));
                        }
                        q += (size_t)ps;
                        filters += std::string(filters.empty() ? "" : ",") + nm;
                    }
                    add("xz.filters", filters);
                }
            }
        }
        break;
    case F_LZMA:
        if (n >= 13) {
            uint8_t b = p[0];
            add("lzma.lc", fmtstr("%u", b % 9));
            add("lzma.lp", fmtstr("%u", (b / 9) % 5));
            add("lzma.pb", fmtstr("%u", b / 45));
            add("lzma.dict_size", fmtstr("%u", rd32(p + 1)));
            uint64_t us = rd64(p + 5);
            add("lzma.uncompressed_size", us == ~0ull ? "unknown(eos)" : fmtstr("%llu", (unsigned long long)us));
        }
        break;
    case F_BZIP2:
        if (n >= 4) add("bzip2.block_size", fmtstr("%u00k", p[3] - '0'));
        break;
    case F_LZ4:
        if (n >= 7 && rd32(p) == 0x184D2204u) {
            uint8_t flg = p[4], bd = p[5];
            add("lz4.version", fmtstr("%u", flg >> 6));
            add("lz4.block_independent", (flg & 0x20) ? "true" : "false");
            add("lz4.block_checksum", (flg & 0x10) ? "true" : "false");
            add("lz4.content_size", (flg & 0x08) ? "true" : "false");
            add("lz4.content_checksum", (flg & 0x04) ? "true" : "false");
            int bs = (bd >> 4) & 7;
            static const char* names[] = {"?", "?", "?", "?", "64KiB", "256KiB", "1MiB", "4MiB"};
            add("lz4.block_max", names[bs]);
        } else {
            add("lz4.frame", "skippable-or-unknown");
        }
        break;
    case F_LZ4_LEGACY:
    case F_LZ4_LG: {
        size_t off = 0, blocks = 0, streams = 0;
        uint32_t maxb = 0;
        while (off + 4 <= n) {
            uint32_t w = rd32(p + off);
            if (w == 0x184C2102u) {
                streams++;
                off += 4;
                continue;
            }
            if (off + 4 + w > n) break;
            if (w > maxb) maxb = w;
            blocks++;
            off += 4 + w;
        }
        add("lz4_legacy.streams", fmtstr("%zu", streams));
        add("lz4_legacy.blocks", fmtstr("%zu", blocks));
        add("lz4_legacy.max_block_compressed", fmtstr("%u", maxb));
        add("lz4_legacy.block_size", "8MiB");
        add("lz4_legacy.lg_trailer", f == F_LZ4_LG ? "true" : "false");
        if (f == F_LZ4_LG && n >= 4) add("lz4_legacy.lg_uncompressed_size", fmtstr("%u", rd32(p + n - 4)));
        break;
    }
    default:
        break;
    }
}

Fmt probeFmt(View v) {
    Probe pr = probeStream(v, "", false);
    return pr.offset == 0 ? pr.fmt : F_UNKNOWN;
}

Probe probeStream(View v, const std::string& nameHint, bool allowScan) {
    Probe r;
    if (v.n == 0) return r;
    Fmt m = checkFmtLg(v.p, v.n);
    if (m == F_LZOP) {
        r.fmt = m;
        r.how = "magic";
        r.tried.push_back("magic:lzop");
        return r;
    }
    if (fmtCompressed(m)) {
        r.fmt = m;
        r.how = "magic";
        r.tried.push_back(std::string("magic:") + fmtName(m));
        describeStream(m, v, r.detail);
        return r;
    }
    if (looksLikeCpio(v.p, v.n)) {
        r.fmt = F_UNKNOWN;
        r.how = "cpio-magic";
        r.tried.push_back("magic:cpio");
        return r;
    }
    static const Fmt order[] = {F_LZMA, F_GZIP, F_XZ, F_BZIP2, F_LZ4_LEGACY, F_LZ4};
    Fmt hint = fromExt(ext(nameHint));
    if (hint != F_UNKNOWN) {
        r.tried.push_back(std::string("extension:") + fmtName(hint));
        if (trialDecode(hint, v)) {
            r.fmt = hint == F_LZ4_LEGACY ? checkFmtLg(v.p, v.n) : hint;
            if (!fmtCompressed(r.fmt)) r.fmt = hint;
            r.how = "extension+trial";
            describeStream(r.fmt, v, r.detail);
            return r;
        }
    }
    if (lzmaPlausible(v.p, v.n)) {
        r.tried.push_back("lzma-heuristic");
        if (trialDecode(F_LZMA, v)) {
            r.fmt = F_LZMA;
            r.how = "lzma-heuristic+trial";
            describeStream(F_LZMA, v, r.detail);
            return r;
        }
    }
    for (Fmt f : order) {
        r.tried.push_back(std::string("trial:") + fmtName(f));
        if (trialDecode(f, v)) {
            r.fmt = f == F_LZ4_LEGACY ? checkFmtLg(v.p, v.n) : f;
            if (!fmtCompressed(r.fmt)) r.fmt = f;
            r.how = "trial";
            describeStream(r.fmt, v, r.detail);
            return r;
        }
    }
    if (!allowScan) return r;
    size_t lim = std::min<size_t>(v.n, 1 << 16);
    for (size_t i = 1; i + 8 < lim; i++) {
        Fmt f = checkFmtLg(v.p + i, v.n - i);
        if (fmtCompressed(f) || looksLikeCpio(v.p + i, v.n - i)) {
            View sub = v.from(i);
            if (fmtCompressed(f) ? trialDecode(f, sub) : true) {
                r.tried.push_back(fmtstr("scan@%zu", i));
                r.fmt = fmtCompressed(f) ? f : F_UNKNOWN;
                r.offset = i;
                r.how = "scan";
                if (fmtCompressed(f)) describeStream(f, sub, r.detail);
                return r;
            }
        }
    }
    r.tried.push_back("scan:none");
    return r;
}

}
