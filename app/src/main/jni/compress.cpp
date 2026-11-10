#include "compress.h"
#include <new>
#include <zlib.h>

namespace cu {

static bool startsWith(const uint8_t* p, size_t n, const char* m, size_t ml) {
    return n >= ml && memcmp(p, m, ml) == 0;
}

static uint32_t crc32ieee(const uint8_t* p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++) crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
    }
    return ~crc;
}

static bool checkXz(const uint8_t* p, size_t n) {
    if (n < 12 || !startsWith(p, n, "\xfd" "7zXZ\x00", 6)) return false;
    if (p[6] != 0 || (p[7] & 0xF0) != 0) return false;
    int id = p[7] & 0x0F;
    if (!(id == 0 || id == 1 || id == 4 || id == 10)) return false;
    return crc32ieee(p + 6, 2) == rd32(p + 8);
}

static bool checkGzip(const uint8_t* p, size_t n) {
    if (n >= 10 && p[0] == 0x1f && p[1] == 0x8b && p[2] == 8 && (p[3] & 0xe0) == 0) return true;
    return n >= 2 && p[0] == 0x1f && p[1] == 0x9e;
}

static bool checkBzip2(const uint8_t* p, size_t n) {
    return n >= 10 && p[0] == 'B' && p[1] == 'Z' && p[2] == 'h' && p[3] >= '1' && p[3] <= '9' &&
           memcmp(p + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0;
}

static bool guessLzma(const uint8_t* p, size_t n) {
    if (n <= 13 || p[0] != 0x5d) return false;
    uint32_t d = rd32(p + 1);
    if (d == 0 || (d & (d - 1))) return false;
    for (int i = 5; i < 13; i++) if (p[i] != 0xff) return false;
    return true;
}

Fmt checkFmt(const uint8_t* p, size_t n) {
    if (startsWith(p, n, "CHROMEOS", 8)) return F_CHROMEOS;
    if (startsWith(p, n, "ANDROID!", 8)) return F_AOSP;
    if (startsWith(p, n, "VNDRBOOT", 8)) return F_AOSP_VENDOR;
    if (checkGzip(p, n)) return F_GZIP;
    if (startsWith(p, n, "\x89LZO\x00\x0d\x0a\x1a\x0a", 9)) return F_LZOP;
    if (checkXz(p, n)) return F_XZ;
    if (guessLzma(p, n)) return F_LZMA;
    if (checkBzip2(p, n)) return F_BZIP2;
    if (startsWith(p, n, "\x03\x21\x4c\x18", 4) || startsWith(p, n, "\x04\x22\x4d\x18", 4)) return F_LZ4;
    if (startsWith(p, n, "\x02\x21\x4c\x18", 4)) return F_LZ4_LEGACY;
    if (startsWith(p, n, "\x88\x16\x88\x58", 4)) return F_MTK;
    if (startsWith(p, n, "\xd0\x0d\xfe\xed", 4)) return F_DTB;
    if (startsWith(p, n, "\x44\x48\x54\x42\x01\x00\x00\x00", 8)) return F_DHTB;
    if (startsWith(p, n, "-SIGNED-BY-SIGNBLOB-", 20)) return F_BLOB;
    if (n >= 0x28 && memcmp(p + 0x24, "\x18\x28\x6f\x01", 4) == 0) return F_ZIMAGE;
    return F_UNKNOWN;
}

const char* fmtName(Fmt f) {
    switch (f) {
    case F_GZIP: return "gzip";
    case F_LZOP: return "lzop";
    case F_XZ: return "xz";
    case F_LZMA: return "lzma";
    case F_BZIP2: return "bzip2";
    case F_LZ4: return "lz4";
    case F_LZ4_LEGACY: return "lz4_legacy";
    case F_LZ4_LG: return "lz4_lg";
    case F_DTB: return "dtb";
    case F_ZIMAGE: return "zimage";
    case F_MTK: return "mtk";
    case F_AOSP: return "aosp";
    case F_AOSP_VENDOR: return "aosp_vendor";
    case F_DHTB: return "dhtb";
    case F_BLOB: return "blob";
    case F_CHROMEOS: return "chromeos";
    default: return "raw";
    }
}

const char* fmtExt(Fmt f) {
    switch (f) {
    case F_GZIP: return "gz";
    case F_LZOP: return "lzo";
    case F_XZ: return "xz";
    case F_LZMA: return "lzma";
    case F_BZIP2: return "bz2";
    case F_LZ4: case F_LZ4_LEGACY: case F_LZ4_LG: return "lz4";
    default: return "";
    }
}

Fmt fmtFromName(const std::string& s) {
    if (s == "gzip") return F_GZIP;
    if (s == "xz") return F_XZ;
    if (s == "lzma") return F_LZMA;
    if (s == "bzip2") return F_BZIP2;
    if (s == "lz4") return F_LZ4;
    if (s == "lz4_legacy") return F_LZ4_LEGACY;
    if (s == "lz4_lg") return F_LZ4_LG;
    return F_UNKNOWN;
}

bool fmtCompressed(Fmt f) {
    return f == F_GZIP || f == F_XZ || f == F_LZMA || f == F_BZIP2 || f == F_LZ4 || f == F_LZ4_LEGACY || f == F_LZ4_LG;
}

bool fmtCompressedAny(Fmt f) { return fmtCompressed(f) || f == F_LZOP; }

namespace {

struct InflateGuard {
    z_stream* z;
    explicit InflateGuard(z_stream* p) : z(p) {}
    ~InflateGuard() { inflateEnd(z); }
};

struct DeflateGuard {
    z_stream* z;
    explicit DeflateGuard(z_stream* p) : z(p) {}
    ~DeflateGuard() { deflateEnd(z); }
};

}

void gzipDecompress(View in, Sink& out) {
    const uint8_t* p = in.p;
    size_t n = in.size();
    size_t pos = 0;
    std::unique_ptr<uint8_t[]> obuf(new uint8_t[1 << 18]);
    int members = 0;
    while (pos < n) {
        if (n - pos < 10 || p[pos] != 0x1f || (p[pos + 1] != 0x8b && p[pos + 1] != 0x9e)) {
            if (members) break;
            throw Error("gzipじゃないみたい");
        }
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 16 + 15) != Z_OK) throw Error("zlibの初期化に失敗したよ");
        InflateGuard guard(&zs);
        zs.next_in = const_cast<uint8_t*>(p + pos);
        zs.avail_in = (uInt)std::min<size_t>(n - pos, 0x7FFFFFFF);
        int ret;
        do {
            zs.next_out = obuf.get();
            zs.avail_out = 1 << 18;
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END) {
                if (ret == Z_BUF_ERROR && members) goto done;
                throw Error(fmtstr("gzipの展開に失敗したよ(%d)", ret));
            }
            size_t got = (1 << 18) - zs.avail_out;
            if (got) out.write(obuf.get(), got);
            checkCancel();
            if (ret == Z_OK && zs.avail_in == 0 && zs.avail_out != 0) {
                throw Error("gzipが途中で切れてるよ");
            }
        } while (ret != Z_STREAM_END);
        pos += zs.total_in;
        members++;
        while (pos < n && p[pos] == 0) pos++;
    }
done:
    return;
}

static void gzipCompressZlib(View in, Sink& out) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, 9, Z_DEFLATED, 16 + 15, 9, Z_DEFAULT_STRATEGY) != Z_OK) throw Error("zlibの初期化に失敗したよ");
    DeflateGuard guard(&zs);
    std::unique_ptr<uint8_t[]> obuf(new uint8_t[1 << 18]);
    size_t pos = 0, n = in.size();
    int ret;
    do {
        size_t chunk = std::min<size_t>(n - pos, 1 << 20);
        zs.next_in = const_cast<uint8_t*>(in.p + pos);
        zs.avail_in = (uInt)chunk;
        pos += chunk;
        int flush = pos >= n ? Z_FINISH : Z_NO_FLUSH;
        do {
            zs.next_out = obuf.get();
            zs.avail_out = 1 << 18;
            ret = deflate(&zs, flush);
            if (ret == Z_STREAM_ERROR) throw Error("gzip圧縮に失敗したよ");
            size_t got = (1 << 18) - zs.avail_out;
            if (got) out.write(obuf.get(), got);
        } while (zs.avail_out == 0);
        subProgress(n ? (int)(pos * 100 / n) : 100);
        checkCancel();
    } while (pos < n || ret != Z_STREAM_END);
}

void gzipCompress(View in, Sink& out) {
    VecSink a;
    gzipCompressZlib(in, a);
    VecSink b;
    bool ok = false;
    try {
        ok = gzipCompressOpt(in, b);
    } catch (const std::bad_alloc&) {
        ok = false;
    }
    if (ok && b.v.size() < a.v.size()) out.write(b.v.data(), b.v.size());
    else out.write(a.v.data(), a.v.size());
}

void decompress(Fmt f, View in, Sink& out) {
    switch (f) {
    case F_GZIP: gzipDecompress(in, out); break;
    case F_XZ: xzDecompress(in, out); break;
    case F_LZMA: lzmaDecompressAlone(in, out); break;
    case F_BZIP2: bzip2Decompress(in, out); break;
    case F_LZ4: case F_LZ4_LEGACY: case F_LZ4_LG: lz4Decompress(f, in, out); break;
    default: throw Error(fmtstr("この形式は展開できないよ: %s", fmtName(f)));
    }
}

void compress(Fmt f, View in, Sink& out) {
    switch (f) {
    case F_GZIP: gzipCompress(in, out); break;
    case F_XZ: xzCompress(in, out); break;
    case F_LZMA: lzmaCompressAlone(in, out); break;
    case F_BZIP2: bzip2Compress(in, out); break;
    case F_LZ4: case F_LZ4_LEGACY: case F_LZ4_LG: lz4Compress(f, in, out); break;
    default: throw Error(fmtstr("この形式には圧縮できないよ: %s", fmtName(f)));
    }
}

}
