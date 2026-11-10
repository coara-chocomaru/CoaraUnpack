#pragma once
#include "common.h"

namespace cu {

enum Fmt {
    F_UNKNOWN = 0,
    F_CHROMEOS,
    F_AOSP,
    F_AOSP_VENDOR,
    F_DHTB,
    F_BLOB,
    F_GZIP,
    F_XZ,
    F_LZMA,
    F_BZIP2,
    F_LZ4,
    F_LZ4_LEGACY,
    F_LZ4_LG,
    F_LZOP,
    F_MTK,
    F_DTB,
    F_ZIMAGE
};

Fmt checkFmt(const uint8_t* p, size_t n);
const char* fmtName(Fmt f);
const char* fmtExt(Fmt f);
Fmt fmtFromName(const std::string& s);
bool fmtCompressed(Fmt f);
bool fmtCompressedAny(Fmt f);

void decompress(Fmt f, View in, Sink& out);
void compress(Fmt f, View in, Sink& out);

void gzipCompress(View in, Sink& out);
bool gzipCompressOpt(View in, Sink& out);
void gzipDecompress(View in, Sink& out);
void lz4BlockDecompress(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap, size_t& outLen);
size_t lz4BlockCompress(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap);
size_t lz4CompressBound(size_t n);
void lz4Compress(Fmt f, View in, Sink& out);
void lz4Decompress(Fmt f, View in, Sink& out);
void lzmaDecompressAlone(View in, Sink& out);
void xzDecompress(View in, Sink& out);
void lzmaCompressAlone(View in, Sink& out);
void xzCompress(View in, Sink& out);
void bzip2Decompress(View in, Sink& out);
void bzip2Compress(View in, Sink& out);

}
