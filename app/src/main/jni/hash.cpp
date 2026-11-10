#include "hash.h"

namespace cu {

static uint32_t g_crc_tab[8][256];
static bool g_crc_init = false;

static void crcInit() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
        g_crc_tab[0][i] = c;
    }
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = g_crc_tab[0][i];
        for (int t = 1; t < 8; t++) {
            c = g_crc_tab[0][c & 0xff] ^ (c >> 8);
            g_crc_tab[t][i] = c;
        }
    }
    g_crc_init = true;
}

uint32_t crc32Update(uint32_t crc, const uint8_t* p, size_t n) {
    if (!g_crc_init) crcInit();
    crc = ~crc;
    while (n >= 8) {
        uint32_t a = rd32(p) ^ crc;
        uint32_t b = rd32(p + 4);
        crc = g_crc_tab[7][a & 0xff] ^ g_crc_tab[6][(a >> 8) & 0xff] ^ g_crc_tab[5][(a >> 16) & 0xff] ^
              g_crc_tab[4][a >> 24] ^ g_crc_tab[3][b & 0xff] ^ g_crc_tab[2][(b >> 8) & 0xff] ^
              g_crc_tab[1][(b >> 16) & 0xff] ^ g_crc_tab[0][b >> 24];
        p += 8;
        n -= 8;
    }
    while (n--) crc = g_crc_tab[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static inline uint32_t rotl(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

uint32_t xxh32(const uint8_t* p, size_t n, uint32_t seed) {
    const uint32_t P1 = 2654435761u, P2 = 2246822519u, P3 = 3266489917u, P4 = 668265263u, P5 = 374761393u;
    const uint8_t* end = p + n;
    uint32_t h;
    if (n >= 16) {
        uint32_t v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
        const uint8_t* lim = end - 16;
        do {
            v1 = rotl(v1 + rd32(p) * P2, 13) * P1; p += 4;
            v2 = rotl(v2 + rd32(p) * P2, 13) * P1; p += 4;
            v3 = rotl(v3 + rd32(p) * P2, 13) * P1; p += 4;
            v4 = rotl(v4 + rd32(p) * P2, 13) * P1; p += 4;
        } while (p <= lim);
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    } else {
        h = seed + P5;
    }
    h += (uint32_t)n;
    while (p + 4 <= end) {
        h = rotl(h + rd32(p) * P3, 17) * P4;
        p += 4;
    }
    while (p < end) {
        h = rotl(h + (*p++) * P5, 11) * P1;
    }
    h ^= h >> 15; h *= P2; h ^= h >> 13; h *= P3; h ^= h >> 16;
    return h;
}

static const uint32_t MD5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
static const int MD5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
                             14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                             4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

Md5::Md5() : len_(0), fill_(0) {
    s_[0] = 0x67452301; s_[1] = 0xefcdab89; s_[2] = 0x98badcfe; s_[3] = 0x10325476;
}

void Md5::block(const uint8_t* b) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++) M[i] = rd32(b + i * 4);
    uint32_t A = s_[0], B = s_[1], C = s_[2], D = s_[3];
    for (int i = 0; i < 64; i++) {
        uint32_t F;
        int g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = F + A + MD5K[i] + M[g];
        A = D; D = C; C = B;
        B = B + rotl(F, MD5S[i]);
    }
    s_[0] += A; s_[1] += B; s_[2] += C; s_[3] += D;
}

void Md5::update(const uint8_t* p, size_t n) {
    len_ += n;
    if (fill_) {
        size_t c = std::min(n, 64 - fill_);
        memcpy(buf_ + fill_, p, c);
        fill_ += c; p += c; n -= c;
        if (fill_ == 64) { block(buf_); fill_ = 0; }
    }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf_, p, n); fill_ = n; }
}

void Md5::final(uint8_t out[16]) {
    uint64_t bits = len_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t z = 0;
    while (fill_ != 56) update(&z, 1);
    uint8_t l[8];
    wr64(l, bits);
    update(l, 8);
    for (int i = 0; i < 4; i++) wr32(out + i * 4, s_[i]);
}

Sha1::Sha1() : len_(0), fill_(0) {
    h_[0] = 0x67452301; h_[1] = 0xEFCDAB89; h_[2] = 0x98BADCFE; h_[3] = 0x10325476; h_[4] = 0xC3D2E1F0;
}

void Sha1::block(const uint8_t* b) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = rd32be(b + i * 4);
    for (int i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h_[0], bb = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (bb & c) | (~bb & d); k = 0x5A827999; }
        else if (i < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t t = rotl(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl(bb, 30); bb = a; a = t;
    }
    h_[0] += a; h_[1] += bb; h_[2] += c; h_[3] += d; h_[4] += e;
}

void Sha1::update(const uint8_t* p, size_t n) {
    len_ += n;
    if (fill_) {
        size_t c = std::min(n, 64 - fill_);
        memcpy(buf_ + fill_, p, c);
        fill_ += c; p += c; n -= c;
        if (fill_ == 64) { block(buf_); fill_ = 0; }
    }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf_, p, n); fill_ = n; }
}

void Sha1::final(uint8_t out[20]) {
    uint64_t bits = len_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t z = 0;
    while (fill_ != 56) update(&z, 1);
    uint8_t l[8];
    wr64be(l, bits);
    update(l, 8);
    for (int i = 0; i < 5; i++) wr32be(out + i * 4, h_[i]);
}

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t rotr(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

Sha256::Sha256() : len_(0), fill_(0) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(h_, iv, sizeof(h_));
}

void Sha256::block(const uint8_t* b) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = rd32be(b + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], bb = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += bb; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const uint8_t* p, size_t n) {
    len_ += n;
    if (fill_) {
        size_t c = std::min(n, 64 - fill_);
        memcpy(buf_ + fill_, p, c);
        fill_ += c; p += c; n -= c;
        if (fill_ == 64) { block(buf_); fill_ = 0; }
    }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf_, p, n); fill_ = n; }
}

void Sha256::final(uint8_t out[32]) {
    uint64_t bits = len_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t z = 0;
    while (fill_ != 56) update(&z, 1);
    uint8_t l[8];
    wr64be(l, bits);
    update(l, 8);
    for (int i = 0; i < 8; i++) wr32be(out + i * 4, h_[i]);
}

Digests digestAll(const uint8_t* p, size_t n) {
    Md5 m; Sha1 s1; Sha256 s2;
    uint32_t crc = 0;
    size_t off = 0;
    while (off < n) {
        size_t c = std::min<size_t>(n - off, 1 << 20);
        m.update(p + off, c);
        s1.update(p + off, c);
        s2.update(p + off, c);
        crc = crc32Update(crc, p + off, c);
        off += c;
        if (n > (4u << 20)) {
            checkCancel();
            subProgress((int)((uint64_t)off * 100 / n));
        }
    }
    uint8_t a[16], b[20], c2[32];
    m.final(a); s1.final(b); s2.final(c2);
    Digests d;
    d.md5 = hex(a, 16);
    d.sha1 = hex(b, 20);
    d.sha256 = hex(c2, 32);
    d.crc = crc;
    return d;
}

std::string md5Hex(const uint8_t* p, size_t n) {
    Md5 m;
    m.update(p, n);
    uint8_t o[16];
    m.final(o);
    return hex(o, 16);
}

std::string sha256Hex(const uint8_t* p, size_t n) {
    uint8_t o[32];
    sha256Raw(p, n, o);
    return hex(o, 32);
}

void sha1Raw(const uint8_t* p, size_t n, uint8_t out[20]) {
    Sha1 s;
    s.update(p, n);
    s.final(out);
}

void sha256Raw(const uint8_t* p, size_t n, uint8_t out[32]) {
    Sha256 s;
    s.update(p, n);
    s.final(out);
}

}
