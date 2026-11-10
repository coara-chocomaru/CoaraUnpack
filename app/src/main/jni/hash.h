#pragma once
#include "common.h"

namespace cu {

uint32_t crc32Update(uint32_t crc, const uint8_t* p, size_t n);
inline uint32_t crc32(const uint8_t* p, size_t n) { return crc32Update(0, p, n); }

uint32_t xxh32(const uint8_t* p, size_t n, uint32_t seed = 0);

class Md5 {
public:
    Md5();
    void update(const uint8_t* p, size_t n);
    void final(uint8_t out[16]);
private:
    uint32_t s_[4];
    uint64_t len_;
    uint8_t buf_[64];
    size_t fill_;
    void block(const uint8_t* b);
};

class Sha1 {
public:
    Sha1();
    void update(const uint8_t* p, size_t n);
    void final(uint8_t out[20]);
private:
    uint32_t h_[5];
    uint64_t len_;
    uint8_t buf_[64];
    size_t fill_;
    void block(const uint8_t* b);
};

class Sha256 {
public:
    Sha256();
    void update(const uint8_t* p, size_t n);
    void final(uint8_t out[32]);
private:
    uint32_t h_[8];
    uint64_t len_;
    uint8_t buf_[64];
    size_t fill_;
    void block(const uint8_t* b);
};

struct Digests {
    std::string md5, sha1, sha256;
    uint32_t crc = 0;
};

Digests digestAll(const uint8_t* p, size_t n);
std::string md5Hex(const uint8_t* p, size_t n);
std::string sha256Hex(const uint8_t* p, size_t n);
void sha1Raw(const uint8_t* p, size_t n, uint8_t out[20]);
void sha256Raw(const uint8_t* p, size_t n, uint8_t out[32]);

}
