#pragma once
#include "common.h"

namespace cu {

struct CpioEntry {
    std::string path;
    uint32_t mode = 0, uid = 0, gid = 0, mtime = 0, nlink = 1, ino = 0;
    uint32_t devmaj = 0, devmin = 0, rdevmaj = 0, rdevmin = 0;
    View data;
    std::string target;
    int archive = 0;
    bool skipped = false;
    int linkGroup = -1;
    bool linkPrimary = true;
};

struct CpioArchive {
    std::vector<CpioEntry> entries;
    std::string format = "070701";
    int archives = 0;
};

void cpioParse(View in, CpioArchive& out);

struct CpioOutEntry {
    std::string path;
    uint32_t mode = 0, uid = 0, gid = 0, mtime = 0, rdevmaj = 0, rdevmin = 0;
    std::string target;
    View data;
    uint32_t ino = 0, nlink = 0;
    bool noData = false;
};

class CpioWriter {
public:
    CpioWriter(Sink& s, bool crc) : s_(s), crc_(crc) {}
    uint32_t allocIno() { return ino_++; }
    void add(const CpioOutEntry& e);
    void finish();
private:
    Sink& s_;
    bool crc_;
    uint64_t pos_ = 0;
    uint32_t ino_ = 1;
    void put(const void* p, size_t n);
    void pad4();
};

std::string normalizeCpioPath(const std::string& p, bool& unsafe);

}
