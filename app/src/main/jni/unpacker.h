#pragma once
#include "common.h"
#include "compress.h"

namespace cu {

struct RdRepackOpts {
    std::string fmt = "auto";
    bool force0777 = false;
};

struct BootUnpackOpts {
    bool skipDecomp = false;
    bool extractRamdisk = false;
};

struct BootRepackOpts {
    bool skipComp = false;
    bool padToOriginal = true;
    bool forceRebuild = false;
    std::string ramdiskFmt = "auto";
    std::string kernelFmt = "auto";
};

void ramdiskUnpack(const std::string& inFile, const std::string& outDir);
void ramdiskRepack(const std::string& dir, const std::string& outFile, const RdRepackOpts& o);
void bootUnpack(const std::string& imgPath, const std::string& outDir, const BootUnpackOpts& o);
void bootRepack(const std::string& dir, const std::string& outFile, const BootRepackOpts& o);

Fmt checkFmtLg(const uint8_t* p, size_t n);
std::string splitTabJoin(const std::vector<std::string>& v);
std::vector<std::string> splitTab(const std::string& s);

}
