#pragma once
#include "common.h"
#include "compress.h"

namespace cu {

typedef std::vector<std::pair<std::string, std::string>> KvList;

struct Probe {
    Fmt fmt = F_UNKNOWN;
    std::string how = "none";
    size_t offset = 0;
    KvList detail;
    std::vector<std::string> tried;
};

bool looksLikeCpio(const uint8_t* p, size_t n);
Probe probeStream(View v, const std::string& nameHint, bool allowScan);
Fmt probeFmt(View v);
void describeStream(Fmt f, View v, KvList& out);
std::string layersName(Fmt f);

}
