#pragma once
#include "common.h"

namespace cu {

struct DtbChain {
    size_t count = 0;
    size_t end = 0;
    bool toEnd = false;
};

int findDtbOffset(const uint8_t* p, size_t n);
DtbChain dtbChain(const uint8_t* p, size_t n, size_t from);
std::string dtbFieldKind(const uint8_t* p, size_t n);
void dtbDescribe(View blob, const std::string& prefix, std::vector<std::string>& lines);
void dtboDescribe(View blob, const std::string& prefix, std::vector<std::string>& lines);

}
