#pragma once
#include "common.h"
#include "info.h"

namespace cu {

void avbDescribe(View vbmeta, InfoWriter& w, const std::string& prefix);
bool parseBootSignature(View tail, size_t& derLen, std::string& target, uint64_t& signedLen);

}
