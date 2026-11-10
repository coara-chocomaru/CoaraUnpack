#pragma once
#include "common.h"
#include "compress.h"

namespace cu {

struct ZImage {
    Bytes head;
    Bytes tail;
    size_t piggyLen = 0;
    Fmt fmt = F_UNKNOWN;
    uint32_t offInflatedSize = 0, offLc0 = 0, offLc1 = 0, offTable = 0;
    size_t piggyOff = 0;

    static std::unique_ptr<ZImage> parse(View z, View* piggyOut);
    Bytes newHead(size_t payloadSz) const;
    Bytes newTail(size_t payloadSz) const;
};

}
