#pragma once
#include "common.h"

namespace cu {

enum HKind { K_V0, K_V1, K_V2, K_V3, K_V4, K_PXA, K_VND3, K_VND4 };

const char* kindName(HKind k);
bool kindFromName(const std::string& s, HKind& k);

struct Hdr {
    HKind kind = K_V0;
    Bytes raw;

    void init(HKind k);
    static size_t structSize(HKind k);
    bool vendor() const { return kind == K_VND3 || kind == K_VND4; }
    size_t hdrSize() const { return raw.size(); }
    size_t hdrSpace() const;

    bool has(const char* key) const;
    uint64_t get(const char* key) const;
    bool set(const char* key, uint64_t v);

    uint32_t kernelSize() const { return (uint32_t)get("kernel_size"); }
    uint32_t ramdiskSize() const { return (uint32_t)get("ramdisk_size"); }
    uint32_t secondSize() const { return (uint32_t)get("second_size"); }
    uint32_t pageSize() const;
    uint32_t headerVersion() const;
    uint32_t extraSize() const { return (uint32_t)get("extra_size"); }
    uint32_t osVersion() const { return (uint32_t)get("os_version"); }
    uint32_t dtbSize() const { return (uint32_t)get("dtb_size"); }
    uint32_t recoveryDtboSize() const { return (uint32_t)get("recovery_dtbo_size"); }
    uint64_t recoveryDtboOffset() const { return get("recovery_dtbo_offset"); }
    uint32_t signatureSize() const { return (uint32_t)get("signature_size"); }
    uint32_t vrTableSize() const { return (uint32_t)get("vendor_ramdisk_table_size"); }
    uint32_t vrEntryNum() const { return (uint32_t)get("vendor_ramdisk_table_entry_num"); }
    uint32_t vrEntrySize() const { return (uint32_t)get("vendor_ramdisk_table_entry_size"); }
    uint32_t bootconfigSize() const { return (uint32_t)get("bootconfig_size"); }

    bool hasName() const;
    std::string name() const;
    void setName(const std::string& s);
    std::string cmdline() const;
    void setCmdline(const std::string& s);
    bool hasId() const;
    Bytes id() const;
    void setId(const uint8_t* p, size_t n);
    Bytes reserved() const;
    void setReserved(const Bytes& b);
    std::string magic() const { return std::string((const char*)raw.data(), 8); }
};

std::string osVersionStr(uint32_t v);
std::string osPatchStr(uint32_t v);
uint32_t osVersionPack(uint32_t oldv, const std::string* ver, const std::string* patch);

}
