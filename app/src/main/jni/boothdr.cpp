#include "boothdr.h"

namespace cu {

namespace {

struct Fld {
    const char* key;
    uint16_t off;
    uint8_t sz;
};

const Fld F_V012[] = {
    {"kernel_size", 8, 4}, {"kernel_addr", 12, 4}, {"ramdisk_size", 16, 4}, {"ramdisk_addr", 20, 4},
    {"second_size", 24, 4}, {"second_addr", 28, 4}, {"tags_addr", 32, 4}, {"page_size", 36, 4},
    {"os_version", 44, 4},
    {"recovery_dtbo_size", 1632, 4}, {"recovery_dtbo_offset", 1636, 8}, {"header_size", 1644, 4},
    {"dtb_size", 1648, 4}, {"dtb_addr", 1652, 8},
    {nullptr, 0, 0}};

const Fld F_PXA[] = {
    {"kernel_size", 8, 4}, {"kernel_addr", 12, 4}, {"ramdisk_size", 16, 4}, {"ramdisk_addr", 20, 4},
    {"second_size", 24, 4}, {"second_addr", 28, 4}, {"extra_size", 32, 4}, {"unknown", 36, 4},
    {"tags_addr", 40, 4}, {"page_size", 44, 4},
    {nullptr, 0, 0}};

const Fld F_V34[] = {
    {"kernel_size", 8, 4}, {"ramdisk_size", 12, 4}, {"os_version", 16, 4}, {"header_size", 20, 4},
    {"header_version", 40, 4}, {"signature_size", 1580, 4},
    {nullptr, 0, 0}};

const Fld F_VND[] = {
    {"header_version", 8, 4}, {"page_size", 12, 4}, {"kernel_addr", 16, 4}, {"ramdisk_addr", 20, 4},
    {"ramdisk_size", 24, 4}, {"tags_addr", 2076, 4}, {"header_size", 2096, 4}, {"dtb_size", 2100, 4},
    {"dtb_addr", 2104, 8},
    {"vendor_ramdisk_table_size", 2112, 4}, {"vendor_ramdisk_table_entry_num", 2116, 4},
    {"vendor_ramdisk_table_entry_size", 2120, 4}, {"bootconfig_size", 2124, 4},
    {nullptr, 0, 0}};

const Fld* table(HKind k) {
    switch (k) {
    case K_V0: case K_V1: case K_V2: return F_V012;
    case K_PXA: return F_PXA;
    case K_V3: case K_V4: return F_V34;
    default: return F_VND;
    }
}

struct StrLoc { size_t off, len; };

}

const char* kindName(HKind k) {
    switch (k) {
    case K_V0: return "v0";
    case K_V1: return "v1";
    case K_V2: return "v2";
    case K_V3: return "v3";
    case K_V4: return "v4";
    case K_PXA: return "pxa";
    case K_VND3: return "vendor_v3";
    default: return "vendor_v4";
    }
}

bool kindFromName(const std::string& s, HKind& k) {
    static const HKind all[] = {K_V0, K_V1, K_V2, K_V3, K_V4, K_PXA, K_VND3, K_VND4};
    for (HKind c : all) if (s == kindName(c)) { k = c; return true; }
    return false;
}

size_t Hdr::structSize(HKind k) {
    switch (k) {
    case K_V0: return 1632;
    case K_V1: return 1648;
    case K_V2: return 1660;
    case K_PXA: return 1640;
    case K_V3: return 1580;
    case K_V4: return 1584;
    case K_VND3: return 2112;
    default: return 2128;
    }
}

void Hdr::init(HKind k) {
    kind = k;
    raw.assign(structSize(k), 0);
}

size_t Hdr::hdrSpace() const {
    if (vendor()) return (size_t)alignUp(hdrSize(), pageSize());
    return pageSize();
}

bool Hdr::has(const char* key) const {
    if (raw.empty()) return false;
    if (!strcmp(key, "header_version")) {
        return kind == K_V1 || kind == K_V2 || kind == K_V3 || kind == K_V4 || vendor();
    }
    if (!strcmp(key, "extra_size") && kind == K_V0) return true;
    for (const Fld* f = table(kind); f->key; f++)
        if (!strcmp(f->key, key)) return (size_t)f->off + f->sz <= raw.size();
    return false;
}

uint64_t Hdr::get(const char* key) const {
    if (raw.empty()) return 0;
    if (kind == K_V0 && !strcmp(key, "extra_size")) return rd32(raw.data() + 40);
    if ((kind == K_V1 || kind == K_V2) && !strcmp(key, "header_version")) return rd32(raw.data() + 40);
    if (kind == K_V0 && !strcmp(key, "header_version")) return 0;
    for (const Fld* f = table(kind); f->key; f++) {
        if (!strcmp(f->key, key)) {
            if ((size_t)f->off + f->sz > raw.size()) return 0;
            return f->sz == 8 ? rd64(raw.data() + f->off) : rd32(raw.data() + f->off);
        }
    }
    return 0;
}

bool Hdr::set(const char* key, uint64_t v) {
    if (raw.empty()) return false;
    if (kind == K_V0 && !strcmp(key, "extra_size")) { wr32(raw.data() + 40, (uint32_t)v); return true; }
    if ((kind == K_V1 || kind == K_V2) && !strcmp(key, "header_version")) { wr32(raw.data() + 40, (uint32_t)v); return true; }
    for (const Fld* f = table(kind); f->key; f++) {
        if (!strcmp(f->key, key)) {
            if ((size_t)f->off + f->sz > raw.size()) return false;
            if (f->sz == 8) wr64(raw.data() + f->off, v); else wr32(raw.data() + f->off, (uint32_t)v);
            return true;
        }
    }
    return false;
}

uint32_t Hdr::pageSize() const {
    if (kind == K_V3 || kind == K_V4) return 4096;
    uint32_t p = (uint32_t)get("page_size");
    return p ? p : 4096;
}

uint32_t Hdr::headerVersion() const {
    switch (kind) {
    case K_V3: return 3;
    case K_V4: return 4;
    default: return (uint32_t)get("header_version");
    }
}

static bool strLoc(HKind k, int which, StrLoc& l) {

    switch (k) {
    case K_V0: case K_V1: case K_V2:
        static const StrLoc a[] = {{48, 16}, {64, 512}, {576, 32}, {608, 1024}};
        l = a[which];
        return true;
    case K_PXA:
        static const StrLoc b[] = {{48, 24}, {72, 512}, {584, 32}, {616, 1024}};
        l = b[which];
        return true;
    case K_V3: case K_V4:
        if (which == 1) { l = {44, 512}; return true; }
        if (which == 3) { l = {44 + 512, 1024}; return true; }
        return false;
    default:
        if (which == 0) { l = {2080, 16}; return true; }
        if (which == 1) { l = {28, 512}; return true; }
        if (which == 3) { l = {28 + 512, 1536}; return true; }
        return false;
    }
}

bool Hdr::hasName() const { StrLoc l; return strLoc(kind, 0, l); }

std::string Hdr::name() const {
    StrLoc l;
    if (!strLoc(kind, 0, l)) return "";
    return cstrOf((const char*)raw.data() + l.off, l.len);
}

void Hdr::setName(const std::string& s) {
    StrLoc l;
    if (!strLoc(kind, 0, l)) return;
    memset(raw.data() + l.off, 0, l.len);
    memcpy(raw.data() + l.off, s.data(), std::min(s.size(), l.len - 1));
}

std::string Hdr::cmdline() const {
    StrLoc a, b;
    strLoc(kind, 1, a);
    strLoc(kind, 3, b);
    std::string r((const char*)raw.data() + a.off, a.len);
    std::string e((const char*)raw.data() + b.off, b.len);
    size_t z = r.find('\0');
    if (z != std::string::npos) {

        r.resize(z);
        if (e.empty() || e[0] == 0) return r;
        return r;
    }
    size_t z2 = e.find('\0');
    if (z2 != std::string::npos) e.resize(z2);
    return r + e;
}

void Hdr::setCmdline(const std::string& s) {
    StrLoc a, b;
    strLoc(kind, 1, a);
    strLoc(kind, 3, b);
    memset(raw.data() + a.off, 0, a.len);
    if (kind != K_V0 && kind != K_V1 && kind != K_V2 && kind != K_PXA) {

        size_t total = a.len + b.len;
        memset(raw.data() + a.off, 0, total);
        memcpy(raw.data() + a.off, s.data(), std::min(s.size(), total - 1));
        return;
    }
    memset(raw.data() + b.off, 0, b.len);
    if (s.size() > a.len) {
        memcpy(raw.data() + a.off, s.data(), a.len);
        memcpy(raw.data() + b.off, s.data() + a.len, std::min(s.size() - a.len, b.len));
    } else {
        memcpy(raw.data() + a.off, s.data(), s.size());
    }
}

bool Hdr::hasId() const { StrLoc l; return strLoc(kind, 2, l); }

Bytes Hdr::id() const {
    StrLoc l;
    if (!strLoc(kind, 2, l)) return Bytes();
    return Bytes(raw.data() + l.off, raw.data() + l.off + l.len);
}

void Hdr::setId(const uint8_t* p, size_t n) {
    StrLoc l;
    if (!strLoc(kind, 2, l)) return;
    memset(raw.data() + l.off, 0, l.len);
    memcpy(raw.data() + l.off, p, std::min(n, l.len));
}

Bytes Hdr::reserved() const {
    if (kind != K_V3 && kind != K_V4) return Bytes();
    return Bytes(raw.data() + 24, raw.data() + 40);
}

void Hdr::setReserved(const Bytes& b) {
    if (kind != K_V3 && kind != K_V4) return;
    if (b.size() != 16) return;
    memcpy(raw.data() + 24, b.data(), 16);
}

std::string osVersionStr(uint32_t v) {
    uint32_t ver = v >> 11;
    return fmtstr("%u.%u.%u", (ver >> 14) & 0x7f, (ver >> 7) & 0x7f, ver & 0x7f);
}

std::string osPatchStr(uint32_t v) {
    uint32_t pl = v & 0x7ff;
    return fmtstr("%u-%02u", (pl >> 4) + 2000, pl & 0xf);
}

uint32_t osVersionPack(uint32_t oldv, const std::string* ver, const std::string* patch) {
    uint32_t verPart = oldv >> 11, pl = oldv & 0x7ff;
    if (ver) {
        unsigned a = 0, b = 0, c = 0;
        if (sscanf(ver->c_str(), "%u.%u.%u", &a, &b, &c) >= 1) verPart = ((a & 0x7f) << 14) | ((b & 0x7f) << 7) | (c & 0x7f);
    }
    if (patch) {
        int y = 0, m = 0;
        if (sscanf(patch->c_str(), "%d-%d", &y, &m) == 2 && y >= 2000) pl = (((uint32_t)(y - 2000) & 0x7f) << 4) | ((uint32_t)m & 0xf);
    }
    return (verPart << 11) | pl;
}

}
