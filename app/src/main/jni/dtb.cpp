#include "dtb.h"

namespace cu {

static const size_t kMinNonEmpty = 0x84;

static bool fdtValid(const uint8_t* p, size_t n, uint32_t* totalOut) {
    if (n < 0x28) return false;
    if (rd32be(p) != 0xd00dfeedu) return false;
    uint32_t total = rd32be(p + 4);
    uint32_t offStruct = rd32be(p + 8), offStrings = rd32be(p + 12), offRsv = rd32be(p + 16);
    uint32_t version = rd32be(p + 20), lastComp = rd32be(p + 24);
    uint32_t szStrings = rd32be(p + 32), szStruct = rd32be(p + 36);
    if (total <= kMinNonEmpty || total > n) return false;
    if (version < 1 || version > 32 || lastComp > version) return false;
    if (offRsv > total || offStruct > total || offStrings > total) return false;
    if ((uint64_t)offStruct + szStruct > total || (uint64_t)offStrings + szStrings > total) return false;
    if (offStruct % 4) return false;
    if (szStruct < 8) return false;
    if (rd32be(p + offStruct) != 1) return false;
    if (p[offStruct + 4] != 0) return false;
    if (totalOut) *totalOut = total;
    return true;
}

int findDtbOffset(const uint8_t* p, size_t n) {
    size_t pos = 0;
    static const uint8_t magic[4] = {0xd0, 0x0d, 0xfe, 0xed};
    while (pos + 0x28 <= n) {
        const void* f = memmem(p + pos, n - pos, magic, 4);
        if (!f) return -1;
        size_t cur = (const uint8_t*)f - p;
        if (fdtValid(p + cur, n - cur, nullptr)) return (int)cur;
        pos = cur + 4;
    }
    return -1;
}

DtbChain dtbChain(const uint8_t* p, size_t n, size_t from) {
    DtbChain c;
    size_t pos = from;
    while (pos < n) {
        uint32_t total = 0;
        if (!fdtValid(p + pos, n - pos, &total)) {
            size_t al = (pos + 3) & ~(size_t)3;
            if (al == pos || al >= n || !fdtValid(p + al, n - al, &total)) break;
            pos = al;
        }
        c.count++;
        pos += total;
    }
    c.end = pos;
    c.toEnd = c.count > 0;
    for (size_t i = pos; i < n && c.toEnd; i++) if (p[i] != 0) c.toEnd = false;
    return c;
}

std::string dtbFieldKind(const uint8_t* p, size_t n) {
    if (n >= 4 && rd32be(p) == 0xd00dfeedu) return "fdt";
    if (n >= 4 && memcmp(p, "QCDT", 4) == 0) return "qcdt";
    if (n >= 4 && memcmp(p, "DTBH", 4) == 0) return "dtbh";
    if (n >= 4 && memcmp(p, "SPRD", 4) == 0) return "sprd";
    return "";
}

static std::string cleanStr(const uint8_t* d, size_t len) {
    std::string r;
    for (size_t i = 0; i < len; i++) {
        if (d[i] == 0) { if (i + 1 < len) r += ", "; continue; }
        if (d[i] >= 32 && d[i] < 127) r += (char)d[i];
        else r += '?';
    }
    return r;
}

static void rootProps(const uint8_t* p, size_t total, std::string& model, std::string& compat) {
    uint32_t offStruct = rd32be(p + 8), offStrings = rd32be(p + 12), szStruct = rd32be(p + 36), szStrings = rd32be(p + 32);
    size_t pos = offStruct, end = (size_t)offStruct + szStruct;
    if (end > total) end = total;
    int depth = 0;
    while (pos + 4 <= end) {
        uint32_t tok = rd32be(p + pos);
        pos += 4;
        if (tok == 1) {
            depth++;
            size_t l = strnlen((const char*)p + pos, end - pos);
            pos = (pos + l + 1 + 3) & ~(size_t)3;
        } else if (tok == 2) {
            depth--;
            if (depth <= 0) break;
        } else if (tok == 3) {
            if (pos + 8 > end) break;
            uint32_t len = rd32be(p + pos), nameoff = rd32be(p + pos + 4);
            pos += 8;
            if (len > end - pos) break;
            if (depth == 1 && nameoff < szStrings) {
                const char* nm = (const char*)p + offStrings + nameoff;
                size_t maxl = std::min<size_t>(szStrings - nameoff, total - offStrings - nameoff);
                std::string name(nm, strnlen(nm, maxl));
                if (name == "model") model = cleanStr(p + pos, len);
                else if (name == "compatible") compat = cleanStr(p + pos, len);
            }
            pos = (pos + len + 3) & ~(size_t)3;
        } else if (tok == 4) {
        } else {
            break;
        }
    }
}

void dtbDescribe(View blob, const std::string& prefix, std::vector<std::string>& lines) {
    size_t pos = 0;
    int idx = 0;
    while (pos < blob.n && idx < 256) {
        int rel = findDtbOffset(blob.p + pos, blob.n - pos);
        if (rel < 0) break;
        size_t off = pos + (size_t)rel;
        uint32_t total = 0;
        if (!fdtValid(blob.p + off, blob.n - off, &total)) break;
        std::string model, compat;
        rootProps(blob.p + off, total, model, compat);
        lines.push_back(fmtstr("%s.%d.offset=0x%zx", prefix.c_str(), idx, off));
        lines.push_back(fmtstr("%s.%d.size=%u", prefix.c_str(), idx, total));
        lines.push_back(fmtstr("%s.%d.version=%u", prefix.c_str(), idx, rd32be(blob.p + off + 20)));
        lines.push_back(fmtstr("%s.%d.boot_cpuid=%u", prefix.c_str(), idx, rd32be(blob.p + off + 28)));
        if (!model.empty()) lines.push_back(fmtstr("%s.%d.model=%s", prefix.c_str(), idx, escapeField(model).c_str()));
        if (!compat.empty()) lines.push_back(fmtstr("%s.%d.compatible=%s", prefix.c_str(), idx, escapeField(compat).c_str()));
        pos = off + total;
        idx++;
    }
    lines.push_back(fmtstr("%s.count=%d", prefix.c_str(), idx));
}

void dtboDescribe(View blob, const std::string& prefix, std::vector<std::string>& lines) {
    if (blob.n < 32 || rd32be(blob.p) != 0xd7b7ab1eu) return;
    uint32_t totalSize = rd32be(blob.p + 4), hdrSize = rd32be(blob.p + 8), entSize = rd32be(blob.p + 12);
    uint32_t cnt = rd32be(blob.p + 16), entOff = rd32be(blob.p + 20), page = rd32be(blob.p + 24), ver = rd32be(blob.p + 28);
    lines.push_back(fmtstr("%s.dt_table.total_size=%u", prefix.c_str(), totalSize));
    lines.push_back(fmtstr("%s.dt_table.header_size=%u", prefix.c_str(), hdrSize));
    lines.push_back(fmtstr("%s.dt_table.entry_size=%u", prefix.c_str(), entSize));
    lines.push_back(fmtstr("%s.dt_table.entry_count=%u", prefix.c_str(), cnt));
    lines.push_back(fmtstr("%s.dt_table.entries_offset=%u", prefix.c_str(), entOff));
    lines.push_back(fmtstr("%s.dt_table.page_size=%u", prefix.c_str(), page));
    lines.push_back(fmtstr("%s.dt_table.version=%u", prefix.c_str(), ver));
    if (entSize < 32 || cnt > 4096) return;
    for (uint32_t i = 0; i < cnt; i++) {
        size_t o = (size_t)entOff + (size_t)i * entSize;
        if (o + 32 > blob.n) break;
        uint32_t dsz = rd32be(blob.p + o), doff = rd32be(blob.p + o + 4), id = rd32be(blob.p + o + 8), rev = rd32be(blob.p + o + 12);
        lines.push_back(fmtstr("%s.dt_table.entry.%u=offset:0x%x size:%u id:0x%x rev:0x%x", prefix.c_str(), i, doff, dsz, id, rev));
    }
}

}
