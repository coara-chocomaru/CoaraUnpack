#include "cpio.h"
#include <sys/stat.h>
#include <map>
#include <tuple>
#include <algorithm>

namespace cu {

static bool hex8(const uint8_t* p, uint32_t& v) {
    v = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t c = p[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    return true;
}

static bool oct(const uint8_t* p, int n, uint32_t& v) {
    v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '7') return false;
        v = (v << 3) | (uint32_t)(p[i] - '0');
    }
    return true;
}

std::string normalizeCpioPath(const std::string& p, bool& unsafe) {
    unsafe = false;
    std::string r;
    size_t i = 0;
    while (i <= p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        std::string c = p.substr(i, j - i);
        if (c == "..") unsafe = true;
        else if (!c.empty() && c != ".") {
            if (!r.empty()) r += '/';
            r += c;
        }
        i = j + 1;
    }
    return r;
}

void cpioParse(View in, CpioArchive& out) {
    const uint8_t* b = in.p;
    size_t n = in.size();
    size_t pos = 0;
    int archive = 0;
    bool first = true;
    struct HL { size_t idx; };
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, std::vector<size_t>> links;
    while (pos < n) {
        while (pos < n && b[pos] == 0) pos++;
        if (pos >= n) break;
        if (pos + 6 > n) break;
        bool newc = memcmp(b + pos, "070701", 6) == 0 || memcmp(b + pos, "070702", 6) == 0;
        bool odc = memcmp(b + pos, "070707", 6) == 0;
        if (!newc && !odc) {
            if (first) throw Error("cpioじゃないみたい(マジックが違うよ)");

            size_t k = pos + 1;
            bool found = false;
            while (k + 6 <= n) {
                if (memcmp(b + k, "07070", 5) == 0 && (b[k + 5] == '1' || b[k + 5] == '2' || b[k + 5] == '7')) { found = true; break; }
                k++;
            }
            if (!found) break;
            pos = k;
            continue;
        }
        if (first) {
            out.format = std::string((const char*)b + pos, 6);
            first = false;
        }
        archive++;
        out.archives = archive;
        bool trailer = false;
        while (pos + 6 <= n && !trailer) {
            newc = memcmp(b + pos, "070701", 6) == 0 || memcmp(b + pos, "070702", 6) == 0;
            odc = memcmp(b + pos, "070707", 6) == 0;
            if (!newc && !odc) break;
            CpioEntry e;
            e.archive = archive;
            uint32_t namesz = 0, filesz = 0, mode = 0;
            size_t hdr;
            if (newc) {
                hdr = 110;
                if (pos + hdr > n) throw Error("cpioが途中で切れてるよ");
                const uint8_t* h = b + pos + 6;
                uint32_t v[13];
                for (int i = 0; i < 13; i++)
                    if (!hex8(h + i * 8, v[i])) throw Error("cpioのヘッダが壊れてるよ");
                e.ino = v[0]; mode = v[1]; e.uid = v[2]; e.gid = v[3]; e.nlink = v[4]; e.mtime = v[5];
                filesz = v[6]; e.devmaj = v[7]; e.devmin = v[8]; e.rdevmaj = v[9]; e.rdevmin = v[10]; namesz = v[11];
            } else {
                hdr = 76;
                if (pos + hdr > n) throw Error("cpioが途中で切れてるよ");
                const uint8_t* h = b + pos + 6;
                uint32_t dev, ino, rdev, mt0, mt1, ns, fs0, fs1;
                uint32_t uid, gid, nl;
                if (!oct(h, 6, dev) || !oct(h + 6, 6, ino) || !oct(h + 12, 6, mode) || !oct(h + 18, 6, uid) ||
                    !oct(h + 24, 6, gid) || !oct(h + 30, 6, nl) || !oct(h + 36, 6, rdev) || !oct(h + 42, 6, mt0) ||
                    !oct(h + 48, 5, mt1) || !oct(h + 53, 6, ns) || !oct(h + 59, 6, fs0) || !oct(h + 65, 5, fs1))
                    throw Error("cpioのヘッダが壊れてるよ");
                (void)mt0; (void)mt1; (void)fs1;
                e.mtime = 0;
                e.ino = ino; e.uid = uid; e.gid = gid; e.nlink = nl; e.devmaj = dev; e.rdevmaj = rdev >> 8; e.rdevmin = rdev & 0xff;
                namesz = ns;
                filesz = fs0;
            }
            e.mode = mode;
            size_t np = pos + hdr;
            if (namesz == 0 || namesz > 65536 || np + namesz > n) throw Error("cpioのファイル名が壊れてるよ");
            std::string name((const char*)b + np, strnlen((const char*)b + np, namesz));
            size_t dp = newc ? ((np + namesz + 3) & ~(size_t)3) : np + namesz;
            if (name == "TRAILER!!!") {
                pos = dp;
                trailer = true;
                break;
            }
            if (dp > n || filesz > n - dp) throw Error(fmtstr("cpioが途中で切れてるよ(%s)", name.c_str()));
            e.data = View(b + dp, filesz);
            e.path = name;
            pos = newc ? ((dp + filesz + 3) & ~(size_t)3) : dp + filesz;
            if (name == "." || name == "..") continue;
            out.entries.push_back(e);
        }
        if (!trailer) break;
    }
    if (first) throw Error("cpioのエントリが見つからないよ");

    for (size_t i = 0; i < out.entries.size(); i++) {
        CpioEntry& e = out.entries[i];
        if ((e.mode & S_IFMT) != S_IFREG || e.nlink < 2) continue;
        links[std::make_tuple(e.archive == 0 ? 0u : (uint32_t)e.archive, e.devmin ^ (e.devmaj << 16), e.ino)].push_back(i);
    }
    int gid = 0;
    for (auto& kv : links) {
        auto& v = kv.second;
        if (v.size() < 2) continue;
        View data;
        for (size_t i : v) if (!out.entries[i].data.empty()) data = out.entries[i].data;
        for (size_t i : v) if (out.entries[i].data.empty()) out.entries[i].data = data;
        size_t last = *std::max_element(v.begin(), v.end());
        for (size_t i : v) {
            out.entries[i].linkGroup = gid;
            out.entries[i].linkPrimary = i == last;
        }
        gid++;
    }
    for (auto& e : out.entries) {
        if ((e.mode & S_IFMT) == S_IFLNK) e.target.assign((const char*)e.data.p, e.data.n);
    }
}

void CpioWriter::put(const void* p, size_t n) {
    s_.write((const uint8_t*)p, n);
    pos_ += n;
}

void CpioWriter::pad4() {
    static const uint8_t z[4] = {0, 0, 0, 0};
    size_t r = pos_ & 3;
    if (r) put(z, 4 - r);
}

void CpioWriter::add(const CpioOutEntry& e) {
    View data = e.data;
    std::string tgt = e.target;
    if ((e.mode & S_IFMT) == S_IFLNK) data = View((const uint8_t*)tgt.data(), tgt.size());
    if ((e.mode & S_IFMT) == S_IFDIR || e.noData) data = View();
    uint32_t chk = 0;
    if (crc_) for (size_t i = 0; i < data.n; i++) chk += data.p[i];
    uint32_t nl = e.nlink ? e.nlink : ((e.mode & S_IFMT) == S_IFDIR ? 2 : 1);
    uint32_t useIno = e.ino ? e.ino : ino_++;
    char h[128];
    snprintf(h, sizeof(h), "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", crc_ ? "070702" : "070701",
             useIno, e.mode, e.uid, e.gid, nl, e.mtime, (uint32_t)data.n, 0u, 0u, e.rdevmaj, e.rdevmin,
             (uint32_t)(e.path.size() + 1), chk);
    put(h, 110);
    put(e.path.c_str(), e.path.size() + 1);
    pad4();
    if (data.n) put(data.p, data.n);
    pad4();
}

void CpioWriter::finish() {
    char h[128];
    snprintf(h, sizeof(h), "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", crc_ ? "070702" : "070701",
             ino_++, 0u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u, 11u, 0u);
    put(h, 110);
    put("TRAILER!!!", 11);
    pad4();
}

}
