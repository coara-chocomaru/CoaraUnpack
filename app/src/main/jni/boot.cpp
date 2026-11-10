#include "unpacker.h"
#include "boothdr.h"
#include "zimage.h"
#include "dtb.h"
#include "avb.h"
#include "cpio.h"
#include "hash.h"
#include "info.h"
#include "streaminfo.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <set>
#include <limits>

namespace cu {

namespace {

const size_t kMtkHdr = 512;
const size_t kDhtbHdr = 512;
const size_t kBlobHdr = 104;
const size_t kBlobSizeOff = 96;
const size_t kNookPre = 1048576;
const size_t kAcclaimPre = 262144;
const size_t kAmonetMicro = 1024;
const size_t kAvbFooter = 64;
const char* kSeandroid = "SEANDROIDENFORCE";
const uint8_t kLgBump[16] = {0x41, 0xa9, 0xe4, 0x67, 0x74, 0x4d, 0x1d, 0x1b, 0xa4, 0x29, 0xf2, 0xec, 0xea, 0x65, 0x52, 0x79};

struct Flags {
    bool mtkK = false, mtkR = false, chromeos = false, dhtb = false, seandroid = false, signer02 = false;
    bool lgbump = false, sha256 = false, blob = false, nook = false, acclaim = false, amonet = false;
    bool avb1 = false, avb = false, zimage = false;
};

struct VrEntry {
    std::string name;
    uint32_t type = 0, size = 0, offset = 0;
    uint32_t boardId[16] = {0};
    Fmt fmt = F_UNKNOWN;
    std::string file;
};

struct BootImg {
    MappedFile map;
    Hdr hdr;
    Flags f;
    Fmt kfmt = F_UNKNOWN, rfmt = F_UNKNOWN, efmt = F_UNKNOWN;
    size_t headerOff = 0;
    size_t offKernel = 0, offRamdisk = 0, offSecond = 0, offExtra = 0, offReco = 0, offDtb = 0, offSig = 0, offVrTable = 0, offBootcfg = 0;
    size_t payloadEnd = 0;
    View kField, kBody, kDtb, mtkK, rField, mtkRhdr, rBody;
    std::unique_ptr<ZImage> z;
    View vbmeta, avbFooter, avb1Sig, tail;
    std::string avb1Target;
    uint64_t avb1Len = 0;
    std::vector<VrEntry> vr;
    bool kernelDtbSplit = false;
    View kFull;
    int kDtbAt = -1;
    DtbChain kChain;
    bool kDetMtk = false, kDetZimage = false;
    Fmt kDetFmt = F_UNKNOWN;
    bool kRawMtkConsistent = false;
    View blk(size_t off, size_t len) const { return map.view().sub(off, len); }
};

HKind pickAospKind(const uint8_t* p) {
    uint32_t ver = rd32(p + 40);
    switch (ver) {
    case 1: return K_V1;
    case 2: return K_V2;
    case 3: return K_V3;
    case 4: return K_V4;
    default: return K_V0;
    }
}

void loadHdr(Hdr& h, HKind k, const uint8_t* p, size_t avail) {
    h.init(k);
    memcpy(h.raw.data(), p, std::min(avail, h.raw.size()));
}

bool parseImageAt(BootImg& b, const uint8_t* addr0, Fmt type) {
    const uint8_t* base = b.map.data();
    const uint8_t* end = base + b.map.size();
    const uint8_t* addr = addr0;
    size_t avail = (size_t)(end - addr);
    if (type == F_AOSP_VENDOR) {
        if (avail < 28) return false;
        uint32_t ver = rd32(addr + 8);
        loadHdr(b.hdr, ver == 4 ? K_VND4 : K_VND3, addr, avail);
        logf("vendor_boot ヘッダ(v%u)を見つけたよ", ver == 4 ? 4u : 3u);
    } else {
        if (avail < 64) return false;
        uint32_t pg = rd32(addr + 36);
        if (pg >= 0x02000000u) {
            logf("Samsung PXA ヘッダだね");
            loadHdr(b.hdr, K_PXA, addr, avail);
        } else {
            bool done = false;
            if (avail > kAmonetMicro + 8 && memmem(addr, kAmonetMicro, "microloader", 11) &&
                memcmp(addr + kAmonetMicro, "ANDROID!", 8) == 0) {
                b.f.amonet = true;
                logf("AMONET microloader つきだね");
                const uint8_t* real = addr + kAmonetMicro;
                uint32_t rpg = rd32(real + 36);
                size_t realSz = rpg > kAmonetMicro ? rpg - kAmonetMicro : 0;
                HKind k = pickAospKind(real);
                loadHdr(b.hdr, k, real, std::min(realSz ? realSz : Hdr::structSize(k), (size_t)(end - real)));
                done = true;
            }
            if (!done) {
                const char* cmd = (const char*)addr + 64;
                if (!memcmp(cmd, "Red Loader", 10) || !memcmp(cmd, "Green Loader", 12) || !memcmp(cmd, "Green Recovery", 14) ||
                    !memcmp(cmd, "eMMC boot.img+secondloader", 26) || !memcmp(cmd, "eMMC recovery.img+secondloader", 30)) {
                    b.f.nook = true;
                    logf("NOOKHD ローダーつきだね");
                    addr += kNookPre;
                } else if (!memcmp(addr + 48, "BauwksBoot", 10)) {
                    b.f.acclaim = true;
                    logf("ACCLAIM ローダーつきだね");
                    addr += kAcclaimPre;
                }
                if (addr + 64 > end || memcmp(addr, "ANDROID!", 8) != 0) return false;
                HKind k = pickAospKind(addr);
                loadHdr(b.hdr, k, addr, (size_t)(end - addr));
            }
        }
    }
    b.headerOff = (size_t)(addr - base);
    if (b.f.amonet) b.headerOff = (size_t)(addr0 - base);

    if (b.hdr.hasId()) {
        Bytes id = b.hdr.id();
        for (int i = 24; i < 32; i++) if (id[i]) { b.f.sha256 = true; break; }
    }

    size_t mapEnd = (size_t)alignUp(b.map.size(), 4096);
    size_t off = b.hdr.hdrSpace();
    bool bad = false;
    auto block = [&](size_t& dst, uint64_t sz) {
        dst = b.headerOff + off;
        off += (size_t)sz;
        off = (size_t)alignUp(off, b.hdr.pageSize());
        if (b.headerOff + off > mapEnd) bad = true;
    };
    block(b.offKernel, b.hdr.kernelSize());
    block(b.offRamdisk, b.hdr.ramdiskSize());
    block(b.offSecond, b.hdr.secondSize());
    block(b.offExtra, b.hdr.extraSize());
    block(b.offReco, b.hdr.recoveryDtboSize());
    block(b.offDtb, b.hdr.dtbSize());
    block(b.offSig, b.hdr.signatureSize());
    block(b.offVrTable, b.hdr.vrTableSize());
    block(b.offBootcfg, b.hdr.bootconfigSize());
    if (bad) {
        logf("このヘッダ位置はサイズが合わないみたい(壊れてるかも)");
        return false;
    }
    b.payloadEnd = b.headerOff + off;
    b.tail = b.map.size() > b.payloadEnd ? b.blk(b.payloadEnd, b.map.size() - b.payloadEnd) : View();

    if (uint32_t ks = b.hdr.kernelSize()) {
        View kf = b.blk(b.offKernel, ks);
        if (kf.n < ks) logf("kernelが途中で切れてるかも(%zu / %u)", kf.n, ks);
        b.kFull = kf;
        int d = findDtbOffset(kf.p, kf.n);
        b.kDtbAt = d;
        if (d > 0) b.kChain = dtbChain(kf.p, kf.n, (size_t)d);
        if (d > 0) {
            b.kDtb = View(kf.p + d, kf.n - d);
            kf = View(kf.p, (size_t)d);
            b.kernelDtbSplit = true;
            logf("kernel末尾にdtbがあったよ (%zu bytes)", b.kDtb.n);
        }
        b.kField = kf;
        b.kfmt = checkFmtLg(kf.p, kf.n);
        View kb = kf;
        if (b.kfmt == F_MTK) {
            b.f.mtkK = true;
            b.mtkK = View(kf.p, std::min<size_t>(kMtkHdr, kf.n));
            logf("MTK kernelヘッダ(512B)だよ: name=%s", cstrOf((const char*)kf.p + 8, 32).c_str());
            kb = kf.from(kMtkHdr);
            b.kfmt = checkFmtLg(kb.p, kb.n);
        }
        b.kBody = kb;
        if (b.kfmt == F_ZIMAGE) {
            View piggy;
            std::unique_ptr<ZImage> z = ZImage::parse(kb, &piggy);
            if (z) {
                logf("ARM zImageだね (piggy=%s)", fmtName(z->fmt));
                b.f.zimage = true;
                b.kBody = z->fmt != F_GZIP ? View(piggy.p, piggy.n - 4) : piggy;
                b.kfmt = z->fmt;
                b.z = std::move(z);
            }
        }
        b.kDetMtk = b.f.mtkK;
        b.kDetZimage = b.f.zimage;
        b.kDetFmt = b.kfmt;
        if (b.f.mtkK && b.mtkK.n >= 8) {
            uint32_t sf = rd32(b.mtkK.p + 4);
            b.kRawMtkConsistent = sf == b.kFull.n - kMtkHdr || sf == b.kField.n - kMtkHdr;
        }
    }
    if (uint32_t rs = b.hdr.ramdiskSize()) {
        View rf = b.blk(b.offRamdisk, rs);
        b.rField = rf;
        if (b.hdr.vrTableSize()) {
            if (b.hdr.vrEntrySize() != 108) throw Error("vendor ramdisk tableのentry sizeが変だよ");
            View tb = b.blk(b.offVrTable, b.hdr.vrTableSize());
            uint32_t num = b.hdr.vrEntryNum();
            if ((uint64_t)num * 108 > tb.n) throw Error("vendor ramdisk tableが壊れてるよ");
            for (uint32_t i = 0; i < num; i++) {
                const uint8_t* e = tb.p + (size_t)i * 108;
                VrEntry v;
                v.size = rd32(e);
                v.offset = rd32(e + 4);
                v.type = rd32(e + 8);
                v.name = cstrOf((const char*)e + 12, 32);
                for (int k = 0; k < 16; k++) v.boardId[k] = rd32(e + 44 + k * 4);
                View r = rf.sub(v.offset, v.size);
                v.fmt = probeFmt(r);
                b.vr.push_back(v);
            }
        } else {
            b.rfmt = probeFmt(rf);
            b.rBody = rf;
            if (b.rfmt == F_MTK) {
                b.f.mtkR = true;
                b.mtkRhdr = View(rf.p, std::min<size_t>(kMtkHdr, rf.n));
                logf("MTK ramdiskヘッダ(512B)だよ: name=%s", cstrOf((const char*)rf.p + 8, 32).c_str());
                b.rBody = rf.from(kMtkHdr);
                b.rfmt = probeFmt(b.rBody);
            }
        }
    }
    if (uint32_t es = b.hdr.extraSize()) {
        View e = b.blk(b.offExtra, es);
        b.efmt = checkFmtLg(e.p, e.n);
    }

    if (b.tail.n) {
        if (b.tail.n >= 16 && memcmp(b.tail.p, kSeandroid, 16) == 0) {
            b.f.seandroid = true;
            if (b.tail.n >= 16 + 512 && memcmp(b.tail.p + 16, "SignerVer02", 11) == 0) b.f.signer02 = true;
        } else if (b.tail.n >= 16 && memcmp(b.tail.p, kLgBump, 16) == 0) {
            b.f.lgbump = true;
        } else {
            size_t derLen = 0;
            if (parseBootSignature(b.tail, derLen, b.avb1Target, b.avb1Len)) {
                b.f.avb1 = true;
                b.avb1Sig = View(b.tail.p, derLen);
            }
        }
        if (b.map.size() >= kAvbFooter + b.payloadEnd) {
            const uint8_t* foot = b.map.data() + b.map.size() - kAvbFooter;
            if (memcmp(foot, "AVBf", 4) == 0) {
                b.avbFooter = View(foot, kAvbFooter);
                uint64_t vo = rd64be(foot + 20), vs = rd64be(foot + 28);
                uint64_t base = b.headerOff;
                if (vs >= 256 && base <= b.map.size() && vo <= b.map.size() - base &&
                    vs <= b.map.size() - base - vo && vs <= SIZE_MAX) {
                    const uint8_t* meta = b.map.data() + (size_t)(base + vo);
                    if (memcmp(meta, "AVB0", 4) == 0) {
                        b.f.avb = true;
                        b.vbmeta = View(meta, (size_t)vs);
                    }
                }
            }
        }
    }
    return true;
}

void parseBoot(BootImg& b, const std::string& path) {
    b.map.open(path);
    if (b.map.size() < 64) throw Error("ファイルが小さすぎてbootイメージじゃないみたい");
    const uint8_t* base = b.map.data();
    const uint8_t* eof = base + b.map.size();
    for (const uint8_t* a = base; a < eof; ++a) {
        uint8_t c = *a;
        if (c != 'C' && c != 'A' && c != 'V' && c != 'D' && c != '-') continue;
        Fmt fmt = checkFmt(a, (size_t)(eof - a));
        switch (fmt) {
        case F_CHROMEOS:
            throw Error("ChromeOS形式のイメージは未対応だよ〜ごめんね");
        case F_DHTB:
            b.f.dhtb = true;
            b.f.seandroid = true;
            logf("DHTBヘッダ(Samsung)だね");
            a += kDhtbHdr - 1;
            break;
        case F_BLOB:
            b.f.blob = true;
            logf("TEGRA blobヘッダだね");
            a += kBlobHdr - 1;
            break;
        case F_AOSP:
        case F_AOSP_VENDOR: {

            b.f.mtkK = b.f.mtkR = false;
            if (parseImageAt(b, a, fmt)) return;
            break;
        }
        default:
            break;
        }
        if ((a - base) % (1 << 22) == 0) checkCancel();
    }
    throw Error("bootイメージのヘッダが見つからなかったよ〜(boot/vendor_boot/init_bootじゃないかも)");
}

void copyFileTo(const std::string& src, const std::string& dst) {
    uint64_t total = (uint64_t)std::max<int64_t>(fileSize(src), 1);
    uint64_t done = 0;
    int in = open(src.c_str(), O_RDONLY | O_CLOEXEC);
    if (in < 0) throw Error(fmtstr("元イメージを開けないよ: %s", strerror(errno)));
    int outFd = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (outFd < 0) {
        int e = errno;
        close(in);
        throw Error(fmtstr("コピー先を作れないよ: %s", strerror(e)));
    }
    Bytes buf(1 << 20);
    try {
        for (;;) {
            ssize_t r = read(in, buf.data(), buf.size());
            if (r < 0) {
                if (errno == EINTR) continue;
                throw Error(fmtstr("コピー読み込み失敗: %s", strerror(errno)));
            }
            if (r == 0) break;
            done += (uint64_t)r;
            subProgress((int)(done * 100 / total));
            size_t off = 0;
            while (off < (size_t)r) {
                ssize_t w = write(outFd, buf.data() + off, (size_t)r - off);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    throw Error(fmtstr("コピー書き込み失敗(容量不足かも): %s", strerror(errno)));
                }
                off += (size_t)w;
            }
            checkCancel();
        }
        fsync(outFd);
    } catch (...) {
        close(in);
        close(outFd);
        unlink(dst.c_str());
        throw;
    }
    close(in);
    close(outFd);
}

std::string typeName(uint32_t t) {
    switch (t) {
    case 1: return "platform";
    case 2: return "recovery";
    case 3: return "dlkm";
    default: return "none";
    }
}

std::string safeName(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '/' || c == '\\' || c == ':' || (unsigned char)c < 32) r += '_';
        else r += c;
    }
    return r;
}

struct Emitted {
    std::string file;
    uint64_t size = 0;
    bool wrote = false;
};

void blobInfo(InfoWriter& w, const std::string& pfx, View stored, Fmt fmt, const std::string& file, const std::string& path,
              bool decompressed) {
    Digests ds = digestAll(stored.p, stored.n);
    w.kv(pfx + ".file", file);
    w.kv(pfx + ".format", fmtCompressed(fmt) ? fmtName(fmt) : "raw");
    w.kvu(pfx + ".stored_size", stored.n);
    w.kv(pfx + ".stored_md5", ds.md5);
    w.kv(pfx + ".stored_sha1", ds.sha1);
    w.kv(pfx + ".stored_sha256", ds.sha256);
    w.kvb(pfx + ".decompressed", decompressed);
    if (fmtCompressed(fmt)) {
        KvList kl;
        describeStream(fmt, stored, kl);
        for (auto& kv : kl) w.kv(pfx + ".codec." + kv.first, kv.second);
    }
    int64_t fs = fileSize(path);
    if (fs > 0 && decompressed && stored.n) w.kv(pfx + ".ratio", fmtstr("%.2f%%", 100.0 * (double)stored.n / (double)fs));
    if (fs >= 0) {
        Digests d;
        if (!decompressed && (uint64_t)fs == stored.n) {
            d = ds;
        } else {
            MappedFile m(path);
            d = digestAll(m.data(), m.size());
        }
        w.kvu(pfx + ".size", (uint64_t)fs);
        w.kv(pfx + ".md5", d.md5);
        w.kv(pfx + ".sha1", d.sha1);
        w.kv(pfx + ".sha256", d.sha256);
        w.kv(pfx + ".crc32", fmtstr("%08x", d.crc));
    }
}

void writeBlob(const std::string& path, View stored, Fmt fmt, bool skipDecomp, bool& decompressed, int lo = -1, int hi = -1) {
    decompressed = false;
    if (!skipDecomp && fmtCompressed(fmt)) {
        FileSink fs(path);
        try {
            if (lo >= 0) {
                ProgressScope ps(lo, hi);
                decompress(fmt, stored, fs);
            } else {
                decompress(fmt, stored, fs);
            }
        } catch (...) {
            fs.close();
            unlink(path.c_str());
            throw;
        }
        fs.close();
        decompressed = true;
    } else {
        writeFile(path, stored.p, stored.n);
    }
}

void analyzeKernel(InfoWriter& w, const std::string& kpath, const std::string& outDir, bool zimage) {
    MappedFile m(kpath);
    if (m.size() == 0) return;
    std::string arch = "unknown";
    if (m.size() > 0x40 && memcmp(m.data() + 0x38, "ARM\x64", 4) == 0) {
        arch = "arm64";
        uint64_t textOff = rd64(m.data() + 8), imgSz = rd64(m.data() + 16), fl = rd64(m.data() + 24);
        w.kvx("kernel.arm64.text_offset", textOff);
        w.kvu("kernel.arm64.image_size", imgSz);
        w.kvx("kernel.arm64.flags", fl);
        static const char* ps[] = {"unspecified", "4K", "16K", "64K"};
        w.kv("kernel.arm64.page_size", ps[(fl >> 1) & 3]);
        w.kv("kernel.arm64.endian", (fl & 1) ? "big" : "little");
    } else if (zimage || (m.size() > 0x28 && rd32(m.data() + 0x24) == 0x016f2818u)) {
        arch = "arm32 (zImage)";
    } else if (m.size() > 4 && m.data()[0] == 0x7f && m.data()[1] == 'E') {
        arch = "elf (vmlinux)";
    } else if (m.size() > 8 && rd32(m.data()) == 0xea000000u) {
        arch = "arm32";
    }
    w.kv("kernel.arch", arch);
    const uint8_t* lv = (const uint8_t*)memmem(m.data(), m.size(), "Linux version ", 14);
    if (lv) {
        size_t maxl = std::min<size_t>(300, (size_t)(m.data() + m.size() - lv));
        size_t l = 0;
        while (l < maxl && lv[l] >= 32 && lv[l] < 127) l++;
        w.kv("kernel.linux_version", std::string((const char*)lv, l));
    }
    const uint8_t* st = (const uint8_t*)memmem(m.data(), m.size(), "IKCFG_ST", 8);
    if (st) {
        const uint8_t* gz = st + 8;
        size_t rem = (size_t)(m.data() + m.size() - gz);
        const uint8_t* ed = (const uint8_t*)memmem(gz, rem, "IKCFG_ED", 8);
        if (ed && ed > gz) {
            try {
                VecSink vs;
                vs.limit = 8u << 20;
                gzipDecompress(View(gz, (size_t)(ed - gz)), vs);
                if (!vs.v.empty()) {
                    writeFile(joinPath(outDir, "kernel.config"), vs.v.data(), vs.v.size());
                    w.kv("kernel.config_file", "kernel.config");
                    w.kvb("kernel.has_ikconfig", true);
                    std::string txt((const char*)vs.v.data(), vs.v.size());
                    size_t p = txt.find("# Linux/");
                    if (p != std::string::npos) w.kv("kernel.config_header", txt.substr(p, txt.find('\n', p) - p));
                    for (const char* key : {"CONFIG_MODULES=", "CONFIG_MODVERSIONS=", "CONFIG_SELINUX=", "CONFIG_KPROBES=",
                                            "CONFIG_KALLSYMS=", "CONFIG_ANDROID_BINDER_IPC=", "CONFIG_DM_VERITY=", "CONFIG_OVERLAY_FS=",
                                            "CONFIG_LOCALVERSION="}) {
                        size_t q = txt.find(std::string("\n") + key);
                        if (q != std::string::npos) {
                            size_t e = txt.find('\n', q + 1);
                            std::string line = txt.substr(q + 1, e - q - 1);
                            size_t eq = line.find('=');
                            w.kv(std::string("kernel.config.") + std::string(key, strlen(key) - 1), line.substr(eq + 1));
                        }
                    }
                }
            } catch (...) {
            }
        }
    }
}

void analyzeCpio(InfoWriter& w, const std::string& pfx, const std::string& path) {
    try {
        MappedFile m(path);
        if (m.size() < 6 || memcmp(m.data(), "07070", 5) != 0) {
            w.kv(pfx + ".cpio", "false");
            return;
        }
        CpioArchive ar;
        cpioParse(m.view(), ar);
        size_t nf = 0, nd = 0, nl = 0, no = 0;
        std::set<std::string> names;
        for (auto& e : ar.entries) {
            switch (e.mode & S_IFMT) {
            case S_IFREG: nf++; break;
            case S_IFDIR: nd++; break;
            case S_IFLNK: nl++; break;
            default: no++;
            }
            names.insert(e.path);
        }
        w.kvb(pfx + ".cpio", true);
        w.kv(pfx + ".cpio_format", ar.format);
        w.kvu(pfx + ".cpio_entries", ar.entries.size());
        w.kvu(pfx + ".cpio_files", nf);
        w.kvu(pfx + ".cpio_dirs", nd);
        w.kvu(pfx + ".cpio_symlinks", nl);
        w.kvu(pfx + ".cpio_other", no);
        std::string notable;
        for (const char* n : {"init", "init.rc", "prop.default", "default.prop", "sepolicy", "system", "system_root", "apex", "first_stage_ramdisk",
                              "init.magisk.rc", ".backup/.magisk", "sbin/magisk", "sbin/su", "verity_key", "ueventd.rc", "lib/modules"}) {
            if (names.count(n)) notable += std::string(notable.empty() ? "" : ",") + n;
        }
        for (auto& n : names) {
            if (n.compare(0, 5, "fstab") == 0 || (n.find("/fstab.") != std::string::npos && n.size() < 60)) {
                notable += std::string(notable.empty() ? "" : ",") + n;
                break;
            }
        }
        if (!notable.empty()) w.kv(pfx + ".cpio_notable", notable);
        for (auto& e : ar.entries) {
            if (e.path == "default.prop" || e.path == "prop.default") {
                std::string txt((const char*)e.data.p, std::min<size_t>(e.data.n, 1 << 20));
                for (const char* k : {"ro.build.version.release=", "ro.build.version.sdk=", "ro.product.device=", "ro.product.model=",
                                      "ro.build.fingerprint=", "ro.secure=", "ro.debuggable=", "ro.adb.secure="}) {
                    size_t q = txt.find(k);
                    if (q != std::string::npos && (q == 0 || txt[q - 1] == '\n')) {
                        size_t en = txt.find('\n', q);
                        std::string line = txt.substr(q, en == std::string::npos ? std::string::npos : en - q);
                        size_t eq = line.find('=');
                        w.kv(pfx + ".prop." + line.substr(0, eq), line.substr(eq + 1));
                    }
                }
            }
        }
    } catch (const Canceled&) {
        throw;
    } catch (const std::exception& e) {
        w.kv(pfx + ".cpio_error", e.what());
    }
}

}

void bootUnpack(const std::string& imgPath, const std::string& outDir, const BootUnpackOpts& o) {
    logf("イメージを読み込み中だよ〜: %s", baseName(imgPath).c_str());
    BootImg b;
    parseBoot(b, imgPath);
    if (o.skipDecomp && b.hdr.kernelSize()) {
        b.kernelDtbSplit = false;
        b.kDtb = View();
        b.f.mtkK = false;
        b.mtkK = View();
        b.f.zimage = false;
        b.z.reset();
        b.kField = b.kFull;
        b.kBody = b.kFull;
        b.kfmt = (b.kDetMtk || b.kDetZimage) ? F_UNKNOWN : checkFmtLg(b.kFull.p, b.kFull.n);
        logf("kernel領域をそのまま取り出すよ (%zu bytes / dtbは分離しないよ)", b.kFull.n);
    }
    progress(3);
    mkdirs(outDir);
    logf("元イメージをフォルダに保管するよ(original.img)");
    {
        ProgressScope ps(3, 10);
        copyFileTo(imgPath, joinPath(outDir, "original.img"));
    }
    InfoWriter w;
    const Hdr& h = b.hdr;
    Digests whole;
    {
        ProgressScope ps(10, 18);
        whole = digestAll(b.map.data(), b.map.size());
    }
    progress(18);
    w.comment("coara unpack / boot image info ─ リパックはこのファイルを読むよ〜");
    w.comment("cmdline や os_version などは書き換えてOK。サイズやハッシュは自動で作り直すよ");
    w.blank();
    w.section("image");
    w.kv("tool", "coara-unpack");
    w.kv("info_version", "1");
    w.kv("kind", "boot");
    w.kv("source_name", baseName(imgPath));
    w.kvu("source_size", b.map.size());
    w.kvu("image.original_size", b.map.size());
    w.kv("source_md5", whole.md5);
    w.kv("source_sha1", whole.sha1);
    w.kv("source_sha256", whole.sha256);
    w.kv("source_crc32", fmtstr("%08x", whole.crc));
    w.kv("original.file", "original.img");
    w.kv("image.type", h.vendor() ? "vendor_boot" : "boot");
    w.kv("image.partition_guess", h.vendor() ? "vendor_boot" : (h.headerVersion() >= 3 && h.kernelSize() == 0 ? "init_boot" : (h.kernelSize() == 0 ? "ramdisk-only" : "boot/recovery")));
    w.kvu("image.header_offset", b.headerOff);
    w.kvu("image.preheader_size", b.headerOff);
    w.kvu("image.payload_end", b.payloadEnd);
    w.kvu("image.tail_offset", b.payloadEnd);
    w.kvu("image.tail_size", b.tail.n);
    w.kvb("flag.mtk_kernel", b.f.mtkK);
    w.kvb("flag.mtk_ramdisk", b.f.mtkR);
    w.kvb("flag.zimage_kernel", b.f.zimage);
    w.kvb("flag.dhtb", b.f.dhtb);
    w.kvb("flag.seandroid", b.f.seandroid);
    w.kvb("flag.signer_ver02", b.f.signer02);
    w.kvb("flag.lg_bump", b.f.lgbump);
    w.kvb("flag.sha256_id", b.f.sha256);
    w.kvb("flag.blob", b.f.blob);
    w.kvb("flag.nookhd", b.f.nook);
    w.kvb("flag.acclaim", b.f.acclaim);
    w.kvb("flag.amonet", b.f.amonet);
    w.kvb("flag.avb1_signed", b.f.avb1);
    w.kvb("flag.avb2_footer", b.f.avb);
    w.kvb("option.skip_decompress", o.skipDecomp);

    w.section("header");
    w.kv("hdr.kind", kindName(h.kind));
    w.kv("hdr.magic", h.magic());
    w.kvu("hdr.header_version", h.headerVersion());
    w.kvu("hdr.page_size", h.pageSize());
    static const char* numKeys[] = {"kernel_addr", "ramdisk_addr", "second_addr", "tags_addr", "dtb_addr", "unknown",
                                    "recovery_dtbo_offset", "header_size"};
    for (const char* k : numKeys) if (h.has(k)) w.kvx(std::string("hdr.") + k, h.get(k));
    static const char* sizeKeys[] = {"kernel_size", "ramdisk_size", "second_size", "extra_size", "recovery_dtbo_size", "dtb_size",
                                     "signature_size", "vendor_ramdisk_table_size", "vendor_ramdisk_table_entry_num",
                                     "vendor_ramdisk_table_entry_size", "bootconfig_size"};
    for (const char* k : sizeKeys) if (h.has(k)) w.kvu(std::string("hdr.") + k, h.get(k));
    if (h.has("os_version")) {
        w.kvx("hdr.os_version_raw", h.osVersion());
        if (h.osVersion()) {
            w.kv("hdr.os_version", osVersionStr(h.osVersion()));
            w.kv("hdr.os_patch_level", osPatchStr(h.osVersion()));
        }
    }
    if (h.hasName()) w.kv("hdr.name", h.name());
    w.kv("hdr.cmdline", h.cmdline());
    if (h.hasId()) w.kv("hdr.id", hex(h.id().data(), h.id().size()));
    if (!h.reserved().empty()) w.kv("hdr.reserved", hex(h.reserved().data(), 16));
    w.kvu("hdr.struct_size", h.hdrSize());
    w.kvu("hdr.space", h.hdrSpace());

    size_t hdrSpace = h.hdrSpace();
    {
        size_t from = b.f.amonet ? b.headerOff : b.headerOff;
        View hv = b.blk(from, hdrSpace);
        writeFile(joinPath(outDir, "header.bin"), hv.p, hv.n);
        w.kv("hdr.file", "header.bin");
        w.kv("hdr.raw_sha256", sha256Hex(hv.p, hv.n));
    }
    if (b.headerOff > 0) {
        View pv = b.blk(0, b.headerOff);
        writeFile(joinPath(outDir, "preheader.bin"), pv.p, pv.n);
        w.kv("image.preheader_file", "preheader.bin");
        w.kv("image.preheader_md5", md5Hex(pv.p, pv.n));
    }

    w.section("layout");
    w.kvu("layout.header.offset", b.headerOff);
    w.kvu("layout.header.size", hdrSpace);
    auto lay = [&](const char* n, size_t off, uint64_t sz) {
        if (sz) {
            w.kvu(std::string("layout.") + n + ".offset", off);
            w.kvu(std::string("layout.") + n + ".size", sz);
        }
    };
    lay("kernel", b.offKernel, h.kernelSize());
    lay("ramdisk", b.offRamdisk, h.ramdiskSize());
    lay("second", b.offSecond, h.secondSize());
    lay("extra", b.offExtra, h.extraSize());
    lay("recovery_dtbo", b.offReco, h.recoveryDtboSize());
    lay("dtb", b.offDtb, h.dtbSize());
    lay("signature", b.offSig, h.signatureSize());
    lay("vendor_ramdisk_table", b.offVrTable, h.vrTableSize());
    lay("bootconfig", b.offBootcfg, h.bootconfigSize());
    {
        std::string mode;
        auto add = [&](const std::string& t) { mode += (mode.empty() ? "" : "+") + t; };
        if (b.kDtbAt > 0) add("appended_in_kernel");
        if (h.dtbSize()) add(h.vendor() ? "vendor_boot_dtb" : "header_dtb");
        if (h.extraSize()) {
            View ev = b.blk(b.offExtra, h.extraSize());
            std::string k = dtbFieldKind(ev.p, ev.n);
            if (!k.empty()) add("extra_" + k);
        }
        if (mode.empty()) mode = (!h.vendor() && h.headerVersion() >= 3) ? "external_vendor_boot" : "none";
        w.kv("layout.dtb_mode", mode);
    }
    progress(20);

    if (h.kernelSize()) {
        w.section("kernel");
        std::string kp = joinPath(outDir, "kernel");
        bool dec = false;
        logf("kernelを取り出すよ (%s)", fmtName(b.kfmt));
        if (b.f.mtkK) {
            writeFile(joinPath(outDir, "mtk_kernel.hdr"), b.mtkK.p, b.mtkK.n);
            w.kv("mtk_kernel.file", "mtk_kernel.hdr");
            w.kvu("mtk_kernel.size_field", b.mtkK.n >= 8 ? rd32(b.mtkK.p + 4) : 0);
            w.kv("mtk_kernel.name", b.mtkK.n >= 40 ? cstrOf((const char*)b.mtkK.p + 8, 32) : "");
        }
        if (b.f.zimage) {
            writeFile(joinPath(outDir, "zimage_head.bin"), b.z->head.data(), b.z->head.size());
            writeFile(joinPath(outDir, "zimage_tail.bin"), b.z->tail.data(), b.z->tail.size());
            w.kv("zimage.head_file", "zimage_head.bin");
            w.kv("zimage.tail_file", "zimage_tail.bin");
            w.kvu("zimage.piggy_size", b.z->piggyLen);
            w.kv("zimage.piggy_format", fmtName(b.z->fmt));
            w.kvu("zimage.off_inflated_size", b.z->offInflatedSize);
            w.kvu("zimage.off_lc0", b.z->offLc0);
            w.kvu("zimage.off_lc1", b.z->offLc1);
            w.kvu("zimage.off_table", b.z->offTable);
            w.kvu("zimage.head_size", b.z->head.size());
            w.kvu("zimage.tail_size", b.z->tail.size());
        }
        w.kvb("kernel.raw", o.skipDecomp);
        w.kvu("kernel.field_size", b.kFull.n);
        w.kv("kernel.layout", b.kDtbAt > 0 ? "kernel_with_appended_dtb" : "kernel_only");
        w.kvb("kernel.detect.mtk_header", b.kDetMtk);
        w.kvb("kernel.detect.zimage", b.kDetZimage);
        w.kv("kernel.detect.format", fmtName(b.kDetFmt));
        w.kvb("kernel.detect.appended_dtb", b.kDtbAt > 0);
        if (b.kDtbAt > 0) {
            w.kvu("kernel.detect.appended_dtb_offset", (uint64_t)b.kDtbAt);
            w.kvu("kernel.detect.appended_dtb_bytes", b.kFull.n - (size_t)b.kDtbAt);
            w.kvu("kernel.detect.appended_dtb_count", b.kChain.count);
            w.kvb("kernel.detect.appended_dtb_reaches_end", b.kChain.toEnd);
        }
        if (o.skipDecomp && b.kDetMtk) {
            w.kvb("kernel.raw_mtk", true);
            w.kvb("kernel.raw_mtk_size_consistent", b.kRawMtkConsistent);
            w.kvu("kernel.raw_mtk_size_field", b.kFull.n >= 8 ? rd32(b.kFull.p + 4) : 0);
        }
        writeBlob(kp, b.kBody, b.kfmt, o.skipDecomp, dec, 20, 40);
        blobInfo(w, "kernel", b.kBody, b.kfmt, "kernel", kp, dec);
        if (b.kernelDtbSplit) {
            writeFile(joinPath(outDir, "kernel_dtb"), b.kDtb.p, b.kDtb.n);
            w.kv("kernel_dtb.file", "kernel_dtb");
            w.kvu("kernel_dtb.size", b.kDtb.n);
            w.kv("kernel_dtb.md5", md5Hex(b.kDtb.p, b.kDtb.n));
            std::vector<std::string> ls;
            dtbDescribe(b.kDtb, "kernel_dtb", ls);
            for (auto& l : ls) w.raw(l + "\n");
        }
        analyzeKernel(w, kp, outDir, b.f.zimage);
    }
    progress(40);
    {
        w.section("ramdisk");
        w.kvb("ramdisk.present", h.ramdiskSize() != 0);
        if (h.ramdiskSize() == 0) {
            logf("ramdiskが無いよ〜(ヘッダにアドレスだけあって、サイズは0だよ)");
            if (h.has("ramdisk_addr")) w.kvx("ramdisk.address_only", h.get("ramdisk_addr"));
        }
    }

    if (h.ramdiskSize()) {
        if (!b.vr.empty()) {
            std::string vdir = joinPath(outDir, "vendor_ramdisk");
            mkdirs(vdir);
            w.kvu("vendor_ramdisk.count", b.vr.size());
            std::set<std::string> used;
            for (size_t i = 0; i < b.vr.size(); i++) {
                VrEntry& v = b.vr[i];
                std::string fn = v.name.empty() ? fmtstr("ramdisk_%zu", i) : safeName(v.name);
                std::string fnLow = fn;
                for (auto& c : fnLow) c = (char)tolower((unsigned char)c);
                if (used.count(fnLow)) fn += fmtstr("_%zu", i);
                used.insert(fnLow);
                fn += ".cpio";
                std::string pf = fmtstr("vendor_ramdisk.%zu", i);
                v.file = "vendor_ramdisk/" + fn;
                View r = b.rField.sub(v.offset, v.size);
                bool dec = false;
                writeBlob(joinPath(outDir, v.file), r, v.fmt, o.skipDecomp, dec, 40 + (int)(18 * i / b.vr.size()), 40 + (int)(18 * (i + 1) / b.vr.size()));
                w.kv(pf + ".name", v.name);
                w.kvu(pf + ".type", v.type);
                w.kv(pf + ".type_name", typeName(v.type));
                std::string bid;
                for (int k = 0; k < 16; k++) bid += fmtstr("%08x", v.boardId[k]);
                w.kv(pf + ".board_id", bid);
                w.kvu(pf + ".offset", v.offset);
                blobInfo(w, pf, r, v.fmt, v.file, joinPath(outDir, v.file), dec);
                analyzeCpio(w, pf, joinPath(outDir, v.file));
                logf("vendor ramdisk[%zu] %s を取り出したよ", i, v.name.c_str());
            }
        } else {
            if (b.f.mtkR) {
                writeFile(joinPath(outDir, "mtk_ramdisk.hdr"), b.mtkRhdr.p, b.mtkRhdr.n);
                w.kv("mtk_ramdisk.file", "mtk_ramdisk.hdr");
                w.kv("mtk_ramdisk.name", b.mtkRhdr.n >= 40 ? cstrOf((const char*)b.mtkRhdr.p + 8, 32) : "");
            }
            std::string rp = joinPath(outDir, "ramdisk.cpio");
            bool dec = false;
            logf("ramdiskを取り出すよ (%s)", fmtName(b.rfmt));
            writeBlob(rp, b.rBody, b.rfmt, o.skipDecomp, dec, 40, 58);
            blobInfo(w, "ramdisk", b.rBody, b.rfmt, "ramdisk.cpio", rp, dec);
            analyzeCpio(w, "ramdisk", rp);
        }
    }
    progress(60);

    auto plain = [&](const char* name, size_t off, uint32_t sz, Fmt fmt, bool tryDecomp) {
        if (!sz) return;
        View v = b.blk(off, sz);
        std::string p = joinPath(outDir, name);
        bool dec = false;
        w.section(name);
        if (tryDecomp) writeBlob(p, v, fmt, o.skipDecomp, dec);
        else writeFile(p, v.p, v.n);
        blobInfo(w, name, v, fmt, name, p, dec);
    };
    plain("second", b.offSecond, h.secondSize(), F_UNKNOWN, false);
    plain("extra", b.offExtra, h.extraSize(), b.efmt, true);
    if (h.recoveryDtboSize()) {
        plain("recovery_dtbo", b.offReco, h.recoveryDtboSize(), F_UNKNOWN, false);
        std::vector<std::string> ls;
        dtboDescribe(b.blk(b.offReco, h.recoveryDtboSize()), "recovery_dtbo", ls);
        for (auto& l : ls) w.raw(l + "\n");
    }
    if (h.dtbSize()) {
        plain("dtb", b.offDtb, h.dtbSize(), F_UNKNOWN, false);
        std::vector<std::string> ls;
        View dv = b.blk(b.offDtb, h.dtbSize());
        dtbDescribe(dv, "dtb", ls);
        dtboDescribe(dv, "dtb", ls);
        for (auto& l : ls) w.raw(l + "\n");
    }
    plain("bootconfig", b.offBootcfg, h.bootconfigSize(), F_UNKNOWN, false);
    if (h.bootconfigSize()) {
        View bc = b.blk(b.offBootcfg, h.bootconfigSize());
        std::string txt((const char*)bc.p, bc.n);
        size_t z = txt.find('\0');
        if (z != std::string::npos) txt.resize(z);
        w.kv("bootconfig.text", txt);
    }
    if (h.signatureSize()) {
        View sv = b.blk(b.offSig, h.signatureSize());
        writeFile(joinPath(outDir, "boot_signature"), sv.p, sv.n);
        w.section("boot_signature");
        w.kv("boot_signature.file", "boot_signature");
        w.kvu("boot_signature.size", sv.n);
        w.kv("boot_signature.sha256", sha256Hex(sv.p, sv.n));
        w.kv("boot_signature.md5", md5Hex(sv.p, sv.n));
        size_t dl = 0;
        std::string tg;
        uint64_t sl = 0;
        if (parseBootSignature(sv, dl, tg, sl)) {
            w.kv("boot_signature.target", tg);
            w.kvu("boot_signature.signed_length", sl);
        }
    }
    progress(75);

    w.section("security");
    w.kvb("security.avb1_signed", b.f.avb1);
    if (b.f.avb1) {
        writeFile(joinPath(outDir, "avb1_signature.bin"), b.avb1Sig.p, b.avb1Sig.n);
        w.kv("security.avb1_signature_file", "avb1_signature.bin");
        w.kvu("security.avb1_signature_size", b.avb1Sig.n);
        w.kv("security.avb1_target", b.avb1Target);
        w.kvu("security.avb1_signed_length", b.avb1Len);
    }
    w.kvb("security.samsung_seandroidenforce", b.f.seandroid);
    if (b.f.signer02) {
        writeFile(joinPath(outDir, "signer_ver02.bin"), b.tail.p + 16, 512);
        w.kv("security.signer_ver02_file", "signer_ver02.bin");
    }
    w.kvb("security.lg_bump", b.f.lgbump);
    w.kvb("security.avb2", b.f.avb);
    if (!b.avbFooter.empty()) {
        writeFile(joinPath(outDir, "avb_footer.bin"), b.avbFooter.p, b.avbFooter.n);
        w.kv("avb.footer_file", "avb_footer.bin");
        w.kv("avb.footer.md5", md5Hex(b.avbFooter.p, b.avbFooter.n));
        w.kv("avb.footer_version", fmtstr("%u.%u", rd32be(b.avbFooter.p + 4), rd32be(b.avbFooter.p + 8)));
        w.kvu("avb.footer_original_image_size", rd64be(b.avbFooter.p + 12));
        w.kvu("avb.footer_vbmeta_offset", rd64be(b.avbFooter.p + 20));
        w.kvu("avb.footer_vbmeta_size", rd64be(b.avbFooter.p + 28));
    }
    if (b.f.avb) {
        writeFile(joinPath(outDir, "vbmeta.bin"), b.vbmeta.p, b.vbmeta.n);
        w.kv("avb.vbmeta_file", "vbmeta.bin");
        w.kv("avb.vbmeta.md5", md5Hex(b.vbmeta.p, b.vbmeta.n));
        w.kv("avb.vbmeta_sha256", sha256Hex(b.vbmeta.p, b.vbmeta.n));
        avbDescribe(b.vbmeta, w, "avb.vbmeta");
    }
    if (!b.f.avb && !b.f.avb1 && !b.f.seandroid && !b.f.lgbump) {
        w.kv("security.note", "署名/AVB情報は見つからなかったよ");
    }
    progress(90);
    writeFile(joinPath(outDir, "info.txt"), w.str());

    if (o.extractRamdisk) {
        try {
            if (!b.vr.empty()) {
                for (auto& v : b.vr) {
                    std::string src = joinPath(outDir, v.file);
                    std::string dst = joinPath(outDir, "rootfs_" + safeName(baseName(v.file)));
                    ramdiskUnpack(src, dst);
                }
            } else if (h.ramdiskSize()) {
                ramdiskUnpack(joinPath(outDir, "ramdisk.cpio"), joinPath(outDir, "ramdisk_extracted"));
            } else {
                logf("ramdiskが無いから展開はスキップしたよ");
            }
        } catch (const Canceled&) {
            throw;
        } catch (const std::exception& e) {
            logf("ramdiskの展開はスキップしたよ: %s", e.what());
        }
    }
    progress(100);
    logf("info.txt に情報を書いたよ〜");
}

namespace {

void pwriteAll(int fd, const void* p, size_t n, uint64_t off) {
    const uint8_t* b = (const uint8_t*)p;
    while (n) {
        ssize_t r = pwrite(fd, b, n, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw Error(fmtstr("書き込み失敗(patch): %s", strerror(errno)));
        }
        b += r;
        off += (uint64_t)r;
        n -= (size_t)r;
    }
}

template <class F>
void preadEach(int fd, uint64_t off, uint64_t len, F fn) {
    Bytes buf(1 << 20);
    while (len) {
        size_t c = (size_t)std::min<uint64_t>(len, buf.size());
        size_t got = 0;
        while (got < c) {
            ssize_t r = pread(fd, buf.data() + got, c - got, (off_t)(off + got));
            if (r < 0) {
                if (errno == EINTR) continue;
                throw Error("読み戻し失敗");
            }
            if (r == 0) throw Error("読み戻しが途中で終わったよ");
            got += (size_t)r;
        }
        fn(buf.data(), c);
        off += c;
        len -= c;
    }
}

struct IdHasher {
    bool use1;
    Sha1 s1;
    Sha256 s2;
    void update(const uint8_t* p, size_t n) { if (use1) s1.update(p, n); else s2.update(p, n); }
    void fin(uint8_t* out, size_t& n) { if (use1) { s1.final(out); n = 20; } else { s2.final(out); n = 32; } }
};

uint64_t compressLen(Fmt f, View in, FileSink& out, int lo = -1, int hi = -1) {
    uint64_t before = out.total();
    if (lo >= 0) {
        ProgressScope ps(lo, hi);
        compress(f, in, out);
    } else {
        compress(f, in, out);
    }
    return out.total() - before;
}

Fmt resolveFmt(const std::string& req, const std::string& orig) {
    std::string r = req;
    if (r.empty() || r == "auto") r = orig;
    if (r == "raw" || r == "none" || r == "cpio" || r.empty()) return F_UNKNOWN;
    return fmtFromName(r);
}

}

void bootRepack(const std::string& dir, const std::string& outFile, const BootRepackOpts& o) {
    std::string infoPath = joinPath(dir, "info.txt");
    if (!fileExists(infoPath)) throw Error("info.txt が見つからないよ〜。unpackしたフォルダを選んでね");
    InfoReader info;
    info.parse(readText(infoPath));
    if (info.get("kind") != "boot") throw Error("このinfo.txtはbootイメージ用じゃないみたい(kind=boot)");
    logf("info.txt を読んだよ〜");

    HKind kind;
    if (!kindFromName(info.get("hdr.kind"), kind)) throw Error("info.txtのhdr.kindが読めないよ");
    Hdr hdr;
    hdr.init(kind);
    std::string headerFile = joinPath(dir, info.get("hdr.file", "header.bin"));
    Bytes hdrRegion;
    size_t hdrShift = info.getb("flag.amonet") ? kAmonetMicro : 0;
    if (fileExists(headerFile)) {
        hdrRegion = readFile(headerFile, 1 << 24);
        if (hdrRegion.size() > hdrShift) {
            size_t n = std::min(hdr.raw.size(), hdrRegion.size() - hdrShift);
            memcpy(hdr.raw.data(), hdrRegion.data() + hdrShift, n);
        }
    }
    Bytes hdrOrig = hdr.raw;
    std::string magic = info.get("hdr.magic", hdr.vendor() ? "VNDRBOOT" : "ANDROID!");
    if (hdr.raw.size() >= 8 && memcmp(hdr.raw.data(), "ANDROID!", 8) != 0 && memcmp(hdr.raw.data(), "VNDRBOOT", 8) != 0) {
        memset(hdr.raw.data(), 0, 8);
        memcpy(hdr.raw.data(), magic.data(), std::min<size_t>(8, magic.size()));
    }
    static const char* allKeys[] = {"kernel_addr", "ramdisk_addr", "second_addr", "tags_addr", "dtb_addr", "unknown",
                                    "recovery_dtbo_offset", "page_size", "header_version", "vendor_ramdisk_table_entry_num",
                                    "vendor_ramdisk_table_entry_size", "vendor_ramdisk_table_size"};
    for (const char* k : allKeys) {
        std::string key = std::string("hdr.") + k;
        if (info.has(key) && hdr.has(k)) hdr.set(k, info.getu(key));
    }
    if (hdr.has("os_version")) {
        if (info.has("hdr.os_version") || info.has("hdr.os_patch_level")) {
            std::string v = info.get("hdr.os_version"), p = info.get("hdr.os_patch_level");
            uint32_t base = (uint32_t)info.getu("hdr.os_version_raw", hdr.osVersion());
            uint32_t cur = (uint32_t)hdr.osVersion();
            bool same = cur == 0 ? (v.empty() && p.empty()) : (v == osVersionStr(cur) && p == osPatchStr(cur));
            if (!same) hdr.set("os_version", osVersionPack(base, info.has("hdr.os_version") ? &v : nullptr, info.has("hdr.os_patch_level") ? &p : nullptr));
        } else if (info.has("hdr.os_version_raw")) {
            hdr.set("os_version", info.getu("hdr.os_version_raw"));
        }
    }
    if (hdr.hasName() && info.has("hdr.name") && info.get("hdr.name") != hdr.name()) hdr.setName(info.get("hdr.name"));
    if (info.has("hdr.cmdline") && info.get("hdr.cmdline") != hdr.cmdline()) hdr.setCmdline(info.get("hdr.cmdline"));
    if (hdr.hasId() && info.has("hdr.id")) {
        Bytes idb;
        if (unhex(info.get("hdr.id"), idb)) hdr.setId(idb.data(), idb.size());
    }
    if (info.has("hdr.reserved")) {
        Bytes rb;
        if (unhex(info.get("hdr.reserved"), rb)) hdr.setReserved(rb);
    }
    if (hdr.pageSize() == 0 || (hdr.pageSize() & (hdr.pageSize() - 1))) throw Error("page_sizeが変だよ(2のべき乗じゃないよ)");

    Flags f;
    f.mtkK = info.getb("flag.mtk_kernel");
    f.mtkR = info.getb("flag.mtk_ramdisk");
    f.zimage = info.getb("flag.zimage_kernel");
    f.dhtb = info.getb("flag.dhtb");
    f.seandroid = info.getb("flag.seandroid");
    f.signer02 = info.getb("flag.signer_ver02");
    f.lgbump = info.getb("flag.lg_bump");
    f.sha256 = info.getb("flag.sha256_id");
    f.blob = info.getb("flag.blob");
    f.nook = info.getb("flag.nookhd");
    f.acclaim = info.getb("flag.acclaim");
    f.amonet = info.getb("flag.amonet");
    f.avb1 = info.getb("flag.avb1_signed");
    f.avb = info.getb("flag.avb2_footer");

    uint64_t origSize = info.getu("image.original_size", 0);

    bool reuseOk = !o.forceRebuild && !o.skipComp && o.ramdiskFmt == "auto" && o.kernelFmt == "auto";
    std::string origPath = joinPath(dir, info.get("original.file", "original.img"));
    MappedFile origMap;
    bool haveOrig = false;
    if (reuseOk && fileExists(origPath) && (uint64_t)fileSize(origPath) == origSize && origSize > 0) {
        origMap.open(origPath);
        haveOrig = true;
    } else if (reuseOk) {
        logf("original.img が無い/サイズ違いだから全部作り直すよ");
    }
    bool hdrSame = hdr.raw == hdrOrig;
    auto same = [&](const std::string& key, const std::string& file) {
        bool had = info.has(key + ".md5");
        bool has = fileExists(joinPath(dir, file));
        if (had != has) return false;
        if (!had) return true;
        MappedFile m(joinPath(dir, file));
        bool eq = md5Hex(m.data(), m.size()) == info.get(key + ".md5");
        if (!eq) logf("%s が変わってるよ", file.c_str());
        return eq;
    };
    auto sameKey = [&](const std::string& key, const std::string& dflt) { return same(key, info.get(key + ".file", dflt)); };
    auto storedView = [&](const std::string& key, const std::string& dflt, uint64_t off, uint64_t len, View& v) {
        if (!haveOrig || len == 0 || off + len > origMap.size()) return false;
        if (!sameKey(key, dflt)) return false;
        v = View(origMap.data() + off, (size_t)len);
        return true;
    };
    bool unchanged = haveOrig && hdrSame;
    if (unchanged) {
        unchanged = same("boot_signature", "boot_signature") &&
                    same("avb.footer", info.get("avb.footer_file", "avb_footer.bin")) &&
                    same("avb.vbmeta", info.get("avb.vbmeta_file", "vbmeta.bin"));
    }
    if (unchanged && f.avb1) unchanged = false;
    if (f.avb1) logf("AVB1署名付きイメージだよ。作業フォルダ内の鍵ペアを使用して再署名するよ");
    if (haveOrig && !hdrSame) logf("ヘッダ(info.txt)が変わってるから再構築するよ");
    if (unchanged) {
        unchanged = sameKey("kernel", "kernel") && sameKey("kernel_dtb", "kernel_dtb") && sameKey("second", "second") &&
                    sameKey("extra", "extra") && sameKey("recovery_dtbo", "recovery_dtbo") && sameKey("dtb", "dtb") &&
                    sameKey("bootconfig", "bootconfig");
        uint32_t vc = (uint32_t)info.getu("vendor_ramdisk.count", 0);
        if (unchanged && vc) {
            for (uint32_t i = 0; i < vc && unchanged; i++) unchanged = sameKey(fmtstr("vendor_ramdisk.%u", i), "");
        } else if (unchanged) {
            unchanged = sameKey("ramdisk", "ramdisk.cpio");
        }
    }
    if (unchanged) {
        logf("中身は変わってないから元イメージをそのまま出力するよ〜");
        {
            ProgressScope ps(0, 100);
            copyFileTo(origPath, outFile);
        }
        progress(100);
        logf("リパックできたよ〜(原本と同一): %s", baseName(outFile).c_str());
        return;
    }

    for (const char* k : {"kernel_size", "ramdisk_size", "second_size", "dtb_size", "bootconfig_size", "extra_size", "recovery_dtbo_size"})
        if (hdr.has(k)) hdr.set(k, 0);
    if (hdr.has("extra_size")) hdr.set("extra_size", 0);

    std::unique_ptr<ZImage> z;
    if (f.zimage) {
        z.reset(new ZImage());
        Bytes hb = readFile(joinPath(dir, info.get("zimage.head_file", "zimage_head.bin")));
        Bytes tb = readFile(joinPath(dir, info.get("zimage.tail_file", "zimage_tail.bin")));
        z->head = hb;
        z->tail = tb;
        z->piggyLen = (size_t)info.getu("zimage.piggy_size");
        z->fmt = fmtFromName(info.get("zimage.piggy_format"));
        z->offInflatedSize = (uint32_t)info.getu("zimage.off_inflated_size");
        z->offLc0 = (uint32_t)info.getu("zimage.off_lc0");
        z->offLc1 = (uint32_t)info.getu("zimage.off_lc1");
        z->offTable = (uint32_t)info.getu("zimage.off_table");
    }

    Bytes avbFoot, avbMeta;
    uint64_t avbVo = 0, avbFinal = 0, avbImgLen = 0;
    std::string avb1Target = info.get("security.avb1_target", "/boot");
    if (info.has("avb.footer_file") && fileExists(joinPath(dir, info.get("avb.footer_file")))) {
        avbFoot = readFile(joinPath(dir, info.get("avb.footer_file")), 4096);
        if (avbFoot.size() != kAvbFooter || memcmp(avbFoot.data(), "AVBf", 4) != 0) throw Error("AVB2フッターが破損しています");
    }
    if (f.avb && avbFoot.empty()) throw Error("AVB2のVBMetaがあるのにフッターがありません");
    if (!avbFoot.empty()) {
        uint64_t footerOffset = rd64be(avbFoot.data() + 20);
        uint64_t footerSize = rd64be(avbFoot.data() + 28);
        if (!f.avb || footerSize < 256 || footerSize > (1u << 24) || footerOffset > UINT64_MAX - footerSize)
            throw Error("AVB2のVBMeta情報が不正です。元のメタデータを維持できないためリパックを中止しました");
        if (!info.has("avb.vbmeta_file") || !fileExists(joinPath(dir, info.get("avb.vbmeta_file"))))
            throw Error("AVB2のVBMetaファイルがありません。署名情報を失わないためリパックを中止しました");
        avbMeta = readFile(joinPath(dir, info.get("avb.vbmeta_file")), (size_t)(1u << 24));
        if (avbMeta.size() != footerSize || avbMeta.size() < 256 || memcmp(avbMeta.data(), "AVB0", 4) != 0)
            throw Error("AVB2のVBMetaサイズまたはヘッダが一致しません");
        uint64_t authSize = rd64be(avbMeta.data() + 12);
        uint64_t auxSize = rd64be(avbMeta.data() + 20);
        if (authSize > UINT64_MAX - 256 || auxSize > UINT64_MAX - 256 - authSize || 256 + authSize + auxSize > avbMeta.size())
            throw Error("AVB2のVBMeta内部サイズが不正です");
    }
    struct { uint64_t header = 0, kernel = 0, ramdisk = 0, second = 0, extra = 0, dtb = 0, tail = 0, eof = 0, reco = 0; } off;
    size_t preSize = 0;
    FileSink out(outFile);
    uint64_t z_payload = 0;
    Bytes signer02Bytes;
    std::vector<VrEntry> vr;
    uint32_t vrCount = (uint32_t)info.getu("vendor_ramdisk.count", 0);
    auto fileIn = [&](const std::string& name) { return joinPath(dir, name); };
    auto alignRel = [&](uint64_t a) {
        uint64_t cur = out.total() - off.header;
        uint64_t r = cur % a;
        if (r) out.zeros((size_t)(a - r));
    };
    auto alignP = [&]() { alignRel(hdr.pageSize()); };

    try {

        if (info.has("image.preheader_file") && fileExists(fileIn(info.get("image.preheader_file")))) {
            Bytes pre = readFile(fileIn(info.get("image.preheader_file")), 1 << 24);
            out.write(pre.data(), pre.size());
            preSize = pre.size();
        }
        off.header = out.total();
        {
            size_t space = hdr.hdrSpace();
            if (!hdrRegion.empty()) {
                out.write(hdrRegion.data(), std::min(space, hdrRegion.size()));
                if (hdrRegion.size() < space) out.zeros(space - hdrRegion.size());
            } else {
                out.zeros(space);
            }
        }
        progress(5);

        off.kernel = out.total();
        uint64_t kstored = info.getu("kernel.stored_size", 0);
        std::string kfile = fileIn(info.get("kernel.file", "kernel"));
        if (f.mtkK) {
            Bytes m = readFile(fileIn(info.get("mtk_kernel.file", "mtk_kernel.hdr")), 4096);
            if (m.size() != kMtkHdr) throw Error("mtk_kernel.hdr のサイズが変だよ");
            out.write(m.data(), m.size());
        }
        if (f.zimage) out.write(z->head.data(), z->head.size());
        View kKeep;
        bool rawKernel = info.getb("kernel.raw");
        if (!f.zimage && storedView("kernel", "kernel", info.getu("layout.kernel.offset") + (f.mtkK ? kMtkHdr : 0), kstored, kKeep)) {
            logf("kernelは変更なしだから元のバイト列を使うよ");
            out.write(kKeep.p, kKeep.n);
            hdr.set("kernel_size", kKeep.n);
        } else if (rawKernel && fileExists(kfile)) {
            MappedFile m(kfile);
            logf("kernelをそのまま書くよ (%s)", humanSize(m.size()).c_str());
            uint64_t origLen = info.getu("kernel.field_size", 0);
            bool patchMtk = info.getb("kernel.raw_mtk") && m.size() >= kMtkHdr && origLen != m.size() && checkFmtLg(m.data(), m.size()) == F_MTK &&
                            rd32(m.data() + 4) == (uint32_t)info.getu("kernel.raw_mtk_size_field", 0);
            if (patchMtk) {
                uint8_t mh[kMtkHdr];
                memcpy(mh, m.data(), kMtkHdr);
                wr32(mh + 4, (uint32_t)((int64_t)rd32(mh + 4) + (int64_t)m.size() - (int64_t)origLen));
                out.write(mh, kMtkHdr);
                out.write(m.data() + kMtkHdr, m.size() - kMtkHdr);
                logf("MTK kernelヘッダのサイズ欄を直したよ");
            } else {
                out.write(m.data(), m.size());
            }
            hdr.set("kernel_size", m.size());
        } else if (fileExists(kfile)) {
            MappedFile m(kfile);
            Fmt kf = resolveFmt(o.kernelFmt, info.get("kernel.format", "raw"));
            uint64_t payload;
            logf("kernelを書くよ (%s)", fmtCompressed(kf) ? fmtName(kf) : "raw");
            if (!o.skipComp && !fmtCompressedAny(checkFmt(m.data(), m.size())) && fmtCompressed(kf)) {
                payload = compressLen(kf, m.view(), out, 5, 25);
                if (f.zimage && kf != F_GZIP) {
                    uint8_t sz[4];
                    wr32(sz, (uint32_t)m.size());
                    out.write(sz, 4);
                    payload += 4;
                }
            } else {
                out.write(m.data(), m.size());
                payload = m.size();
            }
            hdr.set("kernel_size", payload);
            if (f.zimage) {
                z_payload = payload;
                Bytes tail = z->newTail((size_t)payload);
                out.write(tail.data(), tail.size());
                hdr.set("kernel_size", z->head.size() + payload + tail.size());
            }
        } else if (kstored != 0) {
            throw Error("kernel ファイルが見つからないよ〜");
        }
        std::string kdtb = fileIn(info.get("kernel_dtb.file", "kernel_dtb"));
        if (!rawKernel && fileExists(kdtb)) {
            MappedFile m(kdtb);
            out.write(m.data(), m.size());
            hdr.set("kernel_size", hdr.kernelSize() + m.size());
        }
        alignP();
        progress(25);

        off.ramdisk = out.total();
        if (f.mtkR) {
            Bytes m = readFile(fileIn(info.get("mtk_ramdisk.file", "mtk_ramdisk.hdr")), 4096);
            if (m.size() != kMtkHdr) throw Error("mtk_ramdisk.hdr のサイズが変だよ");
            out.write(m.data(), m.size());
        }
        if (vrCount) {
            uint32_t rdOff = 0;
            for (uint32_t i = 0; i < vrCount; i++) {
                std::string pf = fmtstr("vendor_ramdisk.%u", i);
                VrEntry v;
                v.name = info.get(pf + ".name");
                v.type = (uint32_t)info.getu(pf + ".type");
                std::string bid = info.get(pf + ".board_id");
                for (int k = 0; k < 16 && (size_t)(k + 1) * 8 <= bid.size(); k++)
                    v.boardId[k] = (uint32_t)strtoul(bid.substr(k * 8, 8).c_str(), nullptr, 16);
                v.file = info.get(pf + ".file");
                std::string orig = info.get(pf + ".format", "raw");
                MappedFile m(fileIn(v.file));
                Fmt rf = resolveFmt(o.ramdiskFmt, orig);
                v.offset = rdOff;
                View keep;
                if (storedView(pf, "", info.getu("layout.ramdisk.offset") + info.getu(pf + ".offset"), info.getu(pf + ".stored_size"), keep)) {
                    out.write(keep.p, keep.n);
                    v.size = (uint32_t)keep.n;
                } else if (!o.skipComp && !fmtCompressedAny(checkFmt(m.data(), m.size())) && fmtCompressed(rf)) {
                    v.size = (uint32_t)compressLen(rf, m.view(), out, 25 + (int)(33 * i / vrCount), 25 + (int)(33 * (i + 1) / vrCount));
                } else {
                    out.write(m.data(), m.size());
                    v.size = (uint32_t)m.size();
                }
                uint64_t was = info.getu(pf + ".stored_size", 0);
                if (was && v.size > was) logf("! vendor ramdisk[%u] は元より %s 大きくなったよ (%s → %s)", i, humanSize(v.size - was).c_str(), humanSize(was).c_str(), humanSize(v.size).c_str());
                rdOff += v.size;
                vr.push_back(v);
                logf("vendor ramdisk[%u] を書いたよ", i);
            }
            hdr.set("ramdisk_size", rdOff);
            alignP();
        } else {
            std::string rfile = fileIn(info.get("ramdisk.file", "ramdisk.cpio"));
            View rKeep;
            if (storedView("ramdisk", "ramdisk.cpio", info.getu("layout.ramdisk.offset") + (f.mtkR ? kMtkHdr : 0), info.getu("ramdisk.stored_size"), rKeep)) {
                logf("ramdiskは変更なしだから元のバイト列を使うよ");
                out.write(rKeep.p, rKeep.n);
                hdr.set("ramdisk_size", rKeep.n);
                alignP();
            } else if (fileExists(rfile)) {
                MappedFile m(rfile);
                Fmt rf = resolveFmt(o.ramdiskFmt, info.get("ramdisk.format", "raw"));
                if (!o.skipComp && !hdr.vendor() && hdr.headerVersion() == 4 && rf != F_LZ4_LEGACY && o.ramdiskFmt == "auto") {
                    logf("v4 bootのramdiskはlz4_legacyに合わせるね");
                    rf = F_LZ4_LEGACY;
                }
                logf("ramdiskを書くよ (%s)", fmtCompressed(rf) ? fmtName(rf) : "raw");
                if (!o.skipComp && !fmtCompressedAny(checkFmt(m.data(), m.size())) && fmtCompressed(rf)) {
                    hdr.set("ramdisk_size", compressLen(rf, m.view(), out, 25, 58));
                } else {
                    out.write(m.data(), m.size());
                    hdr.set("ramdisk_size", m.size());
                }
                alignP();
            } else if (info.getu("layout.ramdisk.size", 0) != 0) {
                throw Error("ramdisk.cpio が見つからないよ〜");
            } else {
                logf("ramdiskが無いよ〜(元から空だったから、このままサイズ0で作るよ)");
            }
        }
        if (!vrCount) {
            uint64_t was = info.getu("ramdisk.stored_size", 0);
            if (was && hdr.ramdiskSize() > was) logf("! ramdiskは元より %s 大きくなったよ (%s → %s)", humanSize(hdr.ramdiskSize() - was).c_str(), humanSize(was).c_str(), humanSize(hdr.ramdiskSize()).c_str());
        }
        progress(60);

        off.second = out.total();
        if (fileExists(fileIn("second"))) {
            MappedFile m(fileIn("second"));
            out.write(m.data(), m.size());
            hdr.set("second_size", m.size());
            alignP();
        }

        off.extra = out.total();
        if (fileExists(fileIn("extra"))) {
            MappedFile m(fileIn("extra"));
            Fmt ef = resolveFmt("auto", info.get("extra.format", "raw"));
            uint64_t sz;
            if (!o.skipComp && !fmtCompressedAny(checkFmt(m.data(), m.size())) && fmtCompressed(ef)) sz = compressLen(ef, m.view(), out);
            else { out.write(m.data(), m.size()); sz = m.size(); }
            hdr.set("extra_size", sz);
            alignP();
        }

        if (fileExists(fileIn("recovery_dtbo"))) {
            MappedFile m(fileIn("recovery_dtbo"));
            hdr.set("recovery_dtbo_offset", out.total());
            out.write(m.data(), m.size());
            hdr.set("recovery_dtbo_size", m.size());
            alignP();
        }

        off.dtb = out.total();
        if (fileExists(fileIn("dtb"))) {
            MappedFile m(fileIn("dtb"));
            out.write(m.data(), m.size());
            hdr.set("dtb_size", m.size());
            alignP();
        }

        if (hdr.has("signature_size") && fileExists(fileIn("boot_signature"))) {
            MappedFile m(fileIn("boot_signature"));
            out.write(m.data(), m.size());
            wr32(hdr.raw.data() + 1580, (uint32_t)m.size());
            alignP();
        }

        if (!vr.empty()) {
            for (auto& v : vr) {
                uint8_t e[108];
                memset(e, 0, sizeof(e));
                wr32(e, v.size);
                wr32(e + 4, v.offset);
                wr32(e + 8, v.type);
                memcpy(e + 12, v.name.data(), std::min<size_t>(v.name.size(), 31));
                for (int k = 0; k < 16; k++) wr32(e + 44 + k * 4, v.boardId[k]);
                out.write(e, sizeof(e));
            }
            hdr.set("vendor_ramdisk_table_size", vr.size() * 108);
            hdr.set("vendor_ramdisk_table_entry_num", vr.size());
            hdr.set("vendor_ramdisk_table_entry_size", 108);
            alignP();
        }

        if (fileExists(fileIn("bootconfig"))) {
            MappedFile m(fileIn("bootconfig"));
            out.write(m.data(), m.size());
            hdr.set("bootconfig_size", m.size());
            alignP();
        }
        off.tail = out.total();
        if (f.seandroid) {
            out.write((const uint8_t*)kSeandroid, 16);
            if (f.dhtb) { const uint8_t ff[4] = {0xff, 0xff, 0xff, 0xff}; out.write(ff, 4); }
            if (f.signer02) {
                signer02Bytes = readFile(fileIn(info.get("security.signer_ver02_file", "signer_ver02.bin")), 4096);
                if (signer02Bytes.size() != 512) throw Error("signer_ver02.bin のサイズが変だよ");
                out.write(signer02Bytes.data(), 512);
            }
        } else if (f.lgbump) {
            out.write(kLgBump, 16);
        }
        off.eof = out.total();
        uint64_t target = o.padToOriginal ? origSize : 0;
        if (out.total() < target) out.zeros((size_t)(target - out.total()));
        if (origSize && out.total() > origSize) {
            logf("! 元のサイズ(%s)より大きくなったよ: %s。パーティション容量に注意してね", humanSize(origSize).c_str(),
                 humanSize(out.total()).c_str());
        }
        out.close();
    } catch (...) {
        out.close();
        unlink(outFile.c_str());
        throw;
    }
    progress(80);

    int fd = open(outFile.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        unlink(outFile.c_str());
        throw Error(fmtstr("出力を開き直せないよ: %s", strerror(errno)));
    }
    try {
        uint64_t aospSize = off.tail - off.header;
        uint64_t origImgSize = off.eof - off.header;
        if (f.mtkK) {
            uint8_t b4[4];
            wr32(b4, hdr.kernelSize());
            pwriteAll(fd, b4, 4, off.kernel + 4);
            hdr.set("kernel_size", hdr.kernelSize() + kMtkHdr);
        }
        if (f.mtkR) {
            uint8_t b4[4];
            wr32(b4, hdr.ramdiskSize());
            pwriteAll(fd, b4, 4, off.ramdisk + 4);
            hdr.set("ramdisk_size", hdr.ramdiskSize() + kMtkHdr);
        }
        if (f.zimage && z_payload) {
            Bytes hs = z->newHead((size_t)z_payload);
            pwriteAll(fd, hs.data(), hs.size(), off.kernel + (f.mtkK ? kMtkHdr : 0));
        }
        if (hdr.has("header_size") && hdr.kind != K_PXA) hdr.set("header_size", hdr.hdrSize());
        if (hdr.hasId()) {
            IdHasher hs;
            hs.use1 = !f.sha256;
            auto up32 = [&](uint32_t v) { uint8_t b4[4]; wr32(b4, v); hs.update(b4, 4); };
            uint32_t sz = hdr.kernelSize();
            preadEach(fd, off.kernel, sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
            up32(sz);
            sz = hdr.ramdiskSize();
            preadEach(fd, off.ramdisk, sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
            up32(sz);
            sz = hdr.secondSize();
            preadEach(fd, off.second, sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
            up32(sz);
            sz = hdr.extraSize();
            if (sz) {
                preadEach(fd, off.extra, sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
                up32(sz);
            }
            uint32_t ver = hdr.headerVersion();
            if (ver == 1 || ver == 2) {
                sz = hdr.recoveryDtboSize();
                preadEach(fd, hdr.recoveryDtboOffset(), sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
                up32(sz);
            }
            if (ver == 2) {
                sz = hdr.dtbSize();
                preadEach(fd, off.dtb, sz, [&](const uint8_t* p, size_t n) { hs.update(p, n); });
                up32(sz);
            }
            uint8_t dg[32];
            size_t dn = 0;
            hs.fin(dg, dn);
            hdr.setId(dg, dn);
        }

        if (f.amonet) {
            size_t real = std::min(hdr.hdrSpace() > kAmonetMicro ? hdr.hdrSpace() - kAmonetMicro : 0, hdr.hdrSize());
            pwriteAll(fd, hdr.raw.data(), real, off.header + kAmonetMicro);
        } else {
            pwriteAll(fd, hdr.raw.data(), hdr.hdrSize(), off.header);
        }
        if (f.dhtb && preSize >= kDhtbHdr) {
            uint8_t b4[4];
            wr32(b4, (uint32_t)origImgSize);
            pwriteAll(fd, b4, 4, 48);
            Sha256 sh;
            preadEach(fd, off.header, origImgSize, [&](const uint8_t* p, size_t n) { sh.update(p, n); });
            uint8_t dg[32];
            sh.final(dg);
            pwriteAll(fd, dg, 32, 8);
        } else if (f.blob && preSize >= kBlobHdr) {
            uint8_t b4[4];
            wr32(b4, (uint32_t)aospSize);
            pwriteAll(fd, b4, 4, kBlobSizeOff);
        }
        if (f.avb1) {
            Bytes signature = signAvb1PayloadFile(outFile, dir, off.header, aospSize, avb1Target);
            size_t derLen = 0;
            std::string signedTarget;
            uint64_t signedLength = 0;
            if (!parseBootSignature(View(signature.data(), signature.size()), derLen, signedTarget, signedLength) ||
                derLen != signature.size() || signedTarget != avb1Target || signedLength != aospSize) {
                throw Error("生成したAVB1署名データの検証に失敗しました");
            }
            pwriteAll(fd, signature.data(), signature.size(), off.tail);
            off.eof = off.tail + signature.size();
            origImgSize = off.eof - off.header;
            logf("AVB1を作業フォルダ内の秘密鍵とX.509証明書で再署名したよ");
        }
        if (!avbFoot.empty()) {
            avbImgLen = off.eof - off.header;
            if (avbImgLen > UINT64_MAX - 4095) throw Error("AVB2イメージサイズが上限を超えています");
            avbVo = alignUp(avbImgLen, 4096);
            if (avbVo < avbImgLen || avbVo > UINT64_MAX - off.header) throw Error("AVB2のVBMeta位置が上限を超えています");
            uint64_t vbmetaStart = off.header + avbVo;
            if (avbMeta.size() > UINT64_MAX - vbmetaStart) throw Error("AVB2のサイズが上限を超えています");
            uint64_t vbmetaEnd = vbmetaStart + avbMeta.size();
            if (vbmetaEnd > UINT64_MAX - kAvbFooter) throw Error("AVB2フッターの位置が不正です");
            uint64_t endNeed = vbmetaEnd + kAvbFooter;
            uint64_t currentSize = (uint64_t)std::max<int64_t>(0, fileSize(outFile));
            avbFinal = std::max<uint64_t>(currentSize, endNeed);
            if (avbFinal > (uint64_t)std::numeric_limits<off_t>::max()) throw Error("AVB2出力サイズがOSのファイル上限を超えています");
            if (ftruncate(fd, (off_t)avbFinal) != 0) throw Error(fmtstr("AVB2領域を確保できません: %s", strerror(errno)));
            if (vbmetaStart > off.header + avbImgLen) {
                Bytes zeros(65536, 0);
                uint64_t pos = off.header + avbImgLen;
                while (pos < vbmetaStart) {
                    size_t count = (size_t)std::min<uint64_t>(zeros.size(), vbmetaStart - pos);
                    pwriteAll(fd, zeros.data(), count, pos);
                    pos += count;
                }
            }
            pwriteAll(fd, avbMeta.data(), avbMeta.size(), vbmetaStart);
            Bytes foot = avbFoot;
            wr64be(foot.data() + 12, avbImgLen);
            wr64be(foot.data() + 20, avbVo);
            wr64be(foot.data() + 28, avbMeta.size());
            pwriteAll(fd, foot.data(), kAvbFooter, avbFinal - kAvbFooter);
        }
        fsync(fd);
        close(fd);
        fd = -1;
    } catch (...) {
        if (fd >= 0) close(fd);
        unlink(outFile.c_str());
        throw;
    }
    progress(100);
    logf("リパックできたよ〜: %s (%s)", baseName(outFile).c_str(), humanSize((uint64_t)fileSize(outFile)).c_str());
}

}
