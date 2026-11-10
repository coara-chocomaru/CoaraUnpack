#include "unpacker.h"
#include "streaminfo.h"
#include "cpio.h"
#include "hash.h"
#include "info.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <set>
#include <time.h>

namespace cu {

static const char* kRootfs = "rootfs";

std::vector<std::string> splitTab(const std::string& s) {
    std::vector<std::string> r;
    size_t i = 0;
    while (true) {
        size_t j = s.find('\t', i);
        if (j == std::string::npos) {
            r.push_back(s.substr(i));
            break;
        }
        r.push_back(s.substr(i, j - i));
        i = j + 1;
    }
    return r;
}

Fmt checkFmtLg(const uint8_t* p, size_t n) {
    Fmt f = checkFmt(p, n);
    if (f == F_LZ4_LEGACY) {
        size_t off = 4;
        while (off + 4 <= n) {
            uint32_t bs = rd32(p + off);
            off += 4;
            if (off + bs > n) return F_LZ4_LG;
            off += bs;
        }
    }
    return f;
}

static char typeChar(uint32_t mode) {
    switch (mode & S_IFMT) {
    case S_IFREG: return 'f';
    case S_IFDIR: return 'd';
    case S_IFLNK: return 'l';
    case S_IFCHR: return 'c';
    case S_IFBLK: return 'b';
    case S_IFIFO: return 'p';
    case S_IFSOCK: return 's';
    default: return '?';
    }
}

static std::string sanitize(const std::string& p) {
    std::string r = p;
    for (auto& c : r) {
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' || (unsigned char)c < 32)
            c = '_';
    }
    return r;
}

static std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return r;
}

void ramdiskUnpack(const std::string& inFile, const std::string& outDir) {
    logf("ramdiskを読み込み中だよ〜: %s", baseName(inFile).c_str());
    if (fileSize(inFile) == 0) {
        logf("ramdiskが無いよ〜(ファイルが空っぽだよ)");
        throw Error("ramdiskが無いよ〜(ファイルが空っぽだよ)");
    }
    MappedFile src(inFile);
    if (src.size() < 6) throw Error("ファイルが小さすぎるよ〜");
    View v = src.view();
    Bytes mtk, prefix;
    if (checkFmt(v.p, v.n) == F_MTK && v.n > 512) {
        mtk.assign(v.p, v.p + 512);
        v = v.from(512);
        logf("MTKヘッダ(512B)を見つけたよ");
    }
    Probe pr = probeStream(v, baseName(inFile), true);
    if (pr.offset > 0) {
        prefix.assign(v.p, v.p + pr.offset);
        v = v.from(pr.offset);
        logf("先頭に %zu バイトの余白/ヘッダがあったよ。形式の本体はその後ろだね", pr.offset);
    }
    Fmt f = pr.fmt;
    if (!fmtCompressed(f) && f != F_LZOP && !looksLikeCpio(v.p, v.n)) {
        std::string t;
        for (auto& x : pr.tried) t += (t.empty() ? "" : ", ") + x;
        throw Error("ramdiskの形式を特定できなかったよ。試した判定: " + t);
    }
    logf("形式の判定: %s (方法: %s)", layersName(f).c_str(), pr.how.c_str());
    mkdirs(outDir);
    std::string rootfs = joinPath(outDir, kRootfs);
    mkdirs(rootfs);
    Digests sd = digestAll(src.data(), src.size());
    std::string tmp = joinPath(outDir, ".cpio.tmp");
    MappedFile cm;
    View cv = v;
    bool compressed = fmtCompressed(f);
    if (f == F_LZOP) throw Error("lzop形式は未対応だよ〜ごめんね");
    if (compressed) {
        logf("形式: %s だね。展開するよ〜", fmtName(f));
        {
            FileSink fs(tmp);
            ProgressScope ps(2, 20);
            decompress(f, v, fs);
            fs.close();
        }
        cm.open(tmp);
        cv = cm.view();
    } else {
        logf("圧縮なしのcpioみたい");
    }
    progress(20);
    CpioArchive ar;
    cpioParse(cv, ar);
    logf("cpioを読んだよ: %zu エントリ", ar.entries.size());
    Digests cd = digestAll(cv.p, cv.n);

    std::map<std::string, size_t> last;
    std::vector<std::string> norm(ar.entries.size());
    for (size_t i = 0; i < ar.entries.size(); i++) {
        bool unsafe;
        norm[i] = normalizeCpioPath(ar.entries[i].path, unsafe);
        if (unsafe || norm[i].empty()) {
            ar.entries[i].skipped = true;
            if (unsafe) logf("危ないパスはスキップしたよ: %s", ar.entries[i].path.c_str());
            continue;
        }
        last[norm[i]] = i;
    }
    size_t nf = 0, nd = 0, nl = 0, nx = 0, dupes = 0, ndev = 0, nfifo = 0, nsock = 0, nh = 0;
    uint64_t totalBytes = 0, doneBytes = 0;
    for (size_t i = 0; i < ar.entries.size(); i++) {
        if (ar.entries[i].skipped) continue;
        if (last[norm[i]] != i) { ar.entries[i].skipped = true; dupes++; continue; }
    }
    std::map<int, size_t> primaryOf;
    for (size_t i = 0; i < ar.entries.size(); i++) {
        const CpioEntry& e = ar.entries[i];
        if (!e.skipped && e.linkGroup >= 0 && e.linkPrimary) primaryOf[e.linkGroup] = i;
    }
    std::vector<char> asLink(ar.entries.size(), 0);
    std::set<int> groupsUsed;
    for (size_t i = 0; i < ar.entries.size(); i++) {
        const CpioEntry& e = ar.entries[i];
        if (e.skipped) continue;
        if (e.linkGroup >= 0 && !e.linkPrimary && primaryOf.count(e.linkGroup)) {
            asLink[i] = 1;
            groupsUsed.insert(e.linkGroup);
            nh++;
        } else {
            totalBytes += e.data.n;
        }
    }
    std::set<std::string> seen;
    InfoWriter w;
    std::string tbl, sym;
    size_t symCount = 0;
    for (size_t i = 0; i < ar.entries.size(); i++) {
        CpioEntry& e = ar.entries[i];
        if (e.skipped) continue;
        checkCancel();
        char t = typeChar(e.mode);
        std::string md5 = "-";
        std::string disk;
        std::string rel = norm[i];
        if (asLink[i]) {
            sym += fmtstr("S\t%zu\th\t%o\t%u\t%u\t%u\t0:0\t", i, e.mode, e.uid, e.gid, e.mtime) + escapeField(rel) + "\t" +
                   escapeField(norm[primaryOf[e.linkGroup]]) + "\n";
            symCount++;
            continue;
        }
        if (t == 'f' || t == 'd') {
            std::string dp = rel;
            std::string lo = lower(dp);
            if (t == 'f' && seen.count(lo)) {
                dp = sanitize(rel) + fmtstr("~%zu", i);
                lo = lower(dp);
            }
            auto attempt = [&](const std::string& path) {
                std::string full = joinPath(rootfs, path);
                if (t == 'd') {
                    mkdirs(full);
                } else {
                    mkdirs(dirName(full));
                    FileSink fs(full, 0644);
                    fs.write(e.data.p, e.data.n);
                    fs.close();
                }
            };
            try {
                attempt(dp);
            } catch (const Error&) {
                std::string sp = sanitize(dp);
                if (sp == dp) throw;
                dp = sp;
                lo = lower(dp);
                attempt(dp);
            }
            seen.insert(lo);
            if (dp != rel) disk = dp;
            if (t == 'f') {
                chmod(joinPath(rootfs, dp).c_str(), e.mode & 0777);
                md5 = md5Hex(e.data.p, e.data.n);
                nf++;
            } else {
                nd++;
            }
        } else {
            if (t == 'l') nl++;
            else if (t == 'c' || t == 'b') ndev++;
            else if (t == 'p') nfifo++;
            else if (t == 's') nsock++;
            else nx++;
            sym += fmtstr("S\t%zu\t%c\t%o\t%u\t%u\t%u\t%u:%u\t", i, t, e.mode, e.uid, e.gid, e.mtime, e.rdevmaj, e.rdevmin) +
                   escapeField(rel) + "\t" + escapeField(t == 'l' ? e.target : "") + "\n";
            symCount++;
            doneBytes += e.data.n;
            continue;
        }
        doneBytes += e.data.n;
        if (totalBytes) progress(20 + (int)(doneBytes * 75 / totalBytes));
        std::string line = fmtstr("E\t%c\t%o\t%u\t%u\t%u\t%llu\t%u\t%u\t%u:%u\t%s\t", t, e.mode, e.uid, e.gid, e.mtime,
                                  (unsigned long long)(t == 'f' ? e.data.n : 0), e.nlink, e.ino, e.rdevmaj, e.rdevmin,
                                  md5.c_str());
        line += escapeField(rel) + "\t\t" + escapeField(disk) + "\t" + fmtstr("%zu", i) + "\n";
        tbl += line;
    }
    std::string symMd5;
    if (symCount) {
        std::string body = "# coara-unpack symbol table v1\n"
                           "# S seq type mode(octal) uid gid mtime rdev(maj:min) path target\n"
                           "# type: l=symlink(target=リンク先) c=chardev b=blockdev p=fifo s=socket h=hardlink(target=本体のパス)\n"
                           "# 行を消すとリパック時にそのエントリが消えるよ / hは本体(rootfs内のファイル)と同じ中身を共有するよ\n" + sym +
                           fmtstr("Z\t%zu\n", symCount);
        writeFile(joinPath(outDir, "symbol.txt"), (const uint8_t*)body.data(), body.size());
        symMd5 = md5Hex((const uint8_t*)body.data(), body.size());
    }
    w.comment("coara unpack / ramdisk info  ─ リパックで読むよ〜(編集してもOK)");
    w.comment("rootfs/ の中身を編集して、このフォルダを「ramdiskリパック」で選んでね");
    w.comment("シンボリックリンク・デバイスノード・ハードリンクはSDカード上に作れないので、symbol.txt に記録してあるよ");
    w.comment("ファイルとフォルダは下の[entries]、それ以外は symbol.txt だよ(両方そろえてリパックしてね)");
    w.comment("行を消すとそのエントリはリパック時に消えるよ / rootfs/ に足したファイルは自動で入るよ");
    w.blank();
    w.kv("tool", "coara-unpack");
    w.kv("info_version", "2");
    w.kv("kind", "ramdisk");
    w.kv("source_name", baseName(inFile));
    w.kvu("source_size", src.size());
    w.kv("source_md5", sd.md5);
    w.kv("source_sha1", sd.sha1);
    w.kv("source_sha256", sd.sha256);
    w.kv("source_crc32", fmtstr("%08x", sd.crc));
    w.kv("source_format", compressed ? fmtName(f) : "raw");
    w.kv("source_format_detect", pr.how);
    {
        std::string t;
        for (auto& x : pr.tried) t += (t.empty() ? "" : ",") + x;
        w.kv("source_format_tried", t);
    }
    w.kvu("source_stream_offset", pr.offset);
    w.kvb("source_has_prefix", !prefix.empty());
    if (!prefix.empty()) w.kv("source_prefix_hex", hex(prefix.data(), prefix.size()));
    w.kvu("source_stream_size", v.n);
    w.kvu("source_decoded_size", cv.n);
    if (compressed && cv.n) w.kv("source_ratio", fmtstr("%.2f%%", 100.0 * (double)v.n / (double)cv.n));
    for (auto& kv : pr.detail) w.kv("source_codec." + kv.first, kv.second);
    w.kvb("mtk_header", !mtk.empty());
    if (!mtk.empty()) w.kv("mtk_header_hex", hex(mtk.data(), mtk.size()));
    w.kv("cpio_format", ar.format);
    w.kvu("cpio_archives", (uint64_t)ar.archives);
    w.kvu("cpio_size", cv.n);
    w.kv("cpio_md5", cd.md5);
    w.kv("cpio_sha1", cd.sha1);
    w.kv("cpio_sha256", cd.sha256);
    w.kvu("entries_total", nf + nd + nl + nx + ndev + nfifo + nsock + nh);
    w.kvu("entries_files", nf);
    w.kvu("entries_dirs", nd);
    w.kvu("entries_symlinks", nl);
    w.kvu("entries_devices", ndev);
    w.kvu("entries_fifos", nfifo);
    w.kvu("entries_sockets", nsock);
    w.kvu("entries_hardlinks", nh);
    w.kvu("entries_hardlink_groups", groupsUsed.size());
    w.kvu("entries_other", nx);
    w.kv("symbol_file", symCount ? "symbol.txt" : "");
    w.kvu("symbol_count", symCount);
    w.kv("symbol_md5", symMd5);
    w.kvu("entries_duplicates_dropped", dupes);
    w.kvu("files_total_bytes", totalBytes);
    w.kv("rootfs_dir", kRootfs);
    w.blank();
    w.comment("columns: E type mode(octal) uid gid mtime size nlink ino rdev(maj:min) md5 path (unused) disk_path seq");
    w.comment("type: f=file d=dir / seq=元のcpio内の順番(リパックで順番を戻すよ)");
    w.raw("\n[entries]\n");
    w.raw(tbl);
    writeFile(joinPath(outDir, "info.txt"), w.str());
    cm.close();
    unlink(tmp.c_str());
    progress(100);
    logf("ramdiskを展開したよ: ファイル%zu / フォルダ%zu / リンク%zu / デバイス等%zu / ハードリンク%zu / その他%zu", nf, nd, nl,
         ndev + nfifo + nsock, nh, nx);
    if (symCount) logf("リンク・ノードの記録を symbol.txt に書いたよ (%zu件)", symCount);
    if (dupes) logf("同じパスの重複を%zu件まとめたよ(後勝ち)", dupes);
}

namespace {

struct PlanEntry {
    std::string path;
    char type = 'f';
    uint32_t mode = 0, uid = 0, gid = 0, mtime = 0, rmaj = 0, rmin = 0;
    std::string target;
    std::string disk;
    std::string md5;
    bool fromInfo = false;
    uint64_t seq = 0;
};

void scanTree(const std::string& root, const std::string& rel, std::vector<std::pair<std::string, int>>& out) {
    std::vector<std::string> names;
    listDir(rel.empty() ? root : joinPath(root, rel), names);
    for (auto& n : names) {
        std::string r = rel.empty() ? n : rel + "/" + n;
        struct stat st;
        std::string full = joinPath(root, r);
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            out.push_back({r, 'd'});
            scanTree(root, r, out);
        } else if (S_ISLNK(st.st_mode)) {
            out.push_back({r, 'l'});
        } else if (S_ISREG(st.st_mode)) {
            out.push_back({r, 'f'});
        }
        checkCancel();
    }
}

}

void ramdiskRepack(const std::string& dir, const std::string& outFile, const RdRepackOpts& o) {
    std::string infoPath = joinPath(dir, "info.txt");
    if (!fileExists(infoPath)) throw Error("info.txt が見つからないよ〜。unpackしたフォルダを選んでね");
    InfoReader info;
    info.parse(readText(infoPath));
    if (info.get("kind") != "ramdisk") throw Error("このinfo.txtはramdisk用じゃないみたい(kind=ramdiskのやつを選んでね)");
    std::string rootfs = joinPath(dir, info.get("rootfs_dir", kRootfs));
    if (!isDir(rootfs)) throw Error("rootfs フォルダが見つからないよ〜");
    logf("info.txt を読んだよ〜");

    std::vector<PlanEntry> plan;
    std::set<std::string> logical, diskSeen;
    std::map<std::string, size_t> idxByDisk;
    size_t removed = 0, changed = 0, added = 0;
    uint64_t lineNo = 0, lastSeq = 0;
    bool haveSymbolEntries = false;
    for (auto& line : info.lines("entries")) {
        if (line.size() < 3 || line[0] != 'E') continue;
        std::vector<std::string> c = splitTab(line);
        if (c.size() < 12) continue;
        PlanEntry p;
        p.type = c[1].empty() ? 'f' : c[1][0];
        p.mode = (uint32_t)strtoul(c[2].c_str(), nullptr, 8);
        p.uid = (uint32_t)strtoul(c[3].c_str(), nullptr, 10);
        p.gid = (uint32_t)strtoul(c[4].c_str(), nullptr, 10);
        p.mtime = (uint32_t)strtoul(c[5].c_str(), nullptr, 10);
        size_t colon = c[9].find(':');
        if (colon != std::string::npos) {
            p.rmaj = (uint32_t)strtoul(c[9].c_str(), nullptr, 10);
            p.rmin = (uint32_t)strtoul(c[9].c_str() + colon + 1, nullptr, 10);
        }
        p.md5 = c[10];
        p.path = unescapeField(c[11]);
        if (c.size() > 12) p.target = unescapeField(c[12]);
        if (c.size() > 13) p.disk = unescapeField(c[13]);
        if (c.size() > 14 && !c[14].empty()) {
            p.seq = strtoull(c[14].c_str(), nullptr, 10);
            lastSeq = p.seq;
        } else {
            p.seq = lastSeq;
        }
        lineNo++;
        p.fromInfo = true;
        if (p.type != 'f' && p.type != 'd') haveSymbolEntries = true;
        bool unsafe;
        p.path = normalizeCpioPath(p.path, unsafe);
        if (unsafe || p.path.empty()) continue;
        std::string dp = p.disk.empty() ? p.path : p.disk;
        if (p.type == 'f' || p.type == 'd') {
            struct stat st;
            std::string full = joinPath(rootfs, dp);
            if (lstat(full.c_str(), &st) != 0 || (p.type == 'f' ? !S_ISREG(st.st_mode) : !S_ISDIR(st.st_mode))) {
                removed++;
                if (removed <= 30) logf("消えてるから外すね: %s", p.path.c_str());
                continue;
            }
            if (p.type == 'f') {
                if (p.mode == 0) p.mode = S_IFREG | 0644;
            }
        }
        if (logical.count(p.path)) continue;
        logical.insert(p.path);
        diskSeen.insert(dp);
        plan.push_back(p);
    }

    std::string symFile = info.get("symbol_file");
    uint64_t symExpected = info.getu("symbol_count", 0);
    std::string symPath = joinPath(dir, symFile.empty() ? "symbol.txt" : symFile);
    size_t symLoaded = 0, symDropped = 0;
    if (fileExists(symPath)) {
        std::string text = readText(symPath);
        std::string want = info.get("symbol_md5");
        bool symEdited = !want.empty() && md5Hex((const uint8_t*)text.data(), text.size()) != want;
        if (symEdited) logf("symbol.txt が編集されてるよ(そのまま使うね)");
        size_t pos = 0;
        uint64_t footer = UINT64_MAX;
        std::map<std::string, size_t> where;
        for (size_t i = 0; i < plan.size(); i++) where[plan[i].path] = i;
        while (pos < text.size()) {
            size_t nl2 = text.find('\n', pos);
            std::string line = text.substr(pos, nl2 == std::string::npos ? std::string::npos : nl2 - pos);
            pos = nl2 == std::string::npos ? text.size() : nl2 + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            std::vector<std::string> c = splitTab(line);
            if (c[0] == "Z" && c.size() >= 2) {
                footer = strtoull(c[1].c_str(), nullptr, 10);
                continue;
            }
            if (c[0] != "S" || c.size() < 9) continue;
            PlanEntry p;
            p.seq = strtoull(c[1].c_str(), nullptr, 10);
            p.type = c[2].empty() ? '?' : c[2][0];
            p.mode = (uint32_t)strtoul(c[3].c_str(), nullptr, 8);
            p.uid = (uint32_t)strtoul(c[4].c_str(), nullptr, 10);
            p.gid = (uint32_t)strtoul(c[5].c_str(), nullptr, 10);
            p.mtime = (uint32_t)strtoul(c[6].c_str(), nullptr, 10);
            size_t colon = c[7].find(':');
            if (colon != std::string::npos) {
                p.rmaj = (uint32_t)strtoul(c[7].c_str(), nullptr, 10);
                p.rmin = (uint32_t)strtoul(c[7].c_str() + colon + 1, nullptr, 10);
            }
            p.path = unescapeField(c[8]);
            if (c.size() > 9) p.target = unescapeField(c[9]);
            p.fromInfo = true;
            bool unsafe;
            p.path = normalizeCpioPath(p.path, unsafe);
            if (unsafe || p.path.empty()) {
                symDropped++;
                continue;
            }
            if (p.type == 'l' && p.target.empty()) {
                symDropped++;
                logf("リンク先が空だから外すね: %s", p.path.c_str());
                continue;
            }
            if (p.type == 'h') {
                p.target = normalizeCpioPath(p.target, unsafe);
                if (unsafe || p.target.empty()) {
                    symDropped++;
                    continue;
                }
                p.mode = S_IFREG | (p.mode & 07777);
            }
            struct stat st;
            if (lstat(joinPath(rootfs, p.path).c_str(), &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
                symDropped++;
                logf("rootfsに同名のファイル/フォルダがあるからリンク記録は外すね: %s", p.path.c_str());
                continue;
            }
            auto it = where.find(p.path);
            if (it != where.end()) {
                plan[it->second] = p;
            } else {
                where[p.path] = plan.size();
                logical.insert(p.path);
                plan.push_back(p);
            }
            symLoaded++;
        }
        if (!symEdited && footer != UINT64_MAX && footer != symLoaded + symDropped) logf("symbol.txt の件数が合わないよ(記録%llu / 読めた%zu)。途中で切れてるかも", (unsigned long long)footer, symLoaded + symDropped);
    } else if (symExpected > 0 && !haveSymbolEntries) {
        throw Error(fmtstr("symbol.txt が見つからないよ〜。リンクやデバイスノードが%llu件あるから、unpackしたフォルダのsymbol.txtを戻してね", (unsigned long long)symExpected));
    } else if (symExpected > 0) {
        logf("symbol.txt が無いから info.txt の記録だけで組み立てるよ");
    }
    {
        std::set<std::string> filePaths;
        for (auto& p : plan) if (p.type == 'f') filePaths.insert(p.path);
        std::vector<PlanEntry> kept;
        for (auto& p : plan) {
            if (p.type == 'h' && !filePaths.count(p.target)) {
                symDropped++;
                logf("ハードリンクの本体が無いから外すね: %s -> %s", p.path.c_str(), p.target.c_str());
                logical.erase(p.path);
                continue;
            }
            kept.push_back(p);
        }
        plan.swap(kept);
    }
    std::stable_sort(plan.begin(), plan.end(), [](const PlanEntry& a, const PlanEntry& b) { return a.seq < b.seq; });
    std::vector<std::pair<std::string, int>> found;
    scanTree(rootfs, "", found);
    std::vector<PlanEntry> fresh;
    for (auto& fp : found) {
        if (diskSeen.count(fp.first) || logical.count(fp.first)) continue;
        PlanEntry p;
        p.path = fp.first;
        p.type = (char)fp.second;
        struct stat st;
        std::string full = joinPath(rootfs, fp.first);
        lstat(full.c_str(), &st);
        p.mtime = (uint32_t)st.st_mtime;
        if (p.type == 'd') p.mode = S_IFDIR | 0755;
        else if (p.type == 'l') {
            char buf[4096];
            ssize_t n = readlink(full.c_str(), buf, sizeof(buf) - 1);
            if (n < 0) continue;
            p.target.assign(buf, (size_t)n);
            p.mode = S_IFLNK | 0777;
        } else {
            uint8_t head[4] = {0, 0, 0, 0};
            int fd = open(full.c_str(), O_RDONLY);
            if (fd >= 0) { ssize_t rr = read(fd, head, 4); (void)rr; close(fd); }
            bool exec = (head[0] == '#' && head[1] == '!') || (head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F');
            p.mode = S_IFREG | (exec ? 0755 : 0644);
        }
        added++;
        logf("新しく入れるね: %s", p.path.c_str());
        fresh.push_back(p);
    }
    std::sort(fresh.begin(), fresh.end(), [](const PlanEntry& a, const PlanEntry& b) { return a.path < b.path; });

    std::set<std::string> have;
    for (auto& p : plan) have.insert(p.path);
    std::vector<PlanEntry> ordered;
    auto ensureParents = [&](const std::string& path, std::vector<PlanEntry>& dst) {
        size_t pos = 0;
        while ((pos = path.find('/', pos)) != std::string::npos) {
            std::string par = path.substr(0, pos);
            if (!have.count(par)) {
                PlanEntry d;
                d.path = par;
                d.type = 'd';
                d.mode = S_IFDIR | 0755;
                have.insert(par);
                dst.push_back(d);
            }
            pos++;
        }
    };
    for (auto& p : plan) {
        ensureParents(p.path, ordered);
        have.insert(p.path);
        ordered.push_back(p);
    }
    for (auto& p : fresh) {
        ensureParents(p.path, ordered);
        have.insert(p.path);
        ordered.push_back(p);
    }
    progress(10);

    std::string fmtReq = o.fmt;
    Fmt target;
    if (fmtReq == "auto") {
        std::string sf = info.get("source_format", "raw");
        target = sf == "raw" ? F_UNKNOWN : fmtFromName(sf);
    } else if (fmtReq == "raw" || fmtReq == "cpio" || fmtReq == "none") {
        target = F_UNKNOWN;
    } else {
        target = fmtFromName(fmtReq);
        if (target == F_UNKNOWN) throw Error("圧縮形式の指定が変だよ: " + fmtReq);
    }
    bool crc = info.get("cpio_format") == "070702";
    std::string tmpCpio = outFile + ".cpio.tmp";
    {
        FileSink fs(tmpCpio);
        CpioWriter cw(fs, crc);
        size_t done = 0;
        std::map<std::string, std::vector<size_t>> linksOf;
        for (size_t k = 0; k < ordered.size(); k++) if (ordered[k].type == 'h') linksOf[ordered[k].target].push_back(k);
        for (auto& p : ordered) {
            checkCancel();
            if (p.type == 'h') {
                done++;
                continue;
            }
            uint32_t groupIno = 0, groupLinks = 0;
            auto lk = p.type == 'f' ? linksOf.find(p.path) : linksOf.end();
            if (lk != linksOf.end()) {
                groupIno = cw.allocIno();
                groupLinks = (uint32_t)lk->second.size() + 1;
                for (size_t k : lk->second) {
                    const PlanEntry& l = ordered[k];
                    CpioOutEntry le;
                    le.path = l.path;
                    le.uid = l.uid;
                    le.gid = l.gid;
                    le.mtime = l.mtime;
                    le.mode = l.mode;
                    if (o.force0777) le.mode = (le.mode & S_IFMT) | 0777;
                    le.ino = groupIno;
                    le.nlink = groupLinks;
                    le.noData = true;
                    cw.add(le);
                }
            }
            CpioOutEntry e;
            e.ino = groupIno;
            e.nlink = groupLinks;
            e.path = p.path;
            e.uid = p.uid;
            e.gid = p.gid;
            e.mtime = p.mtime;
            e.rdevmaj = p.rmaj;
            e.rdevmin = p.rmin;
            e.mode = p.mode;
            e.target = p.target;
            if (o.force0777) e.mode = (e.mode & S_IFMT) | 0777;
            MappedFile mf;
            if (p.type == 'f') {
                std::string full = joinPath(rootfs, p.disk.empty() ? p.path : p.disk);
                mf.open(full);
                e.data = mf.view();
                if (p.fromInfo && !p.md5.empty() && p.md5 != "-") {
                    if (md5Hex(e.data.p, e.data.n) != p.md5) {
                        changed++;
                        if (changed <= 30) logf("変更されてたよ: %s", p.path.c_str());
                    }
                }
                struct stat st;
                if (!p.fromInfo && stat(full.c_str(), &st) == 0) e.mtime = (uint32_t)st.st_mtime;
            }
            cw.add(e);
            done++;
            progress(10 + (int)(done * 50 / ordered.size()));
        }
        cw.finish();
        fs.close();
    }
    {
        size_t nl = 0, nh = 0, nn = 0;
        for (auto& p : ordered) {
            if (p.type == 'l') nl++;
            else if (p.type == 'h') nh++;
            else if (p.type != 'f' && p.type != 'd') nn++;
        }
        logf("cpioを組み立てたよ〜 (変更%zu / 追加%zu / 削除%zu / リンク%zu / ノード%zu / ハードリンク%zu / 権限%s)", changed, added, removed, nl, nn, nh,
             o.force0777 ? "全部0777" : "そのまま");
    }
    bool hasMtk = info.getb("mtk_header");
    Bytes mtkHdr, prefixBytes;
    if (hasMtk) unhex(info.get("mtk_header_hex"), mtkHdr);
    if (info.getb("source_has_prefix")) unhex(info.get("source_prefix_hex"), prefixBytes);
    bool wrap = hasMtk || !prefixBytes.empty();
    std::string payloadPath = wrap ? outFile + ".payload.tmp" : outFile;
    try {
        MappedFile cm(tmpCpio);
        FileSink out(payloadPath);
        if (target == F_UNKNOWN) {
            out.write(cm.data(), cm.size());
            logf("圧縮なしで書き出すよ");
        } else {
            logf("%s で圧縮するね〜", fmtName(target));
            ProgressScope ps(60, 98);
            compress(target, cm.view(), out);
            logf("圧縮後サイズ: %s (展開時の圧縮ストリームは %s)", humanSize(out.total()).c_str(),
                 humanSize((uint64_t)info.getu("source_stream_size", 0)).c_str());
        }
        out.close();
        if (wrap) {
            MappedFile pm(payloadPath);
            FileSink fo(outFile);
            if (mtkHdr.size() == 512) {
                wr32(mtkHdr.data() + 4, (uint32_t)(prefixBytes.size() + pm.size()));
                fo.write(mtkHdr.data(), 512);
            }
            if (!prefixBytes.empty()) fo.write(prefixBytes.data(), prefixBytes.size());
            fo.write(pm.data(), pm.size());
            fo.close();
        }
    } catch (...) {
        unlink(tmpCpio.c_str());
        if (wrap) unlink(payloadPath.c_str());
        throw;
    }
    unlink(tmpCpio.c_str());
    if (wrap) unlink(payloadPath.c_str());
    progress(100);
    logf("リパックできたよ〜: %s (%s)", baseName(outFile).c_str(), humanSize((uint64_t)fileSize(outFile)).c_str());
}

}
