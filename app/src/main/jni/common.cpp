#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

namespace cu {

std::string fmtstr(const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    char stackbuf[1024];
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(stackbuf, sizeof(stackbuf), f, ap);
    va_end(ap);
    std::string r;
    if (n < 0) {
        r = "";
    } else if ((size_t)n < sizeof(stackbuf)) {
        r.assign(stackbuf, n);
    } else {
        r.resize(n + 1);
        vsnprintf(&r[0], n + 1, f, ap2);
        r.resize(n);
    }
    va_end(ap2);
    return r;
}

Ctx& ctx() {
    static Ctx c;
    return c;
}

void logf(const char* f, ...) {
    va_list ap;
    va_start(ap, f);
    char buf[2048];
    vsnprintf(buf, sizeof(buf), f, ap);
    va_end(ap);
    Ctx& c = ctx();
    if (c.log) c.log(buf);
}

void progress(int pct) {
    Ctx& c = ctx();
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    if (c.progress) c.progress(pct);
}

namespace {
thread_local int gScopeLo = -1;
thread_local int gScopeHi = -1;
}

void subProgress(int pct) {
    if (gScopeLo < 0) return;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    progress(gScopeLo + (gScopeHi - gScopeLo) * pct / 100);
}

ProgressScope::ProgressScope(int lo, int hi) : prevLo_(gScopeLo), prevHi_(gScopeHi) {
    gScopeLo = lo;
    gScopeHi = hi;
}

ProgressScope::~ProgressScope() {
    gScopeLo = prevLo_;
    gScopeHi = prevHi_;
}

void checkCancel() {
    if (ctx().cancel.load()) throw Canceled();
}

void MappedFile::open(const std::string& path) {
    close();
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw Error(fmtstr("ファイルを開けないよ: %s (%s)", path.c_str(), strerror(errno)));
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = errno;
        ::close(fd);
        throw Error(fmtstr("statできないよ: %s (%s)", path.c_str(), strerror(e)));
    }
    if (S_ISDIR(st.st_mode)) {
        ::close(fd);
        throw Error(fmtstr("フォルダは開けないよ: %s", path.c_str()));
    }
    size_t n = (size_t)st.st_size;
    if (n == 0) {
        ::close(fd);
        p_ = reinterpret_cast<const uint8_t*>("");
        n_ = 0;
        return;
    }
    void* m = mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m != MAP_FAILED) {
        map_ = m;
        maplen_ = n;
        p_ = static_cast<const uint8_t*>(m);
        n_ = n;
        ::close(fd);
        return;
    }
    try {
        buf_.resize(n);
    } catch (...) {
        ::close(fd);
        throw Error("メモリが足りないよ〜");
    }
    size_t off = 0;
    while (off < n) {
        ssize_t r = pread(fd, buf_.data() + off, n - off, off);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            ::close(fd);
            throw Error(fmtstr("読み込み失敗: %s (%s)", path.c_str(), strerror(e)));
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    ::close(fd);
    p_ = buf_.data();
    n_ = off;
}

void MappedFile::close() {
    if (map_) {
        munmap(map_, maplen_);
        map_ = nullptr;
        maplen_ = 0;
    }
    Bytes().swap(buf_);
    p_ = nullptr;
    n_ = 0;
}

void VecSink::write(const uint8_t* p, size_t n) {
    if (n > limit || v.size() > limit - n) throw Error("展開サイズが大きすぎるよ〜");
    v.insert(v.end(), p, p + n);
    total_ += n;
}

FileSink::~FileSink() {
    if (fd_ >= 0) {
        try { flush(); } catch (...) {}
        ::close(fd_);
        fd_ = -1;
    }
}

void FileSink::open(const std::string& path, int mode) {
    close();
    path_ = path;
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd_ < 0) throw Error(fmtstr("書き込み先を作れないよ: %s (%s)", path.c_str(), strerror(errno)));
    buf_.reserve(1 << 20);
    total_ = 0;
}

void FileSink::flush() {
    size_t off = 0;
    while (off < buf_.size()) {
        ssize_t r = ::write(fd_, buf_.data() + off, buf_.size() - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            buf_.clear();
            throw Error(fmtstr("書き込み失敗: %s (%s)", path_.c_str(), strerror(e)));
        }
        off += (size_t)r;
    }
    buf_.clear();
}

void FileSink::write(const uint8_t* p, size_t n) {
    if (fd_ < 0) throw Error("出力が開いてないよ");
    total_ += n;
    if (n >= (1 << 20)) {
        flush();
        size_t off = 0;
        while (off < n) {
            ssize_t r = ::write(fd_, p + off, n - off);
            if (r < 0) {
                if (errno == EINTR) continue;
                throw Error(fmtstr("書き込み失敗: %s (%s)", path_.c_str(), strerror(errno)));
            }
            off += (size_t)r;
        }
        return;
    }
    buf_.insert(buf_.end(), p, p + n);
    if (buf_.size() >= (1 << 20)) flush();
}

void FileSink::zeros(size_t n) {
    static const uint8_t z[4096] = {0};
    while (n) {
        size_t c = n > sizeof(z) ? sizeof(z) : n;
        write(z, c);
        n -= c;
    }
}

void FileSink::align(uint64_t a) {
    if (a == 0) return;
    uint64_t r = total_ % a;
    if (r) zeros((size_t)(a - r));
}

void FileSink::close() {
    if (fd_ >= 0) {
        int fd = fd_;
        try { flush(); } catch (...) { ::close(fd); fd_ = -1; throw; }
        ::fsync(fd);
        ::close(fd);
        fd_ = -1;
    }
}

bool fileExists(const std::string& p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0;
}

bool isDir(const std::string& p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

int64_t fileSize(const std::string& p) {
    struct stat st;
    if (stat(p.c_str(), &st) != 0) return -1;
    return (int64_t)st.st_size;
}

void mkdirs(const std::string& p, int mode) {
    if (p.empty() || isDir(p)) return;
    size_t pos = 0;
    while (true) {
        pos = p.find('/', pos + 1);
        std::string cur = pos == std::string::npos ? p : p.substr(0, pos);
        if (!cur.empty() && !isDir(cur)) {
            if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) {
                throw Error(fmtstr("フォルダを作れないよ: %s (%s)", cur.c_str(), strerror(errno)));
            }
        }
        if (pos == std::string::npos) break;
    }
}

void writeFile(const std::string& p, const uint8_t* d, size_t n, int mode) {
    FileSink s(p, mode);
    s.write(d, n);
    s.close();
}

void writeFile(const std::string& p, const std::string& s) {
    writeFile(p, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

Bytes readFile(const std::string& p, size_t maxSize) {
    MappedFile m(p);
    if (m.size() > maxSize) throw Error(fmtstr("ファイルが大きすぎるよ: %s", p.c_str()));
    return Bytes(m.data(), m.data() + m.size());
}

std::string readText(const std::string& p) {
    MappedFile m(p);
    return std::string(reinterpret_cast<const char*>(m.data()), m.size());
}

void listDir(const std::string& p, std::vector<std::string>& names) {
    DIR* d = opendir(p.c_str());
    if (!d) throw Error(fmtstr("フォルダを読めないよ: %s (%s)", p.c_str(), strerror(errno)));
    while (struct dirent* e = readdir(d)) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        names.push_back(e->d_name);
    }
    closedir(d);
    std::sort(names.begin(), names.end());
}

void removeAll(const std::string& p) {
    struct stat st;
    if (lstat(p.c_str(), &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        std::vector<std::string> names;
        try { listDir(p, names); } catch (...) {}
        for (auto& n : names) removeAll(p + "/" + n);
        rmdir(p.c_str());
    } else {
        unlink(p.c_str());
    }
}

std::string joinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

std::string baseName(const std::string& p) {
    size_t e = p.size();
    while (e > 1 && p[e - 1] == '/') e--;
    size_t s = p.rfind('/', e - 1);
    if (s == std::string::npos) return p.substr(0, e);
    return p.substr(s + 1, e - s - 1);
}

std::string dirName(const std::string& p) {
    size_t e = p.size();
    while (e > 1 && p[e - 1] == '/') e--;
    size_t s = p.rfind('/', e - 1);
    if (s == std::string::npos) return ".";
    if (s == 0) return "/";
    return p.substr(0, s);
}

std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string r;
    r.resize(n * 2);
    for (size_t i = 0; i < n; i++) {
        r[i * 2] = d[p[i] >> 4];
        r[i * 2 + 1] = d[p[i] & 15];
    }
    return r;
}

bool unhex(const std::string& s, Bytes& out) {
    out.clear();
    if (s.size() % 2) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int a = v(s[i]), b = v(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back((uint8_t)(a * 16 + b));
    }
    return true;
}

std::string cstrOf(const char* p, size_t maxlen) {
    size_t n = 0;
    while (n < maxlen && p[n]) n++;
    return std::string(p, n);
}

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> r;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = s.find('\n', i);
        if (j == std::string::npos) j = s.size();
        std::string line = s.substr(i, j - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (j == s.size() && line.empty()) break;
        r.push_back(line);
        i = j + 1;
    }
    return r;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

std::string escapeField(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '\\') r += "\\\\";
        else if (c == '\t') r += "\\t";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else r += c;
    }
    return r;
}

std::string unescapeField(const std::string& s) {
    std::string r;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i];
            if (c == 't') r += '\t';
            else if (c == 'n') r += '\n';
            else if (c == 'r') r += '\r';
            else r += c;
        } else {
            r += s[i];
        }
    }
    return r;
}

std::string humanSize(uint64_t n) {
    const char* u[] = {"B", "KiB", "MiB", "GiB"};
    double v = (double)n;
    int i = 0;
    while (v >= 1024.0 && i < 3) { v /= 1024.0; i++; }
    if (i == 0) return fmtstr("%llu B", (unsigned long long)n);
    return fmtstr("%.2f %s", v, u[i]);
}

}
