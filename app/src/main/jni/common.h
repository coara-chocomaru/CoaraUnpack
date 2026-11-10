#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <stdexcept>
#include <algorithm>

namespace cu {

struct Error : public std::runtime_error {
    explicit Error(const std::string& m) : std::runtime_error(m) {}
};

struct Canceled : public std::runtime_error {
    Canceled() : std::runtime_error("canceled") {}
};

std::string fmtstr(const char* f, ...) __attribute__((format(printf, 1, 2)));

struct Ctx {
    std::function<void(const std::string&)> log;
    std::function<void(int)> progress;
    std::atomic<bool> cancel{false};
};

Ctx& ctx();
void logf(const char* f, ...) __attribute__((format(printf, 1, 2)));
void progress(int pct);
void subProgress(int pct);

class ProgressScope {
public:
    ProgressScope(int lo, int hi);
    ~ProgressScope();
    ProgressScope(const ProgressScope&) = delete;
    ProgressScope& operator=(const ProgressScope&) = delete;
private:
    int prevLo_;
    int prevHi_;
};
void checkCancel();

typedef std::vector<uint8_t> Bytes;
Bytes signAvb1PayloadFile(const std::string& path, const std::string& keyDirectory, uint64_t offset, uint64_t length, const std::string& target);

struct View {
    const uint8_t* p = nullptr;
    size_t n = 0;
    View() {}
    View(const uint8_t* a, size_t b) : p(a), n(b) {}
    const uint8_t* data() const { return p; }
    size_t size() const { return n; }
    bool empty() const { return n == 0; }
    View sub(size_t off, size_t len) const {
        if (off > n) off = n;
        if (len > n - off) len = n - off;
        return View(p + off, len);
    }
    View from(size_t off) const { return sub(off, n); }
};

inline uint32_t rd32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd64(const uint8_t* p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
inline uint32_t rd32be(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
inline uint64_t rd64be(const uint8_t* p) { return ((uint64_t)rd32be(p) << 32) | rd32be(p + 4); }
inline void wr32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
inline void wr64(uint8_t* p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }
inline void wr32be(uint8_t* p, uint32_t v) { p[3] = v; p[2] = v >> 8; p[1] = v >> 16; p[0] = v >> 24; }
inline void wr64be(uint8_t* p, uint64_t v) { wr32be(p, (uint32_t)(v >> 32)); wr32be(p + 4, (uint32_t)v); }

class MappedFile {
public:
    MappedFile() {}
    explicit MappedFile(const std::string& path) { open(path); }
    ~MappedFile() { close(); }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    void open(const std::string& path);
    void close();
    const uint8_t* data() const { return p_; }
    size_t size() const { return n_; }
    View view() const { return View(p_, n_); }
private:
    const uint8_t* p_ = nullptr;
    size_t n_ = 0;
    void* map_ = nullptr;
    size_t maplen_ = 0;
    Bytes buf_;
};

class Sink {
public:
    virtual ~Sink() {}
    virtual void write(const uint8_t* p, size_t n) = 0;
    uint64_t total() const { return total_; }
protected:
    uint64_t total_ = 0;
};

class VecSink : public Sink {
public:
    Bytes v;
    void write(const uint8_t* p, size_t n) override;
    size_t limit = (size_t)1 << 31;
};

class FileSink : public Sink {
public:
    FileSink() {}
    explicit FileSink(const std::string& path, int mode = 0644) { open(path, mode); }
    ~FileSink();
    void open(const std::string& path, int mode = 0644);
    void write(const uint8_t* p, size_t n) override;
    void flush();
    void close();
    void zeros(size_t n);
    void align(uint64_t a);
    int fd() const { return fd_; }
private:
    int fd_ = -1;
    Bytes buf_;
    std::string path_;
};

class CountSink : public Sink {
public:
    void write(const uint8_t*, size_t n) override { total_ += n; }
};

bool fileExists(const std::string& p);
bool isDir(const std::string& p);
int64_t fileSize(const std::string& p);
void mkdirs(const std::string& p, int mode = 0755);
void writeFile(const std::string& p, const uint8_t* d, size_t n, int mode = 0644);
void writeFile(const std::string& p, const std::string& s);
Bytes readFile(const std::string& p, size_t maxSize = (size_t)1 << 30);
std::string readText(const std::string& p);
void removeAll(const std::string& p);
void listDir(const std::string& p, std::vector<std::string>& names);
std::string joinPath(const std::string& a, const std::string& b);
std::string baseName(const std::string& p);
std::string dirName(const std::string& p);

std::string hex(const uint8_t* p, size_t n);
bool unhex(const std::string& s, Bytes& out);
std::string cstrOf(const char* p, size_t maxlen);
std::vector<std::string> splitLines(const std::string& s);
std::string trim(const std::string& s);
std::string escapeField(const std::string& s);
std::string unescapeField(const std::string& s);
std::string humanSize(uint64_t n);

inline uint64_t alignUp(uint64_t v, uint64_t a) { return a ? (v + a - 1) / a * a : v; }

}
