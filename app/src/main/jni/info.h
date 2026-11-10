#pragma once
#include "common.h"

namespace cu {

class InfoWriter {
public:
    void comment(const std::string& s) { text_ += "# " + s + "\n"; }
    void blank() { text_ += "\n"; }
    void section(const std::string& s) { text_ += "\n[" + s + "]\n"; }
    void kv(const std::string& k, const std::string& v) { text_ += k + "=" + escapeField(v) + "\n"; }
    void kvu(const std::string& k, uint64_t v) { kv(k, fmtstr("%llu", (unsigned long long)v)); }
    void kvx(const std::string& k, uint64_t v) { kv(k, fmtstr("0x%llx", (unsigned long long)v)); }
    void kvb(const std::string& k, bool v) { kv(k, v ? "true" : "false"); }
    void raw(const std::string& s) { text_ += s; }
    const std::string& str() const { return text_; }
private:
    std::string text_;
};

class InfoReader {
public:
    void parse(const std::string& text);
    bool has(const std::string& k) const { return kv_.count(k) != 0; }
    std::string get(const std::string& k, const std::string& def = "") const;
    uint64_t getu(const std::string& k, uint64_t def = 0) const;
    bool getb(const std::string& k, bool def = false) const;
    const std::vector<std::string>& lines(const std::string& section) const;
private:
    std::map<std::string, std::string> kv_;
    std::map<std::string, std::vector<std::string>> sections_;
    std::vector<std::string> empty_;
};

uint64_t parseNum(const std::string& s, uint64_t def = 0);

}
