#include "info.h"
#include <stdlib.h>

namespace cu {

uint64_t parseNum(const std::string& s0, uint64_t def) {
    std::string s = trim(s0);
    if (s.empty()) return def;
    char* end = nullptr;
    unsigned long long v = strtoull(s.c_str(), &end, 0);
    if (end == s.c_str()) return def;
    return (uint64_t)v;
}

void InfoReader::parse(const std::string& text) {
    std::string cur;
    for (auto& line : splitLines(text)) {
        if (line.empty() || line[0] == '#') continue;
        if (line[0] == '[') {
            size_t e = line.find(']');
            if (e != std::string::npos) {
                cur = line.substr(1, e - 1);
                sections_[cur];
                continue;
            }
        }
        if (!cur.empty() && cur.size() >= 7 && cur.compare(0, 7, "entries") == 0) {
            sections_[cur].push_back(line);
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            if (!cur.empty()) sections_[cur].push_back(line);
            continue;
        }
        kv_[trim(line.substr(0, eq))] = unescapeField(line.substr(eq + 1));
    }
}

std::string InfoReader::get(const std::string& k, const std::string& def) const {
    auto it = kv_.find(k);
    return it == kv_.end() ? def : it->second;
}

uint64_t InfoReader::getu(const std::string& k, uint64_t def) const {
    auto it = kv_.find(k);
    return it == kv_.end() ? def : parseNum(it->second, def);
}

bool InfoReader::getb(const std::string& k, bool def) const {
    auto it = kv_.find(k);
    if (it == kv_.end()) return def;
    std::string v = trim(it->second);
    return v == "true" || v == "1" || v == "yes";
}

const std::vector<std::string>& InfoReader::lines(const std::string& section) const {
    auto it = sections_.find(section);
    return it == sections_.end() ? empty_ : it->second;
}

}
