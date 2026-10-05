// Generates src/fuzzy/fuzzy_unicode_tables.inc: the Unicode data the fzf port needs, derived the
// way Go's `unicode` package derives what fzf sees (Go 1.21-1.25 ship Unicode 15.0.0; the
// tables here are built from Unicode 16.0.0):
//   - character classes for non-ASCII code points (Ll -> lower, Lu -> upper, N* -> number,
//     other L* -> letter, White_Space -> white; everything else is non-word),
//   - simple lowercase mappings (UnicodeData field 13, what unicode.ToLower uses),
//   - fzf's Latin normalization table, parsed from fzf's src/algo/normalize.go.
//
// Usage:
//   gen_fuzzy_unicode <UnicodeData.txt> <PropList.txt> <fzf/src/algo/normalize.go> <out.inc>
// UCD files: https://www.unicode.org/Public/16.0.0/ucd/ (the version is read from PropList.txt)

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

enum Cls : int { NonWord = 0, White = 1, Lower = 2, Upper = 3, Letter = 4, Number = 5 };

std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == d) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

int classify(const std::string& gc) {
    if (gc == "Ll") return Lower;
    if (gc == "Lu") return Upper;
    if (!gc.empty() && gc[0] == 'N') return Number;
    if (!gc.empty() && gc[0] == 'L') return Letter;
    return NonWord;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr, "usage: gen_fuzzy_unicode UnicodeData.txt PropList.txt normalize.go out.inc\n");
        return 2;
    }
    const char* unicode_data = argv[1];
    const char* prop_list = argv[2];
    const char* normalize_go = argv[3];
    const char* out_path = argv[4];
    std::vector<uint8_t> cls(0x110000, NonWord);
    std::map<uint32_t, uint32_t> lower;
    {
        std::ifstream in(unicode_data);
        if (!in) {
            std::fprintf(stderr, "cannot open %s\n", unicode_data);
            return 1;
        }
        std::string line;
        uint32_t range_first = 0;
        bool in_range = false;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto f = split(line, ';');
            if (f.size() < 14) continue;
            uint32_t cp = static_cast<uint32_t>(std::stoul(f[0], nullptr, 16));
            int c = classify(f[2]);
            if (f[1].find(", First>") != std::string::npos) {
                range_first = cp;
                in_range = true;
                continue;
            }
            if (in_range && f[1].find(", Last>") != std::string::npos) {
                for (uint32_t x = range_first; x <= cp; ++x) cls[x] = static_cast<uint8_t>(c);
                in_range = false;
                continue;
            }
            cls[cp] = static_cast<uint8_t>(c);
            if (!f[13].empty()) lower[cp] = static_cast<uint32_t>(std::stoul(f[13], nullptr, 16));
        }
    }
    // White_Space from PropList.txt (what Go's unicode.IsSpace reports), and the UCD version.
    std::string version;
    {
        std::ifstream in(prop_list);
        if (!in) {
            std::fprintf(stderr, "cannot open %s\n", prop_list);
            return 1;
        }
        std::string line;
        int spaces = 0;
        while (std::getline(in, line)) {
            if (version.empty() && line.rfind("# PropList-", 0) == 0) {
                version = line.substr(11, line.find(".txt") - 11);
                continue;
            }
            auto hash = line.find('#');
            std::string body = line.substr(0, hash);
            auto semi = body.find(';');
            if (semi == std::string::npos) continue;
            std::string prop = body.substr(semi + 1);
            prop.erase(0, prop.find_first_not_of(' '));
            prop.erase(prop.find_last_not_of(' ') + 1);
            if (prop != "White_Space") continue;  // not Pattern_White_Space
            std::string range = body.substr(0, semi);
            auto dots = range.find("..");
            uint32_t a = static_cast<uint32_t>(std::stoul(range.substr(0, dots), nullptr, 16));
            uint32_t b = dots == std::string::npos ? a : static_cast<uint32_t>(std::stoul(range.substr(dots + 2), nullptr, 16));
            for (uint32_t x = a; x <= b; ++x)
                if (x >= 0x80) cls[x] = White;
            ++spaces;
        }
        if (version.empty() || spaces == 0) {
            std::fprintf(stderr, "%s: no version header or no White_Space entries\n", prop_list);
            return 1;
        }
    }

    std::vector<std::pair<uint32_t, uint32_t>> norm;
    {
        std::ifstream in(normalize_go);
        if (!in) {
            std::fprintf(stderr, "cannot open %s\n", normalize_go);
            return 1;
        }
        std::string line;
        while (std::getline(in, line)) {
            auto p = line.find("0x");
            auto q = line.find(": '");
            if (p == std::string::npos || q == std::string::npos || p > 2) continue;
            uint32_t key = static_cast<uint32_t>(std::stoul(line.substr(p + 2, q - p - 2), nullptr, 16));
            size_t i = q + 3;
            uint32_t val = static_cast<unsigned char>(line[i]);
            if (line[i] == '\\') val = static_cast<unsigned char>(line[i + 1]);
            norm.emplace_back(key, val);
        }
    }
    std::sort(norm.begin(), norm.end());

    std::ostringstream o;
    o << "// Generated by tools/gen_fuzzy_unicode.cpp from UnicodeData.txt and PropList.txt " << version
      << " and fzf's\n// src/algo/normalize.go (fzf v0.74.4, MIT). Do not edit.\n\n";
    o << "// {first, last, class} for code points >= 0x80; gaps are non-word.\n";
    o << "static constexpr ClassRange kClassRanges[] = {\n";
    int n = 0;
    for (uint32_t cp = 0x80; cp < 0x110000;) {
        uint8_t c = cls[cp];
        uint32_t e = cp;
        while (e + 1 < 0x110000 && cls[e + 1] == c) ++e;
        if (c != NonWord) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "{0x%X,0x%X,%d},", cp, e, c);
            o << buf;
            if (++n % 6 == 0) o << "\n";
        }
        cp = e + 1;
    }
    o << "\n};\n\n// {code point, simple lowercase}\nstatic constexpr CasePair kLowerPairs[] = {\n";
    n = 0;
    for (auto [k, v] : lower) {
        if (k < 0x80) continue;
        char buf[48];
        std::snprintf(buf, sizeof buf, "{0x%X,0x%X},", k, v);
        o << buf;
        if (++n % 8 == 0) o << "\n";
    }
    o << "\n};\n\n// fzf Latin normalization {code point, ASCII}\nstatic constexpr CasePair kNormalizePairs[] = {\n";
    n = 0;
    for (auto [k, v] : norm) {
        char buf[48];
        std::snprintf(buf, sizeof buf, "{0x%X,0x%X},", k, v);
        o << buf;
        if (++n % 8 == 0) o << "\n";
    }
    o << "\n};\n";
    std::ofstream out(out_path, std::ios::binary);
    out << o.str();
    return out ? 0 : 1;
}
