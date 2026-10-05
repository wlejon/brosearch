// Generates src/regex/unicode_fold.inc, src/regex/unicode_class.inc and
// src/regex/unicode_script.inc from the Unicode Character Database. The checked-in .inc files are
// the output for Unicode 16.0.0 (what ripgrep 15 uses).
//
//   cmake --build build --target gen_unicode
//   gen_unicode <ucd-dir> <out-dir>
//
// <ucd-dir> must contain UnicodeData.txt, DerivedCoreProperties.txt, PropList.txt,
// CaseFolding.txt, Scripts.txt, ScriptExtensions.txt and PropertyValueAliases.txt from
// https://www.unicode.org/Public/16.0.0/ucd/.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

using Ranges = std::vector<std::pair<uint32_t, uint32_t>>;

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\t')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

uint32_t hex(const std::string& s) { return static_cast<uint32_t>(std::stoul(trim(s), nullptr, 16)); }

Ranges to_ranges(const std::set<uint32_t>& cps) {
    Ranges r;
    for (uint32_t c : cps) {
        if (!r.empty() && r.back().second + 1 == c) r.back().second = c;
        else r.push_back({c, c});
    }
    return r;
}

std::vector<std::string> lines_of(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot open %s\n", path.c_str());
        std::exit(1);
    }
    std::vector<std::string> out;
    std::string line;
    while (std::getline(in, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trim(line);
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

// Parses "XXXX..YYYY ; Prop" lines into prop -> code points.
void load_props(const std::string& path, std::map<std::string, std::set<uint32_t>>& out) {
    for (auto& line : lines_of(path)) {
        auto f = split(line, ';');
        if (f.size() < 2) continue;
        std::string range = trim(f[0]), prop = trim(f[1]);
        uint32_t lo, hi;
        auto dots = range.find("..");
        if (dots == std::string::npos) lo = hi = hex(range);
        else { lo = hex(range.substr(0, dots)); hi = hex(range.substr(dots + 2)); }
        auto& set = out[prop];
        for (uint32_t c = lo; c <= hi; ++c) set.insert(c);
    }
}

// `compact` writes a table that fits on one line as a one-liner.
void emit_ranges(std::ostringstream& o, const std::string& name, const Ranges& r, size_t per_line = 6,
                 bool compact = false) {
    if (compact && r.size() <= per_line) {
        o << "static const CodepointRange " << name << "[] = {";
        for (auto& [lo, hi] : r) {
            char buf[48];
            std::snprintf(buf, sizeof buf, " {0x%X, 0x%X},", lo, hi);
            o << buf;
        }
        o << " };\n";
        return;
    }
    o << "static const CodepointRange " << name << "[] = {\n";
    for (size_t i = 0; i < r.size(); ++i) {
        if (i % per_line == 0) o << "   ";
        char buf[48];
        std::snprintf(buf, sizeof buf, " {0x%X, 0x%X},", r[i].first, r[i].second);
        o << buf;
        if (i % per_line == per_line - 1 || i + 1 == r.size()) o << "\n";
    }
    o << "};\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: gen_unicode <ucd-dir> <out-dir>\n");
        return 2;
    }
    std::string ucd = argv[1], outdir = argv[2];

    // General categories from UnicodeData.txt (with First/Last range pairs).
    std::map<std::string, std::set<uint32_t>> gc;
    {
        std::ifstream in(ucd + "/UnicodeData.txt", std::ios::binary);
        if (!in) { std::fprintf(stderr, "missing UnicodeData.txt\n"); return 1; }
        std::string line;
        uint32_t range_start = 0;
        while (std::getline(in, line)) {
            auto f = split(trim(line), ';');
            if (f.size() < 3) continue;
            uint32_t cp = hex(f[0]);
            const std::string& name = f[1];
            const std::string& cat = f[2];
            if (name.find(", First>") != std::string::npos) { range_start = cp; continue; }
            if (name.find(", Last>") != std::string::npos) {
                for (uint32_t c = range_start; c <= cp; ++c) gc[cat].insert(c);
                continue;
            }
            gc[cat].insert(cp);
        }
    }
    std::map<std::string, std::set<uint32_t>> props;
    load_props(ucd + "/DerivedCoreProperties.txt", props);
    load_props(ucd + "/PropList.txt", props);

    // \w per UTS#18 Annex C (what regex-syntax uses): Alphabetic + M + Nd + Pc + Join_Control.
    std::set<uint32_t> word = props["Alphabetic"];
    for (const char* c : {"Mn", "Mc", "Me", "Nd", "Pc"}) word.insert(gc[c].begin(), gc[c].end());
    word.insert(props["Join_Control"].begin(), props["Join_Control"].end());

    std::ostringstream cls;
    cls << "// Generated by tools/gen_unicode.cpp from the Unicode 16.0.0 UCD. Do not edit.\n";
    cls << "// clang-format off\n";
    emit_ranges(cls, "kPerlWord", to_ranges(word));
    emit_ranges(cls, "kPerlSpace", to_ranges(props["White_Space"]));
    static const char* const kCats[] = {"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me", "Nd", "Nl",
                                        "No", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc",
                                        "Sk", "So", "Zs", "Zl", "Zp", "Cc", "Cf", "Cs", "Co"};
    for (const char* c : kCats) emit_ranges(cls, std::string("kGc_") + c, to_ranges(gc[c]));
    cls << "static const GeneralCategoryTable kGeneralCategories[] = {\n";
    for (const char* c : kCats)
        cls << "    {\"" << c << "\", kGc_" << c << ", sizeof(kGc_" << c << ") / sizeof(kGc_" << c << "[0])},\n";
    cls << "};\n";

    // Simple case folding orbits (statuses C and S): every code point that folds to the same
    // target, plus the target, forms an orbit; we store cp -> next member, cyclically.
    std::map<uint32_t, std::set<uint32_t>> groups;
    for (auto& line : lines_of(ucd + "/CaseFolding.txt")) {
        auto f = split(line, ';');
        if (f.size() < 3) continue;
        std::string status = trim(f[1]);
        if (status != "C" && status != "S") continue;
        uint32_t from = hex(f[0]), to = hex(f[2]);
        groups[to].insert(to);
        groups[to].insert(from);
    }
    std::vector<std::pair<uint32_t, uint32_t>> orbit_next;
    for (auto& [target, members] : groups) {
        std::vector<uint32_t> m(members.begin(), members.end());
        for (size_t i = 0; i < m.size(); ++i) orbit_next.push_back({m[i], m[(i + 1) % m.size()]});
    }
    std::sort(orbit_next.begin(), orbit_next.end());
    std::ostringstream fold;
    fold << "// Generated by tools/gen_unicode.cpp from the Unicode 16.0.0 UCD. Do not edit.\n";
    fold << "// Simple case folding orbits: {code point, next code point in its orbit}.\n";
    fold << "// clang-format off\n";
    fold << "static const FoldPair kFoldOrbit[] = {\n";
    for (size_t i = 0; i < orbit_next.size(); ++i) {
        if (i % 6 == 0) fold << "   ";
        char buf[48];
        std::snprintf(buf, sizeof buf, " {0x%X, 0x%X},", orbit_next[i].first, orbit_next[i].second);
        fold << buf;
        if (i % 6 == 5 || i + 1 == orbit_next.size()) fold << "\n";
    }
    fold << "};\n";

    // Scripts. Script_Extensions are stored as a delta: scx(X) = (sc(X) - listed) + scx_add(X),
    // where `listed` is every code point ScriptExtensions.txt names (its scx replaces {sc}).
    std::map<std::string, std::vector<std::string>> script_aliases;  // short -> {long, extra...}
    for (auto& line : lines_of(ucd + "/PropertyValueAliases.txt")) {
        auto f = split(line, ';');
        if (f.size() < 3 || trim(f[0]) != "sc") continue;
        std::vector<std::string> names;
        for (size_t k = 2; k < f.size(); ++k) names.push_back(trim(f[k]));
        script_aliases[trim(f[1])] = names;
    }
    std::map<std::string, std::string> long_to_short;
    for (auto& [s, names] : script_aliases) long_to_short[names[0]] = s;
    std::map<std::string, std::set<uint32_t>> sc_long;
    load_props(ucd + "/Scripts.txt", sc_long);
    std::map<std::string, std::set<uint32_t>> sc;  // by short name
    std::set<uint32_t> assigned_script;
    for (auto& [name, cps] : sc_long) {
        if (!long_to_short.count(name)) { std::fprintf(stderr, "unknown script %s\n", name.c_str()); return 1; }
        sc[long_to_short[name]] = cps;
        assigned_script.insert(cps.begin(), cps.end());
    }
    {
        // @missing: 0000..10FFFF; Unknown
        auto& unknown = sc["Zzzz"];
        for (uint32_t c = 0; c <= 0x10FFFF; ++c)
            if (!assigned_script.count(c)) unknown.insert(c);
    }
    std::set<uint32_t> scx_listed;
    std::map<std::string, std::set<uint32_t>> scx_add;
    for (auto& line : lines_of(ucd + "/ScriptExtensions.txt")) {
        auto f = split(line, ';');
        if (f.size() < 2) continue;
        std::string range = trim(f[0]);
        uint32_t lo, hi;
        auto dots = range.find("..");
        if (dots == std::string::npos) lo = hi = hex(range);
        else { lo = hex(range.substr(0, dots)); hi = hex(range.substr(dots + 2)); }
        std::istringstream names(trim(f[1]));
        std::string s;
        std::vector<std::string> list;
        while (names >> s) list.push_back(s);
        for (uint32_t c = lo; c <= hi; ++c) {
            scx_listed.insert(c);
            for (auto& n : list) scx_add[n].insert(c);
        }
    }
    std::ostringstream scr;
    scr << "// Generated by tools/gen_unicode.cpp from the Unicode 16.0.0 UCD. Do not edit.\n";
    scr << "// Script (sc) per script; Script_Extensions (scx) as a delta: scx(X) = (sc(X) - kScxListed) +\n";
    scr << "// kScxAdd_X.\n";
    scr << "// clang-format off\n";
    emit_ranges(scr, "kScxListed", to_ranges(scx_listed), 10, true);
    for (auto& [s, names] : script_aliases) {
        if (!sc[s].empty()) emit_ranges(scr, "kSc_" + s, to_ranges(sc[s]), 10, true);
        if (scx_add.count(s)) emit_ranges(scr, "kScxAdd_" + s, to_ranges(scx_add[s]), 10, true);
    }
    scr << "static const ScriptTable kScripts[] = {\n";
    for (auto& [s, names] : script_aliases) {
        if (names.size() > 2) { std::fprintf(stderr, "too many aliases for %s\n", s.c_str()); return 1; }
        scr << "    {\"" << s << "\", {\"" << names[0] << "\", ";
        if (names.size() > 1) scr << "\"" << names[1] << "\"";
        else scr << "nullptr";
        if (sc[s].empty()) scr << "}, nullptr, 0, ";  // Katakana_Or_Hiragana: Script_Extensions only
        else scr << "}, kSc_" << s << ", sizeof(kSc_" << s << ") / sizeof(kSc_" << s << "[0]), ";
        if (scx_add.count(s))
            scr << "kScxAdd_" << s << ", sizeof(kScxAdd_" << s << ") / sizeof(kScxAdd_" << s << "[0])},\n";
        else
            scr << "nullptr, 0},\n";
    }
    scr << "};\n";

    std::ofstream(outdir + "/unicode_class.inc", std::ios::binary) << cls.str();
    std::ofstream(outdir + "/unicode_fold.inc", std::ios::binary) << fold.str();
    std::ofstream(outdir + "/unicode_script.inc", std::ios::binary) << scr.str();
    std::printf("word ranges %zu, fold pairs %zu\n", to_ranges(word).size(), orbit_next.size());
    return 0;
}
