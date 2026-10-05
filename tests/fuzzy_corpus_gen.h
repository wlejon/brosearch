#pragma once
// Deterministic synthetic corpora for the fuzzy differential tests. Shared (header-only) by the
// ctest suite and `brosearch-cli fuzzy --oracle --gen=...`, so fixtures recorded from fzf over a
// generated corpus can be replayed without storing the corpus.
//
//   unicode: path-like items mixing ASCII with accented Latin (normalizable), Greek, Cyrillic,
//            CJK, titlecase digraphs, dotted I, Kelvin sign, fullwidth forms, invalid UTF-8.
//   long:    items of 200..6000 characters, so longer queries exceed fzf's 100 KiB V2 slab
//            and take the V1 fallback.

#include <cstdint>
#include <string>
#include <vector>

namespace fuzzy_corpus {

struct Rng {
    uint64_t s;
    uint64_t next() {
        uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    size_t below(size_t n) { return static_cast<size_t>(next() % n); }
};

inline std::vector<std::string> unicode_corpus(size_t n, uint64_t seed) {
    static const char* const words[] = {
        "readme", "Makefile", "src", "lib", "main", "test", "Résumé", "résumé", "naïve", "café", "CAFÉ",
        "Ångström", "Straße", "STRASSE", "ΑΘΗΝΑ", "αθήνα", "Ωmega", "Москва", "москва", "Привет",
        "東京", "日本語", "中文文件", "ǅemal", "ǆungla", "İstanbul", "ıi", "\xE2\x84\xAA" "elvin", "ﬁle",
        "ＡＢＣ", "ａｂｃ", "Ünïcödé", "über", "Über", "façade", "jalapeño", "Éclair", "ÉCOLE", "ñandú",
        "Ελληνικά", "data", "config", "build", "Font", "émoji😀", "tab\there", "x\xFFy", "\xC3", "Zürich",
    };
    static const char* const seps[] = {"/", "_", "-", " ", ".", "", "/", "::", " | ", "/"};
    Rng rng{seed};
    std::vector<std::string> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        std::string s;
        size_t parts = 1 + rng.below(5);
        for (size_t p = 0; p < parts; ++p) {
            if (p) s += seps[rng.below(sizeof(seps) / sizeof(*seps))];
            s += words[rng.below(sizeof(words) / sizeof(*words))];
            if (rng.below(5) == 0) s += std::to_string(rng.below(100));
        }
        if (rng.below(7) == 0) s = "  " + s;   // leading whitespace (prefix/equal trimming)
        if (rng.below(9) == 0) s += " ";       // trailing whitespace
        out.push_back(std::move(s));
    }
    return out;
}

inline std::vector<std::string> long_corpus(size_t n, uint64_t seed) {
    static const char* const words[] = {"alpha", "beta", "gamma", "delta", "Render", "scene", "graph", "node",
                                        "mesh", "Buffer", "texture", "shader", "compile", "path", "x", "q",
                                        "file", "Name", "zeta", "omega", "_", "42", "Café", "naïve"};
    static const char* const seps[] = {"/", "_", "-", " ", ".", "", ":", ","};
    Rng rng{seed};
    std::vector<std::string> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        size_t target = 200 + rng.below(5800);
        std::string s;
        while (s.size() < target) {
            if (!s.empty()) s += seps[rng.below(sizeof(seps) / sizeof(*seps))];
            s += words[rng.below(sizeof(words) / sizeof(*words))];
        }
        out.push_back(std::move(s));
    }
    return out;
}

} // namespace fuzzy_corpus
