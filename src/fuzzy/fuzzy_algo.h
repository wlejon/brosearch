#pragma once
// Port of fzf's src/algo/algo.go (v0.74.4): FuzzyMatchV1/V2, ExactMatchNaive/Boundary,
// PrefixMatch, SuffixMatch, EqualMatch. Scores, tie-breaking inside an item (forward vs
// backward), and match positions follow the Go code line by line. Scheme parameters that fzf
// keeps in package globals live in a Scheme value here so several schemes can coexist.

#include "fuzzy/fuzzy_unicode.h"

#include <cstdint>
#include <vector>

namespace bro::search::fuzzy_detail {

constexpr int16_t kScoreMatch = 16;
constexpr int16_t kScoreGapStart = -3;
constexpr int16_t kScoreGapExtension = -1;
constexpr int16_t kBonusBoundary = kScoreMatch / 2;
constexpr int16_t kBonusNonWord = kScoreMatch / 2;
constexpr int16_t kBonusCamel123 = kBonusBoundary + kScoreGapExtension;
constexpr int16_t kBonusConsecutive = -(kScoreGapStart + kScoreGapExtension);
constexpr int16_t kBonusFirstCharMultiplier = 2;

// fzf's slab16Size: V2 falls back to V1 when len(item) * len(pattern) exceeds it.
constexpr int64_t kSlab16Size = 100 * 1024;

struct Scheme {
    int16_t bonus_boundary_white = kBonusBoundary + 2;
    int16_t bonus_boundary_delimiter = kBonusBoundary + 1;
    CharClass initial_class = kWhite;
    CharClass ascii_class[128] = {};
    int16_t bonus_matrix[7][7] = {};

    CharClass class_of(uint32_t r) const noexcept {
        if (r < 128) return ascii_class[r];
        return unicode_class(r);
    }
    int16_t bonus_for(CharClass prev, CharClass cls) const noexcept;
};

enum class SchemeKind : uint8_t { Default, Path, History };

// Builds the parameters fzf's algo.Init(scheme) sets up. `backslash_delimiter` reproduces the
// Windows path scheme (os.PathSeparator == '\\' adds '\\' to the delimiter set).
Scheme make_scheme(SchemeKind kind, bool backslash_delimiter);

// Text being matched: either one byte per character (all-ASCII item, fzf's "IsBytes") or runes.
struct Chars {
    const unsigned char* bytes = nullptr;
    const uint32_t* runes = nullptr;
    int32_t n = 0;

    bool is_bytes() const noexcept { return bytes != nullptr || runes == nullptr; }
    uint32_t get(int32_t i) const noexcept { return bytes ? bytes[i] : runes[i]; }
    int32_t leading_whitespaces() const noexcept;
    int32_t trailing_whitespaces() const noexcept;
};

struct AlgoResult {
    int32_t start = -1;
    int32_t end = -1;
    int32_t score = 0;
    // The start fzf reports when called without positions (V2 then returns the first occurrence
    // of the first pattern char instead of backtracking). Ranking must use this when fzf would.
    int32_t start_nopos = -1;
};

// Per-thread scratch (fzf's Slab). Reused across calls to avoid allocation.
struct Slab {
    std::vector<int16_t> i16;
    std::vector<int32_t> i32;
    std::vector<uint32_t> t;  // lowered/normalized text copy (T in V2)
};

// pattern: already lowercased if !case_sensitive and normalized if normalize (fzf contract).
// pos (optional): receives rune indices of matched characters, in fzf's order (descending
// for V2, ascending for V1) - callers sort.
using AlgoFn = AlgoResult (*)(const Scheme& sc, bool case_sensitive, bool normalize, bool forward,
                              const Chars& text, const uint32_t* pattern, int32_t m,
                              std::vector<int32_t>* pos, Slab& slab);

AlgoResult fuzzy_match_v2(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                          std::vector<int32_t>*, Slab&);
AlgoResult fuzzy_match_v1(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                          std::vector<int32_t>*, Slab&);
AlgoResult exact_match_naive(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                             std::vector<int32_t>*, Slab&);
AlgoResult exact_match_boundary(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                                std::vector<int32_t>*, Slab&);
AlgoResult prefix_match(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                        std::vector<int32_t>*, Slab&);
AlgoResult suffix_match(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                        std::vector<int32_t>*, Slab&);
AlgoResult equal_match(const Scheme&, bool, bool, bool, const Chars&, const uint32_t*, int32_t,
                       std::vector<int32_t>*, Slab&);

} // namespace bro::search::fuzzy_detail
