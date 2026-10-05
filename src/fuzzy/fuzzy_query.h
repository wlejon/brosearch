#pragma once
// Compiled fzf pattern (port of fzf src/pattern.go + the ranking half of src/result.go).

#include "brosearch/fuzzy.h"
#include "fuzzy/fuzzy_algo.h"
#include "fuzzy/fuzzy_fields.h"

#include <string>
#include <vector>

namespace bro::search::fuzzy_detail {

enum class TermType : uint8_t { Fuzzy, Exact, ExactBoundary, Prefix, Suffix, Equal };

struct Term {
    TermType type = TermType::Fuzzy;
    bool inverse = false;
    bool case_sensitive = false;
    bool normalize = false;
    std::vector<uint32_t> text;  // runes; lowercased when !case_sensitive
};

// An item prepared for matching: bytes when all-ASCII, otherwise runes + byte offsets.
struct PreparedItem {
    Chars chars;
    const uint32_t* byte_offsets = nullptr;  // rune index -> byte offset; null for ASCII items
    uint32_t byte_len = 0;
    std::string_view text;                   // the item's bytes (for regex field delimiters)
};

// Per-thread scratch used by matching.
struct MatchScratch {
    Slab slab;
    std::vector<int32_t> pos;
    std::vector<int32_t> all_pos;
    std::vector<uint32_t> runes;    // decode buffer for non-ASCII items
    std::vector<uint32_t> offsets;  // decode buffer for non-ASCII items
    std::vector<FieldSlice> fields;
};

struct QueryImpl {
    FuzzyOptions options;
    Scheme scheme;
    std::vector<FuzzyTiebreak> criteria;  // tiebreaks after score
    bool forward = true;
    bool fzf_with_pos = false;  // fzf computes positions for ranking (pathname/chunk criteria)
    bool extended = true;
    bool fuzzy = true;
    bool sortable = true;
    bool cacheable = true;
    bool empty = false;
    std::string cache_key;
    AlgoFn fuzzy_algo = nullptr;
    std::vector<std::vector<Term>> term_sets;  // non-extended mode: one set with one term
    FieldSpec fields;                          // --nth (inactive when options.nth is empty)

    void build(std::string_view query, const FuzzyOptions& opts);

    // Core matcher. Returns false for no match. Positions are rune indices (sorted, unique)
    // in scratch.all_pos when with_pos.
    bool match_prepared(const PreparedItem& item, int32_t* score_out, FuzzyRank* rank_out, bool with_pos,
                        MatchScratch& scratch) const;

    // Full match on a raw item, filling a FuzzyMatch (byte positions).
    bool match_item(std::string_view item, FuzzyMatch* out, bool with_positions, MatchScratch& scratch) const;
};

// Prepares an item, decoding into scratch buffers when it is not pure ASCII.
PreparedItem prepare_item(std::string_view item, std::vector<uint32_t>& runes, std::vector<uint32_t>& offsets);

// Thread-local scratch for callers without their own.
MatchScratch& thread_scratch();

} // namespace bro::search::fuzzy_detail
