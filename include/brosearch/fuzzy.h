#pragma once
// Fuzzy matching: a faithful port of fzf (v0.74.4) — FuzzyMatchV2 (Smith-Waterman variant with
// fzf's bonuses; falls back to V1 when len(item) * len(query) > 100 KiB as fzf does), the exact /
// prefix / suffix / equal / boundary matchers, extended-search syntax, smart case, Latin
// normalization, scoring schemes and fzf's sort order. For the same input list and query,
// fuzzy_filter() returns items in the order `fzf --filter QUERY` prints them.
//
// Extended-search syntax (default, as in fzf):
//   foo bar      AND: every space-separated term must match ("\ " is a literal space)
//   foo | bar    OR between adjacent terms
//   'foo         exact substring ('foo' = exact at word boundaries)
//   ^foo  foo$   prefix / suffix (^foo$ = equal)
//   !foo         inverse exact (!'foo = inverse fuzzy, !^foo, !foo$)
//
// Incremental use (launcher typing over a growing item list): see brosearch/fuzzy_index.h.

#include "brosearch/cancellation_token.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

enum class FuzzyCase : uint8_t {
    Smart,    // case-insensitive unless the term contains an uppercase letter (fzf default)
    Ignore,   // fzf -i
    Respect,  // fzf +i
};

enum class FuzzyScheme : uint8_t {
    Default,  // fzf --scheme=default
    Path,     // fzf --scheme=path: bonuses tuned for paths; tiebreak pathname,length
    History,  // fzf --scheme=history: no length tiebreak
};

// Sort criteria applied after the score (fzf --tiebreak). Index (input order) always comes last;
// `Index` itself is a no-op marker, so {Index} alone means "score, then input order".
enum class FuzzyTiebreak : uint8_t { Length, Chunk, Pathname, Begin, End, Index };

// One fzf field range (an element of --nth). Fields are 1-based; negative counts from the end;
// 0 stands for an open end. As fzf normalizes them: "2" = {2, 2}, "2.." = {2, 0}, "..3" =
// {0, 3} (as is "1..3"), "-2.." = {-2, 0}, "1..-2" = {0, -2}, ".." = {0, 0} (the whole item).
struct FuzzyField {
    int begin = 0;
    int end = 0;
    bool operator==(const FuzzyField&) const = default;
};

// Parses an fzf --nth value ("1,3..5,-1"). False (and `out` untouched) on a malformed one.
bool parse_fuzzy_nth(std::string_view spec, std::vector<FuzzyField>& out);

struct FuzzyOptions {
    FuzzyCase case_mode = FuzzyCase::Smart;
    FuzzyScheme scheme = FuzzyScheme::Default;
    bool extended = true;    // extended-search syntax (fzf +x disables)
    bool exact = false;      // fzf -e: plain terms match exactly, 'term is fuzzy
    bool normalize = true;   // fold Latin diacritics (fzf --literal disables)
    bool algo_v1 = false;    // fzf --algo=v1 (greedy, faster, lower quality)
    bool sort = true;        // false = keep input order (fzf --no-sort)
    // fzf --tac: reverse the input order (unsorted results come last-first and score ties go
    // to the later item). FuzzyResult::index still counts from the first item.
    bool tac = false;
    // fzf --nth: terms match only these fields of an item (the first field, in this order,
    // where a term matches wins; positions and ranks stay in whole-item coordinates). Empty =
    // the whole item.
    std::vector<FuzzyField> nth;
    // fzf --delimiter, splitting fields for nth: empty = AWK style (runs of non-blanks with
    // their trailing blanks; leading blanks skipped). One character or text with no regex
    // metacharacters (or an invalid regex) is literal; otherwise a regex. "\t" means a tab.
    std::string delimiter;
    // Empty = the scheme's default ([Length]; Path: [Pathname, Length]; History: []).
    std::vector<FuzzyTiebreak> tiebreak;
    // fzf's path scheme treats '\\' as a delimiter on Windows (os.PathSeparator). Follows the
    // host by default; set explicitly for platform-independent results.
#ifdef _WIN32
    bool backslash_delimiter = true;
#else
    bool backslash_delimiter = false;
#endif
    size_t threads = 0;  // batch ranking: 0 = hardware concurrency (capped at 16)
};

// fzf's sort key: lexicographically smaller is better, then the item index.
using FuzzyRank = std::array<uint16_t, 4>;

struct FuzzyMatch {
    int32_t score = 0;
    FuzzyRank rank{};
    // Byte offsets (into the item) of the first byte of every highlighted character, ascending,
    // without duplicates. Filled only when positions were requested.
    std::vector<uint32_t> positions;
};

struct FuzzyResult {
    uint32_t index = 0;  // position of the item in the input
    int32_t score = 0;
    FuzzyRank rank{};
    std::vector<uint32_t> positions;  // as in FuzzyMatch
};

// fzf's result order: rank, then index (the later item first with tac).
[[nodiscard]] inline bool fuzzy_result_less(const FuzzyResult& a, const FuzzyResult& b, bool tac = false) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a.rank[static_cast<size_t>(i)] != b.rank[static_cast<size_t>(i)])
            return a.rank[static_cast<size_t>(i)] < b.rank[static_cast<size_t>(i)];
    }
    return tac ? a.index > b.index : a.index < b.index;
}

namespace fuzzy_detail {
struct QueryImpl;
}

// A compiled query. Immutable and safe to share between threads.
class FuzzyQuery {
public:
    explicit FuzzyQuery(std::string_view query, const FuzzyOptions& options = FuzzyOptions());

    // True when the query has no (positive or negative) terms: everything matches, unsorted.
    [[nodiscard]] bool empty() const noexcept;
    // False when results keep input order (empty query, only inverse terms, or sort disabled).
    [[nodiscard]] bool sortable() const noexcept;
    [[nodiscard]] const FuzzyOptions& options() const noexcept;
    // fzf's cache key: the cacheable terms joined by '\t'; "" when nothing is cacheable.
    [[nodiscard]] const std::string& cache_key() const noexcept;
    // Every term is a single, non-inverse fuzzy (or, with exact=true, exact) term, so the set of
    // matches of any query whose cache key contains this key at either end is a subset.
    [[nodiscard]] bool cacheable() const noexcept;

    // Matches one item. Thread-safe. `out` may be null when only the verdict is needed.
    bool match(std::string_view item, FuzzyMatch* out = nullptr, bool with_positions = false) const;

    [[nodiscard]] const fuzzy_detail::QueryImpl& impl() const noexcept { return *impl_; }

private:
    std::shared_ptr<const fuzzy_detail::QueryImpl> impl_;
};

// One-shot convenience: compile + match.
[[nodiscard]] std::optional<FuzzyMatch> fuzzy_match(std::string_view query, std::string_view item,
                                                    const FuzzyOptions& options = FuzzyOptions());

// Batch ranking (multithreaded). Returns matches in fzf --filter order; `limit` > 0 keeps only the
// best `limit` (same order as the head of the full list). Cancellation returns what was ranked so
// far (possibly empty).
[[nodiscard]] std::vector<FuzzyResult> fuzzy_filter(const FuzzyQuery& query,
                                                    std::span<const std::string_view> items,
                                                    size_t limit = 0, bool with_positions = false,
                                                    const CancellationToken* token = nullptr);
[[nodiscard]] std::vector<FuzzyResult> fuzzy_filter(const FuzzyQuery& query,
                                                    std::span<const std::string> items,
                                                    size_t limit = 0, bool with_positions = false,
                                                    const CancellationToken* token = nullptr);

// An item as fzf shows it: every byte that is not part of valid UTF-8 (as Go decodes it)
// becomes U+FFFD. Byte positions into the item are mapped onto the shown text.
struct FuzzyDisplay {
    std::string text;
    std::vector<uint32_t> positions;
};
[[nodiscard]] FuzzyDisplay fuzzy_display(std::string_view item, std::span<const uint32_t> byte_positions = {});

// Converts byte-offset positions to character (code point) indices, e.g. for terminal cells.
[[nodiscard]] std::vector<uint32_t> fuzzy_char_indices(std::string_view item,
                                                       std::span<const uint32_t> byte_positions);

} // namespace bro::search
