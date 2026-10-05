#pragma once
// Incremental fuzzy index for launchers and pickers: items stream in (from any thread) while the
// user types. Matching is identical to fuzzy_filter() over the same items in insertion order; the
// index only adds reuse:
//   - items are kept in chunks of 1024 with their decoded form precomputed;
//   - like fzf's ChunkCache, the match set of a selective, cacheable query is remembered per full
//     chunk, and a later query whose cache key extends it (typing "fo" -> "foo", or "oo" -> "foo")
//     only re-examines the remembered candidates. Chunks appended since are scanned in full.

#include "brosearch/fuzzy.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

struct FuzzySearchResult {
    std::vector<FuzzyResult> results;  // best `limit` (all if 0) in fzf order
    size_t match_count = 0;            // matches among the searched items
    size_t item_count = 0;             // items in the snapshot that was searched
    size_t candidates_scanned = 0;     // items actually run through the matcher
    bool cancelled = false;            // results are partial
};

class FuzzyIndex {
public:
    explicit FuzzyIndex(const FuzzyOptions& options = FuzzyOptions());
    ~FuzzyIndex();
    FuzzyIndex(const FuzzyIndex&) = delete;
    FuzzyIndex& operator=(const FuzzyIndex&) = delete;

    // Appends items. Safe to call while other threads search; a search sees a consistent prefix.
    uint32_t add(std::string_view item);
    void add(std::span<const std::string_view> items);
    void add(std::span<const std::string> items);

    [[nodiscard]] size_t size() const noexcept;
    // The view stays valid for the lifetime of the index (until clear()).
    [[nodiscard]] std::string_view item(uint32_t index) const;

    // Searches the items present when the call starts. Thread-safe (concurrent searches allowed).
    [[nodiscard]] FuzzySearchResult search(std::string_view query, size_t limit = 0,
                                           bool with_positions = false,
                                           const CancellationToken* token = nullptr);

    [[nodiscard]] const FuzzyOptions& options() const noexcept;
    void set_cache_enabled(bool enabled);
    void clear_cache();
    // Removes all items. Must not race with add()/search()/item().
    void clear();

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace bro::search
