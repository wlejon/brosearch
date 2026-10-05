#pragma once
// Shared pieces of batch ranking (fuzzy_filter) and the incremental index: a compact per-match
// record, fzf's ordering (radix sort on the packed rank key, stable in input order, as fzf's
// radixSortResults), and a persistent worker pool so a keystroke does not pay thread spawns.

#include "fuzzy/fuzzy_query.h"

#include <functional>
#include <string_view>
#include <vector>

namespace bro::search::fuzzy_detail {

struct Hit {
    uint64_t key;  // FuzzyRank packed: points[3] << 48 | ... | points[0]
    uint32_t index;
    int32_t score;
};

inline uint64_t pack_rank(const FuzzyRank& r) noexcept {
    return static_cast<uint64_t>(r[3]) << 48 | static_cast<uint64_t>(r[2]) << 32 |
           static_cast<uint64_t>(r[1]) << 16 | static_cast<uint64_t>(r[0]);
}

inline FuzzyRank unpack_rank(uint64_t k) noexcept {
    return {static_cast<uint16_t>(k), static_cast<uint16_t>(k >> 16), static_cast<uint16_t>(k >> 32),
            static_cast<uint16_t>(k >> 48)};
}

// Worker count for `work_items` items given the requested count (0 = auto).
size_t resolve_threads(size_t requested, size_t work_items);

// Runs fn(task) for task in [0, tasks) on up to `threads` threads (the caller included), using a
// process-wide pool of persistent workers. Returns when every task has finished.
void parallel_for(size_t tasks, size_t threads, const std::function<void(size_t)>& fn);

// Orders hits (given in ascending index order) the way fzf does — rank key, then index — when
// sortable, else keeps input order; keeps the best `limit` if > 0. Converts to FuzzyResult.
std::vector<FuzzyResult> finish_results(std::vector<Hit>& hits, bool sortable, size_t limit);

// Recomputes matches with positions for the (already ranked) results.
void fill_positions(const QueryImpl& q, std::vector<FuzzyResult>& results,
                    const std::function<std::string_view(uint32_t)>& item_at);

} // namespace bro::search::fuzzy_detail
