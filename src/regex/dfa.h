#pragma once
// Lazy (cached) DFA over a Program. States are ordered NFA sets plus the class of the previously
// consumed byte; epsilon closure is deferred to the transition, where both the byte before and the
// byte after the boundary are known, so every look-around assertion is exact. Each transition
// records whether a match ends at the boundary *before* the byte it consumes.
//
// Not thread-safe: one LazyDfa per thread per program (the Program itself is shared, immutable).

#include "regex/prog.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace bro::search::rx {

enum class SearchStatus : uint8_t { NoMatch, Match, GaveUp };

struct SearchResult {
    SearchStatus status = SearchStatus::NoMatch;
    size_t pos = 0;  // match end (forward), match start (reverse), or where the DFA gave up
};

class LazyDfa {
public:
    // leftmost_first: drop lower-priority threads after a match (forward, find-end). For the reverse
    // program use false ("all matches") to find the leftmost start.
    LazyDfa(const Program& prog, bool leftmost_first, size_t cache_bytes = 4u << 20);

    // Forward search for a match ending in [start, end]. Look-around sees data[0, len).
    // earliest: stop at the first match end seen (enough to know a match exists).
    SearchResult forward(const uint8_t* data, size_t len, size_t start, size_t end, bool anchored,
                         bool earliest);

    // Reverse anchored search from `end` down to `start`: the smallest s in [start, end] such that
    // a match spans [s, end). Requires a reverse program.
    SearchResult reverse(const uint8_t* data, size_t len, size_t start, size_t end);

private:
    // Context class of a byte for look-around; kCtxNone = beginning/end of input.
    enum : uint8_t { kCtxNone = 0, kCtxLF, kCtxCR, kCtxWord, kCtxOther, kCtxCount };
    static constexpr uint32_t kUnknown = 0xFFFFFFFFu;
    static constexpr uint32_t kDead = 0;

    struct State {
        uint32_t offset;  // into set_pool_
        uint32_t count;
        uint8_t ctx;
    };

    const Program& prog_;
    bool leftmost_first_;
    size_t cache_bytes_;
    uint32_t stride_;      // byte classes + 1 (EOI column)
    bool use_ctx_;         // program has looks; otherwise ctx is always kCtxNone
    std::array<bool, 256> quit_{};  // bytes on which the DFA gives up (non-ASCII w/ Unicode \b)
    std::array<uint8_t, 256> ctx_of_{};
    std::array<uint8_t, 256> class_rep_{};  // representative byte for each class

    std::vector<State> states_;
    std::vector<uint32_t> set_pool_;
    std::vector<uint32_t> table_;  // states_ x stride_: (next << 1) | match_before, or kUnknown
    std::unordered_map<std::string, uint32_t> index_;
    uint32_t start_cache_[2][kCtxCount];
    size_t clears_ = 0;

    // Scratch for closure computation.
    std::vector<uint32_t> stack_;
    std::vector<uint32_t> seen_gen_;
    uint32_t gen_ = 0;
    std::vector<uint32_t> closure_;
    std::vector<uint32_t> next_set_;
    std::string key_;

    void reset_cache();
    uint32_t intern(const uint32_t* set, size_t n, uint8_t ctx);
    uint32_t start_state(bool anchored, uint8_t ctx);
    // Computes (and caches) the transition of `s` on class column `col` whose concrete input is
    // `byte` (or EOI when col == stride_-1). Returns the table entry.
    uint32_t compute(uint32_t s, uint32_t col, int byte);
    bool look_ok(Look look, uint8_t before, uint8_t after) const;
    uint8_t ctx_byte(int byte) const {
        return byte < 0 ? static_cast<uint8_t>(kCtxNone) : ctx_of_[static_cast<uint8_t>(byte)];
    }
    size_t memory() const;
    bool maybe_clear(uint32_t& current);
};

} // namespace bro::search::rx
