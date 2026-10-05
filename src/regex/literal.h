#pragma once
// Literal analysis and fast substring search.
//
// extract_literals() finds (a) whether the whole pattern is a plain literal (then no automaton is
// needed at all) and (b) the best literal every match must contain, used as a prefilter that
// skips straight to candidate lines. Bytes may be ASCII-case-insensitive (`ci`).

#include "regex/hir.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bro::search::rx {

struct LitByte {
    uint8_t b;   // for ci bytes: the lowercase form
    bool ci;
    bool operator==(const LitByte&) const = default;
};
using Literal = std::vector<LitByte>;

struct LiteralInfo {
    bool exact = false;   // the pattern matches exactly `whole` (no look-arounds)
    Literal whole;
    Literal required;     // must occur in every match; empty if none worth using
    // Up to 3 rare bytes, one of which occurs in every match (alternations, Unicode case folds),
    // used when there is no required literal. Empty if none worth using.
    std::vector<uint8_t> rare_bytes;
};

LiteralInfo extract_literals(const Hir& hir);

// Frequency rank of a byte in typical text/code (higher = more common).
uint8_t byte_rank(uint8_t b);

class LiteralFinder {
public:
    LiteralFinder() = default;
    explicit LiteralFinder(Literal lit);
    // Byte-set mode: finds any of 1-3 bytes.
    static LiteralFinder any_of(const std::vector<uint8_t>& bytes);

    bool empty() const { return lit_.empty() && set_n_ == 0; }
    size_t size() const { return lit_.size(); }
    const Literal& literal() const { return lit_; }

    // First occurrence starting in [start, end - size()], or SIZE_MAX. In byte-set mode, the
    // first byte of the set in [start, end).
    size_t find(const uint8_t* hay, size_t start, size_t end) const;

private:
    Literal lit_;
    uint8_t set_[3] = {0, 0, 0};
    int set_n_ = 0;
    size_t rare_ = 0;       // index of the rarest byte, scanned for with memchr/memchr2
    uint8_t rare_a_ = 0, rare_b_ = 0;
    bool rare_ci_ = false;
    bool any_ci_ = false;
    std::vector<uint8_t> plain_;  // lit bytes (lowercase for ci)
    size_t pair_[2] = {0, 0};     // offsets of the two bytes the packed-pair search keys on

    // A rarest byte at or below this rank is left to memchr (fast when it seldom occurs);
    // otherwise literals of 2+ bytes use the packed-pair search.
    static constexpr int kMemchrRank = 90;

    bool verify(const uint8_t* p) const;
    size_t find_pair(const uint8_t* hay, size_t start, size_t end) const;
};

// memchr for one of two bytes (SSE2 on x86-64). Returns pointer or nullptr.
const uint8_t* memchr2(uint8_t a, uint8_t b, const uint8_t* p, const uint8_t* end);
// memchr for one of three bytes.
const uint8_t* memchr3(uint8_t a, uint8_t b, uint8_t c, const uint8_t* p, const uint8_t* end);

} // namespace bro::search::rx
