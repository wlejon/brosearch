#pragma once
// Sets of code points (or bytes, in non-Unicode mode) as sorted, disjoint, non-adjacent ranges.

#include <algorithm>
#include <cstdint>
#include <vector>

namespace bro::search::rx {

struct CodepointRange {
    uint32_t lo;
    uint32_t hi;
    bool operator==(const CodepointRange&) const = default;
};

constexpr uint32_t kMaxCodepoint = 0x10FFFF;

class CharSet {
public:
    CharSet() = default;
    explicit CharSet(uint32_t c) { r_.push_back({c, c}); }
    CharSet(uint32_t lo, uint32_t hi) { r_.push_back({lo, hi}); }

    const std::vector<CodepointRange>& ranges() const { return r_; }
    bool empty() const { return r_.empty(); }
    bool operator==(const CharSet&) const = default;

    void add(uint32_t lo, uint32_t hi) {
        r_.push_back({lo, hi});
        dirty_ = true;
    }
    void add(uint32_t c) { add(c, c); }
    void add(const CharSet& o) {
        for (auto& x : o.r_) r_.push_back(x);
        dirty_ = true;
    }
    template <size_t N>
    void add_table(const CodepointRange (&t)[N]) {
        for (auto& x : t) r_.push_back(x);
        dirty_ = true;
    }
    void add_table(const CodepointRange* t, size_t n) {
        for (size_t i = 0; i < n; ++i) r_.push_back(t[i]);
        dirty_ = true;
    }

    // Must be called after add() before any query; idempotent.
    void canonicalize() {
        if (!dirty_) return;
        dirty_ = false;
        std::sort(r_.begin(), r_.end(), [](const CodepointRange& a, const CodepointRange& b) {
            return a.lo < b.lo || (a.lo == b.lo && a.hi < b.hi);
        });
        std::vector<CodepointRange> out;
        for (auto& x : r_) {
            if (!out.empty() && x.lo <= out.back().hi + 1) out.back().hi = std::max(out.back().hi, x.hi);
            else out.push_back(x);
        }
        r_.swap(out);
    }

    bool contains(uint32_t c) const {
        size_t lo = 0, hi = r_.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (r_[mid].hi < c) lo = mid + 1;
            else if (r_[mid].lo > c) hi = mid;
            else return true;
        }
        return false;
    }

    // Complement within [0, max]; in Unicode mode surrogates are excluded from the result.
    void negate(uint32_t max, bool exclude_surrogates) {
        canonicalize();
        std::vector<CodepointRange> out;
        uint32_t next = 0;
        for (auto& x : r_) {
            if (x.lo > next) out.push_back({next, x.lo - 1});
            next = x.hi + 1;
        }
        if (next <= max && (r_.empty() || r_.back().hi < max)) out.push_back({next, max});
        r_.swap(out);
        if (exclude_surrogates) subtract(CharSet(0xD800, 0xDFFF));
    }

    void intersect(const CharSet& o) {
        canonicalize();
        std::vector<CodepointRange> out;
        size_t i = 0, j = 0;
        const auto& b = o.r_;
        while (i < r_.size() && j < b.size()) {
            uint32_t lo = std::max(r_[i].lo, b[j].lo), hi = std::min(r_[i].hi, b[j].hi);
            if (lo <= hi) out.push_back({lo, hi});
            if (r_[i].hi < b[j].hi) ++i;
            else ++j;
        }
        r_.swap(out);
    }

    void subtract(const CharSet& o) {
        canonicalize();
        std::vector<CodepointRange> out;
        size_t j = 0;
        const auto& b = o.r_;
        for (auto x : r_) {
            uint32_t lo = x.lo;
            bool alive = true;
            while (j < b.size() && b[j].hi < lo) ++j;
            size_t k = j;
            while (alive && k < b.size() && b[k].lo <= x.hi) {
                if (b[k].lo > lo) out.push_back({lo, b[k].lo - 1});
                if (b[k].hi >= x.hi) alive = false;
                else lo = b[k].hi + 1;
                ++k;
            }
            if (alive) out.push_back({lo, x.hi});
        }
        r_.swap(out);
    }

    void symmetric_difference(const CharSet& o) {
        CharSet both = *this;
        both.intersect(o);
        CharSet uni = *this;
        uni.add(o);
        uni.canonicalize();
        uni.subtract(both);
        *this = uni;
    }

    // Removes a single code point (used to ban the line terminator).
    void remove(uint32_t c) { subtract(CharSet(c)); }

    size_t count() const {
        size_t n = 0;
        for (auto& x : r_) n += x.hi - x.lo + 1;
        return n;
    }

private:
    std::vector<CodepointRange> r_;
    bool dirty_ = false;
};

} // namespace bro::search::rx
