#include "fuzzy/fuzzy_unicode.h"

#include <algorithm>
#include <iterator>

namespace bro::search::fuzzy_detail {

namespace {

struct ClassRange {
    uint32_t first;
    uint32_t last;
    int cls;  // generator classes: 1 white, 2 lower, 3 upper, 4 letter, 5 number
};

struct CasePair {
    uint32_t from;
    uint32_t to;
};

#include "fuzzy/fuzzy_unicode_tables.inc"

constexpr CharClass kGenToClass[] = {kNonWord, kWhite, kLower, kUpper, kLetter, kNumber};

uint32_t lookup_pair(const CasePair* begin, const CasePair* end, uint32_t r) noexcept {
    auto it = std::lower_bound(begin, end, r, [](const CasePair& p, uint32_t v) { return p.from < v; });
    if (it != end && it->from == r) return it->to;
    return r;
}

} // namespace

CharClass unicode_class(uint32_t r) noexcept {
    const ClassRange* b = std::begin(kClassRanges);
    const ClassRange* e = std::end(kClassRanges);
    auto it = std::upper_bound(b, e, r, [](uint32_t v, const ClassRange& c) { return v < c.first; });
    if (it == b) return kNonWord;
    --it;
    if (r <= it->last) return kGenToClass[it->cls];
    return kNonWord;
}

uint32_t to_lower(uint32_t r) noexcept {
    if (r < 0x80) return (r >= 'A' && r <= 'Z') ? r + 32 : r;
    return lookup_pair(std::begin(kLowerPairs), std::end(kLowerPairs), r);
}

bool is_space(uint32_t r) noexcept {
    if (r < 0x80) return r == ' ' || (r >= '\t' && r <= '\r');
    return unicode_class(r) == kWhite;
}

uint32_t normalize_rune(uint32_t r) noexcept {
    if (r < 0xC0 || r > 0xFF61) return r;
    return lookup_pair(std::begin(kNormalizePairs), std::end(kNormalizePairs), r);
}

uint32_t decode_utf8(const unsigned char* p, size_t avail, size_t* len) noexcept {
    constexpr uint32_t kErr = 0xFFFD;
    unsigned char c = p[0];
    if (c < 0x80) {
        *len = 1;
        return c;
    }
    *len = 1;
    if (c < 0xC2 || c > 0xF4) return kErr;
    size_t need = c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
    if (avail < 2) return kErr;
    unsigned char c1 = p[1];
    // Second-byte ranges per Go's utf8 acceptRanges.
    unsigned char lo = 0x80, hi = 0xBF;
    if (c == 0xE0) lo = 0xA0;
    else if (c == 0xED) hi = 0x9F;
    else if (c == 0xF0) lo = 0x90;
    else if (c == 0xF4) hi = 0x8F;
    if (c1 < lo || c1 > hi) return kErr;
    if (need == 2) {
        *len = 2;
        return (static_cast<uint32_t>(c & 0x1F) << 6) | (c1 & 0x3F);
    }
    if (avail < 3 || (p[2] & 0xC0) != 0x80) return kErr;
    if (need == 3) {
        *len = 3;
        return (static_cast<uint32_t>(c & 0x0F) << 12) | (static_cast<uint32_t>(c1 & 0x3F) << 6) | (p[2] & 0x3F);
    }
    if (avail < 4 || (p[3] & 0xC0) != 0x80) return kErr;
    *len = 4;
    return (static_cast<uint32_t>(c & 0x07) << 18) | (static_cast<uint32_t>(c1 & 0x3F) << 12) |
           (static_cast<uint32_t>(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
}

void decode_runes(std::string_view s, std::vector<uint32_t>& out, std::vector<uint32_t>* offsets) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t i = 0;
    while (i < s.size()) {
        size_t len = 1;
        uint32_t r = p[i] < 0x80 ? p[i] : decode_utf8(p + i, s.size() - i, &len);
        out.push_back(r);
        if (offsets) offsets->push_back(static_cast<uint32_t>(i));
        i += len;
    }
}

void append_utf8(std::string& out, uint32_t r) {
    if (r < 0x80) {
        out.push_back(static_cast<char>(r));
    } else if (r < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (r >> 6)));
        out.push_back(static_cast<char>(0x80 | (r & 0x3F)));
    } else if (r < 0x10000) {
        if (r >= 0xD800 && r <= 0xDFFF) r = 0xFFFD;
        out.push_back(static_cast<char>(0xE0 | (r >> 12)));
        out.push_back(static_cast<char>(0x80 | ((r >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (r & 0x3F)));
    } else if (r < 0x110000) {
        out.push_back(static_cast<char>(0xF0 | (r >> 18)));
        out.push_back(static_cast<char>(0x80 | ((r >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((r >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (r & 0x3F)));
    } else {
        append_utf8(out, 0xFFFD);
    }
}

} // namespace bro::search::fuzzy_detail
