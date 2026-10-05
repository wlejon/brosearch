// Port of fzf v0.74.4 src/tokenizer.go (Tokenize, Transform, StripLastDelimiter, ParseRange) and
// the --nth / --delimiter parsing of src/options.go (splitNth, delimiterRegexp).
#include "fuzzy/fuzzy_fields.h"

#include <algorithm>
#include <climits>

namespace bro::search {

namespace {

// Go strconv.Atoi over what splitNth lets through ([0-9,-.]): an optional '-' and digits.
bool go_atoi(std::string_view s, int& out) {
    bool neg = false;
    if (!s.empty() && (s[0] == '-' || s[0] == '+')) {
        neg = s[0] == '-';
        s.remove_prefix(1);
    }
    if (s.empty()) return false;
    long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > INT_MAX) return false;
    }
    out = static_cast<int>(neg ? -v : v);
    return true;
}

FuzzyField new_range(int begin, int end) {
    if (begin == 1 && end != 1) begin = 0;
    if (end == -1) end = 0;
    return {begin, end};
}

bool parse_range(std::string_view s, FuzzyField& out) {
    constexpr std::string_view dots = "..";
    if (s == dots) {
        out = new_range(0, 0);
        return true;
    }
    if (s.substr(0, 2) == dots) {
        int end;
        if (!go_atoi(s.substr(2), end) || end == 0) return false;
        out = new_range(0, end);
        return true;
    }
    if (s.size() >= 2 && s.substr(s.size() - 2) == dots) {
        int begin;
        if (!go_atoi(s.substr(0, s.size() - 2), begin) || begin == 0) return false;
        out = new_range(begin, 0);
        return true;
    }
    if (const size_t at = s.find(dots); at != std::string_view::npos) {
        if (s.find(dots, at + 2) != std::string_view::npos) return false;  // strings.Split: 3+ parts
        int begin, end;
        if (!go_atoi(s.substr(0, at), begin) || !go_atoi(s.substr(at + 2), end)) return false;
        if (begin == 0 || end == 0 || (begin < 0 && end > 0)) return false;
        out = new_range(begin, end);
        return true;
    }
    int n;
    if (!go_atoi(s, n) || n == 0) return false;
    out = new_range(n, n);
    return true;
}

} // namespace

bool parse_fuzzy_nth(std::string_view spec, std::vector<FuzzyField>& out) {
    if (spec.empty()) return false;
    for (char c : spec)
        if (!((c >= '0' && c <= '9') || c == ',' || c == '-' || c == '.')) return false;
    std::vector<FuzzyField> ranges;
    size_t i = 0;
    for (;;) {
        size_t comma = spec.find(',', i);
        FuzzyField f;
        if (!parse_range(spec.substr(i, comma == std::string_view::npos ? std::string_view::npos : comma - i), f))
            return false;
        ranges.push_back(f);
        if (comma == std::string_view::npos) break;
        i = comma + 1;
    }
    out = std::move(ranges);
    return true;
}

} // namespace bro::search

namespace bro::search::fuzzy_detail {

namespace {

size_t byte_of(std::string_view text, const uint32_t* offsets, int32_t n, int32_t r) {
    if (!offsets) return static_cast<size_t>(r);
    return r < n ? offsets[r] : text.size();
}

int32_t rune_of(const uint32_t* offsets, int32_t n, size_t byte) {
    if (!offsets) return static_cast<int32_t>(byte);
    return static_cast<int32_t>(std::lower_bound(offsets, offsets + n, static_cast<uint32_t>(byte)) - offsets);
}

} // namespace

FieldSpec::FieldSpec(const FuzzyOptions& options) : nth_(options.nth) {
    if (options.delimiter.empty()) return;  // AWK
    // delimiterRegexp: "\t" escapes, then literal unless a valid regex with metacharacters.
    std::string d;
    for (size_t i = 0; i < options.delimiter.size(); ++i) {
        if (options.delimiter[i] == '\\' && i + 1 < options.delimiter.size() && options.delimiter[i + 1] == 't') {
            d.push_back('\t');
            ++i;
        } else {
            d.push_back(options.delimiter[i]);
        }
    }
    decode_runes(d, literal_, nullptr);
    kind_ = Kind::Literal;
    if (literal_.size() == 1) return;
    if (d.find_first_of("\\.+*?()|[]{}^$") == std::string::npos) return;
    if (auto re = Regex::compile(d)) {
        regex_ = std::move(re);
        kind_ = Kind::Regex;
    }
}

void FieldSpec::tokenize(std::string_view text, const Chars& chars, const uint32_t* offsets,
                         std::vector<FieldSlice>& tokens) const {
    tokens.clear();
    const int32_t n = chars.n;
    if (kind_ == Kind::Awk) {
        enum { Nil, Black, White } state = Nil;
        int32_t begin = 0, end = 0;
        for (int32_t i = 0; i < n; ++i) {
            const uint32_t r = chars.get(i);
            const bool white = r == 9 || r == 32 || r == 10;
            if (state == Nil) {
                if (!white) state = Black, begin = i, end = i + 1;
            } else if (state == Black) {
                end = i + 1;
                if (white) state = White;
            } else if (white) {
                end = i + 1;
            } else {
                tokens.push_back({begin, end - begin});
                state = Black, begin = i, end = i + 1;
            }
        }
        if (begin < end) tokens.push_back({begin, end - begin});
        return;
    }
    if (kind_ == Kind::Literal) {
        const int32_t m = static_cast<int32_t>(literal_.size());
        if (m == 0) {  // strings.SplitAfter(s, ""): one token per character
            for (int32_t i = 0; i < n; ++i) tokens.push_back({i, 1});
            return;
        }
        int32_t begin = 0;
        for (int32_t i = 0; i + m <= n;) {
            int32_t k = 0;
            while (k < m && chars.get(i + k) == literal_[static_cast<size_t>(k)]) ++k;
            if (k == m) {
                tokens.push_back({begin, i + m - begin});
                begin = i += m;
            } else {
                ++i;
            }
        }
        tokens.push_back({begin, n - begin});
        return;
    }
    int32_t begin = 0;
    for (const RegexMatch& m : regex_->find_all(text)) {
        const int32_t e = rune_of(offsets, n, m.end);
        tokens.push_back({begin, e - begin});
        begin = e;
    }
    if (begin < n) tokens.push_back({begin, n - begin});
}

int32_t FieldSpec::strip_last_delimiter(std::string_view text, const Chars& chars, const uint32_t* offsets,
                                        const FieldSlice& f) const {
    if (kind_ == Kind::Literal) {
        const int32_t m = static_cast<int32_t>(literal_.size());
        if (m == 0 || f.n < m) return f.n;
        for (int32_t k = 0; k < m; ++k)
            if (chars.get(f.begin + f.n - m + k) != literal_[static_cast<size_t>(k)]) return f.n;
        return f.n - m;
    }
    const size_t b = byte_of(text, offsets, chars.n, f.begin);
    const size_t e = byte_of(text, offsets, chars.n, f.begin + f.n);
    const std::string_view field = text.substr(b, e - b);
    const auto all = regex_->find_all(field);
    if (all.empty() || all.back().end != field.size()) return f.n;
    return rune_of(offsets, chars.n, b + all.back().start) - f.begin;
}

void FieldSpec::fields(std::string_view text, const Chars& chars, const uint32_t* offsets,
                       std::vector<FieldSlice>& out) const {
    std::vector<FieldSlice> tokens;
    tokenize(text, chars, offsets, tokens);
    const int num = static_cast<int>(tokens.size());
    out.clear();
    for (const FuzzyField& r : nth_) {
        int first = 0, last = -1;  // token indices, 0-based inclusive; empty when last < first
        int min_idx = 0;
        if (r.begin == r.end) {
            if (r.begin == 0) {
                first = 0, last = num - 1;
            } else {
                int idx = r.begin < 0 ? r.begin + num + 1 : r.begin;
                if (idx >= 1 && idx <= num) first = last = min_idx = idx - 1;
            }
        } else {
            int begin, end;
            if (r.begin == 0) {
                begin = 1, end = r.end < 0 ? r.end + num + 1 : r.end;
            } else if (r.end == 0) {
                begin = r.begin < 0 ? r.begin + num + 1 : r.begin, end = num;
            } else {
                begin = r.begin < 0 ? r.begin + num + 1 : r.begin;
                end = r.end < 0 ? r.end + num + 1 : r.end;
            }
            min_idx = std::max(0, begin - 1);
            first = std::max(begin, 1) - 1;
            last = std::min(end, num) - 1;
        }
        FieldSlice s;
        s.begin = min_idx < num ? tokens[static_cast<size_t>(min_idx)].begin : 0;
        if (first <= last) {
            s.begin = tokens[static_cast<size_t>(first)].begin;
            const FieldSlice& t = tokens[static_cast<size_t>(last)];
            s.n = t.begin + t.n - s.begin;
        }
        out.push_back(s);
    }
    // Strip the last delimiter to allow suffix match (not for AWK fields).
    if (!out.empty() && kind_ != Kind::Awk) out.back().n = strip_last_delimiter(text, chars, offsets, out.back());
}

} // namespace bro::search::fuzzy_detail
