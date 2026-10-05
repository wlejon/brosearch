// Port of fzf v0.74.4 src/pattern.go (BuildPattern, parseTerms, extendedMatch, basicMatch) and
// src/result.go (buildResult): query parsing, per-item matching and the rank key.
#include "fuzzy/fuzzy_query.h"

#include <algorithm>
#include <cstring>

namespace bro::search::fuzzy_detail {

namespace {

std::vector<uint32_t> to_runes(std::string_view s) {
    std::vector<uint32_t> r;
    decode_runes(s, r, nullptr);
    return r;
}

std::string from_runes(const std::vector<uint32_t>& r) {
    std::string s;
    for (uint32_t c : r) append_utf8(s, c);
    return s;
}

// Go strings.ToLower (per-rune unicode.ToLower).
std::string go_to_lower(std::string_view s) {
    auto r = to_runes(s);
    for (auto& c : r) c = to_lower(c);
    return from_runes(r);
}

// fzf algo.NormalizeRunes.
std::vector<uint32_t> normalize_runes(std::vector<uint32_t> r) {
    for (auto& c : r) c = normalize_rune(c);
    return r;
}

bool starts_with(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }
bool ends_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
}

uint16_t as_uint16(int64_t v) noexcept {
    if (v < 0) return 0;
    if (v > 65535) return 65535;
    return static_cast<uint16_t>(v);
}

AlgoFn proc_fun(const QueryImpl& q, TermType t) {
    switch (t) {
        case TermType::Fuzzy: return q.fuzzy_algo;
        case TermType::Exact: return exact_match_naive;
        case TermType::ExactBoundary: return exact_match_boundary;
        case TermType::Prefix: return prefix_match;
        case TermType::Suffix: return suffix_match;
        case TermType::Equal: return equal_match;
    }
    return q.fuzzy_algo;
}

uint16_t trim_length(const Chars& c) {
    int32_t i = c.n - 1;
    while (i >= 0 && is_space(c.get(i))) --i;
    if (i < 0) return 0;
    int32_t j = 0;
    while (j < c.n && is_space(c.get(j))) ++j;
    return as_uint16(i - j + 1);
}

std::vector<std::vector<Term>> parse_terms(bool fuzzy, FuzzyCase case_mode, bool normalize, std::string str) {
    // fzf: str = strings.ReplaceAll(str, "\\ ", "\t"); tokens = split on / +/
    std::string s;
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '\\' && i + 1 < str.size() && str[i + 1] == ' ') {
            s.push_back('\t');
            ++i;
        } else {
            s.push_back(str[i]);
        }
    }
    std::vector<std::string> tokens;
    {
        size_t i = 0;
        std::string cur;
        while (i <= s.size()) {
            if (i == s.size() || s[i] == ' ') {
                tokens.push_back(cur);
                cur.clear();
                while (i < s.size() && s[i] == ' ') ++i;
                if (i == s.size()) break;
                continue;
            }
            cur.push_back(s[i]);
            ++i;
        }
    }
    std::vector<std::vector<Term>> sets;
    std::vector<Term> set;
    bool switch_set = false, after_bar = false;
    for (auto& token : tokens) {
        TermType typ = TermType::Fuzzy;
        bool inv = false;
        std::string text = token;
        std::replace(text.begin(), text.end(), '\t', ' ');
        std::string lower_text = go_to_lower(text);
        bool case_sensitive = case_mode == FuzzyCase::Respect || (case_mode == FuzzyCase::Smart && text != lower_text);
        auto lower_runes = to_runes(lower_text);
        bool normalize_term = normalize && lower_runes == normalize_runes(lower_runes);
        if (!case_sensitive) text = lower_text;
        if (!fuzzy) typ = TermType::Exact;

        if (!set.empty() && !after_bar && text == "|") {
            switch_set = false;
            after_bar = true;
            continue;
        }
        after_bar = false;

        if (starts_with(text, "!")) {
            inv = true;
            typ = TermType::Exact;
            text = text.substr(1);
        }
        if (text != "$" && ends_with(text, "$")) {
            typ = TermType::Suffix;
            text.pop_back();
        }
        if (text.size() > 2 && starts_with(text, "'") && ends_with(text, "'")) {
            typ = TermType::ExactBoundary;
            text = text.substr(1, text.size() - 2);
        } else if (starts_with(text, "'")) {
            // fzf: flip exactness
            typ = (fuzzy && !inv) ? TermType::Exact : TermType::Fuzzy;
            text = text.substr(1);
        } else if (starts_with(text, "^")) {
            typ = typ == TermType::Suffix ? TermType::Equal : TermType::Prefix;
            text = text.substr(1);
        }

        if (!text.empty()) {
            if (switch_set) {
                sets.push_back(std::move(set));
                set.clear();
            }
            auto runes = to_runes(text);
            if (normalize_term) runes = normalize_runes(std::move(runes));
            Term t;
            t.type = typ;
            t.inverse = inv;
            t.case_sensitive = case_sensitive;
            t.normalize = normalize_term;
            t.text = std::move(runes);
            set.push_back(std::move(t));
            switch_set = true;
        }
    }
    if (!set.empty()) sets.push_back(std::move(set));
    return sets;
}

void build_rank(const QueryImpl& q, const Chars& text, int32_t score, int32_t min_begin, int32_t min_end,
                int32_t max_end, bool valid, FuzzyRank& points) {
    points = FuzzyRank{};
    const int32_t num_chars = text.n;
    points[3] = static_cast<uint16_t>(65535 - as_uint16(score));
    size_t idx = 1;
    for (FuzzyTiebreak c : q.criteria) {
        if (idx > 3) break;
        uint16_t val = 65535;
        switch (c) {
            case FuzzyTiebreak::Chunk:
                if (valid) {
                    int32_t b = min_begin, e = max_end;
                    for (; b >= 1; --b)
                        if (is_space(text.get(b - 1))) break;
                    for (; e < num_chars; ++e)
                        if (is_space(text.get(e))) break;
                    val = as_uint16(e - b);
                }
                break;
            case FuzzyTiebreak::Length: val = trim_length(text); break;
            case FuzzyTiebreak::Pathname:
                if (valid) {
                    int32_t last_delim = -1;
                    for (int32_t i = num_chars - 1; i >= 0; --i) {
                        uint32_t r = text.get(i);
                        if (r == '/' || r == '\\') {
                            last_delim = i;
                            break;
                        }
                    }
                    if (last_delim <= min_begin) val = as_uint16(min_begin - last_delim);
                }
                break;
            case FuzzyTiebreak::Index: break;
            case FuzzyTiebreak::Begin:
            case FuzzyTiebreak::End:
                if (valid) {
                    int32_t white_prefix = 0;
                    for (int32_t i = 0; i < num_chars; ++i) {
                        white_prefix = i;
                        if (i == min_begin || !is_space(text.get(i))) break;
                    }
                    if (c == FuzzyTiebreak::Begin) {
                        val = as_uint16(min_end - white_prefix);
                    } else {
                        int64_t tl = trim_length(text);
                        val = as_uint16(65535 - 65535LL * (max_end - white_prefix) / (tl + 1));
                    }
                }
                break;
        }
        points[3 - idx] = val;
        ++idx;
    }
}

bool is_ascii(std::string_view s) noexcept {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    size_t n = s.size(), i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w;
        std::memcpy(&w, p + i, 8);
        if (w & 0x8080808080808080ULL) return false;
    }
    for (; i < n; ++i)
        if (p[i] & 0x80) return false;
    return true;
}

} // namespace

void QueryImpl::build(std::string_view query, const FuzzyOptions& opts) {
    options = opts;
    SchemeKind kind = opts.scheme == FuzzyScheme::Path      ? SchemeKind::Path
                      : opts.scheme == FuzzyScheme::History ? SchemeKind::History
                                                            : SchemeKind::Default;
    scheme = make_scheme(kind, opts.backslash_delimiter);
    criteria.clear();
    if (!opts.tiebreak.empty()) {
        for (FuzzyTiebreak t : opts.tiebreak)
            if (t != FuzzyTiebreak::Index) criteria.push_back(t);
    } else if (opts.scheme == FuzzyScheme::Path) {
        criteria = {FuzzyTiebreak::Pathname, FuzzyTiebreak::Length};
    } else if (opts.scheme == FuzzyScheme::Default) {
        criteria = {FuzzyTiebreak::Length};
    }
    if (criteria.size() > 3) criteria.resize(3);
    // fzf core.go: the highest-priority of chunk/end/begin/pathname decides direction.
    forward = true;
    fzf_with_pos = false;
    for (size_t i = criteria.size(); i-- > 0;) {
        switch (criteria[i]) {
            case FuzzyTiebreak::Chunk: fzf_with_pos = true; break;
            case FuzzyTiebreak::End: forward = false; break;
            case FuzzyTiebreak::Begin: forward = true; break;
            case FuzzyTiebreak::Pathname:
                fzf_with_pos = true;
                forward = false;
                break;
            default: break;
        }
    }
    extended = opts.extended;
    fuzzy = !opts.exact;
    fuzzy_algo = opts.algo_v1 ? fuzzy_match_v1 : fuzzy_match_v2;
    term_sets.clear();
    sortable = true;
    cacheable = true;

    std::string as_string(query);
    if (extended) {
        size_t lead = as_string.find_first_not_of(' ');
        as_string = lead == std::string::npos ? std::string() : as_string.substr(lead);
        while (ends_with(as_string, " ") && !ends_with(as_string, "\\ ")) as_string.pop_back();
        term_sets = parse_terms(fuzzy, opts.case_mode, opts.normalize, as_string);
        sortable = false;
        bool done = false;
        for (auto& ts : term_sets) {
            for (size_t idx = 0; idx < ts.size() && !done; ++idx) {
                const Term& t = ts[idx];
                if (!t.inverse) sortable = true;
                if (!cacheable || idx > 0 || t.inverse || (fuzzy && t.type != TermType::Fuzzy) ||
                    (!fuzzy && t.type != TermType::Exact)) {
                    cacheable = false;
                    if (sortable) done = true;
                }
            }
            if (done) break;
        }
        empty = term_sets.empty();
        cache_key.clear();
        bool first = true;
        for (auto& ts : term_sets) {
            if (ts.size() == 1 && !ts[0].inverse && (fuzzy || ts[0].type == TermType::Exact)) {
                if (!first) cache_key.push_back('\t');
                cache_key += from_runes(ts[0].text);
                first = false;
            }
        }
    } else {
        std::string lower = go_to_lower(as_string);
        auto lower_runes = to_runes(lower);
        bool norm = opts.normalize && lower_runes == normalize_runes(lower_runes);
        bool cs = opts.case_mode == FuzzyCase::Respect || (opts.case_mode == FuzzyCase::Smart && lower != as_string);
        if (!cs) as_string = lower;
        Term t;
        t.type = fuzzy ? TermType::Fuzzy : TermType::Exact;
        t.case_sensitive = cs;
        t.normalize = norm;
        t.text = to_runes(as_string);
        empty = t.text.empty();
        cache_key = as_string;
        term_sets.push_back({std::move(t)});
    }
    if (!opts.sort) sortable = false;
}

bool QueryImpl::match_prepared(const PreparedItem& item, int32_t* score_out, FuzzyRank* rank_out, bool with_pos,
                               MatchScratch& sc) const {
    if (empty) {
        if (score_out) *score_out = 0;
        if (rank_out) *rank_out = FuzzyRank{};
        if (with_pos) sc.all_pos.clear();
        return true;
    }
    const bool need_pos = with_pos || fzf_with_pos;
    int32_t total = 0;
    int32_t min_begin = 65535, min_end = 65535, max_end = 0;
    bool valid = false;
    if (with_pos) sc.all_pos.clear();

    for (const auto& set : term_sets) {
        bool matched = false;
        int32_t ob = 0, oe = 0, cur = 0;
        for (const Term& t : set) {
            AlgoFn fn = extended ? proc_fun(*this, t.type) : (fuzzy ? fuzzy_algo : exact_match_naive);
            sc.pos.clear();
            AlgoResult r = fn(scheme, t.case_sensitive, t.normalize, forward, item.chars, t.text.data(),
                              static_cast<int32_t>(t.text.size()), need_pos ? &sc.pos : nullptr, sc.slab);
            if (r.start >= 0) {
                if (t.inverse) continue;
                ob = (fzf_with_pos || r.start_nopos < 0) ? r.start : r.start_nopos;
                oe = r.end;
                cur = r.score;
                matched = true;
                if (with_pos) {
                    // fzf: fuzzy algorithms report positions; the others report a range.
                    const bool algo_pos = extended ? t.type == TermType::Fuzzy : fuzzy;
                    if (algo_pos) {
                        sc.all_pos.insert(sc.all_pos.end(), sc.pos.begin(), sc.pos.end());
                    } else {
                        for (int32_t i = r.start; i < r.end; ++i) sc.all_pos.push_back(i);
                    }
                }
                break;
            } else if (t.inverse) {
                ob = oe = 0;
                cur = 0;
                matched = true;
                continue;
            }
        }
        if (!matched) return false;
        total += cur;
        if (ob < oe) {
            min_begin = std::min(ob, min_begin);
            min_end = std::min(oe, min_end);
            max_end = std::max(oe, max_end);
            valid = true;
        }
    }
    if (score_out) *score_out = total;
    if (rank_out) build_rank(*this, item.chars, total, min_begin, min_end, max_end, valid, *rank_out);
    if (with_pos) {
        std::sort(sc.all_pos.begin(), sc.all_pos.end());
        sc.all_pos.erase(std::unique(sc.all_pos.begin(), sc.all_pos.end()), sc.all_pos.end());
    }
    return true;
}

bool QueryImpl::match_item(std::string_view item, FuzzyMatch* out, bool with_positions, MatchScratch& sc) const {
    PreparedItem p = prepare_item(item, sc.runes, sc.offsets);
    int32_t score = 0;
    FuzzyRank rank{};
    if (!match_prepared(p, &score, out ? &rank : nullptr, with_positions && out, sc)) return false;
    if (out) {
        out->score = score;
        out->rank = rank;
        out->positions.clear();
        if (with_positions) {
            for (int32_t i : sc.all_pos)
                out->positions.push_back(p.byte_offsets ? p.byte_offsets[i] : static_cast<uint32_t>(i));
        }
    }
    return true;
}

PreparedItem prepare_item(std::string_view item, std::vector<uint32_t>& runes, std::vector<uint32_t>& offsets) {
    PreparedItem p;
    p.byte_len = static_cast<uint32_t>(item.size());
    if (is_ascii(item)) {
        p.chars.bytes = reinterpret_cast<const unsigned char*>(item.data());
        p.chars.n = static_cast<int32_t>(item.size());
        if (item.empty()) p.chars.bytes = reinterpret_cast<const unsigned char*>("");
        return p;
    }
    runes.clear();
    offsets.clear();
    decode_runes(item, runes, &offsets);
    p.chars.runes = runes.data();
    p.chars.n = static_cast<int32_t>(runes.size());
    p.byte_offsets = offsets.data();
    return p;
}

MatchScratch& thread_scratch() {
    thread_local MatchScratch s;
    return s;
}

} // namespace bro::search::fuzzy_detail

namespace bro::search {

using namespace fuzzy_detail;

FuzzyQuery::FuzzyQuery(std::string_view query, const FuzzyOptions& options) {
    auto impl = std::make_shared<QueryImpl>();
    impl->build(query, options);
    impl_ = std::move(impl);
}

bool FuzzyQuery::empty() const noexcept { return impl_->empty; }
bool FuzzyQuery::sortable() const noexcept { return impl_->sortable && !impl_->empty; }
const FuzzyOptions& FuzzyQuery::options() const noexcept { return impl_->options; }
const std::string& FuzzyQuery::cache_key() const noexcept { return impl_->cache_key; }
bool FuzzyQuery::cacheable() const noexcept { return impl_->cacheable && !impl_->empty; }

bool FuzzyQuery::match(std::string_view item, FuzzyMatch* out, bool with_positions) const {
    return impl_->match_item(item, out, with_positions, thread_scratch());
}

std::optional<FuzzyMatch> fuzzy_match(std::string_view query, std::string_view item, const FuzzyOptions& options) {
    FuzzyQuery q(query, options);
    FuzzyMatch m;
    if (!q.match(item, &m, true)) return std::nullopt;
    return m;
}

std::vector<uint32_t> fuzzy_char_indices(std::string_view item, std::span<const uint32_t> byte_positions) {
    std::vector<uint32_t> out;
    out.reserve(byte_positions.size());
    const auto* p = reinterpret_cast<const unsigned char*>(item.data());
    size_t byte = 0;
    uint32_t ch = 0;
    for (uint32_t target : byte_positions) {
        while (byte < item.size() && byte < target) {
            size_t len = 1;
            if (p[byte] >= 0x80) decode_utf8(p + byte, item.size() - byte, &len);
            byte += len;
            ++ch;
        }
        out.push_back(ch);
    }
    return out;
}

} // namespace bro::search
