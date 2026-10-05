#include "regex/matcher.h"

#include <cstring>

namespace bro::search::rx {

namespace {

size_t line_start(const uint8_t* data, size_t lo, size_t pos) {
    while (pos > lo && data[pos - 1] != '\n') --pos;
    return pos;
}

size_t line_end(const uint8_t* data, size_t pos, size_t end) {
    const void* nl = pos < end ? std::memchr(data + pos, '\n', end - pos) : nullptr;
    return nl ? static_cast<size_t>(static_cast<const uint8_t*>(nl) - data) : end;
}

} // namespace

MatcherCache::MatcherCache(const Matcher& m)
    : fwd_(m.forward(), /*leftmost_first=*/true), rev_(m.reverse(), /*leftmost_first=*/false), pike_(m.forward()) {}

std::shared_ptr<const Matcher> Matcher::build(const Hir& hir, size_t size_limit, std::string& error) {
    auto m = std::make_shared<Matcher>();
    if (!compile_program(hir, false, size_limit, m->fwd_, error)) return nullptr;
    if (!compile_program(hir, true, size_limit, m->rev_, error)) return nullptr;
    m->lits_ = extract_literals(hir);
    m->prefilter_ = LiteralFinder(m->lits_.exact ? m->lits_.whole : m->lits_.required);
    if (m->prefilter_.empty() && !m->lits_.rare_bytes.empty()) m->prefilter_ = LiteralFinder::any_of(m->lits_.rare_bytes);
    return m;
}

std::optional<size_t> Matcher::line_via_automata(MatcherCache& c, const uint8_t* data, size_t len, size_t ls,
                                                 size_t le) const {
    // Returns the line start: the match end may be le itself, which is not inside the line.
    SearchResult r = c.fwd_.forward(data, len, ls, le, /*anchored=*/false, /*earliest=*/true);
    if (r.status == SearchStatus::Match) return ls;
    if (r.status == SearchStatus::NoMatch) return std::nullopt;
    if (c.pike_.search(data, len, ls, le, false)) return ls;
    return std::nullopt;
}

std::optional<size_t> Matcher::find_line(MatcherCache& c, const uint8_t* data, size_t len, size_t start,
                                         size_t end) const {
    if (lits_.exact) {
        size_t p = prefilter_.find(data, start, end);
        if (p == SIZE_MAX) return std::nullopt;
        return p;
    }
    size_t pos = start;
    if (!prefilter_.empty()) {
        while (pos <= end) {
            size_t p = prefilter_.find(data, pos, end);
            if (p == SIZE_MAX) return std::nullopt;
            size_t ls = line_start(data, pos, p);
            size_t le = line_end(data, p, end);
            if (auto hit = line_via_automata(c, data, len, ls, le)) return hit;
            pos = le + 1;
        }
        return std::nullopt;
    }
    while (pos <= end) {
        SearchResult r = c.fwd_.forward(data, len, pos, end, false, true);
        if (r.status == SearchStatus::NoMatch) return std::nullopt;
        if (r.status == SearchStatus::Match) {
            size_t e = r.pos;
            // A match ending right after '\n' can only be the empty match at that line's start.
            if (e > pos && data[e - 1] != '\n') return e - 1;
            return e;
        }
        // The DFA gave up at r.pos (non-ASCII next to a Unicode word boundary): no match ends
        // before it, so settle r.pos's line with the PikeVM and resume after it.
        size_t q = r.pos < end ? r.pos : end;
        size_t ls = line_start(data, pos, q);
        size_t le = line_end(data, q, end);
        if (c.pike_.search(data, len, ls, le, false)) return ls;
        pos = le + 1;
    }
    return std::nullopt;
}

std::optional<MatchSpan> Matcher::find(MatcherCache& c, const uint8_t* data, size_t len, size_t start,
                                       size_t end) const {
    if (lits_.exact) {
        size_t p = prefilter_.find(data, start, end);
        if (p == SIZE_MAX) return std::nullopt;
        return MatchSpan{p, p + prefilter_.size()};
    }
    if (!prefilter_.empty() && prefilter_.find(data, start, end) == SIZE_MAX) return std::nullopt;
    SearchResult f = c.fwd_.forward(data, len, start, end, false, false);
    if (f.status == SearchStatus::NoMatch) return std::nullopt;
    if (f.status == SearchStatus::Match) {
        SearchResult r = c.rev_.reverse(data, len, start, f.pos);
        if (r.status == SearchStatus::Match) return MatchSpan{r.pos, f.pos};
    }
    return c.pike_.search(data, len, start, end, false);
}

} // namespace bro::search::rx
