#include "brosearch/regex.h"

#include "regex/matcher.h"
#include "regex/unicode.h"

#include <mutex>

namespace bro::search {

using namespace rx;

struct Regex::Impl {
    std::mutex mu;
    std::vector<std::unique_ptr<MatcherCache>> pool;

    std::unique_ptr<MatcherCache> take(const Matcher& m) {
        {
            std::lock_guard<std::mutex> lock(mu);
            if (!pool.empty()) {
                auto c = std::move(pool.back());
                pool.pop_back();
                return c;
            }
        }
        return std::make_unique<MatcherCache>(m);
    }
    void give(std::unique_ptr<MatcherCache> c) {
        std::lock_guard<std::mutex> lock(mu);
        if (pool.size() < 16) pool.push_back(std::move(c));
    }
};

Regex::Regex() = default;
Regex::~Regex() = default;

namespace {

void text_anchors_to_line(Hir& h, bool crlf) {
    if (h.kind == Hir::Kind::Look) {
        if (h.look == Look::StartText) h.look = crlf ? Look::StartLineCrlf : Look::StartLine;
        else if (h.look == Look::EndText) h.look = crlf ? Look::EndLineCrlf : Look::EndLine;
    }
    for (auto& s : h.subs) text_anchors_to_line(s, crlf);
}

bool literal_has_uppercase(std::string_view s) {
    const auto* b = reinterpret_cast<const uint8_t*>(s.data());
    const auto* e = b + s.size();
    while (b < e) {
        uint32_t cp;
        size_t n = decode_utf8(b, e, &cp);
        if (n == 0) {
            ++b;
            continue;
        }
        if (is_uppercase(cp)) return true;
        b += n;
    }
    return false;
}

} // namespace

std::shared_ptr<const Regex> Regex::compile(std::string_view pattern, const RegexOptions& o, std::string* error) {
    std::string err;
    Hir hir;
    bool ci = o.case_insensitive;
    if (o.literal) {
        if (o.smart_case && !literal_has_uppercase(pattern)) ci = true;
        if (o.line_mode && pattern.find('\n') != std::string_view::npos) {
            if (error) *error = "the literal '\\n' is not allowed in a search pattern";
            return nullptr;
        }
        hir = literal_hir(pattern, ci, o.unicode);
    } else {
        ParseOptions po;
        po.flags.case_insensitive = ci;
        po.flags.multi_line = o.multi_line || o.line_mode;
        po.flags.dot_all = o.dot_matches_new_line;
        po.flags.swap_greed = o.swap_greed;
        po.flags.ignore_whitespace = o.ignore_whitespace;
        po.flags.unicode = o.unicode;
        po.flags.crlf = o.crlf;
        po.ban_newline = o.line_mode;
        ParseResult pr = parse_regex(pattern, po);
        if (!pr.error.empty()) {
            if (error) *error = "regex parse error at offset " + std::to_string(pr.error_offset) + ": " + pr.error;
            return nullptr;
        }
        if (o.smart_case && !ci && pr.any_literal && !pr.any_uppercase) {
            ci = true;
            po.flags.case_insensitive = true;
            pr = parse_regex(pattern, po);
        }
        hir = std::move(pr.hir);
    }
    if (o.line_mode) text_anchors_to_line(hir, o.crlf);
    if (o.whole_line) {
        std::vector<Hir> seq;
        seq.push_back(Hir::look_at(o.crlf ? Look::StartLineCrlf : Look::StartLine));
        seq.push_back(std::move(hir));
        seq.push_back(Hir::look_at(o.crlf ? Look::EndLineCrlf : Look::EndLine));
        hir = Hir::concat(std::move(seq));
    } else if (o.word) {
        std::vector<Hir> seq;
        seq.push_back(Hir::look_at(o.unicode ? Look::WordStartHalfUnicode : Look::WordStartHalfAscii));
        seq.push_back(std::move(hir));
        seq.push_back(Hir::look_at(o.unicode ? Look::WordEndHalfUnicode : Look::WordEndHalfAscii));
        hir = Hir::concat(std::move(seq));
    }
    auto m = Matcher::build(hir, o.size_limit, err);
    if (!m) {
        if (error) *error = err;
        return nullptr;
    }
    auto re = std::make_shared<Regex>();
    re->pattern_ = std::string(pattern);
    re->options_ = o;
    re->case_insensitive_ = ci;
    re->matcher_ = std::move(m);
    re->impl_ = std::make_unique<Impl>();
    return re;
}

bool Regex::is_match(std::string_view hay) const { return find(hay).has_value(); }

std::optional<RegexMatch> Regex::find(std::string_view hay, size_t start) const {
    if (start > hay.size()) return std::nullopt;
    auto cache = impl_->take(*matcher_);
    const auto* d = reinterpret_cast<const uint8_t*>(hay.data());
    auto m = matcher_->find(*cache, d, hay.size(), start, hay.size());
    impl_->give(std::move(cache));
    if (!m) return std::nullopt;
    return RegexMatch{m->start, m->end};
}

std::vector<RegexMatch> Regex::find_all(std::string_view hay) const {
    std::vector<RegexMatch> out;
    auto cache = impl_->take(*matcher_);
    const auto* d = reinterpret_cast<const uint8_t*>(hay.data());
    const size_t n = hay.size();
    size_t pos = 0;
    size_t last_end = SIZE_MAX;
    auto next_boundary = [&](size_t p) {
        if (p >= n) return p + 1;
        if (!options_.unicode) return p + 1;
        uint32_t cp;
        size_t k = decode_utf8(d + p, d + n, &cp);
        return p + (k ? k : 1);
    };
    while (pos <= n) {
        auto m = matcher_->find(*cache, d, n, pos, n);
        if (!m) break;
        if (m->start == m->end && m->end == last_end) {
            pos = next_boundary(pos);
            continue;
        }
        out.push_back({m->start, m->end});
        last_end = m->end;
        pos = m->end > m->start ? m->end : next_boundary(m->end);
        if (m->start == m->end) last_end = m->end;
    }
    impl_->give(std::move(cache));
    return out;
}

} // namespace bro::search
