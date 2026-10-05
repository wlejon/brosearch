#pragma once
// Matcher: the compiled form of one pattern (forward + reverse programs, literal prefilter) and
// the strategies for using them. Immutable and shared across threads; each thread brings its own
// MatcherCache (lazy DFA caches + PikeVM scratch).

#include "regex/dfa.h"
#include "regex/hir.h"
#include "regex/literal.h"
#include "regex/pikevm.h"
#include "regex/prog.h"

#include <memory>
#include <optional>
#include <string>

namespace bro::search::rx {

class Matcher;

class MatcherCache {
public:
    explicit MatcherCache(const Matcher& m);

private:
    friend class Matcher;
    LazyDfa fwd_;
    LazyDfa rev_;
    PikeVm pike_;
};

class Matcher {
public:
    static std::shared_ptr<const Matcher> build(const Hir& hir, size_t size_limit, std::string& error);

    // Earliest evidence of a match in data[start, end): returns a position inside (or at the start
    // of) a line that contains a match. Lines never contain '\n' matches (line mode), so the caller
    // expands the position to its line. Looks see data[0, len).
    std::optional<size_t> find_line(MatcherCache& c, const uint8_t* data, size_t len, size_t start, size_t end) const;

    // Leftmost-first match within [start, end].
    std::optional<MatchSpan> find(MatcherCache& c, const uint8_t* data, size_t len, size_t start, size_t end) const;

    bool is_exact_literal() const { return lits_.exact; }
    // Whether '\n' is outside rg's "non-matching bytes" of the pattern: some match can contain
    // it, or the pattern has a line or text anchor. rg -U searches such patterns as one buffer.
    bool can_match_newline() const { return can_match_newline_; }
    const Program& forward() const { return fwd_; }
    const Program& reverse() const { return rev_; }
    const LiteralFinder& prefilter() const { return prefilter_; }

private:
    Program fwd_;
    Program rev_;
    LiteralInfo lits_;
    LiteralFinder prefilter_;  // exact literal when lits_.exact, else the required literal (may be empty)
    bool can_match_newline_ = false;

    std::optional<size_t> line_via_automata(MatcherCache& c, const uint8_t* data, size_t len, size_t ls,
                                            size_t le) const;
};

} // namespace bro::search::rx
