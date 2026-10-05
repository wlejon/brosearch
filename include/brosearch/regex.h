#pragma once
// Linear-time regular expressions (Rust `regex` / ripgrep syntax): a lazy DFA for matching with a
// PikeVM fallback, Unicode-aware by default (classes, simple case folding, \b), leftmost-first
// semantics. No backreferences or look-around beyond anchors and word boundaries — which is what
// guarantees O(haystack x pattern) time for every input.
//
// Syntax summary: . [abc] [^a-z] [[:alpha:]] [a-z&&[^aeiou]] [\w--\d] \d \w \s \D \W \S \pL \p{Lu}
// \P{N} \p{Greek} \p{sc=Grek} \p{scx=Hira} (general categories, scripts and script extensions,
// Unicode 16); ^ $ \A \z \b \B \< \> \b{start} \b{end}
// \b{start-half} \b{end-half}; * + ? {n} {n,} {,m} {n,m} and lazy variants; (..) (?:..) (?P<n>..)
// (?<n>..); flags (?imsUxuR-imsUxuR) and (?flags:..); escapes \t \n \r \f \v \a \xHH \x{H..}
// \uHHHH \u{..} \UHHHHHHHH and any escaped ASCII punctuation.

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

namespace rx {
class Matcher;
}

struct RegexOptions {
    bool case_insensitive = false;   // (?i), Unicode simple case folding
    bool smart_case = false;         // case-insensitive unless the pattern has an uppercase literal
    bool multi_line = false;         // (?m): ^ and $ match at line boundaries
    bool dot_matches_new_line = false;  // (?s)
    bool swap_greed = false;         // (?U)
    bool ignore_whitespace = false;  // (?x)
    bool unicode = true;             // (?u)
    bool crlf = false;               // (?R): in multi-line mode ^/$ treat "\r\n" as a terminator
    bool literal = false;            // pattern is a fixed string, not a regex
    bool word = false;               // like rg -w: match must not be adjacent to word characters
    bool whole_line = false;         // like rg -x: match must span a whole line
    // Grep line mode: '\n' can never be matched (an explicit literal '\n' is an error), ^/$ are
    // line anchors and \A/\z behave as line anchors too (as in ripgrep).
    bool line_mode = false;
    size_t size_limit = size_t(1) << 22;  // instructions + transitions of the compiled program
};

struct RegexMatch {
    size_t start = 0;
    size_t end = 0;
    bool operator==(const RegexMatch&) const = default;
};

class Regex {
public:
    // Returns nullptr on a syntax error or size-limit overflow (message in *error if given).
    [[nodiscard]] static std::shared_ptr<const Regex> compile(std::string_view pattern,
                                                              const RegexOptions& options,
                                                              std::string* error = nullptr);
    [[nodiscard]] static std::shared_ptr<const Regex> compile(std::string_view pattern,
                                                              std::string* error = nullptr) {
        return compile(pattern, RegexOptions(), error);
    }

    [[nodiscard]] bool is_match(std::string_view haystack) const;
    // Leftmost-first match starting at or after `start`; look-around sees the whole haystack.
    [[nodiscard]] std::optional<RegexMatch> find(std::string_view haystack, size_t start = 0) const;
    // All non-overlapping matches, left to right (empty matches never split a UTF-8 sequence).
    [[nodiscard]] std::vector<RegexMatch> find_all(std::string_view haystack) const;

    // True if case-insensitive matching was chosen (explicitly or by smart case).
    [[nodiscard]] bool case_insensitive() const noexcept { return case_insensitive_; }
    [[nodiscard]] const RegexOptions& options() const noexcept { return options_; }
    [[nodiscard]] const std::string& pattern() const noexcept { return pattern_; }

    // Internal engine handle (src/regex/matcher.h), used by grep.
    [[nodiscard]] const rx::Matcher& matcher() const noexcept { return *matcher_; }

    struct Impl;
    ~Regex();
    Regex();

private:
    std::string pattern_;
    RegexOptions options_;
    bool case_insensitive_ = false;
    std::shared_ptr<const rx::Matcher> matcher_;
    std::unique_ptr<Impl> impl_;  // pool of per-thread caches for the convenience methods
};

} // namespace bro::search
