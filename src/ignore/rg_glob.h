#pragma once
// Glob syntax and matching as ripgrep applies it to ignore files and -g overrides: the globset
// crate configured by the ignore crate (literal_separator, backslash_escape, no empty
// alternates). It differs from git's wildmatch:
//  - "[...]" has no POSIX "[:alpha:]" classes ('[' is an ordinary member), a backslash is an
//    ordinary member, a '-' after a range extends it ("[a-c-e]" is a-e), a reversed range is an
//    error, and classes (negated ones included) match '/'.
//  - An unclosed '[' is a literal '['.
//  - "{a,b}" alternation, nestable; empty alternatives match nothing ("k{,1}m" matches only
//    "k1m"). An unclosed '{' or an unopened '}' is an error.
//  - A trailing backslash is an error.
// Matching is bytewise, like globset's (?-u) regex: '?' is one byte, non-ASCII class members are
// their UTF-8 bytes, and case folding is ASCII-only. Internal.

#include <bitset>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search::detail {

class RgGlob {
public:
    // Compiles a glob (the pattern text after the ignore crate's rewriting, e.g. "**/x"). Null
    // when globset rejects it; `error` then says why.
    static std::shared_ptr<const RgGlob> compile(std::string_view pattern, std::string* error = nullptr);

    [[nodiscard]] bool match(std::string_view text, bool case_insensitive) const;

private:
    enum class Op : uint8_t { Set, Eps, Split, Match };
    struct State {
        Op op;
        bool negated = false;
        uint32_t set = 0;   // Op::Set: index into sets_
        uint32_t out = 0;
        uint32_t out2 = 0;  // Op::Split
    };
    friend struct RgGlobBuilder;

    std::vector<State> states_;
    std::vector<std::bitset<256>> sets_;
    uint32_t start_ = 0;
};

} // namespace bro::search::detail
