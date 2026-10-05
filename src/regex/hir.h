#pragma once
// High-level IR produced by the parser: flags are already applied (case folding expanded into
// classes, '.' resolved, line terminator banned), so the compiler only sees structure.

#include "regex/charset.h"

#include <cstdint>
#include <string>
#include <vector>

namespace bro::search::rx {

// Zero-width assertions. Evaluated at a boundary between the byte before and the byte after.
enum class Look : uint8_t {
    StartLine,       // (?m)^
    EndLine,         // (?m)$
    StartText,       // \A, ^ without multi-line
    EndText,         // \z, $ without multi-line
    StartLineCrlf,   // (?mR)^
    EndLineCrlf,     // (?mR)$
    WordAscii,       // (?-u)\b
    NotWordAscii,    // (?-u)\B
    WordUnicode,     // \b
    NotWordUnicode,  // \B
    WordStartAscii,
    WordEndAscii,
    WordStartUnicode,   // \< \b{start}
    WordEndUnicode,     // \> \b{end}
    WordStartHalfAscii,
    WordEndHalfAscii,
    WordStartHalfUnicode,  // \b{start-half}
    WordEndHalfUnicode,    // \b{end-half}
    Count
};

inline bool look_is_unicode_word(Look l) {
    switch (l) {
        case Look::WordUnicode: case Look::NotWordUnicode: case Look::WordStartUnicode:
        case Look::WordEndUnicode: case Look::WordStartHalfUnicode: case Look::WordEndHalfUnicode:
            return true;
        default:
            return false;
    }
}

struct Hir {
    enum class Kind : uint8_t { Empty, Class, Look, Repeat, Concat, Alt };
    Kind kind = Kind::Empty;
    bool bytes = false;   // Class over raw bytes (non-Unicode mode) instead of code points
    Look look = Look::StartText;
    bool greedy = true;
    uint32_t min = 0;
    uint32_t max = 0;     // kInf for unbounded
    CharSet set;
    std::vector<Hir> subs;

    static constexpr uint32_t kInf = UINT32_MAX;

    static Hir empty() { return Hir{}; }
    static Hir cls(CharSet s, bool bytes) {
        Hir h;
        h.kind = Kind::Class;
        s.canonicalize();
        h.set = std::move(s);
        h.bytes = bytes;
        return h;
    }
    static Hir look_at(Look l) {
        Hir h;
        h.kind = Kind::Look;
        h.look = l;
        return h;
    }
    static Hir repeat(Hir sub, uint32_t mn, uint32_t mx, bool greedy) {
        Hir h;
        h.kind = Kind::Repeat;
        h.min = mn;
        h.max = mx;
        h.greedy = greedy;
        h.subs.push_back(std::move(sub));
        return h;
    }
    static Hir concat(std::vector<Hir> subs) {
        if (subs.size() == 1) return std::move(subs[0]);
        Hir h;
        h.kind = subs.empty() ? Kind::Empty : Kind::Concat;
        h.subs = std::move(subs);
        return h;
    }
    static Hir alt(std::vector<Hir> subs) {
        if (subs.size() == 1) return std::move(subs[0]);
        Hir h;
        h.kind = Kind::Alt;
        h.subs = std::move(subs);
        return h;
    }
};

struct ParseFlags {
    bool case_insensitive = false;  // i
    bool multi_line = false;        // m
    bool dot_all = false;           // s
    bool swap_greed = false;        // U
    bool ignore_whitespace = false; // x
    bool unicode = true;            // u
    bool crlf = false;              // R
};

struct ParseOptions {
    ParseFlags flags;
    // Grep line mode: the line terminator can never be matched. Classes and '.' drop it; an
    // explicit literal '\n' is an error (as in ripgrep without --multiline).
    bool ban_newline = false;
    size_t nest_limit = 250;
};

struct ParseResult {
    Hir hir;
    std::string error;    // empty on success
    size_t error_offset = 0;
    bool any_literal = false;     // for smart case (ripgrep semantics)
    bool any_uppercase = false;
};

ParseResult parse_regex(std::string_view pattern, const ParseOptions& opts);
// A HIR that matches `literal` exactly (with optional case folding), for fixed-string search.
Hir literal_hir(std::string_view literal, bool case_insensitive, bool unicode);

} // namespace bro::search::rx
