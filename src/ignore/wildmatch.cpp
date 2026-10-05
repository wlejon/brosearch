// Port of git's wildmatch.c (dowild) to bounded string_views. The control flow, including the
// WM_ABORT_ALL / WM_ABORT_TO_STARSTAR early-outs and the "**" component rules, is kept as in git
// so results agree with `git check-ignore` / `git ls-files --exclude-standard`.

#include "brosearch/ignore.h"

#include <cstring>

namespace bro::search {

namespace {

enum : int { WM_MATCH = 0, WM_NOMATCH = 1, WM_ABORT_ALL = -1, WM_ABORT_TO_STARSTAR = -2 };
constexpr unsigned WM_CASEFOLD = 1;
constexpr unsigned WM_PATHNAME = 2;

using uchar = unsigned char;

inline bool is_upper(uchar c) { return c >= 'A' && c <= 'Z'; }
inline bool is_lower(uchar c) { return c >= 'a' && c <= 'z'; }
inline bool is_digit(uchar c) { return c >= '0' && c <= '9'; }
inline bool is_alpha(uchar c) { return is_upper(c) || is_lower(c); }
inline bool is_alnum(uchar c) { return is_alpha(c) || is_digit(c); }
inline bool is_space(uchar c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
inline bool is_blank(uchar c) { return c == ' ' || c == '\t'; }
inline bool is_cntrl(uchar c) { return c < 0x20 || c == 0x7f; }
inline bool is_print(uchar c) { return c >= 0x20 && c < 0x7f; }
inline bool is_graph(uchar c) { return c > 0x20 && c < 0x7f; }
inline bool is_punct(uchar c) { return is_graph(c) && !is_alnum(c); }
inline bool is_xdigit(uchar c) { return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
inline uchar to_lower(uchar c) { return is_upper(c) ? static_cast<uchar>(c + 32) : c; }
inline uchar to_upper(uchar c) { return is_lower(c) ? static_cast<uchar>(c - 32) : c; }
inline bool is_glob_special(uchar c) { return c == '*' || c == '?' || c == '[' || c == '\\'; }

struct Matcher {
    const uchar* pat;
    size_t plen;
    const uchar* txt;
    size_t tlen;
    unsigned flags;

    uchar P(size_t i) const { return i < plen ? pat[i] : 0; }
    uchar T(size_t i) const { return i < tlen ? txt[i] : 0; }

    bool cc_eq(size_t s, size_t len, const char* name) const {
        return std::strlen(name) == len && std::memcmp(pat + s, name, len) == 0;
    }

    int dowild(size_t p, size_t text) const {
        uchar p_ch;
        for (; (p_ch = P(p)) != 0; text++, p++) {
            int matched, match_slash, negated;
            uchar t_ch, prev_ch;
            if ((t_ch = T(text)) == 0 && p_ch != '*') return WM_ABORT_ALL;
            if ((flags & WM_CASEFOLD) && is_upper(t_ch)) t_ch = to_lower(t_ch);
            if ((flags & WM_CASEFOLD) && is_upper(p_ch)) p_ch = to_lower(p_ch);
            switch (p_ch) {
            case '\\':
                // Literal match with the following character (unfolded, as in git).
                p_ch = P(++p);
                [[fallthrough]];
            default:
                if (t_ch != p_ch) return WM_NOMATCH;
                continue;
            case '?':
                if ((flags & WM_PATHNAME) && t_ch == '/') return WM_NOMATCH;
                continue;
            case '*':
                if (P(++p) == '*') {
                    const ptrdiff_t prev_p = static_cast<ptrdiff_t>(p) - 2;
                    while (P(++p) == '*') {
                    }
                    if (!(flags & WM_PATHNAME)) {
                        match_slash = 1;  // without WM_PATHNAME, '*' == '**'
                    } else if ((prev_p < 0 || pat[prev_p] == '/') &&
                               (P(p) == 0 || P(p) == '/' || (P(p) == '\\' && P(p + 1) == '/'))) {
                        // "foo/**/bar" also matches "foo/bar": try "**/" matching nothing.
                        if (P(p) == '/' && dowild(p + 1, text) == WM_MATCH) return WM_MATCH;
                        match_slash = 1;
                    } else {
                        match_slash = 0;  // "**" not a whole component: acts like '*'
                    }
                } else {
                    match_slash = (flags & WM_PATHNAME) ? 0 : 1;
                }
                if (P(p) == 0) {
                    // Trailing "**" matches everything; trailing '*' only if no more slashes.
                    if (!match_slash && text < tlen && std::memchr(txt + text, '/', tlen - text)) return WM_NOMATCH;
                    return WM_MATCH;
                } else if (!match_slash && P(p) == '/') {
                    // One '*' followed by '/' with WM_PATHNAME matches the next directory.
                    const void* slash = text < tlen ? std::memchr(txt + text, '/', tlen - text) : nullptr;
                    if (!slash) return WM_NOMATCH;
                    text = static_cast<size_t>(static_cast<const uchar*>(slash) - txt);
                    break;  // the slash is consumed by the loop increment
                }
                while (true) {
                    if (t_ch == 0) break;
                    // Advance quickly to the next occurrence of a following literal.
                    if (!is_glob_special(P(p))) {
                        p_ch = P(p);
                        if ((flags & WM_CASEFOLD) && is_upper(p_ch)) p_ch = to_lower(p_ch);
                        while ((t_ch = T(text)) != 0 && (match_slash || t_ch != '/')) {
                            if ((flags & WM_CASEFOLD) && is_upper(t_ch)) t_ch = to_lower(t_ch);
                            if (t_ch == p_ch) break;
                            text++;
                        }
                        if (t_ch != p_ch) return match_slash ? WM_ABORT_ALL : WM_ABORT_TO_STARSTAR;
                    }
                    if ((matched = dowild(p, text)) != WM_NOMATCH) {
                        if (!match_slash || matched != WM_ABORT_TO_STARSTAR) return matched;
                    } else if (!match_slash && t_ch == '/') {
                        return WM_ABORT_TO_STARSTAR;
                    }
                    t_ch = T(++text);
                }
                return WM_ABORT_ALL;
            case '[':
                p_ch = P(++p);
                if (p_ch == '^') p_ch = '!';
                negated = p_ch == '!' ? 1 : 0;
                if (negated) p_ch = P(++p);
                prev_ch = 0;
                matched = 0;
                do {
                    if (!p_ch) return WM_ABORT_ALL;
                    if (p_ch == '\\') {
                        p_ch = P(++p);
                        if (!p_ch) return WM_ABORT_ALL;
                        if (t_ch == p_ch) matched = 1;
                    } else if (p_ch == '-' && prev_ch && P(p + 1) && P(p + 1) != ']') {
                        p_ch = P(++p);
                        if (p_ch == '\\') {
                            p_ch = P(++p);
                            if (!p_ch) return WM_ABORT_ALL;
                        }
                        if (t_ch <= p_ch && t_ch >= prev_ch) {
                            matched = 1;
                        } else if ((flags & WM_CASEFOLD) && is_lower(t_ch)) {
                            uchar up = to_upper(t_ch);
                            if (up <= p_ch && up >= prev_ch) matched = 1;
                        }
                        p_ch = 0;  // makes prev_ch 0
                    } else if (p_ch == '[' && P(p + 1) == ':') {
                        size_t s;
                        for (s = p += 2; (p_ch = P(p)) && p_ch != ']'; p++) {
                        }
                        if (!p_ch) return WM_ABORT_ALL;
                        const ptrdiff_t i = static_cast<ptrdiff_t>(p) - static_cast<ptrdiff_t>(s) - 1;
                        if (i < 0 || pat[p - 1] != ':') {
                            // No ":]": treat like a normal set member '['.
                            p = s - 2;
                            p_ch = '[';
                            if (t_ch == p_ch) matched = 1;
                            continue;
                        }
                        const size_t n = static_cast<size_t>(i);
                        if (cc_eq(s, n, "alnum")) {
                            if (is_alnum(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "alpha")) {
                            if (is_alpha(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "blank")) {
                            if (is_blank(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "cntrl")) {
                            if (is_cntrl(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "digit")) {
                            if (is_digit(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "graph")) {
                            if (is_graph(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "lower")) {
                            if (is_lower(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "print")) {
                            if (is_print(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "punct")) {
                            if (is_punct(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "space")) {
                            if (is_space(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "upper")) {
                            if (is_upper(t_ch)) matched = 1;
                            else if ((flags & WM_CASEFOLD) && is_lower(t_ch)) matched = 1;
                        } else if (cc_eq(s, n, "xdigit")) {
                            if (is_xdigit(t_ch)) matched = 1;
                        } else {
                            return WM_ABORT_ALL;  // malformed [:class:]
                        }
                        p_ch = 0;
                    } else if (t_ch == p_ch) {
                        matched = 1;
                    }
                } while (prev_ch = p_ch, (p_ch = P(++p)) != ']');
                if (matched == negated || ((flags & WM_PATHNAME) && t_ch == '/')) return WM_NOMATCH;
                continue;
            }
        }
        return T(text) ? WM_NOMATCH : WM_MATCH;
    }
};

} // namespace

bool glob_match(std::string_view pattern, std::string_view text, bool case_insensitive, bool pathname) {
    Matcher m{reinterpret_cast<const uchar*>(pattern.data()), pattern.size(),
              reinterpret_cast<const uchar*>(text.data()), text.size(),
              (case_insensitive ? WM_CASEFOLD : 0u) | (pathname ? WM_PATHNAME : 0u)};
    return m.dowild(0, 0) == WM_MATCH;
}

} // namespace bro::search
