// Regex parser: Rust `regex` crate syntax (what ripgrep accepts), straight to HIR.

#include "regex/hir.h"
#include "regex/unicode.h"

#include <set>
#include <string>

namespace bro::search::rx {

namespace {

struct ParseError {
    std::string msg;
    size_t offset;
};

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
uint32_t hex_val(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint32_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint32_t>(c - 'a' + 10);
    return static_cast<uint32_t>(c - 'A' + 10);
}
bool is_alnum_ascii(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// A class item: either a single literal code point (rangeable) or a set (\d, [:alpha:], ...).
struct ClassItem {
    bool is_char = false;
    uint32_t c = 0;
    CharSet set;
};

class Parser {
public:
    Parser(std::string_view pat, const ParseOptions& opts, ParseResult& res)
        : p_(pat), opts_(opts), res_(res) {}

    Hir parse() {
        ParseFlags flags = opts_.flags;
        Hir h = parse_alternation(flags, 0);
        if (i_ < p_.size()) {
            if (p_[i_] == ')') fail("unopened group");
            fail("unexpected character");
        }
        return h;
    }

private:
    std::string_view p_;
    size_t i_ = 0;
    const ParseOptions& opts_;
    ParseResult& res_;
    std::set<std::string> names_;

    [[noreturn]] void fail(const std::string& msg) { throw ParseError{msg, i_}; }
    [[noreturn]] void fail_at(const std::string& msg, size_t at) { throw ParseError{msg, at}; }

    bool eof() const { return i_ >= p_.size(); }
    char peek(size_t k = 0) const { return i_ + k < p_.size() ? p_[i_ + k] : '\0'; }

    void skip_ws(const ParseFlags& f) {
        if (!f.ignore_whitespace) return;
        while (!eof()) {
            char c = p_[i_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
                ++i_;
            } else if (c == '#') {
                while (!eof() && p_[i_] != '\n') ++i_;
            } else {
                break;
            }
        }
    }

    // Decodes one code point of the pattern; invalid UTF-8 is a parse error (patterns are text).
    uint32_t next_char() {
        uint32_t cp;
        size_t n = decode_utf8(reinterpret_cast<const uint8_t*>(p_.data()) + i_,
                               reinterpret_cast<const uint8_t*>(p_.data()) + p_.size(), &cp);
        if (n == 0) fail("pattern is not valid UTF-8");
        i_ += n;
        return cp;
    }

    void note_literal(uint32_t cp) {
        res_.any_literal = true;
        if (is_uppercase(cp)) res_.any_uppercase = true;
    }

    // Finalizes a class: case folding, negation, line-terminator ban.
    Hir finish_class(CharSet set, bool negated, const ParseFlags& f) {
        set.canonicalize();
        bool bytes = !f.unicode;
        if (f.case_insensitive) {
            if (bytes) {
                CharSet extra;
                for (auto r : set.ranges()) {
                    for (uint32_t c = std::max<uint32_t>(r.lo, 'A'); c <= std::min<uint32_t>(r.hi, 'Z'); ++c) extra.add(c + 32);
                    for (uint32_t c = std::max<uint32_t>(r.lo, 'a'); c <= std::min<uint32_t>(r.hi, 'z'); ++c) extra.add(c - 32);
                }
                set.add(extra);
                set.canonicalize();
            } else {
                add_case_fold_closure(set);
            }
        }
        if (negated) set.negate(bytes ? 0xFF : kMaxCodepoint, !bytes);
        if (opts_.ban_newline) set.remove('\n');
        return Hir::cls(std::move(set), bytes);
    }

    Hir literal(uint32_t cp, const ParseFlags& f, size_t at) {
        note_literal(cp);
        if (cp == '\n' && opts_.ban_newline) fail_at("the literal '\\n' is not allowed in a regex", at);
        if (!f.unicode && cp >= 0x80) {
            // Byte mode: a non-ASCII literal matches its UTF-8 encoding.
            uint8_t buf[4];
            size_t n = encode_utf8(cp, buf);
            std::vector<Hir> seq;
            for (size_t k = 0; k < n; ++k) seq.push_back(Hir::cls(CharSet(buf[k]), true));
            return Hir::concat(std::move(seq));
        }
        return finish_class(CharSet(cp), false, f);
    }

    Hir parse_alternation(ParseFlags& flags, size_t depth) {
        if (depth > opts_.nest_limit) fail("exceeds nest limit");
        std::vector<Hir> alts;
        alts.push_back(parse_concat(flags, depth));
        while (!eof() && p_[i_] == '|') {
            ++i_;
            alts.push_back(parse_concat(flags, depth));
        }
        return Hir::alt(std::move(alts));
    }

    Hir parse_concat(ParseFlags& flags, size_t depth) {
        std::vector<Hir> items;
        for (;;) {
            skip_ws(flags);
            if (eof() || p_[i_] == '|' || p_[i_] == ')') break;
            char c = p_[i_];
            if (c == '*' || c == '+' || c == '?' || c == '{') {
                if (items.empty()) fail("repetition operator missing expression");
                apply_repetition(items.back(), flags);
                continue;
            }
            if (c == '(') {
                size_t at = i_;
                ++i_;
                if (peek() == '?' && try_flag_directive(flags)) continue;  // (?flags)
                items.push_back(parse_group(flags, depth, at));
                continue;
            }
            items.push_back(parse_atom(flags));
        }
        return Hir::concat(std::move(items));
    }

    void apply_repetition(Hir& target, const ParseFlags& flags) {
        size_t at = i_;
        char c = p_[i_++];
        uint32_t mn = 0, mx = Hir::kInf;
        if (c == '*') { mn = 0; mx = Hir::kInf; }
        else if (c == '+') { mn = 1; mx = Hir::kInf; }
        else if (c == '?') { mn = 0; mx = 1; }
        else {
            auto read_num = [&](uint32_t& out) -> bool {
                skip_ws_in_braces();
                size_t start = i_;
                uint64_t v = 0;
                while (!eof() && p_[i_] >= '0' && p_[i_] <= '9') {
                    v = v * 10 + static_cast<uint64_t>(p_[i_] - '0');
                    if (v > 0xFFFFFFFEull) fail("repetition count too large");
                    ++i_;
                }
                bool any_digit = i_ > start;
                skip_ws_in_braces();
                out = static_cast<uint32_t>(v);
                return any_digit;
            };
            uint32_t a = 0, b = 0;
            bool has_a = read_num(a);
            if (eof()) fail_at("unclosed counted repetition", at);
            if (p_[i_] == '}') {
                if (!has_a) fail_at("repetition quantifier expects a valid decimal", at);
                ++i_;
                mn = mx = a;
            } else if (p_[i_] == ',') {
                ++i_;
                bool has_b = read_num(b);
                if (eof() || p_[i_] != '}') fail_at("unclosed counted repetition", at);
                ++i_;
                if (!has_a && !has_b) fail_at("repetition quantifier expects a valid decimal", at);
                mn = has_a ? a : 0;
                mx = has_b ? b : Hir::kInf;
                if (mn > mx) fail_at("invalid repetition range: min greater than max", at);
            } else {
                fail_at("repetition quantifier expects a valid decimal", at);
            }
        }
        bool greedy = true;
        if (!eof() && p_[i_] == '?') {
            greedy = false;
            ++i_;
        }
        if (flags.swap_greed) greedy = !greedy;
        target = Hir::repeat(std::move(target), mn, mx, greedy);
    }

    void skip_ws_in_braces() {
        while (!eof() && (p_[i_] == ' ' || p_[i_] == '\t' || p_[i_] == '\n')) ++i_;
    }

    // At '(?'. If this is a bare flag directive "(?flags)", applies it and returns true.
    bool try_flag_directive(ParseFlags& flags) {
        size_t save = i_;
        ++i_;  // '?'
        ParseFlags nf = flags;
        bool any = false;
        if (!parse_flag_list(nf, any)) {
            i_ = save;
            return false;
        }
        if (peek() == ')') {
            if (!any) fail("empty flag group");
            ++i_;
            flags = nf;
            return true;
        }
        i_ = save;
        return false;
    }

    // Parses [flags][-flags]; stops before ':' or ')'. Returns false if not a flag list.
    bool parse_flag_list(ParseFlags& f, bool& any) {
        bool neg = false;
        bool neg_seen = false;
        while (!eof() && p_[i_] != ':' && p_[i_] != ')') {
            char c = p_[i_];
            bool v = !neg;
            switch (c) {
                case '-':
                    if (neg_seen) fail("repeated negation in flags");
                    neg = neg_seen = true;
                    ++i_;
                    continue;
                case 'i': f.case_insensitive = v; break;
                case 'm': f.multi_line = v; break;
                case 's': f.dot_all = v; break;
                case 'U': f.swap_greed = v; break;
                case 'x': f.ignore_whitespace = v; break;
                case 'u': f.unicode = v; break;
                case 'R': f.crlf = v; break;
                default:
                    return false;
            }
            any = true;
            ++i_;
        }
        if (neg && i_ > 0 && p_[i_ - 1] == '-') fail("dangling flag negation");
        return !eof();
    }

    Hir parse_group(ParseFlags& outer, size_t depth, size_t open_at) {
        ParseFlags inner = outer;
        if (peek() == '?') {
            ++i_;
            if (peek() == 'P' && peek(1) == '<') {
                i_ += 2;
                parse_group_name();
            } else if (peek() == '<') {
                ++i_;
                parse_group_name();
            } else if (peek() == 'P' && peek(1) == '=') {
                fail("backreferences are not supported");
            } else if (peek() == '=' || peek() == '!' || (peek() == '<' && (peek(1) == '=' || peek(1) == '!'))) {
                fail("look-around, including look-ahead and look-behind, is not supported");
            } else {
                bool any = false;
                if (!parse_flag_list(inner, any) || peek() != ':') fail("unrecognized flag or group syntax");
                ++i_;  // ':'
            }
        }
        Hir h = parse_alternation(inner, depth + 1);
        if (eof() || p_[i_] != ')') fail_at("unclosed group", open_at);
        ++i_;
        return h;
    }

    void parse_group_name() {
        size_t start = i_;
        while (!eof() && p_[i_] != '>') {
            char c = p_[i_];
            if (!(is_alnum_ascii(c) || c == '_' || c == '.' || c == '[' || c == ']')) fail("invalid capture group name");
            ++i_;
        }
        if (eof()) fail("unclosed capture group name");
        std::string name(p_.substr(start, i_ - start));
        if (name.empty()) fail("empty capture group name");
        if (name[0] >= '0' && name[0] <= '9') fail("invalid capture group name");
        if (!names_.insert(name).second) fail("duplicate capture group name");
        ++i_;  // '>'
    }

    Hir parse_atom(ParseFlags& flags) {
        size_t at = i_;
        char c = p_[i_];
        switch (c) {
            case '.': {
                ++i_;
                CharSet s;
                if (flags.unicode) s.add(0, kMaxCodepoint);
                else s.add(0, 0xFF);
                if (flags.unicode) s.subtract(CharSet(0xD800, 0xDFFF));
                if (!flags.dot_all) {
                    s.remove('\n');
                    if (flags.crlf) s.remove('\r');
                }
                return finish_class(std::move(s), false, ParseFlags{false, false, false, false, false, flags.unicode, false});
            }
            case '^':
                ++i_;
                return Hir::look_at(flags.multi_line ? (flags.crlf ? Look::StartLineCrlf : Look::StartLine) : Look::StartText);
            case '$':
                ++i_;
                return Hir::look_at(flags.multi_line ? (flags.crlf ? Look::EndLineCrlf : Look::EndLine) : Look::EndText);
            case '[':
                ++i_;
                return parse_class(flags, at);
            case '\\':
                return parse_escape(flags);
            default:
                return literal(next_char(), flags, at);
        }
    }

    uint32_t parse_hex_escape(char kind) {
        // After \x, \u or \U.
        size_t fixed = kind == 'x' ? 2 : kind == 'u' ? 4 : 8;
        uint32_t v = 0;
        if (peek() == '{') {
            ++i_;
            size_t start = i_;
            while (!eof() && p_[i_] != '}') {
                if (!is_hex(p_[i_])) fail("invalid hexadecimal digit");
                v = v * 16 + hex_val(p_[i_]);
                if (v > 0x10FFFF) fail("hexadecimal literal is not a Unicode scalar value");
                ++i_;
            }
            if (eof()) fail("unclosed hexadecimal literal");
            if (i_ == start) fail("hexadecimal literal is empty");
            ++i_;
        } else {
            for (size_t k = 0; k < fixed; ++k) {
                if (eof() || !is_hex(p_[i_])) fail("invalid hexadecimal digit");
                v = v * 16 + hex_val(p_[i_]);
                ++i_;
            }
        }
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) fail("hexadecimal literal is not a Unicode scalar value");
        return v;
    }

    // Parses \p / \P after the letter. Returns the (positive) set and sets `negated`.
    CharSet parse_unicode_class(bool& negated, const ParseFlags& flags) {
        if (!flags.unicode) fail("Unicode classes are not allowed when Unicode mode is disabled");
        std::string name;
        if (peek() == '{') {
            ++i_;
            size_t start = i_;
            while (!eof() && p_[i_] != '}') ++i_;
            if (eof()) fail("unclosed Unicode class");
            name = std::string(p_.substr(start, i_ - start));
            ++i_;
            if (!name.empty() && name[0] == '^') {
                negated = !negated;
                name.erase(0, 1);
            }
            auto eq = name.find_first_of("=:");
            if (eq != std::string::npos) {
                std::string key;
                for (char k : name.substr(0, eq))
                    if (k != ' ' && k != '_' && k != '-') key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(k))));
                std::string value = name.substr(eq + 1);
                CharSet s;
                bool ok = false;
                if (key == "gc" || key == "generalcategory") ok = unicode_general_category(value, &s);
                else if (key == "sc" || key == "script") ok = unicode_script(value, false, &s);
                else if (key == "scx" || key == "scriptextensions") ok = unicode_script(value, true, &s);
                else fail("unsupported Unicode property: " + name);
                if (!ok) fail("unsupported or unknown Unicode class: " + name);
                return s;
            }
        } else {
            if (eof()) fail("missing Unicode class name");
            name = std::string(1, p_[i_++]);
        }
        CharSet s;
        if (!unicode_property(name, &s)) fail("unsupported or unknown Unicode class: " + name);
        return s;
    }

    // Shared by atoms and class items: a Perl/Unicode class escape. Returns true and fills `out`.
    bool try_class_escape(char e, const ParseFlags& flags, CharSet& out, bool& negated) {
        negated = false;
        switch (e) {
            case 'd': out = perl_digit(flags.unicode); return true;
            case 'D': out = perl_digit(flags.unicode); negated = true; return true;
            case 'w': out = perl_word(flags.unicode); return true;
            case 'W': out = perl_word(flags.unicode); negated = true; return true;
            case 's': out = perl_space(flags.unicode); return true;
            case 'S': out = perl_space(flags.unicode); negated = true; return true;
            case 'p': ++i_; out = parse_unicode_class(negated, flags); --i_; return true;
            case 'P': ++i_; negated = true; out = parse_unicode_class(negated, flags); --i_; return true;
            default: return false;
        }
    }

    // Literal escapes. Returns true and sets cp.
    bool try_literal_escape(char e, uint32_t& cp) {
        switch (e) {
            case 'a': cp = 0x07; return true;
            case 'f': cp = 0x0C; return true;
            case 't': cp = '\t'; return true;
            case 'n': cp = '\n'; return true;
            case 'r': cp = '\r'; return true;
            case 'v': cp = 0x0B; return true;
            default: break;
        }
        if (static_cast<unsigned char>(e) < 0x80 && !is_alnum_ascii(e) && e != '<' && e != '>') {
            cp = static_cast<unsigned char>(e);
            return true;
        }
        return false;
    }

    Hir parse_escape(ParseFlags& flags) {
        size_t at = i_;
        ++i_;  // '\'
        if (eof()) fail_at("incomplete escape sequence", at);
        char e = p_[i_];
        CharSet set;
        bool negated = false;
        if (try_class_escape(e, flags, set, negated)) {
            ++i_;
            if (e == 'p' || e == 'P') {
                // finish_class must not fold \p classes differently from regex-syntax: it does fold.
            }
            return finish_class(std::move(set), negated, flags);
        }
        if (e == 'x' || e == 'u' || e == 'U') {
            ++i_;
            uint32_t v = parse_hex_escape(e);
            if (!flags.unicode && e == 'x') {
                note_literal(v);
                if (v > 0xFF) fail_at("hexadecimal byte literal out of range", at);
                if (v == '\n' && opts_.ban_newline) fail_at("the literal '\\n' is not allowed in a regex", at);
                return finish_class(CharSet(v), false, flags);
            }
            return literal(v, flags, at);
        }
        switch (e) {
            case 'b':
                ++i_;
                if (peek() == '{') {
                    size_t start = ++i_;
                    while (!eof() && p_[i_] != '}') ++i_;
                    if (eof()) fail_at("unclosed word boundary", at);
                    std::string_view kind = p_.substr(start, i_ - start);
                    ++i_;
                    bool u = flags.unicode;
                    if (kind == "start") return Hir::look_at(u ? Look::WordStartUnicode : Look::WordStartAscii);
                    if (kind == "end") return Hir::look_at(u ? Look::WordEndUnicode : Look::WordEndAscii);
                    if (kind == "start-half") return Hir::look_at(u ? Look::WordStartHalfUnicode : Look::WordStartHalfAscii);
                    if (kind == "end-half") return Hir::look_at(u ? Look::WordEndHalfUnicode : Look::WordEndHalfAscii);
                    fail_at("unrecognized word boundary type", at);
                }
                return Hir::look_at(flags.unicode ? Look::WordUnicode : Look::WordAscii);
            case 'B': ++i_; return Hir::look_at(flags.unicode ? Look::NotWordUnicode : Look::NotWordAscii);
            case '<': ++i_; return Hir::look_at(flags.unicode ? Look::WordStartUnicode : Look::WordStartAscii);
            case '>': ++i_; return Hir::look_at(flags.unicode ? Look::WordEndUnicode : Look::WordEndAscii);
            case 'A': ++i_; return Hir::look_at(Look::StartText);
            case 'z': ++i_; return Hir::look_at(Look::EndText);
            default: break;
        }
        if (e >= '0' && e <= '9') fail_at("backreferences are not supported", at);
        uint32_t cp;
        if (try_literal_escape(e, cp)) {
            ++i_;
            return literal(cp, flags, at);
        }
        fail_at("unrecognized escape sequence", at);
    }

    // ---- Character classes -------------------------------------------------------------

    Hir parse_class(const ParseFlags& flags, size_t open_at) {
        bool negated = false;
        CharSet set = parse_class_body(flags, open_at, negated);
        return finish_class(std::move(set), negated, flags);
    }

    // After '['. Consumes through the matching ']'. Returns the positive set (+ negation flag).
    CharSet parse_class_body(const ParseFlags& flags, size_t open_at, bool& negated) {
        negated = false;
        skip_ws(flags);
        if (peek() == '^') {
            negated = true;
            ++i_;
        }
        CharSet acc = parse_class_union(flags, open_at, true);
        for (;;) {
            skip_ws(flags);
            if (eof()) fail_at("unclosed character class", open_at);
            if (p_[i_] == ']') {
                ++i_;
                break;
            }
            char op = p_[i_];
            if (!((op == '&' || op == '-' || op == '~') && peek(1) == op)) fail("unexpected character in class");
            i_ += 2;
            CharSet rhs = parse_class_union(flags, open_at, false);
            if (op == '&') acc.intersect(rhs);
            else if (op == '-') acc.subtract(rhs);
            else acc.symmetric_difference(rhs);
        }
        acc.canonicalize();
        return acc;
    }

    bool at_class_op() const {
        char c = peek();
        return (c == '&' || c == '-' || c == '~') && peek(1) == c;
    }

    CharSet parse_class_union(const ParseFlags& flags, size_t open_at, bool first) {
        CharSet acc;
        bool any = false;
        for (;;) {
            skip_ws(flags);
            if (eof()) fail_at("unclosed character class", open_at);
            char c = p_[i_];
            if (c == ']' && !(first && !any)) break;
            if (at_class_op() && any) break;
            if (at_class_op() && !any && !first) fail("class set operation missing operand");
            ClassItem item = parse_class_item(flags, open_at, first && !any);
            any = true;
            if (item.is_char) {
                skip_ws(flags);
                // Range?
                if (peek() == '-' && peek(1) != ']' && peek(1) != '-' && i_ + 1 < p_.size()) {
                    size_t dash = i_;
                    ++i_;
                    skip_ws(flags);
                    ClassItem hi = parse_class_item(flags, open_at, false);
                    if (!hi.is_char) fail_at("invalid range boundary, must be a literal", dash);
                    if (hi.c < item.c) fail_at("invalid range: start greater than end", dash);
                    acc.add(item.c, hi.c);
                } else {
                    acc.add(item.c);
                }
            } else {
                acc.add(item.set);
            }
        }
        if (!any) fail("empty character class");
        acc.canonicalize();
        return acc;
    }

    ClassItem parse_class_item(const ParseFlags& flags, size_t open_at, bool first) {
        ClassItem item;
        char c = p_[i_];
        if (c == '[') {
            if (peek(1) == ':') {
                size_t end = p_.find(":]", i_ + 2);
                if (end != std::string_view::npos) {
                    std::string_view name = p_.substr(i_ + 2, end - (i_ + 2));
                    bool neg = !name.empty() && name[0] == '^';
                    if (neg) name.remove_prefix(1);
                    CharSet s;
                    if (posix_class(name, &s)) {
                        i_ = end + 2;
                        if (neg) s.negate(flags.unicode ? kMaxCodepoint : 0xFF, flags.unicode);
                        item.set = s;
                        return item;
                    }
                }
            }
            ++i_;
            bool neg = false;
            CharSet s = parse_class_body(flags, open_at, neg);
            if (neg) s.negate(flags.unicode ? kMaxCodepoint : 0xFF, flags.unicode);
            item.set = s;
            return item;
        }
        if (c == '\\') {
            size_t at = i_;
            ++i_;
            if (eof()) fail_at("incomplete escape sequence", at);
            char e = p_[i_];
            CharSet s;
            bool neg = false;
            if (try_class_escape(e, flags, s, neg)) {
                ++i_;
                if (neg) s.negate(flags.unicode ? kMaxCodepoint : 0xFF, flags.unicode);
                item.set = s;
                return item;
            }
            if (e == 'x' || e == 'u' || e == 'U') {
                ++i_;
                item.is_char = true;
                item.c = parse_hex_escape(e);
                if (!flags.unicode && item.c > 0xFF) fail_at("hexadecimal byte literal out of range", at);
                note_literal(item.c);
                return item;
            }
            uint32_t cp;
            if (try_literal_escape(e, cp) || e == '<' || e == '>') {
                if (e == '<' || e == '>') cp = static_cast<uint32_t>(e);
                ++i_;
                item.is_char = true;
                item.c = cp;
                note_literal(cp);
                return item;
            }
            fail_at("unrecognized escape sequence in class", at);
        }
        (void)first;
        item.is_char = true;
        size_t at = i_;
        item.c = next_char();
        if (!flags.unicode && item.c >= 0x80) fail_at("non-ASCII character in a byte class", at);
        note_literal(item.c);
        return item;
    }
};

} // namespace

ParseResult parse_regex(std::string_view pattern, const ParseOptions& opts) {
    ParseResult res;
    try {
        Parser p(pattern, opts, res);
        res.hir = p.parse();
    } catch (const ParseError& e) {
        res.error = e.msg;
        res.error_offset = e.offset;
        res.hir = Hir::empty();
    }
    return res;
}

Hir literal_hir(std::string_view lit, bool case_insensitive, bool unicode) {
    std::vector<Hir> seq;
    const auto* b = reinterpret_cast<const uint8_t*>(lit.data());
    const auto* e = b + lit.size();
    while (b < e) {
        uint32_t cp = 0;
        size_t n = unicode ? decode_utf8(b, e, &cp) : 0;
        if (n == 0) {
            // Raw byte (invalid UTF-8, or byte mode).
            CharSet s(*b);
            if (case_insensitive && *b < 0x80) {
                uint8_t c = *b;
                if (c >= 'a' && c <= 'z') s.add(c - 32);
                if (c >= 'A' && c <= 'Z') s.add(c + 32);
            }
            seq.push_back(Hir::cls(std::move(s), true));
            ++b;
            continue;
        }
        CharSet s(cp);
        if (case_insensitive) add_case_fold_closure(s);
        seq.push_back(Hir::cls(std::move(s), false));
        b += n;
    }
    return Hir::concat(std::move(seq));
}

} // namespace bro::search::rx
