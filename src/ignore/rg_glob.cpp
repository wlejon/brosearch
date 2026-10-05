// ripgrep's glob dialect (globset as the ignore crate configures it), compiled to a small byte NFA.
// The parser follows globset's Parser token for token (including its "**" rules and the
// unclosed-class rollback); the NFA is the regex globset would build from those tokens.

#include "ignore/rg_glob.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace bro::search::detail {

namespace {

struct Token {
    enum class Kind : uint8_t { Literal, Any, ZeroOrMore, RecPrefix, RecSuffix, RecZeroOrMore, Class, Alternates };
    Token(Kind k) : kind(k) {}  // NOLINT(google-explicit-constructor): push({Kind::Any}) reads best
    Kind kind;
    char32_t c = 0;
    bool negated = false;
    std::vector<std::pair<char32_t, char32_t>> ranges;
    std::vector<std::vector<Token>> alts;
};
using Tokens = std::vector<Token>;

std::u32string decode_lossy(std::string_view s) {
    std::u32string out;
    size_t i = 0;
    while (i < s.size()) {
        const auto b = static_cast<unsigned char>(s[i]);
        size_t n = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
        char32_t cp = n == 1 ? b : n == 2 ? (b & 0x1F) : n == 3 ? (b & 0x0F) : (b & 0x07);
        bool ok = n != 0 && i + n <= s.size();
        for (size_t k = 1; ok && k < n; ++k) {
            const auto cb = static_cast<unsigned char>(s[i + k]);
            if ((cb & 0xC0) != 0x80) ok = false;
            else cp = (cp << 6) | (cb & 0x3F);
        }
        if (ok && ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
                   (cp >= 0xD800 && cp <= 0xDFFF)))
            ok = false;
        if (!ok) {
            out.push_back(0xFFFD);
            ++i;
        } else {
            out.push_back(cp);
            i += n;
        }
    }
    return out;
}

std::string encode(char32_t c) {
    std::string s;
    if (c < 0x80) {
        s.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
        s.push_back(static_cast<char>(0xC0 | (c >> 6)));
        s.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
        s.push_back(static_cast<char>(0xE0 | (c >> 12)));
        s.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
        s.push_back(static_cast<char>(0xF0 | (c >> 18)));
        s.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        s.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
    return s;
}

class Parser {
public:
    explicit Parser(std::u32string chars) : chars_(std::move(chars)) { frames_.push_back({Tokens{}}); }

    std::optional<Tokens> parse(std::string& err) {
        while (auto c = bump()) {
            bool ok = true;
            switch (*c) {
            case '?': push({Token::Kind::Any}); break;
            case '*': parse_star(); break;
            case '[': ok = parse_class(err); break;
            case '{': frames_.push_back({Tokens{}}); break;
            case '}':
                if (frames_.size() <= 1) {
                    err = "unopened alternate group; missing '{'";
                    return std::nullopt;
                } else {
                    Token t{Token::Kind::Alternates};
                    t.alts = std::move(frames_.back());
                    frames_.pop_back();
                    push(std::move(t));
                }
                break;
            case ',':
                if (frames_.size() <= 1) push(literal(','));
                else frames_.back().emplace_back();
                break;
            case '\\': {
                auto n = bump();
                if (!n) {
                    err = "dangling '\\'";
                    return std::nullopt;
                }
                push(literal(*n));
                break;
            }
            default: push(literal(*c)); break;
            }
            if (!ok) return std::nullopt;
        }
        if (frames_.size() != 1) {
            err = "unclosed alternate group; missing '}'";
            return std::nullopt;
        }
        return std::move(frames_.back().back());
    }

private:
    static Token literal(char32_t c) {
        Token t{Token::Kind::Literal};
        t.c = c;
        return t;
    }

    std::optional<char32_t> peek() const {
        if (pos_ < chars_.size()) return chars_[pos_];
        return std::nullopt;
    }
    std::optional<char32_t> bump() {
        prev_ = cur_;
        cur_ = pos_ < chars_.size() ? std::optional<char32_t>(chars_[pos_++]) : std::nullopt;
        return cur_;
    }
    Tokens& current() { return frames_.back().back(); }
    void push(Token t) { current().push_back(std::move(t)); }

    void parse_star() {
        const std::optional<char32_t> prev = prev_;
        if (peek() != std::optional<char32_t>('*')) {
            push({Token::Kind::ZeroOrMore});
            return;
        }
        bump();
        if (current().empty()) {
            auto p = peek();
            if (p && *p != '/') {
                push({Token::Kind::ZeroOrMore});
                return;
            }
            push({Token::Kind::RecPrefix});
            bump();  // the '/' (or nothing at the end)
            return;
        }
        if (prev != std::optional<char32_t>('/')) {
            push({Token::Kind::ZeroOrMore});
            return;
        }
        bool is_suffix;
        auto p = peek();
        if (!p) {
            bump();
            is_suffix = true;
        } else if ((*p == ',' || *p == '}') && frames_.size() >= 2) {
            is_suffix = true;
        } else if (*p == '/') {
            bump();
            is_suffix = false;
        } else {
            push({Token::Kind::ZeroOrMore});
            return;
        }
        Token last = std::move(current().back());
        current().pop_back();
        if (last.kind == Token::Kind::RecPrefix) push({Token::Kind::RecPrefix});
        else if (last.kind == Token::Kind::RecSuffix) push({Token::Kind::RecSuffix});
        else push({is_suffix ? Token::Kind::RecSuffix : Token::Kind::RecZeroOrMore});
    }

    bool parse_class(std::string& err) {
        const size_t saved_pos = pos_;
        const auto saved_prev = prev_;
        const auto saved_cur = cur_;
        Token t{Token::Kind::Class};
        auto p = peek();
        if (p && (*p == '!' || *p == '^')) {
            bump();
            t.negated = true;
        }
        bool first = true, in_range = false;
        auto extend = [&](char32_t c) {
            t.ranges.back().second = c;
            if (t.ranges.back().second < t.ranges.back().first) {
                err = "invalid range";
                return false;
            }
            return true;
        };
        for (;;) {
            auto c = bump();
            if (!c) {  // no closing ']': the '[' is a literal
                pos_ = saved_pos;
                prev_ = saved_prev;
                cur_ = saved_cur;
                push(literal('['));
                return true;
            }
            if (*c == ']') {
                if (!first) break;
                t.ranges.emplace_back(']', ']');
            } else if (*c == '-') {
                if (first) {
                    t.ranges.emplace_back('-', '-');
                } else if (in_range) {
                    if (!extend('-')) return false;
                    in_range = false;
                } else {
                    in_range = true;
                }
            } else {
                if (in_range) {
                    if (!extend(*c)) return false;
                } else {
                    t.ranges.emplace_back(*c, *c);
                }
                in_range = false;
            }
            first = false;
        }
        if (in_range) t.ranges.emplace_back('-', '-');
        push(std::move(t));
        return true;
    }

    std::u32string chars_;
    size_t pos_ = 0;
    std::optional<char32_t> prev_, cur_;
    std::vector<std::vector<Tokens>> frames_;  // alternation nesting; frames_[0] is the glob itself
};

// Whether a token sequence produces any regex text (globset drops alternatives that do not).
bool emits(const Tokens& ts) {
    for (const auto& t : ts) {
        if (t.kind != Token::Kind::Alternates) return true;
        for (const auto& a : t.alts)
            if (emits(a)) return true;
    }
    return false;
}

} // namespace

struct RgGlobBuilder {
    RgGlob& g;
    struct Frag {
        uint32_t start, end;  // `end` is an Eps state whose `out` is still open
    };

    uint32_t add(RgGlob::State s) {
        g.states_.push_back(s);
        return static_cast<uint32_t>(g.states_.size() - 1);
    }
    Frag eps() {
        uint32_t s = add({RgGlob::Op::Eps});
        return {s, s};
    }
    Frag set(const std::bitset<256>& bits, bool negated) {
        g.sets_.push_back(bits);
        uint32_t e = add({RgGlob::Op::Eps});
        RgGlob::State st{RgGlob::Op::Set};
        st.negated = negated;
        st.set = static_cast<uint32_t>(g.sets_.size() - 1);
        st.out = e;
        return {add(st), e};
    }
    Frag byte(unsigned char b) {
        std::bitset<256> bits;
        bits.set(b);
        return set(bits, false);
    }
    Frag not_slash() { return set(std::bitset<256>().set('/'), true); }
    Frag any_byte() { return set(std::bitset<256>(), true); }
    Frag cat(Frag a, Frag b) {
        g.states_[a.end].out = b.start;
        return {a.start, b.end};
    }
    Frag alt(const std::vector<Frag>& fs) {
        if (fs.empty()) return eps();
        if (fs.size() == 1) return fs[0];
        uint32_t e = add({RgGlob::Op::Eps});
        for (const auto& f : fs) g.states_[f.end].out = e;
        uint32_t start = fs.back().start;
        for (size_t i = fs.size() - 1; i-- > 0;) {
            RgGlob::State sp{RgGlob::Op::Split};
            sp.out = fs[i].start;
            sp.out2 = start;
            start = add(sp);
        }
        return {start, e};
    }
    Frag star(Frag f) {
        uint32_t e = add({RgGlob::Op::Eps});
        RgGlob::State sp{RgGlob::Op::Split};
        sp.out = f.start;
        sp.out2 = e;
        uint32_t s = add(sp);
        g.states_[f.end].out = s;
        return {s, e};
    }
    Frag opt(Frag f) { return alt({f, eps()}); }
    Frag text(std::string_view s) {
        Frag f = eps();
        for (char c : s) f = cat(f, byte(static_cast<unsigned char>(c)));
        return f;
    }

    // A class as globset writes it into a (?-u) regex: each member char as its escaped UTF-8 bytes,
    // so a multi-byte member contributes its bytes and a range spans last byte .. first byte.
    bool klass(const Token& t, Frag& out) {
        std::bitset<256> bits;
        for (const auto& [lo, hi] : t.ranges) {
            std::string a = encode(lo);
            if (lo == hi) {
                for (unsigned char b : a) bits.set(b);
                continue;
            }
            std::string b = encode(hi);
            for (size_t i = 0; i + 1 < a.size(); ++i) bits.set(static_cast<unsigned char>(a[i]));
            const auto rlo = static_cast<unsigned char>(a.back());
            const auto rhi = static_cast<unsigned char>(b.front());
            if (rlo > rhi) return false;
            for (unsigned v = rlo; v <= rhi; ++v) bits.set(v);
            for (size_t i = 1; i < b.size(); ++i) bits.set(static_cast<unsigned char>(b[i]));
        }
        out = set(bits, t.negated);
        return true;
    }

    bool seq(const Tokens& ts, Frag& out) {
        Frag f = eps();
        for (const auto& t : ts) {
            Frag x{};
            switch (t.kind) {
            case Token::Kind::Literal: x = text(encode(t.c)); break;
            case Token::Kind::Any: x = not_slash(); break;
            case Token::Kind::ZeroOrMore: x = star(not_slash()); break;
            case Token::Kind::RecPrefix: x = alt({opt(byte('/')), cat(star(any_byte()), byte('/'))}); break;
            case Token::Kind::RecSuffix: x = cat(byte('/'), star(any_byte())); break;
            case Token::Kind::RecZeroOrMore:
                x = alt({byte('/'), cat(cat(byte('/'), star(any_byte())), byte('/'))});
                break;
            case Token::Kind::Class:
                if (!klass(t, x)) return false;
                break;
            case Token::Kind::Alternates: {
                std::vector<Frag> parts;
                for (const auto& a : t.alts) {
                    if (!emits(a)) continue;
                    Frag p{};
                    if (!seq(a, p)) return false;
                    parts.push_back(p);
                }
                x = alt(parts);
                break;
            }
            }
            f = cat(f, x);
        }
        out = f;
        return true;
    }
};

std::shared_ptr<const RgGlob> RgGlob::compile(std::string_view pattern, std::string* error) {
    std::string err;
    Parser parser(decode_lossy(pattern));
    auto tokens = parser.parse(err);
    if (!tokens) {
        if (error) *error = err;
        return nullptr;
    }
    auto g = std::make_shared<RgGlob>();
    RgGlobBuilder b{*g};
    RgGlobBuilder::Frag f{};
    if (tokens->size() == 1 && (*tokens)[0].kind == Token::Kind::RecPrefix) {
        f = b.star(b.any_byte());  // globset: a glob of just "**" matches everything
    } else if (!b.seq(*tokens, f)) {
        if (error) *error = "invalid range";
        return nullptr;
    }
    uint32_t m = b.add({Op::Match});
    g->states_[f.end].out = m;
    g->start_ = f.start;
    return g;
}

namespace {

inline unsigned char swap_case(unsigned char b) {
    if (b >= 'a' && b <= 'z') return static_cast<unsigned char>(b - 32);
    if (b >= 'A' && b <= 'Z') return static_cast<unsigned char>(b + 32);
    return b;
}

} // namespace

bool RgGlob::match(std::string_view text, bool case_insensitive) const {
    thread_local std::vector<uint32_t> cur, next, stack, mark;
    const size_t n = states_.size();
    if (mark.size() < n) mark.assign(n, UINT32_MAX);
    std::fill(mark.begin(), mark.begin() + static_cast<std::ptrdiff_t>(n), UINT32_MAX);
    uint32_t gen = 0;
    bool matched = false;
    auto add_closure = [&](std::vector<uint32_t>& list, uint32_t s) {
        stack.clear();
        stack.push_back(s);
        while (!stack.empty()) {
            uint32_t x = stack.back();
            stack.pop_back();
            if (mark[x] == gen) continue;
            mark[x] = gen;
            const State& st = states_[x];
            switch (st.op) {
            case Op::Eps: stack.push_back(st.out); break;
            case Op::Split:
                stack.push_back(st.out2);
                stack.push_back(st.out);
                break;
            case Op::Set: list.push_back(x); break;
            case Op::Match: matched = true; break;
            }
        }
    };
    cur.clear();
    add_closure(cur, start_);
    for (size_t i = 0; i < text.size(); ++i) {
        if (cur.empty()) return false;
        const auto b = static_cast<unsigned char>(text[i]);
        const unsigned char b2 = case_insensitive ? swap_case(b) : b;
        next.clear();
        ++gen;
        matched = false;
        for (uint32_t s : cur) {
            const State& st = states_[s];
            const auto& bits = sets_[st.set];
            if ((bits.test(b) || bits.test(b2)) != st.negated) add_closure(next, st.out);
        }
        std::swap(cur, next);
    }
    return matched;
}

} // namespace bro::search::detail
