#include "regex/literal.h"

#include "regex/unicode.h"

#include <bit>
#include <cstring>

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define BROSEARCH_SSE2 1
#include <emmintrin.h>
#endif

namespace bro::search::rx {

namespace {

bool ascii_letter(uint32_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

// Is this class exactly one byte string (possibly one ASCII-case-insensitive letter)?
bool class_exact(const Hir& h, Literal& out) {
    const auto& rs = h.set.ranges();
    if (rs.empty()) return false;
    if (rs.size() == 1 && rs[0].lo == rs[0].hi) {
        uint32_t c = rs[0].lo;
        if (h.bytes || c < 0x80) {
            out.push_back({static_cast<uint8_t>(c), false});
        } else {
            uint8_t buf[4];
            size_t n = encode_utf8(c, buf);
            for (size_t k = 0; k < n; ++k) out.push_back({buf[k], false});
        }
        return true;
    }
    if (rs.size() == 2 && rs[0].lo == rs[0].hi && rs[1].lo == rs[1].hi && ascii_letter(rs[0].lo) &&
        rs[1].lo == rs[0].lo + 32) {
        out.push_back({static_cast<uint8_t>(rs[1].lo), true});
        return true;
    }
    return false;
}

bool exact(const Hir& h, Literal& out, bool& has_look) {
    switch (h.kind) {
        case Hir::Kind::Empty:
            return true;
        case Hir::Kind::Look:
            has_look = true;
            return true;
        case Hir::Kind::Class:
            return class_exact(h, out);
        case Hir::Kind::Concat:
            for (auto& s : h.subs)
                if (!exact(s, out, has_look)) return false;
            return true;
        case Hir::Kind::Repeat: {
            if (h.min != h.max || h.min > 64) return false;
            Literal one;
            if (!exact(h.subs[0], one, has_look)) return false;
            if (one.size() * h.min > 256) return false;
            for (uint32_t k = 0; k < h.min; ++k) out.insert(out.end(), one.begin(), one.end());
            return true;
        }
        case Hir::Kind::Alt:
            return false;
    }
    return false;
}

int literal_score(const Literal& l) {
    if (l.empty()) return -1;
    int rarest = 255;
    for (auto& x : l) rarest = std::min<int>(rarest, x.ci ? byte_rank(x.b) + 10 : byte_rank(x.b));
    return static_cast<int>(std::min<size_t>(l.size(), 16)) * 256 + (255 - rarest);
}

void consider(const Literal& l, Literal& best) {
    if (literal_score(l) > literal_score(best)) best = l;
}

void required(const Hir& h, Literal& best) {
    switch (h.kind) {
        case Hir::Kind::Class: {
            Literal l;
            if (class_exact(h, l)) consider(l, best);
            return;
        }
        case Hir::Kind::Concat: {
            Literal run;
            for (auto& s : h.subs) {
                Literal piece;
                bool look = false;
                if (exact(s, piece, look)) {
                    run.insert(run.end(), piece.begin(), piece.end());
                } else {
                    consider(run, best);
                    run.clear();
                    required(s, best);
                }
            }
            consider(run, best);
            return;
        }
        case Hir::Kind::Repeat: {
            if (h.min >= 1) {
                Literal piece;
                bool look = false;
                if (exact(h.subs[0], piece, look)) {
                    // x{n,m} with n >= 1 contains x^n.
                    Literal rep;
                    for (uint32_t k = 0; k < h.min && rep.size() < 64; ++k) rep.insert(rep.end(), piece.begin(), piece.end());
                    consider(rep, best);
                } else {
                    required(h.subs[0], best);
                }
            }
            return;
        }
        default:
            return;
    }
}

// A set of at most 3 bytes, one of which occurs in every match of a node.
struct ByteSet {
    bool ok = false;
    int n = 0;
    uint8_t b[3] = {0, 0, 0};
    int cost = 0;  // summed byte_rank: lower is a better prefilter

    bool add(uint8_t x) {
        for (int i = 0; i < n; ++i)
            if (b[i] == x) return true;
        if (n == 3) return false;
        b[n++] = x;
        cost += byte_rank(x);
        return true;
    }
};

uint8_t utf8_lead(uint32_t cp) {
    if (cp < 0x80) return static_cast<uint8_t>(cp);
    if (cp < 0x800) return static_cast<uint8_t>(0xC0 | (cp >> 6));
    if (cp < 0x10000) return static_cast<uint8_t>(0xE0 | (cp >> 12));
    return static_cast<uint8_t>(0xF0 | (cp >> 18));
}

// The bytes a class match starts with: every match of the class consumes one of them.
ByteSet class_bytes(const Hir& h) {
    ByteSet s;
    for (const auto& r : h.set.ranges()) {
        if (h.bytes) {
            if (r.hi - r.lo >= 3) return ByteSet{};
            for (uint32_t c = r.lo; c <= r.hi; ++c)
                if (!s.add(static_cast<uint8_t>(c))) return ByteSet{};
            continue;
        }
        // Split at encoding-length boundaries so lead bytes are contiguous within each piece.
        static const uint32_t bounds[] = {0x80, 0x800, 0x10000, 0x110000};
        uint32_t lo = r.lo;
        for (uint32_t bound : bounds) {
            if (lo > r.hi) break;
            if (lo >= bound) continue;
            uint32_t hi = std::min(r.hi, bound - 1);
            uint32_t a = utf8_lead(lo), z = utf8_lead(hi);
            if (z - a >= 3) return ByteSet{};
            for (uint32_t c = a; c <= z; ++c)
                if (!s.add(static_cast<uint8_t>(c))) return ByteSet{};
            lo = hi + 1;
        }
    }
    s.ok = s.n > 0;
    return s;
}

ByteSet required_bytes(const Hir& h) {
    switch (h.kind) {
        case Hir::Kind::Class:
            return class_bytes(h);
        case Hir::Kind::Concat: {
            ByteSet best;
            for (auto& sub : h.subs) {
                ByteSet s = required_bytes(sub);
                if (s.ok && (!best.ok || s.cost < best.cost)) best = s;
            }
            return best;
        }
        case Hir::Kind::Alt: {
            ByteSet u;
            for (auto& sub : h.subs) {
                ByteSet s = required_bytes(sub);
                if (!s.ok) return ByteSet{};
                for (int i = 0; i < s.n; ++i)
                    if (!u.add(s.b[i])) return ByteSet{};
            }
            u.ok = u.n > 0;
            return u;
        }
        case Hir::Kind::Repeat:
            return h.min >= 1 ? required_bytes(h.subs[0]) : ByteSet{};
        default:
            return ByteSet{};
    }
}

} // namespace

uint8_t byte_rank(uint8_t b) {
    static const uint8_t* table = [] {
        static uint8_t t[256];
        for (int i = 0; i < 256; ++i) t[i] = i >= 0x80 ? 40 : 10;
        const char* lower = "etaoinsrhldcumfpgwybvkxjqz";
        for (int i = 0; lower[i]; ++i) t[static_cast<uint8_t>(lower[i])] = static_cast<uint8_t>(245 - i * 4);
        const char* upper = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
        for (int i = 0; upper[i]; ++i) t[static_cast<uint8_t>(upper[i])] = static_cast<uint8_t>(140 - i * 2);
        for (int d = 0; d < 10; ++d) t['0' + d] = static_cast<uint8_t>(d < 3 ? 190 - d * 5 : 160);
        struct P { char c; uint8_t r; };
        static const P punct[] = {{' ', 255}, {'\t', 200}, {'\n', 250}, {'\r', 120}, {'_', 190},
                                  {'.', 180}, {',', 175}, {'(', 175}, {')', 175}, {';', 170},
                                  {'=', 170}, {'"', 165}, {'-', 165}, {'/', 165}, {'*', 160},
                                  {':', 160}, {'{', 150}, {'}', 150}, {'\'', 150}, {'<', 140},
                                  {'>', 140}, {'[', 140}, {']', 140}, {'&', 130}, {'#', 130},
                                  {'+', 130}, {'!', 120}, {'\\', 120}, {'|', 110}, {'%', 100},
                                  {'?', 100}, {'@', 90}, {'$', 90}, {'^', 60}, {'~', 60}, {'`', 60}};
        for (auto& p : punct) t[static_cast<uint8_t>(p.c)] = p.r;
        t[0x7F] = 5;
        return t;
    }();
    return table[b];
}

LiteralInfo extract_literals(const Hir& hir) {
    LiteralInfo info;
    bool has_look = false;
    Literal whole;
    if (exact(hir, whole, has_look) && !whole.empty()) {
        if (!has_look) {
            info.exact = true;
            info.whole = whole;
        }
        info.required = whole;
    } else {
        required(hir, info.required);
    }
    // A single common byte is a poor prefilter: the automaton alone is faster.
    if (info.required.size() == 1 && byte_rank(info.required[0].b) > 100) info.required.clear();
    if (info.required.size() == 2 && byte_rank(info.required[0].b) > 150 && byte_rank(info.required[1].b) > 150)
        info.required.clear();
    if (info.exact && info.required.empty()) info.required = info.whole;
    if (info.required.empty()) {
        // Every byte must be fairly rare, or scanning for the set costs more than the automaton.
        ByteSet s = required_bytes(hir);
        bool rare = s.ok;
        for (int i = 0; i < s.n; ++i)
            if (byte_rank(s.b[i]) > 170) rare = false;
        if (rare) info.rare_bytes.assign(s.b, s.b + s.n);
    }
    return info;
}

const uint8_t* memchr3(uint8_t a, uint8_t b, uint8_t c, const uint8_t* p, const uint8_t* end) {
#ifdef BROSEARCH_SSE2
    const __m128i va = _mm_set1_epi8(static_cast<char>(a));
    const __m128i vb = _mm_set1_epi8(static_cast<char>(b));
    const __m128i vc = _mm_set1_epi8(static_cast<char>(c));
    while (end - p >= 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
        __m128i eq = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(v, va), _mm_cmpeq_epi8(v, vb)), _mm_cmpeq_epi8(v, vc));
        int m = _mm_movemask_epi8(eq);
        if (m) return p + std::countr_zero(static_cast<unsigned>(m));
        p += 16;
    }
#endif
    for (; p < end; ++p)
        if (*p == a || *p == b || *p == c) return p;
    return nullptr;
}

LiteralFinder LiteralFinder::any_of(const std::vector<uint8_t>& bytes) {
    LiteralFinder f;
    f.set_n_ = static_cast<int>(std::min<size_t>(bytes.size(), 3));    for (int i = 0; i < f.set_n_; ++i) f.set_[i] = bytes[static_cast<size_t>(i)];
    return f;
}

const uint8_t* memchr2(uint8_t a, uint8_t b, const uint8_t* p, const uint8_t* end) {
#ifdef BROSEARCH_SSE2
    const __m128i va = _mm_set1_epi8(static_cast<char>(a));
    const __m128i vb = _mm_set1_epi8(static_cast<char>(b));
    while (end - p >= 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
        int m = _mm_movemask_epi8(_mm_or_si128(_mm_cmpeq_epi8(v, va), _mm_cmpeq_epi8(v, vb)));
        if (m) return p + std::countr_zero(static_cast<unsigned>(m));
        p += 16;
    }
#endif
    for (; p < end; ++p)
        if (*p == a || *p == b) return p;
    return nullptr;
}

LiteralFinder::LiteralFinder(Literal lit) : lit_(std::move(lit)) {
    int best = 1 << 30;
    for (size_t i = 0; i < lit_.size(); ++i) {
        int r = byte_rank(lit_[i].b) + (lit_[i].ci ? 10 : 0);
        if (r < best) {
            best = r;
            rare_ = i;
        }
        if (lit_[i].ci) any_ci_ = true;
        plain_.push_back(lit_[i].b);
    }
    if (!lit_.empty()) {
        rare_ci_ = lit_[rare_].ci;
        rare_a_ = lit_[rare_].b;
        rare_b_ = rare_ci_ ? static_cast<uint8_t>(rare_a_ - 32) : rare_a_;
    }
}

bool LiteralFinder::verify(const uint8_t* p) const {
    if (!any_ci_) return std::memcmp(p, plain_.data(), plain_.size()) == 0;
    for (size_t i = 0; i < lit_.size(); ++i) {
        uint8_t c = p[i];
        if (lit_[i].ci) {
            if ((c | 0x20) != lit_[i].b) return false;
        } else if (c != lit_[i].b) {
            return false;
        }
    }
    return true;
}

size_t LiteralFinder::find(const uint8_t* hay, size_t start, size_t end) const {
    if (set_n_) {
        if (end <= start) return SIZE_MAX;
        const uint8_t *p = hay + start, *e = hay + end, *q;
        if (set_n_ == 1) q = static_cast<const uint8_t*>(std::memchr(p, set_[0], end - start));
        else if (set_n_ == 2) q = memchr2(set_[0], set_[1], p, e);
        else q = memchr3(set_[0], set_[1], set_[2], p, e);
        return q ? static_cast<size_t>(q - hay) : SIZE_MAX;
    }
    const size_t n = lit_.size();
    if (n == 0) return start <= end ? start : SIZE_MAX;
    if (end < start || end - start < n) return SIZE_MAX;
    const uint8_t* p = hay + start + rare_;
    const uint8_t* lim = hay + end - n + rare_ + 1;  // exclusive bound for the rare byte
    while (p < lim) {
        const uint8_t* q;
        if (!rare_ci_) q = static_cast<const uint8_t*>(std::memchr(p, rare_a_, static_cast<size_t>(lim - p)));
        else q = memchr2(rare_a_, rare_b_, p, lim);
        if (!q) return SIZE_MAX;
        const uint8_t* s = q - rare_;
        if (verify(s)) return static_cast<size_t>(s - hay);
        p = q + 1;
    }
    return SIZE_MAX;
}

} // namespace bro::search::rx
