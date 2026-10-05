#include "regex/unicode.h"

#include <cctype>
#include <string>

namespace bro::search::rx {

namespace {

struct FoldPair {
    uint32_t cp;
    uint32_t next;
};

struct GeneralCategoryTable {
    const char* name;
    const CodepointRange* ranges;
    size_t count;
};

#include "regex/unicode_class.inc"
#include "regex/unicode_fold.inc"

constexpr size_t kFoldCount = sizeof(kFoldOrbit) / sizeof(kFoldOrbit[0]);

const FoldPair* fold_lower_bound(uint32_t cp) {
    size_t lo = 0, hi = kFoldCount;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (kFoldOrbit[mid].cp < cp) lo = mid + 1;
        else hi = mid;
    }
    return kFoldOrbit + lo;
}

const FoldPair* fold_find(uint32_t cp) {
    const FoldPair* p = fold_lower_bound(cp);
    return (p != kFoldOrbit + kFoldCount && p->cp == cp) ? p : nullptr;
}

bool in_table(const CodepointRange* t, size_t n, uint32_t c) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (t[mid].hi < c) lo = mid + 1;
        else if (t[mid].lo > c) hi = mid;
        else return true;
    }
    return false;
}

const GeneralCategoryTable* category(std::string_view name) {
    for (auto& t : kGeneralCategories)
        if (name == t.name) return &t;
    return nullptr;
}

void add_categories(CharSet& out, std::initializer_list<const char*> names) {
    for (const char* n : names) {
        auto* t = category(n);
        if (t) out.add_table(t->ranges, t->count);
    }
}

std::string loose(std::string_view s) {
    std::string out;
    for (char c : s) {
        if (c == ' ' || c == '_' || c == '-') continue;
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

} // namespace

size_t decode_utf8(const uint8_t* p, const uint8_t* end, uint32_t* cp) {
    if (p >= end) return 0;
    uint8_t b0 = p[0];
    if (b0 < 0x80) {
        *cp = b0;
        return 1;
    }
    size_t len;
    uint32_t c, min;
    if ((b0 & 0xE0) == 0xC0) { len = 2; c = b0 & 0x1F; min = 0x80; }
    else if ((b0 & 0xF0) == 0xE0) { len = 3; c = b0 & 0x0F; min = 0x800; }
    else if ((b0 & 0xF8) == 0xF0) { len = 4; c = b0 & 0x07; min = 0x10000; }
    else return 0;
    if (static_cast<size_t>(end - p) < len) return 0;
    for (size_t i = 1; i < len; ++i) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        c = (c << 6) | (p[i] & 0x3F);
    }
    if (c < min || c > kMaxCodepoint || (c >= 0xD800 && c <= 0xDFFF)) return 0;
    *cp = c;
    return len;
}

size_t decode_utf8_last(const uint8_t* begin, const uint8_t* end, uint32_t* cp) {
    if (end <= begin) return 0;
    // Walk back over at most 3 continuation bytes to a lead byte, then validate forward.
    const uint8_t* s = end - 1;
    size_t back = 0;
    while (s > begin && back < 3 && (*s & 0xC0) == 0x80) {
        --s;
        ++back;
    }
    uint32_t c;
    size_t n = decode_utf8(s, end, &c);
    if (n == 0 || s + n != end) return 0;
    *cp = c;
    return n;
}

size_t encode_utf8(uint32_t cp, uint8_t out[4]) {
    if (cp < 0x80) { out[0] = static_cast<uint8_t>(cp); return 1; }
    if (cp < 0x800) {
        out[0] = static_cast<uint8_t>(0xC0 | (cp >> 6));
        out[1] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = static_cast<uint8_t>(0xE0 | (cp >> 12));
        out[1] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
        out[2] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = static_cast<uint8_t>(0xF0 | (cp >> 18));
    out[1] = static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F));
    out[2] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
    out[3] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
    return 4;
}

void add_case_fold_closure(CharSet& set) {
    set.canonicalize();
    CharSet extra;
    for (auto r : set.ranges()) {
        for (const FoldPair* p = fold_lower_bound(r.lo); p != kFoldOrbit + kFoldCount && p->cp <= r.hi; ++p) {
            // Walk the whole orbit (orbits are short: at most 4 members).
            uint32_t c = p->next;
            for (int guard = 0; c != p->cp && guard < 8; ++guard) {
                extra.add(c);
                const FoldPair* q = fold_find(c);
                if (!q) break;
                c = q->next;
            }
        }
    }
    set.add(extra);
    set.canonicalize();
}

bool has_case_variants(uint32_t cp) { return fold_find(cp) != nullptr; }

bool is_uppercase(uint32_t cp) {
    auto* t = category("Lu");
    return t && in_table(t->ranges, t->count, cp);
}

CharSet perl_word(bool unicode) {
    CharSet s;
    if (unicode) {
        s.add_table(kPerlWord);
    } else {
        s.add('0', '9');
        s.add('A', 'Z');
        s.add('_');
        s.add('a', 'z');
    }
    s.canonicalize();
    return s;
}

CharSet perl_digit(bool unicode) {
    CharSet s;
    if (unicode) add_categories(s, {"Nd"});
    else s.add('0', '9');
    s.canonicalize();
    return s;
}

CharSet perl_space(bool unicode) {
    CharSet s;
    if (unicode) {
        s.add_table(kPerlSpace);
    } else {
        s.add('\t', '\r');
        s.add(' ');
    }
    s.canonicalize();
    return s;
}

bool is_word_codepoint(uint32_t cp) {
    if (cp < 0x80) return is_word_byte(static_cast<uint8_t>(cp));
    return in_table(kPerlWord, sizeof(kPerlWord) / sizeof(kPerlWord[0]), cp);
}

bool unicode_property(std::string_view raw, CharSet* out) {
    struct Alias {
        const char* name;
        std::initializer_list<const char*> cats;
    };
    static const Alias kAliases[] = {
        {"l", {"Lu", "Ll", "Lt", "Lm", "Lo"}}, {"letter", {"Lu", "Ll", "Lt", "Lm", "Lo"}},
        {"lc", {"Lu", "Ll", "Lt"}}, {"casedletter", {"Lu", "Ll", "Lt"}},
        {"lu", {"Lu"}}, {"uppercaseletter", {"Lu"}}, {"ll", {"Ll"}}, {"lowercaseletter", {"Ll"}},
        {"lt", {"Lt"}}, {"titlecaseletter", {"Lt"}}, {"lm", {"Lm"}}, {"modifierletter", {"Lm"}},
        {"lo", {"Lo"}}, {"otherletter", {"Lo"}},
        {"m", {"Mn", "Mc", "Me"}}, {"mark", {"Mn", "Mc", "Me"}}, {"combiningmark", {"Mn", "Mc", "Me"}},
        {"mn", {"Mn"}}, {"nonspacingmark", {"Mn"}}, {"mc", {"Mc"}}, {"spacingmark", {"Mc"}},
        {"me", {"Me"}}, {"enclosingmark", {"Me"}},
        {"n", {"Nd", "Nl", "No"}}, {"number", {"Nd", "Nl", "No"}},
        {"nd", {"Nd"}}, {"decimalnumber", {"Nd"}}, {"digit", {"Nd"}},
        {"nl", {"Nl"}}, {"letternumber", {"Nl"}}, {"no", {"No"}}, {"othernumber", {"No"}},
        {"p", {"Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"}},
        {"punctuation", {"Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"}},
        {"punct", {"Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"}},
        {"pc", {"Pc"}}, {"connectorpunctuation", {"Pc"}}, {"pd", {"Pd"}}, {"dashpunctuation", {"Pd"}},
        {"ps", {"Ps"}}, {"openpunctuation", {"Ps"}}, {"pe", {"Pe"}}, {"closepunctuation", {"Pe"}},
        {"pi", {"Pi"}}, {"initialpunctuation", {"Pi"}}, {"pf", {"Pf"}}, {"finalpunctuation", {"Pf"}},
        {"po", {"Po"}}, {"otherpunctuation", {"Po"}},
        {"s", {"Sm", "Sc", "Sk", "So"}}, {"symbol", {"Sm", "Sc", "Sk", "So"}},
        {"sm", {"Sm"}}, {"mathsymbol", {"Sm"}}, {"sc", {"Sc"}}, {"currencysymbol", {"Sc"}},
        {"sk", {"Sk"}}, {"modifiersymbol", {"Sk"}}, {"so", {"So"}}, {"othersymbol", {"So"}},
        {"z", {"Zs", "Zl", "Zp"}}, {"separator", {"Zs", "Zl", "Zp"}},
        {"zs", {"Zs"}}, {"spaceseparator", {"Zs"}}, {"zl", {"Zl"}}, {"lineseparator", {"Zl"}},
        {"zp", {"Zp"}}, {"paragraphseparator", {"Zp"}},
        {"cc", {"Cc"}}, {"control", {"Cc"}}, {"cntrl", {"Cc"}}, {"cf", {"Cf"}}, {"format", {"Cf"}},
        {"cs", {"Cs"}}, {"surrogate", {"Cs"}}, {"co", {"Co"}}, {"privateuse", {"Co"}},
    };
    std::string name = loose(raw);
    CharSet s;
    if (name == "any") {
        s.add(0, kMaxCodepoint);
    } else if (name == "ascii") {
        s.add(0, 0x7F);
    } else if (name == "whitespace" || name == "space") {
        s = perl_space(true);
    } else if (name == "assigned" || name == "cn" || name == "unassigned" || name == "c" || name == "other") {
        CharSet assigned;
        for (auto& t : kGeneralCategories) assigned.add_table(t.ranges, t.count);
        assigned.canonicalize();
        if (name == "assigned") {
            s = assigned;
        } else {
            s = assigned;
            s.negate(kMaxCodepoint, false);  // Cn
            if (name == "c" || name == "other") add_categories(s, {"Cc", "Cf", "Cs", "Co"});
        }
    } else {
        bool found = false;
        for (auto& a : kAliases) {
            if (name == a.name) {
                add_categories(s, a.cats);
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    s.canonicalize();
    *out = s;
    return true;
}

bool posix_class(std::string_view name, CharSet* out) {
    CharSet s;
    if (name == "alnum") { s.add('0', '9'); s.add('A', 'Z'); s.add('a', 'z'); }
    else if (name == "alpha") { s.add('A', 'Z'); s.add('a', 'z'); }
    else if (name == "ascii") { s.add(0, 0x7F); }
    else if (name == "blank") { s.add('\t'); s.add(' '); }
    else if (name == "cntrl") { s.add(0, 0x1F); s.add(0x7F); }
    else if (name == "digit") { s.add('0', '9'); }
    else if (name == "graph") { s.add('!', '~'); }
    else if (name == "lower") { s.add('a', 'z'); }
    else if (name == "print") { s.add(' ', '~'); }
    else if (name == "punct") { s.add('!', '/'); s.add(':', '@'); s.add('[', '`'); s.add('{', '~'); }
    else if (name == "space") { s.add('\t', '\r'); s.add(' '); }
    else if (name == "upper") { s.add('A', 'Z'); }
    else if (name == "word") { s.add('0', '9'); s.add('A', 'Z'); s.add('a', 'z'); s.add('_'); }
    else if (name == "xdigit") { s.add('0', '9'); s.add('A', 'F'); s.add('a', 'f'); }
    else return false;
    s.canonicalize();
    *out = s;
    return true;
}

} // namespace bro::search::rx
