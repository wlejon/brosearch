#include "harness.h"

#include "brosearch/regex.h"
#include "regex/literal.h"
#include "regex/matcher.h"
#include "regex/pikevm.h"

#include <chrono>
#include <random>

using namespace bro::search;

namespace {

using Spans = std::vector<std::pair<size_t, size_t>>;

Spans all(std::string_view pat, std::string_view hay, RegexOptions o = RegexOptions()) {
    std::string err;
    auto re = Regex::compile(pat, o, &err);
    if (!re) {
        bt::fail(__FILE__, __LINE__, "compile failed for '" + std::string(pat) + "': " + err);
        return {};
    }
    Spans out;
    for (auto m : re->find_all(hay)) out.push_back({m.start, m.end});
    return out;
}

std::optional<std::pair<size_t, size_t>> first(std::string_view pat, std::string_view hay,
                                               RegexOptions o = RegexOptions()) {
    auto re = Regex::compile(pat, o);
    if (!re) {
        bt::fail(__FILE__, __LINE__, "compile failed for '" + std::string(pat) + "'");
        return std::nullopt;
    }
    auto m = re->find(hay);
    if (!m) return std::nullopt;
    return std::make_pair(m->start, m->end);
}

bool compiles(std::string_view pat, RegexOptions o = RegexOptions()) { return Regex::compile(pat, o) != nullptr; }

using P = std::pair<size_t, size_t>;

} // namespace

TEST(regex, leftmost_first) {
    CHECK_EQ(first("a", "bab"), std::optional<P>(P{1, 2}));
    CHECK_EQ(first("a+", "baaab"), std::optional<P>(P{1, 4}));
    CHECK_EQ(first("a|ab", "ab"), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("ab|a", "ab"), std::optional<P>(P{0, 2}));
    CHECK_EQ(first("a*?", "aaa"), std::optional<P>(P{0, 0}));
    CHECK_EQ(first("a+?", "aaa"), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("(?U)a+", "aaa"), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("x{2,3}", "xxxx"), std::optional<P>(P{0, 3}));
    CHECK_EQ(first("x{2,3}?", "xxxx"), std::optional<P>(P{0, 2}));
    CHECK_EQ(first("x{,2}y", "xxxy"), std::optional<P>(P{1, 4}));
    CHECK_EQ(first("x{2}", "x"), std::optional<P>());
    CHECK_EQ(first("b(a|ab)c", "xbabc"), std::optional<P>(P{1, 5}));
    CHECK_EQ(first("samwise|sam", "samwise"), std::optional<P>(P{0, 7}));
    CHECK_EQ(first("sam|samwise", "samwise"), std::optional<P>(P{0, 3}));
}

TEST(regex, find_all_empty_matches) {
    CHECK_EQ(all("", "ab"), (Spans{{0, 0}, {1, 1}, {2, 2}}));
    CHECK_EQ(all("a*", "baaa"), (Spans{{0, 0}, {1, 4}}));
    CHECK_EQ(all("\\b", "ab cd"), (Spans{{0, 0}, {2, 2}, {3, 3}, {5, 5}}));
    RegexOptions m;
    m.multi_line = true;
    CHECK_EQ(all("$", "a\nb", m), (Spans{{1, 1}, {3, 3}}));
    CHECK_EQ(all("^", "a\nb", m), (Spans{{0, 0}, {2, 2}}));
    CHECK_EQ(all("$", "a\nb"), (Spans{{3, 3}}));
    // Empty matches never split a UTF-8 sequence.
    CHECK_EQ(all("", "\xC3\xA9"), (Spans{{0, 0}, {2, 2}}));
}

TEST(regex, unicode_classes) {
    CHECK_EQ(first(".", "\xC3\xA9"), std::optional<P>(P{0, 2}));
    CHECK_EQ(first("(?-u:.)", "\xC3\xA9"), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("\\w+", "h\xC3\xA9llo w\xC3\xB6rld"), std::optional<P>(P{0, 6}));
    CHECK_EQ(first("(?-u)\\w+", "h\xC3\xA9llo"), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("\\d+", "x\xD9\xA3\xD9\xA4y"), std::optional<P>(P{1, 5}));  // Arabic-Indic digits
    CHECK_EQ(first("\\pL+", "12\xCE\xB1\xCE\xB2!"), std::optional<P>(P{2, 6}));
    CHECK_EQ(first("\\p{Lu}", "abcD"), std::optional<P>(P{3, 4}));
    CHECK_EQ(first("\\P{L}", "ab1"), std::optional<P>(P{2, 3}));
    CHECK_EQ(first("\\x{1F600}", "a\xF0\x9F\x98\x80"), std::optional<P>(P{1, 5}));
    CHECK_EQ(first("[^a]", "\xFF"), std::optional<P>());  // invalid UTF-8 is never a scalar value
    CHECK_EQ(first("(?-u:\\xFF)", "a\xFF"), std::optional<P>(P{1, 2}));
    CHECK_EQ(first("\\s", "a\xE2\x80\x83" "b"), std::optional<P>(P{1, 4}));  // EM SPACE
    CHECK_EQ(first("[[:alpha:]]+", "12ab3"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("[[:^digit:]]+", "12ab3"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("[a-z&&[^aeiou]]+", "aeixyz"), std::optional<P>(P{3, 6}));
    CHECK_EQ(first("[\\w--\\d]+", "12ab3"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("[a-c~~b-d]+", "bcad"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("[]a]+", "x]a]"), std::optional<P>(P{1, 4}));
    CHECK_EQ(first("[a-]+", "x-a-"), std::optional<P>(P{1, 4}));
}

TEST(regex, case_folding) {
    CHECK(first("(?i)hello", "HeLLo").has_value());
    CHECK(first("(?i)k", "\xE2\x84\xAA").has_value());        // KELVIN SIGN folds with k
    CHECK(first("(?i)s", "\xC5\xBF").has_value());            // LONG S folds with s
    CHECK(first("(?i)\xCE\xA3", "\xCF\x82").has_value());     // Sigma / final sigma
    CHECK(!first("(?i)stra\xC3\x9F" "e", "STRASSE").has_value());  // simple folding only (as rg)
    CHECK(first("(?i)[a-c]", "B").has_value());
    CHECK(!first("(?i)[^a]", "A").has_value());
    CHECK(first("a(?i)b", "aB").has_value());
    CHECK(!first("a(?i)b", "AB").has_value());
    CHECK(first("(?i:a)b", "Ab").has_value());
    CHECK(!first("(?i:a)b", "AB").has_value());
    CHECK(first("(?i)\xC3\xA9", "\xC3\x89").has_value());
    RegexOptions sc;
    sc.smart_case = true;
    CHECK(first("hello", "HELLO", sc).has_value());
    CHECK(!first("Hello", "HELLO", sc).has_value());
    CHECK(first("\\Whello", " HELLO", sc).has_value());  // escapes are not literals
}

TEST(regex, anchors_and_boundaries) {
    CHECK_EQ(first("^b", "a\nb"), std::optional<P>());
    RegexOptions m;
    m.multi_line = true;
    CHECK_EQ(first("^b", "a\nb", m), std::optional<P>(P{2, 3}));
    CHECK_EQ(first("a$", "a\r\nb", m), std::optional<P>());
    RegexOptions crlf = m;
    crlf.crlf = true;
    CHECK_EQ(first("a$", "a\r\nb", crlf), std::optional<P>(P{0, 1}));
    CHECK_EQ(first("^b", "a\r\nb", crlf), std::optional<P>(P{3, 4}));
    CHECK_EQ(first("\\Aa", "ba"), std::optional<P>());
    CHECK_EQ(first("a\\z", "ab"), std::optional<P>());
    CHECK_EQ(first("\\bfoo\\b", "a foo b"), std::optional<P>(P{2, 5}));
    CHECK_EQ(first("\\bfoo\\b", "\xC3\xA9" "foo"), std::optional<P>());  // é is a word char
    CHECK_EQ(first("(?-u:\\b)foo", "\xC3\xA9" "foo"), std::optional<P>(P{2, 5}));
    CHECK_EQ(first("\\Bfoo", "xfoo"), std::optional<P>(P{1, 4}));
    CHECK_EQ(first("\\<foo\\>", "foox foo"), std::optional<P>(P{5, 8}));
    CHECK_EQ(first("\\b{start}foo", "xfoo foo"), std::optional<P>(P{5, 8}));
    CHECK_EQ(first("foo\\b{end}", "foox foo"), std::optional<P>(P{5, 8}));
    CHECK_EQ(first("\\b{start-half}-foo", "x-foo -foo"), std::optional<P>(P{6, 10}));
    RegexOptions w;
    w.word = true;
    CHECK_EQ(first("-foo", "x-foo -foo", w), std::optional<P>(P{6, 10}));
    CHECK_EQ(first("foo", "foo_x foo", w), std::optional<P>(P{6, 9}));
    CHECK_EQ(first("#foo", "a#foo #foo#", w), std::optional<P>(P{6, 10}));
}

TEST(regex, script_properties) {
    // Greek alpha, Cyrillic a, Han, hiragana a, combining acute (Inherited), U+0951 (scx Deva...).
    CHECK_EQ(first("\\p{Greek}+", "ab\xCE\xB1\xCE\xB2z"), std::optional<P>(P{2, 6}));
    CHECK_EQ(first("\\p{sc=Grek}", "\xD0\xB0\xCE\xB1"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("\\p{Script=greek}", "\xCE\xB1"), std::optional<P>(P{0, 2}));
    CHECK_EQ(first("\\p{Cyrillic}", "\xCE\xB1\xD0\xB0"), std::optional<P>(P{2, 4}));
    CHECK_EQ(first("\\p{Han}", "a\xE4\xB8\xAD"), std::optional<P>(P{1, 4}));
    CHECK_EQ(first("\\P{Latin}", "ab1"), std::optional<P>(P{2, 3}));
    CHECK_EQ(first("[\\p{Hiragana}\\p{Greek}]+", "x\xE3\x81\x82\xCE\xB1"), std::optional<P>(P{1, 6}));
    CHECK_EQ(first("\\p{Inherited}", "e\xCC\x81"), std::optional<P>(P{1, 3}));
    // U+0951 DEVANAGARI STRESS SIGN UDATTA: sc=Inherited, scx lists Devanagari among others.
    CHECK_EQ(first("\\p{sc=Deva}", "\xE0\xA5\x91"), std::optional<P>());
    CHECK_EQ(first("\\p{scx=Deva}", "\xE0\xA5\x91"), std::optional<P>(P{0, 3}));
    CHECK_EQ(first("\\p{scx=Zinh}", "\xE0\xA5\x91"), std::optional<P>());
    // U+30FC KATAKANA-HIRAGANA PROLONGED SOUND MARK: sc=Common, scx={Hira, Kana}.
    CHECK_EQ(first("\\p{Hiragana}", "\xE3\x83\xBC"), std::optional<P>());
    CHECK_EQ(first("\\p{scx=Hira}", "\xE3\x83\xBC"), std::optional<P>(P{0, 3}));
    CHECK_EQ(first("\\p{Common}", "\xE3\x83\xBC"), std::optional<P>(P{0, 3}));
    // General categories win over a script of the same loose name (none collide today).
    CHECK_EQ(first("\\p{L}", "\xCE\xB1"), std::optional<P>(P{0, 2}));
}

TEST(regex, syntax_errors) {
    CHECK(!compiles("(a"));
    CHECK(!compiles("a)"));
    CHECK(!compiles("a{2,1}"));
    CHECK(!compiles("\\1"));
    CHECK(!compiles("*a"));
    CHECK(!compiles("[a"));
    CHECK(!compiles("[z-a]"));
    CHECK(!compiles("(?=a)"));
    CHECK(!compiles("\\p{NoSuchScript}"));
    CHECK(!compiles("\\p{scx=Bogus}"));
    // regex-syntax (rg) has no tables for these two recognised names.
    CHECK(!compiles("\\p{Unknown}"));
    CHECK(!compiles("\\p{sc=Zzzz}"));
    CHECK(!compiles("\\p{scx=Hrkt}"));
    CHECK(!compiles("\\q"));
    CHECK(!compiles("a{"));
    CHECK(!compiles("(?P<n>a)(?P<n>b)"));
    CHECK(compiles("(?P<n>a)(?<m>b)"));
    CHECK(compiles("\\.\\*\\+\\?\\(\\)\\[\\]\\{\\}\\|\\^\\$\\#\\&\\-\\~"));
    CHECK(compiles("(?x) a b # comment\n c"));
    CHECK_EQ(first("(?x) a b # comment\n c", "abc"), std::optional<P>(P{0, 3}));
    RegexOptions line;
    line.line_mode = true;
    CHECK(!compiles("a\\nb", line));
    CHECK(compiles("a[^b]c", line));
    CHECK_EQ(first("a[^b]c", "a\nc", line), std::optional<P>());
    CHECK_EQ(first("a\\sc", "a\nc", line), std::optional<P>());
    // \A and \z are line anchors in line mode (ripgrep).
    CHECK_EQ(first("\\Aabc", "x\nabc", line), std::optional<P>(P{2, 5}));
    CHECK_EQ(all("hello\\z", "first hello\nsecond\nthird hello", line), (Spans{{6, 11}, {25, 30}}));
    CHECK_EQ(all("o\\z", "o\nxo", line), (Spans{{0, 1}, {3, 4}}));
    // Size limit.
    std::string err;
    CHECK(Regex::compile("(((a{100}){100}){100}){10}", RegexOptions(), &err) == nullptr);
    CHECK(!err.empty());
}

TEST(regex, literal_mode) {
    RegexOptions lit;
    lit.literal = true;
    CHECK_EQ(first("a.b(", "xa.b(", lit), std::optional<P>(P{1, 5}));
    CHECK_EQ(first("a.b", "axb", lit), std::optional<P>());
    lit.case_insensitive = true;
    CHECK_EQ(first("HeLLo", "say hello", lit), std::optional<P>(P{4, 9}));
    CHECK_EQ(first("\xC3\xA9t\xC3\xA9", "\xC3\x89T\xC3\x89", lit), std::optional<P>(P{0, 5}));
    CHECK_EQ(first("k", "\xE2\x84\xAA", lit), std::optional<P>(P{0, 3}));
    // Invalid UTF-8 in a literal matches the raw bytes.
    lit.case_insensitive = false;
    CHECK_EQ(first("\xFF\xFE", "a\xFF\xFE", lit), std::optional<P>(P{1, 3}));
}

TEST(regex, pathological_linear_time) {
    auto t0 = std::chrono::steady_clock::now();
    std::string as(200000, 'a');
    CHECK(!first("(a*)*b", as).has_value());
    CHECK(!first("(x+x+)+y", std::string(100000, 'x')).has_value());
    CHECK(!first("(a|aa)+$b", as).has_value());
    CHECK(first("(a|a)*a{20}", as).has_value());
    CHECK(!first("(.*){20}z", as).has_value());
    // Unicode word boundary on non-ASCII text forces the PikeVM; still linear.
    std::string greek;
    for (int i = 0; i < 20000; ++i) greek += "\xCE\xB1\xCE\xB2 ";
    CHECK(!first("\\bzz\\b", greek).has_value());
    CHECK_EQ(all("\\b\xCE\xB1", greek).size(), size_t(20000));
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    CHECK_MSG(ms < 20000, "pathological suite took " << ms << " ms");
}

// The lazy DFA (+ reverse DFA) must agree with the PikeVM on every input.
TEST(regex, dfa_matches_pikevm_random) {
    static const char* const atoms[] = {"a", "b", "ab", "[ab]", "a*", "b+", "a?", "(a|b)", "(a|ab)", "^",
                                        "$", "\\b", "\\B", ".", "\xC3\xA9", "\\w", "(?i:A)", "[^a]", " ",
                                        "(?:ba)*", "\\b{start}", "\\b{end-half}", "a{2}", "(?-u:\\b)"};
    static const char* const hay_atoms[] = {"a", "b", " ", "\xC3\xA9", "\n", "A", "ab"};
    std::mt19937 rng(12345);
    int checked = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        std::string pat;
        int n = 1 + static_cast<int>(rng() % 4);
        for (int k = 0; k < n; ++k) {
            pat += atoms[rng() % (sizeof atoms / sizeof *atoms)];
            if (rng() % 7 == 0) pat += "|";
        }
        if (pat.back() == '|') pat.pop_back();
        RegexOptions o;
        o.multi_line = rng() % 2;
        auto re = Regex::compile(pat, o);
        if (!re) continue;
        std::string hay;
        int h = static_cast<int>(rng() % 12);
        for (int k = 0; k < h; ++k) hay += hay_atoms[rng() % (sizeof hay_atoms / sizeof *hay_atoms)];
        const auto* d = reinterpret_cast<const uint8_t*>(hay.data());
        bro::search::rx::PikeVm vm(re->matcher().forward());
        bro::search::rx::MatcherCache cache(re->matcher());
        for (size_t start = 0; start <= hay.size(); ++start) {
            auto a = re->matcher().find(cache, d, hay.size(), start, hay.size());
            auto b = vm.search(d, hay.size(), start, hay.size(), false);
            bool same = a.has_value() == b.has_value() && (!a || (a->start == b->start && a->end == b->end));
            CHECK_MSG(same, "pattern '" << pat << "' hay '" << hay << "' start " << start << ": dfa "
                                        << (a ? std::to_string(a->start) + "-" + std::to_string(a->end) : "none")
                                        << " pike "
                                        << (b ? std::to_string(b->start) + "-" + std::to_string(b->end) : "none"));
            if (!same) return;
            ++checked;
        }
    }
    CHECK(checked > 5000);
}

// Grep's line search (literal and rare-byte prefilters, then the DFA) must select exactly the lines
// the PikeVM finds a match in. Atoms favour rare bytes, alternations and Unicode case folds.
TEST(regex, find_line_matches_pikevm_random) {
    static const char* const atoms[] = {"X",  "Z|Q", "(?i:k)", "(?i:s)", "\xC3\xA9", "x+", "(XY|QZ)", "[XQ]",
                                        "\\w", "a",   "K*",     "\\b",    "^",        "$",  "(?i:sk)",  "[^Z]",
                                        "Q?", "(?:Z|\xE2\x84\xAA)", ".", " "};
    static const char* const hay_atoms[] = {"X", "Z", "Q", "a", " ", "\n", "k", "K", "\xE2\x84\xAA" /* KELVIN */,
                                            "\xC5\xBF" /* long s */, "s", "\xC3\xA9", "Y", "x"};
    std::mt19937 rng(777);
    int checked = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        std::string pat;
        int n = 1 + static_cast<int>(rng() % 3);
        for (int k = 0; k < n; ++k) {
            pat += atoms[rng() % (sizeof atoms / sizeof *atoms)];
            if (rng() % 5 == 0) pat += "|";
        }
        if (pat.back() == '|') pat.pop_back();
        RegexOptions o;
        o.multi_line = true;
        o.line_mode = true;
        o.case_insensitive = rng() % 3 == 0;
        auto re = Regex::compile(pat, o);
        if (!re) continue;
        std::string hay;
        int h = static_cast<int>(rng() % 30);
        for (int k = 0; k < h; ++k) hay += hay_atoms[rng() % (sizeof hay_atoms / sizeof *hay_atoms)];
        const auto* d = reinterpret_cast<const uint8_t*>(hay.data());
        const size_t len = hay.size();
        bro::search::rx::PikeVm vm(re->matcher().forward());
        bro::search::rx::MatcherCache cache(re->matcher());
        // Expected: start offsets of lines containing a match.
        std::vector<size_t> want, got;
        for (size_t ls = 0; ls <= len;) {
            size_t le = hay.find('\n', ls);
            if (le == std::string::npos) le = len;
            if (!(ls == len && ls > 0) && vm.search(d, len, ls, le, false)) want.push_back(ls);
            ls = le + 1;
        }
        for (size_t pos = 0; pos <= len;) {
            auto p = re->matcher().find_line(cache, d, len, pos, len);
            if (!p || (*p >= len && len > 0 && hay[len - 1] == '\n')) break;
            size_t ls = *p;
            while (ls > pos && hay[ls - 1] != '\n') --ls;
            got.push_back(ls);
            size_t le = hay.find('\n', *p);
            if (le == std::string::npos) break;
            pos = le + 1;
        }
        CHECK_MSG(want == got, "pattern '" << pat << "' hay '" << hay << "': lines differ (" << want.size()
                                           << " expected, " << got.size() << " found)");
        if (want != got) return;
        ++checked;
    }
    CHECK(checked > 2000);
}

// LiteralFinder against a naive scan. Literals over common bytes take the packed-pair path
// (16 candidates per step, then a scalar tail); short haystacks, literals planted at the very end,
// ranges starting mid-buffer and ASCII-case-insensitive bytes probe its block and tail edges.
TEST(regex, literal_finder_matches_naive_search) {
    using rx::LitByte;
    CHECK(rx::byte_rank('e') > 90 && rx::byte_rank(' ') > 90);  // the pair path is exercised
    std::mt19937 rng(20261004);
    auto rnd = [&](size_t n) { return static_cast<size_t>(rng() % n); };
    const std::string alphabets[] = {"et ", "eEtT ", "ab", std::string("e\xC3z"), "qx"};
    size_t checked = 0;
    for (int iter = 0; iter < 6000; ++iter) {
        const std::string& alpha = alphabets[iter % 5];
        const bool ci_any = iter % 3 == 0;
        const size_t n = 2 + rnd(19);
        rx::Literal lit;
        for (size_t i = 0; i < n; ++i) {
            const auto c = static_cast<uint8_t>(alpha[rnd(alpha.size())]);
            const bool letter = (c | 0x20) >= 'a' && (c | 0x20) <= 'z';
            const bool ci = ci_any && letter && rnd(2) == 1;
            lit.push_back(LitByte{ci ? static_cast<uint8_t>(c | 0x20) : c, ci});
        }
        const size_t hl = rnd(90);
        std::string hay;
        for (size_t i = 0; i < hl; ++i) hay.push_back(alpha[rnd(alpha.size())]);
        if (hl >= n && rnd(2) == 1) {
            const size_t at = rnd(2) == 1 ? hl - n : rnd(hl - n + 1);
            for (size_t i = 0; i < n; ++i) {
                uint8_t c = lit[i].b;
                if (lit[i].ci && rnd(2) == 1) c = static_cast<uint8_t>(c - 32);
                hay[at + i] = static_cast<char>(c);
            }
        }
        const size_t start = rnd(hl + 1);
        const size_t end = start + rnd(hl - start + 1);
        size_t want = SIZE_MAX;
        for (size_t p = start; p + n <= end && want == SIZE_MAX; ++p) {
            bool ok = true;
            for (size_t i = 0; i < n && ok; ++i) {
                const auto c = static_cast<uint8_t>(hay[p + i]);
                ok = lit[i].ci ? static_cast<uint8_t>(c | 0x20) == lit[i].b : c == lit[i].b;
            }
            if (ok) want = p;
        }
        const rx::LiteralFinder f(lit);
        const size_t got = f.find(reinterpret_cast<const uint8_t*>(hay.data()), start, end);
        CHECK_MSG(got == want, "literal finder: iter " << iter << " got " << got << " want " << want);
        if (got != want) return;
        ++checked;
    }
    CHECK(checked == 6000);
}
