// gitignore matcher unit tests. The wildmatch table is git's t/t3070-wildmatch.sh (the "wildmatch"
// = WM_PATHNAME column, and "iwildmatch" for the case-folding rows); the rule-level cases were
// checked against `git check-ignore` / `git ls-files --exclude-standard`.

#include "harness.h"

#include "brosearch/ignore.h"

using namespace bro::search;

namespace {

struct WildCase {
    const char* text;
    const char* pattern;
    int match;   // WM_PATHNAME, case-sensitive
    int imatch;  // WM_PATHNAME | WM_CASEFOLD (-1: same as match)
};

const WildCase kWild[] = {
    {"foo", "foo", 1, -1},
    {"foo", "bar", 0, -1},
    {"", "", 1, -1},
    {"foo", "???", 1, -1},
    {"foo", "??", 0, -1},
    {"foo", "*", 1, -1},
    {"foo", "f*", 1, -1},
    {"foo", "*f", 0, -1},
    {"foo", "*foo*", 1, -1},
    {"foobar", "*ob*a*r*", 1, -1},
    {"aaaaaaabababab", "*ab", 1, -1},
    {"foo*", R"(foo\*)", 1, -1},
    {"foobar", R"(foo\*bar)", 0, -1},
    {R"(f\oo)", R"(f\\oo)", 1, -1},
    {"ball", "*[al]?", 1, -1},
    {"ten", "[ten]", 0, -1},
    {"ten", "**[!te]", 1, -1},
    {"ten", "**[!ten]", 0, -1},
    {"ten", "t[a-g]n", 1, -1},
    {"ten", "t[!a-g]n", 0, -1},
    {"ton", "t[!a-g]n", 1, -1},
    {"ton", "t[^a-g]n", 1, -1},
    {"a]b", "a[]]b", 1, -1},
    {"a-b", "a[]-]b", 1, -1},
    {"a]b", "a[]-]b", 1, -1},
    {"aab", "a[]-]b", 0, -1},
    {"aab", "a[]a-]b", 1, -1},
    {"]", "]", 1, -1},
    // Slash handling.
    {"foo/baz/bar", "foo*bar", 0, -1},
    {"foo/baz/bar", "foo**bar", 0, -1},
    {"foobazbar", "foo**bar", 1, -1},
    {"foo/baz/bar", "foo/**/bar", 1, -1},
    {"foo/baz/bar", "foo/**/**/bar", 1, -1},
    {"foo/b/a/z/bar", "foo/**/bar", 1, -1},
    {"foo/b/a/z/bar", "foo/**/**/bar", 1, -1},
    {"foo/bar", "foo/**/bar", 1, -1},
    {"foo/bar", "foo/**/**/bar", 1, -1},
    {"foo/bar", "foo?bar", 0, -1},
    {"foo/bar", "foo[/]bar", 0, -1},
    {"foo/bar", "foo[^a-z]bar", 0, -1},
    {"foo/bar", "f[^eiu][^eiu][^eiu][^eiu][^eiu]r", 0, -1},
    {"foo-bar", "f[^eiu][^eiu][^eiu][^eiu][^eiu]r", 1, -1},
    {"foo", "**/foo", 1, -1},
    {"XXX/foo", "**/foo", 1, -1},
    {"bar/baz/foo", "**/foo", 1, -1},
    {"bar/baz/foo", "*/foo", 0, -1},
    {"foo/bar/baz", "**/bar*", 0, -1},
    {"deep/foo/bar/baz", "**/bar/*", 1, -1},
    {"deep/foo/bar/baz/", "**/bar/*", 0, -1},
    {"deep/foo/bar/baz/", "**/bar/**", 1, -1},
    {"deep/foo/bar", "**/bar/*", 0, -1},
    {"deep/foo/bar/", "**/bar/**", 1, -1},
    {"foo/bar/baz", "**/bar**", 0, -1},
    {"foo/bar/baz/x", "*/bar/**", 1, -1},
    {"deep/foo/bar/baz/x", "*/bar/**", 0, -1},
    {"deep/foo/bar/baz/x", "**/bar/*/*", 1, -1},
    // Misc, including malformed patterns.
    {"acrt", "a[c-c]st", 0, -1},
    {"acrt", "a[c-c]rt", 1, -1},
    {"]", "[!]-]", 0, -1},
    {"a", "[!]-]", 1, -1},
    {"", R"(\)", 0, -1},
    {R"(\)", R"(\)", 0, -1},
    {R"(XXX/\)", R"(*/\)", 0, -1},
    {R"(XXX/\)", R"(*/\\)", 1, -1},
    {"@foo", "@foo", 1, -1},
    {"foo", "@foo", 0, -1},
    {"[ab]", R"(\[ab])", 1, -1},
    {"[ab]", "[[]ab]", 1, -1},
    {"[ab]", "[[:]ab]", 1, -1},
    {"[ab]", "[[::]ab]", 0, -1},
    {"[ab]", "[[:digit]ab]", 1, -1},
    {"[ab]", R"([\[:]ab])", 1, -1},
    {"?a?b", R"(\??\?b)", 1, -1},
    {"abc", R"(\a\b\c)", 1, -1},
    {"foo", "", 0, -1},
    {"foo/bar/baz/to", "**/t[o]", 1, -1},
    // POSIX classes.
    {"a1B", "[[:alpha:]][[:digit:]][[:upper:]]", 1, -1},
    {"a", "[[:digit:][:upper:][:space:]]", 0, 1},
    {"A", "[[:digit:][:upper:][:space:]]", 1, -1},
    {"1", "[[:digit:][:upper:][:space:]]", 1, -1},
    {"1", "[[:digit:][:upper:][:spaci:]]", 0, -1},
    {" ", "[[:digit:][:upper:][:space:]]", 1, -1},
    {".", "[[:digit:][:upper:][:space:]]", 0, -1},
    {".", "[[:digit:][:punct:][:space:]]", 1, -1},
    {"5", "[[:xdigit:]]", 1, -1},
    {"f", "[[:xdigit:]]", 1, -1},
    {"D", "[[:xdigit:]]", 1, -1},
    {"_", "[[:alnum:][:alpha:][:blank:][:cntrl:][:digit:][:graph:][:lower:][:print:][:punct:][:space:][:upper:][:xdigit:]]", 1, -1},
    {".", "[^[:alnum:][:alpha:][:blank:][:cntrl:][:digit:][:lower:][:space:][:upper:][:xdigit:]]", 1, -1},
    {"5", "[a-c[:digit:]x-z]", 1, -1},
    {"b", "[a-c[:digit:]x-z]", 1, -1},
    {"y", "[a-c[:digit:]x-z]", 1, -1},
    {"q", "[a-c[:digit:]x-z]", 0, -1},
    // Escapes and ranges inside classes.
    {"]", R"([\\-^])", 1, -1},
    {"[", R"([\\-^])", 0, -1},
    {"-", R"([\-_])", 1, -1},
    {"]", R"([\]])", 1, -1},
    {R"(\])", R"([\]])", 0, -1},
    {R"(\)", R"([\]])", 0, -1},
    {"ab", "a[]b", 0, -1},
    {"a[]b", "a[]b", 0, -1},
    {"ab[", "ab[", 0, -1},
    {"ab", "[!", 0, -1},
    {"ab", "[-", 0, -1},
    {"-", "[-]", 1, -1},
    {"-", "[a-", 0, -1},
    {"-", "[!a-", 0, -1},
    {"-", "[--A]", 1, -1},
    {"5", "[--A]", 1, -1},
    {" ", "[ --]", 1, -1},
    {"$", "[ --]", 1, -1},
    {"-", "[ --]", 1, -1},
    {"0", "[ --]", 0, -1},
    {"-", "[---]", 1, -1},
    {"-", "[------]", 1, -1},
    {"j", "[a-e-n]", 0, -1},
    {"-", "[a-e-n]", 1, -1},
    {"a", "[!------]", 1, -1},
    {"[", "[]-a]", 0, -1},
    {"^", "[]-a]", 1, -1},
    {"^", "[!]-a]", 0, -1},
    {"[", "[!]-a]", 1, -1},
    {"^", "[a^bc]", 1, -1},
    {"-b]", "[a-]b]", 1, -1},
    {R"(\)", R"([\])", 0, -1},
    {R"(\)", R"([\\])", 1, -1},
    {R"(\)", R"([!\\])", 0, -1},
    {"G", R"([A-\\])", 1, -1},
    {"aaabbb", "b*a", 0, -1},
    {"aabcaa", "*ba*", 0, -1},
    {",", "[,]", 1, -1},
    {",", R"([\\,])", 1, -1},
    {R"(\)", R"([\\,])", 1, -1},
    {"-", "[,-.]", 1, -1},
    {"+", "[,-.]", 0, -1},
    {"-.]", "[,-.]", 0, -1},
    {"2", R"([\1-\3])", 1, -1},
    {"3", R"([\1-\3])", 1, -1},
    {"4", R"([\1-\3])", 0, -1},
    {R"(\)", R"([[-\]])", 1, -1},
    {"[", R"([[-\]])", 1, -1},
    {"]", R"([[-\]])", 1, -1},
    {"-", R"([[-\]])", 0, -1},
    // Recursion.
    {"-adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1", "-*-*-*-*-*-*-12-*-*-*-m-*-*-*", 1, -1},
    {"-adobe-courier-bold-o-normal--12-120-75-75-X-70-iso8859-1", "-*-*-*-*-*-*-12-*-*-*-m-*-*-*", 0, -1},
    {"-adobe-courier-bold-o-normal--12-120-75-75-/-70-iso8859-1", "-*-*-*-*-*-*-12-*-*-*-m-*-*-*", 0, -1},
    {"XXX/adobe/courier/bold/o/normal//12/120/75/75/m/70/iso8859/1", "XXX/*/*/*/*/*/*/12/*/*/*/m/*/*/*", 1, -1},
    {"XXX/adobe/courier/bold/o/normal//12/120/75/75/X/70/iso8859/1", "XXX/*/*/*/*/*/*/12/*/*/*/m/*/*/*", 0, -1},
    {"abcd/abcdefg/abcdefghijk/abcdefghijklmnop.txt", "**/*a*b*g*n*t", 1, -1},
    {"abcd/abcdefg/abcdefghijk/abcdefghijklmnop.txtz", "**/*a*b*g*n*t", 0, -1},
    {"foo", "*/*/*", 0, -1},
    {"foo/bar", "*/*/*", 0, -1},
    {"foo/bba/arr", "*/*/*", 1, -1},
    {"foo/bb/aa/rr", "*/*/*", 0, -1},
    {"foo/bb/aa/rr", "**/**/**", 1, -1},
    {"abcXdefXghi", "*X*i", 1, -1},
    {"ab/cXd/efXg/hi", "*X*i", 0, -1},
    {"ab/cXd/efXg/hi", "*/*X*/*/*i", 1, -1},
    {"ab/cXd/efXg/hi", "**/*X*/**/*i", 1, -1},
    // Case folding.
    {"a", "[A-Z]", 0, 1},
    {"A", "[A-Z]", 1, 1},
    {"A", "[a-z]", 0, 1},
    {"a", "[a-z]", 1, 1},
    {"a", "[[:upper:]]", 0, 1},
    {"A", "[[:upper:]]", 1, 1},
    {"A", "[[:lower:]]", 0, 1},
    {"a", "[[:lower:]]", 1, 1},
    {"A", "[B-Za]", 0, 1},
    {"a", "[B-Za]", 1, 1},
    {"A", "[B-a]", 0, 1},
    {"a", "[B-a]", 1, 1},
    {"z", "[Z-y]", 0, 1},
    {"Z", "[Z-y]", 1, 1},
};

} // namespace

TEST(ignore, wildmatch_table) {
    for (const auto& c : kWild) {
        bool m = glob_match(c.pattern, c.text, false, true);
        CHECK_MSG(m == (c.match == 1), "text '" << c.text << "' pattern '" << c.pattern << "' expected " << c.match);
        int ie = c.imatch < 0 ? c.match : c.imatch;
        bool im = glob_match(c.pattern, c.text, true, true);
        CHECK_MSG(im == (ie == 1), "icase: text '" << c.text << "' pattern '" << c.pattern << "' expected " << ie);
    }
}

TEST(ignore, wildmatch_without_pathname) {
    // Without WM_PATHNAME, '*', '?' and classes cross '/'.
    CHECK(glob_match("foo*bar", "foo/baz/bar", false, false));
    CHECK(glob_match("foo?bar", "foo/bar", false, false));
    CHECK(glob_match("foo[/]bar", "foo/bar", false, false));
    CHECK(glob_match("**/bar*", "foo/bar/baz", false, false));
    CHECK(!glob_match("foo?bar", "foo/bar", false, true));
}

namespace {

IgnoreMatch m1(std::string_view rules, std::string_view path, bool is_dir = false, bool icase = false) {
    Gitignore gi;
    gi.add_content(rules);
    return gi.match(path, is_dir, icase);
}

IgnoreMatch r1(std::string_view rules, std::string_view path, bool is_dir = false, bool icase = false) {
    Gitignore gi(IgnoreDialect::Rg);
    gi.add_content(rules);
    return gi.match(path, is_dir, icase);
}

} // namespace

// ripgrep's globs (globset); the rg_*.spec walk trees hold the same cases against rg itself.
TEST(ignore, rg_glob_syntax) {
    CHECK(rg_glob_match("[[:digit:]]x", ":]x"));
    CHECK(!rg_glob_match("[[:digit:]]x", "1x"));
    CHECK(rg_glob_match("[\\]]x", "\\]x"));
    CHECK(!rg_glob_match("[\\]]x", "]x"));
    CHECK(rg_glob_match("[a-c-e]", "d"));
    CHECK(!rg_glob_match("[a-c-e]", "-"));
    CHECK(rg_glob_match("[a-]", "-"));
    CHECK(rg_glob_match("[!]]", "x"));
    CHECK(!rg_glob_match("[!]]", "]"));
    CHECK(rg_glob_match("a[!b]c", "a/c"));
    CHECK(rg_glob_match("a[/]c", "a/c"));
    CHECK(!rg_glob_match("a?c", "a/c"));
    CHECK(!rg_glob_match("a*c", "a/c"));
    CHECK(rg_glob_match("x[ab", "x[ab"));
    CHECK(!rg_glob_match("x[ab", "xa"));
    CHECK(rg_glob_match("{p,q}z", "qz"));
    CHECK(rg_glob_match("k{,1}m", "k1m"));
    CHECK(!rg_glob_match("k{,1}m", "km"));
    CHECK(rg_glob_match("a{b,{c,d}}e", "ade"));
    CHECK(rg_glob_match("f{}g", "fg"));
    CHECK(rg_glob_match("a,b", "a,b"));
    CHECK(rg_glob_match("**", "a/b"));
    CHECK(rg_glob_match("**/x", "x"));
    CHECK(rg_glob_match("**/x", "a/b/x"));
    CHECK(rg_glob_match("a/**/b", "a/b"));
    CHECK(rg_glob_match("a/**/b", "a/x/y/b"));
    CHECK(rg_glob_match("a/**", "a/x/y"));
    CHECK(!rg_glob_match("a/**", "a"));
    CHECK(rg_glob_match("a**b", "axxb"));
    CHECK(!rg_glob_match("a**b", "a/b"));
    // Bytewise, like globset's (?-u) regex: '?' is one byte, a class member's bytes are members.
    CHECK(rg_glob_match("caf\xC3\xA9", "caf\xC3\xA9"));
    CHECK(rg_glob_match("?", "\xC3"));
    CHECK(!rg_glob_match("?", "\xC3\xA9"));
    CHECK(rg_glob_match("[\xC3\xA9]", "\xA9"));
    // ASCII case folding; a negated class folds before negating.
    CHECK(rg_glob_match("ABC", "abc", true));
    CHECK(!rg_glob_match("ABC", "abc", false));
    CHECK(rg_glob_match("[a-c]", "B", true));
    CHECK(!rg_glob_match("[^a]", "A", true));
    CHECK(!rg_glob_match("\xC3\xA9", "\xC3\x89", true));
    std::string err;
    CHECK(!rg_glob_valid("n{a,b", &err));
    CHECK(!err.empty());
    CHECK(!rg_glob_valid("o}r"));
    CHECK(!rg_glob_valid("[z-a]"));
    CHECK(!rg_glob_valid("[a--]"));
    CHECK(!rg_glob_valid("a\\"));
    CHECK(rg_glob_valid("a\\/"));
}

TEST(ignore, rg_dialect_lines) {
    // All trailing whitespace goes unless the line ends in "\ " (git keeps tabs).
    CHECK(r1("tab\t\n", "tab") == IgnoreMatch::Ignore);
    CHECK(m1("tab\t\n", "tab") == IgnoreMatch::None);
    CHECK(r1("nb\xC2\xA0\n", "nb") == IgnoreMatch::Ignore);
    CHECK(r1("esc\\ \n", "esc ") == IgnoreMatch::Ignore);
    CHECK(r1("esc\\ \n", "esc") == IgnoreMatch::None);
    // "esc\  " trims to a dangling backslash: an error, so no rule (git keeps "esc ").
    CHECK(r1("esc\\  \n", "esc ") == IgnoreMatch::None);
    CHECK(m1("esc\\  \n", "esc ") == IgnoreMatch::Ignore);
    CHECK(r1("[[:digit:]]\n", "1") == IgnoreMatch::None);
    CHECK(m1("[[:digit:]]\n", "1") == IgnoreMatch::Ignore);
    CHECK(r1("a[!b]c\n", "x/a/c") == IgnoreMatch::Ignore);
    CHECK(r1("*.a\n!\n", "x.a") == IgnoreMatch::Whitelist);
    CHECK(m1("*.a\n!\n", "x.a") == IgnoreMatch::Ignore);
    CHECK(r1("a\n\xFF\nb\n", "a") == IgnoreMatch::Ignore);
    CHECK(r1("a\n\xFF\nb\n", "b") == IgnoreMatch::None);
    CHECK(r1("foo/**\n", "foo", true) == IgnoreMatch::None);
    CHECK(r1("foo/**\n", "foo/x") == IgnoreMatch::Ignore);
    CHECK(r1("j\\/\n", "j", true) == IgnoreMatch::Ignore);
    CHECK(r1("j\\/\n", "j", false) == IgnoreMatch::None);
    CHECK(r1("\\!x\n", "!x") == IgnoreMatch::Ignore);
    CHECK(r1("/top\n", "top") == IgnoreMatch::Ignore);
    CHECK(r1("/top\n", "a/top") == IgnoreMatch::None);
    CHECK(r1("lit\n", "a/b/lit") == IgnoreMatch::Ignore);
    CHECK(r1("*.c\n", "a/B.C", false, true) == IgnoreMatch::Ignore);
    Gitignore g(IgnoreDialect::Rg);
    g.add_content("{a,b\n[z-a]\nok\n");
    CHECK_EQ(g.size(), static_cast<size_t>(1));
}

TEST(ignore, rule_parsing) {
    Gitignore gi;
    gi.add_content("# comment\n\n   \n\\#hash\n\\!bang\n!neg\ndir/\n/anchored\nmid/dle\n*.o\nlit\n");
    const auto& r = gi.rules();
    CHECK_EQ(r.size(), static_cast<size_t>(8));
    CHECK_EQ(r[0].pattern, std::string("\\#hash"));
    CHECK(!r[0].negated);
    CHECK(r[2].negated);
    CHECK_EQ(r[2].pattern, std::string("neg"));
    CHECK(r[3].dir_only && r[3].basename_only);
    CHECK(!r[4].basename_only);
    CHECK_EQ(r[4].pattern, std::string("anchored"));
    CHECK(!r[5].basename_only);
    CHECK(r[6].kind == IgnoreRule::Kind::Suffix);
    CHECK(r[7].kind == IgnoreRule::Kind::Literal);
    CHECK_EQ(gi.whitelist_count(), static_cast<size_t>(1));
}

TEST(ignore, escapes_and_comments) {
    CHECK(m1("\\#hash\n", "#hash") == IgnoreMatch::Ignore);
    CHECK(m1("#hash\n", "#hash") == IgnoreMatch::None);
    CHECK(m1("\\!bang\n", "!bang") == IgnoreMatch::Ignore);
    CHECK(m1("!bang\n", "bang") == IgnoreMatch::Whitelist);
}

TEST(ignore, trailing_whitespace) {
    // Unescaped trailing spaces are trimmed; "\ " keeps one; tabs are not trimmed (git).
    CHECK(m1("trail   \n", "trail") == IgnoreMatch::Ignore);
    CHECK(m1("trail   \n", "trail ") == IgnoreMatch::None);
    CHECK(m1("esc\\ \n", "esc ") == IgnoreMatch::Ignore);
    CHECK(m1("esc\\ \n", "esc") == IgnoreMatch::None);
    CHECK(m1("esc\\  \n", "esc ") == IgnoreMatch::Ignore);
    CHECK(m1("tab\t\n", "tab\t") == IgnoreMatch::Ignore);
    CHECK(m1("tab\t\n", "tab") == IgnoreMatch::None);
    CHECK(m1("a b \n", "a b") == IgnoreMatch::Ignore);
}

TEST(ignore, crlf_and_bom) {
    CHECK(m1("\xEF\xBB\xBF*.log\r\n!keep.log\r\n", "a.log") == IgnoreMatch::Ignore);
    CHECK(m1("\xEF\xBB\xBF*.log\r\n!keep.log\r\n", "keep.log") == IgnoreMatch::Whitelist);
    CHECK(m1("first\r\nlast", "last") == IgnoreMatch::Ignore);
    CHECK(m1("first\r\nlast", "first") == IgnoreMatch::Ignore);
}

TEST(ignore, anchoring_and_basename) {
    CHECK(m1("foo\n", "a/b/foo") == IgnoreMatch::Ignore);
    CHECK(m1("/foo\n", "a/foo") == IgnoreMatch::None);
    CHECK(m1("/foo\n", "foo") == IgnoreMatch::Ignore);
    CHECK(m1("a/foo\n", "x/a/foo") == IgnoreMatch::None);
    CHECK(m1("a/foo\n", "a/foo") == IgnoreMatch::Ignore);
    CHECK(m1("*.c\n", "dir/x.c") == IgnoreMatch::Ignore);
    CHECK(m1("d*/x.c\n", "dir/x.c") == IgnoreMatch::Ignore);
    CHECK(m1("d*/x.c\n", "a/dir/x.c") == IgnoreMatch::None);
}

TEST(ignore, dir_only) {
    CHECK(m1("build/\n", "build", true) == IgnoreMatch::Ignore);
    CHECK(m1("build/\n", "build", false) == IgnoreMatch::None);
    CHECK(m1("build/\n", "x/build", true) == IgnoreMatch::Ignore);
    CHECK(m1("/build/\n", "x/build", true) == IgnoreMatch::None);
}

TEST(ignore, doublestar) {
    CHECK(m1("**/logs\n", "logs", true) == IgnoreMatch::Ignore);
    CHECK(m1("**/logs\n", "a/b/logs", true) == IgnoreMatch::Ignore);
    CHECK(m1("out/**\n", "out", true) == IgnoreMatch::None);
    CHECK(m1("out/**\n", "out/a/b") == IgnoreMatch::Ignore);
    CHECK(m1("a/**/b\n", "a/b") == IgnoreMatch::Ignore);
    CHECK(m1("a/**/b\n", "a/x/y/b") == IgnoreMatch::Ignore);
    CHECK(m1("a/**/b\n", "a/xb") == IgnoreMatch::None);
}

TEST(ignore, last_match_wins) {
    CHECK(m1("*.o\n!keep.o\n", "keep.o") == IgnoreMatch::Whitelist);
    CHECK(m1("!keep.o\n*.o\n", "keep.o") == IgnoreMatch::Ignore);
}

TEST(ignore, case_folding_is_ascii) {
    CHECK(m1("*.TXT\n", "a.txt", false, true) == IgnoreMatch::Ignore);
    CHECK(m1("*.TXT\n", "a.txt", false, false) == IgnoreMatch::None);
    CHECK(m1("Build/\n", "build", true, true) == IgnoreMatch::Ignore);
    CHECK(m1("Read*Me\n", "readxme", false, true) == IgnoreMatch::Ignore);
    // Non-ASCII letters are not folded (git's core.ignorecase folds ASCII only).
    CHECK(m1("\xC3\x89t\xC3\xA9\n", "\xC3\xA9t\xC3\xA9", false, true) == IgnoreMatch::None);
}

TEST(ignore, filter_bases_and_precedence) {
    IgnoreFilter f(CaseMode::Sensitive);
    f.add_rules("*.log\nbuild/\n");
    f.add_rules("!keep.log\n*.tmp\n", "sub");
    f.add_rules("!x.tmp\n", "sub/deeper");
    CHECK(f.is_ignored("a.log"));
    CHECK(!f.is_ignored("sub/keep.log"));
    CHECK(f.is_ignored("keep.log"));
    CHECK(f.is_ignored("sub/x.tmp"));
    CHECK(!f.is_ignored("sub/deeper/x.tmp"));
    CHECK(!f.is_ignored("x.tmp"));
    CHECK(f.match("sub/keep.log", false) == IgnoreMatch::Whitelist);
    CHECK(f.match("other.txt", false) == IgnoreMatch::None);
    CHECK_EQ(f.rule_count(), static_cast<size_t>(5));
}

TEST(ignore, filter_no_reinclude_below_excluded_dir) {
    IgnoreFilter f(CaseMode::Sensitive);
    f.add_rules("excl/\n!excl/inner.txt\n");
    CHECK(f.is_ignored("excl/inner.txt"));
    CHECK(f.match("excl/inner.txt", false) == IgnoreMatch::Whitelist);  // rule-level view
    f.add_rules("dir/*\n!dir/keep/\n");
    CHECK(!f.is_ignored("dir/keep/a"));
    CHECK(f.is_ignored("dir/other/a"));
}

TEST(ignore, filter_path_normalization) {
    IgnoreFilter f(CaseMode::Sensitive);
    f.add_rules("/top.txt\n", "./sub/");
    CHECK(f.is_ignored("sub/top.txt"));
    CHECK(f.is_ignored("./sub/top.txt"));
    CHECK(f.is_ignored(std::filesystem::path("sub") / "top.txt"));
#ifdef _WIN32
    CHECK(f.is_ignored("sub\\top.txt"));
#endif
    CHECK(!f.is_ignored("sub/x/top.txt"));
}

TEST(ignore, filter_load_file_empty_base) {
    // A file loaded with no explicit base: relative to the filter root, or the root itself.
    auto dir = bt::scratch_dir("ignore_load_file");
    bt::write_file(dir / ".gitignore", "*.o\n/only_root\n");
    bt::write_file(dir / "sub" / ".gitignore", "/anchored\n");

    IgnoreFilter plain(CaseMode::Sensitive);
    CHECK(plain.load_file(dir / ".gitignore"));
    CHECK(plain.is_ignored("x.o"));
    CHECK(plain.is_ignored("only_root"));
    CHECK(!plain.is_ignored("a/only_root"));

    IgnoreFilter rooted(dir, CaseMode::Sensitive);
    CHECK(rooted.load_file(dir / ".gitignore"));
    CHECK(rooted.load_file(dir / "sub" / ".gitignore"));
    CHECK(rooted.is_ignored("sub/anchored"));
    CHECK(!rooted.is_ignored("anchored"));
    CHECK(rooted.is_ignored(dir / "sub" / "anchored"));  // absolute path under the root
    CHECK(rooted.is_ignored(dir / "deep" / "y.o"));
    CHECK(!rooted.is_ignored(dir / "keep.c"));
    CHECK(!rooted.load_file(dir / "missing"));
}

TEST(ignore, filter_case_modes) {
    IgnoreFilter s(CaseMode::Sensitive);
    s.add_rules("*.TXT\n", "Sub");
    CHECK(!s.is_ignored("Sub/a.txt"));
    CHECK(!s.is_ignored("sub/a.TXT"));
    IgnoreFilter i(CaseMode::Insensitive);
    i.add_rules("*.TXT\n", "Sub");
    CHECK(i.is_ignored("Sub/a.txt"));
    CHECK(i.is_ignored("sub/a.TXT"));

    // Auto inside a repository reads core.ignorecase.
    auto dir = bt::scratch_dir("ignore_auto_case");
    bt::write_file(dir / ".git" / "config", "[core]\n\tbare = false\n\tIgnoreCase = true ; comment\n");
    IgnoreFilter a(dir, CaseMode::Auto);
    CHECK(a.case_insensitive());
    bt::write_file(dir / ".git" / "config", "[core]\n\tignorecase = false\n[core \"x\"]\n\tignorecase = true\n");
    IgnoreFilter b(dir, CaseMode::Auto);
    CHECK(!b.case_insensitive());
}
