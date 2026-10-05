// Direct port of fzf v0.74.4 src/algo/algo_test.go: the same inputs, patterns, expected spans and
// score formulas, run against the internal algorithm entry points.

#include "harness.h"

#include "fuzzy/fuzzy_algo.h"

#include <algorithm>

using namespace bro::search::fuzzy_detail;

namespace {

const Scheme& def() {
    static const Scheme s = make_scheme(SchemeKind::Default, false);
    return s;
}

constexpr int scoreMatch = kScoreMatch, scoreGapStart = kScoreGapStart, scoreGapExtension = kScoreGapExtension;
constexpr int bonusBoundary = kBonusBoundary, bonusNonWord = kBonusNonWord, bonusCamel123 = kBonusCamel123;
constexpr int bonusConsecutive = kBonusConsecutive, bonusFirstCharMultiplier = kBonusFirstCharMultiplier;
constexpr int bonusBoundaryWhite = kBonusBoundary + 2, bonusBoundaryDelimiter = kBonusBoundary + 1;

void assert_match2(AlgoFn fn, const char* fname, bool case_sensitive, bool normalize, bool forward,
                   std::string_view input, std::string_view pattern, int sidx, int eidx, int score) {
    std::vector<uint32_t> pat;
    decode_runes(pattern, pat, nullptr);
    if (!case_sensitive)
        for (auto& c : pat) c = to_lower(c);
    std::vector<uint32_t> runes;
    bool ascii = std::all_of(input.begin(), input.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    Chars chars;
    if (ascii) {
        chars.bytes = reinterpret_cast<const unsigned char*>(input.data());
        chars.n = static_cast<int32_t>(input.size());
    } else {
        decode_runes(input, runes, nullptr);
        chars.runes = runes.data();
        chars.n = static_cast<int32_t>(runes.size());
    }
    Slab slab;
    std::vector<int32_t> pos;
    AlgoResult r = fn(def(), case_sensitive, normalize, forward, chars, pat.data(), static_cast<int32_t>(pat.size()),
                      &pos, slab);
    int start, end;
    if (pos.empty()) {
        start = r.start;
        end = r.end;
    } else {
        std::sort(pos.begin(), pos.end());
        start = pos.front();
        end = pos.back() + 1;
    }
    CHECK_MSG(start == sidx && end == eidx && r.score == score,
              fname << " cs=" << case_sensitive << " fwd=" << forward << " '" << input << "' / '" << pattern
                    << "': got [" << start << "," << end << ") " << r.score << " want [" << sidx << "," << eidx
                    << ") " << score);
}

void assert_match(AlgoFn fn, const char* fname, bool cs, bool fwd, std::string_view in, std::string_view pat, int s,
                  int e, int score) {
    assert_match2(fn, fname, cs, false, fwd, in, pat, s, e, score);
}

} // namespace

TEST(fuzzy, algo_fuzzy_match) {
    struct Named {
        AlgoFn fn;
        const char* name;
    };
    for (Named f : {Named{fuzzy_match_v1, "V1"}, Named{fuzzy_match_v2, "V2"}}) {
        for (bool fwd : {true, false}) {
            auto m = [&](bool cs, const char* in, const char* pat, int s, int e, int score) {
                assert_match(f.fn, f.name, cs, fwd, in, pat, s, e, score);
            };
            m(false, "fooBarbaz1", "oBZ", 2, 9, scoreMatch * 3 + bonusCamel123 + scoreGapStart + scoreGapExtension * 3);
            m(false, "foo bar baz", "fbb", 0, 9,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite * 2 +
                  2 * scoreGapStart + 4 * scoreGapExtension);
            m(false, "/AutomatorDocument.icns", "rdoc", 9, 13, scoreMatch * 4 + bonusCamel123 + bonusConsecutive * 2);
            m(false, "/man1/zshcompctl.1", "zshc", 6, 10,
              scoreMatch * 4 + bonusBoundaryDelimiter * bonusFirstCharMultiplier + bonusBoundaryDelimiter * 3);
            m(false, "/.oh-my-zsh/cache", "zshc", 8, 13,
              scoreMatch * 4 + bonusBoundary * bonusFirstCharMultiplier + bonusBoundary * 2 + scoreGapStart +
                  bonusBoundaryDelimiter);
            m(false, ".vimrc", ".vimrc", 0, 6, scoreMatch * 6 + bonusBoundaryWhite * (bonusFirstCharMultiplier + 5));
            m(false, "/.vimrc", ".vimrc", 1, 7,
              scoreMatch * 6 + bonusBoundaryDelimiter * (bonusFirstCharMultiplier + 5));
            m(false, "a.vimrc", ".vimrc", 1, 7, scoreMatch * 6 + bonusBoundary * (bonusFirstCharMultiplier + 5));
            m(false, "ab0123 456", "12356", 3, 10,
              scoreMatch * 5 + bonusConsecutive * 3 + scoreGapStart + scoreGapExtension);
            m(false, "abc123 456", "12356", 3, 10,
              scoreMatch * 5 + bonusCamel123 * bonusFirstCharMultiplier + bonusCamel123 * 2 + bonusConsecutive +
                  scoreGapStart + scoreGapExtension);
            m(false, "foo/bar/baz", "fbb", 0, 9,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryDelimiter * 2 +
                  2 * scoreGapStart + 4 * scoreGapExtension);
            m(false, "fooBarBaz", "fbb", 0, 7,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusCamel123 * 2 + 2 * scoreGapStart +
                  2 * scoreGapExtension);
            m(false, "foo barbaz", "fbb", 0, 8,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite +
                  scoreGapStart * 2 + scoreGapExtension * 3);
            m(false, "fooBar Baz", "foob", 0, 4,
              scoreMatch * 4 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite * 3);
            m(false, "xFoo-Bar Baz", "foo-b", 1, 6,
              scoreMatch * 5 + bonusCamel123 * bonusFirstCharMultiplier + bonusCamel123 * 2 + bonusNonWord +
                  bonusBoundary);
            m(true, "fooBarbaz", "oBz", 2, 9, scoreMatch * 3 + bonusCamel123 + scoreGapStart + scoreGapExtension * 3);
            m(true, "Foo/Bar/Baz", "FBB", 0, 9,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryDelimiter * 2 +
                  scoreGapStart * 2 + scoreGapExtension * 4);
            m(true, "FooBarBaz", "FBB", 0, 7,
              scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusCamel123 * 2 + scoreGapStart * 2 +
                  scoreGapExtension * 2);
            m(true, "FooBar Baz", "FooB", 0, 4,
              scoreMatch * 4 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite * 2 +
                  std::max(bonusCamel123, bonusBoundaryWhite));
            m(true, "foo-bar", "o-ba", 2, 6, scoreMatch * 4 + bonusBoundary * 3);
            m(true, "fooBarbaz", "oBZ", -1, -1, 0);
            m(true, "Foo Bar Baz", "fbb", -1, -1, 0);
            m(true, "fooBarbaz", "fooBarbazz", -1, -1, 0);
        }
    }
}

TEST(fuzzy, algo_fuzzy_match_backward) {
    assert_match(fuzzy_match_v1, "V1", false, true, "foobar fb", "fb", 0, 4,
                 scoreMatch * 2 + bonusBoundaryWhite * bonusFirstCharMultiplier + scoreGapStart + scoreGapExtension);
    assert_match(fuzzy_match_v1, "V1", false, false, "foobar fb", "fb", 7, 9,
                 scoreMatch * 2 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite);
}

TEST(fuzzy, algo_exact_match_naive) {
    for (bool dir : {true, false}) {
        assert_match(exact_match_naive, "exact", true, dir, "fooBarbaz", "oBA", -1, -1, 0);
        assert_match(exact_match_naive, "exact", true, dir, "fooBarbaz", "fooBarbazz", -1, -1, 0);
        assert_match(exact_match_naive, "exact", false, dir, "fooBarbaz", "oBA", 2, 5,
                     scoreMatch * 3 + bonusCamel123 + bonusConsecutive);
        assert_match(exact_match_naive, "exact", false, dir, "/AutomatorDocument.icns", "rdoc", 9, 13,
                     scoreMatch * 4 + bonusCamel123 + bonusConsecutive * 2);
        assert_match(exact_match_naive, "exact", false, dir, "/man1/zshcompctl.1", "zshc", 6, 10,
                     scoreMatch * 4 + bonusBoundaryDelimiter * (bonusFirstCharMultiplier + 3));
        assert_match(exact_match_naive, "exact", false, dir, "/.oh-my-zsh/cache", "zsh/c", 8, 13,
                     scoreMatch * 5 + bonusBoundary * (bonusFirstCharMultiplier + 3) + bonusBoundaryDelimiter);
    }
    assert_match(exact_match_naive, "exact", false, true, "foobar foob", "oo", 1, 3, scoreMatch * 2 + bonusConsecutive);
    assert_match(exact_match_naive, "exact", false, false, "foobar foob", "oo", 8, 10, scoreMatch * 2 + bonusConsecutive);
}

TEST(fuzzy, algo_prefix_suffix_empty) {
    const int score = scoreMatch * 3 + bonusBoundaryWhite * bonusFirstCharMultiplier + bonusBoundaryWhite * 2;
    for (bool dir : {true, false}) {
        assert_match(prefix_match, "prefix", true, dir, "fooBarbaz", "Foo", -1, -1, 0);
        assert_match(prefix_match, "prefix", false, dir, "fooBarBaz", "baz", -1, -1, 0);
        assert_match(prefix_match, "prefix", false, dir, "fooBarbaz", "Foo", 0, 3, score);
        assert_match(prefix_match, "prefix", false, dir, "foOBarBaZ", "foo", 0, 3, score);
        assert_match(prefix_match, "prefix", false, dir, "f-oBarbaz", "f-o", 0, 3, score);
        assert_match(prefix_match, "prefix", false, dir, " fooBar", "foo", 1, 4, score);
        assert_match(prefix_match, "prefix", false, dir, " fooBar", " fo", 0, 3, score);
        assert_match(prefix_match, "prefix", false, dir, "     fo", "foo", -1, -1, 0);

        assert_match(suffix_match, "suffix", true, dir, "fooBarbaz", "Baz", -1, -1, 0);
        assert_match(suffix_match, "suffix", false, dir, "fooBarbaz", "Foo", -1, -1, 0);
        assert_match(suffix_match, "suffix", false, dir, "fooBarbaz", "baz", 6, 9, scoreMatch * 3 + bonusConsecutive * 2);
        assert_match(suffix_match, "suffix", false, dir, "fooBarBaZ", "baz", 6, 9,
                     (scoreMatch + bonusCamel123) * 3 + bonusCamel123 * (bonusFirstCharMultiplier - 1));
        assert_match(suffix_match, "suffix", false, dir, "fooBarbaz ", "baz", 6, 9,
                     scoreMatch * 3 + bonusConsecutive * 2);
        assert_match(suffix_match, "suffix", false, dir, "fooBarbaz ", "baz ", 6, 10,
                     scoreMatch * 4 + bonusConsecutive * 2 + bonusBoundaryWhite);

        assert_match(fuzzy_match_v1, "V1", true, dir, "foobar", "", 0, 0, 0);
        assert_match(fuzzy_match_v2, "V2", true, dir, "foobar", "", 0, 0, 0);
        assert_match(exact_match_naive, "exact", true, dir, "foobar", "", 0, 0, 0);
        assert_match(prefix_match, "prefix", true, dir, "foobar", "", 0, 0, 0);
        assert_match(suffix_match, "suffix", true, dir, "foobar", "", 6, 6, 0);
    }
}

TEST(fuzzy, algo_normalize) {
    auto t = [](const char* in, const char* pat, int s, int e, int score, std::initializer_list<AlgoFn> fns) {
        for (AlgoFn fn : fns) assert_match2(fn, "normalize", false, true, true, in, pat, s, e, score);
    };
    t("Só Danço Samba", "So", 0, 2, 62, {fuzzy_match_v1, fuzzy_match_v2, prefix_match, exact_match_naive});
    t("Só Danço Samba", "sodc", 0, 7, 97, {fuzzy_match_v1, fuzzy_match_v2});
    t("Danço", "danco", 0, 5, 140,
      {fuzzy_match_v1, fuzzy_match_v2, prefix_match, suffix_match, exact_match_naive, equal_match});
}

TEST(fuzzy, algo_long_strings) {
    std::string bytes(65535 * 2, 'x');
    bytes[65535] = 'z';
    assert_match(fuzzy_match_v2, "V2", true, true, bytes, "zx", 65535, 65537, scoreMatch * 2 + bonusConsecutive);
    std::string u = std::string(30000, 'x') + " Minímal example";
    assert_match2(fuzzy_match_v1, "V1", false, true, false, u, "minim", 30001, 30006, 140);
}

TEST(fuzzy, algo_positions_with_reused_slab) {
    // fzf TestResultPositionsWithReusedSlab: equal-score backtrace must not read stale slab data.
    auto run = [](Slab& slab, std::string_view s) {
        std::vector<uint32_t> pat = {'c', 'o', '/'};
        Chars c;
        c.bytes = reinterpret_cast<const unsigned char*>(s.data());
        c.n = static_cast<int32_t>(s.size());
        std::vector<int32_t> pos;
        fuzzy_match_v2(def(), false, false, true, c, pat.data(), 3, &pos, slab);
        return pos;
    };
    Slab fresh;
    auto a = run(fresh, "core_color/view/server.txt");
    Slab reused;
    run(reused, "completion/keybinding/client/handler/writer_index.txt");
    auto b = run(reused, "core_color/view/server.txt");
    CHECK(a == b);
}
