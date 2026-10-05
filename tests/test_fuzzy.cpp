// fzf parity for the fuzzy matcher. The *.expected fixtures were recorded from fzf 0.74 by
// `brosearch-cli fuzzy --oracle --record=...` (scripts/diff_fuzzy.sh); each entry holds the
// match count, a hash of the full output order, and the top of the list, as item indices.

#include "harness.h"

#include "fuzzy_corpus_gen.h"

#include "brosearch/fuzzy.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <set>

using namespace bro::search;

namespace {

uint64_t fnv_indices(const std::vector<uint32_t>& v) {
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t x : v) {
        for (int b = 0; b < 4; ++b) {
            h ^= (x >> (8 * b)) & 0xFF;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

bool apply_flag(const std::string& f, FuzzyOptions& o) {
    if (f == "-i") o.case_mode = FuzzyCase::Ignore;
    else if (f == "+i") o.case_mode = FuzzyCase::Respect;
    else if (f == "-e") o.exact = true;
    else if (f == "+x") o.extended = false;
    else if (f == "--literal") o.normalize = false;
    else if (f == "--no-sort") o.sort = false;
    else if (f == "--algo=v1") o.algo_v1 = true;
    else if (f == "--scheme=path") o.scheme = FuzzyScheme::Path;
    else if (f == "--scheme=history") o.scheme = FuzzyScheme::History;
    else if (f.rfind("--tiebreak=", 0) == 0) {
        std::string s = f.substr(11);
        size_t i = 0;
        while (i <= s.size()) {
            size_t c = s.find(',', i);
            if (c == std::string::npos) c = s.size();
            std::string t = s.substr(i, c - i);
            if (t == "length") o.tiebreak.push_back(FuzzyTiebreak::Length);
            else if (t == "chunk") o.tiebreak.push_back(FuzzyTiebreak::Chunk);
            else if (t == "pathname") o.tiebreak.push_back(FuzzyTiebreak::Pathname);
            else if (t == "begin") o.tiebreak.push_back(FuzzyTiebreak::Begin);
            else if (t == "end") o.tiebreak.push_back(FuzzyTiebreak::End);
            else if (t == "index") o.tiebreak.push_back(FuzzyTiebreak::Index);
            else return false;
            i = c + 1;
        }
    } else {
        return false;
    }
    return true;
}

// Replays a fixture; returns the number of queries checked.
size_t replay(const std::vector<std::string>& items, const std::string& fixture_name) {
    auto lines = bt::read_lines(bt::fixture_dir() / "fuzzy" / fixture_name);
    std::vector<std::string_view> views(items.begin(), items.end());
    size_t checked = 0;
    for (size_t i = 0; i + 2 < lines.size() + 1; ++i) {
        if (lines[i].rfind("Q ", 0) != 0) continue;
        CHECK_MSG(i + 2 < lines.size(), "truncated fixture " << fixture_name);
        if (i + 2 >= lines.size()) break;
        const std::string& qline = lines[i];
        size_t tab = qline.find('\t');
        std::string flags = qline.substr(2, tab - 2);
        std::string query = qline.substr(tab + 1);
        FuzzyOptions opts;
        opts.backslash_delimiter = true;  // fixtures were recorded with fzf on Windows
        size_t p = 0;
        while (p < flags.size()) {
            size_t sp = flags.find(' ', p);
            if (sp == std::string::npos) sp = flags.size();
            if (sp > p) CHECK_MSG(apply_flag(flags.substr(p, sp - p), opts), "flag " << flags);
            p = sp + 1;
        }
        // N <count> <hash>
        const std::string& nline = lines[i + 1];
        size_t want_count = std::strtoull(nline.c_str() + 2, nullptr, 10);
        uint64_t want_hash = std::strtoull(nline.c_str() + nline.rfind(' ') + 1, nullptr, 16);
        std::vector<uint32_t> want_top;
        const char* t = lines[i + 2].c_str() + 1;
        while (*t) {
            char* end;
            unsigned long v = std::strtoul(t, &end, 10);
            if (end == t) break;
            want_top.push_back(static_cast<uint32_t>(v));
            t = end;
        }

        FuzzyQuery q(query, opts);
        auto res = fuzzy_filter(q, std::span<const std::string_view>(views));
        std::vector<uint32_t> got;
        for (auto& r : res) got.push_back(r.index);
        CHECK_MSG(got.size() == want_count, fixture_name << " [" << flags << "] '" << query << "': count "
                                                          << got.size() << " want " << want_count);
        CHECK_MSG(fnv_indices(got) == want_hash, fixture_name << " [" << flags << "] '" << query << "': order differs");
        std::vector<uint32_t> top(got.begin(), got.begin() + static_cast<ptrdiff_t>(std::min(got.size(), want_top.size())));
        CHECK_MSG(top == want_top, fixture_name << " [" << flags << "] '" << query << "': top differs");
        ++checked;
    }
    return checked;
}

std::vector<std::string> paths_corpus() { return bt::read_lines(bt::fixture_dir() / "fuzzy" / "paths.corpus"); }

} // namespace

TEST(fuzzy, fzf_parity_paths) {
    auto items = paths_corpus();
    CHECK_EQ(items.size(), size_t(1724));
    CHECK_EQ(replay(items, "paths.expected"), size_t(99));
}

TEST(fuzzy, fzf_parity_unicode) {
    CHECK_EQ(replay(fuzzy_corpus::unicode_corpus(3000, 7), "unicode.expected"), size_t(80));
}

TEST(fuzzy, fzf_parity_long_lines_v1_fallback) {
    CHECK_EQ(replay(fuzzy_corpus::long_corpus(300, 11), "long.expected"), size_t(28));
}

TEST(fuzzy, positions_are_valid_and_cover_the_pattern) {
    auto items = fuzzy_corpus::unicode_corpus(2000, 3);
    std::vector<std::string_view> views(items.begin(), items.end());
    const char* queries[] = {"cafe", "αθηνα", "src main", "^readme", "'data", "ǆ", "uber$", "é"};
    for (const char* qs : queries) {
        FuzzyQuery q(qs);
        auto res = fuzzy_filter(q, std::span<const std::string_view>(views), 0, true);
        for (const auto& r : res) {
            const std::string& item = items[r.index];
            CHECK(!r.positions.empty());
            for (size_t k = 0; k < r.positions.size(); ++k) {
                CHECK(r.positions[k] < item.size());
                // Each position starts a UTF-8 sequence (or is an invalid byte on its own).
                unsigned char c = static_cast<unsigned char>(item[r.positions[k]]);
                CHECK((c & 0xC0) != 0x80);
                if (k) CHECK(r.positions[k] > r.positions[k - 1]);
            }
            // Positions match the score fzf_match reports for the item alone.
            auto single = fuzzy_match(qs, item);
            CHECK(single.has_value());
            if (single) {
                CHECK_EQ(single->score, r.score);
                CHECK(single->positions == r.positions);
            }
        }
    }
}

TEST(fuzzy, fuzzy_positions_match_characters) {
    auto m = fuzzy_match("abc", "xAxBxCx");
    CHECK(m.has_value());
    if (m) CHECK_EQ(m->positions, (std::vector<uint32_t>{1, 3, 5}));
    auto u = fuzzy_match("ae", "Ångström é");
    CHECK(u.has_value());
    if (u) {
        CHECK_EQ(u->positions.front(), 0u);  // 'Å' normalizes to 'a' (byte 0)
        auto chars = fuzzy_char_indices("Ångström é", u->positions);
        CHECK_EQ(chars.back(), 9u);  // 'é' is the 10th character
    }
}

TEST(fuzzy, smart_case_and_normalization) {
    CHECK(fuzzy_match("cafe", "CAFÉ").has_value());
    CHECK(fuzzy_match("café", "cafe") == std::nullopt);   // non-ASCII pattern disables normalization
    CHECK(fuzzy_match("Cafe", "cafe") == std::nullopt);   // uppercase -> case-sensitive
    CHECK(fuzzy_match("Cafe", "Café").has_value());
    FuzzyOptions lit;
    lit.normalize = false;
    CHECK(fuzzy_match("cafe", "café", lit) == std::nullopt);
}

TEST(fuzzy, extended_syntax) {
    CHECK(fuzzy_match("^src cpp$", "src/x.cpp").has_value());
    CHECK(!fuzzy_match("^src cpp$", "lib/src/x.cpp").has_value());
    CHECK(!fuzzy_match("!test", "tests/a").has_value());
    CHECK(fuzzy_match("!test", "src/a").has_value());
    CHECK(fuzzy_match("foo | bar", "xbarx").has_value());
    CHECK(!fuzzy_match("'oob", "o_o_b").has_value());
    CHECK(fuzzy_match("oob", "o_o_b").has_value());
    CHECK(fuzzy_match("a\\ b", "a b").has_value());
    CHECK(!fuzzy_match("a\\ b", "ab").has_value());
    FuzzyQuery inv("!foo");
    CHECK(!inv.sortable());
    CHECK(FuzzyQuery("   ").empty());
}

TEST(fuzzy, empty_query_keeps_input_order) {
    std::vector<std::string> items = {"b", "a", "c"};
    auto res = fuzzy_filter(FuzzyQuery(""), std::span<const std::string>(items));
    CHECK_EQ(res.size(), size_t(3));
    for (size_t i = 0; i < res.size(); ++i) CHECK_EQ(res[i].index, static_cast<uint32_t>(i));
}

TEST(fuzzy, no_silent_drops) {
    // Every item that contains the pattern as a subsequence matches, however poor the score.
    std::vector<std::string> items;
    for (int i = 0; i < 500; ++i) items.push_back(std::string(static_cast<size_t>(i), 'x') + "a" + std::string(static_cast<size_t>(i), 'y') + "b");
    auto res = fuzzy_filter(FuzzyQuery("ab"), std::span<const std::string>(items));
    CHECK_EQ(res.size(), items.size());
}

TEST(fuzzy, limit_is_head_of_full_order_and_threads_agree) {
    auto items = fuzzy_corpus::unicode_corpus(20000, 99);
    std::vector<std::string_view> views(items.begin(), items.end());
    for (const char* qs : {"a", "src", "cafe main", "e$"}) {
        FuzzyOptions one;
        one.threads = 1;
        FuzzyOptions many;
        many.threads = 8;
        auto a = fuzzy_filter(FuzzyQuery(qs, one), std::span<const std::string_view>(views));
        auto b = fuzzy_filter(FuzzyQuery(qs, many), std::span<const std::string_view>(views));
        auto top = fuzzy_filter(FuzzyQuery(qs, many), std::span<const std::string_view>(views), 25);
        CHECK_EQ(a.size(), b.size());
        bool same = a.size() == b.size();
        for (size_t i = 0; same && i < a.size(); ++i) same = a[i].index == b[i].index;
        CHECK_MSG(same, qs);
        const size_t want_top = std::min<size_t>(25, a.size());  // not inline: std::min returns a reference
        CHECK_EQ(top.size(), want_top);
        for (size_t i = 0; i < top.size(); ++i) CHECK_EQ(top[i].index, a[i].index);
    }
}

TEST(fuzzy, cancellation) {
    auto items = fuzzy_corpus::long_corpus(400, 5);
    CancellationSource src;
    src.cancel();
    auto res = fuzzy_filter(FuzzyQuery("alphabeta"), std::span<const std::string>(items), 0, false, src.token().get());
    CHECK(res.empty());
}
