// FuzzyIndex: incremental search must be indistinguishable from a cold fuzzy_filter over the same
// items, while reusing earlier match sets as the query is typed.

#include "harness.h"

#include "fuzzy_corpus_gen.h"

#include "brosearch/fuzzy_index.h"

#include <atomic>
#include <thread>

using namespace bro::search;

namespace {

std::vector<std::string> paths_corpus() { return bt::read_lines(bt::fixture_dir() / "fuzzy" / "paths.corpus"); }

// Larger corpus: the paths fixture with numbered variants, so many chunks are full.
std::vector<std::string> big_corpus() {
    auto base = paths_corpus();
    std::vector<std::string> out;
    for (int rep = 0; rep < 12; ++rep)
        for (auto& p : base) {
            std::string s;
            if (rep) s.append("v").append(std::to_string(rep)).append("/");
            s.append(p);
            out.push_back(std::move(s));
        }
    return out;
}

bool same_indices(const std::vector<FuzzyResult>& a, const std::vector<FuzzyResult>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].index != b[i].index || a[i].score != b[i].score) return false;
    return true;
}

std::vector<FuzzyResult> cold(const std::vector<std::string>& items, size_t n, std::string_view q,
                              const FuzzyOptions& o, size_t limit = 0) {
    return fuzzy_filter(FuzzyQuery(q, o), std::span<const std::string>(items.data(), n), limit);
}

} // namespace

TEST(fuzzy_index, typing_refinement_equals_cold_search) {
    auto items = big_corpus();
    const char* typed[] = {"srcrenderskia", "webglscene", "testsjs", "docsapi", "engine.cpp", "Scene",
                           "src gl", "src !test", "^src", "cpp$ rend", "'skia", "qqqzzz"};
    for (bool exact : {false, true}) {
        FuzzyOptions o;
        o.exact = exact;
        FuzzyIndex index(o);
        index.add(std::span<const std::string>(items));
        for (const char* q : typed) {
            std::string s(q);
            for (size_t len = 1; len <= s.size(); ++len) {
                std::string prefix = s.substr(0, len);
                auto got = index.search(prefix);
                CHECK_MSG(same_indices(got.results, cold(items, items.size(), prefix, o)),
                          "exact=" << exact << " prefix '" << prefix << "'");
                CHECK_EQ(got.item_count, items.size());
                CHECK_EQ(got.match_count, got.results.size());
            }
            // Backspacing (shorter queries) also stays exact.
            for (size_t len = s.size(); len-- > 1;) {
                std::string prefix = s.substr(0, len);
                CHECK_MSG(same_indices(index.search(prefix).results, cold(items, items.size(), prefix, o)),
                          "backspace '" << prefix << "'");
            }
        }
    }
}

TEST(fuzzy_index, cache_reuses_previous_match_sets) {
    auto items = big_corpus();
    FuzzyIndex index;
    index.add(std::span<const std::string>(items));
    auto first = index.search("webgl");
    CHECK_EQ(first.candidates_scanned, items.size());  // nothing cached yet
    auto refined = index.search("webglsc");
    // Every full chunk is narrowed to the cached "webgl" candidates.
    CHECK(refined.candidates_scanned < items.size() / 10);
    CHECK(same_indices(refined.results, cold(items, items.size(), "webglsc", FuzzyOptions())));
    // Suffix reuse, as in fzf: "glsc" is a suffix of the key of "webglsc".
    auto suffix_based = index.search("bwebglsc");
    CHECK(suffix_based.candidates_scanned < items.size() / 10);
    CHECK(same_indices(suffix_based.results, cold(items, items.size(), "bwebglsc", FuzzyOptions())));
    // Disabling the cache gives the same answer with a full scan.
    index.set_cache_enabled(false);
    auto full = index.search("webglsc");
    CHECK_EQ(full.candidates_scanned, items.size());
    CHECK(same_indices(full.results, refined.results));
}

TEST(fuzzy_index, items_appended_between_keystrokes) {
    auto items = big_corpus();
    FuzzyIndex index;
    size_t added = 0;
    std::string q = "srcenginecpp";
    for (size_t len = 1; len <= q.size(); ++len) {
        size_t target = items.size() * len / q.size();
        index.add(std::span<const std::string>(items.data() + added, target - added));
        added = target;
        std::string prefix = q.substr(0, len);
        auto got = index.search(prefix);
        CHECK_EQ(got.item_count, added);
        CHECK_MSG(same_indices(got.results, cold(items, added, prefix, FuzzyOptions())), "prefix '" << prefix << "'");
    }
}

TEST(fuzzy_index, concurrent_add_and_search) {
    auto items = big_corpus();
    FuzzyIndex index;
    std::atomic<bool> done{false};
    std::thread writer([&] {
        for (size_t i = 0; i < items.size(); i += 97) {
            size_t n = std::min<size_t>(97, items.size() - i);
            index.add(std::span<const std::string>(items.data() + i, n));
        }
        done = true;
    });
    int checked = 0, failures = 0;
    const char* queries[] = {"src", "rend", "sc gl", "cpp$"};
    while (!done || checked < 8) {
        const char* q = queries[checked % 4];
        auto got = index.search(q);
        // The snapshot is a prefix of the insertion order; compare with a cold search over it.
        if (!same_indices(got.results, cold(items, got.item_count, q, FuzzyOptions()))) ++failures;
        ++checked;
        if (done && checked >= 8) break;
    }
    writer.join();
    CHECK_EQ(failures, 0);
    CHECK_EQ(index.size(), items.size());
    for (uint32_t i = 0; i < items.size(); i += 501) CHECK_EQ(index.item(i), std::string_view(items[i]));
}

TEST(fuzzy_index, limit_positions_and_empty_query) {
    auto items = fuzzy_corpus::unicode_corpus(5000, 21);
    FuzzyIndex index;
    index.add(std::span<const std::string>(items));
    auto top = index.search("cafe", 10, true);
    auto all = cold(items, items.size(), "cafe", FuzzyOptions());
    CHECK_EQ(top.results.size(), size_t(10));
    CHECK_EQ(top.match_count, all.size());
    for (size_t i = 0; i < top.results.size(); ++i) {
        CHECK_EQ(top.results[i].index, all[i].index);
        CHECK(!top.results[i].positions.empty());
        FuzzyMatch m;
        CHECK(FuzzyQuery("cafe").match(items[top.results[i].index], &m, true));
        CHECK(m.positions == top.results[i].positions);
    }
    auto everything = index.search("", 3);
    CHECK_EQ(everything.results.size(), size_t(3));
    CHECK_EQ(everything.results[2].index, 2u);
    index.clear();
    CHECK_EQ(index.size(), size_t(0));
    CHECK(index.search("cafe").results.empty());
}

TEST(fuzzy_index, cancellation_marks_partial) {
    auto items = big_corpus();
    FuzzyIndex index;
    index.add(std::span<const std::string>(items));
    CancellationSource src;
    src.cancel();
    auto r = index.search("src", 0, false, src.token().get());
    CHECK(r.cancelled);
    CHECK(r.results.size() < cold(items, items.size(), "src", FuzzyOptions()).size());
}
