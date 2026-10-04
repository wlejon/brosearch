#include "brosearch/fuzzy.h"
#include <cassert>
#include <iostream>
#include <vector>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

    std::cout << "[test_fuzzy] Testing basic fuzzy match..." << std::endl;
    {
        auto res = bro::search::fuzzy_match("bro", "brosearch");
        assert(res.matched);
        assert(res.score > 0);
        assert(res.matched_indices.size() == 3);
        assert(res.matched_indices[0] == 0);
        assert(res.matched_indices[1] == 1);
        assert(res.matched_indices[2] == 2);
    }

    std::cout << "[test_fuzzy] Testing quick reject for non-matches..." << std::endl;
    {
        auto res = bro::search::fuzzy_match("xyz", "brosearch");
        assert(!res.matched);
        assert(res.matched_indices.empty());
    }

    std::cout << "[test_fuzzy] Testing boundary bonus (delimiter)..." << std::endl;
    {
        auto res_delim = bro::search::fuzzy_match("fb", "foo_bar");
        auto res_nodelim = bro::search::fuzzy_match("fb", "foobar");

        assert(res_delim.matched);
        assert(res_nodelim.matched);
        assert(res_delim.matched_indices.size() == 2);
        assert(res_delim.matched_indices[0] == 0);
        assert(res_delim.matched_indices[1] == 4); // 'b' in "_bar"
        // foo_bar should score higher than foobar due to boundary bonus on 'b'
        assert(res_delim.score > res_nodelim.score);
    }

    std::cout << "[test_fuzzy] Testing camelCase boundary bonus..." << std::endl;
    {
        auto res_camel = bro::search::fuzzy_match("fb", "fooBar");
        assert(res_camel.matched);
        assert(res_camel.matched_indices.size() == 2);
        assert(res_camel.matched_indices[0] == 0);
        assert(res_camel.matched_indices[1] == 3); // 'B' in "Bar"
    }

    std::cout << "[test_fuzzy] Testing consecutive match bonus vs non-consecutive..." << std::endl;
    {
        auto res_consec = bro::search::fuzzy_match("foo", "foobar");
        auto res_scatter = bro::search::fuzzy_match("foo", "fxoxox");

        assert(res_consec.matched);
        assert(res_scatter.matched);
        assert(res_consec.score > res_scatter.score);
    }

    std::cout << "[test_fuzzy] Testing exact match bonus..." << std::endl;
    {
        auto res_exact = bro::search::fuzzy_match("terminal", "terminal");
        auto res_sub = bro::search::fuzzy_match("terminal", "terminal_window");

        assert(res_exact.matched);
        assert(res_sub.matched);
        assert(res_exact.score > res_sub.score);
    }

    std::cout << "[test_fuzzy] Testing path mode bonus..." << std::endl;
    {
        bro::search::FuzzyOptions opts;
        opts.path_mode = true;
        auto res_filename = bro::search::fuzzy_match("main", "src/core/main.cpp", opts);
        assert(res_filename.matched);
        assert(res_filename.matched_indices.size() == 4);
        assert(res_filename.matched_indices[0] == 9); // 'm' in main.cpp
    }

    std::cout << "[test_fuzzy] Testing rank_candidates batch API..." << std::endl;
    {
        std::vector<std::string> candidates = {
            "src/utils/file_scanner.cpp",
            "src/finder.cpp",
            "src/terminal/buffer.cpp",
            "tests/test_finder.cpp",
            "include/brosearch/finder.h",
            "README.md"
        };

        auto ranked = bro::search::rank_candidates("finder", candidates);
        assert(!ranked.empty());
        // The most relevant "finder" matches should come to the top
        assert(ranked[0].text.find("finder") != std::string::npos);
        // Scores should be sorted descending
        for (size_t i = 1; i < ranked.size(); ++i) {
            assert(ranked[i - 1].score >= ranked[i].score);
        }
    }

    std::cout << "[test_fuzzy] Testing batch ranking with max_results..." << std::endl;
    {
        std::vector<std::string> many_candidates;
        for (int i = 0; i < 1000; ++i) {
            many_candidates.push_back("path/to/item_" + std::to_string(i) + ".cpp");
        }

        bro::search::FuzzyOptions opts;
        opts.max_results = 10;
        auto ranked = bro::search::rank_candidates("item_4", many_candidates, opts);
        assert(ranked.size() <= 10);
    }

    std::cout << "[test_fuzzy] Testing batch ranking cancellation..." << std::endl;
    {
        std::vector<std::string> many_candidates(5000, "some/long/path/with/candidate/item.txt");
        bro::search::CancellationToken token;
        token.cancel();

        auto ranked = bro::search::rank_candidates("item", many_candidates, {}, &token);
        assert(ranked.empty());
    }

    std::cout << "[test_fuzzy] All fuzzy tests passed successfully!" << std::endl;
    return 0;
}
