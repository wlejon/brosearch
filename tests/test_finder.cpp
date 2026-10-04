#include "brosearch/finder.h"
#include <cassert>
#include <fstream>
#include <iostream>

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

    std::filesystem::path test_root = std::filesystem::temp_directory_path() / "brosearch_finder_sandbox";
    std::filesystem::remove_all(test_root);

    // Create test folder tree:
    // test_root/
    //   src/
    //     main.cpp
    //     utils.cpp
    //     utils.h
    //   node_modules/
    //     package.json
    //   .git/
    //     HEAD
    //   build/
    //     output.exe
    //   docs/
    //     guide.md
    std::filesystem::create_directories(test_root / "src");
    std::filesystem::create_directories(test_root / "node_modules");
    std::filesystem::create_directories(test_root / ".git");
    std::filesystem::create_directories(test_root / "build");
    std::filesystem::create_directories(test_root / "docs");

    auto write_file = [](const std::filesystem::path& p, const std::string& content) {
        std::ofstream out(p);
        out << content;
    };

    write_file(test_root / "src/main.cpp", "int main() {}");
    write_file(test_root / "src/utils.cpp", "void util() {}");
    write_file(test_root / "src/utils.h", "#pragma once");
    write_file(test_root / "node_modules/package.json", "{}");
    write_file(test_root / ".git/HEAD", "ref: refs/heads/main");
    write_file(test_root / "build/output.exe", "binary");
    write_file(test_root / "docs/guide.md", "# Guide");

    std::cout << "[test_finder] Testing directory walker with default ignores..." << std::endl;
    {
        bro::search::FindOptions opts;
        opts.respect_gitignore = true;
        auto entries = bro::search::find_files(test_root, opts);

        // Should include src/main.cpp, src/utils.cpp, src/utils.h, docs/guide.md
        // Should NOT include anything in node_modules, .git, or build
        for (const auto& e : entries) {
            std::string rel = e.relative_path;
            assert(rel.find("node_modules") == std::string::npos);
            assert(rel.find(".git") == std::string::npos);
            assert(rel.find("build") == std::string::npos);
        }
        assert(entries.size() == 4);
    }

    std::cout << "[test_finder] Testing filename glob filtering (*.cpp)..." << std::endl;
    {
        bro::search::FindOptions opts;
        opts.glob_pattern = "*.cpp";
        auto entries = bro::search::find_files(test_root, opts);
        assert(entries.size() == 2);
        for (const auto& e : entries) {
            (void)e;
            assert(e.filename.ends_with(".cpp"));
        }
    }

    std::cout << "[test_finder] Testing fuzzy pattern ranking in directory walker..." << std::endl;
    {
        bro::search::FindOptions opts;
        opts.fuzzy_pattern = "util";
        auto entries = bro::search::find_files(test_root, opts);

        assert(!entries.empty());
        // utils.cpp and utils.h should match
        assert(entries.size() == 2);
        for (const auto& e : entries) {
            (void)e;
            assert(e.fuzzy_score > 0);
            assert(e.filename.find("utils") != std::string::npos);
        }
    }

    std::cout << "[test_finder] Testing cancellation..." << std::endl;
    {
        bro::search::CancellationToken token;
        token.cancel();

        bro::search::FindOptions opts;
        auto entries = bro::search::find_files(test_root, opts, &token);
        assert(entries.empty());
    }

    std::filesystem::remove_all(test_root);
    std::cout << "[test_finder] All finder tests passed successfully!" << std::endl;
    return 0;
}
