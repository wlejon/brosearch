#include "brosearch/ignore.h"
#include <cassert>
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

    std::cout << "[test_ignore] Testing standalone glob matching..." << std::endl;
    {
        // Simple wildcard *
        assert(bro::search::IgnoreFilter::glob_match("*.cpp", "main.cpp"));
        assert(!bro::search::IgnoreFilter::glob_match("*.cpp", "main.h"));
        assert(!bro::search::IgnoreFilter::glob_match("*.cpp", "src/main.cpp")); // * does not cross /

        // Double wildcard **
        assert(bro::search::IgnoreFilter::glob_match("**/*.cpp", "src/core/main.cpp"));
        assert(bro::search::IgnoreFilter::glob_match("src/**", "src/foo/bar.txt"));

        // Single character ?
        assert(bro::search::IgnoreFilter::glob_match("file?.txt", "file1.txt"));
        assert(bro::search::IgnoreFilter::glob_match("file?.txt", "fileA.txt"));
        assert(!bro::search::IgnoreFilter::glob_match("file?.txt", "file12.txt"));

        // Character class [...]
        assert(bro::search::IgnoreFilter::glob_match("file[0-9].txt", "file5.txt"));
        assert(!bro::search::IgnoreFilter::glob_match("file[0-9].txt", "fileA.txt"));
        assert(bro::search::IgnoreFilter::glob_match("file[!0-9].txt", "fileA.txt"));
    }

    std::cout << "[test_ignore] Testing default ignore list..." << std::endl;
    {
        bro::search::IgnoreFilter filter(true);
        assert(filter.is_ignored(".git", true));
        assert(filter.is_ignored(".git/config", false));
        assert(filter.is_ignored("node_modules", true));
        assert(filter.is_ignored("node_modules/package/index.js", false));
        assert(filter.is_ignored(".vs", true));
        assert(filter.is_ignored("build", true));
        assert(filter.is_ignored("build/app.exe", false));
        assert(filter.is_ignored("dist", true));
        assert(filter.is_ignored(".cache", true));
        assert(filter.is_ignored("app.log", false));
        assert(!filter.is_ignored("src/main.cpp", false));
    }

    std::cout << "[test_ignore] Testing custom rules, trailing slashes, and negation..." << std::endl;
    {
        bro::search::IgnoreFilter filter(false);
        filter.load_string(
            "# Ignore all logs\n"
            "*.log\n"
            "# Except important.log\n"
            "!important.log\n"
            "# Directory-only match\n"
            "temp/\n"
            "# Anchored rule\n"
            "/root_only.txt\n"
        );

        // *.log should be ignored
        assert(filter.is_ignored("debug.log", false));
        assert(filter.is_ignored("subdir/error.log", false));

        // !important.log re-included
        assert(!filter.is_ignored("important.log", false));

        // temp/ directory-only
        assert(filter.is_ignored("temp", true));
        assert(filter.is_ignored("temp/foo.txt", false));
        assert(!filter.is_ignored("temp", false)); // not a directory, shouldn't match temp/

        // /root_only.txt anchored
        assert(filter.is_ignored("root_only.txt", false));
        assert(!filter.is_ignored("sub/root_only.txt", false));
    }

    std::cout << "[test_ignore] Testing hierarchical base directory loading..." << std::endl;
    {
        bro::search::IgnoreFilter filter(false);
        filter.load_string("build/\n*.o\n", "subproject");

        assert(filter.is_ignored("subproject/build", true));
        assert(filter.is_ignored("subproject/build/lib.a", false));
        assert(filter.is_ignored("subproject/test.o", false));
        // Outside subproject:
        assert(!filter.is_ignored("other/build", true));
        assert(!filter.is_ignored("other/test.o", false));
    }

    std::cout << "[test_ignore] All ignore tests passed successfully!" << std::endl;
    return 0;
}
