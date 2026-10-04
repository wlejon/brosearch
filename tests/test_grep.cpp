#include "brosearch/grep.h"
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

    std::cout << "[test_grep] Testing literal substring search in buffer..." << std::endl;
    {
        std::string buffer = "first line\nsecond line with keyword inside\nthird line\n";
        auto matches = bro::search::grep_buffer(buffer, "keyword");
        assert(matches.size() == 1);
        assert(matches[0].line_number == 2);
        assert(matches[0].column == 18);
        assert(matches[0].match_length == 7);
        assert(matches[0].line_content == "second line with keyword inside");
    }

    std::cout << "[test_grep] Testing case-insensitive literal search..." << std::endl;
    {
        std::string buffer = "Error: something failed\nerror: another issue\nWARNING: ok\n";
        bro::search::GrepOptions opts;
        opts.case_sensitive = false;
        auto matches = bro::search::grep_buffer(buffer, "error", opts);
        assert(matches.size() == 2);
        assert(matches[0].line_number == 1);
        assert(matches[1].line_number == 2);
    }

    std::cout << "[test_grep] Testing regex search in buffer..." << std::endl;
    {
        std::string buffer = "version: 1.2.3\nbuild: 456\nversion: 2.0.0\n";
        bro::search::GrepOptions opts;
        opts.is_regex = true;
        auto matches = bro::search::grep_buffer(buffer, R"(version: \d+\.\d+\.\d+)", opts);
        assert(matches.size() == 2);
        assert(matches[0].line_number == 1);
        assert(matches[1].line_number == 3);
        assert(matches[0].line_content == "version: 1.2.3");
        assert(matches[1].line_content == "version: 2.0.0");
    }

    std::cout << "[test_grep] Testing word boundary match option..." << std::endl;
    {
        std::string buffer = "apple pineapple apple_pie apple\n";
        bro::search::GrepOptions opts;
        opts.word_match = true;
        auto matches = bro::search::grep_buffer(buffer, "apple", opts);
        // Only the 1st and last "apple" should match as whole words
        assert(matches.size() == 2);
        assert(matches[0].column == 1);
        assert(matches[1].column == 27);
    }

    std::cout << "[test_grep] Testing binary buffer detection..." << std::endl;
    {
        std::string text_buf = "hello world\nthis is clean text";
        assert(!bro::search::is_binary_buffer(text_buf));

        std::string bin_buf = std::string("hello\0world", 11);
        assert(bro::search::is_binary_buffer(bin_buf));
    }

    std::cout << "[test_grep] Testing file grep and binary file handling..." << std::endl;
    {
        std::filesystem::path temp_txt = std::filesystem::temp_directory_path() / "brosearch_test_text.txt";
        std::filesystem::path temp_bin = std::filesystem::temp_directory_path() / "brosearch_test_bin.bin";

        {
            std::ofstream out(temp_txt);
            out << "line 1: alpha\nline 2: target_pattern in file\nline 3: omega\n";
        }
        {
            std::ofstream out(temp_bin, std::ios::binary);
            char raw[] = {'t', 'a', 'r', 'g', 'e', 't', 0, 'f', 'i', 'l', 'e'};
            out.write(raw, sizeof(raw));
        }

        auto res_txt = bro::search::grep_file(temp_txt, "target_pattern");
        assert(!res_txt.is_binary);
        assert(res_txt.matches.size() == 1);
        assert(res_txt.matches[0].line_number == 2);

        bro::search::GrepOptions bin_opts;
        bin_opts.skip_binary = true;
        auto res_bin = bro::search::grep_file(temp_bin, "target", bin_opts);
        assert(res_bin.is_binary);
        assert(res_bin.matches.empty());

        std::filesystem::remove(temp_txt);
        std::filesystem::remove(temp_bin);
    }

    std::cout << "[test_grep] Testing terminal helpers: detect_urls..." << std::endl;
    {
        std::string terminal_line = "Check out https://github.com/bro/engine and http://example.org/doc for info.";
        auto urls = bro::search::detect_urls(terminal_line);
        assert(urls.size() == 2);
        assert(terminal_line.substr(urls[0].column - 1, urls[0].match_length) == "https://github.com/bro/engine");
        assert(terminal_line.substr(urls[1].column - 1, urls[1].match_length) == "http://example.org/doc");
    }

    std::cout << "[test_grep] Testing terminal helpers: detect_git_hashes..." << std::endl;
    {
        std::string terminal_log = "commit 4a9f8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a\nfixed in 7b2c4e1\n";
        auto hashes = bro::search::detect_git_hashes(terminal_log);
        assert(hashes.size() == 2);
        assert(hashes[0].match_length == 40);
        assert(hashes[1].match_length == 7);
    }

    std::cout << "[test_grep] Testing large buffer search simulation..." << std::endl;
    {
        // 50,000 lines scrollback simulation
        std::string scrollback;
        scrollback.reserve(2 * 1024 * 1024);
        for (int i = 0; i < 50000; ++i) {
            scrollback += "line ";
            scrollback += std::to_string(i);
            scrollback += ": [INFO] normal terminal output message\n";
        }
        scrollback += "line 50000: [FATAL] unique terminal error occurred\n";

        auto matches = bro::search::grep_buffer(scrollback, "[FATAL]");
        assert(matches.size() == 1);
        assert(matches[0].line_number == 50001);
    }

    std::cout << "[test_grep] All grep tests passed successfully!" << std::endl;
    return 0;
}
