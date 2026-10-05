// brosearch-cli: drives the library with output formats that match the reference tools, so the
// differential scripts can diff them byte-for-byte.
//
//   brosearch-cli grep  [rg-like flags] PATTERN [PATH...]   (cli_grep.cpp)
//   brosearch-cli files [rg --files-like flags] [PATH]       (cli_files.cpp)
//   brosearch-cli fuzzy [fzf --filter-like flags] QUERY      (cli_fuzzy.cpp)

#include <cstdio>
#include <cstring>

int cli_grep(int argc, char** argv);
int cli_files(int argc, char** argv);
int cli_fuzzy(int argc, char** argv);

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

// argv on Windows is in the ANSI code page; rebuild it as UTF-8 from the wide command line.
static std::vector<std::string> utf8_args() {
    std::vector<std::string> out;
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    for (int i = 0; i < n; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(len > 0 ? static_cast<size_t>(len - 1) : 0, '\0');
        if (len > 1) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, s.data(), len, nullptr, nullptr);
        out.push_back(std::move(s));
    }
    LocalFree(w);
    return out;
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin), _O_BINARY);
    static std::vector<std::string> args = utf8_args();
    static std::vector<char*> ptrs;
    for (auto& a : args) ptrs.push_back(a.data());
    ptrs.push_back(nullptr);
    argc = static_cast<int>(args.size());
    argv = ptrs.data();
#endif
    if (argc < 2) {
        std::fprintf(stderr, "usage: brosearch-cli {grep|files|fuzzy} ...\n");
        return 2;
    }
    if (!std::strcmp(argv[1], "grep")) return cli_grep(argc - 1, argv + 1);
    if (!std::strcmp(argv[1], "files")) return cli_files(argc - 1, argv + 1);
    if (!std::strcmp(argv[1], "fuzzy")) return cli_fuzzy(argc - 1, argv + 1);
    std::fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 2;
}
