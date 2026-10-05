#include "harness.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>

namespace bt {

namespace {
int g_failures = 0;
const Case* g_current = nullptr;
std::filesystem::path g_scratch_root;

struct ScratchCleanup {
    ~ScratchCleanup() {
        if (!g_scratch_root.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(g_scratch_root, ec);
        }
    }
} g_cleanup;
} // namespace

std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}

void fail(const char* file, int line, const std::string& msg) {
    ++g_failures;
    const char* base = std::strrchr(file, '/');
    const char* base2 = std::strrchr(file, '\\');
    if (base2 > base) base = base2;
    std::cerr << "  FAIL " << (g_current ? g_current->suite : "?") << "." << (g_current ? g_current->name : "?")
              << " at " << (base ? base + 1 : file) << ":" << line << ": " << msg << "\n";
}

std::filesystem::path fixture_dir() { return std::filesystem::path(BROSEARCH_FIXTURES); }

std::filesystem::path scratch_dir(std::string_view name) {
    if (g_scratch_root.empty()) {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        g_scratch_root = std::filesystem::temp_directory_path() /
                         ("brosearch-tests-" + std::to_string(static_cast<unsigned long long>(now)));
    }
    auto dir = g_scratch_root / std::filesystem::path(std::u8string(name.begin(), name.end()));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir);
    return dir;
}

std::string read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& p, std::string_view content) {
    if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::vector<std::string> read_lines(const std::filesystem::path& p) {
    std::vector<std::string> out;
    std::string all = read_file(p);
    size_t i = 0;
    while (i < all.size()) {
        size_t nl = all.find('\n', i);
        if (nl == std::string::npos) nl = all.size();
        size_t end = nl;
        if (end > i && all[end - 1] == '\r') --end;
        out.emplace_back(all.substr(i, end - i));
        i = nl + 1;
    }
    return out;
}

} // namespace bt

int main(int argc, char** argv) {
    std::string suite, filter;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--suite") && i + 1 < argc) suite = argv[++i];
        else if (!std::strcmp(argv[i], "--filter") && i + 1 < argc) filter = argv[++i];
        else if (!std::strcmp(argv[i], "--list")) {
            for (auto& c : bt::registry()) std::cout << c.suite << "." << c.name << "\n";
            return 0;
        }
    }
    int ran = 0, failed_cases = 0;
    for (const auto& c : bt::registry()) {
        if (!suite.empty() && suite != c.suite) continue;
        std::string full = std::string(c.suite) + "." + c.name;
        if (!filter.empty() && full.find(filter) == std::string::npos) continue;
        bt::g_current = &c;
        int before = bt::g_failures;
        auto t0 = std::chrono::steady_clock::now();
        try {
            c.fn();
        } catch (const std::exception& e) {
            bt::fail(__FILE__, __LINE__, std::string("uncaught exception: ") + e.what());
        } catch (...) {
            bt::fail(__FILE__, __LINE__, "uncaught non-std exception");
        }
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        ++ran;
        bool ok = bt::g_failures == before;
        if (!ok) ++failed_cases;
        std::cout << (ok ? "[ ok ] " : "[FAIL] ") << full << " (" << static_cast<long long>(ms) << " ms)\n";
    }
    bt::g_current = nullptr;
    std::cout << ran << " tests, " << failed_cases << " failed\n";
    if (ran == 0) {
        std::cerr << "no tests matched\n";
        return 2;
    }
    return failed_cases ? 1 : 0;
}
