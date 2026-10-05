#pragma once
// Minimal test harness. CHECK* record a failure and keep going; they are active in every
// build configuration (Release included), unlike assert().
//
//   TEST(suite, name) { CHECK(cond); CHECK_EQ(a, b); }
//
// Suites map 1:1 to ctest entries (`brosearch_tests --suite <suite>`); see CMakeLists.txt.

#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace bt {

struct Case {
    const char* suite;
    const char* name;
    void (*fn)();
};

std::vector<Case>& registry();

struct Reg {
    Reg(const char* suite, const char* name, void (*fn)()) { registry().push_back({suite, name, fn}); }
};

void fail(const char* file, int line, const std::string& msg);

// Directory with checked-in fixture files (tests/fixtures).
std::filesystem::path fixture_dir();

// Fresh, empty scratch directory unique to this process + name. Removed at process exit.
std::filesystem::path scratch_dir(std::string_view name);

// Whole-file helpers (binary mode, no newline translation).
std::string read_file(const std::filesystem::path& p);
void write_file(const std::filesystem::path& p, std::string_view content);
std::vector<std::string> read_lines(const std::filesystem::path& p);  // strips \n and \r\n

template <typename T>
std::string show(const T& v) {
    if constexpr (requires(std::ostream& o) { o << v; }) {
        std::ostringstream o;
        o << v;
        return o.str();
    } else if constexpr (requires { v.begin(); v.end(); v.size(); }) {
        std::ostringstream o;
        o << "[" << v.size() << "]{";
        size_t n = 0;
        for (const auto& e : v) {
            if (n++) o << ", ";
            if (n > 40) { o << "..."; break; }
            o << show(e);
        }
        o << "}";
        return o.str();
    } else {
        return "<?>";
    }
}

} // namespace bt

#define BT_TEST_FN(suite, name) bt_test_##suite##_##name
#define TEST(suite, name)                                                                 \
    static void BT_TEST_FN(suite, name)();                                                \
    static ::bt::Reg bt_reg_##suite##_##name(#suite, #name, &BT_TEST_FN(suite, name));    \
    static void BT_TEST_FN(suite, name)()

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) ::bt::fail(__FILE__, __LINE__, "CHECK(" #cond ")");  \
    } while (0)

#define CHECK_MSG(cond, msg)                                                         \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::ostringstream bt_o_;                                                \
            bt_o_ << "CHECK(" #cond "): " << msg;                                    \
            ::bt::fail(__FILE__, __LINE__, bt_o_.str());                             \
        }                                                                            \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        const auto bt_a_ = (a); /* copies: (a) may be a reference to a temporary */        \
        const auto bt_b_ = (b);                                                            \
        if (!(bt_a_ == bt_b_)) {                                                           \
            ::bt::fail(__FILE__, __LINE__,                                                 \
                       "CHECK_EQ(" #a ", " #b "): " + ::bt::show(bt_a_) + " != " +         \
                           ::bt::show(bt_b_));                                             \
        }                                                                                  \
    } while (0)
