// Replays ripgrep's recorded output for every case in tests/fixtures/grep/cases.txt against the
// rg-compatible front end over the materialized corpus. Regenerate with scripts/diff_grep.sh
// --update (needs rg); this test needs neither rg nor the CLI.

#include "harness.h"

#include "grep_oracle.h"

namespace {

// Shell-word splitting for the cases file (single quotes, double quotes, backslash escapes).
std::vector<std::string> shell_words(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_word = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '\'') {
            in_word = true;
            size_t j = s.find('\'', i + 1);
            cur.append(s.substr(i + 1, j - i - 1));
            i = j;
        } else if (c == '"') {
            in_word = true;
            for (++i; i < s.size() && s[i] != '"'; ++i) {
                if (s[i] == '\\' && i + 1 < s.size()) ++i;
                cur.push_back(s[i]);
            }
        } else if (c == '\\' && i + 1 < s.size()) {
            in_word = true;
            cur.push_back(s[++i]);
        } else if (c == ' ' || c == '\t') {
            if (in_word) out.push_back(cur);
            cur.clear();
            in_word = false;
        } else {
            in_word = true;
            cur.push_back(c);
        }
    }
    if (in_word) out.push_back(cur);
    return out;
}

std::string trim_trailing_newlines(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

} // namespace

TEST(grep, rg_oracle_corpus) {
    auto corpus = bt::scratch_dir("grep-corpus");
    grep_oracle::materialize_corpus(corpus);
    auto cases = bt::read_lines(bt::fixture_dir() / "grep" / "cases.txt");
    auto old = std::filesystem::current_path();
    std::filesystem::current_path(corpus);
    int ran = 0;
    for (const auto& line : cases) {
        if (line.empty() || line[0] == '#') continue;
        size_t tab = line.find('\t');
        std::string name = line.substr(0, tab);
        std::vector<std::string> args = shell_words(line.substr(tab + 1));
        args.push_back(".");
        std::string expected = bt::read_file(bt::fixture_dir() / "grep" / (name + ".out"));
        std::string out, err;
        grep_oracle::run_rg_like(args, out, err);
        if (!err.empty()) out += err;
        CHECK_MSG(trim_trailing_newlines(out) == trim_trailing_newlines(expected),
                  "case " << name << "\n--- expected (rg)\n" << expected.substr(0, 2000) << "\n--- got\n"
                          << out.substr(0, 2000));
        ++ran;
    }
    std::filesystem::current_path(old);
    CHECK(ran >= 50);
}
