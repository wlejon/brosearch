#pragma once
// Shared by tools/cli_grep.cpp and tests/test_grep_oracle.cpp:
//  - materialize_corpus(): the adversarial grep corpus (encodings, binary, CRLF, huge lines, ...)
//  - run_rg_like(): an rg-compatible front end (flag subset) producing rg's output format, so the
//    live differential script can diff it against real rg, and ctest can diff it against the
//    checked-in rg outputs in tests/fixtures/grep/.

#include "brosearch/grep.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace grep_oracle {

inline void put(const std::filesystem::path& p, std::string_view content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

inline std::string utf16(std::u16string_view s, bool le, bool bom) {
    std::string out;
    auto unit = [&](char16_t u) {
        char a = static_cast<char>(u & 0xFF), b = static_cast<char>(u >> 8);
        if (le) { out.push_back(a); out.push_back(b); }
        else { out.push_back(b); out.push_back(a); }
    };
    if (bom) unit(0xFEFF);
    for (char16_t c : s) unit(c);
    return out;
}

inline void materialize_corpus(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;
    put(dir / "plain.txt",
        "Hello world\nhello World\nHELLO\nfoo_bar foo-bar foobar\n"
        "stra\xC3\x9F" "e STRASSE Stra\xC3\x9F" "e\n"
        "\xCE\xA3\xCE\xAF\xCF\x83\xCF\x85\xCF\x86\xCE\xBF\xCF\x82 \xCF\x83\xCE\xAF\xCF\x83\xCF\x85\xCF\x86\xCE\xBF\xCF\x82\n"
        "Kelvin \xE2\x84\xAA sign and k\n"
        "\xC5\xBF" "ecret Secret SECRET\n"
        "caf\xC3\xA9 CAF\xC3\x89 cafe\n"
        "tab\there  spaces   end\n"
        "x-foo -foo #foo# a#foo\n"
        "\n"
        "last line before blank\n");
    put(dir / "crlf.txt", "alpha\r\nbeta\r\nalpha beta\r\n\r\ngamma\r\n");
    put(dir / "noeol.txt", "first hello\nsecond\nthird hello");
    put(dir / "empty.txt", "");
    put(dir / "bom8.txt", "\xEF\xBB\xBFhello bom\nsecond bom line\n");
    put(dir / "utf16le.txt", utf16(u"hello utf16\nsecond line \u00e9t\u00e9\n\U0001F600 emoji hello\n", true, true));
    put(dir / "utf16be.txt", utf16(u"hello big endian\nother\n", false, true));
    put(dir / "utf16le_nobom.txt", utf16(u"hello no bom\n", true, false));
    put(dir / "binary_early.bin", std::string("\0\0hello binary\n", 16));
    {
        std::string s = "hello first\nplain middle\n";
        s += std::string(70000, 'x') + "\n";
        s += std::string("hello before nul\0hello after nul\n", 33);
        s += "hello tail\n";
        put(dir / "binary_late.dat", s);
    }
    put(dir / "tiny_bin1.dat", std::string("hi\nhello\0rest hello\n", 21));
    put(dir / "tiny_bin2.dat", std::string("hello there\nmore hello\0\nhello\n", 30));
    put(dir / "latin1.txt", "caf\xE9 hello\n\xFF\xFE broken hello\nok line\n\xC3\x28 bad seq hello\n");
    {
        // A 1.2 MB line whose words avoid what the broad cases match (keeps fixtures small).
        std::string s = "o ";
        for (int i = 0; i < 200000; ++i) s += "xyzzy ";
        s += "needle_at_end\n";
        s += "short hello\n";
        put(dir / "longline.txt", s);
    }
    {
        std::string s;
        for (int i = 1; i <= 20000; ++i) {
            s += "line " + std::to_string(i);
            if (i % 997 == 0) s += " marker";
            s += "\n";
        }
        put(dir / "numbers.txt", s);
    }
    put(dir / "context.txt",
        "one\ntwo match\nthree\nfour\nfive\nsix match\nseven match\neight\nnine\nten\neleven\ntwelve match\n");
    put(dir / "words.txt", "foo bar\nfoobar\nbarfoo\nfoo_x\n\xC3\xA9" "foo\nfoo\xC3\xA9\n(foo)\nfoo.bar\n");
    put(dir / "sub" / "deep" / "nested.txt", "hello nested\nnothing\n");
    put(dir / "sub" / "ignored_by_dotignore.txt", "hello ignored\n");
    put(dir / "sub" / ".ignore", "ignored_by_dotignore.txt\n");
    put(dir / ".hidden.txt", "hello hidden\n");
    (void)fs::path();
}

// ---- rg-compatible front end -----------------------------------------------------------------

struct Cli {
    bro::search::GrepOptions g;
    bro::search::WalkOptions w;
    std::vector<std::string> patterns;
    std::vector<std::string> paths;
    bool line_number = false, column = false, only = false, count = false, count_matches = false;
    bool files_with_matches = false, vimgrep = false, with_filename = true, stats = false;
    bool explicit_binary = false;
    int bench = 0;
};

// Parses rg-style flags. Returns false with a message on unsupported input.
inline bool parse_cli(const std::vector<std::string>& raw, Cli& c, std::string& err) {
    std::vector<std::string> args;
    // Attached short values: -A2, -m1, -C3, -j4, -gGLOB, -eX.
    for (const auto& a : raw) {
        if (a.size() > 2 && a[0] == '-' && a[1] != '-' && std::string_view("ABCmjge").find(a[1]) != std::string_view::npos) {
            args.push_back(a.substr(0, 2));
            args.push_back(a.substr(2));
        } else {
            args.push_back(a);
        }
    }
    size_t i = 0;
    auto value = [&](std::string& out) -> bool {
        if (i + 1 >= args.size()) {
            err = "missing value for " + args[i];
            return false;
        }
        out = args[++i];
        return true;
    };
    bool pattern_given = false, dashdash = false;
    for (; i < args.size(); ++i) {
        const std::string& a = args[i];
        std::string v;
        if (dashdash || a.empty() || a[0] != '-' || a == "-") {
            if (!pattern_given) {
                c.patterns.push_back(a);
                pattern_given = true;
            } else {
                c.paths.push_back(a);
            }
            continue;
        }
        if (a == "--") dashdash = true;
        else if (a == "-F" || a == "--fixed-strings") c.g.fixed_strings = true;
        else if (a == "-i" || a == "--ignore-case") c.g.case_matching = bro::search::CaseMatching::Insensitive;
        else if (a == "-s" || a == "--case-sensitive") c.g.case_matching = bro::search::CaseMatching::Sensitive;
        else if (a == "-S" || a == "--smart-case") c.g.case_matching = bro::search::CaseMatching::Smart;
        else if (a == "-w" || a == "--word-regexp") c.g.word = true;
        else if (a == "-x" || a == "--line-regexp") c.g.whole_line = true;
        else if (a == "-v" || a == "--invert-match") c.g.invert = true;
        else if (a == "-a" || a == "--text") c.g.binary = bro::search::BinaryMode::Text;
        else if (a == "--binary") c.explicit_binary = true;
        else if (a == "--crlf") c.g.crlf = true;
        else if (a == "-n" || a == "--line-number") c.line_number = true;
        else if (a == "-N" || a == "--no-line-number") c.line_number = false;
        else if (a == "--column") { c.column = true; c.line_number = true; }
        else if (a == "-o" || a == "--only-matching") c.only = true;
        else if (a == "-c" || a == "--count") c.count = true;
        else if (a == "--count-matches") c.count_matches = true;
        else if (a == "-l" || a == "--files-with-matches") c.files_with_matches = true;
        else if (a == "--vimgrep") { c.vimgrep = true; c.line_number = c.column = true; }
        else if (a == "-H" || a == "--with-filename") c.with_filename = true;
        else if (a == "-I" || a == "--no-filename") c.with_filename = false;
        else if (a == "--no-heading" || a == "--sort-files") {}
        else if (a == "--sort") { if (!value(v)) return false; }
        else if (a == "--hidden" || a == "-.") c.w.hidden = true;
        else if (a == "--no-ignore") { c.w.git_ignore = c.w.ignore_files = c.w.git_exclude = c.w.git_global = false; c.w.parents = false; }
        else if (a == "-g" || a == "--glob") { if (!value(v)) return false; c.w.globs.push_back(v); }
        else if (a == "-j" || a == "--threads") { if (!value(v)) return false; c.g.threads = c.w.threads = std::strtoull(v.c_str(), nullptr, 10); }
        else if (a == "-e" || a == "--regexp") { if (!value(v)) return false; c.patterns.push_back(v); pattern_given = true; }
        else if (a == "-A" || a == "--after-context") { if (!value(v)) return false; c.g.after_context = std::strtoull(v.c_str(), nullptr, 10); }
        else if (a == "-B" || a == "--before-context") { if (!value(v)) return false; c.g.before_context = std::strtoull(v.c_str(), nullptr, 10); }
        else if (a == "-C" || a == "--context") { if (!value(v)) return false; c.g.after_context = c.g.before_context = std::strtoull(v.c_str(), nullptr, 10); }
        else if (a == "-m" || a == "--max-count") { if (!value(v)) return false; c.g.max_count = std::strtoull(v.c_str(), nullptr, 10); }
        else if (a == "--stats") c.stats = true;
        else if (a.rfind("--bench=", 0) == 0) c.bench = std::atoi(a.c_str() + 8);
        else {
            err = "unsupported flag: " + a;
            return false;
        }
    }
    if (c.patterns.empty()) {
        err = "no pattern given";
        return false;
    }
    if (c.patterns.size() > 1) {
        // rg -e a -e b == a|b. Fixed strings are escaped first.
        std::string joined;
        for (size_t k = 0; k < c.patterns.size(); ++k) {
            if (k) joined += "|";
            if (c.g.fixed_strings) {
                for (char ch : c.patterns[k]) {
                    if (std::string_view("\\.+*?()|[]{}^$#&-~").find(ch) != std::string_view::npos) joined += '\\';
                    joined += ch;
                }
            } else {
                joined += "(?:" + c.patterns[k] + ")";
            }
        }
        c.patterns = {joined};
        c.g.fixed_strings = false;
    }
    if (c.paths.empty()) c.paths.push_back(".");
    // rg matches ignore patterns case-sensitively everywhere (the library default, Auto, follows
    // git's core.ignorecase instead).
    c.w.ignore_case = bro::search::CaseMode::Sensitive;
    // Summary modes need no line text; -l stops at the first match like rg.
    if (c.count || c.count_matches || c.files_with_matches) {
        c.g.collect_lines = false;
        c.g.line_numbers = false;
        c.g.collect_spans = c.count_matches;
        if (c.files_with_matches) c.g.max_count = 1;
    }
    return true;
}

// rg --sort path order: component-wise by name (a directory's entries before a sibling whose
// name extends the directory's, e.g. "a/x" before "a.txt").
inline bool path_less(const std::string& a, const std::string& b) {
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        unsigned char x = a[i] == '/' ? 0 : static_cast<unsigned char>(a[i]);
        unsigned char y = b[i] == '/' ? 0 : static_cast<unsigned char>(b[i]);
        if (x != y) return x < y;
    }
    return a.size() < b.size();
}

// Formats one file's result exactly like rg --no-heading (paths with '/').
inline void format_file(const Cli& c, const bro::search::GrepFileResult& r, const std::string& display,
                        bool& printed_any, std::string& out) {
    using bro::search::LineKind;
    if (r.matched_lines == 0 && !r.binary_matched) return;
    auto num = [&](uint64_t v, char sep) {
        char buf[24];
        auto res = std::to_chars(buf, buf + sizeof buf, v);
        out.append(buf, res.ptr);
        out.push_back(sep);
    };
    // Appends "path:line:col:" (each part only when enabled), then `text` and a newline.
    auto row = [&](char sep, uint64_t line, size_t col, std::string_view text) {
        if (c.with_filename) {
            out += display;
            out.push_back(sep);
        }
        if (c.line_number) num(line, sep);
        if (c.column && col) num(col, sep);
        out += text;
        out.push_back('\n');
    };
    const std::string nul_note = "(found \"\\0\" byte around offset " + std::to_string(r.binary_offset) + ")";
    // rg's counting printers (-c, --count-matches) ignore files where quit-mode binary detection
    // fired, even when lines before the NUL matched. (-l stops at the first match, before the
    // NUL's block is read, so it lists them.)
    const bool counting = c.count || c.count_matches;
    if (counting && r.binary && c.g.binary == bro::search::BinaryMode::Quit) return;
    if (r.matched_lines == 0 && !c.files_with_matches && !c.count && !c.count_matches) {
        out += display + ": binary file matches " + nul_note + "\n";
        printed_any = true;
        return;
    }
    if (c.files_with_matches) {
        out += display + "\n";
        printed_any = true;
        return;
    }
    if (c.count || c.count_matches) {
        size_t n = c.count_matches ? (c.g.invert ? r.matched_lines : r.matches) : r.matched_lines;
        out += (c.with_filename ? display + ":" : std::string()) + std::to_string(n) + "\n";
        printed_any = true;
        return;
    }
    const bool context = c.g.after_context || c.g.before_context;
    uint64_t prev_line = 0;
    bool first_in_file = true;
    for (const auto& l : r.lines) {
        if (context && printed_any && (first_in_file || l.line_number != prev_line + 1)) out += "--\n";
        first_in_file = false;
        prev_line = l.line_number;
        printed_any = true;
        if (l.kind == LineKind::Context) {
            row('-', l.line_number, 0, l.text);
            continue;
        }
        if (c.only && !c.g.invert) {
            std::string_view t(l.text);
            for (const auto& s : l.spans) row(':', l.line_number, s.start + 1, t.substr(s.start, s.end - s.start));
            continue;
        }
        if (c.vimgrep && !c.g.invert) {
            for (const auto& s : l.spans) row(':', l.line_number, s.start + 1, l.text);
            continue;
        }
        size_t col = l.spans.empty() ? 1 : l.spans[0].start + 1;
        row(':', l.line_number, col, l.text);
    }
    if (r.binary_matched) {
        out += display + ": binary file matches " + nul_note + "\n";
    } else if (r.binary && c.g.binary == bro::search::BinaryMode::Quit) {
        out += display + ": WARNING: stopped searching binary file after match " + nul_note + "\n";
    }
}

// Runs a search the way `rg ARGS` would (from the current directory) and returns its stdout.
// Files are processed in sorted path order (rg --sort path). Returns rg's exit code: 0 = matches,
// 1 = none, 2 = error.
inline int run_rg_like(const std::vector<std::string>& args, std::string& out, std::string& err,
                       bro::search::GrepStats* stats_out = nullptr) {
    namespace bs = bro::search;
    Cli c;
    if (!parse_cli(args, c, err)) return 2;
    if (!c.line_number && !c.column) {}
    std::string perr;
    auto grep = bs::Grep::compile(c.patterns[0], c.g, &perr);
    if (!grep) {
        err = perr;
        return 2;
    }
    // Each file is formatted where it was searched (in the worker), as though something had been
    // printed before it; the leading context separator of whichever chunk prints first is dropped.
    struct Item {
        std::string display;
        std::string text;
    };
    std::vector<Item> items;
    std::mutex mu;
    std::atomic<bool> matched{false};
    auto add = [&](std::string display, const bs::GrepFileResult& r) {
        if (r.matched_lines || r.binary_matched) matched = true;
        bool printed = true;
        std::string text;
        format_file(c, r, display, printed, text);
        if (text.empty()) return;
        std::lock_guard<std::mutex> lock(mu);
        items.push_back({std::move(display), std::move(text)});
    };
    bs::GrepStats total;
    for (const auto& root : c.paths) {
        std::filesystem::path rp = std::filesystem::path(std::u8string(root.begin(), root.end()));
        std::error_code ec;
        if (std::filesystem::is_regular_file(rp, ec)) {
            // Explicit files: rg searches binary files in "convert" mode and reports them.
            bs::GrepOptions go = c.g;
            if (go.binary == bs::BinaryMode::Quit) go.binary = bs::BinaryMode::Report;
            auto g2 = bs::Grep::compile(c.patterns[0], go, &perr);
            add(root, g2->search_file(rp));
            continue;
        }
        bs::GrepStats st;
        auto gg = grep;
        if (c.explicit_binary) {
            bs::GrepOptions go = c.g;
            go.binary = bs::BinaryMode::Report;
            gg = bs::Grep::compile(c.patterns[0], go, &perr);
        }
        gg->search_tree(rp, c.w, [&](const bs::GrepFileResult& r) {
            if (!r.error.empty()) return true;
            add(root == "." ? "./" + r.path : root + "/" + r.path, r);
            return true;
        }, nullptr, &st);
        total.files_searched += st.files_searched;
        total.files_matched += st.files_matched;
        total.matched_lines += st.matched_lines;
        total.matches += st.matches;
        total.bytes_searched += st.bytes_searched;
        total.elapsed_ms += st.elapsed_ms;
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return path_less(a.display, b.display); });
    for (auto& it : items) {
        std::string_view t(it.text);
        if (out.empty() && (c.g.after_context || c.g.before_context) && t.substr(0, 3) == "--\n") t.remove_prefix(3);
        out += t;
    }
    if (stats_out) *stats_out = total;
    return matched.load() ? 0 : 1;
}

} // namespace grep_oracle
