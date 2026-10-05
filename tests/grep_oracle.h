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
#include <functional>
#include <memory>
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
    {
        // NUL past rg's first 64 KiB read, so rg's block boundaries (and their shift when it
        // keeps context lines across a roll) decide what is searched before it.
        std::string s;
        for (int i = 1; i <= 20000; ++i) s += "row " + std::to_string(i) + "\n";
        s += std::string("x\0y\nneedle row\nlast row\n", 24);
        put(dir / "binary_big.dat", s);
    }
    put(dir / "binary_mixed.dat", std::string("hello one\nhello two\0hello three\nfoo\nhello four\n", 47));
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
    // Script properties: U+0342 (Inherited, scx Greek), U+00B7 (Common, scx many), U+30FC
    // (Common, scx Hira Kana), U+0951 (Inherited, scx Deva ...), U+0378 (unassigned: Unknown).
    put(dir / "scripts.txt",
        "greek \xCE\xB1\xCE\xB2\xCE\xB3 \xCE\xB4\n"
        "perispomeni \xCD\x82 alone\n"
        "middle \xC2\xB7 dot\n"
        "han \xE4\xB8\xAD\xE6\x96\x87\xE5\xAD\x97\n"
        "kana \xE3\x81\xB2\xE3\x82\x89 \xE3\x82\xAB\xE3\x82\xBF \xE3\x83\xBC\n"
        "cyrillic \xD0\x96\xD1\x83\xD0\xBA\n"
        "unknown \xCD\xB8 here\n"
        "deva \xE0\xA4\x95\xE0\xA5\x91\n");
    // Multiline (-U) blocks, adjacency and per-block columns.
    put(dir / "multi.txt",
        "alpha one\nbeta two\ngamma three\nalpha four beta\ndelta five\nepsilon alpha\nbeta six\n"
        "zeta seven\nalpha\nbeta\nend\n");
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
    bool pattern_given = false, dashdash = false, filename_set = false;
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
        else if (a == "-U" || a == "--multiline") c.g.multiline = true;
        else if (a == "--multiline-dotall") c.g.multiline_dotall = true;
        else if (a == "-n" || a == "--line-number") c.line_number = true;
        else if (a == "-N" || a == "--no-line-number") c.line_number = false;
        else if (a == "--column") { c.column = true; c.line_number = true; }
        else if (a == "-o" || a == "--only-matching") c.only = true;
        else if (a == "-c" || a == "--count") c.count = true;
        else if (a == "--count-matches") c.count_matches = true;
        else if (a == "-l" || a == "--files-with-matches") c.files_with_matches = true;
        else if (a == "--vimgrep") { c.vimgrep = true; c.line_number = c.column = true; }
        else if (a == "-H" || a == "--with-filename") { c.with_filename = true; filename_set = true; }
        else if (a == "-I" || a == "--no-filename") { c.with_filename = false; filename_set = true; }
        // --no-mmap: this front end always models rg's buffered reader (rg memory-maps a few
        // explicitly named files on Windows and Linux, and its binary detection differs there).
        else if (a == "--no-heading" || a == "--sort-files" || a == "--no-mmap") {}
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
    if (!filename_set) {
        // rg shows file names unless it was given exactly one path and that path is a file.
        std::error_code ec;
        const std::string& p = c.paths[0];
        c.with_filename = c.paths.size() > 1 ||
                          !std::filesystem::is_regular_file(std::filesystem::path(std::u8string(p.begin(), p.end())), ec);
    }
    // rg matches ignore patterns case-sensitively everywhere (the library default, Auto, follows
    // git's core.ignorecase instead).
    c.w.ignore_case = bro::search::CaseMode::Sensitive;
    // Summary modes need no line text; -l stops at the first match like rg.
    if (c.count || c.count_matches || c.files_with_matches) {
        c.g.collect_lines = false;
        c.g.line_numbers = false;
        c.g.collect_spans = c.count_matches;
        if (c.files_with_matches) c.g.max_count = 1;
    } else if (!c.only && !c.vimgrep) {
        // A plain line needs at most its first match (for --column), as rg's printer does.
        if (c.column) c.g.max_spans_per_line = 1;
        else c.g.collect_spans = false;
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

// Formats one file exactly like rg --no-heading (paths with '/'), streaming: lines are formatted
// as the searching worker reports them, the per-file summary when it finishes. Output is
// formatted as though something had been printed before this file (see run_rg_like).
class Formatter final : public bro::search::GrepFileVisitor {
public:
    using Done = std::function<void(Formatter&, const bro::search::GrepFileResult&)>;
    Formatter(const Cli& c, std::string_view display, const Done& done) : display_(display), c_(c), done_(done) {}

    std::string display_;
    std::string out;

    bool line(const bro::search::GrepLineView& l) override {
        using bro::search::LineKind;
        const bool context = c_.g.after_context || c_.g.before_context;
        if (context && (first_ || l.line_number != prev_line_ + 1)) out += "--\n";
        first_ = false;
        prev_line_ = l.line_number;
        prev_end_ = l.byte_offset + l.text.size() + 1;
        if (l.kind == LineKind::Context) {
            row('-', l.line_number, 0, l.text);
            return true;
        }
        if (!l.region_continued) block_start_ = l.byte_offset;
        if (c_.only && !c_.g.invert) {
            // rg's -o column counts from the start of the block of lines (one line unless
            // multiline), and a match's later pieces repeat its start column.
            for (const auto& s : l.spans) {
                const uint64_t abs = s.continued ? match_start_ : l.byte_offset + s.start;
                if (!s.continued) match_start_ = abs;
                row(':', l.line_number, static_cast<size_t>(abs - block_start_ + 1),
                    l.text.substr(s.start, s.end - s.start));
            }
            return true;
        }
        if (c_.vimgrep && !c_.g.invert) {
            // One row per match, on the line where it starts.
            for (const auto& s : l.spans)
                if (!s.continued) row(':', l.line_number, s.start + 1, l.text);
            return true;
        }
        // Every line of a multiline region shows the column of the region's first match.
        size_t col = l.spans.empty() ? 1 : l.spans[0].start + 1;
        if (l.region_continued) col = region_col_;
        else region_col_ = col;
        row(':', l.line_number, col, l.text);
        return true;
    }

    bool finish(const bro::search::GrepFileResult& r) override {
        summary(r);
        done_(*this, r);
        return true;
    }

private:
    const Cli& c_;
    const Done& done_;
    uint64_t prev_line_ = 0;
    uint64_t prev_end_ = 0;
    bool first_ = true;
    size_t region_col_ = 1;
    uint64_t block_start_ = 0;  // byte offset of the current block's first line
    uint64_t match_start_ = 0;  // byte offset of the last match that started

    void num(uint64_t v, char sep) {
        char buf[24];
        auto res = std::to_chars(buf, buf + sizeof buf, v);
        out.append(buf, res.ptr);
        out.push_back(sep);
    }
    // Appends "path:line:col:" (each part only when enabled), then `text` and a newline.
    void row(char sep, uint64_t line, size_t col, std::string_view text) {
        if (c_.with_filename) {
            out += display_;
            out.push_back(sep);
        }
        if (c_.line_number) num(line, sep);
        if (c_.column && col) num(col, sep);
        out += text;
        out.push_back('\n');
    }

    void summary(const bro::search::GrepFileResult& r) {
        if (!r.error.empty() || (r.matched_lines == 0 && !r.binary_matched)) return;
        const std::string nul_note = "(found \"\\0\" byte around offset " + std::to_string(r.binary_offset) + ")";
        const std::string who = c_.with_filename ? display_ + ": " : std::string();
        // rg's counting printers (-c, --count-matches) ignore files where quit-mode binary
        // detection fired, even when lines before the NUL matched. (-l stops at the first match,
        // before the NUL's block is read, so it lists them.)
        const bool counting = c_.count || c_.count_matches;
        if (counting && r.binary && c_.g.binary == bro::search::BinaryMode::Quit) return;
        if (r.matched_lines == 0 && !c_.files_with_matches && !counting) {
            out += who + "binary file matches " + nul_note + "\n";
            return;
        }
        if (c_.files_with_matches) {
            out += display_ + "\n";
            return;
        }
        if (counting) {
            size_t n = c_.count_matches ? (c_.g.invert ? r.matched_lines : r.matches) : r.matched_lines;
            out += (c_.with_filename ? display_ + ":" : std::string()) + std::to_string(n) + "\n";
            return;
        }
        if (r.binary_matched) {
            // rg breaks the context before the line it stopped at, if it is not adjacent.
            const bool context = c_.g.after_context || c_.g.before_context;
            if (context && !first_ && r.binary_stop_offset != UINT64_MAX && r.binary_stop_offset != prev_end_)
                out += "--\n";
            out += who + "binary file matches " + nul_note + "\n";
        } else if (r.binary && c_.g.binary == bro::search::BinaryMode::Quit) {
            out += who + "WARNING: stopped searching binary file after match " + nul_note + "\n";
        }
    }
};

// Runs a search the way `rg ARGS` would (from the current directory) and returns its stdout.
// Files are processed in sorted path order (rg --sort path). Returns rg's exit code: 0 = matches,
// 1 = none, 2 = error.
// Output goes to `write` in order, one chunk per file (no final concatenation).
using Writer = std::function<void(std::string_view)>;
inline int run_rg_like(const std::vector<std::string>& args, const Writer& write, std::string& err,
                       bro::search::GrepStats* stats_out = nullptr) {
    namespace bs = bro::search;
    Cli c;
    if (!parse_cli(args, c, err)) return 2;
    std::string perr;
    auto grep = bs::Grep::compile(c.patterns[0], c.g, &perr);
    if (!grep) {
        err = perr;
        return 2;
    }
    // Each file is formatted where it was searched (in the worker), as though something had been
    // printed before it; the leading context separator of whichever chunk prints first is dropped.
    struct Item {
        size_t root;  // rg keeps the order of the paths it was given; --sort path sorts within each
        std::string display;
        std::string text;
    };
    std::vector<Item> items;
    std::mutex mu;
    std::atomic<bool> matched{false};
    size_t root_index = 0;
    const Formatter::Done done = [&](Formatter& f, const bs::GrepFileResult& r) {
        if (r.error.empty() && (r.matched_lines || r.binary_matched)) matched = true;
        if (f.out.empty()) return;
        std::lock_guard<std::mutex> lock(mu);
        items.push_back({root_index, std::move(f.display_), std::move(f.out)});
    };
    bs::GrepStats total;
    for (; root_index < c.paths.size(); ++root_index) {
        const std::string& root = c.paths[root_index];
        std::filesystem::path rp = std::filesystem::path(std::u8string(root.begin(), root.end()));
        std::error_code ec;
        if (std::filesystem::is_regular_file(rp, ec)) {
            // Explicit files: rg searches binary files in "convert" mode and reports them.
            bs::GrepOptions go = c.g;
            if (go.binary == bs::BinaryMode::Quit) go.binary = bs::BinaryMode::Report;
            auto g2 = bs::Grep::compile(c.patterns[0], go, &perr);
            Cli ce = c;
            ce.g = go;
            Formatter f(ce, root, done);
            g2->search_file(rp, root, f);
            continue;
        }
        bs::GrepStats st;
        auto gg = grep;
        Cli cb = c;
        if (c.explicit_binary) {
            cb.g.binary = bs::BinaryMode::Report;
            gg = bs::Grep::compile(c.patterns[0], cb.g, &perr);
        }
        const std::string prefix = root == "." ? "./" : root + "/";
        gg->search_tree(rp, c.w, [&](std::string_view path) {
            std::string display = prefix;
            display += path;
            return std::make_unique<Formatter>(cb, display, done);
        }, nullptr, &st);
        total.files_searched += st.files_searched;
        total.files_matched += st.files_matched;
        total.matched_lines += st.matched_lines;
        total.matches += st.matches;
        total.bytes_searched += st.bytes_searched;
        total.elapsed_ms += st.elapsed_ms;
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        return a.root != b.root ? a.root < b.root : path_less(a.display, b.display);
    });
    bool first = true;
    for (auto& it : items) {
        std::string_view t(it.text);
        if (first && (c.g.after_context || c.g.before_context) && t.substr(0, 3) == "--\n") t.remove_prefix(3);
        first = false;
        write(t);
    }
    if (stats_out) *stats_out = total;
    return matched.load() ? 0 : 1;
}

inline int run_rg_like(const std::vector<std::string>& args, std::string& out, std::string& err,
                       bro::search::GrepStats* stats_out = nullptr) {
    return run_rg_like(args, [&](std::string_view t) { out += t; }, err, stats_out);
}

} // namespace grep_oracle
