#include "harness.h"

#include "brosearch/grep.h"
#include "grep/decode.h"

#include <atomic>
#include <chrono>
#include <thread>

using namespace bro::search;

namespace {

struct L {
    char kind;  // ':' match, '-' context
    uint64_t line;
    std::string text;
    bool operator==(const L&) const = default;
};
std::ostream& operator<<(std::ostream& o, const L& l) { return o << l.line << l.kind << l.text; }
using Ls = std::vector<L>;

std::vector<L> run(std::string_view pat, std::string_view buf, GrepOptions o = GrepOptions()) {
    std::string err;
    auto g = Grep::compile(pat, o, &err);
    if (!g) {
        bt::fail(__FILE__, __LINE__, "compile failed: " + err);
        return {};
    }
    std::vector<L> out;
    for (auto& l : g->search_buffer(buf)) out.push_back({l.kind == LineKind::Match ? ':' : '-', l.line_number, l.text});
    return out;
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

} // namespace

TEST(grep, last_line_without_newline) {
    CHECK_EQ(run("hello\\z", "first hello\nsecond\nthird hello"), (Ls{{':', 1, "first hello"}, {':', 3, "third hello"}}));
    CHECK_EQ(run("\\w+ hello", "first hello\nsecond\nthird hello"), (Ls{{':', 1, "first hello"}, {':', 3, "third hello"}}));
    CHECK_EQ(run("o$", "o\nxo"), (Ls{{':', 1, "o"}, {':', 2, "xo"}}));
    CHECK_EQ(run("^$", "a\n\nb\n"), (Ls{{':', 2, ""}}));
    CHECK_EQ(run("^", "a\nb\n"), (Ls{{':', 1, "a"}, {':', 2, "b"}}));
    CHECK_EQ(run("^", ""), (Ls{}));
    CHECK_EQ(run("x*", "a\n"), (Ls{{':', 1, "a"}}));
}

TEST(grep, context_invert_max_count) {
    const char* text = "a1\nb\nc\na2\nd\ne\nf\ng\na3\n";
    GrepOptions o;
    o.before_context = 1;
    o.after_context = 1;
    CHECK_EQ(run("a", text, o), (Ls{{':', 1, "a1"}, {'-', 2, "b"}, {'-', 3, "c"}, {':', 4, "a2"}, {'-', 5, "d"},
                                    {'-', 8, "g"}, {':', 9, "a3"}}));
    GrepOptions inv;
    inv.invert = true;
    CHECK_EQ(run("[a-e]", text, inv), (Ls{{':', 7, "f"}, {':', 8, "g"}}));
    inv.max_count = 1;
    CHECK_EQ(run("[a-e]", text, inv), (Ls{{':', 7, "f"}}));
    GrepOptions mc;
    mc.max_count = 2;
    mc.after_context = 2;
    // Trailing context after the last allowed match shows selected lines as matches (rg).
    CHECK_EQ(run("a|d", text, mc), (Ls{{':', 1, "a1"}, {'-', 2, "b"}, {'-', 3, "c"}, {':', 4, "a2"}, {':', 5, "d"},
                                       {'-', 6, "e"}}));
    GrepOptions ic;
    ic.invert = true;
    ic.after_context = 1;
    CHECK_EQ(run("^.$", "x\nyy\nz\n", ic), (Ls{{':', 2, "yy"}, {'-', 3, "z"}}));
}

TEST(grep, spans_and_columns) {
    auto g = Grep::compile("o", GrepOptions());
    auto lines = g->search_buffer("foo boo\nbar\n");
    CHECK_EQ(lines.size(), size_t(1));
    if (lines.size() == 1) {
        CHECK_EQ(lines[0].spans, (std::vector<GrepSpan>{{1, 2}, {2, 3}, {5, 6}, {6, 7}}));
        CHECK_EQ(lines[0].byte_offset, uint64_t(0));
    }
    auto e = Grep::compile("x*", GrepOptions());
    auto el = e->search_buffer("ab\n");
    CHECK_EQ(el.size(), size_t(1));
    if (el.size() == 1) CHECK_EQ(el[0].spans, (std::vector<GrepSpan>{{0, 0}, {1, 1}, {2, 2}}));
    GrepOptions w;
    w.word = true;
    w.fixed_strings = true;
    auto wl = Grep::compile("foo", w)->search_buffer("foo foobar xfoo (foo)\n");
    CHECK_EQ(wl.size(), size_t(1));
    if (wl.size() == 1) CHECK_EQ(wl[0].spans, (std::vector<GrepSpan>{{0, 3}, {17, 20}}));
}

TEST(grep, case_modes_unicode) {
    GrepOptions ci;
    ci.case_matching = CaseMatching::Insensitive;
    CHECK_EQ(run("\xC3\xA9t\xC3\xA9", "\xC3\x89T\xC3\x89\nete\n", ci), (Ls{{':', 1, "\xC3\x89T\xC3\x89"}}));
    ci.fixed_strings = true;
    CHECK_EQ(run("\xCF\x83\xCE\xAF\xCF\x83\xCF\x85\xCF\x86\xCE\xBF\xCF\x82",
                 "\xCE\xA3\xCE\x8A\xCE\xA3\xCE\xA5\xCE\xA6\xCE\x9F\xCE\xA3\n", ci)
                 .size(),
             size_t(1));
    // Non-ASCII bytes in the haystack never break case-insensitive literal search.
    CHECK_EQ(run("hello", "\xFF\xFE\x80 HELLO \xC3\n\xE9t\xE9 hello\n", ci).size(), size_t(2));
    // Non-ASCII pattern with invalid UTF-8 haystack.
    CHECK_EQ(run("\xC3\xA9", "caf\xE9\ncaf\xC3\x89\n", ci), (Ls{{':', 2, "caf\xC3\x89"}}));
    GrepOptions smart;
    smart.case_matching = CaseMatching::Smart;
    CHECK_EQ(run("abc", "ABC\n", smart).size(), size_t(1));
    CHECK_EQ(run("Abc", "ABC\n", smart).size(), size_t(0));
}

TEST(grep, file_encodings_and_binary) {
    auto dir = bt::scratch_dir("grep-files");
    bt::write_file(dir / "bom8.txt", "\xEF\xBB\xBFhello\n");
    bt::write_file(dir / "le.txt", std::string("\xFF\xFEh\0i\0\n\0h\0e\0l\0l\0o\0\n\0", 20));
    bt::write_file(dir / "be.txt", std::string("\xFE\xFF\0h\0e\0l\0l\0o\0\n", 14));
    bt::write_file(dir / "bad16.txt", std::string("\xFF\xFE\x00\xD8h\0e\0l\0l\0o\0\n\0x", 17));  // lone surrogate + odd byte
    // Not "nul.bin": Windows before 11 reserves NUL.<any extension> as the null device.
    bt::write_file(dir / "early_nul.bin", std::string("hello\n\0hello\n", 13));
    bt::write_file(dir / "late.bin", "hi\nhello\n" + std::string(100000, 'y') + "\n" + std::string(1, '\0') + "hello\n");
    auto g = Grep::compile("hello", GrepOptions());
    auto r = g->search_file(dir / "bom8.txt");
    CHECK_EQ(r.lines.size(), size_t(1));
    if (!r.lines.empty()) CHECK_EQ(r.lines[0].spans[0].start, size_t(0));  // BOM stripped
    r = g->search_file(dir / "le.txt");
    CHECK_EQ(r.lines.size(), size_t(1));
    if (!r.lines.empty()) CHECK_EQ(r.lines[0].line_number, uint64_t(2));
    CHECK_EQ(g->search_file(dir / "be.txt").lines.size(), size_t(1));
    r = g->search_file(dir / "bad16.txt");
    CHECK_EQ(r.lines.size(), size_t(1));
    if (!r.lines.empty()) CHECK_EQ(r.lines[0].text, std::string("\xEF\xBF\xBDhello"));
    // NUL within the first block: nothing searched (rg quit mode).
    r = g->search_file(dir / "early_nul.bin");
    CHECK_MSG(r.binary, "error '" << r.error << "', " << r.bytes_searched << " bytes searched");
    CHECK_EQ(r.matched_lines, size_t(0));
    // NUL in a later block: earlier complete lines are searched.
    r = g->search_file(dir / "late.bin");
    CHECK(r.binary);
    CHECK_EQ(r.matched_lines, size_t(1));
    GrepOptions text;
    text.binary = BinaryMode::Text;
    CHECK_EQ(Grep::compile("hello", text)->search_file(dir / "late.bin").matched_lines, size_t(2));
    GrepOptions report;
    report.binary = BinaryMode::Report;
    r = Grep::compile("hello", report)->search_file(dir / "early_nul.bin");
    CHECK_MSG(r.binary_matched, "error '" << r.error << "', " << r.bytes_searched << " bytes searched");
    CHECK(r.lines.empty());
    r = g->search_file(dir / "missing.txt");
    CHECK(!r.error.empty());
    GrepOptions nobom;
    nobom.bom_sniffing = false;
    CHECK_EQ(Grep::compile("hello", nobom)->search_file(dir / "le.txt").matched_lines, size_t(0));
}

TEST(grep, binary_cutoff_model) {
    using grep_detail::rg_binary_cutoff;
    std::string s("hi\nhello\0rest\n", 14);
    const auto* d = reinterpret_cast<const uint8_t*>(s.data());
    CHECK_EQ(rg_binary_cutoff(d, s.size(), 8), size_t(3));  // first read is the 3 BOM-sniff bytes
    std::string t("hello there\nmore\0", 17);
    CHECK_EQ(rg_binary_cutoff(reinterpret_cast<const uint8_t*>(t.data()), t.size(), 16), size_t(0));
    std::string u = std::string(70000, 'a') + "\n" + std::string(10, 'b') + std::string(1, '\0');
    CHECK_EQ(rg_binary_cutoff(reinterpret_cast<const uint8_t*>(u.data()), u.size(), u.size() - 1), size_t(0));
}

TEST(grep, utf16_transcoding) {
    std::string out;
    const uint8_t pair[] = {0x3D, 0xD8, 0x00, 0xDE};  // U+1F600 as LE surrogate pair
    grep_detail::transcode_utf16(pair, 4, true, out);
    CHECK_EQ(out, std::string("\xF0\x9F\x98\x80"));
    out.clear();
    const uint8_t lone[] = {0x00, 0xDC, 0x41, 0x00};  // lone low surrogate, then 'A'
    grep_detail::transcode_utf16(lone, 4, true, out);
    CHECK_EQ(out, std::string("\xEF\xBF\xBD" "A"));
}

TEST(grep, huge_line_and_pathological) {
    std::string big;
    big.reserve(20u << 20);
    for (int i = 0; i < 2000000; ++i) big += "abcdefghi ";
    big += "NEEDLE\n";
    auto t0 = std::chrono::steady_clock::now();
    GrepOptions o;
    auto l = Grep::compile("NEE+DLE", o)->search_buffer(big);
    CHECK_EQ(l.size(), size_t(1));
    auto l2 = Grep::compile("(a|b)*z", o)->search_buffer(big);
    CHECK_EQ(l2.size(), size_t(0));
    auto l3 = Grep::compile("\\bNEEDLE\\b", o)->search_buffer(big);
    CHECK_EQ(l3.size(), size_t(1));
    GrepOptions ci;
    ci.case_matching = CaseMatching::Insensitive;
    auto l4 = Grep::compile("needle", ci)->search_buffer(big);
    CHECK_EQ(l4.size(), size_t(1));
    double ms = ms_since(t0);
    CHECK_MSG(ms < 30000, "huge line searches took " << ms << " ms");
}

TEST(grep, cancellation_is_prompt) {
    // Unicode \b next to non-ASCII text runs on the PikeVM: the slowest path, many seconds here.
    std::string big;
    for (int i = 0; i < 1000000; ++i) big += "some caf\xC3\xA9 text line without it\n";
    auto g = Grep::compile("\\b\\w+\xC3\xA9\\w*q\\b", GrepOptions());
    CancellationSource src;
    std::atomic<bool> done{false};
    double after_cancel_ms = -1;
    std::thread t([&] {
        (void)g->search_buffer(big, src.token().get());
        done = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto t0 = std::chrono::steady_clock::now();
    src.cancel();
    t.join();
    after_cancel_ms = ms_since(t0);
    CHECK(done.load());
    CHECK_MSG(after_cancel_ms < 500, "cancel took " << after_cancel_ms << " ms");
}

TEST(grep, multi_file_stats_and_tree) {
    auto dir = bt::scratch_dir("grep-tree");
    bt::write_file(dir / "a.txt", "one hit\ntwo\nhit hit\n");
    bt::write_file(dir / "b" / "c.txt", "nothing\n");
    bt::write_file(dir / "b" / "d.txt", "hit\n");
    bt::write_file(dir / ".hidden", "hit\n");
    auto g = Grep::compile("hit", GrepOptions());
    std::vector<std::string> paths;
    GrepStats st;
    g->search_tree(dir, WalkOptions(), [&](const GrepFileResult& r) {
        paths.push_back(r.path);
        return true;
    }, nullptr, &st);
    std::sort(paths.begin(), paths.end());
    CHECK_EQ(paths, (std::vector<std::string>{"a.txt", "b/d.txt"}));
    CHECK_EQ(st.files_searched, size_t(3));
    CHECK_EQ(st.files_matched, size_t(2));
    CHECK_EQ(st.matched_lines, size_t(3));
    CHECK_EQ(st.matches, size_t(4));
    CHECK_EQ(st.bytes_searched, uint64_t(20 + 8 + 4));
    GrepStats st2;
    size_t seen = 0;
    g->search_files({dir / "a.txt", dir / "b" / "d.txt", dir / "nope"}, [&](const GrepFileResult& r) {
        ++seen;
        return r.error.empty() || true;
    }, nullptr, &st2);
    CHECK_EQ(seen, size_t(3));  // two matches + one error
    CHECK_EQ(st2.files_matched, size_t(2));
    // A sink returning false stops the search.
    size_t calls = 0;
    g->search_tree(dir, WalkOptions(), [&](const GrepFileResult&) { return ++calls < 1; });
    CHECK_EQ(calls, size_t(1));
}

TEST(grep, invalid_patterns_report_errors) {
    std::string err;
    CHECK(Grep::compile("a\\nb", GrepOptions(), &err) == nullptr);
    CHECK(!err.empty());
    GrepOptions f;
    f.fixed_strings = true;
    CHECK(Grep::compile("a\nb", f, &err) == nullptr);
    CHECK(Grep::compile("(", GrepOptions(), &err) == nullptr);
}

TEST(grep, terminal_detectors) {
    auto urls = detect_urls("see https://example.com/a?b=1, and\n(http://x.org/p).\n");
    CHECK_EQ(urls.size(), size_t(2));
    if (urls.size() == 2) {
        CHECK_EQ(urls[0].line_number, size_t(1));
        CHECK_EQ(urls[0].column, size_t(5));
        CHECK_EQ(urls[0].length, std::string("https://example.com/a?b=1").size());
        CHECK_EQ(urls[1].line_number, size_t(2));
        CHECK_EQ(urls[1].column, size_t(2));
    }
    auto hashes = detect_git_hashes("commit 664f977d render\nfull 664f977dabc123 x deadbeefz\n");
    CHECK_EQ(hashes.size(), size_t(2));
}
