// `brosearch-cli fuzzy`: behaves like `fzf --filter QUERY`, reading items from stdin and printing
// the matching items in fzf's order, one per line.
//
//   brosearch-cli fuzzy [options] QUERY        (or --filter=QUERY / -f QUERY)
//     -i / +i              ignore / respect case (default: smart case)
//     -e, --exact          exact-match mode
//     +x, --no-extended    disable extended-search syntax
//     --literal            do not normalize Latin script letters
//     --scheme=S           default | path | history
//     --tiebreak=L         comma list of length,chunk,pathname,begin,end,index
//     --algo=v1|v2
//     --no-sort            keep input order
//     --tac                reverse the input order
//     -n, --nth=RANGES     match only these fields (fzf syntax: 1,3..,-1)
//     -d, --delimiter=D    field delimiter for --nth (default: AWK-style whitespace)
//     --read0              items are NUL-separated
//     --posix-path         path scheme: '\\' is not a delimiter (fzf on Linux/macOS)
//     --windows-path       path scheme: '\\' is a delimiter (fzf on Windows)
//     --limit=N            print only the best N
//     --threads=N
//     --debug              print "score<TAB>byte positions<TAB>item"
//     --bench=N            run the query N times and print timing to stderr
//     --index              use FuzzyIndex (incremental engine) instead of fuzzy_filter
//
// Differential oracle (see scripts/diff_fuzzy.sh):
//   brosearch-cli fuzzy --oracle --queries=FILE (--corpus=FILE | --gen=unicode|long)
//                       [--fzf=PATH] [--record=FIXTURE] [--top=N] [--verbose]
//   Without --corpus/--gen the items come from stdin; --save-corpus=FILE keeps them as a fixture.
//   Runs every query of FILE ("flags<TAB>query" per line) through the real fzf and through
//   brosearch, reports set/order agreement, also checks FuzzyIndex (typed-prefix refinement)
//   against a cold search, and with --record writes the fzf results as a ctest fixture.

#include "brosearch/fuzzy.h"
#include "brosearch/fuzzy_index.h"

#include "../tests/fuzzy_corpus_gen.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace bro::search;

namespace {

bool starts(const char* a, const char* p) { return std::strncmp(a, p, std::strlen(p)) == 0; }

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

std::string read_stream(std::FILE* f) {
    std::string data;
    char buf[1 << 16];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) data.append(buf, n);
    return data;
}

std::vector<std::string> split_lines(const std::string& data, char delim, bool trim_cr) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < data.size()) {
        size_t e = data.find(delim, i);
        if (e == std::string::npos) e = data.size();
        size_t end = e;
        if (trim_cr && end > i && data[end - 1] == '\r') --end;
        out.emplace_back(data, i, end - i);
        i = e + 1;
    }
    return out;
}

bool parse_tiebreak(std::string_view s, std::vector<FuzzyTiebreak>& out) {
    out.clear();
    size_t i = 0;
    while (i <= s.size()) {
        size_t c = s.find(',', i);
        if (c == std::string_view::npos) c = s.size();
        std::string_view t = s.substr(i, c - i);
        if (t == "length") out.push_back(FuzzyTiebreak::Length);
        else if (t == "chunk") out.push_back(FuzzyTiebreak::Chunk);
        else if (t == "pathname") out.push_back(FuzzyTiebreak::Pathname);
        else if (t == "begin") out.push_back(FuzzyTiebreak::Begin);
        else if (t == "end") out.push_back(FuzzyTiebreak::End);
        else if (t == "index") out.push_back(FuzzyTiebreak::Index);
        else return false;
        i = c + 1;
    }
    return true;
}

// Applies one fzf-compatible matching flag. Returns false if `a` is not one.
bool apply_flag(const char* a, FuzzyOptions& opts) {
    if (!std::strcmp(a, "-i")) opts.case_mode = FuzzyCase::Ignore;
    else if (!std::strcmp(a, "+i")) opts.case_mode = FuzzyCase::Respect;
    else if (!std::strcmp(a, "--smart-case")) opts.case_mode = FuzzyCase::Smart;
    else if (!std::strcmp(a, "-e") || !std::strcmp(a, "--exact")) opts.exact = true;
    else if (!std::strcmp(a, "+x") || !std::strcmp(a, "--no-extended")) opts.extended = false;
    else if (!std::strcmp(a, "--literal")) opts.normalize = false;
    else if (!std::strcmp(a, "--no-sort") || !std::strcmp(a, "+s")) opts.sort = false;
    else if (!std::strcmp(a, "--posix-path")) opts.backslash_delimiter = false;
    else if (!std::strcmp(a, "--windows-path")) opts.backslash_delimiter = true;
    else if (starts(a, "--algo=")) opts.algo_v1 = !std::strcmp(a + 7, "v1");
    else if (starts(a, "--threads=")) opts.threads = std::strtoull(a + 10, nullptr, 10);
    else if (starts(a, "--scheme=")) {
        std::string_view s = a + 9;
        if (s == "default") opts.scheme = FuzzyScheme::Default;
        else if (s == "path") opts.scheme = FuzzyScheme::Path;
        else if (s == "history") opts.scheme = FuzzyScheme::History;
        else return false;
    } else if (starts(a, "--tiebreak=")) {
        if (!parse_tiebreak(a + 11, opts.tiebreak)) return false;
    } else if (!std::strcmp(a, "--tac")) {
        opts.tac = true;
    } else if (starts(a, "--nth=")) {
        if (!parse_fuzzy_nth(a + 6, opts.nth)) return false;
    } else if (starts(a, "--delimiter=")) {
        opts.delimiter = a + 12;
    } else {
        return false;
    }
    return true;
}

// Flags that fzf understands and brosearch uses only to mirror the host fzf.
bool is_local_only_flag(std::string_view f) {
    return f == "--posix-path" || f == "--windows-path" || f.substr(0, 10) == "--threads=";
}

uint64_t fnv_indices(const std::vector<uint32_t>& v) {
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t x : v) {
        for (int b = 0; b < 4; ++b) {
            h ^= (x >> (8 * b)) & 0xFF;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

std::string shell_quote(std::string_view s) {
#ifdef _WIN32
    std::string q = "\"";
    for (char c : s) {
        if (c == '"') q += "\\\"";
        else q.push_back(c);
    }
    return q + "\"";
#else
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q.push_back(c);
    }
    return q + "'";
#endif
}

#ifdef _WIN32
std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// Runs `cmd` (a full command line, UTF-8) with stdin from `input_file` (may be empty) and returns
// its stdout. CreateProcessW keeps non-ASCII arguments intact, which _popen (via the ANSI code
// page) does not.
std::string run_capture(const std::string& cmd, const std::string& input_file = std::string()) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return {};
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE in = INVALID_HANDLE_VALUE;
    if (!input_file.empty())
        in = CreateFileW(widen(input_file).c_str(), GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in != INVALID_HANDLE_VALUE ? in : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    std::wstring line = widen(cmd);
    BOOL ok = CreateProcessW(nullptr, line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (in != INVALID_HANDLE_VALUE) CloseHandle(in);
    std::string out;
    if (ok) {
        char buf[1 << 16];
        DWORD n = 0;
        while (ReadFile(rd, buf, sizeof buf, &n, nullptr) && n > 0) out.append(buf, n);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(rd);
    return out;
}
#else
std::string run_capture(const std::string& cmd, const std::string& input_file = std::string()) {
    std::string full = input_file.empty() ? cmd : cmd + " < " + shell_quote(input_file);
    std::FILE* p = popen(full.c_str(), "r");
    if (!p) return {};
    std::string out = read_stream(p);
    pclose(p);
    return out;
}
#endif

// What fzf prints for an item: Go's string([]rune) turns invalid UTF-8 bytes into U+FFFD.
std::string go_printed(const std::string& s) { return fuzzy_display(s).text; }

struct OracleQuery {
    std::vector<std::string> flags;
    std::string query;
};

std::vector<OracleQuery> load_queries(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<OracleQuery> out;
    for (auto& line : split_lines(data, '\n', true)) {
        if (line.empty() || line[0] == '#') continue;
        OracleQuery q;
        size_t tab = line.find('\t');
        std::string flags = tab == std::string::npos ? std::string() : line.substr(0, tab);
        q.query = tab == std::string::npos ? line : line.substr(tab + 1);
        size_t i = 0;
        while (i < flags.size()) {
            size_t sp = flags.find(' ', i);
            if (sp == std::string::npos) sp = flags.size();
            if (sp > i) q.flags.push_back(flags.substr(i, sp - i));
            i = sp + 1;
        }
        out.push_back(std::move(q));
    }
    return out;
}

// Typing simulation: every prefix of the query, through one FuzzyIndex, must equal a cold search.
bool check_index_refinement(const std::vector<std::string>& items, const OracleQuery& oq, const FuzzyOptions& opts,
                            std::string* why) {
    FuzzyIndex index(opts);
    // Stream items in two halves around the typing to exercise appends between keystrokes.
    size_t half = items.size() / 2;
    index.add(std::span<const std::string>(items.data(), half));
    for (size_t len = 1; len <= oq.query.size(); ++len) {
        if (len == (oq.query.size() + 1) / 2)
            index.add(std::span<const std::string>(items.data() + half, items.size() - half));
        std::string prefix = oq.query.substr(0, len);
        auto got = index.search(prefix).results;
        size_t visible = index.size();
        FuzzyQuery cold(prefix, opts);
        auto want = fuzzy_filter(cold, std::span<const std::string>(items.data(), visible));
        bool same = got.size() == want.size();
        for (size_t k = 0; same && k < got.size(); ++k) same = got[k].index == want[k].index;
        if (!same) {
            *why = "index refinement differs at prefix '" + prefix + "'";
            return false;
        }
    }
    return true;
}

int fuzzy_oracle(int argc, char** argv) {
    std::string fzf = std::getenv("FZF") ? std::getenv("FZF") : "fzf";
    std::string corpus_path, gen, queries_path, record_path, save_corpus;
    size_t top = 50;
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (starts(a, "--fzf=")) fzf = a + 6;
        else if (starts(a, "--corpus=")) corpus_path = a + 9;
        else if (starts(a, "--gen=")) gen = a + 6;
        else if (starts(a, "--queries=")) queries_path = a + 10;
        else if (starts(a, "--record=")) record_path = a + 9;
        else if (starts(a, "--save-corpus=")) save_corpus = a + 14;
        else if (starts(a, "--top=")) top = std::strtoull(a + 6, nullptr, 10);
        else if (!std::strcmp(a, "--verbose")) verbose = true;
        else {
            std::fprintf(stderr, "oracle: unknown argument %s\n", a);
            return 2;
        }
    }
    std::vector<std::string> items;
    std::string corpus_name;
    if (!gen.empty()) {
        if (gen == "unicode") items = fuzzy_corpus::unicode_corpus(3000, 7);
        else if (gen == "long") items = fuzzy_corpus::long_corpus(300, 11);
        else {
            std::fprintf(stderr, "oracle: unknown generator %s\n", gen.c_str());
            return 2;
        }
        corpus_name = "gen:" + gen;
        corpus_path = (std::filesystem::temp_directory_path() / ("brosearch-fuzzy-" + gen + ".txt")).string();
        std::ofstream out(corpus_path, std::ios::binary | std::ios::trunc);
        for (auto& s : items) out << s << '\n';
    } else if (corpus_path.empty() || !save_corpus.empty()) {
        // Items from stdin (e.g. `rg --files`), '\r' trimmed; optionally saved as a fixture corpus.
        items = split_lines(read_stream(stdin), '\n', true);
        if (save_corpus.empty())
            save_corpus = (std::filesystem::temp_directory_path() / "brosearch-fuzzy-stdin.txt").string();
        std::ofstream out(save_corpus, std::ios::binary | std::ios::trunc);
        for (auto& s : items) out << s << '\n';
        corpus_path = save_corpus;
        corpus_name = std::filesystem::path(corpus_path).filename().string();
    } else {
        std::ifstream in(corpus_path, std::ios::binary);
        if (!in) {
            std::fprintf(stderr, "oracle: cannot read corpus %s\n", corpus_path.c_str());
            return 2;
        }
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        items = split_lines(data, '\n', false);
        corpus_name = std::filesystem::path(corpus_path).filename().string();
    }
    auto queries = load_queries(queries_path);
    if (queries.empty()) {
        std::fprintf(stderr, "oracle: no queries in '%s'\n", queries_path.c_str());
        return 2;
    }
    std::string version = run_capture(shell_quote(fzf) + " --version");
    while (!version.empty() && (version.back() == '\n' || version.back() == '\r')) version.pop_back();

    std::string fixture = "# brosearch fuzzy fixture, recorded from fzf " + version +
#ifdef _WIN32
                          " on Windows" +
#else
                          " on POSIX" +
#endif
                          "\ncorpus " + corpus_name + "\n";
    size_t order_ok = 0, set_ok = 0, index_ok = 0;
    double fzf_ms = 0, our_ms = 0;
    std::vector<std::string_view> views(items.begin(), items.end());
    std::vector<std::string> printed;  // items as fzf prints them
    printed.reserve(items.size());
    for (auto& s : items) printed.push_back(go_printed(s));
    for (const auto& oq : queries) {
        FuzzyOptions opts;
        std::string fzf_flags, flag_line;
        bool flags_ok = true;
        for (auto& f : oq.flags) {
            if (!apply_flag(f.c_str(), opts)) flags_ok = false;
            if (!flag_line.empty()) flag_line += ' ';
            flag_line += f;
            if (!is_local_only_flag(f)) fzf_flags += " " + f;
        }
        if (!flags_ok) {
            std::fprintf(stderr, "oracle: bad flags for query '%s'\n", oq.query.c_str());
            return 2;
        }
        if (opts.tac) opts.sort = true;  // as cli_fuzzy: fzf --filter sorts under --tac
        auto t0 = std::chrono::steady_clock::now();
        std::string raw =
            run_capture(shell_quote(fzf) + " --filter=" + shell_quote(oq.query) + fzf_flags, corpus_path);
        fzf_ms += ms_since(t0);
        auto want = split_lines(raw, '\n', true);

        t0 = std::chrono::steady_clock::now();
        FuzzyQuery q(oq.query, opts);
        auto res = fuzzy_filter(q, std::span<const std::string_view>(views));
        our_ms += ms_since(t0);

        bool same_order = res.size() == want.size();
        size_t first_diff = 0;
        for (size_t k = 0; same_order && k < res.size(); ++k) {
            if (printed[res[k].index] != want[k]) {
                same_order = false;
                first_diff = k;
            }
        }
        std::map<std::string, int> ms;
        for (auto& w : want) ms[w]++;
        for (auto& r : res) ms[printed[r.index]]--;
        bool same_set = true;
        for (auto& [k, v] : ms) same_set = same_set && v == 0;
        order_ok += same_order;
        set_ok += same_set;

        std::string why;
        bool idx_ok = check_index_refinement(items, oq, opts, &why);
        index_ok += idx_ok;

        if (!same_order || !idx_ok || verbose) {
            std::printf("%s [%s] '%s': fzf=%zu ours=%zu set=%s order=%s index=%s\n",
                        same_order && idx_ok ? "ok  " : "DIFF", flag_line.c_str(), oq.query.c_str(), want.size(),
                        res.size(), same_set ? "same" : "DIFF", same_order ? "same" : "DIFF",
                        idx_ok ? "same" : why.c_str());
            if (!same_order && first_diff < res.size() && first_diff < want.size()) {
                std::printf("    first difference at #%zu: fzf '%s'  ours '%s' (score %d)\n", first_diff,
                            want[first_diff].c_str(), items[res[first_diff].index].c_str(), res[first_diff].score);
            }
        }

        if (!record_path.empty()) {
            // fzf output -> item indices (duplicates are emitted in index order, reversed by --tac).
            std::map<std::string, std::deque<uint32_t>> where;
            for (uint32_t i = 0; i < items.size(); ++i) where[printed[i]].push_back(i);
            std::vector<uint32_t> idx;
            for (auto& w : want) {
                auto& d = where[w];
                idx.push_back(d.empty() ? UINT32_MAX : opts.tac ? d.back() : d.front());
                if (!d.empty()) {
                    if (opts.tac) d.pop_back();
                    else d.pop_front();
                }
            }
            char hbuf[32];
            std::snprintf(hbuf, sizeof hbuf, "%016llx", static_cast<unsigned long long>(fnv_indices(idx)));
            fixture += "Q " + flag_line + "\t" + oq.query + "\nN " + std::to_string(idx.size()) + " " + hbuf + "\nT";
            for (size_t k = 0; k < idx.size() && k < top; ++k) fixture += " " + std::to_string(idx[k]);
            fixture += "\n";
        }
    }
    std::printf("corpus %s (%zu items): %zu queries, order identical %zu, set identical %zu, index==cold %zu; "
                "fzf %.0f ms (incl. process spawn), brosearch %.1f ms\n",
                corpus_name.c_str(), items.size(), queries.size(), order_ok, set_ok, index_ok, fzf_ms, our_ms);
    if (!record_path.empty()) {
        std::ofstream out(record_path, std::ios::binary | std::ios::trunc);
        out << fixture;
        std::printf("recorded %s\n", record_path.c_str());
    }
    return order_ok == queries.size() && index_ok == queries.size() ? 0 : 1;
}

} // namespace

int cli_fuzzy(int argc, char** argv) {
    if (argc > 1 && !std::strcmp(argv[1], "--oracle")) return fuzzy_oracle(argc - 1, argv + 1);
    FuzzyOptions opts;
    std::string query;
    bool have_query = false, read0 = false, debug = false, use_index = false;
    size_t limit = 0;
    int bench = 0;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (apply_flag(a, opts)) continue;
        if (!std::strcmp(a, "--read0")) read0 = true;
        else if (!std::strcmp(a, "--debug")) debug = true;
        else if (!std::strcmp(a, "--index")) use_index = true;
        else if (starts(a, "--limit=")) limit = std::strtoull(a + 8, nullptr, 10);
        else if (starts(a, "--bench=")) bench = std::atoi(a + 8);
        else if ((!std::strcmp(a, "-n") || !std::strcmp(a, "--nth")) && i + 1 < argc) {
            if (!parse_fuzzy_nth(argv[++i], opts.nth)) {
                std::fprintf(stderr, "fuzzy: invalid --nth: %s\n", argv[i]);
                return 2;
            }
        } else if ((!std::strcmp(a, "-d") || !std::strcmp(a, "--delimiter")) && i + 1 < argc) {
            opts.delimiter = argv[++i];
        } else if (starts(a, "--filter=")) {
            query = a + 9;
            have_query = true;
        } else if ((!std::strcmp(a, "-f") || !std::strcmp(a, "--filter")) && i + 1 < argc) {
            query = argv[++i];
            have_query = true;
        } else if (!have_query && (a[0] != '-' || a[1] == '\0')) {
            query = a;
            have_query = true;
        } else {
            std::fprintf(stderr, "fuzzy: unexpected argument: %s\n", a);
            return 2;
        }
    }

    std::string data = read_stream(stdin);
#ifdef _WIN32
    const bool trim_cr = !read0;  // fzf trims "\r\n" on Windows only
#else
    const bool trim_cr = false;
#endif
    std::vector<std::string_view> items;
    {
        const char delim = read0 ? '\0' : '\n';
        size_t i = 0;
        while (i < data.size()) {
            size_t e = data.find(delim, i);
            if (e == std::string::npos) e = data.size();
            size_t end = e;
            if (trim_cr && end > i && data[end - 1] == '\r') --end;
            items.emplace_back(data.data() + i, end - i);
            i = e + 1;
        }
    }

    // fzf --filter streams unsorted results only without --tac; with it, the matcher sorts
    // whenever the pattern is sortable (core.go: matcher.sort = pattern.sortable).
    if (opts.tac) opts.sort = true;
    FuzzyQuery q(query, opts);
    std::vector<FuzzyResult> results;
    auto run = [&] {
        if (use_index) {
            FuzzyIndex index(opts);
            index.add(std::span<const std::string_view>(items));
            results = index.search(query, limit, debug).results;
        } else {
            results = fuzzy_filter(q, std::span<const std::string_view>(items), limit, debug);
        }
    };
    if (bench > 0) {
        double best = 1e300, total = 0;
        for (int r = 0; r < bench; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            run();
            double ms = ms_since(t0);
            best = std::min(best, ms);
            total += ms;
        }
        std::fprintf(stderr, "items=%zu matches=%zu best=%.2fms avg=%.2fms\n", items.size(), results.size(), best,
                     total / bench);
    } else {
        run();
    }

    std::string out;
    out.reserve(results.size() * 32);
    for (const auto& r : results) {
        if (debug) {
            out += std::to_string(r.score);
            out.push_back('\t');
            for (size_t k = 0; k < r.positions.size(); ++k) {
                if (k) out.push_back(',');
                out += std::to_string(r.positions[k]);
            }
            out.push_back('\t');
        }
        out += fuzzy_display(items[r.index]).text;  // invalid UTF-8 shows as U+FFFD, as in fzf
        out.push_back(read0 ? '\0' : '\n');
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return results.empty() ? 1 : 0;
}
