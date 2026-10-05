// `brosearch-cli grep`: an rg-compatible front end (see tests/grep_oracle.h for the flag subset).
// Output equals `rg --sort path --no-heading [flags] PATTERN [PATH...]` (with '/' separators).
//
//   brosearch-cli grep [rg flags] PATTERN [PATH...]
//   brosearch-cli grep --materialize-corpus DIR     write the adversarial test corpus
//   extras: --stats (summary on stderr), --bench=N (run N times, timing on stderr)

#include "../tests/grep_oracle.h"

#include <chrono>
#include <cstdio>
#include <cstring>

int cli_grep(int argc, char** argv) {
    if (argc >= 3 && !std::strcmp(argv[1], "--materialize-corpus")) {
        std::string_view d(argv[2]);
        grep_oracle::materialize_corpus(std::filesystem::path(std::u8string(d.begin(), d.end())));
        return 0;
    }
    if (argc >= 3 && !std::strcmp(argv[1], "--write-fixture")) {
        // Copies stdin to the named file byte-for-byte (used by scripts/diff_grep.sh --update).
        std::string data;
        char buf[1 << 16];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, stdin)) > 0) data.append(buf, n);
        std::string_view d(argv[2]);
        grep_oracle::put(std::filesystem::path(std::u8string(d.begin(), d.end())), data);
        return 0;
    }
    std::vector<std::string> args(argv + 1, argv + argc);
    grep_oracle::Cli probe;
    std::string err;
    if (!grep_oracle::parse_cli(args, probe, err)) {
        std::fprintf(stderr, "brosearch grep: %s\n", err.c_str());
        return 2;
    }
    std::string out;
    bro::search::GrepStats stats;
    int rc = 0;
    int runs = probe.bench > 0 ? probe.bench : 1;
    double best = 1e300, total = 0;
    // Normal runs stream each file's output to stdout; --bench collects it so only the last
    // run's output is printed.
    const grep_oracle::Writer to_stdout = [](std::string_view t) { std::fwrite(t.data(), 1, t.size(), stdout); };
    for (int r = 0; r < runs; ++r) {
        out.clear();
        auto t0 = std::chrono::steady_clock::now();
        rc = probe.bench > 0 ? grep_oracle::run_rg_like(args, out, err, &stats)
                             : grep_oracle::run_rg_like(args, to_stdout, err, &stats);
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        best = std::min(best, ms);
        total += ms;
    }
    if (rc == 2) {
        std::fprintf(stderr, "brosearch grep: %s\n", err.c_str());
        return 2;
    }
    if (probe.bench > 0) std::fwrite(out.data(), 1, out.size(), stdout);
    if (probe.bench > 0) std::fprintf(stderr, "best=%.2fms avg=%.2fms\n", best, total / runs);
    if (probe.stats) {
        std::fprintf(stderr, "%zu files searched, %zu matched, %zu matched lines, %zu matches, %llu bytes, %.2f ms\n",
                     stats.files_searched, stats.files_matched, stats.matched_lines, stats.matches,
                     static_cast<unsigned long long>(stats.bytes_searched), stats.elapsed_ms);
    }
    return rc;
}
