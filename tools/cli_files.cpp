// `brosearch-cli files`: behaves like `rg --files [PATH...]`, printing one path per line with
// '/' separators (rg on Windows prints '\'; the differential script normalizes).
//
//   rg flags: --hidden/-. --no-ignore --no-ignore-vcs --no-ignore-dot --no-ignore-parent
//             --no-ignore-exclude --no-ignore-global --no-require-git -L/--follow
//             -g/--glob G  --iglob G  --glob-case-insensitive  -d/--max-depth N  -j/--threads N
//             --ignore-file F
//   extras:   --sort            sort output bytewise (deterministic)
//             --case=auto|sensitive|insensitive   ignore-pattern case mode (default auto)
//             --global-file F   global excludes file instead of core.excludesFile
//             --dirs            also print directories
//             --count           print only the number of files
//             --bench=N         walk N times, print best/avg ms to stderr
//   spec mode (tests/tree_spec.h; used by scripts/diff_files.sh):
//             --materialize SPEC DIR   build the tree; prints "git <dir> <true|false|->" per repo
//             --run-spec SPEC DIR      walk DIR with the spec's options, sorted
//             --rg-args SPEC           the rg flags equivalent to the spec's options, one per line
//             --check-spec SPEC DIR    exit 0 if --run-spec output equals the spec's @expect
//             --update-spec SPEC       replace the spec's @expect block with stdin

#include "brosearch/walk.h"

#include "../tests/tree_spec.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

using namespace bro::search;
namespace fs = std::filesystem;

namespace {

std::string read_text(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string read_stdin() {
    std::string data;
    char buf[1 << 16];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, stdin)) > 0) data.append(buf, n);
    return data;
}

fs::path arg_path(const char* s) {
#ifdef _WIN32
    std::string_view v(s);
    return fs::path(std::u8string(v.begin(), v.end()));
#else
    return fs::path(s);
#endif
}

bool load_spec(const char* file, tree_spec::Spec& spec) {
    std::string err;
    if (!tree_spec::parse(read_text(arg_path(file)), spec, err)) {
        std::fprintf(stderr, "%s: %s\n", file, err.c_str());
        return false;
    }
    return true;
}

std::vector<std::string> run_spec(const tree_spec::Spec& spec, const fs::path& dir, bool& ok) {
    WalkOptions o;
    std::string err;
    ok = tree_spec::walk_options(spec, dir, o, err);
    if (!ok) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return {};
    }
    return list_files(tree_spec::walk_root(spec, dir), o);
}

void print_lines(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& l : lines) {
        out += l;
        out.push_back('\n');
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
}

int spec_mode(int argc, char** argv) {
    const std::string_view mode = argv[1];
    tree_spec::Spec spec;
    if (argc < 3 || !load_spec(argv[2], spec)) return 2;
    if (mode == "--rg-args") {
        for (const auto& w : spec.options) {
            if (w.rfind("glob=", 0) == 0) std::printf("-g\n%s\n", w.c_str() + 5);
            else if (w.rfind("max-depth=", 0) == 0) std::printf("--max-depth\n%s\n", w.c_str() + 10);
            else if (w.rfind("threads=", 0) == 0 || w.rfind("case=", 0) == 0 || w == "parents") continue;
            else std::printf("--%s\n", w.c_str());
        }
        return 0;
    }
    if (mode == "--update-spec") {
        std::string list = read_stdin();
        std::vector<std::string> lines;
        size_t i = 0;
        while (i < list.size()) {
            size_t nl = list.find('\n', i);
            if (nl == std::string::npos) nl = list.size();
            std::string l = list.substr(i, nl - i);
            if (!l.empty() && l.back() == '\r') l.pop_back();
            if (!l.empty()) lines.push_back(std::move(l));
            i = nl + 1;
        }
        std::sort(lines.begin(), lines.end());
        std::string out = spec.header;
        for (const auto& l : lines) {
            size_t keep = l.find_last_not_of(' ') + 1;  // npos+1 == 0: all spaces
            for (size_t k = 0; k < l.size(); ++k) {
                const unsigned char c = static_cast<unsigned char>(l[k]);
                if (c == ' ' && k >= keep) out += "\\x20";  // trailing spaces stay visible
                else if (c == '\\') out += "\\\\";
                else if (c < 0x20 || c >= 0x80) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\x%02x", c);
                    out += b;  // specs stay ASCII so any byte sequence round-trips
                } else out.push_back(static_cast<char>(c));
            }
            out.push_back('\n');
        }
        std::ofstream f(arg_path(argv[2]), std::ios::binary | std::ios::trunc);
        f.write(out.data(), static_cast<std::streamsize>(out.size()));
        return 0;
    }
    if (argc < 4) return 2;
    fs::path dir = arg_path(argv[3]);
    if (mode == "--materialize") {
        tree_spec::materialize(spec, dir);
        for (const auto& g : spec.git_roots)
            std::printf("git %s %s\n", g.dir.c_str(), g.ignorecase ? (*g.ignorecase ? "true" : "false") : "-");
        std::printf("root %s\n", spec.root.empty() ? "." : spec.root.c_str());
        std::printf("oracle %s\n", spec.oracle.c_str());
        std::printf("posix %d\n", spec.posix_only ? 1 : 0);
        return 0;
    }
    bool ok;
    auto files = run_spec(spec, dir, ok);
    if (!ok) return 2;
    if (mode == "--run-spec") {
        print_lines(files);
        return 0;
    }
    if (mode == "--check-spec") return files == spec.expect ? 0 : 1;
    std::fprintf(stderr, "unknown spec mode\n");
    return 2;
}

} // namespace

int cli_files(int argc, char** argv) {
    if (argc >= 2 && std::strncmp(argv[1], "--", 2) == 0 &&
        (!std::strcmp(argv[1], "--materialize") || !std::strcmp(argv[1], "--run-spec") ||
         !std::strcmp(argv[1], "--rg-args") || !std::strcmp(argv[1], "--check-spec") ||
         !std::strcmp(argv[1], "--update-spec")))
        return spec_mode(argc, argv);

    WalkOptions o;
    std::vector<std::string> paths;
    bool sort = false, dirs = false, count = false;
    int bench = 0;
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        if (a == "--hidden" || a == "-.") o.hidden = true;
        else if (a == "-L" || a == "--follow") o.follow_symlinks = true;
        else if (a == "-g" || a == "--glob") { if (auto v = next()) o.globs.emplace_back(v); }
        else if (a == "--iglob") { if (auto v = next()) { o.globs.emplace_back(v); o.glob_case_insensitive = true; } }
        else if (a == "-d" || a == "--max-depth") { if (auto v = next()) o.max_depth = std::strtoull(v, nullptr, 10); }
        else if (a == "-j" || a == "--threads") { if (auto v = next()) o.threads = std::strtoull(v, nullptr, 10); }
        else if (a == "--ignore-file") { if (auto v = next()) o.extra_ignore_files.push_back(arg_path(v)); }
        else if (a == "--global-file") { if (auto v = next()) o.git_global_file = arg_path(v); }
        else if (a == "--sort") sort = true;
        else if (a == "--dirs") { dirs = true; o.yield_directories = true; }
        else if (a == "--count") count = true;
        else if (a.rfind("--bench=", 0) == 0) bench = std::atoi(argv[i] + 8);
        else if (a.rfind("--", 0) == 0 && tree_spec::apply_walk_option(o, a.substr(2))) continue;
        else if (a.rfind("-", 0) == 0 && a.size() > 1) {
            std::fprintf(stderr, "unknown flag: %s\n", argv[i]);
            return 2;
        } else paths.emplace_back(a);
    }
    if (paths.empty()) paths.emplace_back("");
    o.native_paths = false;

    std::string out;
    std::mutex mu;
    size_t files = 0;
    for (const auto& p : paths) {
        fs::path root = p.empty() ? fs::path(".") : arg_path(p.c_str());
        std::string prefix = p;
        if (!prefix.empty() && prefix.back() != '/' && prefix.back() != '\\') prefix.push_back('/');
        bool root_is_file = !p.empty() && fs::is_regular_file(root);
        auto run = [&](bool collect) {
            walk(root, o, [&](const WalkEntry& e) {
                if (e.type != EntryType::File && !(dirs && e.type == EntryType::Directory)) return true;
                std::lock_guard<std::mutex> lk(mu);
                if (e.type == EntryType::File) ++files;
                if (!collect) return true;
                if (root_is_file) out.append(p);
                else {
                    out.append(prefix);
                    out.append(e.rel_path);
                }
                out.push_back('\n');
                return true;
            });
        };
        if (bench > 0) {
            double best = 1e300, total = 0;
            for (int r = 0; r < bench; ++r) {
                files = 0;
                auto t0 = std::chrono::steady_clock::now();
                run(false);
                double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
                best = std::min(best, ms);
                total += ms;
            }
            std::fprintf(stderr, "files=%zu best=%.2fms avg=%.2fms\n", files, best, total / bench);
            continue;
        }
        run(!count);
    }
    if (bench > 0) return 0;
    if (count) {
        std::printf("%zu\n", files);
        return 0;
    }
    if (sort) {
        std::vector<std::string_view> lines;
        size_t i = 0;
        while (i < out.size()) {
            size_t nl = out.find('\n', i);
            lines.emplace_back(out.data() + i, nl - i);
            i = nl + 1;
        }
        std::sort(lines.begin(), lines.end());
        std::string sorted;
        sorted.reserve(out.size());
        for (auto l : lines) {
            sorted.append(l);
            sorted.push_back('\n');
        }
        out.swap(sorted);
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return files ? 0 : 1;
}
