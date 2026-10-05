// Walker tests. The spec trees in fixtures/walk carry expectations recorded from git / rg by
// scripts/diff_files.sh; the remaining tests cover API behaviour the oracles do not see.

#include "harness.h"
#include "tree_spec.h"

#include "brosearch/walk.h"
#include "ignore/git_repo.h"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <set>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace bro::search;
namespace fs = std::filesystem;

namespace {

std::vector<std::string> collect(const fs::path& root, const WalkOptions& o, bool dirs = false) {
    std::vector<std::string> out;
    std::mutex mu;
    walk(root, o, [&](const WalkEntry& e) {
        if (e.type == EntryType::File || (dirs && e.type == EntryType::Directory)) {
            std::lock_guard<std::mutex> lk(mu);
            out.emplace_back(e.rel_path);
        }
        return true;
    });
    std::sort(out.begin(), out.end());
    return out;
}

// Concatenation via += (GCC 12's -Wrestrict misfires on chained operator+ of std::string).
template <typename... A>
std::string cat(const A&... parts) {
    std::string s;
    ((s += parts), ...);
    return s;
}

WalkOptions hermetic() {
    WalkOptions o;
    o.parents = false;
    o.git_global = false;
    o.ignore_case = CaseMode::Sensitive;
    return o;
}

} // namespace

TEST(walk, spec_trees) {
    size_t ran = 0;
    std::vector<fs::path> specs;
    for (const auto& e : fs::directory_iterator(bt::fixture_dir() / "walk"))
        if (e.path().extension() == ".spec") specs.push_back(e.path());
    std::sort(specs.begin(), specs.end());
    CHECK(specs.size() >= 20);
    for (const auto& file : specs) {
        tree_spec::Spec spec;
        std::string err;
        std::string name = file.stem().string();
        if (!tree_spec::parse(bt::read_file(file), spec, err)) {
            CHECK_MSG(false, name << ": " << err);
            continue;
        }
        if (auto why = tree_spec::platform_skip(spec); !why.empty()) {
            std::printf("  skip %s: %s\n", name.c_str(), why.c_str());
            continue;
        }
        CHECK_MSG(!spec.expect.empty(), name << ": empty @expect");
        auto tree = bt::scratch_dir(cat("spec_", name)) / "tree";
        if (auto why = tree_spec::materialize(spec, tree); !why.empty()) {
            std::printf("  skip %s: %s\n", name.c_str(), why.c_str());
            continue;
        }
        WalkOptions o;
        if (!tree_spec::walk_options(spec, tree, o, err)) {
            CHECK_MSG(false, name << ": " << err);
            continue;
        }
        for (size_t threads : {size_t(1), size_t(0)}) {
            o.threads = threads;
            auto got = list_files(tree_spec::walk_root(spec, tree), o);
            CHECK_MSG(got == spec.expect, name << " (threads=" << threads << "): got " << bt::show(got)
                                               << " expected " << bt::show(spec.expect));
        }
        ++ran;
    }
    CHECK(ran >= 20);
}

// The standalone IgnoreFilter (git check-ignore semantics, ancestors included) must reproduce the
// git-oracle trees too: load global, info/exclude and every .gitignore with the base derived from
// its location, then filter a plain recursive listing.
TEST(walk, ignore_filter_reproduces_git_trees) {
    size_t ran = 0;
    for (const auto& de : fs::directory_iterator(bt::fixture_dir() / "walk")) {
        if (de.path().extension() != ".spec") continue;
        tree_spec::Spec spec;
        std::string err;
        if (!tree_spec::parse(bt::read_file(de.path()), spec, err) || spec.oracle != "git" || !spec.root.empty())
            continue;
        if (!tree_spec::platform_skip(spec).empty()) continue;
        std::string name = de.path().stem().string();
        auto tree = bt::scratch_dir(cat("filter_", name)) / "tree";
        if (!tree_spec::materialize(spec, tree).empty()) continue;
        IgnoreFilter f(tree, CaseMode::Auto);
        if (spec.global) f.load_file(tree_spec::global_file_for(tree), "");
        f.load_file(tree / ".git" / "info" / "exclude", "");
        std::vector<fs::path> files;
        for (auto it = fs::recursive_directory_iterator(tree); it != fs::recursive_directory_iterator(); ++it) {
            if (it->path().filename() == ".git") {
                it.disable_recursion_pending();
                continue;
            }
            if (it->is_regular_file()) files.push_back(it->path());
        }
        // Shallow .gitignore files first is not required (precedence is by base depth).
        for (const auto& p : files)
            if (p.filename() == ".gitignore") CHECK(f.load_file(p));
        std::vector<std::string> kept;
        for (const auto& p : files) {
            auto rel = p.lexically_relative(tree).generic_u8string();
            std::string r(rel.begin(), rel.end());
            if (!f.is_ignored(r, false)) kept.push_back(f.precomposes() ? precompose_name(r) : r);
        }
        std::sort(kept.begin(), kept.end());
        CHECK_MSG(kept == spec.expect, name << ": got " << bt::show(kept) << " expected " << bt::show(spec.expect));
        ++ran;
    }
    CHECK(ran >= 10);
}

TEST(walk, parallel_matches_serial_on_large_tree) {
    auto root = bt::scratch_dir("walk_large");
    bt::write_file(root / ".ignore", "*.skip\nd3/\n");
    size_t expected = 0;
    for (int a = 0; a < 12; ++a) {
        for (int b = 0; b < 10; ++b) {
            fs::path dir = root / cat("d", std::to_string(a)) / cat("e", std::to_string(b));
            for (int c = 0; c < 12; ++c) {
                bool skip = c % 5 == 0;
                bt::write_file(dir / cat("f", std::to_string(c), skip ? ".skip" : ".txt"), "");
                if (!skip && a != 3) ++expected;
            }
        }
    }
    WalkOptions o = hermetic();
    o.threads = 1;
    auto serial = collect(root, o);
    o.threads = 8;
    auto parallel = collect(root, o);
    CHECK_EQ(serial.size(), expected);
    CHECK(serial == parallel);
    std::set<std::string> uniq(parallel.begin(), parallel.end());
    CHECK_EQ(uniq.size(), parallel.size());
}

TEST(walk, callback_stop_and_cancellation) {
    auto root = bt::scratch_dir("walk_stop");
    for (int i = 0; i < 50; ++i) bt::write_file(root / cat("d", std::to_string(i % 5)) / cat("f", std::to_string(i)), "");
    WalkOptions o = hermetic();
    o.threads = 1;
    int calls = 0;
    walk(root, o, [&](const WalkEntry&) { return ++calls < 3; });
    CHECK_EQ(calls, 3);

    CancellationSource src;
    src.cancel();
    int seen = 0;
    walk(root, o, [&](const WalkEntry&) { ++seen; return true; }, src.token().get());
    CHECK_EQ(seen, 0);

    // Cancelling from inside the callback stops a parallel walk promptly.
    CancellationSource src2;
    std::atomic<int> after{0};
    o.threads = 4;
    walk(root, o, [&](const WalkEntry&) {
        if (src2.is_cancelled()) ++after;
        src2.cancel();
        return true;
    }, src2.token().get());
    CHECK(after.load() < 50);
}

TEST(walk, entry_fields_and_root_forms) {
    auto root = bt::scratch_dir("walk_fields");
    bt::write_file(root / "a" / "b" / "c.txt", "hello");
    bt::write_file(root / "top.txt", "x");
    WalkOptions o = hermetic();
    o.yield_directories = true;
    o.threads = 1;
    std::vector<std::string> seen;
    walk(root, o, [&](const WalkEntry& e) {
        seen.push_back(cat(e.rel_path, "#", std::to_string(e.depth), e.type == EntryType::Directory ? "d" : "f"));
        CHECK(e.native_path && fs::exists(*e.native_path));
        if (e.rel_path == "a/b/c.txt") CHECK_EQ(bt::read_file(*e.native_path), std::string("hello"));
        return true;
    });
    std::sort(seen.begin(), seen.end());
    CHECK_EQ(seen, (std::vector<std::string>{"a#1d", "a/b#2d", "a/b/c.txt#3f", "top.txt#1f"}));

    // max_depth (rg semantics) with directories reported.
    o.max_depth = 1;
    CHECK_EQ(collect(root, o, true), (std::vector<std::string>{"a", "top.txt"}));
    o.max_depth = 0;
    CHECK(collect(root, o, true).empty());

    // Root given with a trailing separator, and a file as the root.
    o = hermetic();
    CHECK_EQ(collect(fs::path(cat(root.string(), "/")), o), (std::vector<std::string>{"a/b/c.txt", "top.txt"}));
    std::vector<std::string> single;
    walk(root / "top.txt", o, [&](const WalkEntry& e) {
        single.emplace_back(e.rel_path);
        CHECK(e.depth == 0 && e.type == EntryType::File);
        return true;
    });
    CHECK_EQ(single, (std::vector<std::string>{"top.txt"}));
    CHECK(collect(root / "missing", o).empty());
}

TEST(walk, toggles_and_extra_sources) {
    auto root = bt::scratch_dir("walk_toggles");
    bt::write_file(root / ".git" / "config", "[core]\n");
    bt::write_file(root / ".gitignore", "*.g\n");
    bt::write_file(root / ".ignore", "*.i\n");
    bt::write_file(root / "extra.txt", "*.e\n");
    bt::write_file(root / "global.txt", "*.gl\n!keep.e\n");
    // "B.G" (not "A.G": case-insensitive filesystems would make it the same file as a.g).
    for (const char* f : {"a.g", "a.i", "a.e", "a.gl", "keep.e", "B.G", "plain"}) bt::write_file(root / f, "");
    WalkOptions o = hermetic();
    o.git_global = true;
    o.git_global_file = root / "global.txt";
    o.extra_ignore_files.push_back(root / "extra.txt");
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"B.G", "extra.txt", "global.txt", "keep.e", "plain"}));
    o.ignore_case = CaseMode::Insensitive;
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"extra.txt", "global.txt", "keep.e", "plain"}));
    o.ignore_case = CaseMode::Sensitive;
    o.git_ignore = false;
    o.ignore_files = false;
    o.git_global = false;
    o.extra_ignore_files.clear();
    CHECK_EQ(collect(root, o).size(), static_cast<size_t>(9));
    // No surprise defaults: build/, *.log, node_modules etc. are ordinary names.
    auto plain = bt::scratch_dir("walk_no_defaults");
    for (const char* f : {"build/x", "bin/y", "out/z", "dist/w", "node_modules/m", "a.log", "b.tmp"})
        bt::write_file(plain / f, "");
    CHECK_EQ(collect(plain, hermetic()).size(), static_cast<size_t>(7));
}

TEST(walk, glob_overrides) {
    auto root = bt::scratch_dir("walk_globs");
    for (const char* f : {"a.C", "b.c", "sub/c.c", "sub/d.h"}) bt::write_file(root / f, "");
    WalkOptions o = hermetic();
    o.globs = {"*.c"};
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"b.c", "sub/c.c"}));
    o.glob_case_insensitive = true;
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"a.C", "b.c", "sub/c.c"}));
    o.globs = {"!sub"};
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"a.C", "b.c"}));
}

// git's core.precomposeUnicode: on macOS NFD names are matched and reported in NFC (native_path
// keeps the bytes on disk); everywhere else every mode leaves names alone. The spec trees
// precompose_*_darwin hold the git / rg oracles for the same behaviour.
TEST(walk, precompose_unicode) {
    const std::string nfd_cafe = "cafe\xcc\x81", nfc_cafe = "caf\xc3\xa9";
#ifdef __APPLE__
    CHECK_EQ(precompose_name(nfd_cafe + ".txt"), nfc_cafe + ".txt");
    CHECK_EQ(precompose_name("u\xcc\x88" "ber/" + nfd_cafe), "\xc3\xbc" "ber/" + nfc_cafe);
    const bool converts = true;
#else
    CHECK_EQ(precompose_name(nfd_cafe), nfd_cafe);
    const bool converts = false;
#endif
    CHECK_EQ(precompose_name("plain/ascii.txt"), std::string("plain/ascii.txt"));
    CHECK_EQ(precompose_name(nfc_cafe), nfc_cafe);
    CHECK_EQ(precompose_name("bad\xff" + nfd_cafe), "bad\xff" + nfd_cafe);  // ill-formed: kept

    auto root = bt::scratch_dir("walk_precompose");
    bt::write_file(root / tree_spec::u8path(nfd_cafe + ".txt"), "nfd");
    bt::write_file(root / tree_spec::u8path(nfd_cafe + "2/x.txt"), "");
    bt::write_file(root / ".ignore", nfc_cafe + "2/\n");
    WalkOptions o = hermetic();
    o.threads = 1;
    o.precompose_unicode = Precompose::On;
    std::vector<std::string> seen;
    walk(root, o, [&](const WalkEntry& e) {
        seen.emplace_back(e.rel_path);
        CHECK(e.native_path && fs::exists(*e.native_path));
        if (e.native_path && e.rel_path.find('/') == std::string_view::npos) {
            auto n = e.native_path->filename().u8string();
            CHECK_EQ(std::string(n.begin(), n.end()), nfd_cafe + ".txt");  // bytes as stored
        }
        return true;
    });
    if (converts) CHECK_EQ(seen, (std::vector<std::string>{nfc_cafe + ".txt"}));
    else CHECK_EQ(seen, (std::vector<std::string>{nfd_cafe + ".txt", nfd_cafe + "2/x.txt"}));
    o.precompose_unicode = Precompose::Off;
    CHECK_EQ(collect(root, o), (std::vector<std::string>{nfd_cafe + ".txt", nfd_cafe + "2/x.txt"}));
    o.precompose_unicode = Precompose::Auto;  // no repository: off, as git and rg
    CHECK_EQ(collect(root, o), (std::vector<std::string>{nfd_cafe + ".txt", nfd_cafe + "2/x.txt"}));

    IgnoreFilter on(root, CaseMode::Sensitive, Precompose::On);
    on.add_rule(nfc_cafe + ".txt");
    CHECK_EQ(on.precomposes(), converts);
    CHECK_EQ(on.is_ignored(nfd_cafe + ".txt"), converts);
    CHECK(on.is_ignored(nfc_cafe + ".txt"));
    IgnoreFilter off(root, CaseMode::Sensitive, Precompose::Off);
    off.add_rule(nfc_cafe + ".txt");
    CHECK(!off.is_ignored(nfd_cafe + ".txt"));
}

// CaseMode::Auto outside a repository follows the filesystem where the platform can say (macOS
// volumes are case-insensitive or not; pathconf tells), else the platform default. Oracle: does
// a file created as "CaseProbe" open as "caseprobe"?
TEST(walk, auto_case_outside_repo_matches_filesystem) {
    auto root = bt::scratch_dir("walk_case_probe");
    if (!bro::search::detail::find_repo_root(root).empty()) {
        std::printf("  skip: scratch dir is inside a git repository\n");
        return;
    }
    bt::write_file(root / "CaseProbe", "");
    const bool fs_icase = fs::exists(root / "caseprobe");
    IgnoreFilter f(root, CaseMode::Auto);
    CHECK_EQ(f.case_insensitive(), fs_icase);
    bt::write_file(root / "Foo.LOG", "");
    bt::write_file(root / ".ignore", "*.log\n");
    WalkOptions o = hermetic();
    o.ignore_case = CaseMode::Auto;
    CHECK_EQ(collect(root, o).size(), fs_icase ? size_t(1) : size_t(2));  // CaseProbe [, Foo.LOG]
}

#ifdef _WIN32
TEST(walk, windows_hidden_attribute) {
    auto root = bt::scratch_dir("walk_hidden_attr");
    bt::write_file(root / "visible.txt", "");
    bt::write_file(root / "attr_hidden.txt", "");
    bt::write_file(root / "hdir" / "inner.txt", "");
    SetFileAttributesW((root / "attr_hidden.txt").c_str(), FILE_ATTRIBUTE_HIDDEN);
    SetFileAttributesW((root / "hdir").c_str(), FILE_ATTRIBUTE_HIDDEN);
    WalkOptions o = hermetic();
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"visible.txt"}));
    o.hidden = true;
    CHECK_EQ(collect(root, o), (std::vector<std::string>{"attr_hidden.txt", "hdir/inner.txt", "visible.txt"}));
}
#endif
