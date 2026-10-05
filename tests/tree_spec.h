#pragma once
// Directory-tree specs for walker/ignore differential tests (header-only; shared by the ctest
// suite and `brosearch-cli files --materialize/--update-spec`, which scripts/diff_files.sh uses
// to rebuild each tree, run git / rg on it, and refresh the @expect block).
//
// Spec format (one directive per line, '#' comments outside @expect):
//   @oracle git|rg          tool whose output the @expect block holds
//   @options w1 w2 ...      walker options (see apply_walk_option), e.g. hidden glob=!.git;
//                           ignore-file=REL (relative to the walk root). The walker follows the
//                           oracle's dialect (IgnoreDialect::Rg for rg) unless dialect= says otherwise.
//   @posix                  only meaningful on POSIX (non-UTF-8 names)
//   @darwin                 only meaningful on macOS (core.precomposeUnicode, NFD names)
//   @git DIR [ignorecase=true|false] [precompose=true|false]
//                           fake repository at DIR ("." = tree root): DIR/.git/config
//   @exclude DIR = TEXT     DIR/.git/info/exclude
//   @global = TEXT          global excludes (HOME/.config/git/ignore beside the tree)
//   @file PATH [= TEXT]     file (empty unless TEXT); parent dirs created
//   @dir PATH               empty directory
//   @symlink PATH = TARGET  symbolic link (POSIX only; skipped where links cannot be made)
//   @root DIR               walk tree/DIR instead of the tree root (oracle runs from there)
//   @unreadable DIR [= pruned]
//                           chmod 000 DIR once built (POSIX; skipped where it is not enforced).
//                           The walk must report it, unless "pruned" (an ignore rule skips it);
//                           diff_files.sh also compares the oracle's error messages. DIR is
//                           relative to the tree, which such specs walk (no @root).
//   @expect                rest of the file: expected `files` output, one path per line
// PATH and TEXT take escapes: \n \r \t \\ \xHH (so names may hold spaces or raw bytes).
// A filesystem may refuse names a spec needs (APFS rejects non-UTF-8 bytes): materialize() then
// returns the reason and the caller skips the spec.

#include "brosearch/walk.h"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tree_spec {

struct Entry {
    std::string path;
    std::string content;  // file content, or symlink target
    bool dir = false;
    bool symlink = false;
};

struct GitRoot {
    std::string dir;
    std::optional<bool> ignorecase;
    std::optional<bool> precompose;
    std::optional<std::string> exclude;
};

struct Spec {
    std::string oracle = "rg";
    std::vector<std::string> options;
    bool posix_only = false;
    bool darwin_only = false;
    std::string root;  // relative walk root ("" = tree)
    std::vector<GitRoot> git_roots;
    std::optional<std::string> global;
    std::vector<Entry> entries;
    struct Unreadable {
        std::string dir;     // made unreadable (mode 000) after materializing
        bool reported;       // false: "= pruned", an ignore rule skips it before it is opened
    };
    std::vector<Unreadable> unreadable;
    std::vector<std::string> expect;
    std::string header;  // everything up to and including the "@expect" line, verbatim
};

inline std::string unescape(std::string_view s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) {
            out.push_back(c);
            continue;
        }
        char n = s[++i];
        switch (n) {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '\\': out.push_back('\\'); break;
        case 'x': {
            auto hex = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                return 0;
            };
            if (i + 2 < s.size()) {
                out.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
                i += 2;
            }
            break;
        }
        default: out.push_back('\\'); out.push_back(n); break;
        }
    }
    return out;
}

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// Splits "LHS = RHS" at the first " = ".
inline void split_assign(std::string_view s, std::string_view& lhs, std::optional<std::string_view>& rhs) {
    size_t eq = s.find(" = ");
    if (eq == std::string_view::npos) {
        lhs = trim(s);
        rhs.reset();
    } else {
        lhs = trim(s.substr(0, eq));
        rhs = s.substr(eq + 3);
    }
}

inline bool parse(std::string_view text, Spec& spec, std::string& err) {
    size_t i = 0;
    bool in_expect = false;
    while (i < text.size()) {
        size_t nl = text.find('\n', i);
        size_t end = nl == std::string_view::npos ? text.size() : nl;
        std::string_view raw = text.substr(i, end - i);
        i = nl == std::string_view::npos ? text.size() : nl + 1;
        std::string_view line = raw;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (in_expect) {
            if (!line.empty()) spec.expect.push_back(unescape(line));
            continue;
        }
        spec.header.append(line);
        spec.header.push_back('\n');
        std::string_view t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        auto word_end = t.find(' ');
        std::string_view kw = t.substr(0, word_end);
        std::string_view rest = word_end == std::string_view::npos ? std::string_view() : t.substr(word_end + 1);
        std::string_view lhs;
        std::optional<std::string_view> rhs;
        if (kw == "@expect") {
            in_expect = true;
        } else if (kw == "@oracle") {
            spec.oracle = std::string(trim(rest));
        } else if (kw == "@posix") {
            spec.posix_only = true;
        } else if (kw == "@darwin") {
            spec.darwin_only = true;
        } else if (kw == "@root") {
            spec.root = unescape(trim(rest));
        } else if (kw == "@symlink") {
            split_assign(rest, lhs, rhs);
            Entry e;
            e.path = unescape(lhs);
            e.symlink = true;
            e.content = unescape(rhs.value_or(""));
            spec.entries.push_back(std::move(e));
        } else if (kw == "@options") {
            size_t j = 0;
            while (j < rest.size()) {
                size_t sp = rest.find(' ', j);
                if (sp == std::string_view::npos) sp = rest.size();
                if (sp > j) spec.options.push_back(unescape(rest.substr(j, sp - j)));
                j = sp + 1;
            }
        } else if (kw == "@git") {
            GitRoot g;
            std::string_view r = trim(rest);
            size_t sp = r.find(' ');
            g.dir = unescape(r.substr(0, sp));
            while (sp != std::string_view::npos) {
                r = trim(r.substr(sp + 1));
                sp = r.find(' ');
                std::string_view o = r.substr(0, sp);
                if (o == "ignorecase=true") g.ignorecase = true;
                else if (o == "ignorecase=false") g.ignorecase = false;
                else if (o == "precompose=true") g.precompose = true;
                else if (o == "precompose=false") g.precompose = false;
                else { err = "bad @git option: " + std::string(o); return false; }
            }
            spec.git_roots.push_back(std::move(g));
        } else if (kw == "@exclude") {
            split_assign(rest, lhs, rhs);
            std::string dir = unescape(lhs);
            bool found = false;
            for (auto& g : spec.git_roots)
                if (g.dir == dir) { g.exclude = unescape(rhs.value_or("")); found = true; }
            if (!found) { err = "@exclude before @git " + dir; return false; }
        } else if (kw == "@global") {
            spec.global = unescape(rest.size() >= 2 && rest.substr(0, 2) == "= " ? rest.substr(2) : rest);
        } else if (kw == "@unreadable") {
            split_assign(rest, lhs, rhs);
            spec.unreadable.push_back({unescape(lhs), !(rhs && trim(*rhs) == "pruned")});
        } else if (kw == "@file" || kw == "@dir") {
            split_assign(rest, lhs, rhs);
            Entry e;
            e.path = unescape(lhs);
            e.dir = kw == "@dir";
            if (rhs) e.content = unescape(*rhs);
            spec.entries.push_back(std::move(e));
        } else {
            err = "unknown directive: " + std::string(kw);
            return false;
        }
    }
    if (!in_expect) { err = "missing @expect"; return false; }
    return true;
}

inline std::filesystem::path u8path(std::string_view s) {
#ifdef _WIN32
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
#else
    return std::filesystem::path(std::string(s));  // raw bytes, may be non-UTF-8
#endif
}

inline void write_bytes(const std::filesystem::path& p, std::string_view content) {
    std::filesystem::create_directories(p.parent_path());
    errno = 0;
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) {
        const int e = errno ? errno : EIO;
        throw std::filesystem::filesystem_error("cannot create file", p, std::error_code(e, std::generic_category()));
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// Whether this platform runs the spec at all ("" = yes, else why not).
inline std::string platform_skip(const Spec& spec) {
#ifdef _WIN32
    if (spec.posix_only) return "POSIX-only spec";
    if (!spec.unreadable.empty()) return "needs POSIX permissions";
#endif
#ifndef __APPLE__
    if (spec.darwin_only) return "macOS-only spec";
#endif
    (void)spec;
    return {};
}

// HOME used for the spec's global excludes file: a sibling of the tree directory.
inline std::filesystem::path home_for(const std::filesystem::path& tree) {
    return tree.parent_path() / (tree.filename().native() + std::filesystem::path(".home").native());
}

inline std::filesystem::path global_file_for(const std::filesystem::path& tree) {
    return home_for(tree) / ".config" / "git" / "ignore";
}

// Builds the tree. Returns "" on success, or why the filesystem cannot hold it (a name it refuses,
// e.g. non-UTF-8 bytes on APFS: EILSEQ); other failures throw.
inline std::string materialize(const Spec& spec, const std::filesystem::path& tree) {
    try {
        std::filesystem::create_directories(tree);
        for (const auto& g : spec.git_roots) {
            auto gd = (g.dir == "." ? tree : tree / u8path(g.dir)) / ".git";
            std::filesystem::create_directories(gd / "info");
            std::string cfg = "[core]\n\trepositoryformatversion = 0\n";
            if (g.ignorecase) cfg += std::string("\tignorecase = ") + (*g.ignorecase ? "true" : "false") + "\n";
            if (g.precompose) cfg += std::string("\tprecomposeunicode = ") + (*g.precompose ? "true" : "false") + "\n";
            write_bytes(gd / "config", cfg);
            if (g.exclude) write_bytes(gd / "info" / "exclude", *g.exclude);
        }
        if (spec.global) write_bytes(global_file_for(tree), *spec.global);
        for (const auto& e : spec.entries) {
            auto p = tree / u8path(e.path);
            if (e.dir) {
                std::filesystem::create_directories(p);
            } else if (e.symlink) {
                std::error_code ec;
                std::filesystem::create_directories(p.parent_path(), ec);
                std::filesystem::create_symlink(u8path(e.content), p, ec);  // may fail on Windows
            } else {
                write_bytes(p, e.content);
            }
        }
    } catch (const std::filesystem::filesystem_error& ex) {
        if (ex.code() == std::errc::illegal_byte_sequence) return std::string("filesystem refuses a name: ") + ex.what();
        throw;
    }
    for (const auto& u : spec.unreadable) {
        const auto p = tree / u8path(u.dir);
        std::filesystem::permissions(p, std::filesystem::perms::none);
        std::error_code ec;
        std::filesystem::directory_iterator probe(p, ec);
        if (!ec) {  // e.g. running as root: the mode is not enforced
            std::filesystem::permissions(p, std::filesystem::perms::owner_all);
            return "permissions are not enforced here (root?)";
        }
    }
    return {};
}

// Gives @unreadable directories back their permissions so the tree can be deleted.
inline void restore(const Spec& spec, const std::filesystem::path& tree) {
    std::error_code ec;
    for (const auto& u : spec.unreadable)
        std::filesystem::permissions(tree / u8path(u.dir), std::filesystem::perms::owner_all, ec);
}

inline std::filesystem::path walk_root(const Spec& spec, const std::filesystem::path& tree) {
    return spec.root.empty() ? tree : tree / u8path(spec.root);
}

// Applies one option word ("hidden", "glob=PAT", "max-depth=2", ...). False if unknown.
inline bool apply_walk_option(bro::search::WalkOptions& o, std::string_view w) {
    auto val = [&](std::string_view key) -> std::optional<std::string_view> {
        if (w.size() > key.size() && w.substr(0, key.size()) == key && w[key.size()] == '=')
            return w.substr(key.size() + 1);
        return std::nullopt;
    };
    if (w == "hidden") o.hidden = true;
    else if (w == "no-ignore") { o.git_ignore = o.ignore_files = o.git_exclude = o.git_global = o.parents = false; }
    else if (w == "no-ignore-vcs") { o.git_ignore = o.git_exclude = o.git_global = false; }
    else if (w == "no-ignore-dot") o.ignore_files = false;
    else if (w == "no-ignore-parent") o.parents = false;
    else if (w == "no-ignore-exclude") o.git_exclude = false;
    else if (w == "no-ignore-global") o.git_global = false;
    else if (w == "no-require-git") o.require_git = false;
    else if (w == "follow") o.follow_symlinks = true;
    else if (w == "glob-case-insensitive") o.glob_case_insensitive = true;
    else if (auto v = val("glob")) o.globs.emplace_back(*v);
    else if (auto v2 = val("max-depth")) o.max_depth = std::stoull(std::string(*v2));
    else if (auto v3 = val("threads")) o.threads = std::stoull(std::string(*v3));
    else if (auto v4 = val("case")) {
        if (*v4 == "auto") o.ignore_case = bro::search::CaseMode::Auto;
        else if (*v4 == "sensitive") o.ignore_case = bro::search::CaseMode::Sensitive;
        else if (*v4 == "insensitive") o.ignore_case = bro::search::CaseMode::Insensitive;
        else return false;
    } else if (auto v6 = val("dialect")) {
        if (*v6 == "git") o.dialect = bro::search::IgnoreDialect::Git;
        else if (*v6 == "rg") o.dialect = bro::search::IgnoreDialect::Rg;
        else return false;
    } else if (auto v5 = val("precompose")) {
        if (*v5 == "auto") o.precompose_unicode = bro::search::Precompose::Auto;
        else if (*v5 == "on") o.precompose_unicode = bro::search::Precompose::On;
        else if (*v5 == "off") o.precompose_unicode = bro::search::Precompose::Off;
        else return false;
    } else return false;
    return true;
}

// Walk options for a materialized spec: hermetic global excludes (only the spec's own).
inline bool walk_options(const Spec& spec, const std::filesystem::path& tree, bro::search::WalkOptions& o,
                         std::string& err) {
    o = bro::search::WalkOptions();
    o.parents = false;  // never pick up ignore files from wherever the scratch dir lives
    // Each oracle's own reading of ignore files; rg runs from the walk root with no path argument.
    o.dialect = spec.oracle == "rg" ? bro::search::IgnoreDialect::Rg : bro::search::IgnoreDialect::Git;
    o.display_root = ".";
    for (const auto& w : spec.options) {
        if (w == "parents") { o.parents = true; continue; }
        if (w.rfind("ignore-file=", 0) == 0) {  // relative to the walk root, as rg (run there) takes it
            o.extra_ignore_files.push_back(walk_root(spec, tree) / u8path(w.substr(12)));
            continue;
        }
        if (!apply_walk_option(o, w)) { err = "unknown option: " + w; return false; }
    }
    if (spec.global) o.git_global_file = global_file_for(tree);
    else o.git_global = false;
    return true;
}

} // namespace tree_spec
