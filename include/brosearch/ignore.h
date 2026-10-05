#pragma once
// gitignore semantics, ported from git (dir.c + wildmatch.c):
//  - '#' comments, blank lines, trailing spaces trimmed unless escaped ("foo\ "), CRLF lines,
//    UTF-8 BOM at the start of a file.
//  - "!pat" re-includes; "\!" / "\#" escape a leading '!' / '#'.
//  - "pat/" matches directories only.
//  - A pattern with no '/' (other than a trailing one) matches the basename at any depth;
//    otherwise it is anchored to the directory holding the rules (a leading '/' is dropped).
//  - wildmatch: '*' and '?' never match '/'; "**" spans directories only as a whole path
//    component ("**/x", "x/**", "a/**/b"), otherwise it behaves like '*'; "[...]" classes with
//    ranges, '!' or '^' negation, POSIX "[:alpha:]" etc.; backslash escapes the next character.
//  - Case folding (CaseMode) is ASCII-only, exactly like git's core.ignorecase.
//  - A path below an ignored directory is ignored no matter what (git cannot re-include it);
//    IgnoreFilter::is_ignored applies this by checking every ancestor directory.
//
// IgnoreDialect::Rg instead reads lines the way ripgrep's ignore crate does:
//  - all trailing whitespace (tabs and Unicode spaces too) is trimmed unless the line ends in
//    "\ "; a file stops at its first line that is not valid UTF-8;
//  - a line globset rejects (unclosed '{', reversed range, trailing '\') is skipped;
//  - a lone "!" whitelists everything;
//  - patterns are globset globs: no POSIX classes, classes match '/', "{a,b}" alternation, an
//    unclosed '[' is literal (see rg_glob_match).

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

namespace detail {
class RgGlob;
}

// Whose reading of ignore files and globs to follow: git's (dir.c + wildmatch) or ripgrep's (the
// ignore and globset crates). The walker also anchors global excludes, extra ignore files and -g
// globs differently under Rg (see WalkOptions::dialect).
enum class IgnoreDialect : uint8_t { Git, Rg };

// One glob in ripgrep's dialect, matched against a whole '/'-separated path (no implicit "**/").
// False for a glob ripgrep rejects.
[[nodiscard]] bool rg_glob_match(std::string_view glob, std::string_view text, bool case_insensitive = false);
// Whether ripgrep accepts the glob; `error` (when given) says why not.
[[nodiscard]] bool rg_glob_valid(std::string_view glob, std::string* error = nullptr);

// How ignore patterns compare letters. Auto = the repository's core.ignorecase when inside a git
// repo, else the platform default (insensitive on Windows; on macOS whatever the volume reports,
// insensitive if unknown; sensitive elsewhere).
enum class CaseMode : uint8_t { Auto, Sensitive, Insensitive };

// Unicode precomposition of path names, git's core.precomposeUnicode. macOS compares names
// normalization-insensitively, and HFS+ (and Cocoa's file APIs, on APFS too) store them decomposed
// (NFD), while ignore patterns are normally typed composed (NFC). When on, each non-ASCII name is
// converted to NFC before matching, exactly as git converts it (patterns are used as written), and
// the walker reports rel_path in NFC; WalkEntry::native_path keeps the bytes on disk.
// Auto = the repository's core.precomposeUnicode (which `git init` sets to true on macOS); off
// outside a repository. Like git, this only exists on macOS: elsewhere the two normalizations are
// different names and every mode means off.
enum class Precompose : uint8_t { Auto, Off, On };

// The NFC form git uses for an NFD name on macOS (`name` itself if ASCII, ill-formed, already
// composed, or on any other platform).
[[nodiscard]] std::string precompose_name(std::string_view name);

// Outcome of matching one path: no rule matched, the last matching rule ignores it, or the last
// matching rule is a negation ("!pat") that whitelists it.
enum class IgnoreMatch : uint8_t { None, Ignore, Whitelist };

// git wildmatch. `pathname` = WM_PATHNAME ('*', '?' and classes do not match '/').
[[nodiscard]] bool glob_match(std::string_view pattern, std::string_view text,
                              bool case_insensitive = false, bool pathname = true);

struct IgnoreRule {
    enum class Kind : uint8_t { Glob, Literal, Suffix };

    std::string original;      // the line as written (newline/CR removed)
    std::string pattern;       // '!' and trailing '/' removed, trailing spaces trimmed
    bool negated = false;      // "!pat"
    bool dir_only = false;     // "pat/"
    bool basename_only = false;// no '/' in pattern: match the last path component at any depth
    Kind kind = Kind::Glob;    // Literal / Suffix ("*.ext") are fast paths for basename rules
    // IgnoreDialect::Rg: the compiled glob, matched against the whole path. `pattern` then holds
    // the glob as the ignore crate rewrites it ("**/" prefix for basename rules, "/**" -> "/**/*").
    std::shared_ptr<const detail::RgGlob> rg;
};

// One ordered list of rules sharing a base directory (one ignore file, or lines added
// programmatically). Paths given to match() are relative to that base, '/'-separated.
class Gitignore {
public:
    explicit Gitignore(IgnoreDialect dialect = IgnoreDialect::Git) : dialect_(dialect) {}

    [[nodiscard]] IgnoreDialect dialect() const noexcept { return dialect_; }

    // Parses one line (without its '\n'; a trailing '\r' is removed).
    void add_line(std::string_view line);
    // Parses a whole file's content: optional UTF-8 BOM, '\n' or "\r\n" line ends.
    void add_content(std::string_view content);
    // Reads and parses a file. Returns false if it cannot be read.
    bool add_file(const std::filesystem::path& file);

    // The last rule matching `path` decides (git's last-match-wins).
    [[nodiscard]] IgnoreMatch match(std::string_view path, bool is_dir, bool case_insensitive) const;

    [[nodiscard]] bool empty() const noexcept { return rules_.empty(); }
    [[nodiscard]] size_t size() const noexcept { return rules_.size(); }
    [[nodiscard]] const std::vector<IgnoreRule>& rules() const noexcept { return rules_; }
    [[nodiscard]] size_t whitelist_count() const noexcept { return whitelists_; }

private:
    void add_line_rg(std::string_view line);

    std::vector<IgnoreRule> rules_;
    size_t whitelists_ = 0;
    IgnoreDialect dialect_ = IgnoreDialect::Git;
};

// A set of rule groups at different base directories, answering git check-ignore style
// questions for paths relative to a root. Precedence follows git: rules whose base is deeper win;
// among groups with the same base, the one added later wins (so add info/exclude and global
// excludes *before* the root .gitignore). Within a group the last matching rule wins.
class IgnoreFilter {
public:
    // No root: paths and bases are taken as given (relative). Auto resolves to the platform default.
    explicit IgnoreFilter(CaseMode mode = CaseMode::Sensitive);
    // With a root: absolute paths under it are made relative, load_file() derives each file's base
    // from its location, and Auto reads core.ignorecase / core.precomposeUnicode from the
    // repository containing `root`. Precomposition applies to the paths asked about.
    explicit IgnoreFilter(const std::filesystem::path& root, CaseMode mode = CaseMode::Auto,
                          Precompose precompose = Precompose::Auto);

    void add_rule(std::string_view line, std::string_view base_dir = "");
    void add_rules(std::string_view content, std::string_view base_dir = "");
    // Base = the file's directory relative to the root ("" when there is no root, or when the file
    // is outside it).
    bool load_file(const std::filesystem::path& file);
    bool load_file(const std::filesystem::path& file, std::string_view base_dir);
    void clear() noexcept { groups_.clear(); }

    // Rules applied to this path only (ancestors not considered).
    [[nodiscard]] IgnoreMatch match(std::string_view path, bool is_dir) const;
    // git semantics: ignored if the path, or any ancestor directory, is ignored.
    [[nodiscard]] bool is_ignored(std::string_view path, bool is_dir = false) const;
    [[nodiscard]] bool is_ignored(const std::string& path, bool is_dir = false) const {
        return is_ignored(std::string_view(path), is_dir);
    }
    [[nodiscard]] bool is_ignored(const char* path, bool is_dir = false) const {
        return is_ignored(std::string_view(path), is_dir);
    }
    [[nodiscard]] bool is_ignored(const std::filesystem::path& path, bool is_dir = false) const;

    [[nodiscard]] bool case_insensitive() const noexcept { return icase_; }
    [[nodiscard]] bool precomposes() const noexcept { return precompose_; }
    [[nodiscard]] size_t rule_count() const noexcept;

private:
    struct Group {
        std::string base;  // normalized: no leading/trailing '/', "" = root
        Gitignore rules;
    };
    Group& group_for(std::string_view base_dir);
    [[nodiscard]] std::string normalize(std::string_view path) const;
    [[nodiscard]] IgnoreMatch match_normalized(std::string_view path, bool is_dir) const;

    std::filesystem::path root_;
    bool icase_ = false;
    bool precompose_ = false;
    std::vector<Group> groups_;
};

} // namespace bro::search
