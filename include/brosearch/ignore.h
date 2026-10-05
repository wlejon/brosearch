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

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

// How ignore patterns compare letters. Auto = the repository's core.ignorecase when inside a git
// repo, else the platform default (insensitive on Windows and macOS, sensitive elsewhere).
enum class CaseMode : uint8_t { Auto, Sensitive, Insensitive };

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
};

// One ordered list of rules sharing a base directory (one ignore file, or lines added
// programmatically). Paths given to match() are relative to that base, '/'-separated.
class Gitignore {
public:
    Gitignore() = default;

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
    std::vector<IgnoreRule> rules_;
    size_t whitelists_ = 0;
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
    // from its location, and Auto reads core.ignorecase from the repository containing `root`.
    explicit IgnoreFilter(const std::filesystem::path& root, CaseMode mode = CaseMode::Auto);

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
    std::vector<Group> groups_;
};

} // namespace bro::search
