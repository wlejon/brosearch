#pragma once
// Minimal git repository + config discovery: enough to find info/exclude, core.ignorecase and
// core.excludesFile the way git (and ripgrep's ignore crate) do. Internal.

#include "brosearch/ignore.h"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace bro::search::detail {

// Reads a whole file; nullopt if it cannot be opened.
std::optional<std::string> read_whole_file(const std::filesystem::path& p);

// `dir/.git` exists (directory, or a gitfile as used by worktrees and submodules).
bool has_dot_git(const std::filesystem::path& dir);

struct GitDirs {
    std::filesystem::path git_dir;     // .git, or the gitfile's target
    std::filesystem::path common_dir;  // shared dir for worktrees (holds info/exclude, config)
};
// Resolves `dir/.git` (directory or "gitdir: <path>" file, plus the "commondir" indirection).
std::optional<GitDirs> resolve_git_dirs(const std::filesystem::path& dir);

// Nearest ancestor-or-self of `start` (made absolute) containing .git; empty if none.
std::filesystem::path find_repo_root(const std::filesystem::path& start);

// git-config lookup of `section.key` (case-insensitive names, last value wins, quoting and
// escapes handled, bare keys = "true"). Subsections are not matched.
std::optional<std::string> config_value(std::string_view config_text, std::string_view section,
                                        std::string_view key);
std::optional<bool> parse_config_bool(std::string_view v);

// core.ignorecase of the repository whose root is `repo_root`, if set.
std::optional<bool> repo_ignorecase(const std::filesystem::path& repo_root);
// core.precomposeUnicode of the repository whose root is `repo_root`, if set.
std::optional<bool> repo_precompose(const std::filesystem::path& repo_root);

// Default for CaseMode::Auto outside a repository: insensitive on Windows; on macOS what the
// volume holding `near` reports (pathconf _PC_CASE_SENSITIVE; APFS and HFS+ can be either),
// insensitive when unknown; sensitive elsewhere.
bool platform_default_ignorecase(const std::filesystem::path& near = {});

// CaseMode / Precompose resolved for a walk or filter rooted at `root` (absolute).
bool resolve_ignorecase(CaseMode mode, const std::filesystem::path& root);
bool resolve_precompose(Precompose mode, const std::filesystem::path& root);

// NFD -> NFC of one name or path, as git does on macOS (iconv "UTF-8-MAC" -> "UTF-8"). Writes
// `out` and returns true only when `in` holds non-ASCII bytes and converts to something
// different; false (out untouched) for ASCII, ill-formed input, and on every other platform.
bool precompose_utf8(std::string_view in, std::string& out);

// The global excludes file as ripgrep resolves it: core.excludesFile from ~/.gitconfig, then from
// $XDG_CONFIG_HOME/git/config (default ~/.config/git/config), else $XDG_CONFIG_HOME/git/ignore.
// "~/" is expanded. Empty if no home directory is known.
std::filesystem::path global_excludes_path();

} // namespace bro::search::detail
