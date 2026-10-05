#pragma once
// Minimal git repository + config discovery: enough to find info/exclude, core.ignorecase and
// core.excludesFile the way git (and ripgrep's ignore crate) do. Internal.

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

// Platform default for CaseMode::Auto outside a repository.
bool platform_default_ignorecase();

// The global excludes file as ripgrep resolves it: core.excludesFile from ~/.gitconfig, then from
// $XDG_CONFIG_HOME/git/config (default ~/.config/git/config), else $XDG_CONFIG_HOME/git/ignore.
// "~/" is expanded. Empty if no home directory is known.
std::filesystem::path global_excludes_path();

} // namespace bro::search::detail
