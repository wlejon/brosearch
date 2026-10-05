#pragma once
// Per-directory ignore state for the walker, modelled on ripgrep's ignore::dir::Ignore: a chain
// of immutable nodes from the directory being listed up to the filesystem root. Internal.

#include "brosearch/ignore.h"
#include "brosearch/walk.h"
#include "walk/dir_reader.h"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search::detail {

enum class MatcherKind : uint8_t { Custom, Ignore, Git, Exclude };  // precedence order

struct DirNode;

struct ActiveMatcher {
    MatcherKind kind;
    const Gitignore* rules;
    const DirNode* owner;
};

struct DirNode {
    std::shared_ptr<const DirNode> parent;
    // Above the walk root (ripgrep's "absolute parent"). Its `base` is then the prefix that turns a
    // root-relative path into one relative to this directory, e.g. "bro/src/".
    bool abs_parent = false;
    bool has_git = false;  // this directory holds .git (only tracked when require_git)
    bool any_git = false;  // has_git here or in any ancestor
    std::string base;      // in-root: path from the root ("" for the root itself)
    std::unique_ptr<Gitignore> custom, ignore, git, exclude;
    // Matchers that apply to entries of this directory, nearest directory first. .gitignore and
    // info/exclude rules beyond the nearest repository boundary are already dropped.
    std::vector<ActiveMatcher> active;
    const DirNode* repo = nullptr;  // nearest directory in the chain with has_git
    bool has_id = false;
    FileId id;                      // for symlink loop detection (follow_symlinks only)

    // Fills active/repo/any_git from the parent. Call once the matchers are loaded.
    void finish();
};

struct IgnoreConfig {
    bool skip_hidden = true;
    bool require_git = true;
    bool use_parents = true;
    bool icase = false;
    bool glob_icase = false;
    bool any_rules = false;     // any ignore source enabled (ripgrep's has_any_ignore_rules)
    IgnoreDialect dialect = IgnoreDialect::Git;
    // Rg: overrides, global excludes and extra ignore files match the path as ripgrep prints it,
    // this prefix (the root as given, e.g. "." or "src" or "/abs/dir") joined with `rel`.
    std::string rg_prefix;
    Gitignore overrides;        // -g globs (match inverted); Git: relative to the walk root
    size_t override_includes = 0;
    Gitignore global;           // global excludes; Git: relative to the nearest repository root
    bool has_global = false;
    Gitignore explicit_files;   // extra_ignore_files; Git: relative to the walk root

    // The ripgrep candidate path for `rel` (see rg_prefix), with the ignore crate's stripping of a
    // leading "./" and, unless it is a bare name, a leading '/'.
    [[nodiscard]] std::string_view rg_candidate(std::string_view rel, std::string& scratch) const;

    // Decides one entry. `rel` is relative to the walk root; `node` is its directory's node.
    [[nodiscard]] IgnoreMatch matched(const DirNode& node, std::string_view rel, bool is_dir,
                                      bool hidden) const;
};

} // namespace bro::search::detail
