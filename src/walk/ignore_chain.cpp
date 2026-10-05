#include "walk/ignore_chain.h"

namespace bro::search::detail {

void DirNode::finish() {
    const DirNode* p = parent.get();
    any_git = has_git || (p && p->any_git);
    repo = has_git ? this : (p ? p->repo : nullptr);
    active.clear();
    if (custom) active.push_back({MatcherKind::Custom, custom.get(), this});
    if (ignore) active.push_back({MatcherKind::Ignore, ignore.get(), this});
    if (git) active.push_back({MatcherKind::Git, git.get(), this});
    if (exclude) active.push_back({MatcherKind::Exclude, exclude.get(), this});
    if (!p) return;
    for (const auto& m : p->active) {
        // ripgrep's saw_git: once the walk up passes a directory containing .git, outer
        // .gitignore / info/exclude files no longer apply.
        if (has_git && (m.kind == MatcherKind::Git || m.kind == MatcherKind::Exclude)) continue;
        active.push_back(m);
    }
}

namespace {

// Path of `rel` (relative to the walk root) as seen from `owner`'s directory.
std::string_view relative_to(const DirNode* owner, std::string_view rel, std::string& scratch) {
    if (!owner) return rel;
    if (owner->abs_parent) {
        scratch.assign(owner->base);
        scratch.append(rel);
        return scratch;
    }
    if (owner->base.empty()) return rel;
    return rel.substr(owner->base.size() + 1);
}

} // namespace

IgnoreMatch IgnoreConfig::matched(const DirNode& node, std::string_view rel, bool is_dir, bool hidden) const {
    // Overrides first: any match decides; with include globs, unmatched files are ignored.
    if (!overrides.empty()) {
        IgnoreMatch m = overrides.match(rel, is_dir, glob_icase);
        if (m == IgnoreMatch::Ignore) return IgnoreMatch::Whitelist;
        if (m == IgnoreMatch::Whitelist) return IgnoreMatch::Ignore;
        if (override_includes > 0 && !is_dir) return IgnoreMatch::Ignore;
    }

    IgnoreMatch result = IgnoreMatch::None;
    if (any_rules) {
        thread_local std::string scratch;
        const bool any_git = !require_git || node.any_git;
        IgnoreMatch slot[4] = {IgnoreMatch::None, IgnoreMatch::None, IgnoreMatch::None, IgnoreMatch::None};
        for (const auto& m : node.active) {
            const auto k = static_cast<size_t>(m.kind);
            if (slot[k] != IgnoreMatch::None) continue;
            if ((m.kind == MatcherKind::Git || m.kind == MatcherKind::Exclude) && !any_git) continue;
            if (m.owner->abs_parent && !use_parents) continue;
            slot[k] = m.rules->match(relative_to(m.owner, rel, scratch), is_dir, icase);
        }
        for (IgnoreMatch s : slot) {
            if (s != IgnoreMatch::None) {
                result = s;
                break;
            }
        }
        if (result == IgnoreMatch::None && has_global && any_git)
            result = global.match(relative_to(node.repo, rel, scratch), is_dir, icase);
        if (result == IgnoreMatch::None && !explicit_files.empty())
            result = explicit_files.match(rel, is_dir, icase);
        if (result == IgnoreMatch::Ignore) return result;
    }
    if (result == IgnoreMatch::None && skip_hidden && hidden) return IgnoreMatch::Ignore;
    return result;
}

} // namespace bro::search::detail
