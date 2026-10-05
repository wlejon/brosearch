// Parallel directory walker. Work unit = one directory: a worker lists it, builds its ignore node
// from the ignore files present in the listing (no extra stat calls), filters the entries, reports
// the survivors and queues the surviving subdirectories. Ignored directories are never opened.

#include "brosearch/walk.h"

#include "ignore/git_repo.h"
#include "walk/dir_reader.h"
#include "walk/ignore_chain.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace fs = std::filesystem;

namespace bro::search {

namespace {

using detail::DirNode;
using detail::NativeString;


std::string to_utf8(const fs::path& p) {
    auto u = p.generic_u8string();
    return std::string(u.begin(), u.end());
}

struct Task {
    std::shared_ptr<const DirNode> parent;
    std::string rel;          // directory path relative to the root ("" = root)
    NativeString enum_dir;    // absolute path used for enumeration
    NativeString disp_dir;    // root-as-given based path, for WalkEntry::native_path
    size_t depth = 0;         // depth of this directory (root = 0)
};

class Walker {
public:
    Walker(const WalkOptions& o, const WalkCallback& cb, const CancellationToken* tok)
        : opts_(o), cb_(cb), token_(tok) {}

    void run(const fs::path& root);

private:
    bool cancelled() const {
        return stop_.load(std::memory_order_relaxed) || (token_ && token_->is_cancelled());
    }
    std::shared_ptr<const DirNode> build_abs_parents(const fs::path& abs_root);
    void load_dir_files(DirNode& node, const NativeString& dir, bool has_gitignore, bool has_ignore,
                        bool has_rgignore, bool has_git_entry) const;
    void process(Task& task, detail::DirListing& listing, std::vector<Task>& out);
    void worker();
    bool emit(std::string_view rel, EntryType type, size_t depth, const NativeString& disp_dir,
              detail::NativeView name);

    const WalkOptions& opts_;
    const WalkCallback& cb_;
    const CancellationToken* token_;
    detail::IgnoreConfig cfg_;
    bool track_git_ = false;
    bool precompose_ = false;  // NFD names -> NFC for matching and rel_path (macOS only)

    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Task> stack_;
    size_t pending_ = 0;
    std::atomic<bool> stop_{false};
};

std::shared_ptr<const DirNode> Walker::build_abs_parents(const fs::path& abs_root) {
    std::vector<fs::path> ancestors;  // nearest first
    for (fs::path p = abs_root.parent_path(); !p.empty(); p = p.parent_path()) {
        ancestors.push_back(p);
        if (p == p.parent_path()) break;
    }
    std::shared_ptr<const DirNode> chain;
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
        auto node = std::make_shared<DirNode>();
        node->parent = chain;
        node->abs_parent = true;
        std::string prefix = to_utf8(abs_root.lexically_relative(*it));
        if (!prefix.empty() && prefix.back() != '/') prefix.push_back('/');
        node->base = std::move(prefix);
        std::error_code ec;
        bool dot_git = detail::has_dot_git(*it);
        node->has_git = track_git_ && dot_git;
        if (opts_.parents) {
            NativeString dir = detail::enum_path(*it);
            auto exists = [&](const char* name) { return fs::exists(*it / name, ec); };
            load_dir_files(*node, dir, opts_.git_ignore && exists(".gitignore"),
                           opts_.ignore_files && exists(".ignore"), opts_.ignore_files && exists(".rgignore"),
                           dot_git);
        }
        node->finish();
        chain = std::move(node);
    }
    return chain;
}

void Walker::load_dir_files(DirNode& node, const NativeString& dir, bool has_gitignore, bool has_ignore,
                            bool has_rgignore, bool has_git_entry) const {
    auto load = [&](std::unique_ptr<Gitignore>& slot, const char* name) {
        NativeString p = dir;
        p.push_back(detail::kNativeSep);
        for (const char* c = name; *c; ++c) p.push_back(static_cast<NativeString::value_type>(*c));
        auto gi = std::make_unique<Gitignore>(opts_.dialect);
        if (gi->add_file(fs::path(p)) && !gi->empty()) slot = std::move(gi);
    };
    if (has_rgignore) load(node.custom, ".rgignore");
    if (has_ignore) load(node.ignore, ".ignore");
    if (has_gitignore) load(node.git, ".gitignore");
    if (has_git_entry && track_git_ && opts_.git_exclude) {
        if (auto dirs = detail::resolve_git_dirs(fs::path(dir))) {
            auto gi = std::make_unique<Gitignore>(opts_.dialect);
            if (gi->add_file(dirs->common_dir / "info" / "exclude") && !gi->empty()) node.exclude = std::move(gi);
        }
    }
}

bool Walker::emit(std::string_view rel, EntryType type, size_t depth, const NativeString& disp_dir,
                  detail::NativeView name) {
    fs::path np;
    WalkEntry e;
    if (opts_.native_paths) {
        NativeString native = disp_dir;
        if (!native.empty() && native.back() != detail::kNativeSep && native.back() != '/')
            native.push_back(detail::kNativeSep);
        native += name;
        np = fs::path(std::move(native));
        e.native_path = &np;
    }
    e.rel_path = rel;
    e.type = type;
    e.depth = depth;
    if (!cb_(e)) {
        stop_.store(true, std::memory_order_relaxed);
        return false;
    }
    return true;
}

void Walker::process(Task& task, detail::DirListing& listing, std::vector<Task>& out) {
    std::error_code read_ec;
    if (!detail::read_dir(task.enum_dir, listing, read_ec)) {
        if (opts_.on_error) {
            const fs::path shown(task.disp_dir);
            WalkError err;
            err.op = WalkError::Op::ReadDir;
            err.rel_path = task.rel;
            err.native_path = &shown;
            err.error = read_ec;
            opts_.on_error(err);
        }
        return;
    }
    const auto& entries = listing.entries;

    auto node = std::make_shared<DirNode>();
    node->parent = task.parent;
    node->base = task.rel;
    bool f_gitignore = false, f_ignore = false, f_rgignore = false, f_git = false;
    for (const auto& e : entries) {
        const std::string_view n = listing.name(e);
        if (n.size() < 4 || n[0] != '.') continue;
        if (n == ".gitignore") f_gitignore = true;
        else if (n == ".ignore") f_ignore = true;
        else if (n == ".rgignore") f_rgignore = true;
        else if (n == ".git") f_git = true;
    }
    node->has_git = track_git_ && f_git;
    load_dir_files(*node, task.enum_dir, opts_.git_ignore && f_gitignore, opts_.ignore_files && f_ignore,
                   opts_.ignore_files && f_rgignore, f_git);
    if (opts_.follow_symlinks) {
        EntryType t;
        node->has_id = detail::stat_follow(task.enum_dir, t, node->id);
    }
    node->finish();

    const size_t depth = task.depth + 1;
    if (depth > opts_.max_depth) return;
    std::string rel, nfc;
    size_t counter = 0;
    for (const auto& e : entries) {
        if ((++counter & 255) == 0 && cancelled()) return;
        std::string_view name = listing.name(e);
        if (precompose_ && detail::precompose_utf8(name, nfc)) name = nfc;
        const detail::NativeView nname = listing.native_name(e);
        rel.assign(task.rel);
        if (!rel.empty()) rel.push_back('/');
        rel.append(name);

        EntryType type = e.type;
        bool linked_dir = false;
        detail::FileId target_id;
        NativeString child_enum;
        if (type == EntryType::Symlink && opts_.follow_symlinks) {
            child_enum = task.enum_dir;
            child_enum.push_back(detail::kNativeSep);
            child_enum += nname;
            EntryType t;
            if (detail::stat_follow(child_enum, t, target_id)) {
                type = t == EntryType::Directory ? EntryType::Directory
                                                 : (t == EntryType::File ? EntryType::File : EntryType::Other);
                linked_dir = type == EntryType::Directory;
            }
        }
        const bool is_dir = type == EntryType::Directory;
        const bool hidden = (!name.empty() && name[0] == '.') || e.hidden_attr;
        if (cfg_.matched(*node, rel, is_dir, hidden) == IgnoreMatch::Ignore) continue;

        if (!is_dir) {
            if (!emit(rel, type, depth, task.disp_dir, nname)) return;
            continue;
        }
        if (opts_.yield_directories && !emit(rel, EntryType::Directory, depth, task.disp_dir, nname))
            return;
        if (depth >= opts_.max_depth) continue;
        if (linked_dir) {
            bool loop = false;
            for (const DirNode* a = node.get(); a && !a->abs_parent; a = a->parent.get()) {
                if (a->has_id && a->id == target_id) {
                    loop = true;
                    break;
                }
            }
            if (loop) continue;
        }
        Task t;
        t.parent = node;
        t.rel = rel;
        if (child_enum.empty()) {
            child_enum = task.enum_dir;
            child_enum.push_back(detail::kNativeSep);
            child_enum += nname;
        }
        t.enum_dir = std::move(child_enum);
        t.disp_dir = task.disp_dir;
        if (!t.disp_dir.empty() && t.disp_dir.back() != detail::kNativeSep && t.disp_dir.back() != '/')
            t.disp_dir.push_back(detail::kNativeSep);
        t.disp_dir += nname;
        t.depth = depth;
        out.push_back(std::move(t));
    }
}

void Walker::worker() {
    detail::DirListing entries;
    std::vector<Task> out;
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&] { return !stack_.empty() || pending_ == 0 || stop_.load(std::memory_order_relaxed); });
            if (stop_.load(std::memory_order_relaxed) || stack_.empty()) {
                cv_.notify_all();
                return;
            }
            task = std::move(stack_.back());
            stack_.pop_back();
        }
        out.clear();
        if (!cancelled()) process(task, entries, out);
        if (token_ && token_->is_cancelled()) stop_.store(true, std::memory_order_relaxed);
        bool done;
        {
            std::lock_guard<std::mutex> lk(mu_);
            // Reverse so the single-threaded walk pops children in listing order (depth-first).
            for (auto it = out.rbegin(); it != out.rend(); ++it) stack_.push_back(std::move(*it));
            pending_ += out.size();
            --pending_;
            done = pending_ == 0;
        }
        if (done || stop_.load(std::memory_order_relaxed) || out.size() > 1) cv_.notify_all();
        else if (!out.empty()) cv_.notify_one();
    }
}

void Walker::run(const fs::path& root) {
    std::error_code ec;
    fs::file_status st = fs::status(root, ec);
    if (ec || !fs::exists(st)) {
        if (opts_.on_error) {
            WalkError err;
            err.op = WalkError::Op::Stat;
            err.native_path = &root;
            // ENOENT / ERROR_FILE_NOT_FOUND (both 2) when the library reports not_found without a code.
            err.error = ec ? ec : std::error_code(2, std::system_category());
            opts_.on_error(err);
        }
        return;
    }
    if (!fs::is_directory(st)) {
        std::string name = to_utf8(root.filename());
        WalkEntry e;
        e.rel_path = name;
        e.type = fs::is_regular_file(st) ? EntryType::File : EntryType::Other;
        e.depth = 0;
        e.native_path = &root;
        cb_(e);
        return;
    }
    fs::path abs = fs::absolute(root, ec).lexically_normal();
    if (ec) return;
    // lexically_normal keeps a trailing separator for "dir/"; drop it so parent_path() is right.
    while (abs.has_relative_path() && !abs.has_filename()) abs = abs.parent_path();

    track_git_ = opts_.require_git && (opts_.git_ignore || opts_.git_exclude);
    cfg_.skip_hidden = !opts_.hidden;
    cfg_.require_git = opts_.require_git;
    cfg_.use_parents = opts_.parents;
    cfg_.glob_icase = opts_.glob_case_insensitive;
    cfg_.icase = detail::resolve_ignorecase(opts_.ignore_case, abs);
    precompose_ = detail::resolve_precompose(opts_.precompose_unicode, abs);
    cfg_.dialect = opts_.dialect;
    cfg_.overrides = Gitignore(opts_.dialect);
    cfg_.global = Gitignore(opts_.dialect);
    cfg_.explicit_files = Gitignore(opts_.dialect);
    if (opts_.dialect == IgnoreDialect::Rg) {
        cfg_.rg_prefix = to_utf8(opts_.display_root.empty() ? root : opts_.display_root);
        while (cfg_.rg_prefix.size() > 1 && cfg_.rg_prefix.back() == '/') cfg_.rg_prefix.pop_back();
    }
    for (const auto& g : opts_.globs) cfg_.overrides.add_line(g);
    cfg_.override_includes = cfg_.overrides.size() - cfg_.overrides.whitelist_count();
    if (opts_.git_global) {
        fs::path gpath = opts_.git_global_file.empty() ? detail::global_excludes_path() : opts_.git_global_file;
        if (!gpath.empty() && cfg_.global.add_file(gpath) && !cfg_.global.empty()) cfg_.has_global = true;
    }
    for (const auto& f : opts_.extra_ignore_files) cfg_.explicit_files.add_file(f);
    cfg_.any_rules = opts_.git_ignore || opts_.ignore_files || opts_.git_exclude || cfg_.has_global ||
                     !cfg_.explicit_files.empty();

    Task t;
    if (opts_.parents || opts_.git_ignore || opts_.git_exclude || opts_.git_global) t.parent = build_abs_parents(abs);
    t.enum_dir = detail::enum_path(abs);
    t.disp_dir = root.native();
    t.depth = 0;
    stack_.push_back(std::move(t));
    pending_ = 1;

    size_t n = opts_.threads;
    if (n == 0) n = std::clamp<size_t>(std::thread::hardware_concurrency(), 1, 12);
    if (n == 1) {
        worker();
        return;
    }
    std::vector<std::thread> threads;
    threads.reserve(n);
    for (size_t i = 0; i < n; ++i) threads.emplace_back([this] { worker(); });
    for (auto& th : threads) th.join();
}

} // namespace

void walk(const fs::path& root, const WalkOptions& options, const WalkCallback& on_entry,
          const CancellationToken* token) {
    Walker w(options, on_entry, token);
    w.run(root);
}

std::vector<std::string> list_files(const fs::path& root, const WalkOptions& options,
                                    const CancellationToken* token) {
    std::vector<std::string> out;
    std::mutex mu;
    WalkOptions o = options;
    o.native_paths = false;
    walk(
        root, o,
        [&](const WalkEntry& e) {
            if (e.type != EntryType::File) return true;
            std::lock_guard<std::mutex> lk(mu);
            out.emplace_back(e.rel_path);
            return true;
        },
        token);
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace bro::search
