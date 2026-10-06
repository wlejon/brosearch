#include "host_search_internal.h"

#include <filesystem>
#include <system_error>

namespace brosearch::api {

HostClass g_gitignoreClass;

static bro::search::WalkOptions parseWalkOptions(Value optVal) {
    bro::search::WalkOptions o;
    if (!ev::isObject(optVal)) return o;
    ev::Persistent opt(optVal);

    Value ignVal = ev::getProperty(opt.get(), "ignore");
    if (!ev::isUndefined(ignVal) && !ev::toBool(ignVal)) {
        o.git_ignore = false;
        o.ignore_files = false;
        o.git_exclude = false;
        o.git_global = false;
        o.parents = false;
        o.require_git = false;
    }
    Value rgVal = ev::getProperty(opt.get(), "requireGit");
    if (!ev::isUndefined(rgVal)) {
        o.require_git = ev::toBool(rgVal);
    }
    Value hidVal = ev::getProperty(opt.get(), "hidden");
    if (!ev::isUndefined(hidVal)) {
        o.hidden = ev::toBool(hidVal);
    }
    Value depVal = ev::getProperty(opt.get(), "maxDepth");
    if (ev::isNumber(depVal)) {
        double d = ev::toDouble(depVal);
        if (d >= 0) o.max_depth = static_cast<size_t>(d);
    }
    Value symVal = ev::getProperty(opt.get(), "followSymlinks");
    if (!ev::isUndefined(symVal)) {
        o.follow_symlinks = ev::toBool(symVal);
    }
    Value dirsVal = ev::getProperty(opt.get(), "yieldDirectories");
    if (!ev::isUndefined(dirsVal)) {
        o.yield_directories = ev::toBool(dirsVal);
    }
    Value globsVal = ev::getProperty(opt.get(), "globs");
    if (ev::isObject(globsVal)) {
        Value lenVal = ev::getProperty(globsVal, "length");
        if (ev::isNumber(lenVal)) {
            uint32_t gn = static_cast<uint32_t>(ev::toDouble(lenVal));
            for (uint32_t i = 0; i < gn; ++i) {
                Value g = ev::getElement(globsVal, i);
                if (ev::isString(g)) o.globs.push_back(ev::toUtf8(g));
            }
        }
    }
    return o;
}

static void executeWalk(const std::filesystem::path& root,
                        const bro::search::WalkOptions& walk_opts,
                        const std::string& query,
                        size_t max_results,
                        const bro::search::CancellationToken* token,
                        std::vector<std::string>& out_files,
                        const std::function<void(const std::string&)>& on_file = nullptr) {
    std::error_code ec;
    bool root_is_file = std::filesystem::is_regular_file(root, ec);
    std::mutex mu;

    if (query.empty()) {
        bro::search::walk(root, walk_opts, [&](const bro::search::WalkEntry& e) -> bool {
            if (token && token->is_cancelled()) return false;
            if (e.type != bro::search::EntryType::File && !(walk_opts.yield_directories && e.type == bro::search::EntryType::Directory)) {
                return true;
            }
            std::string p = root_is_file ? root.string() : std::string(e.rel_path);
            {
                std::lock_guard<std::mutex> lk(mu);
                if (max_results > 0 && out_files.size() >= max_results) return false;
                out_files.push_back(p);
            }
            if (on_file) on_file(p);
            return true;
        }, token);
    } else {
        std::vector<std::string> walked;
        bro::search::walk(root, walk_opts, [&](const bro::search::WalkEntry& e) -> bool {
            if (token && token->is_cancelled()) return false;
            if (e.type != bro::search::EntryType::File && !(walk_opts.yield_directories && e.type == bro::search::EntryType::Directory)) {
                return true;
            }
            std::string p = root_is_file ? root.string() : std::string(e.rel_path);
            std::lock_guard<std::mutex> lk(mu);
            walked.push_back(std::move(p));
            return true;
        }, token);

        bro::search::FuzzyOptions fopts;
        fopts.scheme = bro::search::FuzzyScheme::Path;
        bro::search::FuzzyQuery fq(query, fopts);
        auto results = bro::search::fuzzy_filter(fq, std::span<const std::string>(walked), max_results, false, token);
        out_files.reserve(results.size());
        for (const auto& r : results) {
            out_files.push_back(walked[r.index]);
            if (on_file) on_file(out_files.back());
        }
    }
}

static Value js_filesSync(Value, std::span<const Value> args) {
    std::string rootStr = (!args.empty() && ev::isString(args[0])) ? ev::toUtf8(args[0]) : ".";
    std::filesystem::path root(rootStr);

    Value optVal = args.size() > 1 ? args[1] : ev::undefined();
    ev::Persistent optP(optVal);
    bro::search::WalkOptions walk_opts = parseWalkOptions(optP.get());
    walk_opts.threads = 1;

    std::string query;
    size_t max_results = 0;
    ev::Persistent onFileFn;
    std::shared_ptr<bro::search::CancellationToken> cancel_tok;

    if (ev::isObject(optP.get())) {
        Value qVal = ev::getProperty(optP.get(), "query");
        if (ev::isString(qVal)) query = ev::toUtf8(qVal);

        Value mrVal = ev::getProperty(optP.get(), "maxResults");
        if (ev::isNumber(mrVal)) {
            double d = ev::toDouble(mrVal);
            if (d > 0) max_results = static_cast<size_t>(d);
        }

        Value ofVal = ev::getProperty(optP.get(), "onFile");
        if (ev::isFunction(ofVal)) onFileFn.set(ofVal);

        Value tokVal = ev::getProperty(optP.get(), "cancellationToken");
        if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        else {
            tokVal = ev::getProperty(optP.get(), "token");
            if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        }
    }

    std::vector<std::string> files;
    auto on_file = [&](const std::string& p) {
        if (ev::isFunction(onFileFn.get())) {
            ev::Persistent s(ev::fromUtf8(p));
            const Value arg = s.get();
            ev::call(onFileFn.get(), ev::undefined(), std::span<const Value>(&arg, 1));
        }
    };

    executeWalk(root, walk_opts, query, max_results, cancel_tok ? cancel_tok.get() : nullptr, files, on_file);

    ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(files.size())));
    for (size_t i = 0; i < files.size(); ++i) {
        ev::Persistent s(ev::fromUtf8(files[i]));
        resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), s.get()));
    }
    return resArr.get();
}

static Value js_files(Value, std::span<const Value> args) {
    std::string rootStr = (!args.empty() && ev::isString(args[0])) ? ev::toUtf8(args[0]) : ".";
    std::filesystem::path root(rootStr);

    Value optVal = args.size() > 1 ? args[1] : ev::undefined();
    ev::Persistent optP(optVal);
    bro::search::WalkOptions walk_opts = parseWalkOptions(optP.get());

    std::string query;
    size_t max_results = 0;
    ev::Persistent onFileFn;
    std::shared_ptr<bro::search::CancellationToken> cancel_tok;

    if (ev::isObject(optP.get())) {
        Value qVal = ev::getProperty(optP.get(), "query");
        if (ev::isString(qVal)) query = ev::toUtf8(qVal);

        Value mrVal = ev::getProperty(optP.get(), "maxResults");
        if (ev::isNumber(mrVal)) {
            double d = ev::toDouble(mrVal);
            if (d > 0) max_results = static_cast<size_t>(d);
        }

        Value ofVal = ev::getProperty(optP.get(), "onFile");
        if (ev::isFunction(ofVal)) onFileFn.set(ofVal);

        Value tokVal = ev::getProperty(optP.get(), "cancellationToken");
        if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        else {
            tokVal = ev::getProperty(optP.get(), "token");
            if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        }
    }

    if (!cancel_tok) {
        cancel_tok = std::make_shared<bro::search::CancellationToken>();
    }

    auto job = std::make_shared<AsyncJob>();
    job->is_grep = false;
    job->cancel_token = cancel_tok;
    job->promise.set(ev::createPromise());
    job->callback.set(onFileFn.get());

    job->worker = std::thread([job, root, walk_opts, query, max_results] {
        try {
            executeWalk(root, walk_opts, query, max_results, job->cancel_token.get(), job->files_result,
                        [&](const std::string& p) {
                            std::lock_guard<std::mutex> lk(job->stream_files_mu);
                            job->stream_files.push_back(p);
                        });
        } catch (const std::exception& e) {
            job->error = e.what();
        }
        job->done.store(true, std::memory_order_release);
    });

    Value pVal = job->promise.get();
    trackAsyncJob(job);
    return pVal;
}

// --- GitignoreMatcher ---

static bro::search::IgnoreFilter* unwrapGitignore(Value self) {
    return static_cast<bro::search::IgnoreFilter*>(g_gitignoreClass.unwrap(self));
}

static Value js_Gitignore_ctor(Value, std::span<const Value> args) {
    bro::search::CaseMode mode = bro::search::CaseMode::Auto;
    bro::search::Precompose pre = bro::search::Precompose::Auto;

    if (args.empty()) {
        auto filter = std::make_unique<bro::search::IgnoreFilter>(mode);
        return g_gitignoreClass.createInstance(std::move(filter));
    }

    std::string rootStr = ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";

    if (args.size() > 1 && ev::isObject(args[1])) {
        ev::Persistent opt(args[1]);
        Value cm = ev::getProperty(opt.get(), "caseMode");
        if (ev::isString(cm)) {
            std::string s = ev::toUtf8(cm);
            if (s == "sensitive") mode = bro::search::CaseMode::Sensitive;
            else if (s == "insensitive") mode = bro::search::CaseMode::Insensitive;
        }
        Value pr = ev::getProperty(opt.get(), "precompose");
        if (ev::isString(pr)) {
            std::string s = ev::toUtf8(pr);
            if (s == "on") pre = bro::search::Precompose::On;
            else if (s == "off") pre = bro::search::Precompose::Off;
        }
    }

    std::unique_ptr<bro::search::IgnoreFilter> filter;
    if (rootStr.empty()) {
        filter = std::make_unique<bro::search::IgnoreFilter>(mode);
    } else {
        filter = std::make_unique<bro::search::IgnoreFilter>(std::filesystem::path(rootStr), mode, pre);
    }

    return g_gitignoreClass.createInstance(std::move(filter));
}

static void decorateGitignore(ObjectBuilder& b) {
    b.def("add", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::throwTypeError("GitignoreMatcher: invalid receiver");
        if (args.empty() || !ev::isString(args[0])) return self;
        std::string pattern = ev::toUtf8(args[0]);
        std::string baseDir = args.size() > 1 && ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";
        f->add_rule(pattern, baseDir);
        return self;
    });

    b.def("addRule", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::throwTypeError("GitignoreMatcher: invalid receiver");
        if (args.empty() || !ev::isString(args[0])) return self;
        std::string pattern = ev::toUtf8(args[0]);
        std::string baseDir = args.size() > 1 && ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";
        f->add_rule(pattern, baseDir);
        return self;
    });

    b.def("addRules", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::throwTypeError("GitignoreMatcher: invalid receiver");
        if (args.empty() || !ev::isString(args[0])) return self;
        std::string content = ev::toUtf8(args[0]);
        std::string baseDir = args.size() > 1 && ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";
        f->add_rules(content, baseDir);
        return self;
    });

    b.def("loadFile", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::throwTypeError("GitignoreMatcher: invalid receiver");
        if (args.empty() || !ev::isString(args[0])) return ev::fromBool(false);
        std::string path = ev::toUtf8(args[0]);
        bool ok = false;
        if (args.size() > 1 && ev::isString(args[1])) {
            ok = f->load_file(std::filesystem::path(path), ev::toUtf8(args[1]));
        } else {
            ok = f->load_file(std::filesystem::path(path));
        }
        return ev::fromBool(ok);
    });

    b.def("isIgnored", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f || args.empty() || !ev::isString(args[0])) return ev::fromBool(false);
        std::string path = ev::toUtf8(args[0]);
        bool isDir = args.size() > 1 ? ev::toBool(args[1]) : false;
        return ev::fromBool(f->is_ignored(path, isDir));
    });

    b.def("match", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f || args.empty() || !ev::isString(args[0])) return ev::fromUtf8("none");
        std::string path = ev::toUtf8(args[0]);
        bool isDir = args.size() > 1 ? ev::toBool(args[1]) : false;
        auto m = f->match(path, isDir);
        if (m == bro::search::IgnoreMatch::Ignore) return ev::fromUtf8("ignore");
        if (m == bro::search::IgnoreMatch::Whitelist) return ev::fromUtf8("whitelist");
        return ev::fromUtf8("none");
    });

    b.accessor("ruleCount", [](Value self, std::span<const Value>) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::fromDouble(0);
        return ev::fromDouble(static_cast<double>(f->rule_count()));
    });

    b.accessor("caseInsensitive", [](Value self, std::span<const Value>) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::fromBool(false);
        return ev::fromBool(f->case_insensitive());
    });

    b.def("clear", 0, [](Value self, std::span<const Value>) -> Value {
        auto* f = unwrapGitignore(self);
        if (!f) return ev::throwTypeError("GitignoreMatcher: invalid receiver");
        f->clear();
        return self;
    });
}

void installWalk(ObjectBuilder& searchObj) {
    g_gitignoreClass.install("GitignoreMatcher", 2, js_Gitignore_ctor, decorateGitignore);
    g_gitignoreClass.alias("Gitignore");

    searchObj.def("files", 2, js_files);
    searchObj.def("filesSync", 2, js_filesSync);
    searchObj.set("GitignoreMatcher", g_gitignoreClass.constructor());
    searchObj.set("Gitignore", g_gitignoreClass.constructor());
}

} // namespace brosearch::api
