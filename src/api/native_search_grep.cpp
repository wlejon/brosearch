#include "host_search_internal.h"

#include <filesystem>
#include <system_error>

namespace brosearch::api {

HostClass g_regexClass;
HostClass g_cancellationTokenClass;

std::shared_ptr<bro::search::CancellationToken> unwrapToken(Value val) {
    if (!ev::isObject(val)) return nullptr;
    auto* sp = static_cast<std::shared_ptr<bro::search::CancellationToken>*>(g_cancellationTokenClass.unwrap(val));
    return (sp && *sp) ? *sp : nullptr;
}

static bro::search::GrepOptions parseGrepOptions(Value optVal) {
    bro::search::GrepOptions o;
    if (!ev::isObject(optVal)) return o;
    ev::Persistent opt(optVal);

    Value fxVal = ev::getProperty(opt.get(), "fixedStrings");
    if (!ev::isUndefined(fxVal)) o.fixed_strings = ev::toBool(fxVal);

    Value scVal = ev::getProperty(opt.get(), "smartCase");
    if (!ev::isUndefined(scVal) && ev::toBool(scVal)) {
        o.case_matching = bro::search::CaseMatching::Smart;
    } else {
        Value csVal = ev::getProperty(opt.get(), "caseSensitive");
        if (!ev::isUndefined(csVal)) {
            o.case_matching = ev::toBool(csVal) ? bro::search::CaseMatching::Sensitive
                                                : bro::search::CaseMatching::Insensitive;
        }
    }

    Value wVal = ev::getProperty(opt.get(), "word");
    if (!ev::isUndefined(wVal)) o.word = ev::toBool(wVal);

    Value wlVal = ev::getProperty(opt.get(), "wholeLine");
    if (!ev::isUndefined(wlVal)) o.whole_line = ev::toBool(wlVal);

    Value invVal = ev::getProperty(opt.get(), "invert");
    if (!ev::isUndefined(invVal)) o.invert = ev::toBool(invVal);

    Value mlVal = ev::getProperty(opt.get(), "multiline");
    if (!ev::isUndefined(mlVal)) o.multiline = ev::toBool(mlVal);

    Value mfsVal = ev::getProperty(opt.get(), "maxFilesize");
    if (ev::isNumber(mfsVal)) {
        double d = ev::toDouble(mfsVal);
        if (d > 0) o.max_filesize = static_cast<uint64_t>(d);
    }

    return o;
}

static bro::search::WalkOptions parseGrepWalkOptions(Value optVal) {
    bro::search::WalkOptions w;
    if (!ev::isObject(optVal)) return w;
    ev::Persistent opt(optVal);

    Value ignVal = ev::getProperty(opt.get(), "ignore");
    if (!ev::isUndefined(ignVal) && !ev::toBool(ignVal)) {
        w.git_ignore = false;
        w.ignore_files = false;
        w.git_exclude = false;
        w.git_global = false;
        w.parents = false;
        w.require_git = false;
    }
    Value rgVal = ev::getProperty(opt.get(), "requireGit");
    if (!ev::isUndefined(rgVal)) {
        w.require_git = ev::toBool(rgVal);
    }

    Value hidVal = ev::getProperty(opt.get(), "hidden");
    if (!ev::isUndefined(hidVal)) {
        w.hidden = ev::toBool(hidVal);
    }

    Value fpVal = ev::getProperty(opt.get(), "filePattern");
    if (ev::isString(fpVal)) {
        w.globs.push_back(ev::toUtf8(fpVal));
    } else if (ev::isObject(fpVal)) {
        Value lenVal = ev::getProperty(fpVal, "length");
        if (ev::isNumber(lenVal)) {
            uint32_t n = static_cast<uint32_t>(ev::toDouble(lenVal));
            for (uint32_t i = 0; i < n; ++i) {
                Value elem = ev::getElement(fpVal, i);
                if (ev::isString(elem)) w.globs.push_back(ev::toUtf8(elem));
            }
        }
    }

    Value globsVal = ev::getProperty(opt.get(), "globs");
    if (ev::isObject(globsVal)) {
        Value lenVal = ev::getProperty(globsVal, "length");
        if (ev::isNumber(lenVal)) {
            uint32_t n = static_cast<uint32_t>(ev::toDouble(lenVal));
            for (uint32_t i = 0; i < n; ++i) {
                Value elem = ev::getElement(globsVal, i);
                if (ev::isString(elem)) w.globs.push_back(ev::toUtf8(elem));
            }
        }
    }

    return w;
}

static void executeGrep(const std::filesystem::path& root,
                        std::shared_ptr<const bro::search::Grep> grep,
                        const bro::search::WalkOptions& walk_opts,
                        size_t max_results,
                        const bro::search::CancellationToken* token,
                        std::vector<AsyncJob::Hit>& out_hits,
                        const std::function<void(const AsyncJob::Hit&)>& on_hit = nullptr) {
    std::error_code ec;
    bool is_file = std::filesystem::is_regular_file(root, ec);
    std::mutex mu;

    if (is_file) {
        auto fr = grep->search_file(root, token);
        std::lock_guard<std::mutex> lk(mu);
        for (const auto& line : fr.lines) {
            if (line.kind != bro::search::LineKind::Match) continue;
            uint64_t col = 1;
            if (!line.spans.empty()) {
                col = line.spans[0].start + 1;
            }
            AsyncJob::Hit hit{root.string(), line.line_number, col, line.text};
            out_hits.push_back(hit);
            if (on_hit) on_hit(hit);
            if (max_results > 0 && out_hits.size() >= max_results) break;
        }
    } else {
        auto file_sink = [&](const bro::search::GrepFileResult& fr) -> bool {
            if (token && token->is_cancelled()) return false;
            std::lock_guard<std::mutex> lk(mu);
            for (const auto& line : fr.lines) {
                if (line.kind != bro::search::LineKind::Match) continue;
                uint64_t col = 1;
                if (!line.spans.empty()) {
                    col = line.spans[0].start + 1;
                }
                AsyncJob::Hit hit{fr.path, line.line_number, col, line.text};
                out_hits.push_back(hit);
                if (on_hit) on_hit(hit);
                if (max_results > 0 && out_hits.size() >= max_results) {
                    return false;
                }
            }
            return true;
        };

        grep->search_tree(root, walk_opts, file_sink, token, nullptr);
    }
}

static Value js_grepSync(Value, std::span<const Value> args) {
    if (args.size() < 2) return ev::makeArray(0);
    std::string rootStr = ev::isString(args[0]) ? ev::toUtf8(args[0]) : ".";
    std::string pattern = ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";

    Value optVal = args.size() > 2 ? args[2] : ev::undefined();
    ev::Persistent optP(optVal);

    bro::search::GrepOptions grep_opts = parseGrepOptions(optP.get());
    bro::search::WalkOptions walk_opts = parseGrepWalkOptions(optP.get());
    grep_opts.threads = 1;
    walk_opts.threads = 1;

    size_t max_results = 0;
    ev::Persistent onMatchFn;
    std::shared_ptr<bro::search::CancellationToken> cancel_tok;

    if (ev::isObject(optP.get())) {
        Value mrVal = ev::getProperty(optP.get(), "maxResults");
        if (ev::isNumber(mrVal)) {
            double d = ev::toDouble(mrVal);
            if (d > 0) max_results = static_cast<size_t>(d);
        }
        Value omVal = ev::getProperty(optP.get(), "onMatch");
        if (ev::isFunction(omVal)) onMatchFn.set(omVal);

        Value tokVal = ev::getProperty(optP.get(), "cancellationToken");
        if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        else {
            tokVal = ev::getProperty(optP.get(), "token");
            if (ev::isObject(tokVal)) cancel_tok = unwrapToken(tokVal);
        }
    }

    std::string compile_err;
    auto grep = bro::search::Grep::compile(pattern, grep_opts, &compile_err);
    if (!grep) {
        return ev::throwError("Grep compile error: " + compile_err);
    }

    std::vector<AsyncJob::Hit> hits;
    auto on_hit = [&](const AsyncJob::Hit& h) {
        if (ev::isFunction(onMatchFn.get())) {
            ObjectBuilder hb;
            hb.set("path", h.path);
            hb.set("line", static_cast<double>(h.line));
            hb.set("column", static_cast<double>(h.column));
            hb.set("text", h.text);
            const Value arg = hb.get();
            ev::call(onMatchFn.get(), ev::undefined(), std::span<const Value>(&arg, 1));
        }
    };

    executeGrep(std::filesystem::path(rootStr), grep, walk_opts, max_results,
                cancel_tok ? cancel_tok.get() : nullptr, hits, on_hit);

    ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(hits.size())));
    for (size_t i = 0; i < hits.size(); ++i) {
        const auto& h = hits[i];
        ObjectBuilder hb;
        hb.set("path", h.path);
        hb.set("line", static_cast<double>(h.line));
        hb.set("column", static_cast<double>(h.column));
        hb.set("text", h.text);
        resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), hb.get()));
    }
    return resArr.get();
}

static Value js_grep(Value, std::span<const Value> args) {
    if (args.size() < 2) {
        ev::Persistent p(ev::createPromise());
        ev::Persistent empty(ev::makeArray(0));
        ev::resolvePromise(p.get(), empty.get());
        return p.get();
    }

    std::string rootStr = ev::isString(args[0]) ? ev::toUtf8(args[0]) : ".";
    std::string pattern = ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";

    Value optVal = args.size() > 2 ? args[2] : ev::undefined();
    ev::Persistent optP(optVal);

    bro::search::GrepOptions grep_opts = parseGrepOptions(optP.get());
    bro::search::WalkOptions walk_opts = parseGrepWalkOptions(optP.get());

    size_t max_results = 0;
    ev::Persistent onMatchFn;
    std::shared_ptr<bro::search::CancellationToken> cancel_tok;

    if (ev::isObject(optP.get())) {
        Value mrVal = ev::getProperty(optP.get(), "maxResults");
        if (ev::isNumber(mrVal)) {
            double d = ev::toDouble(mrVal);
            if (d > 0) max_results = static_cast<size_t>(d);
        }
        Value omVal = ev::getProperty(optP.get(), "onMatch");
        if (ev::isFunction(omVal)) onMatchFn.set(omVal);

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
    job->is_grep = true;
    job->cancel_token = cancel_tok;
    job->promise.set(ev::createPromise());
    job->callback.set(onMatchFn.get());

    std::string compile_err;
    auto grep = bro::search::Grep::compile(pattern, grep_opts, &compile_err);
    if (!grep) {
        ev::Persistent err(makeError("Grep compile error: " + compile_err));
        ev::rejectPromise(job->promise.get(), err.get());
        return job->promise.get();
    }

    job->worker = std::thread([job, root = std::filesystem::path(rootStr), grep, walk_opts, max_results] {
        try {
            executeGrep(root, grep, walk_opts, max_results, job->cancel_token.get(), job->grep_result,
                        [&](const AsyncJob::Hit& h) {
                            std::lock_guard<std::mutex> lk(job->stream_grep_mu);
                            job->stream_grep.push_back(h);
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

static Value js_grepBuffer(Value, std::span<const Value> args) {
    if (args.size() < 2) return ev::makeArray(0);
    std::string buffer = ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
    std::string pattern = ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";

    Value optVal = args.size() > 2 ? args[2] : ev::undefined();
    bro::search::GrepOptions grep_opts = parseGrepOptions(optVal);

    std::string compile_err;
    auto grep = bro::search::Grep::compile(pattern, grep_opts, &compile_err);
    if (!grep) {
        return ev::throwError("Grep compile error: " + compile_err);
    }

    auto lines = grep->search_buffer(buffer);

    ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(lines.size())));
    for (size_t i = 0; i < lines.size(); ++i) {
        const auto& line = lines[i];
        ObjectBuilder hb;
        uint64_t col = 1;
        if (!line.spans.empty()) col = line.spans[0].start + 1;
        hb.set("line", static_cast<double>(line.line_number));
        hb.set("column", static_cast<double>(col));
        hb.set("text", line.text);
        resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), hb.get()));
    }
    return resArr.get();
}

// --- Regex ---

static std::shared_ptr<const bro::search::Regex>* unwrapRegex(Value self) {
    return static_cast<std::shared_ptr<const bro::search::Regex>*>(g_regexClass.unwrap(self));
}

static bro::search::RegexOptions parseRegexOptions(Value optVal) {
    bro::search::RegexOptions o;
    if (!ev::isObject(optVal)) return o;
    ev::Persistent opt(optVal);

    Value ci = ev::getProperty(opt.get(), "caseInsensitive");
    if (!ev::isUndefined(ci)) o.case_insensitive = ev::toBool(ci);

    Value sc = ev::getProperty(opt.get(), "smartCase");
    if (!ev::isUndefined(sc)) o.smart_case = ev::toBool(sc);

    Value ml = ev::getProperty(opt.get(), "multiline");
    if (!ev::isUndefined(ml)) o.multi_line = ev::toBool(ml);

    Value dot = ev::getProperty(opt.get(), "dotMatchesNewline");
    if (!ev::isUndefined(dot)) o.dot_matches_new_line = ev::toBool(dot);

    Value lit = ev::getProperty(opt.get(), "literal");
    if (!ev::isUndefined(lit)) o.literal = ev::toBool(lit);

    Value w = ev::getProperty(opt.get(), "word");
    if (!ev::isUndefined(w)) o.word = ev::toBool(w);

    Value wl = ev::getProperty(opt.get(), "wholeLine");
    if (!ev::isUndefined(wl)) o.whole_line = ev::toBool(wl);

    return o;
}

static Value js_Regex_ctor(Value, std::span<const Value> args) {
    if (args.empty() || !ev::isString(args[0])) {
        return ev::throwTypeError("Regex: pattern string required");
    }
    std::string pattern = ev::toUtf8(args[0]);
    bro::search::RegexOptions opts = args.size() > 1 ? parseRegexOptions(args[1]) : bro::search::RegexOptions();

    std::string err;
    auto rx = bro::search::Regex::compile(pattern, opts, &err);
    if (!rx) {
        return ev::throwError("Regex compile error: " + err);
    }

    return g_regexClass.createInstance(std::make_unique<std::shared_ptr<const bro::search::Regex>>(std::move(rx)));
}

static void decorateRegex(ObjectBuilder& b) {
    b.def("test", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::throwTypeError("Regex: invalid receiver");
        std::string haystack = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
        return ev::fromBool((*rxPtr)->is_match(haystack));
    });

    b.def("isMatch", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::throwTypeError("Regex: invalid receiver");
        std::string haystack = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
        return ev::fromBool((*rxPtr)->is_match(haystack));
    });

    b.def("exec", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::throwTypeError("Regex: invalid receiver");
        std::string haystack = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
        size_t start = args.size() > 1 ? static_cast<size_t>(ev::toDouble(args[1])) : 0;

        auto match = (*rxPtr)->find(haystack, start);
        if (!match) return ev::null();

        ObjectBuilder mb;
        mb.set("start", static_cast<double>(match->start));
        mb.set("end", static_cast<double>(match->end));
        mb.set("match", haystack.substr(match->start, match->end - match->start));
        return mb.get();
    });

    b.def("find", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::throwTypeError("Regex: invalid receiver");
        std::string haystack = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
        size_t start = args.size() > 1 ? static_cast<size_t>(ev::toDouble(args[1])) : 0;

        auto match = (*rxPtr)->find(haystack, start);
        if (!match) return ev::null();

        ObjectBuilder mb;
        mb.set("start", static_cast<double>(match->start));
        mb.set("end", static_cast<double>(match->end));
        mb.set("match", haystack.substr(match->start, match->end - match->start));
        return mb.get();
    });

    b.def("findAll", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::throwTypeError("Regex: invalid receiver");
        std::string haystack = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";

        auto matches = (*rxPtr)->find_all(haystack);
        ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(matches.size())));
        for (size_t i = 0; i < matches.size(); ++i) {
            const auto& m = matches[i];
            ObjectBuilder mb;
            mb.set("start", static_cast<double>(m.start));
            mb.set("end", static_cast<double>(m.end));
            mb.set("match", haystack.substr(m.start, m.end - m.start));
            resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), mb.get()));
        }
        return resArr.get();
    });

    b.accessor("pattern", [](Value self, std::span<const Value>) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::undefined();
        return ev::fromUtf8((*rxPtr)->pattern());
    });

    b.accessor("caseInsensitive", [](Value self, std::span<const Value>) -> Value {
        auto* rxPtr = unwrapRegex(self);
        if (!rxPtr || !*rxPtr) return ev::fromBool(false);
        return ev::fromBool((*rxPtr)->case_insensitive());
    });
}

static Value js_regex(Value, std::span<const Value> args) {
    if (args.empty() || !ev::isString(args[0])) {
        return ev::throwTypeError("bro.search.regex: pattern string required");
    }
    std::string pattern = ev::toUtf8(args[0]);
    bro::search::RegexOptions opts = args.size() > 1 ? parseRegexOptions(args[1]) : bro::search::RegexOptions();

    std::string err;
    auto rx = bro::search::Regex::compile(pattern, opts, &err);
    if (!rx) {
        return ev::throwError("Regex compile error: " + err);
    }
    return g_regexClass.createInstance(std::make_unique<std::shared_ptr<const bro::search::Regex>>(std::move(rx)));
}

// --- CancellationToken ---

static std::shared_ptr<bro::search::CancellationToken>* unwrapCancellationToken(Value self) {
    return static_cast<std::shared_ptr<bro::search::CancellationToken>*>(g_cancellationTokenClass.unwrap(self));
}

static Value js_CancellationToken_ctor(Value, std::span<const Value>) {
    auto tok = std::make_shared<bro::search::CancellationToken>();
    return g_cancellationTokenClass.createInstance(
        std::make_unique<std::shared_ptr<bro::search::CancellationToken>>(std::move(tok)));
}

static void decorateCancellationToken(ObjectBuilder& b) {
    b.def("cancel", 0, [](Value self, std::span<const Value>) -> Value {
        auto* sp = unwrapCancellationToken(self);
        if (!sp || !*sp) return ev::throwTypeError("CancellationToken: invalid receiver");
        (*sp)->cancel();
        return self;
    });

    b.accessor("isCancelled", [](Value self, std::span<const Value>) -> Value {
        auto* sp = unwrapCancellationToken(self);
        if (!sp || !*sp) return ev::fromBool(false);
        return ev::fromBool((*sp)->is_cancelled());
    });

    b.def("reset", 0, [](Value self, std::span<const Value>) -> Value {
        auto* sp = unwrapCancellationToken(self);
        if (!sp || !*sp) return ev::throwTypeError("CancellationToken: invalid receiver");
        (*sp)->reset();
        return self;
    });
}

void installGrep(ObjectBuilder& searchObj) {
    g_regexClass.install("Regex", 2, js_Regex_ctor, decorateRegex);
    g_cancellationTokenClass.install("CancellationToken", 0, js_CancellationToken_ctor, decorateCancellationToken);

    searchObj.def("grep", 3, js_grep);
    searchObj.def("grepSync", 3, js_grepSync);
    searchObj.def("grepBuffer", 3, js_grepBuffer);
    searchObj.def("regex", 2, js_regex);
    searchObj.set("Regex", g_regexClass.constructor());
    searchObj.set("CancellationToken", g_cancellationTokenClass.constructor());
}

} // namespace brosearch::api
