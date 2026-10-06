#include "host_search_internal.h"

namespace brosearch::api {

HostClass g_fuzzyIndexClass;

static bro::search::FuzzyOptions parseFuzzyOptions(Value optVal) {
    bro::search::FuzzyOptions opts;
    if (!ev::isObject(optVal)) return opts;
    ev::Persistent opt(optVal);

    Value caseVal = ev::getProperty(opt.get(), "case");
    if (ev::isString(caseVal)) {
        std::string s = ev::toUtf8(caseVal);
        if (s == "ignore") opts.case_mode = bro::search::FuzzyCase::Ignore;
        else if (s == "respect") opts.case_mode = bro::search::FuzzyCase::Respect;
        else if (s == "smart") opts.case_mode = bro::search::FuzzyCase::Smart;
    }
    Value csVal = ev::getProperty(opt.get(), "caseSensitive");
    if (!ev::isUndefined(csVal)) {
        opts.case_mode = ev::toBool(csVal) ? bro::search::FuzzyCase::Respect : bro::search::FuzzyCase::Ignore;
    }
    Value schemeVal = ev::getProperty(opt.get(), "scheme");
    if (ev::isString(schemeVal)) {
        std::string s = ev::toUtf8(schemeVal);
        if (s == "path") opts.scheme = bro::search::FuzzyScheme::Path;
        else if (s == "history") opts.scheme = bro::search::FuzzyScheme::History;
        else opts.scheme = bro::search::FuzzyScheme::Default;
    }
    Value extVal = ev::getProperty(opt.get(), "extended");
    if (!ev::isUndefined(extVal)) opts.extended = ev::toBool(extVal);
    Value exactVal = ev::getProperty(opt.get(), "exact");
    if (!ev::isUndefined(exactVal)) opts.exact = ev::toBool(exactVal);
    Value normVal = ev::getProperty(opt.get(), "normalize");
    if (!ev::isUndefined(normVal)) opts.normalize = ev::toBool(normVal);
    Value algoVal = ev::getProperty(opt.get(), "algo");
    if (ev::isString(algoVal)) {
        opts.algo_v1 = (ev::toUtf8(algoVal) == "v1");
    }
    Value sortVal = ev::getProperty(opt.get(), "sort");
    if (!ev::isUndefined(sortVal)) opts.sort = ev::toBool(sortVal);
    Value tacVal = ev::getProperty(opt.get(), "tac");
    if (!ev::isUndefined(tacVal)) opts.tac = ev::toBool(tacVal);
    Value nthVal = ev::getProperty(opt.get(), "nth");
    if (ev::isString(nthVal)) {
        bro::search::parse_fuzzy_nth(ev::toUtf8(nthVal), opts.nth);
    }
    Value delimVal = ev::getProperty(opt.get(), "delimiter");
    if (ev::isString(delimVal)) {
        opts.delimiter = ev::toUtf8(delimVal);
    }
    return opts;
}

static Value js_fuzzy(Value, std::span<const Value> args) {
    if (args.empty()) return ev::makeArray(0);
    std::string query = ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";

    if (args.size() < 2 || !ev::isObject(args[1])) {
        return ev::makeArray(0);
    }
    ev::Persistent candP(args[1]);

    Value optVal = args.size() > 2 ? args[2] : ev::undefined();
    ev::Persistent optP(optVal);
    bro::search::FuzzyOptions opts = parseFuzzyOptions(optP.get());

    size_t limit = 0;
    bool withPositions = true;
    std::string keyProp;
    ev::Persistent keyFn;

    if (ev::isObject(optP.get())) {
        Value limVal = ev::getProperty(optP.get(), "limit");
        if (ev::isNumber(limVal)) {
            double d = ev::toDouble(limVal);
            if (d > 0) limit = static_cast<size_t>(d);
        }
        Value posVal = ev::getProperty(optP.get(), "withPositions");
        if (!ev::isUndefined(posVal)) {
            withPositions = ev::toBool(posVal);
        }
        Value kVal = ev::getProperty(optP.get(), "key");
        if (ev::isString(kVal)) {
            keyProp = ev::toUtf8(kVal);
        } else if (ev::isFunction(kVal)) {
            keyFn.set(kVal);
        }
    }

    Value lenVal = ev::getProperty(candP.get(), "length");
    if (!ev::isNumber(lenVal)) return ev::makeArray(0);
    uint32_t count = static_cast<uint32_t>(ev::toDouble(lenVal));

    std::vector<std::string> items;
    items.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        Value elem = ev::getElement(candP.get(), i);
        if (ev::isString(elem)) {
            items.push_back(ev::toUtf8(elem));
        } else if (ev::isObject(elem)) {
            if (!keyProp.empty()) {
                Value v = ev::getProperty(elem, keyProp);
                items.push_back(ev::isString(v) ? ev::toUtf8(v) : "");
            } else if (ev::isFunction(keyFn.get())) {
                const Value arg = elem;
                auto callRes = ev::call(keyFn.get(), candP.get(), std::span<const Value>(&arg, 1));
                items.push_back((!callRes.thrown && ev::isString(callRes.value)) ? ev::toUtf8(callRes.value) : "");
            } else {
                items.push_back(ev::toUtf8(elem));
            }
        } else {
            items.push_back(ev::toUtf8(elem));
        }
    }

    bro::search::FuzzyQuery fq(query, opts);
    auto results = bro::search::fuzzy_filter(fq, std::span<const std::string>(items), limit, withPositions);

    ev::Persistent outArr(ev::makeArray(static_cast<uint32_t>(results.size())));
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        ObjectBuilder mb;
        Value origItem = ev::getElement(candP.get(), r.index);
        mb.set("item", origItem);
        mb.set("score", static_cast<double>(r.score));
        mb.set("index", static_cast<double>(r.index));

        if (withPositions) {
            ev::Persistent posArr(ev::makeArray(static_cast<uint32_t>(r.positions.size())));
            for (size_t p = 0; p < r.positions.size(); ++p) {
                posArr.set(ev::setElement(posArr.get(), static_cast<uint32_t>(p), ev::fromDouble(r.positions[p])));
            }
            mb.set("positions", posArr.get());
        }

        outArr.set(ev::setElement(outArr.get(), static_cast<uint32_t>(i), mb.get()));
    }

    return outArr.get();
}

static Value js_fuzzyMatch(Value, std::span<const Value> args) {
    if (args.size() < 2) return ev::null();
    std::string query = ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";
    std::string item = ev::isString(args[1]) ? ev::toUtf8(args[1]) : "";
    bro::search::FuzzyOptions opts = args.size() > 2 ? parseFuzzyOptions(args[2]) : bro::search::FuzzyOptions();

    auto match = bro::search::fuzzy_match(query, item, opts);
    if (!match.has_value()) return ev::null();

    ObjectBuilder b;
    b.set("score", static_cast<double>(match->score));
    ev::Persistent posArr(ev::makeArray(static_cast<uint32_t>(match->positions.size())));
    for (size_t i = 0; i < match->positions.size(); ++i) {
        posArr.set(ev::setElement(posArr.get(), static_cast<uint32_t>(i), ev::fromDouble(match->positions[i])));
    }
    b.set("positions", posArr.get());
    return b.get();
}

// --- FuzzyIndex ---

static bro::search::FuzzyIndex* unwrapIndex(Value self) {
    return static_cast<bro::search::FuzzyIndex*>(g_fuzzyIndexClass.unwrap(self));
}

static Value js_FuzzyIndex_ctor(Value, std::span<const Value> args) {
    bro::search::FuzzyOptions opts;
    ev::Persistent itemsP;

    if (!args.empty()) {
        if (ev::isObject(args[0])) {
            Value lenVal = ev::getProperty(args[0], "length");
            if (ev::isNumber(lenVal)) {
                itemsP.set(args[0]);
                if (args.size() > 1 && ev::isObject(args[1])) {
                    opts = parseFuzzyOptions(args[1]);
                }
            } else {
                opts = parseFuzzyOptions(args[0]);
            }
        }
    }

    auto idx = std::make_unique<bro::search::FuzzyIndex>(opts);

    if (ev::isObject(itemsP.get())) {
        Value lenVal = ev::getProperty(itemsP.get(), "length");
        uint32_t n = static_cast<uint32_t>(ev::toDouble(lenVal));
        std::vector<std::string> items;
        items.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            Value elem = ev::getElement(itemsP.get(), i);
            items.push_back(ev::isString(elem) ? ev::toUtf8(elem) : "");
        }
        idx->add(std::span<const std::string>(items));
    }

    return g_fuzzyIndexClass.createInstance(std::move(idx));
}

static void decorateFuzzyIndex(ObjectBuilder& b) {
    b.def("add", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::throwTypeError("FuzzyIndex: invalid receiver");
        if (args.empty()) return self;

        if (ev::isString(args[0])) {
            idx->add(ev::toUtf8(args[0]));
        } else if (ev::isObject(args[0])) {
            ev::Persistent arr(args[0]);
            Value lenVal = ev::getProperty(arr.get(), "length");
            if (ev::isNumber(lenVal)) {
                uint32_t n = static_cast<uint32_t>(ev::toDouble(lenVal));
                std::vector<std::string> items;
                items.reserve(n);
                for (uint32_t i = 0; i < n; ++i) {
                    Value elem = ev::getElement(arr.get(), i);
                    items.push_back(ev::isString(elem) ? ev::toUtf8(elem) : "");
                }
                idx->add(std::span<const std::string>(items));
            }
        }
        return self;
    });

    b.def("search", 2, [](Value self, std::span<const Value> args) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::throwTypeError("FuzzyIndex: invalid receiver");
        std::string query = !args.empty() && ev::isString(args[0]) ? ev::toUtf8(args[0]) : "";

        size_t limit = 0;
        bool withPositions = true;
        if (args.size() > 1 && ev::isObject(args[1])) {
            ev::Persistent opt(args[1]);
            Value limVal = ev::getProperty(opt.get(), "limit");
            if (ev::isNumber(limVal)) {
                double d = ev::toDouble(limVal);
                if (d > 0) limit = static_cast<size_t>(d);
            }
            Value posVal = ev::getProperty(opt.get(), "withPositions");
            if (!ev::isUndefined(posVal)) {
                withPositions = ev::toBool(posVal);
            }
        }

        auto sr = idx->search(query, limit, withPositions);

        ev::Persistent outArr(ev::makeArray(static_cast<uint32_t>(sr.results.size())));
        for (size_t i = 0; i < sr.results.size(); ++i) {
            const auto& r = sr.results[i];
            ObjectBuilder mb;
            mb.set("item", std::string(idx->item(r.index)));
            mb.set("score", static_cast<double>(r.score));
            mb.set("index", static_cast<double>(r.index));

            if (withPositions) {
                ev::Persistent posArr(ev::makeArray(static_cast<uint32_t>(r.positions.size())));
                for (size_t p = 0; p < r.positions.size(); ++p) {
                    posArr.set(ev::setElement(posArr.get(), static_cast<uint32_t>(p), ev::fromDouble(r.positions[p])));
                }
                mb.set("positions", posArr.get());
            }

            outArr.set(ev::setElement(outArr.get(), static_cast<uint32_t>(i), mb.get()));
        }
        return outArr.get();
    });

    b.accessor("size", [](Value self, std::span<const Value>) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::fromDouble(0);
        return ev::fromDouble(static_cast<double>(idx->size()));
    });

    b.def("item", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx || args.empty()) return ev::undefined();
        uint32_t i = static_cast<uint32_t>(ev::toDouble(args[0]));
        if (i >= idx->size()) return ev::undefined();
        return ev::fromUtf8(idx->item(i));
    });

    b.def("clear", 0, [](Value self, std::span<const Value>) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::throwTypeError("FuzzyIndex: invalid receiver");
        idx->clear();
        return self;
    });

    b.def("clearCache", 0, [](Value self, std::span<const Value>) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::throwTypeError("FuzzyIndex: invalid receiver");
        idx->clear_cache();
        return self;
    });

    b.def("setCacheEnabled", 1, [](Value self, std::span<const Value> args) -> Value {
        auto* idx = unwrapIndex(self);
        if (!idx) return ev::throwTypeError("FuzzyIndex: invalid receiver");
        idx->set_cache_enabled(!args.empty() && ev::toBool(args[0]));
        return self;
    });
}

void installFuzzy(ObjectBuilder& searchObj) {
    g_fuzzyIndexClass.install("FuzzyIndex", 2, js_FuzzyIndex_ctor, decorateFuzzyIndex);

    searchObj.def("fuzzy", 3, js_fuzzy);
    searchObj.def("fuzzyMatch", 3, js_fuzzyMatch);
    searchObj.set("FuzzyIndex", g_fuzzyIndexClass.constructor());
}

} // namespace brosearch::api
