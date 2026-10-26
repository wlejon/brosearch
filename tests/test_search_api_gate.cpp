// bro.search under a path gate (api.h, "Path gate"): a walk or a grep asks the
// gate for its root, a refusal is an Error carrying the gate's sentence, code
// EACCES and the path, and with the gate removed everything behaves as before.
// Run from test_search_api.cpp's main against its realm and its temp tree.

#include "../src/api/api.h"
#include "embed/embed.h"
#include "eval/eval.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace fs = std::filesystem;
namespace ev = bronze::embed;

#define GCHECK(cond, msg)                                                      \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << "): " << (msg) << std::endl;              \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

std::string u8(const fs::path& p) {
    std::u8string s = p.u8string();
    return std::string(s.begin(), s.end());
}

// The path as JS passes it (forward slashes) and as the gate is handed it.
std::string jsPath(const fs::path& p) { return p.generic_string(); }
std::string gatePath(const fs::path& p) {
    return u8(fs::absolute(fs::path(jsPath(p))).lexically_normal());
}
std::string q(const fs::path& p) { return "'" + jsPath(p) + "'"; }

std::string refusal(const fs::path& p) {
    std::string path = gatePath(p);
    return "denied|no files access: " + path + "|EACCES|" + path;
}

std::string evalString(const std::string& src) {
    auto r = bronze::eval::evalScript(src);
    if (r.thrown) return "<thrown>";
    return ev::isString(r.value) ? ev::toUtf8(r.value) : "<not a string>";
}

// Runs `stmt` synchronously, its value `v`; "ok:<v>" or the refusal string.
std::string syncJs(const std::string& expr) {
    return evalString("(function() { try { const v = " + expr + "; return 'ok:' + String(v); }\n"
                      "  catch (e) { return 'denied|' + e.message + '|' + e.code + '|' + e.path; } })()");
}

// Runs `expr` (a promise) to completion; "ok:<value>" or the refusal string.
std::string awaitJs(const std::string& expr) {
    bronze::eval::evalScript("globalThis._gateOut = undefined;\n"
                             "Promise.resolve().then(() => " + expr + ").then(\n"
                             "  v => 'ok:' + String(v),\n"
                             "  e => 'denied|' + e.message + '|' + e.code + '|' + e.path)\n"
                             ".then(s => { globalThis._gateOut = s; });");
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
        brosearch::api::tickSearchAsync();
        ev::drainMicrotasks();
        std::string s = evalString("typeof globalThis._gateOut === 'string' ? globalThis._gateOut : ''");
        if (!s.empty()) return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return "<timeout>";
}

} // namespace

void runPathGateTests(const fs::path& tmp) {
    std::cout << "Testing the path gate..." << std::endl;

    // tmp holds src/alpha.cpp, src/beta.cpp, docs/readme.md, docs/notes.txt.
    const fs::path src = tmp / "src";
    const fs::path docs = tmp / "docs";
    const std::string docsPrefix = gatePath(docs);

    std::atomic<int> calls{0};
    brosearch::api::setPathGate([&](const std::string& path, brosearch::api::PathAccess access) -> std::string {
        ++calls;
        if (access != brosearch::api::PathAccess::Read) return "unexpected write: " + path;
        if (path.compare(0, docsPrefix.size(), docsPrefix) == 0) return "no files access: " + path;
        return "";
    });

    std::string r;
    r = syncJs("bro.search.filesSync(" + q(docs) + ").length");
    GCHECK(r == refusal(docs), r);
    r = syncJs("bro.search.filesSync(" + q(src) + ").length");
    GCHECK(r == "ok:2", r);
    r = awaitJs("bro.search.files(" + q(docs) + ")");
    GCHECK(r == refusal(docs), r);
    r = awaitJs("bro.search.files(" + q(src) + ").then(f => f.length)");
    GCHECK(r == "ok:2", r);

    r = syncJs("bro.search.grepSync(" + q(docs) + ", 'Hello').length");
    GCHECK(r == refusal(docs), r);
    r = syncJs("bro.search.grepSync(" + q(docs / "readme.md") + ", 'Hello').length");
    GCHECK(r == refusal(docs / "readme.md"), r);
    r = syncJs("bro.search.grepSync(" + q(src) + ", 'return').length");
    GCHECK(r == "ok:2", r);
    r = awaitJs("bro.search.grep(" + q(docs / "readme.md") + ", 'Hello')");
    GCHECK(r == refusal(docs / "readme.md"), r);
    r = awaitJs("bro.search.grep(" + q(src) + ", 'return').then(h => h.length)");
    GCHECK(r == "ok:2", r);

    r = syncJs("new bro.search.GitignoreMatcher(" + q(docs) + ")");
    GCHECK(r == refusal(docs), r);
    r = syncJs("new bro.search.GitignoreMatcher(" + q(src) + ").loadFile(" + q(docs / "notes.txt") + ")");
    GCHECK(r == refusal(docs / "notes.txt"), r);
    r = syncJs("new bro.search.GitignoreMatcher(" + q(src) + ").isIgnored('a.log', false)");
    GCHECK(r == "ok:false", r);

    // With the gate removed, nothing asks and everything works as before.
    brosearch::api::setPathGate(nullptr);
    const int before = calls.load();
    r = syncJs("bro.search.filesSync(" + q(docs) + ").length");
    GCHECK(r == "ok:2", r);
    r = awaitJs("bro.search.grep(" + q(docs / "readme.md") + ", 'Hello').then(h => h.length)");
    GCHECK(r == "ok:1", r);
    GCHECK(calls.load() == before, "a removed gate was still asked");

    std::cout << "  path gate [PASS]" << std::endl;
}
