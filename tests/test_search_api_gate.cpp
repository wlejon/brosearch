// bro.search under the host's access gate (embed/embed_access.h; api.h,
// "Access"): a walk or a grep asks the gate for its root, a refusal is an Error carrying the gate's sentence, code
// EACCES and the path, and with the gate removed everything behaves as before.
// Run from test_search_api.cpp's main against its realm and its temp tree.

#include "../src/api/api.h"
#include "embed/embed.h"
#include "embed/embed_access.h"
#include "eval/eval.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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
    ev::setAccessGate([&](const ev::AccessRequest& r) -> std::string {
        ++calls;
        const std::string path(r.subject);
        if (r.kind != ev::AccessKind::Read) return "unexpected access: " + path;
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
    ev::setAccessGate(nullptr);
    const int before = calls.load();
    r = syncJs("bro.search.filesSync(" + q(docs) + ").length");
    GCHECK(r == "ok:2", r);
    r = awaitJs("bro.search.grep(" + q(docs / "readme.md") + ", 'Hello').then(h => h.length)");
    GCHECK(r == "ok:1", r);
    GCHECK(calls.load() == before, "a removed gate was still asked");

    std::cout << "  path gate [PASS]" << std::endl;
}

// A walk or grep started with files() or grep() keeps reading after the call
// returns, so it is held in the gate's ledger while it runs; when the host
// takes the grant back it is cancelled, streams nothing more, and its promise
// rejects with an Error named PermissionRevoked. One whose grant is kept
// finishes.
void runRevokeTests(const fs::path& tmp) {
    std::cout << "Testing revocation of running walks..." << std::endl;

    const fs::path big = tmp / "revoke_big";
    const fs::path kept = tmp / "src";
    for (int d = 0; d < 40; ++d) {
        fs::create_directories(big / ("d" + std::to_string(d)));
        for (int f = 0; f < 100; ++f) {
            std::ofstream(big / ("d" + std::to_string(d)) / ("f" + std::to_string(f) + ".txt")) << "needle\n";
        }
    }
    const std::string bigPrefix = gatePath(big);
    std::atomic<bool> revoke{false};
    ev::setAccessGate([&](const ev::AccessRequest& r) -> std::string {
        const std::string path(r.subject);
        if (revoke.load() && path.compare(0, bigPrefix.size(), bigPrefix) == 0) {
            return std::string(ev::kPermissionRevokedPrefix) + "no files access: " + path;
        }
        return "";
    });

    const size_t heldBefore = ev::heldAccessCount();
    auto res = bronze::eval::evalScript(
        "globalThis._rv = { files: null, grep: null, kept: null, streamedAfter: 0, revoked: false };\n"
        "const out = (k) => [v => { _rv[k] = 'resolved:' + v.length; }, e => { _rv[k] = e; }];\n"
        "bro.search.files(" + q(big) + ", { onFile: () => { if (_rv.revoked) _rv.streamedAfter++; } })"
        ".then(...out('files'));\n"
        "bro.search.grep(" + q(big) + ", 'needle', { onMatch: () => { if (_rv.revoked) _rv.streamedAfter++; } })"
        ".then(...out('grep'));\n"
        "bro.search.files(" + q(kept) + ").then(...out('kept'));\n");
    GCHECK(!res.thrown, "starting the walks threw");
    GCHECK(ev::heldAccessCount() == heldBefore + 3,
           "three running jobs held: " + std::to_string(ev::heldAccessCount() - heldBefore));

    revoke.store(true);
    ev::accessChanged();
    const int revoked = ev::revalidateHeldAccess();
    bronze::eval::evalScript("_rv.revoked = true;");
    GCHECK(revoked == 2, "the two walks of the revoked folder: " + std::to_string(revoked));

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(20)) {
        brosearch::api::tickSearchAsync();
        ev::drainMicrotasks();
        if (evalString("_rv.files && _rv.grep && _rv.kept ? 'y' : 'n'") == "y") break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    auto described = [](const std::string& k) {
        return evalString("(function(e) { return e && typeof e === 'object' ? e.name + '|' + e.message + '|' + "
                          "e.code + '|' + e.path : String(e); })(_rv." + k + ")");
    };
    const std::string expect = "PermissionRevoked|no files access: " + bigPrefix + "|EACCES|" + bigPrefix;
    std::string got = described("files");
    GCHECK(got == expect, got);
    got = described("grep");
    GCHECK(got == expect, got);
    got = described("kept");
    GCHECK(got == "resolved:2", got);
    GCHECK(evalString("String(_rv.streamedAfter)") == "0", "a revoked walk streamed after the revocation");
    GCHECK(ev::heldAccessCount() == heldBefore, "settled jobs released: " + std::to_string(ev::heldAccessCount()));

    ev::setAccessGate(nullptr);
    std::error_code ec;
    fs::remove_all(big, ec);
    std::cout << "  revocation [PASS]" << std::endl;
}
