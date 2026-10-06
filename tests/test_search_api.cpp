#include "../src/api/api.h"
#include "embed/embed.h"
#include "eval/eval.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":" << __LINE__ << ")" \
                      << std::endl;                                                     \
            std::exit(1);                                                               \
        }                                                                               \
    } while (0)

#define CHECK_EQ(a, b)                                                                  \
    do {                                                                                \
        if ((a) != (b)) {                                                               \
            std::cerr << "CHECK_EQ failed: " #a " != " #b " (" << (a) << " != " << (b)  \
                      << ") at " << __FILE__ << ":" << __LINE__ << std::endl;           \
            std::exit(1);                                                               \
        }                                                                               \
    } while (0)

namespace ev = bronze::embed;
using namespace bronze::eval;
using bronze::Value;


static void write_file(const std::filesystem::path& p, const std::string& content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << content;
}

static void pumpAsync(int maxTicks = 100) {
    for (int i = 0; i < maxTicks; ++i) {
        brosearch::api::tickSearchAsync();
        ev::drainMicrotasks();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

int main() {
    std::cout << "Starting brosearch JavaScript API tests..." << std::endl;

    // 1. Install bro.search into the active Bronze realm
    brosearch::api::installSearch();

    auto g = ev::globalValue("bro");
    CHECK(g.found);
    CHECK(ev::isObject(g.value));

    ev::Persistent searchP(ev::getProperty(g.value, "search"));
    CHECK(ev::isObject(searchP.get()));
    std::cout << "  Mounted bro.search successfully." << std::endl;

    // Verify all functions and classes exist on bro.search
    const char* methods[] = {
        "fuzzy", "fuzzyMatch", "FuzzyIndex",
        "files", "filesSync", "GitignoreMatcher", "Gitignore",
        "grep", "grepSync", "grepBuffer", "regex", "Regex",
        "CancellationToken", "tick", "version"
    };
    for (const char* m : methods) {
        Value prop = ev::getProperty(searchP.get(), m);
        CHECK(!ev::isUndefined(prop));
        std::cout << "  Found bro.search." << m << std::endl;
    }

    // 2. Test fuzzy matching
    {
        std::cout << "Testing bro.search.fuzzy..." << std::endl;
        const char* script = R"JS(
            (function() {
                const candidates = ["apple", "application", "banana", "pineapple", "apricot", "grape"];
                const res = bro.search.fuzzy("app", candidates);
                if (!Array.isArray(res)) throw new Error("not array");
                if (res.length < 3) throw new Error("expected >= 3 matches, got " + res.length);
                if (res[0].item !== "apple" && res[0].item !== "application") {
                    throw new Error("unexpected top match: " + res[0].item);
                }
                if (typeof res[0].score !== "number" || res[0].score <= 0) {
                    throw new Error("invalid score: " + res[0].score);
                }
                if (!Array.isArray(res[0].positions) || res[0].positions.length !== 3) {
                    throw new Error("invalid positions: " + JSON.stringify(res[0].positions));
                }

                // Object candidates with key option
                const objects = [
                    { id: 1, name: "Fix search indexing" },
                    { id: 2, name: "Add unit tests" },
                    { id: 3, name: "Refactor fuzzy search" }
                ];
                const resObj = bro.search.fuzzy("search", objects, { key: "name" });
                if (resObj.length !== 2) throw new Error("expected 2 matches, got " + resObj.length);
                if (resObj[0].item.id !== 1 && resObj[0].item.id !== 3) {
                    throw new Error("unexpected item in object match");
                }

                // Function key selector
                const resFn = bro.search.fuzzy("unit", objects, { key: (x) => x.name });
                if (resFn.length !== 1 || resFn[0].item.id !== 2) {
                    throw new Error("function key selector failed");
                }

                // Limit option
                const resLim = bro.search.fuzzy("app", candidates, { limit: 2 });
                if (resLim.length !== 2) throw new Error("limit failed");

                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "Fuzzy test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 3. Test fuzzyMatch
    {
        std::cout << "Testing bro.search.fuzzyMatch..." << std::endl;
        const char* script = R"JS(
            (function() {
                const m1 = bro.search.fuzzyMatch("cat", "concatenate");
                if (!m1) throw new Error("expected match");
                if (typeof m1.score !== "number" || m1.score <= 0) throw new Error("invalid score");
                if (!Array.isArray(m1.positions) || m1.positions.length !== 3) throw new Error("bad positions");

                const m2 = bro.search.fuzzyMatch("xyz", "hello world");
                if (m2 !== null) throw new Error("expected null for non-match");
                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "fuzzyMatch test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 4. Test FuzzyIndex
    {
        std::cout << "Testing bro.search.FuzzyIndex..." << std::endl;
        const char* script = R"JS(
            (function() {
                const idx = new bro.search.FuzzyIndex(["file1.txt", "file2.js", "README.md"]);
                if (idx.size !== 3) throw new Error("expected size 3, got " + idx.size);
                if (idx.item(0) !== "file1.txt") throw new Error("item(0) mismatch");

                idx.add("main.cpp");
                if (idx.size !== 4) throw new Error("expected size 4");

                idx.add(["parser.rs", "lexer.go"]);
                if (idx.size !== 6) throw new Error("expected size 6");

                const hits = idx.search("file");
                if (hits.length < 2) throw new Error("expected >= 2 matches, got " + hits.length);
                if (hits[0].item.indexOf("file") < 0) throw new Error("top match mismatch: " + hits[0].item);
                if (typeof hits[0].score !== "number" || hits[0].score <= 0) throw new Error("bad score");

                idx.clear();
                if (idx.size !== 0) throw new Error("expected size 0 after clear");
                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "FuzzyIndex test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 5. Test Regex
    {
        std::cout << "Testing bro.search.regex..." << std::endl;
        const char* script = R"JS(
            (function() {
                const rx = bro.search.regex("(\\w+)-(\\d+)", { caseInsensitive: true });
                if (rx.pattern !== "(\\w+)-(\\d+)") throw new Error("bad pattern");
                if (!rx.caseInsensitive) throw new Error("expected caseInsensitive");

                if (!rx.test("item-123")) throw new Error("test failed");
                if (rx.test("item-abc")) throw new Error("test should fail");

                const m = rx.find("prefix item-456 suffix");
                if (!m) throw new Error("find failed");
                if (m.start !== 7 || m.end !== 15 || m.match !== "item-456") {
                    throw new Error("find mismatch: " + JSON.stringify(m));
                }

                const all = rx.findAll("a-1 b-2 c-3");
                if (all.length !== 3) throw new Error("findAll expected 3, got " + all.length);
                if (all[0].match !== "a-1" || all[1].match !== "b-2" || all[2].match !== "c-3") {
                    throw new Error("findAll matches mismatch");
                }

                let threw = false;
                try {
                    bro.search.regex("[unclosed");
                } catch (e) {
                    threw = true;
                }
                if (!threw) throw new Error("invalid regex should throw");

                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "Regex test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 6. Test GitignoreMatcher
    {
        std::cout << "Testing bro.search.GitignoreMatcher..." << std::endl;
        const char* script = R"JS(
            (function() {
                const gm = new bro.search.GitignoreMatcher();
                gm.add("*.log");
                gm.add("build/");
                gm.add("!important.log");

                if (gm.ruleCount < 3) throw new Error("ruleCount mismatch");

                if (!gm.isIgnored("debug.log")) throw new Error("debug.log should be ignored");
                if (gm.isIgnored("important.log")) throw new Error("important.log should not be ignored");
                if (gm.isIgnored("main.cpp")) throw new Error("main.cpp should not be ignored");
                if (!gm.isIgnored("build", true)) throw new Error("build dir should be ignored");

                if (gm.match("debug.log") !== "ignore") throw new Error("match debug.log failed");
                if (gm.match("important.log") !== "whitelist") throw new Error("match important.log failed");
                if (gm.match("main.cpp") !== "none") throw new Error("match main.cpp failed");

                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "GitignoreMatcher test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 7. Test CancellationToken
    {
        std::cout << "Testing bro.search.CancellationToken..." << std::endl;
        const char* script = R"JS(
            (function() {
                const tok = new bro.search.CancellationToken();
                if (tok.isCancelled !== false) throw new Error("should not be cancelled");
                tok.cancel();
                if (tok.isCancelled !== true) throw new Error("should be cancelled");
                tok.reset();
                if (tok.isCancelled !== false) throw new Error("should be reset");
                return "OK";
            })()
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "CancellationToken test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 8. Create temporary fixture directory for file walking & grep
    auto tmp_dir = std::filesystem::temp_directory_path() /
                   ("brosearch_api_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(tmp_dir);
    std::filesystem::create_directories(tmp_dir / ".git");

    write_file(tmp_dir / "src" / "alpha.cpp", "int alpha() {\n    return 42;\n}\n");
    write_file(tmp_dir / "src" / "beta.cpp", "int beta() {\n    return 100;\n}\n");
    write_file(tmp_dir / "docs" / "readme.md", "# Documentation\nHello world from search test.\n");
    write_file(tmp_dir / "docs" / "notes.txt", "Note: alpha and beta functions are tested.\n");
    write_file(tmp_dir / "build.log", "Build completed with 0 errors.\n");
    write_file(tmp_dir / ".hidden.txt", "hidden file content\n");
    write_file(tmp_dir / ".gitignore", "*.log\n.hidden*\n");

    std::string tmp_str = tmp_dir.string();

    // 9. Test filesSync
    {
        std::cout << "Testing bro.search.filesSync..." << std::endl;
        std::string script = R"JS(
            (function(root) {
                // Default options: honours .gitignore, skips hidden files
                const files = bro.search.filesSync(root);
                if (!Array.isArray(files)) throw new Error("filesSync should return array");

                let hasAlpha = false, hasReadme = false, hasLog = false, hasHidden = false;
                for (const f of files) {
                    if (f.indexOf("alpha.cpp") >= 0) hasAlpha = true;
                    if (f.indexOf("readme.md") >= 0) hasReadme = true;
                    if (f.indexOf("build.log") >= 0) hasLog = true;
                    if (f.indexOf(".hidden") >= 0) hasHidden = true;
                }
                if (!hasAlpha || !hasReadme) throw new Error("expected alpha and readme: " + JSON.stringify(files));
                if (hasLog) throw new Error(".log should be ignored by .gitignore");
                if (hasHidden) throw new Error("hidden file should be skipped by default");

                // With ignore: false, build.log should appear
                const allFiles = bro.search.filesSync(root, { ignore: false });
                let foundLog = false;
                for (const f of allFiles) {
                    if (f.indexOf("build.log") >= 0) foundLog = true;
                }
                if (!foundLog) throw new Error("build.log should appear with ignore: false");

                // With query option: fuzzy ranks matching files
                const cppFiles = bro.search.filesSync(root, { query: "cpp" });
                if (cppFiles.length !== 2) throw new Error("expected 2 cpp files, got " + cppFiles.length);

                // Callback option
                const cbList = [];
                bro.search.filesSync(root, { onFile: (p) => cbList.push(p) });
                if (cbList.length !== files.length) throw new Error("onFile callback count mismatch");

                return "OK";
            })(")JS" + tmp_str + R"JS(")
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "filesSync test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 10. Test files (async Promise)
    {
        std::cout << "Testing bro.search.files (Promise)..." << std::endl;
        std::string launch = R"JS(
            (function(root) {
                globalThis.__async_files = { done: false, result: null, error: null };
                const p = bro.search.files(root);
                p.then(
                    (res) => { globalThis.__async_files.done = true; globalThis.__async_files.result = res; },
                    (err) => { globalThis.__async_files.done = true; globalThis.__async_files.error = String(err); }
                );
                return "LAUNCHED";
            })(")JS" + tmp_str + R"JS(")
        )JS";
        auto res = evalScript(launch);
        CHECK(!res.thrown);

        pumpAsync(100);

        const char* checkScript = R"JS(
            (function() {
                const s = globalThis.__async_files;
                if (!s.done) return "WAIT";
                if (s.error) throw new Error("async files rejected: " + s.error);
                if (!Array.isArray(s.result) || s.result.length === 0) {
                    throw new Error("async files result empty or not array");
                }
                return "OK";
            })()
        )JS";
        res = evalScript(checkScript);
        if (res.thrown) {
            std::cerr << "async files check failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 11. Test grepSync and grepBuffer
    {
        std::cout << "Testing bro.search.grepSync and grepBuffer..." << std::endl;
        std::string script = R"JS(
            (function(root) {
                // Test grepBuffer
                const buf = "Line 1: hello\nLine 2: world\nLine 3: hello again\nLine 4: end";
                const bHits = bro.search.grepBuffer(buf, "hello");
                if (bHits.length !== 2) throw new Error("grepBuffer expected 2 hits, got " + bHits.length);
                if (bHits[0].line !== 1 || bHits[1].line !== 3) throw new Error("grepBuffer lines mismatch");

                // Test grepSync in directory
                const hits = bro.search.grepSync(root, "return \\d+");
                if (hits.length !== 2) throw new Error("grepSync expected 2 hits, got " + hits.length);

                for (const h of hits) {
                    if (typeof h.path !== "string" || typeof h.line !== "number" ||
                        typeof h.column !== "number" || typeof h.text !== "string") {
                        throw new Error("hit shape mismatch: " + JSON.stringify(h));
                    }
                }

                // Streaming callback
                const streamHits = [];
                bro.search.grepSync(root, "alpha", { onMatch: (h) => streamHits.push(h) });
                if (streamHits.length < 1) throw new Error("streamHits expected >= 1 hit");

                return "OK";
            })(")JS" + tmp_str + R"JS(")
        )JS";
        auto res = evalScript(script);
        if (res.thrown) {
            std::cerr << "grepSync test failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // 12. Test grep (async Promise)
    {
        std::cout << "Testing bro.search.grep (Promise)..." << std::endl;
        std::string launch = R"JS(
            (function(root) {
                globalThis.__async_grep = { done: false, result: null, error: null };
                const p = bro.search.grep(root, "return");
                p.then(
                    (res) => { globalThis.__async_grep.done = true; globalThis.__async_grep.result = res; },
                    (err) => { globalThis.__async_grep.done = true; globalThis.__async_grep.error = String(err); }
                );
                return "LAUNCHED";
            })(")JS" + tmp_str + R"JS(")
        )JS";
        auto res = evalScript(launch);
        CHECK(!res.thrown);

        pumpAsync(100);

        const char* checkScript = R"JS(
            (function() {
                const s = globalThis.__async_grep;
                if (!s.done) return "WAIT";
                if (s.error) throw new Error("async grep rejected: " + s.error);
                if (!Array.isArray(s.result) || s.result.length !== 2) {
                    throw new Error("async grep expected 2 results, got " + JSON.stringify(s.result));
                }
                return "OK";
            })()
        )JS";
        res = evalScript(checkScript);
        if (res.thrown) {
            std::cerr << "async grep check failed: " << ev::toUtf8(res.value) << std::endl;
            std::exit(1);
        }
        CHECK_EQ(ev::toUtf8(res.value), "OK");
    }

    // Cleanup temp directory
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);

    // Shutdown async tasks
    brosearch::api::shutdownSearchAsync();

    std::cout << "All brosearch JavaScript API tests passed successfully!" << std::endl;
    return 0;
}
