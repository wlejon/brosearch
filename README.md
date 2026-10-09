# brosearch

[![CI](https://github.com/wlejon/brosearch/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brosearch/actions/workflows/ci.yml)

The search layer for fuzzy matching, file finding, and content grep. It is a
standalone C++20 library requiring only the standard library and threads (no
external dependencies). Everything lives in namespace `bro::search`, behind the
umbrella header `<brosearch/search.h>`.

In the [Bro ecosystem](https://github.com/wlejon/bro/blob/main/docs/ecosystem.md),
brosearch sits in the terminal and engine layer:
- [bropty](https://github.com/wlejon/bropty) uses it for linear-time regex scrollback search;
- [brokeys](https://github.com/wlejon/brokeys) uses its automaton engine for regex `when` evaluation;
- [bro](https://github.com/wlejon/bro) links it under `BRO_WITH_TERMINAL` and `BRO_WITH_KEYS` to power launcher, file manager, and terminal search.

The bar is strict agreement with reference tools, validated by extensive differential suites:
- **fuzzy** = `fzf --filter`
- **finder** = `rg --files`, with `git ls-files` / `git check-ignore`
- **grep** = `rg`

## Platforms

Platform support is verified in continuous integration across GCC, Clang, and MSVC:

| Platform | Compiler | Path & Encoding Model | Case & Filesystem Semantics |
|----------|----------|-----------------------|------------------------------|
| **Linux** (x86-64, AArch64) | GCC 12+, Clang 16+ | Native UTF-8 POSIX paths | POSIX case-sensitive directory walking |
| **Windows** (x86-64) | MSVC 2022+ | UTF-8 converted to wide strings (`std::wstring` / Win32 APIs) | NTFS case-insensitive semantics; POSIX permission specs skipped |
| **macOS** (Apple Silicon, Intel) | Apple Clang | UTF-8 with optional `UTF-8-MAC` precomposition | Volume sensitivity via `pathconf(_PC_CASE_SENSITIVE)`; APFS skips non-UTF-8 names |

### Platform-specific filesystem behaviors

- **macOS Case Sensitivity**: Outside a git repository, `CaseMode::Auto` queries filesystem volume capabilities using `pathconf(_PC_CASE_SENSITIVE)`. Inside a repository, `core.ignorecase` governs.
- **macOS Precomposition**: When `Precompose::Auto` is set (the default), directory walking inside a repository with `core.precomposeUnicode=true` (standard on macOS) matches and reports NFD names in NFC via iconv `UTF-8-MAC` conversion, while `WalkEntry::native_path` preserves the filesystem's raw bytes.
- **APFS Encoding Skip**: APFS strictly rejects filenames containing invalid UTF-8 byte sequences. As a result, the `nonutf8_posix.spec` fixture test is skipped on APFS with the reason logged.
- **Windows File Semantics**: Specs relying on POSIX-only filename characters (colons, trailing spaces/dots) or POSIX file modes are skipped on Windows.

## Modules

| Header | What |
|--------|------|
| `fuzzy.h` | `FuzzyQuery` / `fuzzy_match` / `fuzzy_filter`: fzf's v2 algorithm (with v1 fallback for long items) and fzf's extended query syntax (`'exact ^prefix suffix$ !not a\|b`), with smart case, Latin diacritic folding and fzf's default, path and history scoring schemes. Ranking and tie-breaks match fzf. `--nth` / `--delimiter` field matching and `--tac` are supported, and `fuzzy_display` renders items as fzf prints them (invalid UTF-8 as U+FFFD). Batch filtering is multithreaded and cancellable. |
| `fuzzy_index.h` | `FuzzyIndex`: an append-only item store for incremental and streaming use. Searches run concurrently with `add()`, and a refined query only re-scans matches cached from its prefix, matching fzf's incremental model. |
| `ignore.h` | `Gitignore` / `IgnoreFilter` / `glob_match`: git wildmatch semantics or rg semantics (`IgnoreDialect::Rg`, `rg_glob_match`). `CaseMode::Auto` follows `core.ignorecase`, `Sensitive` matches rg; `Precompose::Auto` follows `core.precomposeUnicode` on macOS. |
| `walk.h` | `walk` / `list_files`: parallel directory walking with pruning. Honours `.gitignore`, `.ignore`, `.rgignore`, `.git/info/exclude`, global excludes and parent-directory ignore files with ripgrep precedence, plus `-g` overrides. |
| `regex.h` | `Regex`: linear-time regex engine with Rust/ripgrep syntax (see below). |
| `grep.h` | `Grep`: ripgrep-compatible line search over buffers, files, and directory trees. Fixed strings, smart/insensitive case, `-w`/`-x`, invert, context lines, max count, `-U` multiline, UTF-8 and UTF-16 BOM decoding, binary detection, and terminal helpers `detect_urls` / `detect_git_hashes`. |
| `cancellation_token.h` | `CancellationSource` / `CancellationToken`, accepted by all long-running searches. |

## Regex engine (`src/regex/`)

brosearch contains its own linear-time regular expression engine without third-party dependencies:
- **HIR compilation**: Unicode simple case folding, `\w`, `\d`, `\s`, general categories, scripts and script extensions (`\p{Greek}`, `\p{scx=Hira}`).
- **Byte Thompson NFA**: UTF-8 range compilation for both forward and reverse programs.
- **Lazy DFA**: States track preceding byte context classes for exact look-around (`^`, `$`, `\b`, `\B`). Uses leftmost-first matching and a reverse DFA to find start offsets.
- **PikeVM fallback**: Handles Unicode `\b` next to non-ASCII bytes and DFA state thrashing.
- **Literal prefilters**: Prefilters search for required literals using rarest-byte heuristics, SSE2 `memchr2`/`memchr3`, or memchr.
- **Unicode 16 tables**: Generated by `tools/gen_unicode.cpp` from UCD files into `src/regex/unicode_*.inc`.

## Building and embedding

### Standalone build

```bash
# Linux / macOS (Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure

# Windows (MSVC / Visual Studio 2022)
cmake -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The build produces:
- `brosearch`: Static library (CMake target `brosearch::brosearch` or `brosearch`).
- `brosearch_cli`: Command-line interface executable (binary named `brosearch`).

A plain `git clone` is enough: there are no submodules. The library itself needs nothing beyond
the standard library; its JavaScript binding (`BROSEARCH_ENABLE_API`, on when brosearch is the
top-level project) needs [bronze](https://github.com/wlejon/bronze) and, through it,
[brass](https://github.com/wlejon/brass). They resolve the way every repo in the ecosystem
resolves a dependency (`cmake/bro_deps.cmake`): an existing target, then a working tree at
`../<name>`, then the commit `CMakeLists.txt` pins, fetched at configure (override with
`-DFETCHCONTENT_SOURCE_DIR_<NAME>=<path>`).

### Embedding in a CMake project

Bro-ecosystem consumers pin brosearch with `bro_dependency(brosearch ...)`, which takes a
`../brosearch` working tree when there is one. Any other project can add it directly:

```cmake
add_subdirectory(path/to/brosearch)

target_link_libraries(my_tool PRIVATE brosearch::brosearch)
```

Configuration options:
- `BROSEARCH_BUILD_TESTS`: Build ctest test suite (default `ON` when top-level, `OFF` when embedded via `add_subdirectory`).
- `BROSEARCH_BUILD_TOOLS`: Build `brosearch` CLI executable (default `ON` when top-level, `OFF` when embedded via `add_subdirectory`).
- `BROSEARCH_COVERAGE`: Build with gcov coverage instrumentation on GCC/Clang (default `OFF`).

## API overview

```cpp
#include <brosearch/search.h>
#include <iostream>

using namespace bro::search;

int main() {
    // 1. Fuzzy matching (fzf v2 algorithm)
    FuzzyQuery query("doc");
    std::string item = "document_parser.cpp";
    FuzzyMatch match;
    if (query.match(item, match)) {
        std::cout << "Matched '" << item << "' with score: " << match.score << "\n";
    }

    // 2. Linear-time regex search
    Regex re("fn\\s+[a-z_]+", RegexOptions::Default);
    std::string text = "fn parse_tokens() -> bool";
    Match m;
    if (re.find(text, m)) {
        std::cout << "Found match: " << text.substr(m.start, m.length()) << "\n";
    }

    // 3. Ripgrep-compatible directory walking with .gitignore
    WalkOptions opts;
    opts.threads = 4;
    walk(".", opts, [](const WalkEntry& entry) {
        if (!entry.is_dir) {
            std::cout << entry.path << "\n";
        }
        return WalkAction::Continue;
    });
}
```

## Tests

Every test is a real ctest executable that catches invariant violations in Release builds (no reliance on `assert()`).

### Test breakdown

| Suite | Focus |
|-------|-------|
| `core` | Basic string utilities, UTF-8 decoding, cancellation tokens |
| `ignore` | Git wildmatch and ripgrep glob dialects, parent ignore inheritance, case mode switching |
| `walk` | Multithreaded directory walking, ignore rule precedence, hidden file rules, error callbacks |
| `fuzzy` | fzf scoring parity, extended search syntax (`^prefix`, `'exact`, `suffix$`, `!invert`), tie-breaks |
| `fuzzy_index` | Incremental item store concurrency, prefix match cache reuse, streaming additions |
| `regex` | HIR compilation, DFA look-around transitions, PikeVM fallback, Unicode 16 character classes |
| `grep` | Line search, context lines, multi-line patterns, binary file detection, BOM handling |

Test suites validate expectations against checked-in oracle fixtures (`tests/fixtures/`):
- `tests/fixtures/fuzzy/`: Recorded `fzf` output.
- `tests/fixtures/walk/*.spec`: Tree specifications with expected `rg --files` and `git` results.
- `tests/fixtures/grep/`: 107 ripgrep reference outputs across an adversarial corpus generated by `tests/grep_oracle.h`.

Because test fixtures are bundled, external installations of `fzf`, `rg`, or `git` are **not required** to run CI test jobs.

### CI skips

- **`nonutf8_posix.spec`**: Skipped on macOS / APFS because APFS rejects filenames with invalid UTF-8 bytes.
- **POSIX-only tree specs**: Skipped on Windows when specs require POSIX permission bits or characters not valid in NTFS filenames.

### Live differential runners

Developers can run live differential tests against real external tools installed on their system:

```bash
scripts/diff_grep.sh  [--update] [--real DIR]... [--timing]   # vs ripgrep; --update re-records fixtures
scripts/diff_files.sh ...                                     # vs rg --files, git ls-files, git check-ignore
scripts/diff_fuzzy.sh ...                                     # vs fzf --filter
```

## Known differences and gaps

- **Grep and regex:**
  - Explicitly named files follow rg's `--no-mmap` path. rg memory-maps a small number of explicitly named files on Windows and Linux (never on macOS), and its mmap path handles binary data differently; the `explicit_*` fixtures pass `--no-mmap`.
  - The rg front end lives in `tests/grep_oracle.h`. It collects whole-file results, so output-heavy searches (hundreds of thousands of lines) are slower than rg's streaming printer.
- **Fuzzy:** Tables are Unicode 16. fzf 0.74.4 uses Go 1.25.6, whose tables are Unicode 15.0.0; case folding for code points added in Unicode 16 can differ from fzf.
- **Ignore:** Default dialect is git's case behavior (`CaseMode::Auto`), whereas rg always matches case-sensitively. Outside a git repository, `Auto` on macOS queries `pathconf(_PC_CASE_SENSITIVE)`.
  - `IgnoreDialect::Git` (default) reads ignore files as git does; `IgnoreDialect::Rg` follows rg 15 (trailing tabs trimmed, globset `{a,b}`, global exclude anchoring). Older rg releases differ.
  - rg 15.2 on Windows does not match a `-g` glob with a leading `/`; brosearch follows POSIX rg behavior and anchors it at the root.

## License

MIT; see [LICENSE](LICENSE). Tables in `src/regex/unicode_*.inc` and
`src/fuzzy/fuzzy_unicode_tables.inc` are generated from the Unicode Character
Database ([Unicode License v3](https://www.unicode.org/license.txt)).
