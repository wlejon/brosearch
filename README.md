# brosearch

`brosearch` is the high-performance, multithreaded Search and Fuzzy Matching engine for the Bro ecosystem (`bro.search`).

It powers sub-millisecond search experiences across Bro applications:
- **Terminal (`bropty`)**: Instant regex search across 500,000 lines of scrollback buffer, URL/git-commit detection, and fzf-style fuzzy command history search.
- **File Explorer (`brovfs`)**: Sub-millisecond fuzzy filtering of 50,000+ files as the user types in the search bar, plus project-wide multithreaded text and regex grep.
- **General Bro Apps**: Code editor find-in-files, quick-open command palettes (`Ctrl+P`), asset filtering.

Pure C++20 engine designed to be embedded directly into Bro and sibling projects with zero external dependencies.

---

## Features

- **`fuzzy_matcher` (`brosearch/fuzzy.h`)**:
  - High-performance fzf-style fuzzy matching.
  - Boundary bonuses: after `/`, `\`, `-`, `_`, `.`, space, or lowercase-to-uppercase `camelCase` transitions.
  - Consecutive match bonuses and non-consecutive gap penalties.
  - Exact match and path-mode prioritization.
  - Returns match scores and an array of 0-indexed character offsets for UI highlight rendering.
  - Fast multithreaded batch ranking API (`rank_candidates`).
- **`content_grep` (`brosearch/grep.h`)**:
  - Fast Boyer-Moore-Horspool literal substring matcher and optimized regex search.
  - Returns 1-indexed line numbers, 1-indexed columns, match byte lengths, and line content snippets.
  - Automatic binary file detection to avoid corrupting UI or wasting memory.
  - Responsive `CancellationToken` support for live as-you-type search queries.
  - Scrollback buffer helpers, URL detection, and git hash detection.
- **`ignore_filter` (`brosearch/ignore.h`)**:
  - Gitignore specification parser: supports `*`, `**`, `?`, `[...]`, negation `!`, directory-only trailing `/`, and leading `/`.
  - Built-in default ignore list (`.git`, `node_modules`, `.vs`, `build`, `dist`, `.cache`, etc.).
  - Hierarchical `.gitignore` support for nested subdirectories.
- **`file_finder` (`brosearch/finder.h`)**:
  - Multithreaded directory walker combining `ignore_filter` pruning with filename glob or fuzzy matching.
  - Prunes ignored subtrees before descending for maximum I/O performance.
  - Streaming callback and batch vector collection APIs.

---

## Architecture & Module Layout

```
brosearch/
├── include/brosearch/
│   ├── version.h              # Version macros & functions
│   ├── cancellation_token.h   # Thread-safe cancellation token & source
│   ├── fuzzy.h                # Fuzzy matcher & batch ranking
│   ├── ignore.h               # Gitignore & glob pattern matcher
│   ├── grep.h                 # File & buffer content search
│   ├── finder.h               # Multithreaded file walker
│   └── search.h               # Umbrella header
├── src/
│   ├── version.cpp
│   ├── cancellation_token.cpp
│   ├── fuzzy.cpp
│   ├── ignore.cpp
│   ├── grep.cpp
│   └── finder.cpp
└── tests/
    ├── CMakeLists.txt
    ├── test_smoke.cpp
    ├── test_fuzzy.cpp
    ├── test_grep.cpp
    ├── test_ignore.cpp
    └── test_finder.cpp
```

---

## Quick Example

### Fuzzy Match
```cpp
#include <brosearch/search.h>
#include <iostream>

int main() {
    auto res = bro::search::fuzzy_match("bf", "bro_finder.cpp");
    if (res.matched) {
        std::cout << "Score: " << res.score << "\n";
        std::cout << "Matched indices: ";
        for (auto idx : res.matched_indices) {
            std::cout << idx << " ";
        }
        std::cout << "\n";
    }
}
```

### Content Grep
```cpp
#include <brosearch/search.h>
#include <iostream>

int main() {
    bro::search::GrepOptions opts;
    opts.case_sensitive = false;
    auto res = bro::search::grep_file("src/main.cpp", "int main", opts);
    for (const auto& match : res.matches) {
        std::cout << match.line_number << ":" << match.column << ": " << match.line_content << "\n";
    }
}
```

---

## Building & Testing

```bash
cmake -B build -S .
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```
