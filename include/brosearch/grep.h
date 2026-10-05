#pragma once
// Content search with ripgrep semantics: line-oriented matching (a match never spans a line
// terminator), the linear-time regex engine from regex.h with literal prefilters, BOM sniffing
// (UTF-8 BOM stripped, UTF-16 LE/BE transcoded to UTF-8), rg's binary-file handling, inverted
// matching, context lines, per-file match limits, statistics and prompt cancellation.
//
// Defaults mirror rg: regex syntax, case-sensitive, binary files searched only up to their first
// NUL byte (BinaryMode::Quit).

#include "brosearch/cancellation_token.h"
#include "brosearch/regex.h"
#include "brosearch/walk.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

enum class CaseMatching : uint8_t {
    Sensitive,
    Insensitive,  // rg -i (Unicode simple case folding)
    Smart,        // rg -S: insensitive unless the pattern contains an uppercase literal
};

enum class BinaryMode : uint8_t {
    // rg's default for files found by walking: a NUL byte ends the search of that file; lines
    // before it are still searched and reported. GrepFileResult::binary records the NUL.
    Quit,
    // rg's default for files named explicitly: the whole file is searched (NULs act as line
    // terminators) but no lines are reported; a match sets GrepFileResult::binary_matched.
    Report,
    // rg -a/--text: search binary data as text.
    Text,
};

struct GrepOptions {
    bool fixed_strings = false;  // rg -F: the pattern is a literal string
    CaseMatching case_matching = CaseMatching::Sensitive;
    bool word = false;           // rg -w
    bool whole_line = false;     // rg -x
    bool invert = false;         // rg -v: select non-matching lines
    bool crlf = false;           // rg --crlf: ^/$ treat "\r\n" as a line terminator
    bool unicode = true;         // (?u) default for the pattern
    size_t before_context = 0;   // rg -B
    size_t after_context = 0;    // rg -A
    size_t max_count = 0;        // rg -m: stop a file after this many selected lines (0 = no limit)
    BinaryMode binary = BinaryMode::Quit;
    bool bom_sniffing = true;    // files only: honour UTF-8 / UTF-16 byte order marks
    uint64_t max_filesize = 0;   // files larger than this are skipped (0 = no limit)
    bool line_numbers = true;    // compute GrepLine::line_number (counting costs a pass over the data)
    bool collect_spans = true;   // compute the match spans of each matching line
    bool collect_lines = true;   // file searches: store lines in GrepFileResult (false = counts only)
    size_t threads = 0;          // multi-file searches: 0 = hardware concurrency (capped)
    size_t regex_size_limit = size_t(1) << 22;
};

struct GrepSpan {
    size_t start = 0;  // byte offsets within GrepLine::text
    size_t end = 0;
    bool operator==(const GrepSpan&) const = default;
};

enum class LineKind : uint8_t { Match, Context };

// A reported line, valid only during the callback (views into the searched data).
struct GrepLineView {
    LineKind kind = LineKind::Match;
    uint64_t line_number = 0;  // 1-based (0 when line_numbers is off)
    uint64_t byte_offset = 0;  // of the line start in the searched (decoded) content
    std::string_view text;     // without the line terminator
    std::span<const GrepSpan> spans;  // match spans (empty for context and inverted matches)
};

struct GrepLine {
    LineKind kind = LineKind::Match;
    uint64_t line_number = 0;
    uint64_t byte_offset = 0;
    std::string text;
    std::vector<GrepSpan> spans;
};

struct GrepFileResult {
    std::string path;              // UTF-8, as walked (relative) or as given
    std::vector<GrepLine> lines;   // match and context lines in file order
    size_t matched_lines = 0;      // selected lines (inverted lines when invert)
    size_t matches = 0;            // match spans (0 when collect_spans is off or invert)
    bool binary = false;           // a NUL byte was found (search stopped there in Quit mode)
    uint64_t binary_offset = 0;    // offset of the first NUL in the decoded content
    bool binary_matched = false;   // Report mode: the binary file matched (lines suppressed)
    uint64_t bytes_searched = 0;
    std::string error;             // I/O error (file unreadable), empty on success
};

struct GrepStats {
    size_t files_searched = 0;
    size_t files_matched = 0;
    size_t matched_lines = 0;
    size_t matches = 0;
    size_t binary_files = 0;
    uint64_t bytes_searched = 0;
    double elapsed_ms = 0.0;
};

// Return false to stop (the current buffer/file for LineSink; the whole search for FileSink).
using LineSink = std::function<bool(const GrepLineView&)>;
// Called once per file that has matches (or an error), serialized across worker threads.
using FileSink = std::function<bool(const GrepFileResult&)>;

class Grep {
public:
    // nullptr on an invalid pattern (message in *error).
    [[nodiscard]] static std::shared_ptr<const Grep> compile(std::string_view pattern, const GrepOptions& options,
                                                             std::string* error = nullptr);

    // In-memory text (e.g. terminal scrollback). No BOM handling; binary mode as configured.
    // Returns the number of selected lines.
    size_t search_buffer(std::string_view buffer, const LineSink& sink,
                         const CancellationToken* token = nullptr) const;
    [[nodiscard]] std::vector<GrepLine> search_buffer(std::string_view buffer,
                                                      const CancellationToken* token = nullptr) const;

    [[nodiscard]] GrepFileResult search_file(const std::filesystem::path& file,
                                             const CancellationToken* token = nullptr) const;

    // Parallel search of the given files; the sink sees files in completion order.
    void search_files(const std::vector<std::filesystem::path>& files, const FileSink& sink,
                      const CancellationToken* token = nullptr, GrepStats* stats = nullptr) const;

    // Walk `root` (ripgrep ignore semantics, see walk.h) and search every file, pipelined.
    // GrepFileResult::path is the walk-relative path.
    void search_tree(const std::filesystem::path& root, const WalkOptions& walk_options, const FileSink& sink,
                     const CancellationToken* token = nullptr, GrepStats* stats = nullptr) const;

    [[nodiscard]] const GrepOptions& options() const noexcept { return options_; }
    [[nodiscard]] const Regex& regex() const noexcept { return *regex_; }

private:
    GrepOptions options_;
    std::shared_ptr<const Regex> regex_;

    struct CachePool;
    std::shared_ptr<CachePool> pool_;

    GrepFileResult search_path(const std::filesystem::path& file, std::string display,
                               const CancellationToken* token) const;
};

// Terminal helpers: URLs (http/https/ftp/file schemes) and git object hashes (7-40 hex digits as
// a whole word) in arbitrary text. Line/column are 1-based, columns in bytes.
struct TextMatch {
    size_t line_number = 1;
    size_t column = 1;
    size_t byte_offset = 0;
    size_t length = 0;
};
[[nodiscard]] std::vector<TextMatch> detect_urls(std::string_view text);
[[nodiscard]] std::vector<TextMatch> detect_git_hashes(std::string_view text);

} // namespace bro::search
