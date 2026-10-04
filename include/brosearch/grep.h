#pragma once

#include "brosearch/cancellation_token.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

struct GrepMatch {
    std::string file_path;       // Empty if matched in an in-memory buffer
    size_t line_number = 1;      // 1-indexed
    size_t column = 1;           // 1-indexed
    size_t byte_offset = 0;      // Byte offset from start of file/buffer
    size_t match_length = 0;     // Byte length of the match
    std::string line_content;    // Full text of the line containing the match
};

struct GrepOptions {
    bool is_regex = false;
    bool case_sensitive = false;
    bool word_match = false;     // Match whole words only
    bool invert_match = false;   // Invert matching (return lines that do not match)
    size_t max_matches = 0;      // 0 = unlimited total matches
    size_t max_matches_per_file = 0; // 0 = unlimited per file
    bool skip_binary = true;     // Skip files detected as binary
    size_t max_file_size = 100 * 1024 * 1024; // Maximum file size (100MB default)
    size_t thread_count = 0;     // 0 = auto (hardware concurrency)
};

struct GrepFileResult {
    std::string file_path;
    bool is_binary = false;
    std::vector<GrepMatch> matches;
    std::string error;
};

struct GrepStats {
    size_t files_searched = 0;
    size_t files_matched = 0;
    size_t total_matches = 0;
    size_t bytes_searched = 0;
    double elapsed_ms = 0.0;
};

// Binary buffer detection: inspects up to check_bytes for null characters
[[nodiscard]] bool is_binary_buffer(std::string_view buffer, size_t check_bytes = 8192) noexcept;
[[nodiscard]] bool is_binary_file(const std::filesystem::path& file_path, size_t check_bytes = 8192);

// Fast search in an in-memory buffer (ideal for terminal scrollback buffer)
[[nodiscard]] std::vector<GrepMatch> grep_buffer(
    std::string_view buffer,
    std::string_view pattern,
    const GrepOptions& options = {},
    const CancellationToken* token = nullptr
);

// Search a single file on disk
[[nodiscard]] GrepFileResult grep_file(
    const std::filesystem::path& file_path,
    std::string_view pattern,
    const GrepOptions& options = {},
    const CancellationToken* token = nullptr
);

// Parallel search across multiple files
[[nodiscard]] std::vector<GrepFileResult> grep_files(
    const std::vector<std::filesystem::path>& file_paths,
    std::string_view pattern,
    const GrepOptions& options = {},
    const CancellationToken* token = nullptr,
    GrepStats* stats = nullptr
);

// Streaming callback variant of parallel file search
void grep_files_callback(
    const std::vector<std::filesystem::path>& file_paths,
    std::string_view pattern,
    const GrepOptions& options,
    std::function<bool(const GrepFileResult&)> on_file_result,
    const CancellationToken* token = nullptr,
    GrepStats* stats = nullptr
);

// Terminal helpers: detect URLs (e.g. http://, https://) and git commit hashes
[[nodiscard]] std::vector<GrepMatch> detect_urls(std::string_view text);
[[nodiscard]] std::vector<GrepMatch> detect_git_hashes(std::string_view text);

} // namespace bro::search
