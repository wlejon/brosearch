#pragma once

#include "brosearch/cancellation_token.h"
#include "brosearch/ignore.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bro::search {

struct FileEntry {
    std::filesystem::path path;
    std::string relative_path;
    std::string filename;
    bool is_directory = false;
    uint64_t file_size = 0;
    int32_t fuzzy_score = 0;
    std::vector<uint32_t> matched_indices;
};

struct FindOptions {
    bool recursive = true;
    size_t max_depth = 0;                  // 0 = unlimited
    bool follow_symlinks = false;
    bool include_files = true;
    bool include_directories = false;
    bool include_hidden = false;
    bool respect_gitignore = true;
    std::string glob_pattern;             // e.g. "*.cpp", "*.h" (empty = all)
    std::string fuzzy_pattern;            // If non-empty, scores and sorts matches
    size_t max_results = 0;               // 0 = unlimited
    size_t thread_count = 0;              // 0 = auto (hardware concurrency)
    std::shared_ptr<IgnoreFilter> custom_ignore_filter;
};

// Multithreaded directory walker combining ignore_filter with glob or fuzzy matching
[[nodiscard]] std::vector<FileEntry> find_files(
    const std::filesystem::path& root_path,
    const FindOptions& options = {},
    const CancellationToken* token = nullptr
);

// Streaming callback variant of find_files
void find_files_callback(
    const std::filesystem::path& root_path,
    const FindOptions& options,
    std::function<bool(const FileEntry&)> on_entry,
    const CancellationToken* token = nullptr
);

} // namespace bro::search
