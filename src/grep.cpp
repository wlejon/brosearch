#include "brosearch/grep.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <regex>
#include <thread>

namespace bro::search {

namespace {

inline char to_lower_char(char c) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

inline bool is_word_char(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// Boyer-Moore-Horspool bad-character shift table
class HorspoolMatcher {
public:
    HorspoolMatcher(std::string_view pattern, bool case_sensitive)
        : pattern_(pattern), case_sensitive_(case_sensitive), m_(pattern.size()) {
        std::fill(shift_.begin(), shift_.end(), m_);
        if (m_ == 0) return;

        for (size_t i = 0; i < m_ - 1; ++i) {
            unsigned char c = static_cast<unsigned char>(pattern_[i]);
            if (case_sensitive_) {
                shift_[c] = m_ - 1 - i;
            } else {
                shift_[to_lower_char(c)] = m_ - 1 - i;
                shift_[static_cast<unsigned char>(std::toupper(c))] = m_ - 1 - i;
            }
        }
    }

    template <typename Callback>
    void search(std::string_view text, Callback&& cb, const CancellationToken* token = nullptr) const {
        if (m_ == 0 || text.size() < m_) return;

        const size_t n = text.size();

        // Optimized single-character search
        if (m_ == 1) {
            char target = pattern_[0];
            if (case_sensitive_) {
                const char* cur = text.data();
                const char* end = cur + n;
                while (cur < end) {
                    if (token && token->is_cancelled()) return;
                    const char* found = static_cast<const char*>(std::memchr(cur, target, end - cur));
                    if (!found) break;
                    size_t offset = found - text.data();
                    if (!cb(offset, 1)) return;
                    cur = found + 1;
                }
            } else {
                char lower_t = to_lower_char(target);
                char upper_t = static_cast<char>(std::toupper(static_cast<unsigned char>(target)));
                for (size_t i = 0; i < n; ++i) {
                    if (token && token->is_cancelled()) return;
                    char c = text[i];
                    if (c == lower_t || c == upper_t) {
                        if (!cb(i, 1)) return;
                    }
                }
            }
            return;
        }

        // Standard Horspool
        size_t i = m_ - 1;
        while (i < n) {
            if (token && token->is_cancelled()) return;

            int64_t k = static_cast<int64_t>(m_ - 1);
            int64_t j = static_cast<int64_t>(i);

            if (case_sensitive_) {
                while (k >= 0 && text[j] == pattern_[k]) {
                    --j;
                    --k;
                }
            } else {
                while (k >= 0 && to_lower_char(text[j]) == to_lower_char(pattern_[k])) {
                    --j;
                    --k;
                }
            }

            if (k < 0) {
                // Found match at j + 1
                if (!cb(static_cast<size_t>(j + 1), m_)) return;
                i += (m_ > 1 ? shift_[static_cast<unsigned char>(text[i])] : 1);
            } else {
                unsigned char c = static_cast<unsigned char>(text[i]);
                i += shift_[case_sensitive_ ? c : to_lower_char(c)];
            }
        }
    }

private:
    std::string_view pattern_;
    bool case_sensitive_;
    size_t m_;
    std::array<size_t, 256> shift_{};
};

// Line information extractor
void extract_line_info(
    std::string_view buffer,
    size_t match_offset,
    size_t& out_line_num,
    size_t& out_last_scan_pos,
    size_t& out_column,
    std::string& out_line_content
) {
    // Count newlines from out_last_scan_pos to match_offset
    for (size_t pos = out_last_scan_pos; pos < match_offset; ++pos) {
        if (buffer[pos] == '\n') {
            ++out_line_num;
        }
    }
    out_last_scan_pos = match_offset;

    // Find start of line (backwards from match_offset)
    size_t line_start = match_offset;
    while (line_start > 0 && buffer[line_start - 1] != '\n') {
        --line_start;
    }

    // Find end of line (forwards from match_offset)
    size_t line_end = match_offset;
    while (line_end < buffer.size() && buffer[line_end] != '\n' && buffer[line_end] != '\r') {
        ++line_end;
    }

    out_column = (match_offset - line_start) + 1;
    out_line_content = std::string(buffer.substr(line_start, line_end - line_start));
}

} // namespace

bool is_binary_buffer(std::string_view buffer, size_t check_bytes) noexcept {
    const size_t n = std::min(buffer.size(), check_bytes);
    return std::memchr(buffer.data(), '\0', n) != nullptr;
}

bool is_binary_file(const std::filesystem::path& file_path, size_t check_bytes) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return false;

    std::vector<char> buf(check_bytes);
    file.read(buf.data(), static_cast<std::streamsize>(check_bytes));
    std::streamsize bytes_read = file.gcount();
    if (bytes_read <= 0) return false;

    return is_binary_buffer(std::string_view(buf.data(), static_cast<size_t>(bytes_read)), static_cast<size_t>(bytes_read));
}

std::vector<GrepMatch> grep_buffer(
    std::string_view buffer,
    std::string_view pattern,
    const GrepOptions& options,
    const CancellationToken* token
) {
    std::vector<GrepMatch> matches;
    if (pattern.empty() || buffer.empty()) {
        return matches;
    }

    if (token && token->is_cancelled()) {
        return matches;
    }

    size_t line_num = 1;
    size_t last_scan_pos = 0;

    auto check_word_boundaries = [&](size_t offset, size_t length) -> bool {
        if (!options.word_match) return true;
        if (offset > 0 && is_word_char(buffer[offset - 1])) {
            return false;
        }
        size_t after_idx = offset + length;
        if (after_idx < buffer.size() && is_word_char(buffer[after_idx])) {
            return false;
        }
        return true;
    };

    if (options.is_regex) {
        try {
            auto flags = std::regex_constants::optimize;
            if (!options.case_sensitive) {
                flags |= std::regex_constants::icase;
            }
            std::regex re(std::string(pattern), flags);

            auto words_begin = std::cregex_iterator(buffer.data(), buffer.data() + buffer.size(), re);
            auto words_end = std::cregex_iterator();

            for (auto it = words_begin; it != words_end; ++it) {
                if (token && token->is_cancelled()) break;

                size_t offset = static_cast<size_t>(it->position());
                size_t length = static_cast<size_t>(it->length());

                if (!check_word_boundaries(offset, length)) {
                    continue;
                }

                size_t column = 1;
                std::string line_content;
                extract_line_info(buffer, offset, line_num, last_scan_pos, column, line_content);

                GrepMatch match;
                match.line_number = line_num;
                match.column = column;
                match.byte_offset = offset;
                match.match_length = length;
                match.line_content = std::move(line_content);
                matches.push_back(std::move(match));

                if (options.max_matches > 0 && matches.size() >= options.max_matches) {
                    break;
                }
            }
        } catch (const std::regex_error&) {
            return {};
        }
    } else {
        HorspoolMatcher matcher(pattern, options.case_sensitive);

        matcher.search(buffer, [&](size_t offset, size_t length) -> bool {
            if (!check_word_boundaries(offset, length)) {
                return true;
            }

            size_t column = 1;
            std::string line_content;
            extract_line_info(buffer, offset, line_num, last_scan_pos, column, line_content);

            GrepMatch match;
            match.line_number = line_num;
            match.column = column;
            match.byte_offset = offset;
            match.match_length = length;
            match.line_content = std::move(line_content);
            matches.push_back(std::move(match));

            if (options.max_matches > 0 && matches.size() >= options.max_matches) {
                return false;
            }
            return true;
        }, token);
    }

    return matches;
}

GrepFileResult grep_file(
    const std::filesystem::path& file_path,
    std::string_view pattern,
    const GrepOptions& options,
    const CancellationToken* token
) {
    GrepFileResult result;
    result.file_path = file_path.generic_string();

    std::error_code ec;
    uintmax_t file_size = std::filesystem::file_size(file_path, ec);
    if (ec) {
        result.error = ec.message();
        return result;
    }

    if (options.max_file_size > 0 && file_size > options.max_file_size) {
        result.error = "File exceeds max_file_size limit";
        return result;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        result.error = "Failed to open file";
        return result;
    }

    std::string buffer;
    buffer.resize(static_cast<size_t>(file_size));
    file.read(buffer.data(), static_cast<std::streamsize>(file_size));

    if (is_binary_buffer(buffer)) {
        result.is_binary = true;
        if (options.skip_binary) {
            return result;
        }
    }

    result.matches = grep_buffer(buffer, pattern, options, token);
    for (auto& m : result.matches) {
        m.file_path = result.file_path;
    }

    if (options.max_matches_per_file > 0 && result.matches.size() > options.max_matches_per_file) {
        result.matches.resize(options.max_matches_per_file);
    }

    return result;
}

void grep_files_callback(
    const std::vector<std::filesystem::path>& file_paths,
    std::string_view pattern,
    const GrepOptions& options,
    std::function<bool(const GrepFileResult&)> on_file_result,
    const CancellationToken* token,
    GrepStats* stats
) {
    auto start_time = std::chrono::steady_clock::now();
    const size_t total_files = file_paths.size();
    if (total_files == 0) return;

    size_t num_threads = options.thread_count;
    if (num_threads == 0) {
        num_threads = std::max(1u, std::min(std::thread::hardware_concurrency(), 8u));
    }
    if (total_files < 8) {
        num_threads = 1;
    }

    std::atomic<size_t> next_idx{0};
    std::atomic<bool> stop_flag{false};
    std::atomic<size_t> total_matches_count{0};
    std::atomic<size_t> bytes_searched_count{0};
    std::atomic<size_t> matched_files_count{0};
    std::mutex cb_mutex;

    auto worker = [&]() {
        while (!stop_flag.load(std::memory_order_relaxed)) {
            if (token && token->is_cancelled()) {
                stop_flag.store(true, std::memory_order_relaxed);
                break;
            }

            size_t idx = next_idx.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total_files) break;

            const auto& path = file_paths[idx];
            GrepFileResult res = grep_file(path, pattern, options, token);

            if (!res.matches.empty()) {
                matched_files_count.fetch_add(1, std::memory_order_relaxed);
                total_matches_count.fetch_add(res.matches.size(), std::memory_order_relaxed);

                std::lock_guard<std::mutex> lock(cb_mutex);
                if (!stop_flag.load(std::memory_order_relaxed)) {
                    if (!on_file_result(res)) {
                        stop_flag.store(true, std::memory_order_relaxed);
                    }
                }
            }

            if (options.max_matches > 0 &&
                total_matches_count.load(std::memory_order_relaxed) >= options.max_matches) {
                stop_flag.store(true, std::memory_order_relaxed);
                break;
            }
        }
    };

    if (num_threads == 1) {
        worker();
    } else {
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker);
        }
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }

    if (stats) {
        auto end_time = std::chrono::steady_clock::now();
        stats->files_searched = std::min(next_idx.load(), total_files);
        stats->files_matched = matched_files_count.load();
        stats->total_matches = total_matches_count.load();
        stats->bytes_searched = bytes_searched_count.load();
        stats->elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    }
}

std::vector<GrepFileResult> grep_files(
    const std::vector<std::filesystem::path>& file_paths,
    std::string_view pattern,
    const GrepOptions& options,
    const CancellationToken* token,
    GrepStats* stats
) {
    std::vector<GrepFileResult> results;
    std::mutex results_mutex;

    grep_files_callback(
        file_paths,
        pattern,
        options,
        [&](const GrepFileResult& res) -> bool {
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(res);
            return true;
        },
        token,
        stats
    );

    return results;
}

std::vector<GrepMatch> detect_urls(std::string_view text) {
    static const std::regex url_re(
        R"((https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+))",
        std::regex_constants::optimize
    );

    std::vector<GrepMatch> matches;
    auto begin = std::cregex_iterator(text.data(), text.data() + text.size(), url_re);
    auto end = std::cregex_iterator();

    size_t line_num = 1;
    size_t last_scan_pos = 0;

    for (auto it = begin; it != end; ++it) {
        size_t offset = static_cast<size_t>(it->position());
        size_t length = static_cast<size_t>(it->length());

        size_t column = 1;
        std::string line_content;
        extract_line_info(text, offset, line_num, last_scan_pos, column, line_content);

        GrepMatch match;
        match.line_number = line_num;
        match.column = column;
        match.byte_offset = offset;
        match.match_length = length;
        match.line_content = std::move(line_content);
        matches.push_back(std::move(match));
    }

    return matches;
}

std::vector<GrepMatch> detect_git_hashes(std::string_view text) {
    static const std::regex hash_re(
        R"(\b([0-9a-fA-F]{7,40})\b)",
        std::regex_constants::optimize
    );

    std::vector<GrepMatch> matches;
    auto begin = std::cregex_iterator(text.data(), text.data() + text.size(), hash_re);
    auto end = std::cregex_iterator();

    size_t line_num = 1;
    size_t last_scan_pos = 0;

    for (auto it = begin; it != end; ++it) {
        size_t offset = static_cast<size_t>(it->position());
        size_t length = static_cast<size_t>(it->length());

        size_t column = 1;
        std::string line_content;
        extract_line_info(text, offset, line_num, last_scan_pos, column, line_content);

        GrepMatch match;
        match.line_number = line_num;
        match.column = column;
        match.byte_offset = offset;
        match.match_length = length;
        match.line_content = std::move(line_content);
        matches.push_back(std::move(match));
    }

    return matches;
}

} // namespace bro::search
