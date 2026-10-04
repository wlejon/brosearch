#pragma once

#include "brosearch/cancellation_token.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

enum class FuzzyCaseSensitivity {
    Smart,       // Case-insensitive unless pattern contains uppercase characters
    Insensitive, // Always case-insensitive
    Sensitive    // Always case-sensitive
};

struct FuzzyOptions {
    FuzzyCaseSensitivity case_sensitivity = FuzzyCaseSensitivity::Smart;
    bool path_mode = true;       // Extra bonus for filename matches over directory paths
    int32_t min_score = 0;       // Minimum score to include in results
    size_t max_results = 0;      // 0 = unlimited
    size_t thread_count = 0;     // 0 = auto (hardware concurrency)
};

struct FuzzyMatchResult {
    bool matched = false;
    int32_t score = 0;
    std::vector<uint32_t> matched_indices;

    explicit operator bool() const noexcept { return matched; }
};

struct FuzzyRankedResult {
    size_t index = 0;
    std::string text;
    int32_t score = 0;
    std::vector<uint32_t> matched_indices;
};

// Computes fuzzy match score and returns the exact character indices for UI highlighting
[[nodiscard]] FuzzyMatchResult fuzzy_match(
    std::string_view pattern,
    std::string_view candidate,
    const FuzzyOptions& options = {}
);

// Fast scoring only (does not construct matched_indices)
[[nodiscard]] int32_t fuzzy_score(
    std::string_view pattern,
    std::string_view candidate,
    const FuzzyOptions& options = {}
);

// Multithreaded batch ranking for candidate collections
[[nodiscard]] std::vector<FuzzyRankedResult> rank_candidates(
    std::string_view pattern,
    std::span<const std::string> candidates,
    const FuzzyOptions& options = {},
    const CancellationToken* token = nullptr
);

[[nodiscard]] std::vector<FuzzyRankedResult> rank_candidates(
    std::string_view pattern,
    std::span<const std::string_view> candidates,
    const FuzzyOptions& options = {},
    const CancellationToken* token = nullptr
);

[[nodiscard]] inline std::vector<FuzzyRankedResult> rank_candidates(
    std::string_view pattern,
    const std::vector<std::string>& candidates,
    const FuzzyOptions& options = {},
    const CancellationToken* token = nullptr
) {
    return rank_candidates(pattern, std::span<const std::string>(candidates), options, token);
}

} // namespace bro::search
