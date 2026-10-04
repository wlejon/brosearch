#include "brosearch/fuzzy.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cmath>
#include <future>
#include <thread>

namespace bro::search {

namespace {

constexpr int32_t NEG_INF = -1000000;
constexpr int32_t SCORE_MATCH = 16;
constexpr int32_t SCORE_BOUNDARY = 28;
constexpr int32_t SCORE_CAMEL = 24;
constexpr int32_t SCORE_FIRST_CHAR = 32;
constexpr int32_t SCORE_PATH_BONUS = 8;
constexpr int32_t GAP_OPEN_PENALTY = -6;
constexpr int32_t GAP_EXT_PENALTY = -1;
constexpr int32_t EXACT_MATCH_BONUS = 100;

inline bool is_delimiter(char c) noexcept {
    switch (c) {
        case '/':
        case '\\':
        case '-':
        case '_':
        case '.':
        case ' ':
        case ':':
        case ';':
        case ',':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '+':
        case '=':
        case '@':
            return true;
        default:
            return false;
    }
}

inline bool is_path_separator(char c) noexcept {
    return c == '/' || c == '\\';
}

inline bool char_equals(char a, char b, bool case_sensitive) noexcept {
    if (case_sensitive) {
        return a == b;
    }
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

bool determine_case_sensitivity(std::string_view pattern, FuzzyCaseSensitivity cs) noexcept {
    if (cs == FuzzyCaseSensitivity::Sensitive) {
        return true;
    }
    if (cs == FuzzyCaseSensitivity::Insensitive) {
        return false;
    }
    for (char c : pattern) {
        if (std::isupper(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

// Quick subsequence check - rejects candidates that cannot possibly match
bool quick_subsequence_check(std::string_view pattern, std::string_view candidate, bool case_sensitive) noexcept {
    if (pattern.empty()) {
        return true;
    }
    if (candidate.size() < pattern.size()) {
        return false;
    }

    size_t p_idx = 0;
    const size_t p_len = pattern.size();
    const size_t c_len = candidate.size();

    for (size_t c_idx = 0; c_idx < c_len; ++c_idx) {
        if (char_equals(pattern[p_idx], candidate[c_idx], case_sensitive)) {
            ++p_idx;
            if (p_idx == p_len) {
                return true;
            }
        }
    }
    return false;
}

// Precomputes boundary bonuses for candidate characters
std::vector<int32_t> compute_boundary_bonuses(std::string_view candidate, bool path_mode) {
    const size_t n = candidate.size();
    std::vector<int32_t> bonuses(n, 0);

    size_t last_slash = std::string_view::npos;
    if (path_mode) {
        for (size_t i = 0; i < n; ++i) {
            if (is_path_separator(candidate[i])) {
                last_slash = i;
            }
        }
    }

    for (size_t i = 0; i < n; ++i) {
        int32_t bonus = 0;
        const char curr = candidate[i];

        if (i == 0) {
            bonus += SCORE_FIRST_CHAR;
        } else {
            const char prev = candidate[i - 1];
            if (is_delimiter(prev)) {
                bonus += SCORE_BOUNDARY;
            } else if (std::islower(static_cast<unsigned char>(prev)) &&
                       std::isupper(static_cast<unsigned char>(curr))) {
                bonus += SCORE_CAMEL;
            } else if (!std::isdigit(static_cast<unsigned char>(prev)) &&
                       std::isdigit(static_cast<unsigned char>(curr))) {
                bonus += SCORE_CAMEL;
            }
        }

        if (path_mode && last_slash != std::string_view::npos && i > last_slash) {
            bonus += SCORE_PATH_BONUS;
        }

        bonuses[i] = bonus;
    }

    return bonuses;
}

inline int32_t consecutive_bonus(int32_t count) noexcept {
    if (count <= 0) return 0;
    if (count == 1) return 8;
    if (count == 2) return 12;
    if (count == 3) return 16;
    return 18;
}

} // namespace

FuzzyMatchResult fuzzy_match(
    std::string_view pattern,
    std::string_view candidate,
    const FuzzyOptions& options
) {
    if (pattern.empty()) {
        return FuzzyMatchResult{true, 0, {}};
    }
    if (candidate.empty() || candidate.size() < pattern.size()) {
        return FuzzyMatchResult{false, 0, {}};
    }

    const bool case_sensitive = determine_case_sensitivity(pattern, options.case_sensitivity);

    if (!quick_subsequence_check(pattern, candidate, case_sensitive)) {
        return FuzzyMatchResult{false, 0, {}};
    }

    const size_t m = pattern.size();
    const size_t n = candidate.size();

    // Exact match fast path
    if (m == n) {
        bool exact = true;
        for (size_t i = 0; i < m; ++i) {
            if (!char_equals(pattern[i], candidate[i], case_sensitive)) {
                exact = false;
                break;
            }
        }
        if (exact) {
            std::vector<uint32_t> indices(m);
            for (size_t i = 0; i < m; ++i) {
                indices[i] = static_cast<uint32_t>(i);
            }
            int32_t score = EXACT_MATCH_BONUS + static_cast<int32_t>(m) * (SCORE_MATCH + 10);
            return FuzzyMatchResult{true, score, std::move(indices)};
        }
    }

    std::vector<int32_t> bonuses = compute_boundary_bonuses(candidate, options.path_mode);

    // DP Tables:
    // D[i * (n + 1) + j]: best score matching pattern[0..i) with candidate[0..j)
    // M[i * (n + 1) + j]: best score matching pattern[0..i) with candidate[0..j) where candidate[j-1] matched pattern[i-1]
    // C[i * (n + 1) + j]: consecutive count at (i, j)
    const size_t stride = n + 1;
    const size_t total_cells = (m + 1) * stride;

    std::vector<int32_t> D(total_cells, NEG_INF);
    std::vector<int32_t> M(total_cells, NEG_INF);
    std::vector<int16_t> C(total_cells, 0);

    for (size_t j = 0; j <= n; ++j) {
        D[0 * stride + j] = 0;
    }

    for (size_t i = 1; i <= m; ++i) {
        const char p_char = pattern[i - 1];

        for (size_t j = 1; j <= n; ++j) {
            const char c_char = candidate[j - 1];
            const size_t idx = i * stride + j;
            const size_t prev_idx = (i - 1) * stride + (j - 1);

            if (char_equals(p_char, c_char, case_sensitive)) {
                const int32_t bonus = bonuses[j - 1];

                // Option 1: match consecutive to previous matched char
                int32_t score_m = NEG_INF;
                if (i > 1 && j > 1 && M[prev_idx] != NEG_INF) {
                    score_m = M[prev_idx] + SCORE_MATCH + consecutive_bonus(C[prev_idx]) + bonus;
                }

                // Option 2: start new match run from D[i-1][j-1]
                int32_t score_d = NEG_INF;
                if (i == 1) {
                    int32_t lead_penalty = static_cast<int32_t>(j - 1) * GAP_EXT_PENALTY;
                    if (lead_penalty < -15) lead_penalty = -15;
                    score_d = SCORE_MATCH + bonus + lead_penalty;
                } else if (D[prev_idx] != NEG_INF) {
                    score_d = D[prev_idx] + SCORE_MATCH + bonus + GAP_OPEN_PENALTY;
                }

                if (score_m >= score_d && score_m != NEG_INF) {
                    M[idx] = score_m;
                    C[idx] = static_cast<int16_t>(C[prev_idx] + 1);
                } else {
                    M[idx] = score_d;
                    C[idx] = 1;
                }
            }

            // D[i][j] is max of M[i][j] or skipping candidate[j-1]
            int32_t skip_score = NEG_INF;
            if (j > 1 && D[i * stride + (j - 1)] != NEG_INF) {
                skip_score = D[i * stride + (j - 1)] + GAP_EXT_PENALTY;
            }

            D[idx] = std::max(M[idx], skip_score);
        }
    }

    // Find best ending position in candidate
    int32_t best_score = NEG_INF;
    size_t best_j = 0;

    for (size_t j = m; j <= n; ++j) {
        if (M[m * stride + j] != NEG_INF) {
            int32_t trailing_penalty = static_cast<int32_t>(n - j) * GAP_EXT_PENALTY;
            if (trailing_penalty < -20) trailing_penalty = -20;
            int32_t score = M[m * stride + j] + trailing_penalty;
            if (score > best_score) {
                best_score = score;
                best_j = j;
            }
        }
    }

    if (best_score == NEG_INF || best_score < options.min_score) {
        return FuzzyMatchResult{false, 0, {}};
    }

    // Backtrack to extract matched indices
    std::vector<uint32_t> matched_indices;
    matched_indices.reserve(m);

    size_t curr_i = m;
    size_t curr_j = best_j;

    while (curr_i > 0 && curr_j > 0) {
        if (M[curr_i * stride + curr_j] == D[curr_i * stride + curr_j] ||
            curr_j == best_j) {
            // Matched at curr_j - 1
            matched_indices.push_back(static_cast<uint32_t>(curr_j - 1));
            --curr_i;
            --curr_j;
        } else {
            --curr_j;
        }
    }

    std::reverse(matched_indices.begin(), matched_indices.end());

    if (matched_indices.size() != m) {
        // Fallback: simple greedy reconstruction
        matched_indices.clear();
        size_t p_i = 0;
        for (size_t c_i = 0; c_i < n && p_i < m; ++c_i) {
            if (char_equals(pattern[p_i], candidate[c_i], case_sensitive)) {
                matched_indices.push_back(static_cast<uint32_t>(c_i));
                ++p_i;
            }
        }
    }

    return FuzzyMatchResult{true, best_score, std::move(matched_indices)};
}

int32_t fuzzy_score(
    std::string_view pattern,
    std::string_view candidate,
    const FuzzyOptions& options
) {
    FuzzyMatchResult res = fuzzy_match(pattern, candidate, options);
    return res.matched ? res.score : 0;
}

namespace {

template <typename CandidateType>
std::vector<FuzzyRankedResult> rank_candidates_impl(
    std::string_view pattern,
    std::span<const CandidateType> candidates,
    const FuzzyOptions& options,
    const CancellationToken* token
) {
    if (candidates.empty()) {
        return {};
    }

    const size_t total = candidates.size();

    // Determine thread count
    size_t num_threads = options.thread_count;
    if (num_threads == 0) {
        num_threads = std::max(1u, std::min(std::thread::hardware_concurrency(), 8u));
    }
    // For small batches, run sequentially to avoid thread overhead
    if (total < 256) {
        num_threads = 1;
    }

    std::vector<FuzzyRankedResult> all_results;
    all_results.reserve(std::min(total, options.max_results > 0 ? options.max_results * 2 : total));

    if (num_threads == 1) {
        for (size_t i = 0; i < total; ++i) {
            if (token && token->is_cancelled()) {
                break;
            }
            std::string_view cand_view;
            if constexpr (std::is_same_v<CandidateType, std::string>) {
                cand_view = candidates[i];
            } else {
                cand_view = candidates[i];
            }
            FuzzyMatchResult match = fuzzy_match(pattern, cand_view, options);
            if (match.matched && match.score >= options.min_score) {
                all_results.push_back(FuzzyRankedResult{
                    i,
                    std::string(cand_view),
                    match.score,
                    std::move(match.matched_indices)
                });
            }
        }
    } else {
        const size_t chunk_size = (total + num_threads - 1) / num_threads;
        std::vector<std::future<std::vector<FuzzyRankedResult>>> futures;
        futures.reserve(num_threads);

        for (size_t t = 0; t < num_threads; ++t) {
            const size_t start = t * chunk_size;
            const size_t end = std::min(start + chunk_size, total);
            if (start >= end) break;

            futures.push_back(std::async(std::launch::async, [=, &candidates]() {
                std::vector<FuzzyRankedResult> local_res;
                local_res.reserve((end - start) / 4);

                for (size_t i = start; i < end; ++i) {
                    if (token && token->is_cancelled()) {
                        break;
                    }
                    std::string_view cand_view = candidates[i];
                    FuzzyMatchResult match = fuzzy_match(pattern, cand_view, options);
                    if (match.matched && match.score >= options.min_score) {
                        local_res.push_back(FuzzyRankedResult{
                            i,
                            std::string(cand_view),
                            match.score,
                            std::move(match.matched_indices)
                        });
                    }
                }
                return local_res;
            }));
        }

        for (auto& fut : futures) {
            auto chunk_results = fut.get();
            all_results.insert(
                all_results.end(),
                std::make_move_iterator(chunk_results.begin()),
                std::make_move_iterator(chunk_results.end())
            );
        }
    }

    // Sort: highest score first; tie break on shorter length; then original index
    auto comparator = [](const FuzzyRankedResult& a, const FuzzyRankedResult& b) noexcept {
        if (a.score != b.score) {
            return a.score > b.score;
        }
        if (a.text.size() != b.text.size()) {
            return a.text.size() < b.text.size();
        }
        return a.index < b.index;
    };

    if (options.max_results > 0 && all_results.size() > options.max_results) {
        std::partial_sort(
            all_results.begin(),
            all_results.begin() + options.max_results,
            all_results.end(),
            comparator
        );
        all_results.resize(options.max_results);
    } else {
        std::sort(all_results.begin(), all_results.end(), comparator);
    }

    return all_results;
}

} // namespace

std::vector<FuzzyRankedResult> rank_candidates(
    std::string_view pattern,
    std::span<const std::string> candidates,
    const FuzzyOptions& options,
    const CancellationToken* token
) {
    return rank_candidates_impl(pattern, candidates, options, token);
}

std::vector<FuzzyRankedResult> rank_candidates(
    std::string_view pattern,
    std::span<const std::string_view> candidates,
    const FuzzyOptions& options,
    const CancellationToken* token
) {
    return rank_candidates_impl(pattern, candidates, options, token);
}

} // namespace bro::search
