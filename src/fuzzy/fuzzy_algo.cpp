// Port of fzf v0.74.4 src/algo/algo.go. Comments marked "fzf:" quote the reasoning of the
// original; structure and arithmetic are kept identical so scores agree bit for bit.
#include "fuzzy/fuzzy_algo.h"

#include <algorithm>
#include <cstring>

namespace bro::search::fuzzy_detail {

namespace {

inline int16_t max3(int16_t a, int16_t b, int16_t c) noexcept { return std::max(a, std::max(b, c)); }

// Lowercase + normalize the way V1, calculateScore and the exact matchers do (every non-ASCII
// rune is lowercased, not only class==upper as in V2's phase 2).
inline uint32_t fold_any(uint32_t c, bool case_sensitive, bool normalize) noexcept {
    if (!case_sensitive) {
        if (c >= 'A' && c <= 'Z') c += 32;
        else if (c > 127) c = to_lower(c);
    }
    if (normalize) c = normalize_rune(c);
    return c;
}

inline int32_t index_at(int32_t index, int32_t max, bool forward) noexcept {
    return forward ? index : max - index - 1;
}

int32_t try_skip(const Chars& in, bool case_sensitive, unsigned char b, int32_t from) noexcept {
    const unsigned char* p = in.bytes;
    if (!case_sensitive && b >= 'a' && b <= 'z') {
        unsigned char u = static_cast<unsigned char>(b - 32);
        for (int32_t i = from; i < in.n; ++i) {
            if (p[i] == b || p[i] == u) return i;
        }
        return -1;
    }
    if (from >= in.n) return -1;
    const void* hit = std::memchr(p + from, b, static_cast<size_t>(in.n - from));
    return hit ? static_cast<int32_t>(static_cast<const unsigned char*>(hit) - p) : -1;
}

int32_t last_index_two(const unsigned char* p, int32_t from, int32_t n, unsigned char b, bool both) noexcept {
    unsigned char u = static_cast<unsigned char>(b - 32);
    for (int32_t i = n - 1; i >= from; --i) {
        if (p[i] == b || (both && p[i] == u)) return i - from;
    }
    return -1;
}

// fzf asciiFuzzyIndex. For rune input fzf may narrow the range with a rune prefilter; that is a
// pure optimisation (it never changes a result), so rune input scans the whole text here.
bool ascii_fuzzy_index(const Chars& in, const uint32_t* pattern, int32_t m, bool case_sensitive,
                       int32_t& min_idx, int32_t& max_idx) noexcept {
    if (!in.is_bytes()) {
        min_idx = 0;
        max_idx = in.n;
        return true;
    }
    for (int32_t i = 0; i < m; ++i) {
        if (pattern[i] >= 128) return false;  // fzf: "Not possible"
    }
    int32_t first_idx = 0, idx = 0, last_idx = 0;
    unsigned char b = 0;
    for (int32_t pidx = 0; pidx < m; ++pidx) {
        b = static_cast<unsigned char>(pattern[pidx]);
        idx = try_skip(in, case_sensitive, b, idx);
        if (idx < 0) return false;
        if (pidx == 0 && idx > 0) first_idx = idx - 1;  // fzf: step back to find the right bonus point
        last_idx = idx;
        ++idx;
    }
    // fzf: find the last appearance of the last character of the pattern to limit the scope
    if (in.n - last_idx > 1) {
        bool both = !case_sensitive && b >= 'a' && b <= 'z';
        int32_t end = last_index_two(in.bytes, last_idx + 1, in.n, b, both);
        if (end >= 0) {
            min_idx = first_idx;
            max_idx = last_idx + 1 + end + 1;
            return true;
        }
    }
    min_idx = first_idx;
    max_idx = last_idx + 1;
    return true;
}

int16_t bonus_at(const Scheme& sc, const Chars& in, int32_t idx) noexcept {
    if (idx == 0) return sc.bonus_boundary_white;
    return sc.bonus_matrix[sc.class_of(in.get(idx - 1))][sc.class_of(in.get(idx))];
}

// fzf fuzzyMatchV2Single: single ASCII char on ASCII input; same result as the general path.
AlgoResult v2_single(const Scheme& sc, bool case_sensitive, bool forward, const Chars& in, unsigned char b,
                     std::vector<int32_t>* pos) {
    int16_t max_score = 0;
    int32_t max_pos = -1;
    for (int32_t idx = 0; idx < in.n;) {
        idx = try_skip(in, case_sensitive, b, idx);
        if (idx < 0) break;
        CharClass cls = sc.ascii_class[in.bytes[idx] & 0x7F];
        CharClass prev = idx > 0 ? sc.ascii_class[in.bytes[idx - 1] & 0x7F] : sc.initial_class;
        int16_t bonus = sc.bonus_matrix[prev][cls];
        int16_t score = static_cast<int16_t>(kScoreMatch + bonus * kBonusFirstCharMultiplier);
        if ((forward && score > max_score) || (!forward && score >= max_score)) {
            max_score = score;
            max_pos = idx;
            if (forward && bonus >= kBonusBoundary) break;
        }
        ++idx;
    }
    if (max_pos < 0) return {};
    if (pos) pos->push_back(max_pos);
    return {max_pos, max_pos + 1, max_score};
}

// fzf calculateScore: "Implement the same sorting criteria as V2".
int32_t calculate_score(const Scheme& sc, bool case_sensitive, bool normalize, const Chars& text,
                        const uint32_t* pattern, int32_t sidx, int32_t eidx, std::vector<int32_t>* pos) {
    int32_t pidx = 0, score = 0, consecutive = 0;
    bool in_gap = false;
    int16_t first_bonus = 0;
    CharClass prev_class = sc.initial_class;
    if (sidx > 0) prev_class = sc.class_of(text.get(sidx - 1));
    for (int32_t idx = sidx; idx < eidx; ++idx) {
        uint32_t ch = text.get(idx);
        CharClass cls = sc.class_of(ch);
        ch = fold_any(ch, case_sensitive, normalize);
        if (ch == pattern[pidx]) {
            if (pos) pos->push_back(idx);
            score += kScoreMatch;
            int16_t bonus = sc.bonus_matrix[prev_class][cls];
            if (consecutive == 0) {
                first_bonus = bonus;
            } else {
                // fzf: break consecutive chunk
                if (bonus >= kBonusBoundary && bonus > first_bonus) first_bonus = bonus;
                bonus = max3(bonus, first_bonus, kBonusConsecutive);
            }
            if (pidx == 0) score += static_cast<int16_t>(bonus * kBonusFirstCharMultiplier);
            else score += bonus;
            in_gap = false;
            ++consecutive;
            ++pidx;
        } else {
            score += in_gap ? kScoreGapExtension : kScoreGapStart;
            in_gap = true;
            consecutive = 0;
            first_bonus = 0;
        }
        prev_class = cls;
    }
    return score;
}

AlgoResult exact_match_impl(const Scheme& sc, bool case_sensitive, bool normalize, bool forward, bool boundary_check,
                            const Chars& text, const uint32_t* pattern, int32_t len_pattern) {
    if (len_pattern == 0) return {0, 0, 0};
    const int32_t len_runes = text.n;
    if (len_runes < len_pattern) return {};
    int32_t mi, ma;
    if (!ascii_fuzzy_index(text, pattern, len_pattern, case_sensitive, mi, ma)) return {};

    // fzf: "For simplicity, only look at the bonus at the first character position"
    int32_t pidx = 0, best_pos = -1;
    int16_t bonus = 0, bbonus = 0, best_bonus = -1;
    for (int32_t index = 0; index < len_runes; ++index) {
        int32_t index_ = index_at(index, len_runes, forward);
        uint32_t ch = fold_any(text.get(index_), case_sensitive, normalize);
        int32_t pidx_ = index_at(pidx, len_pattern, forward);
        bool ok = pattern[pidx_] == ch;
        if (ok) {
            if (pidx_ == 0) bonus = bonus_at(sc, text, index_);
            if (boundary_check) {
                if (forward && pidx_ == 0) {
                    bbonus = bonus;
                } else if (!forward && pidx_ == len_pattern - 1) {
                    bbonus = index_ < len_runes - 1 ? bonus_at(sc, text, index_ + 1) : sc.bonus_boundary_white;
                }
                ok = bbonus >= kBonusBoundary;
                if (ok && pidx_ == 0) ok = index_ == 0 || sc.class_of(text.get(index_ - 1)) <= kDelimiter;
                if (ok && pidx_ == len_pattern - 1)
                    ok = index_ == len_runes - 1 || sc.class_of(text.get(index_ + 1)) <= kDelimiter;
            }
        }
        if (ok) {
            ++pidx;
            if (pidx == len_pattern) {
                if (bonus > best_bonus) {
                    best_pos = index;
                    best_bonus = bonus;
                }
                if (bonus >= kBonusBoundary) break;
                index -= pidx - 1;
                pidx = 0;
                bonus = 0;
            }
        } else {
            index -= pidx;
            pidx = 0;
            bonus = 0;
        }
    }
    if (best_pos < 0) return {};
    int32_t sidx, eidx;
    if (forward) {
        sidx = best_pos - len_pattern + 1;
        eidx = best_pos + 1;
    } else {
        sidx = len_runes - (best_pos + 1);
        eidx = len_runes - (best_pos - len_pattern + 1);
    }
    int32_t score;
    if (boundary_check) {
        // fzf: underscore boundaries should be ranked lower than the other types of boundaries
        score = bonus;
        int32_t deduct = bonus - kBonusBoundary + 1;
        if (sidx > 0 && text.get(sidx - 1) == '_') {
            score -= deduct + 1;
            deduct = 1;
        }
        if (eidx < len_runes && text.get(eidx) == '_') score -= deduct;
        // fzf: add base score so that this can compete with other match types e.g. 'foo' | bar
        score += kScoreMatch * len_pattern + sc.bonus_boundary_white * (len_pattern + 1);
    } else {
        score = calculate_score(sc, case_sensitive, normalize, text, pattern, sidx, eidx, nullptr);
    }
    return {sidx, eidx, score};
}

} // namespace

int16_t Scheme::bonus_for(CharClass prev, CharClass cls) const noexcept {
    if (cls >= kNonWord) {
        switch (prev) {
            case kWhite: return bonus_boundary_white;
            case kDelimiter: return bonus_boundary_delimiter;
            case kNonWord: return kBonusBoundary;
            default: break;
        }
    }
    if ((prev == kLower && cls == kUpper) || (prev != kNumber && cls == kNumber)) return kBonusCamel123;
    switch (cls) {
        case kNonWord:
        case kDelimiter: return kBonusNonWord;
        case kWhite: return bonus_boundary_white;
        default: return 0;
    }
}

Scheme make_scheme(SchemeKind kind, bool backslash_delimiter) {
    Scheme sc;
    const char* delimiters = "/,:;|";
    switch (kind) {
        case SchemeKind::Default:
            sc.bonus_boundary_white = kBonusBoundary + 2;
            sc.bonus_boundary_delimiter = kBonusBoundary + 1;
            break;
        case SchemeKind::Path:
            sc.bonus_boundary_white = kBonusBoundary;
            sc.bonus_boundary_delimiter = kBonusBoundary + 1;
            delimiters = backslash_delimiter ? "\\/" : "/";
            sc.initial_class = kDelimiter;
            break;
        case SchemeKind::History:
            sc.bonus_boundary_white = kBonusBoundary;
            sc.bonus_boundary_delimiter = kBonusBoundary;
            break;
    }
    for (int i = 0; i < 128; ++i) {
        CharClass c = kNonWord;
        if (i >= 'a' && i <= 'z') c = kLower;
        else if (i >= 'A' && i <= 'Z') c = kUpper;
        else if (i >= '0' && i <= '9') c = kNumber;
        else if (i == ' ' || (i >= '\t' && i <= '\r')) c = kWhite;
        else if (std::strchr(delimiters, i) && i != 0) c = kDelimiter;
        sc.ascii_class[i] = c;
    }
    for (int i = 0; i <= kNumber; ++i)
        for (int j = 0; j <= kNumber; ++j)
            sc.bonus_matrix[i][j] = sc.bonus_for(static_cast<CharClass>(i), static_cast<CharClass>(j));
    return sc;
}

int32_t Chars::leading_whitespaces() const noexcept {
    int32_t w = 0;
    while (w < n && is_space(get(w))) ++w;
    return w;
}

int32_t Chars::trailing_whitespaces() const noexcept {
    int32_t w = 0;
    while (w < n && is_space(get(n - 1 - w))) ++w;
    return w;
}

AlgoResult fuzzy_match_v2(const Scheme& sc, bool case_sensitive, bool normalize, bool forward, const Chars& input,
                          const uint32_t* pattern, int32_t M, std::vector<int32_t>* pos, Slab& slab) {
    if (M == 0) return {0, 0, 0};
    int32_t N = input.n;
    if (M > N) return {};
    // fzf: O(nm) can be prohibitively expensive for large input; fall back to the greedy algorithm
    if (static_cast<int64_t>(N) * M > kSlab16Size || M > 1000)
        return fuzzy_match_v1(sc, case_sensitive, normalize, forward, input, pattern, M, pos, slab);

    if (M == 1 && input.is_bytes() && pattern[0] < 128)
        return v2_single(sc, case_sensitive, forward, input, static_cast<unsigned char>(pattern[0]), pos);

    // Phase 1. Optimized search for ASCII string
    int32_t min_idx, max_idx;
    if (!ascii_fuzzy_index(input, pattern, M, case_sensitive, min_idx, max_idx)) return {};
    N = max_idx - min_idx;

    if (slab.i16.size() < static_cast<size_t>(N) * 3) slab.i16.resize(static_cast<size_t>(N) * 3);
    if (slab.i32.size() < static_cast<size_t>(M)) slab.i32.resize(static_cast<size_t>(M));
    if (slab.t.size() < static_cast<size_t>(N)) slab.t.resize(static_cast<size_t>(N));
    int16_t* H0 = slab.i16.data();
    int16_t* C0 = H0 + N;
    int16_t* B = C0 + N;
    int32_t* F = slab.i32.data();
    uint32_t* T = slab.t.data();
    for (int32_t i = 0; i < N; ++i) T[i] = input.get(min_idx + i);

    // Phase 2. Calculate bonus for each point
    int16_t max_score = 0;
    int32_t max_score_pos = 0;
    int32_t pidx = 0, last_idx = 0;
    uint32_t pchar0 = pattern[0], pchar = pattern[0];
    int16_t prev_h0 = 0;
    CharClass prev_class = sc.initial_class;
    bool in_gap = false;
    for (int32_t off = 0; off < N; ++off) {
        uint32_t ch = T[off];
        CharClass cls;
        if (ch < 128) {
            cls = sc.ascii_class[ch];
            if (!case_sensitive && cls == kUpper) {
                ch += 32;
                T[off] = ch;
            }
        } else {
            cls = unicode_class(ch);
            if (!case_sensitive && cls == kUpper) ch = to_lower(ch);
            if (normalize) ch = normalize_rune(ch);
            T[off] = ch;
        }
        int16_t bonus = sc.bonus_matrix[prev_class][cls];
        B[off] = bonus;
        prev_class = cls;

        if (ch == pchar) {
            if (pidx < M) {
                F[pidx] = off;
                ++pidx;
                pchar = pattern[std::min(pidx, M - 1)];
            }
            last_idx = off;
        }
        if (ch == pchar0) {
            int16_t score = static_cast<int16_t>(kScoreMatch + bonus * kBonusFirstCharMultiplier);
            H0[off] = score;
            C0[off] = 1;
            if (M == 1 && ((forward && score > max_score) || (!forward && score >= max_score))) {
                max_score = score;
                max_score_pos = off;
                if (forward && bonus >= kBonusBoundary) break;
            }
            in_gap = false;
        } else {
            H0[off] = std::max<int16_t>(static_cast<int16_t>(prev_h0 + (in_gap ? kScoreGapExtension : kScoreGapStart)), 0);
            C0[off] = 0;
            in_gap = true;
        }
        prev_h0 = H0[off];
    }
    if (pidx != M) return {};
    if (M == 1) {
        if (pos) pos->push_back(min_idx + max_score_pos);
        return {min_idx + max_score_pos, min_idx + max_score_pos + 1, max_score};
    }

    // Phase 3. Fill in score matrix (H). fzf: unlike the original algorithm, no omission.
    const int32_t f0 = F[0];
    const int32_t width = last_idx - f0 + 1;
    const size_t cells = static_cast<size_t>(width) * M;
    if (slab.i16.size() < static_cast<size_t>(N) * 3 + cells * 2) {
        // Grow while preserving H0/C0/B (they live at the front).
        slab.i16.resize(static_cast<size_t>(N) * 3 + cells * 2);
        H0 = slab.i16.data();
        C0 = H0 + N;
        B = C0 + N;
    }
    int16_t* H = B + N;
    int16_t* C = H + cells;
    std::memcpy(H, H0 + f0, sizeof(int16_t) * width);
    std::memcpy(C, C0 + f0, sizeof(int16_t) * width);

    for (int32_t off = 0; off < M - 1; ++off) {
        const int32_t f = F[off + 1];
        const uint32_t pc = pattern[off + 1];
        const int32_t pi = off + 1;
        const int32_t row = pi * width;
        bool gap = false;
        const int32_t len = last_idx + 1 - f;
        const uint32_t* Tsub = T + f;
        const int16_t* Bsub = B + f;
        int16_t* Csub = C + row + f - f0;
        const int16_t* Cdiag = C + row + f - f0 - 1 - width;
        int16_t* Hsub = H + row + f - f0;
        const int16_t* Hdiag = H + row + f - f0 - 1 - width;
        int16_t* Hleft = H + row + f - f0 - 1;
        Hleft[0] = 0;
        for (int32_t k = 0; k < len; ++k) {
            const int32_t col = k + f;
            int16_t s1 = 0, s2, consecutive = 0;
            s2 = static_cast<int16_t>(Hleft[k] + (gap ? kScoreGapExtension : kScoreGapStart));
            if (pc == Tsub[k]) {
                s1 = static_cast<int16_t>(Hdiag[k] + kScoreMatch);
                int16_t b = Bsub[k];
                consecutive = static_cast<int16_t>(Cdiag[k] + 1);
                if (consecutive > 1) {
                    int16_t fb = B[col - consecutive + 1];
                    // fzf: break consecutive chunk
                    if (b >= kBonusBoundary && b > fb) consecutive = 1;
                    else b = max3(b, kBonusConsecutive, fb);
                }
                if (s1 + b < s2) {
                    s1 = static_cast<int16_t>(s1 + Bsub[k]);
                    consecutive = 0;
                } else {
                    s1 = static_cast<int16_t>(s1 + b);
                }
            }
            Csub[k] = consecutive;
            gap = s1 < s2;
            int16_t score = max3(s1, s2, 0);
            if (pi == M - 1 && ((forward && score > max_score) || (!forward && score >= max_score))) {
                max_score = score;
                max_score_pos = col;
            }
            Hsub[k] = score;
        }
    }

    // Phase 4. (Optional) Backtrace to find character positions
    int32_t j = f0;
    if (pos) {
        int32_t i = M - 1;
        j = max_score_pos;
        bool prefer_match = true;
        for (;;) {
            const int32_t I = i * width;
            const int32_t j0 = j - f0;
            const int16_t s = H[I + j0];
            int16_t s1 = 0, s2 = 0;
            if (i > 0 && j >= F[i]) s1 = H[I - width + j0 - 1];
            if (j > F[i]) s2 = H[I + j0 - 1];
            const int32_t row = i;
            if (s > s1 && (s > s2 || (s == s2 && prefer_match))) {
                pos->push_back(j + min_idx);
                if (i == 0) break;
                --i;
            }
            // fzf: row below is only written from column F[row+1]
            prefer_match = C[I + j0] > 1 ||
                           (row + 1 < M && j < last_idx && j + 1 >= F[row + 1] && C[I + width + j0 + 1] > 0);
            --j;
        }
    }
    return {min_idx + j, min_idx + max_score_pos + 1, max_score, min_idx + f0};
}

AlgoResult fuzzy_match_v1(const Scheme& sc, bool case_sensitive, bool normalize, bool forward, const Chars& text,
                          const uint32_t* pattern, int32_t len_pattern, std::vector<int32_t>* pos, Slab&) {
    if (len_pattern == 0) return {0, 0, 0};
    int32_t mi, ma;
    if (!ascii_fuzzy_index(text, pattern, len_pattern, case_sensitive, mi, ma)) return {};
    int32_t pidx = 0, sidx = -1, eidx = -1;
    const int32_t len_runes = text.n;
    for (int32_t index = 0; index < len_runes; ++index) {
        uint32_t ch = fold_any(text.get(index_at(index, len_runes, forward)), case_sensitive, normalize);
        if (ch == pattern[index_at(pidx, len_pattern, forward)]) {
            if (sidx < 0) sidx = index;
            if (++pidx == len_pattern) {
                eidx = index + 1;
                break;
            }
        }
    }
    if (sidx >= 0 && eidx >= 0) {
        --pidx;
        for (int32_t index = eidx - 1; index >= sidx; --index) {
            uint32_t ch = fold_any(text.get(index_at(index, len_runes, forward)), case_sensitive, normalize);
            if (ch == pattern[index_at(pidx, len_pattern, forward)]) {
                if (--pidx < 0) {
                    sidx = index;
                    break;
                }
            }
        }
        if (!forward) {
            int32_t s = len_runes - eidx, e = len_runes - sidx;
            sidx = s;
            eidx = e;
        }
        int32_t score = calculate_score(sc, case_sensitive, normalize, text, pattern, sidx, eidx, pos);
        return {sidx, eidx, score};
    }
    return {};
}

AlgoResult exact_match_naive(const Scheme& sc, bool cs, bool norm, bool fwd, const Chars& t, const uint32_t* p,
                             int32_t m, std::vector<int32_t>*, Slab&) {
    return exact_match_impl(sc, cs, norm, fwd, false, t, p, m);
}

AlgoResult exact_match_boundary(const Scheme& sc, bool cs, bool norm, bool fwd, const Chars& t, const uint32_t* p,
                                int32_t m, std::vector<int32_t>*, Slab&) {
    return exact_match_impl(sc, cs, norm, fwd, true, t, p, m);
}

AlgoResult prefix_match(const Scheme& sc, bool case_sensitive, bool normalize, bool, const Chars& text,
                        const uint32_t* pattern, int32_t m, std::vector<int32_t>*, Slab&) {
    if (m == 0) return {0, 0, 0};
    int32_t trimmed = 0;
    if (!is_space(pattern[0])) trimmed = text.leading_whitespaces();
    if (text.n - trimmed < m) return {};
    for (int32_t i = 0; i < m; ++i) {
        if (fold_any(text.get(trimmed + i), case_sensitive, normalize) != pattern[i]) return {};
    }
    int32_t score = calculate_score(sc, case_sensitive, normalize, text, pattern, trimmed, trimmed + m, nullptr);
    return {trimmed, trimmed + m, score};
}

AlgoResult suffix_match(const Scheme& sc, bool case_sensitive, bool normalize, bool, const Chars& text,
                        const uint32_t* pattern, int32_t m, std::vector<int32_t>*, Slab&) {
    int32_t trimmed = text.n;
    if (m == 0 || !is_space(pattern[m - 1])) trimmed -= text.trailing_whitespaces();
    if (m == 0) return {trimmed, trimmed, 0};
    int32_t diff = trimmed - m;
    if (diff < 0) return {};
    for (int32_t i = 0; i < m; ++i) {
        if (fold_any(text.get(i + diff), case_sensitive, normalize) != pattern[i]) return {};
    }
    int32_t sidx = trimmed - m;
    int32_t score = calculate_score(sc, case_sensitive, normalize, text, pattern, sidx, trimmed, nullptr);
    return {sidx, trimmed, score};
}

AlgoResult equal_match(const Scheme& sc, bool case_sensitive, bool normalize, bool, const Chars& text,
                       const uint32_t* pattern, int32_t m, std::vector<int32_t>*, Slab&) {
    if (m == 0) return {};
    int32_t trimmed = 0;
    if (!is_space(pattern[0])) trimmed = text.leading_whitespaces();
    int32_t trimmed_end = 0;
    if (!is_space(pattern[m - 1])) trimmed_end = text.trailing_whitespaces();
    if (text.n - trimmed - trimmed_end != m) return {};
    for (int32_t i = 0; i < m; ++i) {
        uint32_t ch = text.get(trimmed + i);
        if (!case_sensitive) ch = to_lower(ch);
        if (normalize) {
            if (normalize_rune(pattern[i]) != normalize_rune(ch)) return {};
        } else if (pattern[i] != ch) {
            return {};
        }
    }
    int32_t score = (kScoreMatch + sc.bonus_boundary_white) * m +
                    (kBonusFirstCharMultiplier - 1) * sc.bonus_boundary_white;
    return {trimmed, trimmed + m, score};
}

} // namespace bro::search::fuzzy_detail
