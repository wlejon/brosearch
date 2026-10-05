#include "grep/searcher.h"

#include "grep/decode.h"
#include "regex/unicode.h"

#include <algorithm>
#include <cstring>

namespace bro::search::grep_detail {

namespace {

// Matches are searched in line-aligned chunks of about this size so cancellation is prompt even
// in one huge file.
// The slowest path (the PikeVM) covers 128 KiB in tens of milliseconds even unoptimized.
constexpr size_t kChunk = size_t(128) << 10;

class Driver {
public:
    Driver(const rx::Matcher& m, rx::MatcherCache& c, const uint8_t* d, size_t len, const GrepOptions& o,
           const LineSink& sink, const CancellationToken* token)
        : m_(m), c_(c), d_(d), len_(len), o_(o), sink_(sink), token_(token) {}

    // Counts selected lines (and spans when collect_spans) without reporting them.
    ContentResult count() {
        size_t pos = 0;
        const size_t limit = o_.max_count ? o_.max_count : SIZE_MAX;
        while (!stop_ && res_.selected < limit && pos < len_) {
            size_t ls = len_, le = len_;
            bool found = next_matching_line(pos, ls, le);
            if (stop_) break;
            if (!found) ls = le = len_;
            if (o_.invert) {
                // Every line in [pos, ls) is selected.
                uint64_t n = count_newlines(d_ + pos, ls - pos);
                if (ls == len_ && ls > pos && d_[len_ - 1] != '\n') ++n;
                res_.selected += static_cast<size_t>(std::min<uint64_t>(n, limit - res_.selected));
            } else if (found) {
                ++res_.selected;
                if (o_.collect_spans) {
                    compute_spans(ls, le);
                    res_.matches += spans_.size();
                }
            }
            if (!found) break;
            pos = le + 1;
        }
        return res_;
    }

    ContentResult run() {
        size_t pos = 0;
        size_t after_left = 0;
        while (!stop_) {
            size_t ls, le;
            if (!next_selected(pos, ls, le)) {
                emit_after_context(pos, len_, after_left);
                break;
            }
            pos = emit_after_context(pos, ls, after_left);
            emit_before_context(ls);
            if (stop_) break;
            emit(LineKind::Match, ls, le);
            ++res_.selected;
            pos = le + 1;
            after_left = o_.after_context;
            if (o_.max_count && res_.selected >= o_.max_count) {
                // rg still prints the trailing context, showing selected lines in it as matches.
                trailing_ = true;
                emit_after_context(pos, len_, after_left);
                break;
            }
        }
        return res_;
    }

private:
    const rx::Matcher& m_;
    rx::MatcherCache& c_;
    const uint8_t* d_;
    size_t len_;
    const GrepOptions& o_;
    const LineSink& sink_;
    const CancellationToken* token_;
    ContentResult res_;
    bool stop_ = false;
    bool trailing_ = false;  // emitting the context after max_count was reached

    size_t count_pos_ = 0;
    uint64_t count_lines_ = 0;
    size_t emitted_end_ = 0;
    std::vector<GrepSpan> spans_;

    // Invert bookkeeping: the next matching line at or after the cursor.
    bool have_next_match_ = false;
    size_t next_match_ls_ = 0, next_match_le_ = 0;

    size_t line_end(size_t pos) const {
        if (pos >= len_) return len_;
        const void* nl = std::memchr(d_ + pos, '\n', len_ - pos);
        return nl ? static_cast<size_t>(static_cast<const uint8_t*>(nl) - d_) : len_;
    }
    size_t line_start(size_t lo, size_t pos) const {
        while (pos > lo && d_[pos - 1] != '\n') --pos;
        return pos;
    }

    bool cancelled() {
        if (token_ && token_->is_cancelled()) {
            res_.cancelled = true;
            stop_ = true;
            return true;
        }
        return false;
    }

    // Position inside the next line (at or after `pos`, a line start) containing a match.
    bool next_match_pos(size_t pos, size_t& out) {
        while (pos < len_) {
            if (cancelled()) return false;
            size_t chunk_end = len_;
            if (len_ - pos > kChunk) {
                const void* nl = std::memchr(d_ + pos + kChunk, '\n', len_ - pos - kChunk);
                if (nl) chunk_end = static_cast<size_t>(static_cast<const uint8_t*>(nl) - d_);
            }
            if (auto p = m_.find_line(c_, d_, len_, pos, chunk_end)) {
                if (*p >= len_) return false;  // empty match at EOF after a final '\n': no line there
                out = *p;
                return true;
            }
            pos = chunk_end + 1;
        }
        return false;
    }

    bool next_matching_line(size_t pos, size_t& ls, size_t& le) {
        size_t p;
        if (!next_match_pos(pos, p)) return false;
        ls = line_start(pos, p);
        le = line_end(p);
        return true;
    }

    bool next_selected(size_t pos, size_t& ls, size_t& le) {
        if (!o_.invert) return next_matching_line(pos, ls, le);
        for (;;) {
            if (pos >= len_ || stop_) return false;
            if (!have_next_match_ || next_match_ls_ < pos) {
                if (!next_matching_line(pos, next_match_ls_, next_match_le_)) {
                    if (stop_) return false;
                    next_match_ls_ = next_match_le_ = SIZE_MAX;
                }
                have_next_match_ = true;
            }
            if (next_match_ls_ > pos) {
                ls = pos;
                le = line_end(pos);
                return true;
            }
            pos = next_match_le_ + 1;
            have_next_match_ = false;
        }
    }

    uint64_t line_number(size_t ls) {
        if (!o_.line_numbers) return 0;
        if (ls > count_pos_) {
            count_lines_ += count_newlines(d_ + count_pos_, ls - count_pos_);
            count_pos_ = ls;
        }
        return count_lines_ + 1;
    }

    void compute_spans(size_t ls, size_t le) {
        spans_.clear();
        size_t pos = ls;
        size_t last_end = SIZE_MAX;
        auto next_boundary = [&](size_t p) {
            if (p >= le) return p + 1;
            uint32_t cp;
            size_t k = o_.unicode ? rx::decode_utf8(d_ + p, d_ + le, &cp) : 0;
            return p + (k ? k : 1);
        };
        while (pos <= le) {
            auto mm = m_.find(c_, d_, len_, pos, le);
            if (!mm) break;
            if (mm->start == mm->end && mm->end == last_end) {
                pos = next_boundary(pos);
                continue;
            }
            spans_.push_back({mm->start - ls, mm->end - ls});
            last_end = mm->end;
            pos = mm->end > mm->start ? mm->end : next_boundary(mm->end);
        }
    }

    void emit(LineKind kind, size_t ls, size_t le) {
        GrepLineView v;
        v.kind = kind;
        v.line_number = line_number(ls);
        v.byte_offset = ls;
        v.text = std::string_view(reinterpret_cast<const char*>(d_ + ls), le - ls);
        if (kind == LineKind::Match && !o_.invert && o_.collect_spans) {
            compute_spans(ls, le);
            res_.matches += spans_.size();
            v.spans = std::span<const GrepSpan>(spans_.data(), spans_.size());
        }
        emitted_end_ = le + 1;
        if (!sink_(v)) stop_ = true;
    }

    size_t emit_after_context(size_t pos, size_t limit, size_t& left) {
        while (left > 0 && pos < limit && pos < len_ && !stop_) {
            size_t le = line_end(pos);
            LineKind kind = LineKind::Context;
            if (trailing_ && m_.find(c_, d_, len_, pos, le).has_value() != o_.invert) kind = LineKind::Match;
            emit(kind, pos, le);
            --left;
            pos = le + 1;
        }
        return pos;
    }

    void emit_before_context(size_t ls) {
        if (o_.before_context == 0 || ls == 0) return;
        size_t s = ls;
        for (size_t k = 0; k < o_.before_context; ++k) {
            if (s <= emitted_end_ || s == 0) break;
            s = line_start(emitted_end_, s - 1);
        }
        if (s < emitted_end_) s = emitted_end_;
        while (s < ls && !stop_) {
            size_t le = line_end(s);
            emit(LineKind::Context, s, le);
            s = le + 1;
        }
    }
};

} // namespace

ContentResult search_content(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                             const GrepOptions& o, const LineSink& sink, const CancellationToken* token,
                             bool count_only) {
    Driver d(m, cache, data, len, o, sink, token);
    return count_only ? d.count() : d.run();
}

bool any_match(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len, bool invert,
               const CancellationToken* token) {
    GrepOptions o;
    o.invert = invert;
    o.line_numbers = false;
    o.collect_spans = false;
    bool found = false;
    LineSink sink = [&](const GrepLineView&) {
        found = true;
        return false;
    };
    search_content(m, cache, data, len, o, sink, token);
    return found;
}

} // namespace bro::search::grep_detail
