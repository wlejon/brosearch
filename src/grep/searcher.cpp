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
           const LineSink& sink, const CancellationToken* token, const BinaryGuard* guard)
        : m_(m), c_(c), d_(d), len_(len), o_(o), sink_(sink), token_(token), guard_(guard) {}

    // Counts selected lines (and spans when collect_spans) without reporting them.
    ContentResult count() {
        size_t pos = 0;
        const size_t limit = limit_selected() ? o_.max_count : SIZE_MAX;
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
                res_.selected += o_.multiline ? region_.size() : 1;
                if (o_.collect_spans) {
                    if (o_.multiline) {
                        res_.matches += region_.size();
                    } else {
                        compute_spans(ls, le);
                        res_.matches += spans_.size();
                    }
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
            if (!admit(ls, le, true)) break;
            if (o_.multiline && !o_.invert) {
                emit_region(ls, le);
                res_.selected += region_.size();
            } else {
                emit(LineKind::Match, ls, le);
                ++res_.selected;
            }
            if (last_) break;
            pos = le + 1;
            after_left = o_.after_context;
            if (limit_selected() && res_.selected >= o_.max_count) {
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
    const BinaryGuard* guard_;
    ContentResult res_;
    bool stop_ = false;
    bool suppress_ = false;  // Report-mode binary data seen: count, but report nothing more
    bool last_ = false;      // Report mode, reporting: the selected lines being admitted end it

    // BinaryGuard: may the lines [ls, le) be reported? Records the first NUL among them. In
    // Report mode a counting search goes on silently; a reporting one ends like rg's standard
    // printer, which stops at that point, counting the lines only if they are a match.
    bool admit(size_t ls, size_t le, bool is_match) {
        if (!guard_ || res_.binary_hit || le <= ls) return !stop_;
        if (const void* z = std::memchr(d_ + ls, 0, std::min(le, len_) - ls)) {
            res_.binary_hit = true;
            res_.binary_offset = static_cast<size_t>(static_cast<const uint8_t*>(z) - d_);
            res_.binary_stop = ls;
            suppress_ = true;
            if (guard_->quit || (!guard_->counting && !is_match)) stop_ = true;
            else if (!guard_->counting) last_ = true;
        }
        return !stop_;
    }
    bool report(const GrepLineView& v) { return suppress_ || sink_(v); }
    bool trailing_ = false;  // emitting the context after max_count was reached

    size_t count_pos_ = 0;
    uint64_t count_lines_ = 0;
    size_t emitted_end_ = 0;
    std::vector<GrepSpan> spans_;

    // Invert bookkeeping: the next matching line at or after the cursor.
    bool have_next_match_ = false;
    size_t next_match_ls_ = 0, next_match_le_ = 0;

    // Multiline: the matches of the current region (absolute offsets).
    std::vector<rx::MatchSpan> region_;
    size_t inverted_matches_ = 0;  // multiline invert: matches found so far (max_count)
    // Multiline invert treats max_count as a limit on matches, not on selected lines.
    bool limit_selected() const { return o_.max_count && !(o_.multiline && o_.invert); }

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

    size_t next_boundary(size_t p, size_t limit) const {
        if (p >= limit) return p + 1;
        uint32_t cp;
        size_t k = o_.unicode ? rx::decode_utf8(d_ + p, d_ + limit, &cp) : 0;
        return p + (k ? k : 1);
    }

    // Multiline: the next region at or after `pos` (a line start): the lines [ls, le] touched by
    // a run of matches, each starting on a line the previous ones reached. Its matches are left
    // in region_.
    bool next_region(size_t pos, size_t& ls, size_t& le) {
        region_.clear();
        if (o_.invert && o_.max_count && inverted_matches_ >= o_.max_count) return false;
        const bool found = find_region(pos, ls, le);
        if (o_.invert) inverted_matches_ += region_.size();
        return found;
    }

    bool find_region(size_t pos, size_t& ls, size_t& le) {
        size_t search = pos;
        size_t last_end = SIZE_MAX;
        bool have = false;
        while (search <= len_) {
            if (cancelled()) return false;
            auto mm = m_.find(c_, d_, len_, search, len_);
            if (!mm) break;
            // An empty match at the end of input after a final '\n' is on no line.
            if (mm->start == mm->end && mm->start == len_ && (len_ == 0 || d_[len_ - 1] == '\n')) break;
            if (mm->start == mm->end && mm->end == last_end) {
                search = next_boundary(search, len_);
                continue;
            }
            const size_t mls = line_start(pos, mm->start);
            const size_t last = mm->end > mm->start ? mm->end - 1 : mm->start;
            const size_t mle = line_end(last);
            if (!have) {
                ls = mls;
                le = mle;
                have = true;
            } else if (mls <= le + 1) {
                le = std::max(le, mle);  // overlapping or adjacent lines: one block, as in rg
            } else {
                break;  // starts past the block: the next search finds it again
            }
            region_.push_back(*mm);
            // max_count counts matches here: a block can end early. Inverted, rg stops matching
            // after max_count matches and selects every line after them.
            if (o_.max_count) {
                const size_t done = o_.invert ? inverted_matches_ : res_.selected;
                if (done + region_.size() >= o_.max_count) break;
            }
            last_end = mm->end;
            search = mm->end > mm->start ? mm->end : next_boundary(mm->end, len_);
        }
        return have;
    }

    // Reports the lines of a multiline region with their pieces of its matches.
    void emit_region(size_t ls, size_t le) {
        size_t a = ls;
        bool first = true;
        while (a <= le && a <= len_ && !stop_) {
            const size_t b = line_end(a);
            spans_.clear();
            if (o_.collect_spans) {
                for (const auto& mm : region_) {
                    if (mm.end < a || mm.start > b) continue;
                    if (mm.start < a && mm.end <= a) continue;  // ended at this line's start
                    const size_t s = std::max(mm.start, a), e = std::min(mm.end, b);
                    if (s == e && mm.start != mm.end) continue;  // only the line terminator
                    if (spans_.size() == o_.max_spans_per_line && o_.max_spans_per_line) break;
                    spans_.push_back({s - a, e - a, mm.start < a});
                }
            }
            GrepLineView v;
            v.kind = LineKind::Match;
            v.line_number = line_number(a);
            v.byte_offset = a;
            v.text = std::string_view(reinterpret_cast<const char*>(d_ + a), b - a);
            v.spans = std::span<const GrepSpan>(spans_.data(), spans_.size());
            v.region_continued = !first;
            emitted_end_ = b + 1;
            if (!report(v)) stop_ = true;
            first = false;
            if (b >= len_) break;
            a = b + 1;
        }
        if (o_.collect_spans) res_.matches += region_.size();
    }

    bool next_matching_line(size_t pos, size_t& ls, size_t& le) {
        if (o_.multiline) return next_region(pos, ls, le);
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

    void compute_spans(size_t ls, size_t le, size_t max_spans = 0) {
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
            spans_.push_back({mm->start - ls, mm->end - ls, false});
            if (spans_.size() == max_spans) break;
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
            compute_spans(ls, le, o_.max_spans_per_line);
            res_.matches += spans_.size();
            v.spans = std::span<const GrepSpan>(spans_.data(), spans_.size());
        }
        emitted_end_ = le + 1;
        if (!report(v)) stop_ = true;
    }

    size_t emit_after_context(size_t pos, size_t limit, size_t& left) {
        while (left > 0 && pos < limit && pos < len_ && !stop_) {
            size_t le = line_end(pos);
            if (!admit(pos, le, false)) break;
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
            if (!admit(s, le, false)) break;
            emit(LineKind::Context, s, le);
            s = le + 1;
        }
    }
};

} // namespace

ContentResult search_content(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                             const GrepOptions& o, const LineSink& sink, const CancellationToken* token,
                             bool count_only, const BinaryGuard* guard) {
    if (guard && count_only) {
        // The guard needs every selected line's extent; the reporting path has them.
        static const LineSink kNone = [](const GrepLineView&) { return true; };
        BinaryGuard g = *guard;
        g.counting = true;
        Driver d(m, cache, data, len, o, kNone, token, &g);
        return d.run();
    }
    Driver d(m, cache, data, len, o, sink, token, guard);
    return count_only ? d.count() : d.run();
}

std::optional<size_t> first_selected(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                                     bool invert, const CancellationToken* token) {
    GrepOptions o;
    o.invert = invert;
    o.line_numbers = false;
    o.collect_spans = false;
    std::optional<size_t> found;
    LineSink sink = [&](const GrepLineView& v) {
        found = static_cast<size_t>(v.byte_offset);
        return false;
    };
    search_content(m, cache, data, len, o, sink, token, false, nullptr);
    return found;
}

} // namespace bro::search::grep_detail
