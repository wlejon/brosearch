#pragma once
// The per-buffer grep driver: finds selected lines (matching, or non-matching with invert),
// interleaves before/after context, computes spans and line numbers, honours max_count and
// cancellation. Works on one contiguous buffer; decoding and binary handling happen before.

#include "brosearch/grep.h"
#include "regex/matcher.h"

namespace bro::search::grep_detail {

struct ContentResult {
    size_t selected = 0;   // selected lines reported
    size_t matches = 0;    // match spans reported
    bool cancelled = false;
};

// count_only: the sink is never called; only counts are produced (no context, faster for -v).
ContentResult search_content(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                             const GrepOptions& o, const LineSink& sink, const CancellationToken* token,
                             bool count_only = false);

// True if any line in data[0, len) matches (Report mode, -l style questions).
bool any_match(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len, bool invert,
               const CancellationToken* token);

} // namespace bro::search::grep_detail
