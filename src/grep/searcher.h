#pragma once
// The per-buffer grep driver: finds selected lines (matching, or non-matching with invert),
// interleaves before/after context, computes spans and line numbers, honours max_count and
// cancellation. Works on one contiguous buffer; decoding and binary handling happen before.

#include "brosearch/grep.h"
#include "regex/matcher.h"

#include <optional>

namespace bro::search::grep_detail {

struct ContentResult {
    size_t selected = 0;   // selected lines reported
    size_t matches = 0;    // match spans reported
    bool cancelled = false;
    bool binary_hit = false;     // a reported line held a NUL (BinaryGuard)
    size_t binary_offset = 0;    // where
    size_t binary_stop = 0;      // start of the lines that held it
};

// rg's lazy binary detection for whole-buffer (multiline) searches: only the lines about to be
// reported (match blocks and context) are checked for a NUL. quit: stop there (rg's Quit mode).
// Report mode: a counting search goes on silently; a reporting one stops there, counting the
// lines only if they are a match (rg's standard printer). counting is set by search_content.
struct BinaryGuard {
    bool quit = false;
    bool counting = false;
};

// count_only: the sink is never called; only counts are produced (no context, faster for -v).
ContentResult search_content(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                             const GrepOptions& o, const LineSink& sink, const CancellationToken* token,
                             bool count_only = false, const BinaryGuard* guard = nullptr);

// Start of the first selected line in data[0, len) (matching, or not matching with invert).
std::optional<size_t> first_selected(const rx::Matcher& m, rx::MatcherCache& cache, const uint8_t* data, size_t len,
                                     bool invert, const CancellationToken* token);

} // namespace bro::search::grep_detail
