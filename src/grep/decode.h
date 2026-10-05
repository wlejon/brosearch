#pragma once
// Text decoding helpers for grep: BOM sniffing, UTF-16 -> UTF-8 transcoding (WHATWG-style:
// unpaired surrogates and a dangling odd byte become U+FFFD), fast newline counting.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace bro::search::grep_detail {

enum class Bom : uint8_t { None, Utf8, Utf16LE, Utf16BE };

Bom sniff_bom(std::string_view data);

// Transcodes UTF-16 code units (BOM already removed) to UTF-8, appending to `out`.
void transcode_utf16(const uint8_t* p, size_t n, bool little_endian, std::string& out);

// Number of '\n' bytes in [p, p + n).
uint64_t count_newlines(const uint8_t* p, size_t n);

// ripgrep reads files through a 64 KiB line buffer (tripling when one line does not fit) and
// checks each newly read block for NUL before searching it. When the block holding the first NUL
// arrives, only the complete lines from earlier blocks have been searched. Returns that prefix
// length, so a NUL at `nul` reproduces rg's output exactly.
//
// With context (`context` set), rg keeps lines across each buffer roll: the last
// `before_context` + 1 complete lines, or everything after the last line it reported while
// searching that block, whichever starts later. Kept bytes shrink the next read, which moves
// the block boundaries. visited(lo, hi) returns the end (after its '\n') of the last line reported
// while the lines starting in [lo, hi) were searched, or 0 when none was.
struct CutoffContext {
    size_t before_context = 0;
    std::function<size_t(size_t lo, size_t hi)> visited;
};
size_t rg_binary_cutoff(const uint8_t* d, size_t len, size_t nul, const CutoffContext* context = nullptr);

} // namespace bro::search::grep_detail
