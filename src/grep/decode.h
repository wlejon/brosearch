#pragma once
// Text decoding helpers for grep: BOM sniffing, UTF-16 -> UTF-8 transcoding (WHATWG-style:
// unpaired surrogates and a dangling odd byte become U+FFFD), fast newline counting.

#include <cstddef>
#include <cstdint>
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
size_t rg_binary_cutoff(const uint8_t* d, size_t len, size_t nul);

} // namespace bro::search::grep_detail
