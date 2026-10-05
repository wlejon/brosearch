#pragma once
// Unicode helpers for the fzf port: the exact subset of Go's `unicode` package that fzf's
// matcher consults (Unicode 15.0.0, as shipped with the Go toolchain fzf is built with).

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search::fuzzy_detail {

// Mirrors fzf's charClass enum; the order matters (comparisons like `class >= NonWord`).
enum CharClass : uint8_t {
    kWhite = 0,
    kNonWord = 1,
    kDelimiter = 2,
    kLower = 3,
    kUpper = 4,
    kLetter = 5,
    kNumber = 6,
};

// Class of a non-ASCII code point ignoring delimiters (fzf's delimiter set is ASCII-only).
CharClass unicode_class(uint32_t r) noexcept;

// unicode.ToLower (simple mapping).
uint32_t to_lower(uint32_t r) noexcept;

// unicode.IsSpace.
bool is_space(uint32_t r) noexcept;

// unicode.IsUpper / IsLower for non-ASCII (used by the pattern parser's smart case).
inline bool is_upper(uint32_t r) noexcept {
    if (r < 0x80) return r >= 'A' && r <= 'Z';
    return unicode_class(r) == kUpper;
}

// fzf's normalizeRune: Latin letters with diacritics (and a few look-alikes) to ASCII.
uint32_t normalize_rune(uint32_t r) noexcept;

// Decodes UTF-8 the way Go's utf8.DecodeRune does: every invalid byte becomes U+FFFD and
// consumes exactly one byte. Returns the code point and writes its byte length to *len.
uint32_t decode_utf8(const unsigned char* p, size_t avail, size_t* len) noexcept;

// Appends runes (and, if offsets != nullptr, the byte offset of each rune) to out.
void decode_runes(std::string_view s, std::vector<uint32_t>& out, std::vector<uint32_t>* offsets);

// Encodes a code point as UTF-8 (U+FFFD for invalid values).
void append_utf8(std::string& out, uint32_t r);

} // namespace bro::search::fuzzy_detail
