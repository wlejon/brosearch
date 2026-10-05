#pragma once
// Unicode support for the regex engine: UTF-8 coding, simple case folding, Perl classes and
// general categories (tables generated from the UCD by tools/gen_unicode.cpp).

#include "regex/charset.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bro::search::rx {

// Decodes one scalar value. Returns the byte length consumed (1..4), or 0 if the bytes at p are
// not a valid UTF-8 sequence (in which case *cp is untouched and callers treat one byte as opaque).
size_t decode_utf8(const uint8_t* p, const uint8_t* end, uint32_t* cp);
// Decodes the scalar value ending right before `end` (start bound `begin`). Same return contract.
size_t decode_utf8_last(const uint8_t* begin, const uint8_t* end, uint32_t* cp);
size_t encode_utf8(uint32_t cp, uint8_t out[4]);

// Adds every code point that is simple-case-fold-equivalent to a member of `set`.
void add_case_fold_closure(CharSet& set);
// True if `cp` has any case-fold equivalents other than itself.
bool has_case_variants(uint32_t cp);
// True if cp is Uppercase_Letter (used by smart case).
bool is_uppercase(uint32_t cp);

CharSet perl_word(bool unicode);
CharSet perl_digit(bool unicode);
CharSet perl_space(bool unicode);
bool is_word_codepoint(uint32_t cp);
inline bool is_word_byte(uint8_t b) {
    return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_';
}

// \p{name}: general categories by short or long name (L, Letter, Lu, Uppercase_Letter, ...),
// plus Any, ASCII and Assigned. Names compare loosely (case, spaces, '_' and '-' ignored).
bool unicode_property(std::string_view name, CharSet* out);

// POSIX [:name:] classes (ASCII only, as in regex-syntax).
bool posix_class(std::string_view name, CharSet* out);

} // namespace bro::search::rx
