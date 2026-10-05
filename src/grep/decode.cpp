#include "grep/decode.h"

#include <algorithm>
#include <bit>
#include <cstring>

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define BROSEARCH_SSE2 1
#include <emmintrin.h>
#endif

namespace bro::search::grep_detail {

Bom sniff_bom(std::string_view d) {
    if (d.size() >= 3 && static_cast<uint8_t>(d[0]) == 0xEF && static_cast<uint8_t>(d[1]) == 0xBB &&
        static_cast<uint8_t>(d[2]) == 0xBF)
        return Bom::Utf8;
    if (d.size() >= 2 && static_cast<uint8_t>(d[0]) == 0xFF && static_cast<uint8_t>(d[1]) == 0xFE) return Bom::Utf16LE;
    if (d.size() >= 2 && static_cast<uint8_t>(d[0]) == 0xFE && static_cast<uint8_t>(d[1]) == 0xFF) return Bom::Utf16BE;
    return Bom::None;
}

namespace {

void put_utf8(uint32_t cp, std::string& out) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

} // namespace

void transcode_utf16(const uint8_t* p, size_t n, bool le, std::string& out) {
    out.reserve(out.size() + n + n / 2);
    auto unit = [&](size_t i) -> uint32_t {
        return le ? static_cast<uint32_t>(p[i] | (p[i + 1] << 8)) : static_cast<uint32_t>((p[i] << 8) | p[i + 1]);
    };
    size_t i = 0;
    while (i + 1 < n) {
        uint32_t u = unit(i);
        i += 2;
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 1 < n) {
                uint32_t v = unit(i);
                if (v >= 0xDC00 && v <= 0xDFFF) {
                    i += 2;
                    put_utf8(0x10000 + ((u - 0xD800) << 10) + (v - 0xDC00), out);
                    continue;
                }
            }
            put_utf8(0xFFFD, out);
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            put_utf8(0xFFFD, out);
        } else {
            put_utf8(u, out);
        }
    }
    if (i < n) put_utf8(0xFFFD, out);
}

uint64_t count_newlines(const uint8_t* p, size_t n) {
    uint64_t count = 0;
    const uint8_t* end = p + n;
#ifdef BROSEARCH_SSE2
    const __m128i nl = _mm_set1_epi8('\n');
    while (end - p >= 64) {
        __m128i a = _mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p)), nl);
        __m128i b = _mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16)), nl);
        __m128i c = _mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 32)), nl);
        __m128i d = _mm_cmpeq_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 48)), nl);
        uint64_t m = static_cast<uint32_t>(_mm_movemask_epi8(a)) | (static_cast<uint64_t>(static_cast<uint32_t>(_mm_movemask_epi8(b))) << 16) |
                     (static_cast<uint64_t>(static_cast<uint32_t>(_mm_movemask_epi8(c))) << 32) |
                     (static_cast<uint64_t>(static_cast<uint32_t>(_mm_movemask_epi8(d))) << 48);
        count += static_cast<uint64_t>(std::popcount(m));
        p += 64;
    }
#endif
    for (; p < end; ++p) count += *p == '\n';
    return count;
}

size_t rg_binary_cutoff(const uint8_t* d, size_t len, size_t nul, const CutoffContext* context) {
    size_t cap = size_t(64) << 10;
    size_t consumed = 0;   // buffer start: bytes before it were rolled out
    size_t searched = 0;   // complete lines before this have been searched
    size_t read_end = 0;
    for (;;) {
        if (read_end - consumed == cap) cap *= 3;  // buffer full of one partial line: grow
        size_t next = std::min(len, read_end + (cap - (read_end - consumed)));
        // rg's BOM-sniffing reader hands back the (up to 3) peeked bytes as the first read.
        if (read_end == 0) next = std::min<size_t>(len, 3);
        if (nul >= read_end && nul < next) return searched;
        read_end = next;
        if (read_end >= len) return len;
        // Search the complete lines in the buffer (through its last '\n'), then roll.
        size_t last = 0;
        for (size_t i = read_end; i > consumed; --i) {
            if (d[i - 1] == '\n') {
                last = i;
                break;
            }
        }
        if (last == 0 || last <= searched) continue;
        const size_t from = searched;
        searched = last;
        if (!context) {
            consumed = last;
            continue;
        }
        // Start of the line before_context lines before the buffer's last line.
        size_t keep = last - 1;  // on the last line's '\n'
        for (size_t k = 0;; ++k) {
            while (keep > consumed && d[keep - 1] != '\n') --keep;
            if (k == context->before_context || keep == consumed) break;
            --keep;  // onto the previous line's '\n'
        }
        consumed = std::max({consumed, keep, context->visited(from, last)});
    }
}

} // namespace bro::search::grep_detail
