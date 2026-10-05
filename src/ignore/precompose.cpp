// NFD -> NFC precomposition of file names, git's core.precomposeUnicode (compat/precompose_utf8.c).
// macOS only, like git: HFS+ stores names decomposed and Cocoa's file APIs write them that way on
// APFS too, while both compare names normalization-insensitively. Everywhere else two
// normalizations are two different names, so nothing is converted.

#include "ignore/git_repo.h"

#if defined(__APPLE__)
#include <iconv.h>
#endif

namespace bro::search::detail {

#if defined(__APPLE__)

namespace {

// One converter per thread: iconv descriptors carry shift state and are not thread-safe.
struct MacToUtf8 {
    iconv_t cd = iconv_open("UTF-8", "UTF-8-MAC");
    MacToUtf8() = default;
    MacToUtf8(const MacToUtf8&) = delete;
    MacToUtf8& operator=(const MacToUtf8&) = delete;
    ~MacToUtf8() {
        if (cd != reinterpret_cast<iconv_t>(-1)) iconv_close(cd);
    }
};

} // namespace

bool precompose_utf8(std::string_view in, std::string& out) {
    bool ascii = true;
    for (unsigned char c : in) {
        if (c >= 0x80) {
            ascii = false;
            break;
        }
    }
    if (ascii) return false;
    thread_local MacToUtf8 conv;
    if (conv.cd == reinterpret_cast<iconv_t>(-1)) return false;
    iconv(conv.cd, nullptr, nullptr, nullptr, nullptr);  // reset shift state
    std::string buf(in.size() * 3 + 16, '\0');  // composition never grows a UTF-8 string
    char* src = const_cast<char*>(in.data());
    size_t src_left = in.size();
    char* dst = buf.data();
    size_t dst_left = buf.size();
    if (iconv(conv.cd, &src, &src_left, &dst, &dst_left) == static_cast<size_t>(-1) || src_left != 0)
        return false;  // ill-formed UTF-8: keep the bytes, as git does
    buf.resize(buf.size() - dst_left);
    if (buf == in) return false;
    out = std::move(buf);
    return true;
}

#else

bool precompose_utf8(std::string_view, std::string&) { return false; }

#endif

} // namespace bro::search::detail
