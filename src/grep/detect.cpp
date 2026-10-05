// Terminal helpers built on the regex engine.

#include "brosearch/grep.h"
#include "grep/decode.h"

namespace bro::search {

namespace {

std::vector<TextMatch> detect(const Regex& re, std::string_view text) {
    std::vector<TextMatch> out;
    size_t counted_pos = 0;
    size_t line = 1;
    for (auto m : re.find_all(text)) {
        if (m.end == m.start) continue;
        line += grep_detail::count_newlines(reinterpret_cast<const uint8_t*>(text.data()) + counted_pos,
                                            m.start - counted_pos);
        counted_pos = m.start;
        size_t nl = m.start ? text.rfind('\n', m.start - 1) : std::string_view::npos;
        size_t ls = nl == std::string_view::npos ? 0 : nl + 1;
        out.push_back(TextMatch{line, m.start - ls + 1, m.start, m.end - m.start});
    }
    return out;
}

std::shared_ptr<const Regex> make(std::string_view pattern) {
    RegexOptions o;
    o.multi_line = true;
    o.line_mode = true;
    return Regex::compile(pattern, o);
}

} // namespace

std::vector<TextMatch> detect_urls(std::string_view text) {
    // Scheme, then URL characters; a trailing '.', ',', ')' etc. is excluded unless balanced text
    // follows, which is what terminals commonly do.
    static const auto re = make(R"((?:https?|ftp|file)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*[A-Za-z0-9\-_~/#@$&*+=%])");
    return re ? detect(*re, text) : std::vector<TextMatch>{};
}

std::vector<TextMatch> detect_git_hashes(std::string_view text) {
    static const auto re = make(R"(\b[0-9a-f]{7,40}\b)");
    return re ? detect(*re, text) : std::vector<TextMatch>{};
}

} // namespace bro::search
