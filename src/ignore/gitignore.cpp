// gitignore rule parsing and matching (git dir.c semantics) plus the IgnoreFilter rule stack.

#include "brosearch/ignore.h"

#include "ignore/git_repo.h"
#include "ignore/rg_glob.h"

#include <algorithm>

namespace fs = std::filesystem;

namespace bro::search {

namespace {

inline char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

bool equals(std::string_view a, std::string_view b, bool icase) {
    if (a.size() != b.size()) return false;
    if (!icase) return a == b;
    for (size_t i = 0; i < a.size(); ++i)
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    return true;
}

bool has_glob_special(std::string_view s) { return s.find_first_of("*?[\\") != std::string_view::npos; }

// git's trim_trailing_spaces(): drop trailing ' ' unless escaped by a backslash.
void trim_trailing_spaces(std::string& s) {
    size_t last_space = std::string::npos;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == ' ') {
            if (last_space == std::string::npos) last_space = i;
        } else if (c == '\\') {
            ++i;
            if (i >= s.size()) return;
            last_space = std::string::npos;
        } else {
            last_space = std::string::npos;
        }
    }
    if (last_space != std::string::npos) s.resize(last_space);
}

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

bool valid_utf8(std::string_view s) {
    size_t i = 0;
    while (i < s.size()) {
        const auto b = static_cast<unsigned char>(s[i]);
        if (b < 0x80) {
            ++i;
            continue;
        }
        size_t n = (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 0;
        if (n == 0 || i + n > s.size()) return false;
        uint32_t cp = n == 2 ? (b & 0x1F) : n == 3 ? (b & 0x0F) : (b & 0x07);
        for (size_t k = 1; k < n; ++k) {
            const auto c = static_cast<unsigned char>(s[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += n;
    }
    return true;
}

// Rust's str::trim_end: drops trailing White_Space characters (the line is valid UTF-8).
std::string_view trim_end_unicode_space(std::string_view s) {
    for (;;) {
        if (s.empty()) return s;
        const auto b = static_cast<unsigned char>(s.back());
        if (b < 0x80) {
            if (b == ' ' || (b >= '\t' && b <= '\r')) {
                s.remove_suffix(1);
                continue;
            }
            return s;
        }
        size_t start = s.size() - 1;
        while (start > 0 && (static_cast<unsigned char>(s[start]) & 0xC0) == 0x80) --start;
        uint32_t cp = 0;
        const auto lead = static_cast<unsigned char>(s[start]);
        const size_t n = s.size() - start;
        cp = n == 2 ? (lead & 0x1F) : n == 3 ? (lead & 0x0F) : (lead & 0x07);
        for (size_t k = start + 1; k < s.size(); ++k) cp = (cp << 6) | (static_cast<unsigned char>(s[k]) & 0x3F);
        const bool ws = cp == 0x85 || cp == 0xA0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A) ||
                        cp == 0x2028 || cp == 0x2029 || cp == 0x202F || cp == 0x205F || cp == 0x3000;
        if (!ws) return s;
        s.remove_suffix(n);
    }
}

std::string path_to_utf8(const fs::path& p) {
    auto u = p.generic_u8string();
    return std::string(u.begin(), u.end());
}

std::string normalize_base(std::string_view b) {
    std::string s(b);
#ifdef _WIN32
    std::replace(s.begin(), s.end(), '\\', '/');
#endif
    while (s.rfind("./", 0) == 0) s.erase(0, 2);
    while (!s.empty() && s.front() == '/') s.erase(0, 1);
    while (!s.empty() && s.back() == '/') s.pop_back();
    if (s == ".") s.clear();
    return s;
}

size_t depth_of(std::string_view base) {
    return base.empty() ? 0 : 1 + static_cast<size_t>(std::count(base.begin(), base.end(), '/'));
}

} // namespace

bool rg_glob_match(std::string_view glob, std::string_view text, bool case_insensitive) {
    auto g = detail::RgGlob::compile(glob);
    return g && g->match(text, case_insensitive);
}

bool rg_glob_valid(std::string_view glob, std::string* error) {
    return detail::RgGlob::compile(glob, error) != nullptr;
}

// ---------------------------------------------------------------------------------------------
// Gitignore

void Gitignore::add_line(std::string_view line) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (dialect_ == IgnoreDialect::Rg) {
        add_line_rg(line);
        return;
    }
    if (line.empty() || line.front() == '#') return;
    std::string s(line);
    trim_trailing_spaces(s);
    if (s.empty()) return;

    IgnoreRule r;
    r.original = std::string(line);
    std::string_view p = s;
    if (p.front() == '!') {
        r.negated = true;
        p.remove_prefix(1);
    }
    if (!p.empty() && p.back() == '/') {
        r.dir_only = true;
        p.remove_suffix(1);
    }
    if (p.empty()) return;
    r.basename_only = p.find('/') == std::string_view::npos;
    if (!r.basename_only && p.front() == '/') p.remove_prefix(1);  // match_pathname() drops it
    r.pattern = std::string(p);
    if (r.basename_only) {
        if (!has_glob_special(r.pattern)) r.kind = IgnoreRule::Kind::Literal;
        else if (r.pattern.front() == '*' && !has_glob_special(std::string_view(r.pattern).substr(1)))
            r.kind = IgnoreRule::Kind::Suffix;
    }
    if (r.negated) ++whitelists_;
    rules_.push_back(std::move(r));
}

// The ignore crate's GitignoreBuilder::add_line.
void Gitignore::add_line_rg(std::string_view line) {
    if (!line.empty() && line.front() == '#') return;
    if (!ends_with(line, "\\ ")) line = trim_end_unicode_space(line);
    if (line.empty()) return;

    IgnoreRule r;
    r.original = std::string(line);
    bool absolute = false;
    if (line.substr(0, 2) == "\\!" || line.substr(0, 2) == "\\#") {
        line.remove_prefix(1);
    } else {
        if (line.front() == '!') {
            r.negated = true;
            line.remove_prefix(1);
        }
        if (!line.empty() && line.front() == '/') {
            line.remove_prefix(1);
            absolute = true;
        }
    }
    if (!line.empty() && line.back() == '/') {
        r.dir_only = true;
        line.remove_suffix(1);
        if (!line.empty() && line.back() == '\\') line.remove_suffix(1);  // "foo\/"
    }
    std::string actual(line);
    const bool anywhere = !absolute && line.find('/') == std::string_view::npos;
    if (anywhere && !(actual.rfind("**/", 0) == 0 || actual == "**")) actual.insert(0, "**/");
    if (ends_with(actual, "/**")) actual += "/*";
    r.rg = detail::RgGlob::compile(actual);
    if (!r.rg) return;  // ripgrep reports the line and skips it
    // Fast paths: "**/lit" is a basename compare, "**/*lit" a basename suffix compare.
    if (anywhere && !line.empty() && line.find_first_of("*?[]{}\\,") == std::string_view::npos) {
        r.basename_only = true;
        r.kind = IgnoreRule::Kind::Literal;
        r.pattern = std::string(line);
    } else if (anywhere && line.size() > 1 && line.front() == '*' &&
               line.substr(1).find_first_of("*?[]{}\\,") == std::string_view::npos) {
        r.basename_only = true;
        r.kind = IgnoreRule::Kind::Suffix;
        r.pattern = std::string(line);
    } else {
        r.pattern = std::move(actual);
    }
    if (r.negated) ++whitelists_;
    rules_.push_back(std::move(r));
}

void Gitignore::add_content(std::string_view content) {
    if (content.size() >= 3 && static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB && static_cast<unsigned char>(content[2]) == 0xBF)
        content.remove_prefix(3);
    size_t i = 0;
    while (i < content.size()) {
        size_t nl = content.find('\n', i);
        if (nl == std::string_view::npos) nl = content.size();
        std::string_view line = content.substr(i, nl - i);
        // The ignore crate reads lines as UTF-8 and stops at the first one that is not.
        if (dialect_ == IgnoreDialect::Rg && !valid_utf8(line)) break;
        add_line(line);
        i = nl + 1;
    }
}

bool Gitignore::add_file(const fs::path& file) {
    auto text = detail::read_whole_file(file);
    if (!text) return false;
    add_content(*text);
    return true;
}

IgnoreMatch Gitignore::match(std::string_view path, bool is_dir, bool icase) const {
    if (rules_.empty() || path.empty()) return IgnoreMatch::None;
    size_t slash = path.rfind('/');
    std::string_view base = slash == std::string_view::npos ? path : path.substr(slash + 1);
    for (size_t i = rules_.size(); i-- > 0;) {
        const IgnoreRule& r = rules_[i];
        if (r.dir_only && !is_dir) continue;
        bool m;
        if (r.rg && r.kind == IgnoreRule::Kind::Glob) {
            m = r.rg->match(path, icase);
        } else if (r.basename_only) {
            switch (r.kind) {
            case IgnoreRule::Kind::Literal:
                m = equals(base, r.pattern, icase);
                break;
            case IgnoreRule::Kind::Suffix: {
                std::string_view suf = std::string_view(r.pattern).substr(1);
                m = base.size() >= suf.size() && equals(base.substr(base.size() - suf.size()), suf, icase);
                break;
            }
            default:
                m = glob_match(r.pattern, base, icase, false);
                break;
            }
        } else {
            m = glob_match(r.pattern, path, icase, true);
        }
        if (m) return r.negated ? IgnoreMatch::Whitelist : IgnoreMatch::Ignore;
    }
    return IgnoreMatch::None;
}

// ---------------------------------------------------------------------------------------------
// IgnoreFilter

std::string precompose_name(std::string_view name) {
    std::string out;
    if (detail::precompose_utf8(name, out)) return out;
    return std::string(name);
}

IgnoreFilter::IgnoreFilter(CaseMode mode) {
    icase_ = mode == CaseMode::Insensitive ||
             (mode == CaseMode::Auto && detail::platform_default_ignorecase());
}

IgnoreFilter::IgnoreFilter(const fs::path& root, CaseMode mode, Precompose precompose) {
    std::error_code ec;
    root_ = fs::absolute(root, ec).lexically_normal();
    if (ec) root_ = root;
    icase_ = detail::resolve_ignorecase(mode, root_);
    precompose_ = detail::resolve_precompose(precompose, root_);
}

IgnoreFilter::Group& IgnoreFilter::group_for(std::string_view base_dir) {
    std::string base = normalize_base(base_dir);
    for (auto& g : groups_)
        if (g.base == base) return g;
    // Keep groups ordered deepest-first so the first group that matches decides.
    size_t d = depth_of(base);
    auto it = std::find_if(groups_.begin(), groups_.end(), [&](const Group& g) { return depth_of(g.base) < d; });
    it = groups_.insert(it, Group{std::move(base), Gitignore{}});
    return *it;
}

void IgnoreFilter::add_rule(std::string_view line, std::string_view base_dir) {
    group_for(base_dir).rules.add_line(line);
}

void IgnoreFilter::add_rules(std::string_view content, std::string_view base_dir) {
    group_for(base_dir).rules.add_content(content);
}

bool IgnoreFilter::load_file(const fs::path& file) {
    std::string base;
    if (!root_.empty()) {
        std::error_code ec;
        fs::path dir = fs::absolute(file, ec).lexically_normal().parent_path();
        fs::path rel = dir.lexically_relative(root_);
        std::string r = path_to_utf8(rel);
        if (!rel.empty() && r != "." && r.rfind("..", 0) != 0) base = r;
    }
    return load_file(file, base);
}

bool IgnoreFilter::load_file(const fs::path& file, std::string_view base_dir) {
    auto text = detail::read_whole_file(file);
    if (!text) return false;
    group_for(base_dir).rules.add_content(*text);
    return true;
}

size_t IgnoreFilter::rule_count() const noexcept {
    size_t n = 0;
    for (const auto& g : groups_) n += g.rules.size();
    return n;
}

std::string IgnoreFilter::normalize(std::string_view path) const {
    std::string s(path);
#ifdef _WIN32
    std::replace(s.begin(), s.end(), '\\', '/');
#endif
    if (!root_.empty()) {
        std::string root = path_to_utf8(root_);
        while (!root.empty() && root.back() == '/') root.pop_back();
        bool absolute = !s.empty() && (s[0] == '/' || (s.size() > 1 && s[1] == ':'));
#ifdef _WIN32
        const bool root_icase = true;  // drive letters and NTFS names compare case-insensitively
#else
        const bool root_icase = icase_;
#endif
        if (absolute && s.size() >= root.size() &&
            equals(std::string_view(s).substr(0, root.size()), root, root_icase) &&
            (s.size() == root.size() || s[root.size()] == '/')) {
            s.erase(0, root.size());
        }
    }
    while (s.rfind("./", 0) == 0) s.erase(0, 2);
    while (!s.empty() && s.front() == '/') s.erase(0, 1);
    while (!s.empty() && s.back() == '/') s.pop_back();
    if (s == ".") s.clear();
    if (precompose_) {
        std::string nfc;
        if (detail::precompose_utf8(s, nfc)) s = std::move(nfc);
    }
    return s;
}

IgnoreMatch IgnoreFilter::match_normalized(std::string_view path, bool is_dir) const {
    for (const auto& g : groups_) {
        std::string_view rel = path;
        if (!g.base.empty()) {
            if (path.size() <= g.base.size() || path[g.base.size()] != '/' ||
                !equals(path.substr(0, g.base.size()), g.base, icase_))
                continue;
            rel = path.substr(g.base.size() + 1);
        }
        IgnoreMatch m = g.rules.match(rel, is_dir, icase_);
        if (m != IgnoreMatch::None) return m;
    }
    return IgnoreMatch::None;
}

IgnoreMatch IgnoreFilter::match(std::string_view path, bool is_dir) const {
    std::string p = normalize(path);
    if (p.empty()) return IgnoreMatch::None;
    return match_normalized(p, is_dir);
}

bool IgnoreFilter::is_ignored(std::string_view path, bool is_dir) const {
    std::string p = normalize(path);
    if (p.empty()) return false;
    for (size_t k = p.find('/'); k != std::string::npos; k = p.find('/', k + 1)) {
        if (match_normalized(std::string_view(p).substr(0, k), true) == IgnoreMatch::Ignore) return true;
    }
    return match_normalized(p, is_dir) == IgnoreMatch::Ignore;
}

bool IgnoreFilter::is_ignored(const fs::path& path, bool is_dir) const {
    if (!root_.empty() && path.is_absolute()) {
        fs::path rel = path.lexically_normal().lexically_relative(root_);
        return is_ignored(std::string_view(path_to_utf8(rel)), is_dir);
    }
    return is_ignored(std::string_view(path_to_utf8(path)), is_dir);
}

} // namespace bro::search
