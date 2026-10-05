#include "ignore/git_repo.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>

#if defined(__APPLE__)
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace bro::search::detail {

std::optional<std::string> read_whole_file(const fs::path& p) {
#ifdef _WIN32
    FILE* f = _wfopen(p.c_str(), L"rb");
#else
    FILE* f = std::fopen(p.c_str(), "rb");
#endif
    if (!f) return std::nullopt;
    std::string out;
    char buf[16384];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    std::fclose(f);
    return out;
}

bool has_dot_git(const fs::path& dir) {
    std::error_code ec;
    return fs::exists(dir / ".git", ec);
}

namespace {

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return std::string(s.substr(b, e - b));
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + 32);
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y + 32);
        if (x != y) return false;
    }
    return true;
}

fs::path path_from_utf8(std::string_view s) { return fs::path(std::u8string(s.begin(), s.end())); }

std::optional<fs::path> env_path(const char* name) {
#ifdef _WIN32
    std::wstring wname(name, name + std::char_traits<char>::length(name));
    const wchar_t* v = _wgetenv(wname.c_str());
    if (!v || !*v) return std::nullopt;
    return fs::path(v);
#else
    const char* v = std::getenv(name);
    if (!v || !*v) return std::nullopt;
    return fs::path(v);
#endif
}

std::optional<fs::path> home_dir() {
    if (auto h = env_path("HOME")) return h;
#ifdef _WIN32
    if (auto h = env_path("USERPROFILE")) return h;
#endif
    return std::nullopt;
}

fs::path xdg_config_home() {
    if (auto x = env_path("XDG_CONFIG_HOME")) return *x;
    if (auto h = home_dir()) return *h / ".config";
    return {};
}

fs::path expand_tilde(std::string_view v) {
    if (v.size() >= 2 && v[0] == '~' && (v[1] == '/' || v[1] == '\\')) {
        if (auto h = home_dir()) return *h / path_from_utf8(v.substr(2));
    }
    return path_from_utf8(v);
}

std::optional<fs::path> excludes_from_config(const fs::path& config) {
    auto text = read_whole_file(config);
    if (!text) return std::nullopt;
    auto v = config_value(*text, "core", "excludesfile");
    if (!v || v->empty()) return std::nullopt;
    return expand_tilde(*v);
}

} // namespace

std::optional<GitDirs> resolve_git_dirs(const fs::path& dir) {
    std::error_code ec;
    fs::path dot = dir / ".git";
    GitDirs d;
    if (fs::is_directory(dot, ec)) {
        d.git_dir = dot;
    } else if (fs::is_regular_file(dot, ec)) {
        auto text = read_whole_file(dot);
        if (!text) return std::nullopt;
        std::string t = trim(*text);
        if (t.rfind("gitdir:", 0) != 0) return std::nullopt;
        fs::path target = path_from_utf8(trim(std::string_view(t).substr(7)));
        d.git_dir = target.is_absolute() ? target : (dir / target);
    } else {
        return std::nullopt;
    }
    d.common_dir = d.git_dir;
    if (auto cd = read_whole_file(d.git_dir / "commondir")) {
        fs::path c = path_from_utf8(trim(*cd));
        if (!c.empty()) d.common_dir = c.is_absolute() ? c : (d.git_dir / c);
    }
    return d;
}

fs::path find_repo_root(const fs::path& start) {
    std::error_code ec;
    fs::path p = fs::absolute(start, ec).lexically_normal();
    if (ec) return {};
    while (true) {
        if (has_dot_git(p)) return p;
        fs::path parent = p.parent_path();
        if (parent.empty() || parent == p) return {};
        p = parent;
    }
}

std::optional<std::string> config_value(std::string_view text, std::string_view section, std::string_view key) {
    std::optional<std::string> result;
    bool in_section = false;
    size_t i = 0;
    while (i < text.size()) {
        size_t nl = text.find('\n', i);
        if (nl == std::string_view::npos) nl = text.size();
        std::string_view line = text.substr(i, nl - i);
        i = nl + 1;
        size_t b = 0;
        while (b < line.size() && (line[b] == ' ' || line[b] == '\t')) ++b;
        line.remove_prefix(b);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[') {
            size_t close = line.find(']');
            if (close == std::string_view::npos) continue;
            std::string_view inner = line.substr(1, close - 1);
            size_t sp = inner.find_first_of(" \t\"");
            std::string_view name = sp == std::string_view::npos ? inner : inner.substr(0, sp);
            // "[core.sub]" / "[core \"sub\"]" are subsections, not the plain section.
            in_section = sp == std::string_view::npos && iequals(name, section);
            line.remove_prefix(close + 1);
            size_t c = 0;
            while (c < line.size() && (line[c] == ' ' || line[c] == '\t')) ++c;
            line.remove_prefix(c);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        }
        if (!in_section) continue;
        size_t k = 0;
        while (k < line.size() && (std::isalnum(static_cast<unsigned char>(line[k])) || line[k] == '-')) ++k;
        std::string_view name = line.substr(0, k);
        if (!iequals(name, key)) continue;
        std::string_view rest = line.substr(k);
        size_t r = 0;
        while (r < rest.size() && (rest[r] == ' ' || rest[r] == '\t')) ++r;
        rest.remove_prefix(r);
        if (rest.empty() || rest[0] == '\r' || rest[0] == '#' || rest[0] == ';') {
            result = "true";
            continue;
        }
        if (rest[0] != '=') continue;
        rest.remove_prefix(1);
        std::string value;
        bool quoted = false;
        size_t pending_ws = 0;
        for (size_t j = 0; j < rest.size(); ++j) {
            char c = rest[j];
            if (c == '\r') break;
            if (!quoted && (c == '#' || c == ';')) break;
            if (c == '"') { quoted = !quoted; continue; }
            if (c == '\\' && j + 1 < rest.size()) {
                char n = rest[++j];
                value.append(pending_ws, ' ');
                pending_ws = 0;
                value.push_back(n == 'n' ? '\n' : n == 't' ? '\t' : n == 'b' ? '\b' : n);
                continue;
            }
            if (!quoted && (c == ' ' || c == '\t')) {
                if (!value.empty()) ++pending_ws;
                continue;
            }
            value.append(pending_ws, ' ');
            pending_ws = 0;
            value.push_back(c);
        }
        result = value;
    }
    return result;
}

std::optional<bool> parse_config_bool(std::string_view v) {
    std::string s = trim(v);
    if (iequals(s, "true") || iequals(s, "yes") || iequals(s, "on") || s == "1") return true;
    if (iequals(s, "false") || iequals(s, "no") || iequals(s, "off") || s == "0" || s.empty()) return false;
    return std::nullopt;
}

namespace {

std::optional<bool> repo_core_bool(const fs::path& repo_root, std::string_view key) {
    auto dirs = resolve_git_dirs(repo_root);
    if (!dirs) return std::nullopt;
    auto text = read_whole_file(dirs->common_dir / "config");
    if (!text) return std::nullopt;
    auto v = config_value(*text, "core", key);
    if (!v) return std::nullopt;
    return parse_config_bool(*v);
}

} // namespace

std::optional<bool> repo_ignorecase(const fs::path& repo_root) { return repo_core_bool(repo_root, "ignorecase"); }

std::optional<bool> repo_precompose(const fs::path& repo_root) {
    return repo_core_bool(repo_root, "precomposeunicode");
}

bool platform_default_ignorecase([[maybe_unused]] const fs::path& near) {
#if defined(_WIN32)
    return true;
#elif defined(__APPLE__)
    if (!near.empty()) {
        long r = pathconf(near.c_str(), _PC_CASE_SENSITIVE);
        if (r == 0 || r == 1) return r == 0;
    }
    return true;
#else
    return false;
#endif
}

bool resolve_ignorecase(CaseMode mode, const fs::path& root) {
    if (mode != CaseMode::Auto) return mode == CaseMode::Insensitive;
    fs::path repo_root = find_repo_root(root);
    if (!repo_root.empty())
        if (auto v = repo_ignorecase(repo_root)) return *v;
    return platform_default_ignorecase(root);
}

bool resolve_precompose(Precompose mode, [[maybe_unused]] const fs::path& root) {
#if defined(__APPLE__)
    if (mode != Precompose::Auto) return mode == Precompose::On;
    fs::path repo_root = find_repo_root(root);
    if (repo_root.empty()) return false;
    return repo_precompose(repo_root).value_or(false);
#else
    (void)mode;
    return false;
#endif
}

fs::path global_excludes_path() {
    if (auto h = home_dir()) {
        if (auto p = excludes_from_config(*h / ".gitconfig")) return *p;
    }
    fs::path xdg = xdg_config_home();
    if (xdg.empty()) return {};
    if (auto p = excludes_from_config(xdg / "git" / "config")) return *p;
    return xdg / "git" / "ignore";
}

} // namespace bro::search::detail
