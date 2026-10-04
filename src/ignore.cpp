#include "brosearch/ignore.h"

#include <cctype>
#include <fstream>
#include <sstream>

namespace bro::search {

namespace {

inline char to_lower_char(char c) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

inline bool char_equals(char a, char b, bool case_sensitive) noexcept {
    if (case_sensitive) return a == b;
    return to_lower_char(a) == to_lower_char(b);
}

std::string normalize_path_separators(std::string_view p) {
    std::string s;
    s.reserve(p.size());
    for (char c : p) {
        if (c == '\\') {
            s.push_back('/');
        } else {
            s.push_back(c);
        }
    }
    // Remove leading "./"
    if (s.rfind("./", 0) == 0) {
        s.erase(0, 2);
    }
    // Remove leading "/"
    while (!s.empty() && s.front() == '/') {
        s.erase(0, 1);
    }
    // Remove trailing "/"
    while (!s.empty() && s.back() == '/') {
        s.pop_back();
    }
    return s;
}

std::string_view trim_whitespace(std::string_view str) {
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.front()))) {
        str.remove_prefix(1);
    }
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
        str.remove_suffix(1);
    }
    return str;
}

bool glob_match_recursive(std::string_view pat, std::string_view str, bool case_sensitive) {
    size_t p = 0;
    size_t s = 0;
    const size_t p_len = pat.size();
    const size_t s_len = str.size();

    while (p < p_len && s < s_len) {
        if (p + 1 < p_len && pat[p] == '*' && pat[p + 1] == '*') {
            // ** matches 0 or more characters INCLUDING '/'
            while (p < p_len && pat[p] == '*') ++p;
            if (p == p_len) return true; // trailing ** matches everything
            // Skip a slash after ** if any
            if (pat[p] == '/') {
                ++p;
            }
            // Try matching remainder from each position
            for (size_t i = s; i <= s_len; ++i) {
                if (glob_match_recursive(pat.substr(p), str.substr(i), case_sensitive)) {
                    return true;
                }
            }
            return false;
        } else if (pat[p] == '*') {
            // * matches 0 or more characters EXCLUDING '/'
            ++p;
            if (p == p_len) {
                return str.substr(s).find('/') == std::string_view::npos;
            }
            for (size_t i = s; i <= s_len; ++i) {
                if (i > s && str[i - 1] == '/') break;
                if (glob_match_recursive(pat.substr(p), str.substr(i), case_sensitive)) {
                    return true;
                }
            }
            return false;
        } else if (pat[p] == '?') {
            if (str[s] == '/') return false;
            ++p;
            ++s;
        } else if (pat[p] == '[') {
            size_t close_bracket = pat.find(']', p);
            if (close_bracket == std::string_view::npos) {
                if (!char_equals(pat[p], str[s], case_sensitive)) return false;
                ++p;
                ++s;
            } else {
                bool match_class = false;
                bool invert = (p + 1 < close_bracket && (pat[p + 1] == '!' || pat[p + 1] == '^'));
                size_t class_start = invert ? p + 2 : p + 1;
                char target = case_sensitive ? str[s] : to_lower_char(str[s]);

                for (size_t c = class_start; c < close_bracket; ++c) {
                    if (c + 2 < close_bracket && pat[c + 1] == '-') {
                        char low = case_sensitive ? pat[c] : to_lower_char(pat[c]);
                        char high = case_sensitive ? pat[c + 2] : to_lower_char(pat[c + 2]);
                        if (target >= low && target <= high) {
                            match_class = true;
                            break;
                        }
                        c += 2;
                    } else {
                        char expected = case_sensitive ? pat[c] : to_lower_char(pat[c]);
                        if (target == expected) {
                            match_class = true;
                            break;
                        }
                    }
                }
                if (invert) match_class = !match_class;
                if (!match_class) return false;
                p = close_bracket + 1;
                ++s;
            }
        } else {
            if (!char_equals(pat[p], str[s], case_sensitive)) {
                return false;
            }
            ++p;
            ++s;
        }
    }

    while (p < p_len && pat[p] == '*') {
        ++p;
    }

    return (p == p_len && s == s_len);
}

} // namespace

bool IgnoreFilter::glob_match(
    std::string_view pattern,
    std::string_view text,
    bool case_sensitive
) {
    if (pattern.empty()) return text.empty();
    if (pattern == "*") return text.find('/') == std::string_view::npos;
    if (pattern == "**") return true;
    return glob_match_recursive(pattern, text, case_sensitive);
}

bool IgnoreRule::matches(std::string_view relative_path, bool is_directory) const {
    std::string_view test_path = relative_path;

    // If rule has base_dir, strip base_dir prefix
    if (!base_dir.empty()) {
        if (test_path.rfind(base_dir, 0) == 0) {
            test_path.remove_prefix(base_dir.size());
            while (!test_path.empty() && test_path.front() == '/') {
                test_path.remove_prefix(1);
            }
        } else {
            return false;
        }
    }

    if (test_path.empty()) {
        return false;
    }

    if (anchored) {
        if (!directory_only || is_directory) {
            if (IgnoreFilter::glob_match(clean_pattern, test_path)) {
                return true;
            }
        }
        // Check if clean_pattern matches a directory prefix:
        // E.g. clean_pattern is "foo", test_path is "foo/bar"
        if (test_path.size() > clean_pattern.size() &&
            test_path[clean_pattern.size()] == '/') {
            if (IgnoreFilter::glob_match(clean_pattern, test_path.substr(0, clean_pattern.size()))) {
                return true;
            }
        }
        // General prefix check for directory components
        size_t slash_pos = test_path.find('/');
        while (slash_pos != std::string_view::npos) {
            std::string_view prefix = test_path.substr(0, slash_pos);
            if (IgnoreFilter::glob_match(clean_pattern, prefix)) {
                return true;
            }
            slash_pos = test_path.find('/', slash_pos + 1);
        }
        return false;
    }

    // Unanchored rule:
    // 1. Direct match against full test_path
    if (!directory_only || is_directory) {
        if (IgnoreFilter::glob_match(clean_pattern, test_path)) {
            return true;
        }
    }

    // 2. Check each path segment:
    size_t start = 0;
    while (start < test_path.size()) {
        size_t next_slash = test_path.find('/', start);
        size_t len = (next_slash == std::string_view::npos) ? (test_path.size() - start) : (next_slash - start);
        std::string_view segment = test_path.substr(start, len);
        bool seg_is_dir = (next_slash != std::string_view::npos) ? true : is_directory;

        if (!directory_only || seg_is_dir) {
            if (IgnoreFilter::glob_match(clean_pattern, segment)) {
                return true;
            }
        }

        if (next_slash == std::string_view::npos) {
            break;
        }
        start = next_slash + 1;
    }

    // 3. Check against path suffixes: e.g. clean_pattern "b/*.txt" in "a/b/foo.txt"
    size_t slash_pos = test_path.find('/');
    while (slash_pos != std::string_view::npos) {
        std::string_view suffix = test_path.substr(slash_pos + 1);
        if (!directory_only || is_directory) {
            if (IgnoreFilter::glob_match(clean_pattern, suffix)) {
                return true;
            }
        }
        slash_pos = test_path.find('/', slash_pos + 1);
    }

    return false;
}

IgnoreFilter::IgnoreFilter(bool use_defaults) {
    if (use_defaults) {
        add_default_ignores();
    }
}

void IgnoreFilter::add_default_ignores() {
    static const char* const DEFAULT_IGNORES[] = {
        ".git",
        ".git/",
        ".svn/",
        ".hg/",
        ".vs/",
        ".vscode/",
        ".idea/",
        "build/",
        "build-*/",
        "build_*/",
        "dist/",
        "bin/",
        "obj/",
        "out/",
        "node_modules/",
        "__pycache__/",
        ".cache/",
        ".DS_Store",
        "Thumbs.db",
        "*.log",
        "*.tmp"
    };

    for (const char* pattern : DEFAULT_IGNORES) {
        add_rule(pattern);
    }
}

void IgnoreFilter::add_rule(std::string_view rule_line, std::string_view base_dir) {
    rule_line = trim_whitespace(rule_line);
    if (rule_line.empty() || rule_line.front() == '#') {
        return; // Comment or blank line
    }

    IgnoreRule rule;
    rule.original_pattern = std::string(rule_line);
    rule.base_dir = normalize_path_separators(base_dir);

    if (rule_line.front() == '!') {
        rule.is_negation = true;
        rule_line.remove_prefix(1);
        rule_line = trim_whitespace(rule_line);
    }

    if (rule_line.empty()) {
        return;
    }

    if (rule_line.back() == '/') {
        rule.directory_only = true;
        rule_line.remove_suffix(1);
    }

    if (rule_line.front() == '/') {
        rule.anchored = true;
        rule_line.remove_prefix(1);
    } else if (rule_line.find('/') != std::string_view::npos) {
        // Contains '/' in the middle
        rule.anchored = true;
    } else {
        rule.anchored = false;
    }

    rule.clean_pattern = normalize_path_separators(rule_line);
    rule.has_glob = (rule.clean_pattern.find_first_of("*?[]") != std::string::npos);

    rules_.push_back(std::move(rule));
}

bool IgnoreFilter::load_file(const std::filesystem::path& gitignore_path, std::string_view base_dir) {
    std::ifstream file(gitignore_path);
    if (!file.is_open()) {
        return false;
    }

    std::string b_dir = std::string(base_dir);
    if (b_dir.empty()) {
        b_dir = gitignore_path.parent_path().generic_string();
    }

    std::string line;
    while (std::getline(file, line)) {
        add_rule(line, b_dir);
    }
    return true;
}

void IgnoreFilter::load_string(std::string_view content, std::string_view base_dir) {
    std::istringstream stream((std::string(content)));
    std::string line;
    while (std::getline(stream, line)) {
        add_rule(line, base_dir);
    }
}

void IgnoreFilter::clear() noexcept {
    rules_.clear();
}

bool IgnoreFilter::is_ignored(std::string_view path, bool is_directory) const {
    std::string norm_path = normalize_path_separators(path);
    if (norm_path.empty()) {
        return false;
    }

    bool ignored = false;
    for (const auto& rule : rules_) {
        if (rule.matches(norm_path, is_directory)) {
            ignored = !rule.is_negation;
        }
    }
    return ignored;
}

bool IgnoreFilter::is_ignored(const std::string& path, bool is_directory) const {
    return is_ignored(std::string_view(path), is_directory);
}

bool IgnoreFilter::is_ignored(const char* path, bool is_directory) const {
    return is_ignored(std::string_view(path), is_directory);
}

bool IgnoreFilter::is_ignored(const std::filesystem::path& path, bool is_directory) const {
    std::string s = path.generic_string();
    return is_ignored(std::string_view(s), is_directory);
}

} // namespace bro::search
