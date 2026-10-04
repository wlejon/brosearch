#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search {

struct IgnoreRule {
    std::string original_pattern;
    std::string clean_pattern;
    std::string base_dir;       // Normalized directory containing the .gitignore
    bool is_negation = false;    // Starts with '!'
    bool directory_only = false;// Ends with '/'
    bool anchored = false;      // Starts with '/' or has '/' in the middle
    bool has_glob = false;

    [[nodiscard]] bool matches(std::string_view relative_path, bool is_directory) const;
};

class IgnoreFilter {
public:
    explicit IgnoreFilter(bool use_defaults = true);
    ~IgnoreFilter() = default;

    // Adds default ignore rules (.git, node_modules, .vs, build, dist, .cache, etc.)
    void add_default_ignores();

    // Adds a single gitignore-style rule line
    void add_rule(std::string_view rule_line, std::string_view base_dir = "");

    // Loads rules from a .gitignore file on disk
    bool load_file(const std::filesystem::path& gitignore_path, std::string_view base_dir = "");

    // Loads rules from a string (e.g. multiple lines separated by \n)
    void load_string(std::string_view content, std::string_view base_dir = "");

    // Clears all rules
    void clear() noexcept;

    // Returns true if the path is ignored according to current rules
    [[nodiscard]] bool is_ignored(std::string_view path, bool is_directory = false) const;
    [[nodiscard]] bool is_ignored(const std::string& path, bool is_directory = false) const;
    [[nodiscard]] bool is_ignored(const char* path, bool is_directory = false) const;
    [[nodiscard]] bool is_ignored(const std::filesystem::path& path, bool is_directory = false) const;

    [[nodiscard]] size_t rule_count() const noexcept { return rules_.size(); }
    [[nodiscard]] const std::vector<IgnoreRule>& rules() const noexcept { return rules_; }

    // Standalone glob matching supporting *, **, ?, and character classes
    [[nodiscard]] static bool glob_match(
        std::string_view pattern,
        std::string_view text,
        bool case_sensitive = false
    );

private:
    std::vector<IgnoreRule> rules_;
};

} // namespace bro::search
