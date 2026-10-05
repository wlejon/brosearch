#pragma once
// Parallel directory walker with ripgrep's ignore semantics (the `ignore` crate as used by
// `rg --files`): .gitignore (inside a git repo unless require_git=false), .ignore, .rgignore,
// .git/info/exclude, the global git excludes file, parent-directory ignore files, hidden-file
// skipping. Ignored directories are pruned, never descended.

#include "brosearch/cancellation_token.h"
#include "brosearch/ignore.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace bro::search {

enum class EntryType : uint8_t { File, Directory, Symlink, Other };

struct WalkEntry {
    // Path relative to the walk root, '/'-separated, UTF-8 (WTF-8 for ill-formed UTF-16 names on
    // Windows; raw bytes on POSIX, precomposed to NFC when WalkOptions::precompose_unicode is in
    // effect on macOS). Valid only for the duration of the callback.
    std::string_view rel_path;
    EntryType type = EntryType::File;
    size_t depth = 0;  // 1 = direct child of root
    // Native path (root as given / the names as stored on disk), for opening the file. Null when
    // WalkOptions::native_paths is false.
    const std::filesystem::path* native_path = nullptr;
};

// A path the walk could not read. Its entries (or, for the root, the whole walk) are skipped.
struct WalkError {
    enum class Op : uint8_t {
        Stat,     // the root could not be queried (e.g. it does not exist)
        ReadDir,  // a directory (the root included) could not be opened for listing
    };
    Op op = Op::ReadDir;
    // Relative to the walk root, '/'-separated ("" = the root itself).
    std::string_view rel_path;
    // The root as given joined with the native names, as rg displays it.
    const std::filesystem::path* native_path = nullptr;
    std::error_code error;
};

// Called concurrently from worker threads when threads != 1.
using WalkErrorCallback = std::function<void(const WalkError&)>;

struct WalkOptions {
    bool hidden = false;          // include dot-files (and Windows hidden-attribute entries)
    bool git_ignore = true;       // .gitignore files
    bool ignore_files = true;     // .ignore and .rgignore
    bool git_exclude = true;      // $GIT_DIR/info/exclude
    bool git_global = true;       // core.excludesFile, else $XDG_CONFIG_HOME/git/ignore
    bool parents = true;          // ignore files in ancestors of the root
    bool require_git = true;      // .gitignore/exclude only apply inside a git repository
    bool follow_symlinks = false;
    bool yield_directories = false;  // also report directories (rg --files never does)
    size_t max_depth = SIZE_MAX;     // rg --max-depth semantics: 1 = only the root's children
    CaseMode ignore_case = CaseMode::Auto;  // matching of ignore patterns, see ignore.h
    // Git reads ignore files and globs like git; Rg like ripgrep (ignore.h lists the differences).
    // Under Rg, -g globs, global excludes and extra_ignore_files are also anchored the way rg
    // anchors them: matched against the path as rg prints it, display_root joined with rel_path
    // (a leading "./" dropped), so "/x" in the global excludes file matches x only when the walk
    // root is "." and a relative or absolute root shifts what they match. Under Git, global
    // excludes are relative to the repository root and the others to the walk root.
    IgnoreDialect dialect = IgnoreDialect::Git;
    // Rg: the root as the user typed it (empty = the root passed to walk()).
    std::filesystem::path display_root;
    // NFD names matched and reported in NFC (macOS, git's core.precomposeUnicode), see ignore.h.
    // rg never precomposes; Off reproduces it.
    Precompose precompose_unicode = Precompose::Auto;
    // ripgrep -g/--glob overrides (gitignore syntax, anchored as `dialect` says): "pat" includes (files
    // matching no include are skipped; directories are still descended), "!pat" excludes.
    // Overrides beat ignore files and hidden-skipping, as in rg.
    std::vector<std::string> globs;
    bool glob_case_insensitive = false;  // rg --glob-case-insensitive
    // Additional gitignore-format files applied at the root (rg --ignore-file); lowest precedence.
    std::vector<std::filesystem::path> extra_ignore_files;
    // Global excludes file to use instead of resolving core.excludesFile (empty = resolve).
    std::filesystem::path git_global_file;
    size_t threads = 0;  // 0 = hardware concurrency (capped); 1 = single-threaded, deterministic order
    // Fill WalkEntry::native_path (costs a path allocation per entry). When false it is null.
    bool native_paths = true;
    // Unreadable directories (rg prints "PATH: Permission denied (os error 13)" and exits 2) and a
    // root that cannot be queried. Null = skip them silently.
    WalkErrorCallback on_error;
};

// Return false to stop the walk. Called concurrently from worker threads when threads != 1.
using WalkCallback = std::function<bool(const WalkEntry&)>;

// Every non-ignored entry below `root` is reported except directories (unless
// yield_directories). Non-directories are reported with their own type: Symlink for links that
// are not followed (or are broken), Other for devices/fifos/sockets — rg --files lists only
// EntryType::File. With follow_symlinks, links report their target's type and symlinked
// directories are descended (loops to an ancestor are skipped). Directory precedence for
// ignore rules is ripgrep's: .rgignore > .ignore > .gitignore > info/exclude > global excludes >
// extra_ignore_files, nearest directory first; .gitignore/info/exclude stop at the repository
// boundary. Ignored directories are pruned without being opened. The root itself is never
// filtered; if `root` is a file it is reported once (rel_path = its file name, depth 0).
void walk(const std::filesystem::path& root, const WalkOptions& options, const WalkCallback& on_entry,
          const CancellationToken* token = nullptr);

// Convenience: rel paths of all EntryType::File entries, sorted bytewise.
[[nodiscard]] std::vector<std::string> list_files(const std::filesystem::path& root,
                                                  const WalkOptions& options,
                                                  const CancellationToken* token = nullptr);

} // namespace bro::search
