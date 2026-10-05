#pragma once
// Native directory enumeration for the walker. Windows: FindFirstFileExW with FindExInfoBasic and
// FIND_FIRST_EX_LARGE_FETCH on a \\?\ path (no MAX_PATH limit). POSIX: readdir with d_type,
// lstat only when the filesystem reports DT_UNKNOWN. Names are packed into one buffer per
// listing so a reused DirListing enumerates without per-entry allocations. Internal.

#include "brosearch/walk.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bro::search::detail {

#ifdef _WIN32
using NativeString = std::wstring;
using NativeView = std::wstring_view;
inline constexpr wchar_t kNativeSep = L'\\';
#else
using NativeString = std::string;
using NativeView = std::string_view;
inline constexpr char kNativeSep = '/';
#endif

struct RawEntry {
    uint32_t name_off = 0, name_len = 0;  // UTF-8 (WTF-8 on Windows) / raw bytes (POSIX)
#ifdef _WIN32
    uint32_t wname_off = 0, wname_len = 0;
#endif
    EntryType type = EntryType::Other;  // of the entry itself (symlinks not followed)
    bool hidden_attr = false;           // Windows FILE_ATTRIBUTE_HIDDEN
};

struct DirListing {
    std::vector<RawEntry> entries;
    std::string names;
#ifdef _WIN32
    std::wstring wnames;
#endif
    void clear() {
        entries.clear();
        names.clear();
#ifdef _WIN32
        wnames.clear();
#endif
    }
    std::string_view name(const RawEntry& e) const { return std::string_view(names).substr(e.name_off, e.name_len); }
    NativeView native_name(const RawEntry& e) const {
#ifdef _WIN32
        return std::wstring_view(wnames).substr(e.wname_off, e.wname_len);
#else
        return name(e);
#endif
    }
};

// Replaces `out` with the entries of `dir` ("." and ".." excluded). False if it cannot be opened.
bool read_dir(const NativeString& dir, DirListing& out);

struct FileId {
    uint64_t dev = 0;
    uint64_t ino = 0;
    bool operator==(const FileId&) const = default;
};

// Follows symlinks. False if the target does not exist / cannot be queried.
bool stat_follow(const NativeString& path, EntryType& type, FileId& id);

// Absolute path in the form used for enumeration (Windows: \\?\ or \\?\UNC\ prefixed).
NativeString enum_path(const std::filesystem::path& absolute);

#ifdef _WIN32
// UTF-16 -> WTF-8 (unpaired surrogates encoded as 3-byte sequences), appended to `out`.
void append_wtf8(const wchar_t* s, size_t n, std::string& out);
#endif

} // namespace bro::search::detail
