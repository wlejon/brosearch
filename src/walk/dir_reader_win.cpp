#ifdef _WIN32

#include "walk/dir_reader.h"

#include <windows.h>

namespace bro::search::detail {

void append_wtf8(const wchar_t* s, size_t n, std::string& out) {
    for (size_t i = 0; i < n; ++i) {
        uint32_t c = static_cast<uint16_t>(s[i]);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
            uint32_t d = static_cast<uint16_t>(s[i + 1]);
            if (d >= 0xDC00 && d <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
}

bool read_dir(const NativeString& dir, DirListing& out, std::error_code& ec) {
    out.clear();
    std::wstring pattern = dir;
    if (pattern.empty() || pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern.push_back(L'*');
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return true;  // an empty volume root (no "." entry)
        ec.assign(static_cast<int>(err), std::system_category());
        return false;
    }
    do {
        const wchar_t* n = fd.cFileName;
        if (n[0] == L'.' && (n[1] == 0 || (n[1] == L'.' && n[2] == 0))) continue;
        RawEntry e;
        const size_t wlen = wcslen(n);
        e.wname_off = static_cast<uint32_t>(out.wnames.size());
        e.wname_len = static_cast<uint32_t>(wlen);
        out.wnames.append(n, wlen);
        e.name_off = static_cast<uint32_t>(out.names.size());
        append_wtf8(n, wlen, out.names);
        e.name_len = static_cast<uint32_t>(out.names.size() - e.name_off);
        const DWORD a = fd.dwFileAttributes;
        // Same rule as Rust's FileType::is_symlink: a name-surrogate reparse point (symlinks and
        // junctions) is a link; other reparse points (e.g. OneDrive placeholders) are not.
        if ((a & FILE_ATTRIBUTE_REPARSE_POINT) && (fd.dwReserved0 & 0x20000000u))
            e.type = EntryType::Symlink;
        else if (a & FILE_ATTRIBUTE_DIRECTORY)
            e.type = EntryType::Directory;
        else
            e.type = EntryType::File;
        e.hidden_attr = (a & FILE_ATTRIBUTE_HIDDEN) != 0;
        out.entries.push_back(e);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return true;
}

bool stat_follow(const NativeString& path, EntryType& type, FileId& id) {
    HANDLE h = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = GetFileInformationByHandle(h, &info);
    CloseHandle(h);
    if (!ok) return false;
    type = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? EntryType::Directory : EntryType::File;
    id.dev = info.dwVolumeSerialNumber;
    id.ino = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return true;
}

NativeString enum_path(const std::filesystem::path& absolute) {
    std::wstring p = absolute.lexically_normal().make_preferred().native();
    while (p.size() > 3 && p.back() == L'\\') p.pop_back();
    if (p.rfind(LR"(\\?\)", 0) == 0) return p;
    if (p.rfind(LR"(\\)", 0) == 0) return LR"(\\?\UNC\)" + p.substr(2);
    return LR"(\\?\)" + p;
}

} // namespace bro::search::detail

#endif // _WIN32
