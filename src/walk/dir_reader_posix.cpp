#ifndef _WIN32

#include "walk/dir_reader.h"

#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>

namespace bro::search::detail {

namespace {

EntryType type_from_mode(mode_t m) {
    if (S_ISDIR(m)) return EntryType::Directory;
    if (S_ISREG(m)) return EntryType::File;
    if (S_ISLNK(m)) return EntryType::Symlink;
    return EntryType::Other;
}

} // namespace

bool read_dir(const NativeString& dir, DirListing& out, std::error_code& ec) {
    out.clear();
    DIR* d = opendir(dir.c_str());
    if (!d) {
        ec.assign(errno, std::system_category());
        return false;
    }
    std::string full;
    while (struct dirent* ent = readdir(d)) {
        const char* n = ent->d_name;
        if (n[0] == '.' && (n[1] == 0 || (n[1] == '.' && n[2] == 0))) continue;
        RawEntry e;
        e.name_off = static_cast<uint32_t>(out.names.size());
        out.names.append(n);
        e.name_len = static_cast<uint32_t>(out.names.size() - e.name_off);
#ifdef DT_UNKNOWN
        switch (ent->d_type) {
        case DT_DIR: e.type = EntryType::Directory; break;
        case DT_REG: e.type = EntryType::File; break;
        case DT_LNK: e.type = EntryType::Symlink; break;
        case DT_UNKNOWN: {
            full = dir;
            if (full.empty() || full.back() != '/') full.push_back('/');
            full += n;
            struct stat st;
            e.type = lstat(full.c_str(), &st) == 0 ? type_from_mode(st.st_mode) : EntryType::Other;
            break;
        }
        default: e.type = EntryType::Other; break;
        }
#else
        full = dir + "/" + n;
        struct stat st;
        e.type = lstat(full.c_str(), &st) == 0 ? type_from_mode(st.st_mode) : EntryType::Other;
#endif
        out.entries.push_back(e);
    }
    closedir(d);
    return true;
}

bool stat_follow(const NativeString& path, EntryType& type, FileId& id) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    type = type_from_mode(st.st_mode);
    id.dev = static_cast<uint64_t>(st.st_dev);
    id.ino = static_cast<uint64_t>(st.st_ino);
    return true;
}

NativeString enum_path(const std::filesystem::path& absolute) {
    std::string p = absolute.lexically_normal().native();
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

} // namespace bro::search::detail

#endif // !_WIN32
