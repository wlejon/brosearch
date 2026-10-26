// The helpers bro.search's natives use to ask the host's access gate
// (embed/embed_access.h; what each native asks is in api.h, "Access").

#include "host_search_internal.h"
#include "embed/embed_access.h"

namespace brosearch::api {

namespace {

std::string absoluteUtf8(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(p, ec);
    if (ec) abs = p;
    std::u8string u = abs.lexically_normal().u8string();
    return std::string(u.begin(), u.end());
}

} // namespace

PathRefusal checkPath(const std::filesystem::path& p, PathAccess access) {
    if (!ev::accessGateActive()) return {};
    PathRefusal r;
    r.path = absoluteUtf8(p);
    r.message = ev::checkAccess(access == PathAccess::Write ? ev::AccessKind::Write : ev::AccessKind::Read, r.path);
    return r;
}

Value newAccessError(const PathRefusal& refusal) {
    return ev::newAccessError(refusal.message, "EACCES", refusal.path);
}

Value throwAccessError(const PathRefusal& refusal) {
    return ev::throwAccessError(refusal.message, "EACCES", refusal.path);
}

Value rejectedAccessPromise(const PathRefusal& refusal) {
    return ev::rejectedAccessPromise(refusal.message, "EACCES", refusal.path);
}

uint64_t holdPath(const std::filesystem::path& p, std::function<void(const std::string& refusal)> revoke) {
    if (!ev::accessGateActive()) return 0;
    return ev::holdAccess(ev::AccessKind::Read, absoluteUtf8(p), std::move(revoke));
}

void releaseHeldPath(uint64_t& id) {
    if (id == 0) return;
    ev::releaseAccess(id);
    id = 0;
}

Value newRevokedError(const std::string& refusal, const std::filesystem::path& p) {
    return ev::newAccessError(refusal, "EACCES", absoluteUtf8(p));
}

} // namespace brosearch::api
