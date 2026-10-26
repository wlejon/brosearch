#pragma once

#include "api.h"
#include "embed/embed.h"
#include "host_class.h"
#include "object_builder.h"
#include "arg_reader.h"

#include "brosearch/fuzzy.h"
#include "brosearch/fuzzy_index.h"
#include "brosearch/walk.h"
#include "brosearch/ignore.h"
#include "brosearch/regex.h"
#include "brosearch/grep.h"
#include "brosearch/cancellation_token.h"

#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace brosearch::api {

namespace ev = bronze::embed;
using Value = bronze::Value;

Value makeError(const std::string& msg);

// Asking the host's access gate (access_gate.cpp; embed/embed_access.h).
enum class PathAccess { Read, Write };
struct PathRefusal {
    std::string message;  // the gate's sentence; empty when allowed
    std::string path;     // the absolute path the gate was asked about
    explicit operator bool() const { return !message.empty(); }
};
/// Asks the gate about `p` (made absolute and lexically normal).
PathRefusal checkPath(const std::filesystem::path& p, PathAccess access);
/// The refusal as an Error: message, code "EACCES", path. Fresh: root it.
Value newAccessError(const PathRefusal& refusal);
/// Throws newAccessError into the running program.
Value throwAccessError(const PathRefusal& refusal);
/// A promise already rejected with newAccessError.
Value rejectedAccessPromise(const PathRefusal& refusal);
/// Holds a walk or grep that keeps reading `p` after the call returned in the
/// gate's ledger on the calling thread: when the host takes the grant back,
/// `revoke` runs there with the refusal. 0 when no gate is installed.
uint64_t holdPath(const std::filesystem::path& p, std::function<void(const std::string& refusal)> revoke);
void releaseHeldPath(uint64_t& id);
/// A revoke's refusal as the Error the job rejects with (PermissionRevoked for
/// a grant taken back), code EACCES, `path` the absolute path. Fresh: root it.
Value newRevokedError(const std::string& refusal, const std::filesystem::path& p);

extern HostClass g_fuzzyIndexClass;
extern HostClass g_regexClass;
extern HostClass g_gitignoreClass;
extern HostClass g_cancellationTokenClass;

void installFuzzy(ObjectBuilder& b);
void installWalk(ObjectBuilder& b);
void installGrep(ObjectBuilder& b);

std::shared_ptr<bro::search::CancellationToken> unwrapToken(Value val);

struct AsyncJob {
    uint64_t id = 0;
    std::thread worker;
    std::shared_ptr<bro::search::CancellationToken> cancel_token;
    ev::Persistent promise;
    ev::Persistent callback; // onFile or onMatch
    std::atomic<bool> done{false};
    std::string error;

    // What the job reads (the walk's or grep's root), held in the access
    // gate's ledger while it runs (trackAsyncJob). `revoked` is the refusal
    // when the host took the grant back: the job is cancelled, streams nothing
    // more, and its promise rejects with it. Both are touched only on the JS
    // thread that started the job.
    std::filesystem::path root;
    uint64_t held = 0;
    std::string revoked;

    // files job
    bool is_grep = false;
    std::vector<std::string> files_result;
    std::mutex stream_files_mu;
    std::vector<std::string> stream_files;

    // grep job
    struct Hit {
        std::string path;
        uint64_t line = 0;
        uint64_t column = 0;
        std::string text;
    };
    std::vector<Hit> grep_result;
    std::mutex stream_grep_mu;
    std::vector<Hit> stream_grep;
};

void trackAsyncJob(std::shared_ptr<AsyncJob> job);
bool drainAsyncJobs();
void cancelAllAsyncJobs();

} // namespace brosearch::api
