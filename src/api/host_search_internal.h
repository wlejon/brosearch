#pragma once

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
