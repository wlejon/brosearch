#include "api.h"
#include "host_search_internal.h"
#include "brosearch/version.h"

#include <algorithm>
#include <vector>

namespace brosearch::api {

namespace {

thread_local std::vector<std::shared_ptr<AsyncJob>> t_jobs;
thread_local uint64_t t_next_job_id = 0;

Value js_tick(Value, std::span<const Value>) {
    tickSearchAsync();
    return ev::undefined();
}

} // namespace

Value makeError(const std::string& msg) {
    ev::Persistent text(ev::fromUtf8(msg));
    auto ctor = ev::globalValue("Error");
    if (ctor.found && ev::isFunction(ctor.value)) {
        ev::Persistent c(ctor.value);
        const Value arg = text.get();
        auto r = ev::construct(c.get(), std::span<const Value>(&arg, 1));
        if (!r.thrown) return r.value;
    }
    return text.get();
}

void trackAsyncJob(std::shared_ptr<AsyncJob> job) {
    job->id = ++t_next_job_id;
    t_jobs.push_back(std::move(job));
}

bool drainAsyncJobs() {
    bool did_work = false;
    if (t_jobs.empty()) return false;

    // 1. Drain streaming callbacks on JS thread
    for (auto& job : t_jobs) {
        if (!ev::isFunction(job->callback.get())) continue;

        if (!job->is_grep) {
            std::vector<std::string> batch;
            {
                std::lock_guard<std::mutex> lk(job->stream_files_mu);
                batch.swap(job->stream_files);
            }
            if (!batch.empty()) {
                did_work = true;
                for (const auto& path : batch) {
                    ev::Persistent s(ev::fromUtf8(path));
                    const Value arg = s.get();
                    ev::call(job->callback.get(), ev::undefined(), std::span<const Value>(&arg, 1));
                }
            }
        } else {
            std::vector<AsyncJob::Hit> batch;
            {
                std::lock_guard<std::mutex> lk(job->stream_grep_mu);
                batch.swap(job->stream_grep);
            }
            if (!batch.empty()) {
                did_work = true;
                for (const auto& h : batch) {
                    ObjectBuilder hb;
                    hb.set("path", h.path);
                    hb.set("line", static_cast<double>(h.line));
                    hb.set("column", static_cast<double>(h.column));
                    hb.set("text", h.text);
                    const Value arg = hb.get();
                    ev::call(job->callback.get(), ev::undefined(), std::span<const Value>(&arg, 1));
                }
            }
        }
    }

    // 2. Check for completed jobs
    std::vector<std::shared_ptr<AsyncJob>> remaining;
    std::vector<std::shared_ptr<AsyncJob>> completed;

    for (auto& job : t_jobs) {
        if (job->done.load(std::memory_order_acquire)) {
            completed.push_back(std::move(job));
        } else {
            remaining.push_back(std::move(job));
        }
    }
    t_jobs = std::move(remaining);

    for (auto& job : completed) {
        if (job->worker.joinable()) {
            job->worker.join();
        }
        did_work = true;

        if (!job->error.empty()) {
            ev::Persistent err(makeError(job->error));
            ev::rejectPromise(job->promise.get(), err.get());
        } else if (!job->is_grep) {
            ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(job->files_result.size())));
            for (size_t i = 0; i < job->files_result.size(); ++i) {
                ev::Persistent s(ev::fromUtf8(job->files_result[i]));
                resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), s.get()));
            }
            ev::resolvePromise(job->promise.get(), resArr.get());
        } else {
            ev::Persistent resArr(ev::makeArray(static_cast<uint32_t>(job->grep_result.size())));
            for (size_t i = 0; i < job->grep_result.size(); ++i) {
                const auto& h = job->grep_result[i];
                ObjectBuilder hb;
                hb.set("path", h.path);
                hb.set("line", static_cast<double>(h.line));
                hb.set("column", static_cast<double>(h.column));
                hb.set("text", h.text);
                resArr.set(ev::setElement(resArr.get(), static_cast<uint32_t>(i), hb.get()));
            }
            ev::resolvePromise(job->promise.get(), resArr.get());
        }
        job->callback.set(ev::undefined());
    }

    return did_work;
}

void cancelAllAsyncJobs() {
    for (auto& job : t_jobs) {
        if (job->cancel_token) {
            job->cancel_token->cancel();
        }
    }
    for (auto& job : t_jobs) {
        if (job->worker.joinable()) {
            job->worker.join();
        }
    }
    t_jobs.clear();
}

static Value ensureBroSearch() {
    ev::Persistent globalThisVal;
    auto gt = ev::globalValue("globalThis");
    if (gt.found && ev::isObject(gt.value)) {
        globalThisVal.set(gt.value);
    }

    ev::Persistent broP;
    auto bro = ev::globalValue("bro");
    if (bro.found && ev::isObject(bro.value)) broP.set(bro.value);
    if (!ev::isObject(broP.get()) && ev::isObject(globalThisVal.get())) {
        Value candidate = ev::getProperty(globalThisVal.get(), "bro");
        if (ev::isObject(candidate)) broP.set(candidate);
    }
    if (!ev::isObject(broP.get())) {
        broP.set(ev::createObject());
        ev::registerGlobal("bro", broP.get());
        if (ev::isObject(globalThisVal.get())) {
            globalThisVal.set(ev::setProperty(globalThisVal.get(), "bro", broP.get()));
        }
    }

    ev::Persistent searchP(ev::getProperty(broP.get(), "search"));
    if (!ev::isObject(searchP.get())) {
        searchP.set(ev::createObject());
        broP.set(ev::setProperty(broP.get(), "search", searchP.get()));
    }
    return searchP.get();
}

void installSearch() {
    ev::Persistent searchObjVal(ensureBroSearch());
    ObjectBuilder searchObj(searchObjVal.get());

    searchObj.set("version", std::string(bro::search::version_string()));
    searchObj.def("tick", 0, js_tick);

    installFuzzy(searchObj);
    installWalk(searchObj);
    installGrep(searchObj);
}

bool tickSearchAsync() {
    return drainAsyncJobs();
}

void shutdownSearchAsync() {
    cancelAllAsyncJobs();
}

} // namespace brosearch::api
