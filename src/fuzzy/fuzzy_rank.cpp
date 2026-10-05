// Batch ranking: parallel match over blocks of items, then fzf's ordering (rank, then index).
#include "fuzzy/fuzzy_rank.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace bro::search::fuzzy_detail {

namespace {

size_t default_threads() {
    size_t n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    return std::min<size_t>(n, 16);
}

class Pool {
public:
    Pool() {
        size_t n = default_threads();
        for (size_t i = 0; i + 1 < n; ++i) workers_.emplace_back([this, i] { loop(i); });
    }
    ~Pool() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_) t.join();
    }

    // Returns false if the pool is busy with another caller's job.
    bool run(size_t tasks, size_t threads, const std::function<void(size_t)>& fn) {
        std::unique_lock<std::mutex> use(use_mu_, std::try_to_lock);
        if (!use.owns_lock()) return false;
        size_t helpers = std::min(threads - 1, workers_.size());
        {
            std::lock_guard<std::mutex> lock(mu_);
            fn_ = &fn;
            tasks_ = tasks;
            next_.store(0, std::memory_order_relaxed);
            helpers_ = helpers;
            active_ = helpers;
            ++generation_;
        }
        cv_.notify_all();
        drain();
        std::unique_lock<std::mutex> lock(mu_);
        done_cv_.wait(lock, [&] { return active_ == 0; });
        fn_ = nullptr;
        return true;
    }

private:
    void drain() {
        for (;;) {
            size_t t = next_.fetch_add(1, std::memory_order_relaxed);
            if (t >= tasks_) return;
            (*fn_)(t);
        }
    }

    void loop(size_t id) {
        uint64_t seen = 0;
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [&] { return stop_ || (generation_ != seen && id < helpers_); });
                if (stop_) return;
                seen = generation_;
            }
            drain();
            {
                std::lock_guard<std::mutex> lock(mu_);
                if (--active_ == 0) done_cv_.notify_all();
            }
        }
    }

    std::mutex use_mu_;
    std::mutex mu_;
    std::condition_variable cv_, done_cv_;
    std::vector<std::thread> workers_;
    const std::function<void(size_t)>* fn_ = nullptr;
    size_t tasks_ = 0;
    std::atomic<size_t> next_{0};
    size_t helpers_ = 0;
    size_t active_ = 0;
    uint64_t generation_ = 0;
    bool stop_ = false;
};

Pool& pool() {
    static Pool p;
    return p;
}

// Stable LSD radix sort on the 64-bit key (16-bit digits), skipping digits that never vary.
void radix_sort(std::vector<Hit>& hits) {
    if (hits.size() < 256) {
        std::stable_sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.key < b.key; });
        return;
    }
    std::vector<Hit> tmp(hits.size());
    std::vector<uint32_t> count(65536);
    for (int shift = 0; shift < 64; shift += 16) {
        const uint64_t first = (hits[0].key >> shift) & 0xFFFF;
        bool varies = false;
        for (const Hit& h : hits)
            if (((h.key >> shift) & 0xFFFF) != first) {
                varies = true;
                break;
            }
        if (!varies) continue;
        std::fill(count.begin(), count.end(), 0u);
        for (const Hit& h : hits) ++count[(h.key >> shift) & 0xFFFF];
        uint32_t sum = 0;
        for (auto& c : count) {
            uint32_t v = c;
            c = sum;
            sum += v;
        }
        for (const Hit& h : hits) tmp[count[(h.key >> shift) & 0xFFFF]++] = h;
        hits.swap(tmp);
    }
}

} // namespace

size_t resolve_threads(size_t requested, size_t work_items) {
    size_t n = requested ? requested : default_threads();
    // Small inputs are faster on one thread than with hand-off overhead.
    size_t useful = std::max<size_t>(1, work_items / 2048);
    return std::max<size_t>(1, std::min(n, useful));
}

void parallel_for(size_t tasks, size_t threads, const std::function<void(size_t)>& fn) {
    threads = std::min(threads, tasks);
    if (threads > 1 && pool().run(tasks, threads, fn)) return;
    for (size_t t = 0; t < tasks; ++t) fn(t);
}

std::vector<FuzzyResult> all_items(size_t count, size_t limit, bool tac) {
    std::vector<FuzzyResult> results(limit ? std::min(limit, count) : count);
    for (size_t i = 0; i < results.size(); ++i) results[i].index = static_cast<uint32_t>(tac ? count - 1 - i : i);
    return results;
}

std::vector<FuzzyResult> finish_results(std::vector<Hit>& hits, bool sortable, size_t limit, bool tac) {
    if (tac) std::reverse(hits.begin(), hits.end());  // descending index; the sorts below are stable on it
    auto less = [tac](const Hit& a, const Hit& b) {
        return a.key != b.key ? a.key < b.key : (tac ? a.index > b.index : a.index < b.index);
    };
    if (sortable) {
        if (limit && hits.size() > limit) {
            std::nth_element(hits.begin(), hits.begin() + static_cast<ptrdiff_t>(limit), hits.end(), less);
            hits.resize(limit);
            std::sort(hits.begin(), hits.end(), less);
        } else {
            radix_sort(hits);
        }
    } else if (limit && hits.size() > limit) {
        hits.resize(limit);
    }
    std::vector<FuzzyResult> out(hits.size());
    for (size_t i = 0; i < hits.size(); ++i) {
        out[i].index = hits[i].index;
        out[i].score = hits[i].score;
        out[i].rank = unpack_rank(hits[i].key);
    }
    return out;
}

void fill_positions(const QueryImpl& q, std::vector<FuzzyResult>& results,
                    const std::function<std::string_view(uint32_t)>& item_at) {
    MatchScratch& sc = thread_scratch();
    FuzzyMatch m;
    for (auto& r : results) {
        if (q.match_item(item_at(r.index), &m, true, sc)) r.positions = std::move(m.positions);
    }
}

} // namespace bro::search::fuzzy_detail

namespace bro::search {

using namespace fuzzy_detail;

namespace {

template <typename T>
std::vector<FuzzyResult> filter_impl(const FuzzyQuery& query, std::span<const T> items, size_t limit,
                                     bool with_positions, const CancellationToken* token) {
    const QueryImpl& q = query.impl();
    const size_t n = items.size();
    if (q.empty) return all_items(n, limit, q.options.tac);
    // Blocks of ~2048 typical (64-byte) items: long items get smaller blocks so they still spread
    // across threads.
    size_t bytes = 0;
    for (size_t i = 0; i < n; ++i) bytes += std::string_view(items[i]).size();
    const size_t avg = n ? std::max<size_t>(64, bytes / n) : 64;
    const size_t kBlock = std::clamp<size_t>(2048 * 64 / avg, 8, 2048);
    const size_t blocks = (n + kBlock - 1) / kBlock;
    std::vector<std::vector<Hit>> per_block(blocks);

    parallel_for(blocks, resolve_threads(q.options.threads, std::max(n, bytes / 64)), [&](size_t b) {
        if (token && token->is_cancelled()) return;
        MatchScratch& sc = thread_scratch();
        auto& out = per_block[b];
        const size_t end = std::min(n, (b + 1) * kBlock);
        FuzzyRank rank;
        for (size_t i = b * kBlock; i < end; ++i) {
            std::string_view item(items[i]);
            PreparedItem p = prepare_item(item, sc.runes, sc.offsets);
            int32_t score;
            if (q.match_prepared(p, &score, &rank, false, sc))
                out.push_back(Hit{pack_rank(rank), static_cast<uint32_t>(i), score});
        }
    });
    size_t total = 0;
    for (auto& v : per_block) total += v.size();
    std::vector<Hit> hits;
    hits.reserve(total);
    for (auto& v : per_block) hits.insert(hits.end(), v.begin(), v.end());
    auto results = finish_results(hits, q.sortable, limit, q.options.tac);
    if (with_positions) fill_positions(q, results, [&](uint32_t i) { return std::string_view(items[i]); });
    return results;
}

} // namespace

std::vector<FuzzyResult> fuzzy_filter(const FuzzyQuery& query, std::span<const std::string_view> items, size_t limit,
                                      bool with_positions, const CancellationToken* token) {
    return filter_impl(query, items, limit, with_positions, token);
}

std::vector<FuzzyResult> fuzzy_filter(const FuzzyQuery& query, std::span<const std::string> items, size_t limit,
                                      bool with_positions, const CancellationToken* token) {
    return filter_impl(query, items, limit, with_positions, token);
}

} // namespace bro::search
