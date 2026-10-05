// Incremental fuzzy index: chunked append-only item store + fzf-style per-chunk match cache.
#include "brosearch/fuzzy_index.h"

#include "fuzzy/fuzzy_rank.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

namespace bro::search {

using namespace fuzzy_detail;

namespace {

constexpr size_t kChunkSize = 1024;                  // fzf chunkSize
constexpr size_t kBitWords = kChunkSize / 64;
constexpr size_t kQueryCacheMax = kChunkSize / 2;    // fzf queryCacheMax
constexpr size_t kMaxKeysPerChunk = 64;              // bound memory; oldest key evicted first

using Bitmap = std::array<uint64_t, kBitWords>;

struct StoredItem {
    std::string text;
    std::vector<uint32_t> runes;    // empty for ASCII items
    std::vector<uint32_t> offsets;  // byte offset per rune, for non-ASCII items
    bool ascii = true;

    PreparedItem prepared() const {
        PreparedItem p;
        p.byte_len = static_cast<uint32_t>(text.size());
        p.text = text;
        if (ascii) {
            p.chars.bytes = reinterpret_cast<const unsigned char*>(text.c_str());
            p.chars.n = static_cast<int32_t>(text.size());
        } else {
            p.chars.runes = runes.data();
            p.chars.n = static_cast<int32_t>(runes.size());
            p.byte_offsets = offsets.data();
        }
        return p;
    }
};

struct Chunk {
    std::unique_ptr<StoredItem[]> items{new StoredItem[kChunkSize]};
    std::atomic<uint32_t> count{0};
    uint32_t base = 0;  // index of items[0]
};

struct CacheEntry {
    std::string key;
    Bitmap bits;
};

} // namespace

struct FuzzyIndex::Impl {
    FuzzyOptions options;
    mutable std::shared_mutex chunks_mutex;  // guards the chunk list (not item contents)
    std::deque<std::unique_ptr<Chunk>> chunks;
    std::atomic<size_t> total{0};

    std::mutex cache_mutex;
    std::unordered_map<const Chunk*, std::vector<CacheEntry>> cache;
    bool cache_enabled = true;

    const Bitmap* lookup(const Chunk* c, const std::string& key, Bitmap& out) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(c);
        if (it == cache.end()) return nullptr;
        for (auto& e : it->second)
            if (e.key == key) {
                out = e.bits;
                return &out;
            }
        return nullptr;
    }

    // fzf ChunkCache.Search: the longest proper prefix or suffix of the key with an entry.
    const Bitmap* search(const Chunk* c, const std::string& key, Bitmap& out) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(c);
        if (it == cache.end()) return nullptr;
        for (size_t idx = 1; idx < key.size(); ++idx) {
            std::string_view prefix(key.data(), key.size() - idx);
            std::string_view suffix(key.data() + idx, key.size() - idx);
            for (std::string_view sub : {prefix, suffix}) {
                for (auto& e : it->second)
                    if (e.key == sub) {
                        out = e.bits;
                        return &out;
                    }
            }
        }
        return nullptr;
    }

    void store(const Chunk* c, const std::string& key, const Bitmap& bits) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto& v = cache[c];
        for (auto& e : v)
            if (e.key == key) {
                e.bits = bits;
                return;
            }
        if (v.size() >= kMaxKeysPerChunk) v.erase(v.begin());
        v.push_back({key, bits});
    }

    void append_locked(std::string_view text) {
        if (chunks.empty() || chunks.back()->count.load(std::memory_order_relaxed) == kChunkSize) {
            auto c = std::make_unique<Chunk>();
            c->base = static_cast<uint32_t>(total.load(std::memory_order_relaxed));
            chunks.push_back(std::move(c));
        }
        Chunk& c = *chunks.back();
        uint32_t slot = c.count.load(std::memory_order_relaxed);
        StoredItem& it = c.items[slot];
        it.text.assign(text.data(), text.size());
        std::vector<uint32_t> runes, offsets;
        PreparedItem p = prepare_item(it.text, runes, offsets);
        it.ascii = p.chars.is_bytes();
        if (!it.ascii) {
            it.runes = std::move(runes);
            it.offsets = std::move(offsets);
        }
        c.count.store(slot + 1, std::memory_order_release);
        total.fetch_add(1, std::memory_order_release);
    }
};

FuzzyIndex::FuzzyIndex(const FuzzyOptions& options) : impl_(std::make_unique<Impl>()) { impl_->options = options; }
FuzzyIndex::~FuzzyIndex() = default;

uint32_t FuzzyIndex::add(std::string_view item) {
    std::unique_lock<std::shared_mutex> lock(impl_->chunks_mutex);
    uint32_t idx = static_cast<uint32_t>(impl_->total.load(std::memory_order_relaxed));
    impl_->append_locked(item);
    return idx;
}

void FuzzyIndex::add(std::span<const std::string_view> items) {
    std::unique_lock<std::shared_mutex> lock(impl_->chunks_mutex);
    for (auto s : items) impl_->append_locked(s);
}

void FuzzyIndex::add(std::span<const std::string> items) {
    std::unique_lock<std::shared_mutex> lock(impl_->chunks_mutex);
    for (const auto& s : items) impl_->append_locked(s);
}

size_t FuzzyIndex::size() const noexcept { return impl_->total.load(std::memory_order_acquire); }

std::string_view FuzzyIndex::item(uint32_t index) const {
    std::shared_lock<std::shared_mutex> lock(impl_->chunks_mutex);
    size_t ci = index / kChunkSize;
    if (ci >= impl_->chunks.size()) return {};
    const Chunk& c = *impl_->chunks[ci];
    if (index % kChunkSize >= c.count.load(std::memory_order_acquire)) return {};
    return c.items[index % kChunkSize].text;
}

const FuzzyOptions& FuzzyIndex::options() const noexcept { return impl_->options; }

void FuzzyIndex::set_cache_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(impl_->cache_mutex);
    impl_->cache_enabled = enabled;
    if (!enabled) impl_->cache.clear();
}

void FuzzyIndex::clear_cache() {
    std::lock_guard<std::mutex> lock(impl_->cache_mutex);
    impl_->cache.clear();
}

void FuzzyIndex::clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->chunks_mutex);
    clear_cache();
    impl_->chunks.clear();
    impl_->total.store(0);
}

FuzzySearchResult FuzzyIndex::search(std::string_view query_text, size_t limit, bool with_positions,
                                     const CancellationToken* token) {
    FuzzySearchResult out;
    FuzzyQuery query(query_text, impl_->options);
    const QueryImpl& q = query.impl();

    // Snapshot: chunk pointers and their counts at this moment.
    std::vector<std::pair<const Chunk*, uint32_t>> snap;
    {
        std::shared_lock<std::shared_mutex> lock(impl_->chunks_mutex);
        snap.reserve(impl_->chunks.size());
        for (auto& c : impl_->chunks) snap.emplace_back(c.get(), c->count.load(std::memory_order_acquire));
    }
    for (auto& s : snap) out.item_count += s.second;

    if (q.empty) {
        out.results = all_items(out.item_count, limit, q.options.tac);
        out.match_count = out.item_count;
        out.candidates_scanned = 0;
        return out;
    }

    bool use_cache;
    {
        std::lock_guard<std::mutex> lock(impl_->cache_mutex);
        use_cache = impl_->cache_enabled;
    }
    const std::string& key = q.cache_key;
    const bool cacheable = q.cacheable && use_cache;

    std::vector<std::vector<Hit>> per_chunk(snap.size());
    std::vector<size_t> scanned(snap.size(), 0);
    std::atomic<bool> cancelled{false};

    parallel_for(snap.size(), resolve_threads(impl_->options.threads, out.item_count), [&](size_t ci) {
        MatchScratch& sc = thread_scratch();
        {
            if (token && token->is_cancelled()) {
                cancelled.store(true, std::memory_order_relaxed);
                return;
            }
            const Chunk* c = snap[ci].first;
            const uint32_t count = snap[ci].second;
            const bool full = count == kChunkSize;
            Bitmap cached_store{};
            const Bitmap* cached = nullptr;
            if (use_cache && full && !key.empty()) {
                if (cacheable) cached = impl_->lookup(c, key, cached_store);
                if (!cached) cached = impl_->search(c, key, cached_store);
            }
            Bitmap bits{};
            auto& res = per_chunk[ci];
            size_t n_scanned = 0;
            for (uint32_t i = 0; i < count; ++i) {
                if (cached && !((*cached)[i / 64] >> (i % 64) & 1)) continue;
                ++n_scanned;
                int32_t score;
                FuzzyRank rank;
                if (q.match_prepared(c->items[i].prepared(), &score, &rank, false, sc)) {
                    res.push_back(Hit{pack_rank(rank), c->base + i, score});
                    bits[i / 64] |= uint64_t(1) << (i % 64);
                }
            }
            scanned[ci] = n_scanned;
            if (cacheable && full && res.size() <= kQueryCacheMax) impl_->store(c, key, bits);
        }
    });
    out.cancelled = cancelled.load();
    size_t total = 0;
    for (auto& v : per_chunk) total += v.size();
    out.match_count = total;
    for (size_t s : scanned) out.candidates_scanned += s;
    std::vector<Hit> hits;
    hits.reserve(total);
    for (auto& v : per_chunk) hits.insert(hits.end(), v.begin(), v.end());
    out.results = finish_results(hits, q.sortable, limit, q.options.tac);
    if (with_positions) {
        fill_positions(q, out.results, [&](uint32_t idx) {
            const Chunk* c = snap[idx / kChunkSize].first;
            return std::string_view(c->items[idx % kChunkSize].text);
        });
    }
    return out;
}

} // namespace bro::search
