#include "brosearch/grep.h"

#include "grep/decode.h"
#include "grep/searcher.h"
#include "regex/matcher.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <sys/stat.h>
#endif

namespace bro::search {

using namespace grep_detail;

struct Grep::CachePool {
    struct Worker {
        explicit Worker(const rx::Matcher& m) : cache(m) {}
        rx::MatcherCache cache;
        std::string buffer;
        std::string decoded;
    };
    std::mutex mu;
    std::vector<std::unique_ptr<Worker>> free;

    std::unique_ptr<Worker> take(const rx::Matcher& m) {
        {
            std::lock_guard<std::mutex> lock(mu);
            if (!free.empty()) {
                auto w = std::move(free.back());
                free.pop_back();
                return w;
            }
        }
        return std::make_unique<Worker>(m);
    }
    void give(std::unique_ptr<Worker> w) {
        if (w->buffer.capacity() > (size_t(64) << 20)) std::string().swap(w->buffer);
        if (w->decoded.capacity() > (size_t(64) << 20)) std::string().swap(w->decoded);
        std::lock_guard<std::mutex> lock(mu);
        free.push_back(std::move(w));
    }
};

namespace {

size_t default_threads(size_t requested) {
    if (requested) return requested;
    unsigned hc = std::thread::hardware_concurrency();
    return std::clamp<size_t>(hc ? hc : 4, 1, 16);
}

// Reads a whole file. Returns false with `err` on failure; sets `skipped` when over max_size.
bool read_whole(const std::filesystem::path& p, uint64_t max_size, std::string& out, std::string& err, bool& skipped) {
    skipped = false;
    out.clear();
#ifdef _WIN32
    std::FILE* f = _wfopen(p.c_str(), L"rb");
#else
    std::FILE* f = std::fopen(p.c_str(), "rb");
#endif
    if (!f) {
        err = "cannot open file";
        return false;
    }
    uint64_t size = 0;
#ifdef _WIN32
    struct _stat64 st;
    if (_fstat64(_fileno(f), &st) == 0) size = static_cast<uint64_t>(st.st_size);
#else
    struct stat st;
    if (fstat(fileno(f), &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            std::fclose(f);
            err = "is a directory";
            return false;
        }
        size = static_cast<uint64_t>(st.st_size);
    }
#endif
    if (max_size && size > max_size) {
        std::fclose(f);
        skipped = true;
        return true;
    }
    // Size from stat is a hint (special files report 0, files may grow); read until EOF.
    out.resize(static_cast<size_t>(size) + 1);
    size_t got = 0;
    for (;;) {
        if (got == out.size()) out.resize(out.size() * 2 + 65536);
        size_t n = std::fread(&out[got], 1, out.size() - got, f);
        got += n;
        if (n == 0) break;
    }
    bool bad = std::ferror(f) != 0;
    std::fclose(f);
    out.resize(got);
    if (bad) {
        err = "read error";
        return false;
    }
    return true;
}

std::string path_utf8(const std::filesystem::path& p) {
    auto u8 = p.generic_u8string();
    return std::string(u8.begin(), u8.end());
}

} // namespace

std::shared_ptr<const Grep> Grep::compile(std::string_view pattern, const GrepOptions& options, std::string* error) {
    RegexOptions ro;
    ro.literal = options.fixed_strings;
    ro.case_insensitive = options.case_matching == CaseMatching::Insensitive;
    ro.smart_case = options.case_matching == CaseMatching::Smart;
    ro.word = options.word;
    ro.whole_line = options.whole_line;
    ro.crlf = options.crlf;
    ro.unicode = options.unicode;
    ro.multi_line = true;
    ro.line_mode = true;
    ro.size_limit = options.regex_size_limit;
    auto re = Regex::compile(pattern, ro, error);
    if (!re) return nullptr;
    auto g = std::make_shared<Grep>();
    g->options_ = options;
    g->regex_ = std::move(re);
    g->pool_ = std::make_shared<CachePool>();
    return g;
}

size_t Grep::search_buffer(std::string_view buffer, const LineSink& sink, const CancellationToken* token) const {
    auto w = pool_->take(regex_->matcher());
    const uint8_t* d = reinterpret_cast<const uint8_t*>(buffer.data());
    size_t len = buffer.size();
    size_t selected = 0;
    const void* nul = options_.binary == BinaryMode::Text ? nullptr : std::memchr(d, 0, len);
    if (nul) len = rg_binary_cutoff(d, len, static_cast<size_t>(static_cast<const uint8_t*>(nul) - d));
    selected = search_content(regex_->matcher(), w->cache, d, len, options_, sink, token).selected;
    pool_->give(std::move(w));
    return selected;
}

std::vector<GrepLine> Grep::search_buffer(std::string_view buffer, const CancellationToken* token) const {
    std::vector<GrepLine> out;
    search_buffer(
        buffer,
        [&](const GrepLineView& v) {
            out.push_back(GrepLine{v.kind, v.line_number, v.byte_offset, std::string(v.text),
                                   std::vector<GrepSpan>(v.spans.begin(), v.spans.end())});
            return true;
        },
        token);
    return out;
}

GrepFileResult Grep::search_path(const std::filesystem::path& file, std::string display,
                                 const CancellationToken* token) const {
    GrepFileResult res;
    res.path = std::move(display);
    auto w = pool_->take(regex_->matcher());
    bool skipped = false;
    if (!read_whole(file, options_.max_filesize, w->buffer, res.error, skipped) || skipped) {
        pool_->give(std::move(w));
        return res;
    }
    std::string_view content(w->buffer);
    if (options_.bom_sniffing) {
        switch (sniff_bom(content)) {
            case Bom::Utf8:
                content.remove_prefix(3);
                break;
            case Bom::Utf16LE:
            case Bom::Utf16BE:
                w->decoded.clear();
                transcode_utf16(reinterpret_cast<const uint8_t*>(content.data()) + 2, content.size() - 2,
                                sniff_bom(content) == Bom::Utf16LE, w->decoded);
                content = w->decoded;
                break;
            case Bom::None:
                break;
        }
    }
    const uint8_t* d = reinterpret_cast<const uint8_t*>(content.data());
    size_t len = content.size();
    const void* nul = options_.binary == BinaryMode::Text ? nullptr : std::memchr(d, 0, len);
    if (nul) {
        res.binary = true;
        res.binary_offset = static_cast<uint64_t>(static_cast<const uint8_t*>(nul) - d);
    }
    // Binary data: rg has searched the complete lines read before the block holding the NUL.
    size_t searched = nul ? rg_binary_cutoff(d, len, static_cast<size_t>(res.binary_offset)) : len;
    res.bytes_searched = searched;
    LineSink sink = [&](const GrepLineView& v) {
        if (options_.collect_lines)
            res.lines.push_back(GrepLine{v.kind, v.line_number, v.byte_offset, std::string(v.text),
                                         std::vector<GrepSpan>(v.spans.begin(), v.spans.end())});
        return true;
    };
    const bool count_only = !options_.collect_lines;
    ContentResult cr = search_content(regex_->matcher(), w->cache, d, searched, options_, sink, token, count_only);
    res.matched_lines = cr.selected;
    res.matches = cr.matches;
    // Stopping at max_count before the NUL's block means rg never saw the binary data.
    if (nul && options_.max_count && cr.selected >= options_.max_count) {
        res.binary = false;
        pool_->give(std::move(w));
        return res;
    }
    if (nul && options_.binary == BinaryMode::Report &&
        (options_.max_count == 0 || cr.selected < options_.max_count)) {
        // The rest is searched with NULs as line terminators; a match is reported, not shown.
        std::string conv(content.substr(searched));
        std::replace(conv.begin(), conv.end(), '\0', '\n');
        res.bytes_searched = len;
        res.binary_matched = any_match(regex_->matcher(), w->cache, reinterpret_cast<const uint8_t*>(conv.data()),
                                       conv.size(), options_.invert, token);
    }
    pool_->give(std::move(w));
    return res;
}

GrepFileResult Grep::search_file(const std::filesystem::path& file, const CancellationToken* token) const {
    return search_path(file, path_utf8(file), token);
}

namespace {

struct StatsAccumulator {
    std::mutex mu;
    GrepStats s;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();

    void add(const GrepFileResult& r) {
        std::lock_guard<std::mutex> lock(mu);
        ++s.files_searched;
        if (r.matched_lines || r.binary_matched) ++s.files_matched;
        if (r.binary) ++s.binary_files;
        s.matched_lines += r.matched_lines;
        s.matches += r.matches;
        s.bytes_searched += r.bytes_searched;
    }
    void finish(GrepStats* out) {
        if (!out) return;
        s.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        *out = s;
    }
};

} // namespace

void Grep::search_files(const std::vector<std::filesystem::path>& files, const FileSink& sink,
                        const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<size_t> next{0};
    std::atomic<bool> stop{false};
    std::mutex sink_mu;
    auto worker = [&] {
        for (;;) {
            if (stop.load(std::memory_order_relaxed) || (token && token->is_cancelled())) return;
            size_t i = next.fetch_add(1);
            if (i >= files.size()) return;
            GrepFileResult r = search_path(files[i], path_utf8(files[i]), token);
            acc.add(r);
            if (r.matched_lines || r.binary_matched || !r.error.empty()) {
                std::lock_guard<std::mutex> lock(sink_mu);
                if (!stop.load() && !sink(r)) stop.store(true);
            }
        }
    };
    size_t n = std::min(default_threads(options_.threads), std::max<size_t>(files.size(), 1));
    if (n <= 1) {
        worker();
    } else {
        std::vector<std::thread> threads;
        for (size_t t = 0; t < n; ++t) threads.emplace_back(worker);
        for (auto& t : threads) t.join();
    }
    acc.finish(stats);
}

void Grep::search_tree(const std::filesystem::path& root, const WalkOptions& walk_options, const FileSink& sink,
                       const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<bool> stop{false};
    std::mutex sink_mu;
    WalkOptions wo = walk_options;
    if (wo.threads == 0) wo.threads = default_threads(options_.threads);
    walk(
        root, wo,
        [&](const WalkEntry& e) {
            if (stop.load(std::memory_order_relaxed) || (token && token->is_cancelled())) return false;
            if (e.type != EntryType::File || !e.native_path) return true;
            GrepFileResult r = search_path(*e.native_path, std::string(e.rel_path), token);
            acc.add(r);
            if (r.matched_lines || r.binary_matched || !r.error.empty()) {
                std::lock_guard<std::mutex> lock(sink_mu);
                if (!stop.load() && !sink(r)) stop.store(true);
            }
            return !stop.load(std::memory_order_relaxed);
        },
        token);
    acc.finish(stats);
}

} // namespace bro::search
