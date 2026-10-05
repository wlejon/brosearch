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
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace bro::search {

using namespace grep_detail;

namespace {
// A reusable read buffer that, unlike std::string::resize, never zero-fills what it grows into.
class ReadBuffer {
public:
    [[nodiscard]] const char* data() const noexcept { return p_.get(); }
    [[nodiscard]] size_t size() const noexcept { return n_; }
    [[nodiscard]] size_t capacity() const noexcept { return cap_; }
    // Room for at least `extra` more bytes after size(); returns where they go.
    char* reserve(size_t extra) {
        if (n_ + extra > cap_) {
            size_t cap = std::max<size_t>(cap_ ? cap_ : 65536, n_ + extra);
            if (cap < cap_ * 2) cap = cap_ * 2;
            std::unique_ptr<char[]> q(new char[cap]);
            if (n_) std::memcpy(q.get(), p_.get(), n_);
            p_ = std::move(q);
            cap_ = cap;
        }
        return p_.get() + n_;
    }
    void commit(size_t n) noexcept { n_ += n; }
    void clear() noexcept { n_ = 0; }
    void release() noexcept {
        p_.reset();
        n_ = cap_ = 0;
    }

private:
    std::unique_ptr<char[]> p_;
    size_t n_ = 0;
    size_t cap_ = 0;
};
} // namespace

struct Grep::CachePool {
    struct Worker {
        explicit Worker(const rx::Matcher& m) : cache(m) {}
        rx::MatcherCache cache;
        ReadBuffer buffer;
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
        if (w->buffer.capacity() > (size_t(64) << 20)) w->buffer.release();
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

// Reads a whole file with plain descriptor I/O (no stdio buffer copy). Returns false with `err`
// on failure; sets `skipped` when over max_size.
bool read_whole(const std::filesystem::path& p, uint64_t max_size, ReadBuffer& out, std::string& err,
                bool& skipped) {
    skipped = false;
    out.clear();
#ifdef _WIN32
    const int fd = _wopen(p.c_str(), _O_RDONLY | _O_BINARY | _O_NOINHERIT);
#else
    const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
#endif
    if (fd < 0) {
        err = "cannot open file";
        return false;
    }
    uint64_t size = 0;
#ifdef _WIN32
    struct _stat64 st;
    if (_fstat64(fd, &st) == 0) size = static_cast<uint64_t>(st.st_size);
#else
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            ::close(fd);
            err = "is a directory";
            return false;
        }
        size = static_cast<uint64_t>(st.st_size);
    }
#endif
    if (max_size && size > max_size) {
#ifdef _WIN32
        _close(fd);
#else
        ::close(fd);
#endif
        skipped = true;
        return true;
    }
    // Size from stat is a hint (special files report 0, files may grow); read until EOF. The
    // slack lets the final zero-length read (and modest growth) land without reallocating.
    bool bad = false;
    out.reserve(static_cast<size_t>(size) + 65536);
    for (;;) {
        if (out.capacity() - out.size() < 4096) out.reserve(std::max<size_t>(65536, out.size()));
        char* dst = out.reserve(0);
        const size_t room = std::min<size_t>(out.capacity() - out.size(), size_t(1) << 30);
#ifdef _WIN32
        const int n = _read(fd, dst, static_cast<unsigned>(room));
#else
        ssize_t n;
        do {
            n = ::read(fd, dst, room);
        } while (n < 0 && errno == EINTR);
#endif
        if (n < 0) {
            bad = true;
            break;
        }
        if (n == 0) break;
        out.commit(static_cast<size_t>(n));
    }
#ifdef _WIN32
    _close(fd);
#else
    ::close(fd);
#endif
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

// A multiline (-U) search of a file holding a NUL, as rg does it: the whole file is one buffer
// and is never converted. A NUL in its first 64 KiB is caught up front (Quit: nothing is searched;
// Report: nothing is shown, everything is counted); past that only the lines about to be
// reported are checked (see BinaryGuard).
void search_whole_binary(const rx::Matcher& m, rx::MatcherCache& cache, const GrepOptions& o, const uint8_t* d,
                         size_t len, const LineSink& sink, const CancellationToken* token, bool count_only,
                         GrepFileResult& res) {
    constexpr size_t kUpFront = size_t(64) << 10;  // grep-searcher's DEFAULT_BUFFER_CAPACITY
    const bool quit = o.binary == BinaryMode::Quit;
    res.bytes_searched = len;
    if (res.binary_offset < kUpFront) {
        if (quit) {
            res.bytes_searched = 0;
            return;
        }
        static const LineSink kNone = [](const GrepLineView&) { return true; };
        ContentResult cr = search_content(m, cache, d, len, o, kNone, token, true);
        res.matched_lines = cr.selected;
        res.matches = cr.matches;
        res.binary_matched = cr.selected > 0;
        return;
    }
    BinaryGuard guard;
    guard.quit = quit;
    ContentResult cr = search_content(m, cache, d, len, o, sink, token, count_only, &guard);
    res.matched_lines = cr.selected;
    res.matches = cr.matches;
    res.binary = cr.binary_hit && quit;
    if (cr.binary_hit) res.binary_offset = cr.binary_offset;
    res.binary_matched = cr.binary_hit && !quit && cr.selected > 0;
    if (cr.binary_hit && !quit) res.binary_stop_offset = cr.binary_stop;
}

// rg_binary_cutoff's context model: the lines rg would report from data[0, limit), each keyed by
// where rg's searcher is when it reports it (its own start for a match or trailing context, its
// match's start for leading context), with its end. Keys are non-decreasing.
CutoffContext cutoff_context(const rx::Matcher& m, rx::MatcherCache& cache, const GrepOptions& o, const uint8_t* d,
                             size_t limit, const CancellationToken* token) {
    struct Visit {
        size_t at, end;
    };
    auto visits = std::make_shared<std::vector<Visit>>();
    std::vector<size_t> leading;  // leading context waiting for its match
    size_t prev_end = SIZE_MAX, run = 0;
    bool trailing = false;
    GrepOptions po = o;
    po.collect_spans = false;
    po.line_numbers = false;
    LineSink sink = [&](const GrepLineView& v) {
        const size_t s = static_cast<size_t>(v.byte_offset), e = s + v.text.size() + 1;
        if (v.kind == LineKind::Match) {
            for (size_t i : leading) (*visits)[i].at = s;
            leading.clear();
            visits->push_back({s, e});
            trailing = true;
            run = 0;
        } else if (trailing && s == prev_end && run < o.after_context) {
            visits->push_back({s, e});
            ++run;
        } else {
            leading.push_back(visits->size());
            visits->push_back({SIZE_MAX, e});
            trailing = false;
        }
        prev_end = e;
        return true;
    };
    search_content(m, cache, d, limit, po, sink, token);
    CutoffContext cc;
    cc.before_context = o.before_context;
    cc.visited = [visits](size_t lo, size_t hi) -> size_t {
        auto it = std::lower_bound(visits->begin(), visits->end(), hi,
                                   [](const Visit& v, size_t key) { return v.at < key; });
        if (it == visits->begin()) return 0;
        --it;
        return it->at >= lo ? it->end : 0;
    };
    return cc;
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
    ro.line_mode = !options.multiline;
    ro.dot_matches_new_line = options.multiline && options.multiline_dotall;
    ro.size_limit = options.regex_size_limit;
    auto re = Regex::compile(pattern, ro, error);
    if (!re) return nullptr;
    GrepOptions effective = options;
    if (options.multiline && !re->matcher().can_match_newline()) {
        // Like rg: a pattern that can never match a line terminator (and has no anchors) is
        // searched line by line even under -U.
        ro.line_mode = true;
        ro.dot_matches_new_line = false;
        auto line_re = Regex::compile(pattern, ro, nullptr);
        if (line_re) {
            re = std::move(line_re);
            effective.multiline = false;
        }
    }
    auto g = std::make_shared<Grep>();
    g->options_ = effective;
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
    if (!options_.collect_lines) return search_path(file, std::move(display), token, nullptr);
    std::vector<GrepLine> lines;
    LineSink sink = [&](const GrepLineView& v) {
        lines.push_back(GrepLine{v.kind, v.line_number, v.byte_offset, std::string(v.text),
                                 std::vector<GrepSpan>(v.spans.begin(), v.spans.end())});
        return true;
    };
    GrepFileResult res = search_path(file, std::move(display), token, &sink);
    res.lines = std::move(lines);
    return res;
}

GrepFileResult Grep::search_path(const std::filesystem::path& file, std::string display,
                                 const CancellationToken* token, const LineSink* line_sink) const {
    GrepFileResult res;
    res.path = std::move(display);
    auto w = pool_->take(regex_->matcher());
    bool skipped = false;
    if (!read_whole(file, options_.max_filesize, w->buffer, res.error, skipped) || skipped) {
        pool_->give(std::move(w));
        return res;
    }
    std::string_view content(w->buffer.data(), w->buffer.size());
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
    static const LineSink kNoSink = [](const GrepLineView&) { return true; };
    const bool count_only = line_sink == nullptr;
    if (nul && options_.multiline) {
        search_whole_binary(regex_->matcher(), w->cache, options_, d, len, line_sink ? *line_sink : kNoSink, token,
                            count_only, res);
        pool_->give(std::move(w));
        return res;
    }
    // Binary data: rg has searched the complete lines read before the block holding the NUL.
    size_t searched = len;
    if (nul) {
        const size_t at = static_cast<size_t>(res.binary_offset);
        if (options_.before_context || options_.after_context) {  // rg -c / -l keep context too
            size_t line = at;
            while (line > 0 && d[line - 1] != '\n') --line;
            const CutoffContext cc = cutoff_context(regex_->matcher(), w->cache, options_, d, line, token);
            searched = rg_binary_cutoff(d, len, at, &cc);
        } else {
            searched = rg_binary_cutoff(d, len, at);
        }
    }
    res.bytes_searched = searched;
    // Report mode with after-context: where the last reported match line ended.
    size_t last_match_end = SIZE_MAX;
    LineSink tracking;
    const LineSink* sink = line_sink ? line_sink : &kNoSink;
    if (nul && line_sink && options_.binary == BinaryMode::Report && options_.after_context) {
        tracking = [&](const GrepLineView& v) {
            if (v.kind == LineKind::Match) last_match_end = static_cast<size_t>(v.byte_offset) + v.text.size();
            return (*line_sink)(v);
        };
        sink = &tracking;
    }
    ContentResult cr = search_content(regex_->matcher(), w->cache, d, searched, options_, *sink, token, count_only);
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
        const auto* cd = reinterpret_cast<const uint8_t*>(conv.data());
        if (count_only) {
            // Counting (rg -c / --count-matches / -l): rg's summary printer counts the converted
            // remainder too (as `rg --no-mmap`; see README for rg's memory-map path).
            GrepOptions rest = options_;
            if (rest.max_count) rest.max_count -= cr.selected;
            ContentResult more = search_content(regex_->matcher(), w->cache, cd, conv.size(), rest, kNoSink, token, true);
            res.matched_lines += more.selected;
            res.matches += more.matches;
            res.binary_matched = more.selected > 0;
        } else {
            // rg's standard printer stops at the first line it is handed after the binary data
            // was read (trailing context still owed, leading context of the next match, or the
            // match). The file "matches" if a match was reported before or is that line.
            const bool owed_after = last_match_end != SIZE_MAX &&
                                    count_newlines(d + last_match_end, searched - last_match_end) <=
                                        options_.after_context;
            bool stops_on_match = false;
            if (owed_after) {
                res.binary_stop_offset = searched;
            } else if (auto p = first_selected(regex_->matcher(), w->cache, cd, conv.size(), options_.invert, token)) {
                size_t q = *p;  // back over its leading context
                for (size_t k = 0; k < options_.before_context && q > 0; ++k) {
                    --q;
                    while (q > 0 && cd[q - 1] != '\n') --q;
                }
                res.binary_stop_offset = searched + q;
                stops_on_match = q == *p;
            }
            res.binary_matched = cr.selected > 0 || stops_on_match;
        }
    }
    pool_->give(std::move(w));
    return res;
}

GrepFileResult Grep::search_file(const std::filesystem::path& file, const CancellationToken* token) const {
    return search_path(file, path_utf8(file), token);
}

GrepFileResult Grep::search_file(const std::filesystem::path& file, std::string display, GrepFileVisitor& visitor,
                                 const CancellationToken* token) const {
    LineSink sink = [&](const GrepLineView& v) { return visitor.line(v); };
    GrepFileResult res = search_path(file, std::move(display), token, options_.collect_lines ? &sink : nullptr);
    visitor.finish(res);
    return res;
}

bool Grep::stream_path(const std::filesystem::path& file, std::string display, const GrepVisitorFactory& make,
                       const CancellationToken* token, GrepFileResult& res) const {
    std::unique_ptr<GrepFileVisitor> visitor;
    LineSink sink = [&](const GrepLineView& v) {
        if (!visitor) visitor = make(display);
        return visitor->line(v);
    };
    res = search_path(file, display, token, options_.collect_lines ? &sink : nullptr);
    if (!visitor && (res.matched_lines || res.binary_matched || !res.error.empty())) visitor = make(display);
    return visitor ? visitor->finish(res) : true;
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

namespace {

// Runs `one(path, display)` (returns false to stop everything) over a file list on worker threads.
template <class F>
void for_each_file(const std::vector<std::filesystem::path>& files, size_t threads, const CancellationToken* token,
                   std::atomic<bool>& stop, F&& one) {
    std::atomic<size_t> next{0};
    auto worker = [&] {
        for (;;) {
            if (stop.load(std::memory_order_relaxed) || (token && token->is_cancelled())) return;
            size_t i = next.fetch_add(1);
            if (i >= files.size()) return;
            if (!one(files[i], path_utf8(files[i]))) stop.store(true);
        }
    };
    size_t n = std::min(threads, std::max<size_t>(files.size(), 1));
    if (n <= 1) {
        worker();
    } else {
        std::vector<std::thread> pool;
        for (size_t t = 0; t < n; ++t) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
    }
}

// The same over a directory walk (files are searched in the walk's worker threads).
template <class F>
void for_each_walked(const std::filesystem::path& root, WalkOptions wo, size_t threads,
                     const CancellationToken* token, std::atomic<bool>& stop, F&& one) {
    if (wo.threads == 0) wo.threads = threads;
    walk(
        root, wo,
        [&](const WalkEntry& e) {
            if (stop.load(std::memory_order_relaxed) || (token && token->is_cancelled())) return false;
            if (e.type != EntryType::File || !e.native_path) return true;
            if (!one(*e.native_path, std::string(e.rel_path))) stop.store(true);
            return !stop.load(std::memory_order_relaxed);
        },
        token);
}

} // namespace

void Grep::search_files(const std::vector<std::filesystem::path>& files, const FileSink& sink,
                        const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<bool> stop{false};
    std::mutex sink_mu;
    for_each_file(files, default_threads(options_.threads), token, stop,
                  [&](const std::filesystem::path& p, std::string display) {
                      GrepFileResult r = search_path(p, std::move(display), token);
                      acc.add(r);
                      if (!(r.matched_lines || r.binary_matched || !r.error.empty())) return true;
                      std::lock_guard<std::mutex> lock(sink_mu);
                      return !stop.load() && sink(r);
                  });
    acc.finish(stats);
}

void Grep::search_tree(const std::filesystem::path& root, const WalkOptions& walk_options, const FileSink& sink,
                       const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<bool> stop{false};
    std::mutex sink_mu;
    for_each_walked(root, walk_options, default_threads(options_.threads), token, stop,
                    [&](const std::filesystem::path& p, std::string display) {
                        GrepFileResult r = search_path(p, std::move(display), token);
                        acc.add(r);
                        if (!(r.matched_lines || r.binary_matched || !r.error.empty())) return true;
                        std::lock_guard<std::mutex> lock(sink_mu);
                        return !stop.load() && sink(r);
                    });
    acc.finish(stats);
}

void Grep::search_files(const std::vector<std::filesystem::path>& files, const GrepVisitorFactory& make,
                        const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<bool> stop{false};
    for_each_file(files, default_threads(options_.threads), token, stop,
                  [&](const std::filesystem::path& p, std::string display) {
                      GrepFileResult r;
                      const bool go_on = stream_path(p, std::move(display), make, token, r);
                      acc.add(r);
                      return go_on;
                  });
    acc.finish(stats);
}

void Grep::search_tree(const std::filesystem::path& root, const WalkOptions& walk_options,
                       const GrepVisitorFactory& make, const CancellationToken* token, GrepStats* stats) const {
    StatsAccumulator acc;
    std::atomic<bool> stop{false};
    for_each_walked(root, walk_options, default_threads(options_.threads), token, stop,
                    [&](const std::filesystem::path& p, std::string display) {
                        GrepFileResult r;
                        const bool go_on = stream_path(p, std::move(display), make, token, r);
                        acc.add(r);
                        return go_on;
                    });
    acc.finish(stats);
}

} // namespace bro::search
