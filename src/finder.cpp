#include "brosearch/finder.h"
#include "brosearch/fuzzy.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

namespace bro::search {

namespace {

struct DirTask {
    std::filesystem::path dir_path;
    size_t depth = 0;
};

class TaskQueue {
public:
    void push(DirTask task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_.push(std::move(task));
            ++active_tasks_;
        }
        cv_.notify_one();
    }

    bool pop(DirTask& task) {
        std::unique_lock<std::mutex> lock(mutex_);
        while (tasks_.empty()) {
            if (active_tasks_ == 0 || stopped_) {
                return false;
            }
            cv_.wait(lock);
        }
        task = std::move(tasks_.front());
        tasks_.pop();
        return true;
    }

    void task_done() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --active_tasks_;
        }
        cv_.notify_all();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        cv_.notify_all();
    }

    bool is_empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return tasks_.empty() && active_tasks_ == 0;
    }

private:
    std::queue<DirTask> tasks_;
    size_t active_tasks_ = 0;
    bool stopped_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
};

} // namespace

void find_files_callback(
    const std::filesystem::path& root_path,
    const FindOptions& options,
    std::function<bool(const FileEntry&)> on_entry,
    const CancellationToken* token
) {
    std::error_code ec;
    if (!std::filesystem::exists(root_path, ec) || !std::filesystem::is_directory(root_path, ec)) {
        return;
    }

    // Prepare ignore filter
    std::shared_ptr<IgnoreFilter> filter = options.custom_ignore_filter;
    if (!filter) {
        filter = std::make_shared<IgnoreFilter>(options.respect_gitignore);
    }
    if (options.respect_gitignore) {
        std::filesystem::path root_gitignore = root_path / ".gitignore";
        if (std::filesystem::exists(root_gitignore, ec)) {
            filter->load_file(root_gitignore, root_path.generic_string());
        }
    }

    size_t num_threads = options.thread_count;
    if (num_threads == 0) {
        num_threads = std::max(1u, std::min(std::thread::hardware_concurrency(), 8u));
    }

    TaskQueue queue;
    queue.push(DirTask{root_path, 0});

    std::atomic<bool> stopped{false};
    std::atomic<size_t> result_count{0};
    std::mutex cb_mutex;
    std::mutex filter_mutex;

    auto dir_options = options.follow_symlinks
        ? std::filesystem::directory_options::follow_directory_symlink
        : std::filesystem::directory_options::none;

    auto worker = [&]() {
        DirTask task;
        while (!stopped.load(std::memory_order_relaxed) && queue.pop(task)) {
            if (token && token->is_cancelled()) {
                stopped.store(true, std::memory_order_relaxed);
                queue.task_done();
                queue.stop();
                break;
            }

            // Check if directory has local .gitignore
            if (options.respect_gitignore && task.depth > 0) {
                std::filesystem::path local_gitignore = task.dir_path / ".gitignore";
                std::error_code git_ec;
                if (std::filesystem::exists(local_gitignore, git_ec)) {
                    std::lock_guard<std::mutex> lock(filter_mutex);
                    filter->load_file(local_gitignore, task.dir_path.generic_string());
                }
            }

            std::error_code iter_ec;
            std::filesystem::directory_iterator iter(task.dir_path, dir_options, iter_ec);
            if (!iter_ec) {
                for (const auto& entry : iter) {
                    if (stopped.load(std::memory_order_relaxed)) break;
                    if (token && token->is_cancelled()) {
                        stopped.store(true, std::memory_order_relaxed);
                        break;
                    }

                    std::string filename = entry.path().filename().string();
                    if (!options.include_hidden && !filename.empty() && filename.front() == '.') {
                        continue;
                    }

                    std::error_code status_ec;
                    bool is_dir = entry.is_directory(status_ec);
                    if (status_ec) continue;

                    std::error_code rel_ec;
                    std::filesystem::path rel_p = std::filesystem::relative(entry.path(), root_path, rel_ec);
                    std::string rel_str = rel_ec ? filename : rel_p.generic_string();

                    // Check ignore rules
                    {
                        std::lock_guard<std::mutex> lock(filter_mutex);
                        if (filter->is_ignored(rel_str, is_dir)) {
                            continue;
                        }
                    }

                    if (is_dir) {
                        if (options.include_directories) {
                            bool match_glob = true;
                            if (!options.glob_pattern.empty()) {
                                match_glob = IgnoreFilter::glob_match(options.glob_pattern, filename);
                            }
                            if (match_glob) {
                                FileEntry fe;
                                fe.path = entry.path();
                                fe.relative_path = rel_str;
                                fe.filename = filename;
                                fe.is_directory = true;

                                std::lock_guard<std::mutex> lock(cb_mutex);
                                if (!on_entry(fe)) {
                                    stopped.store(true, std::memory_order_relaxed);
                                    break;
                                }
                                size_t c = ++result_count;
                                if (options.max_results > 0 && c >= options.max_results) {
                                    stopped.store(true, std::memory_order_relaxed);
                                    break;
                                }
                            }
                        }

                        if (options.recursive && (options.max_depth == 0 || task.depth + 1 <= options.max_depth)) {
                            queue.push(DirTask{entry.path(), task.depth + 1});
                        }
                    } else if (options.include_files) {
                        bool match_glob = true;
                        if (!options.glob_pattern.empty()) {
                            match_glob = IgnoreFilter::glob_match(options.glob_pattern, filename);
                        }
                        if (match_glob) {
                            FileEntry fe;
                            fe.path = entry.path();
                            fe.relative_path = rel_str;
                            fe.filename = filename;
                            fe.is_directory = false;

                            std::error_code sz_ec;
                            fe.file_size = static_cast<uint64_t>(entry.file_size(sz_ec));

                            std::lock_guard<std::mutex> lock(cb_mutex);
                            if (!on_entry(fe)) {
                                stopped.store(true, std::memory_order_relaxed);
                                break;
                            }
                            size_t c = ++result_count;
                            if (options.max_results > 0 && c >= options.max_results) {
                                stopped.store(true, std::memory_order_relaxed);
                                break;
                            }
                        }
                    }
                }
            }

            queue.task_done();
        }
    };

    if (num_threads == 1) {
        worker();
    } else {
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker);
        }
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }
}

std::vector<FileEntry> find_files(
    const std::filesystem::path& root_path,
    const FindOptions& options,
    const CancellationToken* token
) {
    std::vector<FileEntry> entries;
    find_files_callback(
        root_path,
        options,
        [&](const FileEntry& entry) -> bool {
            entries.push_back(entry);
            return true;
        },
        token
    );

    // If fuzzy pattern is provided, score and rank results
    if (!options.fuzzy_pattern.empty()) {
        std::vector<FileEntry> matched_entries;
        matched_entries.reserve(entries.size());

        FuzzyOptions f_opts;
        f_opts.path_mode = true;

        for (auto& entry : entries) {
            if (token && token->is_cancelled()) break;

            FuzzyMatchResult res = fuzzy_match(options.fuzzy_pattern, entry.relative_path, f_opts);
            if (res.matched) {
                entry.fuzzy_score = res.score;
                entry.matched_indices = std::move(res.matched_indices);
                matched_entries.push_back(std::move(entry));
            }
        }

        auto comparator = [](const FileEntry& a, const FileEntry& b) noexcept {
            if (a.fuzzy_score != b.fuzzy_score) {
                return a.fuzzy_score > b.fuzzy_score;
            }
            if (a.relative_path.size() != b.relative_path.size()) {
                return a.relative_path.size() < b.relative_path.size();
            }
            return a.filename < b.filename;
        };

        if (options.max_results > 0 && matched_entries.size() > options.max_results) {
            std::partial_sort(
                matched_entries.begin(),
                matched_entries.begin() + options.max_results,
                matched_entries.end(),
                comparator
            );
            matched_entries.resize(options.max_results);
        } else {
            std::sort(matched_entries.begin(), matched_entries.end(), comparator);
        }

        return matched_entries;
    }

    return entries;
}

} // namespace bro::search
