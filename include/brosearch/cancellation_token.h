#pragma once

#include <atomic>
#include <memory>

namespace bro::search {

class CancellationToken {
public:
    CancellationToken() = default;
    ~CancellationToken() = default;

    CancellationToken(const CancellationToken&) = delete;
    CancellationToken& operator=(const CancellationToken&) = delete;

    void cancel() noexcept;
    [[nodiscard]] bool is_cancelled() const noexcept;
    void reset() noexcept;

private:
    std::atomic<bool> cancelled_{false};
};

class CancellationSource {
public:
    CancellationSource();
    ~CancellationSource() = default;

    [[nodiscard]] std::shared_ptr<CancellationToken> token() const noexcept;
    void cancel() noexcept;
    [[nodiscard]] bool is_cancelled() const noexcept;
    void reset() noexcept;

private:
    std::shared_ptr<CancellationToken> token_;
};

} // namespace bro::search
