#include "brosearch/cancellation_token.h"

namespace bro::search {

void CancellationToken::cancel() noexcept {
    cancelled_.store(true, std::memory_order_release);
}

bool CancellationToken::is_cancelled() const noexcept {
    return cancelled_.load(std::memory_order_acquire);
}

void CancellationToken::reset() noexcept {
    cancelled_.store(false, std::memory_order_release);
}

CancellationSource::CancellationSource()
    : token_(std::make_shared<CancellationToken>()) {}

std::shared_ptr<CancellationToken> CancellationSource::token() const noexcept {
    return token_;
}

void CancellationSource::cancel() noexcept {
    if (token_) {
        token_->cancel();
    }
}

bool CancellationSource::is_cancelled() const noexcept {
    return token_ && token_->is_cancelled();
}

void CancellationSource::reset() noexcept {
    if (token_) {
        token_->reset();
    }
}

} // namespace bro::search
