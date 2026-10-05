#include "regex/dfa.h"

#include "regex/unicode.h"

#include <cstring>

namespace bro::search::rx {

LazyDfa::LazyDfa(const Program& prog, bool leftmost_first, size_t cache_bytes)
    : prog_(prog), leftmost_first_(leftmost_first), cache_bytes_(cache_bytes) {
    stride_ = prog_.num_byte_classes + 1;
    use_ctx_ = prog_.look_mask != 0;
    for (int b = 0; b < 256; ++b) {
        uint8_t ctx = kCtxNone;
        if (use_ctx_) {
            if (b == '\n') ctx = kCtxLF;
            else if (b == '\r') ctx = kCtxCR;
            else if (is_word_byte(static_cast<uint8_t>(b))) ctx = kCtxWord;
            else ctx = kCtxOther;
        }
        ctx_of_[b] = ctx;
        quit_[b] = prog_.has_unicode_word && b >= 0x80;
    }
    for (int b = 255; b >= 0; --b) class_rep_[prog_.byte_class[b]] = static_cast<uint8_t>(b);
    seen_gen_.assign(prog_.insts.size(), 0);
    reset_cache();
}

void LazyDfa::reset_cache() {
    states_.clear();
    set_pool_.clear();
    table_.clear();
    index_.clear();
    for (auto& row : start_cache_)
        for (auto& v : row) v = kUnknown;
    // State 0 is the dead state: empty set, every transition goes to itself without a match.
    states_.push_back({0, 0, kCtxNone});
    table_.assign(stride_, 0);
}

size_t LazyDfa::memory() const {
    return states_.size() * sizeof(State) + set_pool_.size() * 4 + table_.size() * 4 +
           index_.size() * 64 + set_pool_.size() * 4;
}

uint32_t LazyDfa::intern(const uint32_t* set, size_t n, uint8_t ctx) {
    if (n == 0) return kDead;
    key_.assign(1, static_cast<char>(ctx));
    key_.append(reinterpret_cast<const char*>(set), n * sizeof(uint32_t));
    auto it = index_.find(key_);
    if (it != index_.end()) return it->second;
    uint32_t id = static_cast<uint32_t>(states_.size());
    states_.push_back({static_cast<uint32_t>(set_pool_.size()), static_cast<uint32_t>(n), ctx});
    set_pool_.insert(set_pool_.end(), set, set + n);
    table_.resize(table_.size() + stride_, kUnknown);
    index_.emplace(key_, id);
    return id;
}

uint32_t LazyDfa::start_state(bool anchored, uint8_t ctx) {
    uint32_t& slot = start_cache_[anchored ? 1 : 0][ctx];
    if (slot == kUnknown) {
        uint32_t s = anchored ? prog_.start_anchored : prog_.start_unanchored;
        slot = intern(&s, 1, ctx);
    }
    return slot;
}

bool LazyDfa::look_ok(Look look, uint8_t before, uint8_t after) const {
    const bool wb = before == kCtxWord, wa = after == kCtxWord;
    switch (look) {
        case Look::StartLine: return before == kCtxNone || before == kCtxLF;
        case Look::EndLine: return after == kCtxNone || after == kCtxLF;
        case Look::StartText: return before == kCtxNone;
        case Look::EndText: return after == kCtxNone;
        case Look::StartLineCrlf:
            return before == kCtxNone || before == kCtxLF || (before == kCtxCR && after != kCtxLF);
        case Look::EndLineCrlf:
            return after == kCtxNone || after == kCtxCR || (after == kCtxLF && before != kCtxCR);
        case Look::WordAscii: case Look::WordUnicode: return wb != wa;
        case Look::NotWordAscii: case Look::NotWordUnicode: return wb == wa;
        case Look::WordStartAscii: case Look::WordStartUnicode: return !wb && wa;
        case Look::WordEndAscii: case Look::WordEndUnicode: return wb && !wa;
        case Look::WordStartHalfAscii: case Look::WordStartHalfUnicode: return !wb;
        case Look::WordEndHalfAscii: case Look::WordEndHalfUnicode: return !wa;
        default: return false;
    }
}

uint32_t LazyDfa::compute(uint32_t s, uint32_t col, int byte) {
    const State st = states_[s];
    uint8_t before, after;
    if (!prog_.reverse) {
        before = st.ctx;
        after = ctx_byte(byte);
    } else {
        before = ctx_byte(byte);
        after = st.ctx;
    }
    if (++gen_ == 0) {
        std::fill(seen_gen_.begin(), seen_gen_.end(), 0);
        gen_ = 1;
    }
    closure_.clear();
    bool matched = false;
    for (uint32_t k = 0; k < st.count && !(matched && leftmost_first_); ++k) {
        stack_.clear();
        stack_.push_back(set_pool_[st.offset + k]);
        while (!stack_.empty()) {
            uint32_t id = stack_.back();
            stack_.pop_back();
            if (seen_gen_[id] == gen_) continue;
            seen_gen_[id] = gen_;
            const Inst& in = prog_.insts[id];
            switch (in.op) {
                case Inst::Op::Match:
                    matched = true;
                    if (leftmost_first_) stack_.clear();
                    break;
                case Inst::Op::Fail:
                    break;
                case Inst::Op::Sparse:
                    closure_.push_back(id);
                    break;
                case Inst::Op::Union:
                    for (uint32_t a = in.n; a-- > 0;) stack_.push_back(prog_.alts[in.a + a]);
                    break;
                case Inst::Op::Look:
                    if (look_ok(in.look, before, after)) stack_.push_back(in.next);
                    break;
            }
        }
    }
    uint32_t entry;
    if (byte < 0) {
        entry = (kDead << 1) | (matched ? 1u : 0u);
    } else {
        if (++gen_ == 0) {
            std::fill(seen_gen_.begin(), seen_gen_.end(), 0);
            gen_ = 1;
        }
        next_set_.clear();
        const uint8_t b = static_cast<uint8_t>(byte);
        for (uint32_t id : closure_) {
            const Inst& in = prog_.insts[id];
            const Trans* t = prog_.trans.data() + in.a;
            for (uint32_t k = 0; k < in.n; ++k) {
                if (b >= t[k].lo && b <= t[k].hi) {
                    uint32_t target = t[k].next;
                    if (seen_gen_[target] != gen_) {
                        seen_gen_[target] = gen_;
                        next_set_.push_back(target);
                    }
                    break;
                }
            }
        }
        uint32_t ns = intern(next_set_.data(), next_set_.size(), ctx_byte(byte));
        entry = (ns << 1) | (matched ? 1u : 0u);
    }
    table_[static_cast<size_t>(s) * stride_ + col] = entry;
    return entry;
}

bool LazyDfa::maybe_clear(uint32_t& current) {
    if (memory() <= cache_bytes_) return true;
    if (++clears_ > 32) return false;
    const State st = states_[current];
    std::vector<uint32_t> set(set_pool_.begin() + st.offset, set_pool_.begin() + st.offset + st.count);
    reset_cache();
    current = intern(set.data(), set.size(), st.ctx);
    return true;
}

SearchResult LazyDfa::forward(const uint8_t* data, size_t len, size_t start, size_t end, bool anchored,
                              bool earliest) {
    clears_ = 0;
    if (start > 0 && quit_[data[start - 1]]) return {SearchStatus::GaveUp, start};
    uint32_t s = start_state(anchored, start > 0 ? ctx_byte(data[start - 1]) : static_cast<uint8_t>(kCtxNone));
    constexpr size_t kNone = static_cast<size_t>(-1);
    size_t last = kNone;
    const uint8_t* cls = prog_.byte_class.data();
    const uint32_t stride = stride_;
    const uint32_t* tab = table_.data();
    for (size_t i = start; i < end; ++i) {
        const uint8_t b = data[i];
        uint32_t e = tab[static_cast<size_t>(s) * stride + cls[b]];
        if (e == kUnknown) {
            if (quit_[b]) return {SearchStatus::GaveUp, i};
            if (!maybe_clear(s)) return {SearchStatus::GaveUp, i};
            e = compute(s, cls[b], b);
            tab = table_.data();
        }
        if (e & 1u) {
            last = i;
            if (earliest) return {SearchStatus::Match, i};
        }
        s = e >> 1;
        if (s == kDead) return last != kNone ? SearchResult{SearchStatus::Match, last} : SearchResult{};
    }
    int after = end < len ? data[end] : -1;
    if (after >= 0 && quit_[after]) return {SearchStatus::GaveUp, end};
    uint32_t col = after < 0 ? stride - 1 : cls[after];
    uint32_t e = tab[static_cast<size_t>(s) * stride + col];
    if (e == kUnknown) {
        if (!maybe_clear(s)) return {SearchStatus::GaveUp, end};
        e = compute(s, col, after);
    }
    if (e & 1u) last = end;
    return last != kNone ? SearchResult{SearchStatus::Match, last} : SearchResult{};
}

SearchResult LazyDfa::reverse(const uint8_t* data, size_t len, size_t start, size_t end) {
    clears_ = 0;
    int after = end < len ? data[end] : -1;
    if (after >= 0 && quit_[after]) return {SearchStatus::GaveUp, end};
    uint32_t s = start_state(true, ctx_byte(after));
    constexpr size_t kNone = static_cast<size_t>(-1);
    size_t best = kNone;
    const uint8_t* cls = prog_.byte_class.data();
    const uint32_t stride = stride_;
    const uint32_t* tab = table_.data();
    for (size_t i = end; i > start; --i) {
        const uint8_t b = data[i - 1];
        uint32_t e = tab[static_cast<size_t>(s) * stride + cls[b]];
        if (e == kUnknown) {
            if (quit_[b]) return {SearchStatus::GaveUp, i - 1};
            if (!maybe_clear(s)) return {SearchStatus::GaveUp, i};
            e = compute(s, cls[b], b);
            tab = table_.data();
        }
        if (e & 1u) best = i;
        s = e >> 1;
        if (s == kDead) return best != kNone ? SearchResult{SearchStatus::Match, best} : SearchResult{};
    }
    int before = start > 0 ? data[start - 1] : -1;
    if (before >= 0 && quit_[before]) return {SearchStatus::GaveUp, start};
    uint32_t col = before < 0 ? stride - 1 : cls[before];
    uint32_t e = tab[static_cast<size_t>(s) * stride + col];
    if (e == kUnknown) {
        if (!maybe_clear(s)) return {SearchStatus::GaveUp, start};
        e = compute(s, col, before);
    }
    if (e & 1u) best = start;
    return best != kNone ? SearchResult{SearchStatus::Match, best} : SearchResult{};
}

} // namespace bro::search::rx
