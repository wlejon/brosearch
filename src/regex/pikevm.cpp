#include "regex/pikevm.h"

#include "regex/unicode.h"

namespace bro::search::rx {

PikeVm::PikeVm(const Program& prog) : prog_(prog) {
    for (Threads* t : {&clist_, &nlist_}) {
        t->sparse.assign(prog_.insts.size(), 0);
        t->starts.assign(prog_.insts.size(), 0);
        t->dense.reserve(prog_.insts.size());
    }
}

bool PikeVm::look_ok(Look look, const uint8_t* data, size_t len, size_t at) const {
    const int before = at > 0 ? data[at - 1] : -1;
    const int after = at < len ? data[at] : -1;
    auto wbyte = [](int b) { return b >= 0 && is_word_byte(static_cast<uint8_t>(b)); };
    auto wcp_before = [&]() {
        if (at == 0) return false;
        uint32_t cp;
        size_t lo = at >= 4 ? at - 4 : 0;
        return decode_utf8_last(data + lo, data + at, &cp) != 0 && is_word_codepoint(cp);
    };
    auto wcp_after = [&]() {
        if (at >= len) return false;
        uint32_t cp;
        return decode_utf8(data + at, data + len, &cp) != 0 && is_word_codepoint(cp);
    };
    switch (look) {
        case Look::StartLine: return before < 0 || before == '\n';
        case Look::EndLine: return after < 0 || after == '\n';
        case Look::StartText: return before < 0;
        case Look::EndText: return after < 0;
        case Look::StartLineCrlf: return before < 0 || before == '\n' || (before == '\r' && after != '\n');
        case Look::EndLineCrlf: return after < 0 || after == '\r' || (after == '\n' && before != '\r');
        case Look::WordAscii: return wbyte(before) != wbyte(after);
        case Look::NotWordAscii: return wbyte(before) == wbyte(after);
        case Look::WordStartAscii: return !wbyte(before) && wbyte(after);
        case Look::WordEndAscii: return wbyte(before) && !wbyte(after);
        case Look::WordStartHalfAscii: return !wbyte(before);
        case Look::WordEndHalfAscii: return !wbyte(after);
        case Look::WordUnicode: return wcp_before() != wcp_after();
        case Look::NotWordUnicode: return wcp_before() == wcp_after();
        case Look::WordStartUnicode: return !wcp_before() && wcp_after();
        case Look::WordEndUnicode: return wcp_before() && !wcp_after();
        case Look::WordStartHalfUnicode: return !wcp_before();
        case Look::WordEndHalfUnicode: return !wcp_after();
        default: return false;
    }
}

void PikeVm::add_thread(Threads& list, uint32_t id, size_t start_pos, const uint8_t* data, size_t len,
                        size_t at) {
    stack_.clear();
    stack_.push_back(id);
    while (!stack_.empty()) {
        uint32_t cur = stack_.back();
        stack_.pop_back();
        if (list.contains(cur)) continue;
        list.insert(cur, start_pos);
        const Inst& in = prog_.insts[cur];
        switch (in.op) {
            case Inst::Op::Union:
                for (uint32_t a = in.n; a-- > 0;) stack_.push_back(prog_.alts[in.a + a]);
                break;
            case Inst::Op::Look:
                if (look_ok(in.look, data, len, at)) stack_.push_back(in.next);
                break;
            default:
                break;
        }
    }
}

std::optional<MatchSpan> PikeVm::search(const uint8_t* data, size_t len, size_t start, size_t end, bool anchored) {
    clist_.dense.clear();
    nlist_.dense.clear();
    std::optional<MatchSpan> best;
    for (size_t pos = start;; ++pos) {
        if (!best && (!anchored || pos == start)) add_thread(clist_, prog_.start_anchored, pos, data, len, pos);
        if (clist_.dense.empty()) break;
        const int b = pos < end ? data[pos] : -1;
        for (size_t k = 0; k < clist_.dense.size(); ++k) {
            const uint32_t id = clist_.dense[k];
            const Inst& in = prog_.insts[id];
            if (in.op == Inst::Op::Match) {
                best = MatchSpan{clist_.starts[id], pos};
                break;  // lower-priority threads are cut
            }
            if (in.op != Inst::Op::Sparse || b < 0) continue;
            const Trans* t = prog_.trans.data() + in.a;
            for (uint32_t j = 0; j < in.n; ++j) {
                if (b >= t[j].lo && b <= t[j].hi) {
                    add_thread(nlist_, t[j].next, clist_.starts[id], data, len, pos + 1);
                    break;
                }
            }
        }
        if (pos >= end) break;
        std::swap(clist_, nlist_);
        nlist_.dense.clear();
    }
    return best;
}

} // namespace bro::search::rx
