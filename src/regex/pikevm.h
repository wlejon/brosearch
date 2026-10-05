#pragma once
// PikeVM: NFA simulation with leftmost-first priorities, tracking each thread's start. Linear in
// haystack x program size. Used when the lazy DFA gives up (Unicode word boundaries next to
// non-ASCII text, or a thrashing cache). Evaluates Unicode \b exactly by decoding code points.

#include "regex/dfa.h"
#include "regex/prog.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace bro::search::rx {

struct MatchSpan {
    size_t start;
    size_t end;
};

class PikeVm {
public:
    explicit PikeVm(const Program& prog);
    // Leftmost-first match with start >= `start` and end <= `end`; look-around sees data[0, len).
    std::optional<MatchSpan> search(const uint8_t* data, size_t len, size_t start, size_t end, bool anchored);

private:
    struct Threads {
        std::vector<uint32_t> dense;   // inst ids in priority order
        std::vector<uint32_t> sparse;  // inst id -> index in dense
        std::vector<size_t> starts;    // per inst id: start position of the thread at that inst
        bool contains(uint32_t id) const {
            uint32_t i = sparse[id];
            return i < dense.size() && dense[i] == id;
        }
        void insert(uint32_t id, size_t st) {
            sparse[id] = static_cast<uint32_t>(dense.size());
            dense.push_back(id);
            starts[id] = st;
        }
    };

    const Program& prog_;
    Threads clist_, nlist_;
    std::vector<uint32_t> stack_;

    void add_thread(Threads& list, uint32_t id, size_t start_pos, const uint8_t* data, size_t len, size_t at);
    bool look_ok(Look look, const uint8_t* data, size_t len, size_t at) const;
};

} // namespace bro::search::rx
