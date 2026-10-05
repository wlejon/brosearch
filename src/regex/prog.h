#pragma once
// Byte-level Thompson NFA. Unicode classes are compiled to UTF-8 byte automata, so every engine
// (lazy DFA, PikeVM) works on bytes. A reverse program matches reversed strings and is used to
// find match starts from a known end.

#include "regex/hir.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace bro::search::rx {

struct Trans {
    uint8_t lo;
    uint8_t hi;
    uint32_t next;
    bool operator==(const Trans&) const = default;
};

struct Inst {
    enum class Op : uint8_t { Match, Fail, Sparse, Union, Look };
    Op op = Op::Fail;
    Look look = Look::StartText;
    uint32_t a = 0;     // Sparse: first index into trans; Union: first index into alts
    uint32_t n = 0;     // Sparse: transition count; Union: alternative count
    uint32_t next = 0;  // Look: continuation
};

struct Program {
    std::vector<Inst> insts;
    std::vector<Trans> trans;
    std::vector<uint32_t> alts;
    uint32_t start_anchored = 0;
    uint32_t start_unanchored = 0;
    bool reverse = false;
    uint32_t look_mask = 0;          // bit (1 << Look) for every look used
    bool has_unicode_word = false;   // needs code point context: DFA quits on non-ASCII
    std::array<uint8_t, 256> byte_class{};
    uint32_t num_byte_classes = 1;

    bool uses(Look l) const { return (look_mask >> static_cast<unsigned>(l)) & 1u; }
};

// Compiles `hir` into `out`. Returns false (with `error`) if the program exceeds `size_limit`
// instructions + transitions.
bool compile_program(const Hir& hir, bool reverse, size_t size_limit, Program& out, std::string& error);

} // namespace bro::search::rx
