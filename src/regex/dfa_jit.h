#pragma once
// Native `brass` MIR + KernelJit acceleration for `LazyDfa::forward` and `LazyDfa::reverse`.
// Builds DFA transition and byte-stream scanning kernels via `brass::codegen::GrammarBuilder`,
// optimizes them with `brass::run_smt_guard_elimination` and `brass::run_mir_superopt`,
// and compiles them once per process into native machine code via `brass::codegen::KernelJit`.

#include <brass/codegen/grammar_builder.hpp>
#include <brass/codegen/kernel_jit.hpp>
#include <brass/mir/module.hpp>
#include <brass/mir/smt_guard_elim.hpp>
#include <brass/mir/superopt.hpp>

#include <cstdint>
#include <memory>

namespace bro::search::rx {

// Signature of the compiled native forward LazyDfa inner scan loop:
//   int64_t brosearch_dfa_forward_scan(
//       const uint32_t* tab,
//       const uint8_t* cls,
//       const uint8_t* data,
//       int64_t end,
//       int32_t earliest,
//       int64_t* io_state); // io_state[0] = i, io_state[1] = off, io_state[2] = last
//
// Return codes:
//   0 = reached `end` cleanly
//   1 = encountered `kUnknown` (0xFFFFFFFFu) at `io_state[0]` with state offset `io_state[1]`
//   2 = encountered `kDead` (0) after updating `io_state[2]`
//   3 = matched early (`earliest != 0` and `(e & 1) != 0`), with `io_state[2] == match_pos`
using DfaForwardScanJitFn = int64_t (*)(
    const uint32_t* tab,
    const uint8_t* cls,
    const uint8_t* data,
    int64_t end,
    int32_t earliest,
    int64_t* io_state);

// Signature of the compiled native reverse LazyDfa inner scan loop:
//   int64_t brosearch_dfa_reverse_scan(
//       const uint32_t* tab,
//       const uint8_t* cls,
//       const uint8_t* data,
//       int64_t start,
//       int64_t* io_state); // io_state[0] = i, io_state[1] = off, io_state[2] = best
//
// Return codes:
//   0 = reached `start` cleanly
//   1 = encountered `kUnknown` (0xFFFFFFFFu) at `io_state[0]` (inspecting `data[i - 1]`)
//   2 = encountered `kDead` (0) after updating `io_state[2]`
using DfaReverseScanJitFn = int64_t (*)(
    const uint32_t* tab,
    const uint8_t* cls,
    const uint8_t* data,
    int64_t start,
    int64_t* io_state);

struct DfaJitStats {
    uint32_t smt_guards_eliminated = 0;
    uint32_t superopt_masks_elided = 0;
    uint32_t superopt_extensions_elided = 0;
    uint32_t superopt_dags_synthesized = 0;
    uint32_t superopt_solver_queries = 0;
};

class DfaJit {
public:
    // Builds the unoptimized `brass::Module` containing the LazyDfa step & scan kernels
    // using `brass::codegen::GrammarBuilder`. Exposed for `brass::verify::verify_mir_equivalence`.
    static std::unique_ptr<brass::Module> buildMirModule();

    // Runs `brass::run_smt_guard_elimination` and `brass::run_mir_superopt` on the module.
    static void optimizeMirModule(
        brass::Module& mod,
        brass::SmtGuardElimStats* guard_stats = nullptr,
        brass::SuperoptStats* superopt_stats = nullptr);

    // Process-wide compiled JIT entry points and optimization statistics.
    static DfaForwardScanJitFn forwardScanFn() noexcept;
    static DfaReverseScanJitFn reverseScanFn() noexcept;
    static const DfaJitStats& stats() noexcept;
    static bool isAvailable() noexcept;
};

} // namespace bro::search::rx
