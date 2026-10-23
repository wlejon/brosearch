#include "regex/dfa_jit.h"

#include <string_view>

namespace bro::search::rx {

namespace {

// Emits `brosearch_dfa_step`: loop-free single transition step over LazyDfa's compressed
// byte-class table `tab[off + cls[b]]`. Includes redundant `& 0xFF` masks on `load_byte`
// that `brass::run_mir_superopt` proves redundant and elides.
void emitLazyDfaStepFunction(brass::codegen::GrammarBuilder& gb, std::string_view name) {
    using namespace brass;
    Builder& b = gb.builder();
    Module* mod = b.current_module();
    Function* fn = mod->create_function(
        name, Type::i32(), {Type::ptr(), Type::ptr(), Type::i32(), Type::i32()});
    b.set_function(fn);

    BasicBlock* entry = b.append_block("entry");
    b.position_at_end(entry);
    Value* tab_ptr = b.add_block_param(entry, Type::ptr());
    Value* cls_ptr = b.add_block_param(entry, Type::ptr());
    Value* off_in = b.add_block_param(entry, Type::i32());
    Value* byte_in = b.add_block_param(entry, Type::i32());

    Value* b_masked = b.build_and(byte_in, gb.const_i32(0xFF));
    Value* b_idx = b.build_zext_i64(b_masked);
    Value* col_raw = gb.load_byte(cls_ptr, b_idx);
    // Redundant `& 0xFF` mask on `load_byte` result; `run_mir_superopt` proves and elides it.
    Value* col = b.build_and(col_raw, gb.const_i32(0xFF));
    Value* idx32 = b.build_add(off_in, col);
    Value* idx64 = b.build_zext_i64(idx32);
    Value* entry_val = gb.load_i32_indexed(tab_ptr, idx64, 4, 0);
    b.build_ret(entry_val);
}

// Emits `brosearch_dfa_forward_scan` into `mod` using `brass::codegen::GrammarBuilder`.
void emitLazyDfaForwardScanFunction(brass::codegen::GrammarBuilder& gb, std::string_view name) {
    using namespace brass;
    Builder& b = gb.builder();
    Module* mod = b.current_module();
    Function* fn = mod->create_function(
        name, Type::i64(),
        {Type::ptr(), Type::ptr(), Type::ptr(), Type::i64(), Type::i32(), Type::ptr()});
    b.set_function(fn);

    BasicBlock* entry = b.append_block("entry");
    b.position_at_end(entry);
    Value* tab_ptr = b.add_block_param(entry, Type::ptr());
    Value* cls_ptr = b.add_block_param(entry, Type::ptr());
    Value* data_ptr = b.add_block_param(entry, Type::ptr());
    Value* end_idx = b.add_block_param(entry, Type::i64());
    Value* earliest_in = b.add_block_param(entry, Type::i32());
    Value* io_state = b.add_block_param(entry, Type::ptr());

    BasicBlock* loop_head_bb = b.create_block("loop_head");
    BasicBlock* body_bb = b.create_block("body");
    BasicBlock* step_bb = b.create_block("step");
    BasicBlock* next_state_bb = b.create_block("next_state");
    BasicBlock* exit_bb = b.create_block("exit");

    Value* init_i = gb.load_i64(io_state, 0);
    Value* init_off64 = gb.load_i64(io_state, 8);
    Value* init_off = b.build_trunc_i32(init_off64);
    Value* init_last = gb.load_i64(io_state, 16);
    Value* earliest_bool = b.build_ne(earliest_in, gb.const_i32(0));
    b.build_br(loop_head_bb, {init_i, init_off, init_last});

    // Loop header: (cur_i: i64, cur_off: i32, cur_last: i64)
    fn->append_block(loop_head_bb);
    b.position_at_end(loop_head_bb);
    Value* cur_i = b.add_block_param(loop_head_bb, Type::i64());
    Value* cur_off = b.add_block_param(loop_head_bb, Type::i32());
    Value* cur_last = b.add_block_param(loop_head_bb, Type::i64());

    Value* has_more = b.build_ult(cur_i, end_idx);
    b.build_br_if(
        has_more,
        body_bb, {},
        exit_bb, {gb.const_i64(0), cur_i, cur_off, cur_last});

    // Load `b = data[cur_i]`, `col = cls[b]`, `e = tab[cur_off + col]`
    fn->append_block(body_bb);
    b.position_at_end(body_bb);
    Value* b_raw = gb.load_byte(data_ptr, cur_i);
    Value* b_masked = b.build_and(b_raw, gb.const_i32(0xFF));
    Value* b_idx = b.build_zext_i64(b_masked);
    Value* col_raw = gb.load_byte(cls_ptr, b_idx);
    Value* col = b.build_and(col_raw, gb.const_i32(0xFF));
    Value* idx32 = b.build_add(cur_off, col);
    Value* idx64 = b.build_zext_i64(idx32);
    Value* e = gb.load_i32_indexed(tab_ptr, idx64, 4, 0);

    Value* is_unk = b.build_eq(e, gb.const_i32(-1));
    b.build_br_if(
        is_unk,
        exit_bb, {gb.const_i64(1), cur_i, cur_off, cur_last},
        step_bb, {});

    // Known transition: check match bit `(e & 1)` and `earliest`
    fn->append_block(step_bb);
    b.position_at_end(step_bb);
    Value* match_bit = b.build_and(e, gb.const_i32(1));
    Value* is_match = b.build_ne(match_bit, gb.const_i32(0));
    Value* updated_last = b.build_select(is_match, cur_i, cur_last);
    Value* stop_early = b.build_and(is_match, earliest_bool);
    b.build_br_if(
        stop_early,
        exit_bb, {gb.const_i64(3), cur_i, cur_off, updated_last},
        next_state_bb, {updated_last});

    // Advance state `next_off = e >> 1` and `next_i = cur_i + 1`
    fn->append_block(next_state_bb);
    b.position_at_end(next_state_bb);
    Value* next_last = b.add_block_param(next_state_bb, Type::i64());
    Value* next_off = b.build_lshr(e, gb.const_i32(1));
    Value* next_i = b.build_add(cur_i, gb.const_i64(1));
    Value* is_dead = b.build_eq(next_off, gb.const_i32(0));
    b.build_br_if(
        is_dead,
        exit_bb, {gb.const_i64(2), next_i, next_off, next_last},
        loop_head_bb, {next_i, next_off, next_last});

    // Unified exit block: write back (final_i, final_off, final_last) to `io_state`
    fn->append_block(exit_bb);
    b.position_at_end(exit_bb);
    Value* ret_code = b.add_block_param(exit_bb, Type::i64());
    Value* final_i = b.add_block_param(exit_bb, Type::i64());
    Value* final_off = b.add_block_param(exit_bb, Type::i32());
    Value* final_last = b.add_block_param(exit_bb, Type::i64());

    gb.store_i64(io_state, final_i, 0);
    gb.store_i64(io_state, b.build_zext_i64(final_off), 8);
    gb.store_i64(io_state, final_last, 16);
    b.build_ret(ret_code);
}

// Emits `brosearch_dfa_reverse_scan` into `mod` using `brass::codegen::GrammarBuilder`.
void emitLazyDfaReverseScanFunction(brass::codegen::GrammarBuilder& gb, std::string_view name) {
    using namespace brass;
    Builder& b = gb.builder();
    Module* mod = b.current_module();
    Function* fn = mod->create_function(
        name, Type::i64(),
        {Type::ptr(), Type::ptr(), Type::ptr(), Type::i64(), Type::ptr()});
    b.set_function(fn);

    BasicBlock* entry = b.append_block("entry");
    b.position_at_end(entry);
    Value* tab_ptr = b.add_block_param(entry, Type::ptr());
    Value* cls_ptr = b.add_block_param(entry, Type::ptr());
    Value* data_ptr = b.add_block_param(entry, Type::ptr());
    Value* start_idx = b.add_block_param(entry, Type::i64());
    Value* io_state = b.add_block_param(entry, Type::ptr());

    BasicBlock* loop_head_bb = b.create_block("loop_head");
    BasicBlock* body_bb = b.create_block("body");
    BasicBlock* step_bb = b.create_block("step");
    BasicBlock* exit_bb = b.create_block("exit");

    Value* init_i = gb.load_i64(io_state, 0);
    Value* init_off64 = gb.load_i64(io_state, 8);
    Value* init_off = b.build_trunc_i32(init_off64);
    Value* init_best = gb.load_i64(io_state, 16);
    b.build_br(loop_head_bb, {init_i, init_off, init_best});

    // Loop header: (cur_i: i64, cur_off: i32, cur_best: i64)
    fn->append_block(loop_head_bb);
    b.position_at_end(loop_head_bb);
    Value* cur_i = b.add_block_param(loop_head_bb, Type::i64());
    Value* cur_off = b.add_block_param(loop_head_bb, Type::i32());
    Value* cur_best = b.add_block_param(loop_head_bb, Type::i64());

    Value* has_more = b.build_ugt(cur_i, start_idx);
    b.build_br_if(
        has_more,
        body_bb, {},
        exit_bb, {gb.const_i64(0), cur_i, cur_off, cur_best});

    // Inspect `data[cur_i - 1]`
    fn->append_block(body_bb);
    b.position_at_end(body_bb);
    Value* prev_i = b.build_sub(cur_i, gb.const_i64(1));
    Value* b_raw = gb.load_byte(data_ptr, prev_i);
    Value* b_masked = b.build_and(b_raw, gb.const_i32(0xFF));
    Value* b_idx = b.build_zext_i64(b_masked);
    Value* col_raw = gb.load_byte(cls_ptr, b_idx);
    Value* col = b.build_and(col_raw, gb.const_i32(0xFF));
    Value* idx32 = b.build_add(cur_off, col);
    Value* idx64 = b.build_zext_i64(idx32);
    Value* e = gb.load_i32_indexed(tab_ptr, idx64, 4, 0);

    Value* is_unk = b.build_eq(e, gb.const_i32(-1));
    b.build_br_if(
        is_unk,
        exit_bb, {gb.const_i64(1), cur_i, cur_off, cur_best},
        step_bb, {});

    // Known transition: update `best` if `(e & 1) != 0` and advance to `prev_i`
    fn->append_block(step_bb);
    b.position_at_end(step_bb);
    Value* match_bit = b.build_and(e, gb.const_i32(1));
    Value* is_match = b.build_ne(match_bit, gb.const_i32(0));
    Value* updated_best = b.build_select(is_match, cur_i, cur_best);
    Value* next_off = b.build_lshr(e, gb.const_i32(1));
    Value* is_dead = b.build_eq(next_off, gb.const_i32(0));
    b.build_br_if(
        is_dead,
        exit_bb, {gb.const_i64(2), prev_i, next_off, updated_best},
        loop_head_bb, {prev_i, next_off, updated_best});

    // Unified exit block
    fn->append_block(exit_bb);
    b.position_at_end(exit_bb);
    Value* ret_code = b.add_block_param(exit_bb, Type::i64());
    Value* final_i = b.add_block_param(exit_bb, Type::i64());
    Value* final_off = b.add_block_param(exit_bb, Type::i32());
    Value* final_best = b.add_block_param(exit_bb, Type::i64());

    gb.store_i64(io_state, final_i, 0);
    gb.store_i64(io_state, b.build_zext_i64(final_off), 8);
    gb.store_i64(io_state, final_best, 16);
    b.build_ret(ret_code);
}

struct SharedDfaJitKernels {
    std::unique_ptr<brass::Module> mod;
    std::unique_ptr<brass::codegen::KernelJit> jit;
    brass::codegen::KernelFunction forward_kf;
    brass::codegen::KernelFunction reverse_kf;
    DfaForwardScanJitFn forward_fn = nullptr;
    DfaReverseScanJitFn reverse_fn = nullptr;
    DfaJitStats stats{};

    SharedDfaJitKernels() {
        mod = DfaJit::buildMirModule();
        brass::SmtGuardElimStats guard_stats{};
        brass::SuperoptStats superopt_stats{};
        DfaJit::optimizeMirModule(*mod, &guard_stats, &superopt_stats);

        stats.smt_guards_eliminated = static_cast<uint32_t>(guard_stats.guards_proven_eliminated);
        stats.superopt_masks_elided = superopt_stats.masks_elided;
        stats.superopt_extensions_elided = superopt_stats.extensions_elided;
        stats.superopt_dags_synthesized = superopt_stats.dags_synthesized;
        stats.superopt_solver_queries = superopt_stats.solver_queries;

        brass::codegen::KernelOptions kopts;
        kopts.enable_optimizations = true;
        kopts.enable_unroll = false;
        kopts.enable_vectorize = false;
        jit = std::make_unique<brass::codegen::KernelJit>(kopts);

        forward_kf = jit->compile(*mod, "brosearch_dfa_forward_scan");
        reverse_kf = jit->compile(*mod, "brosearch_dfa_reverse_scan");
        forward_fn = forward_kf.as<DfaForwardScanJitFn>();
        reverse_fn = reverse_kf.as<DfaReverseScanJitFn>();
    }
};

const SharedDfaJitKernels& getSharedDfaJitKernels() {
    static const SharedDfaJitKernels instance;
    return instance;
}

} // namespace

std::unique_ptr<brass::Module> DfaJit::buildMirModule() {
    auto mod = std::make_unique<brass::Module>("brosearch_dfa_jit");
    brass::codegen::GrammarBuilder gb(*mod);

    gb.build_dfa_table_step_function("brosearch_dfa_table_step");
    gb.build_dfa_scan_string_function("brosearch_dfa_scan_bytes", 1);
    emitLazyDfaStepFunction(gb, "brosearch_dfa_step");
    emitLazyDfaForwardScanFunction(gb, "brosearch_dfa_forward_scan");
    emitLazyDfaReverseScanFunction(gb, "brosearch_dfa_reverse_scan");

    for (brass::Function* fn : mod->functions()) {
        if (fn) fn->rebuild_cfg_predecessors();
    }
    return mod;
}

void DfaJit::optimizeMirModule(
    brass::Module& mod,
    brass::SmtGuardElimStats* guard_stats,
    brass::SuperoptStats* superopt_stats) {
    for (brass::Function* fn : mod.functions()) {
        if (fn) fn->rebuild_cfg_predecessors();
    }

    brass::SmtGuardElimOptions gopts;
    gopts.stats = guard_stats;
    brass::run_smt_guard_elimination(mod, gopts);

    brass::SuperoptOptions sopts;
    sopts.stats = superopt_stats;
    brass::run_mir_superopt(mod, sopts);

    for (brass::Function* fn : mod.functions()) {
        if (fn) fn->rebuild_cfg_predecessors();
    }
}

DfaForwardScanJitFn DfaJit::forwardScanFn() noexcept {
    return getSharedDfaJitKernels().forward_fn;
}

DfaReverseScanJitFn DfaJit::reverseScanFn() noexcept {
    return getSharedDfaJitKernels().reverse_fn;
}

const DfaJitStats& DfaJit::stats() noexcept {
    return getSharedDfaJitKernels().stats;
}

bool DfaJit::isAvailable() noexcept {
    const auto& k = getSharedDfaJitKernels();
    return k.forward_fn != nullptr && k.reverse_fn != nullptr;
}

} // namespace bro::search::rx
