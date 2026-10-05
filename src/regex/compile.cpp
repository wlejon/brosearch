// HIR -> byte-level NFA. Continuation-passing: compile(h, next) returns h's entry point, so no
// patch lists are needed. Unicode classes become UTF-8 automata: forward via a suffix-shared trie
// (as regex-automata's Utf8Compiler), reverse via suffix-shared byte chains.

#include "regex/prog.h"
#include "regex/unicode.h"

#include <map>
#include <unordered_map>

namespace bro::search::rx {

namespace {

struct SizeLimitExceeded {};

struct Utf8Range {
    uint8_t lo, hi;
    bool operator==(const Utf8Range&) const = default;
};
using Utf8Seq = std::vector<Utf8Range>;

uint32_t max_scalar(int nbytes) {
    switch (nbytes) {
        case 1: return 0x7F;
        case 2: return 0x7FF;
        case 3: return 0xFFFF;
        default: return 0x10FFFF;
    }
}

// Splits [lo, hi] (scalar values) into UTF-8 byte-range sequences, in ascending order.
std::vector<Utf8Seq> utf8_sequences(uint32_t lo, uint32_t hi) {
    std::vector<Utf8Seq> out;
    std::vector<std::pair<uint32_t, uint32_t>> stack{{lo, hi}};
    while (!stack.empty()) {
        auto [s, e] = stack.back();
        stack.pop_back();
        for (;;) {
            // Surrogates are never encoded.
            if (s < 0xE000 && e > 0xD7FF) {
                if (s <= 0xD7FF && e >= 0xE000) {
                    stack.push_back({0xE000, e});
                    e = 0xD7FF;
                    continue;
                }
                if (s >= 0xD800 && e <= 0xDFFF) break;
                if (s >= 0xD800) s = 0xE000;
                else e = 0xD7FF;
                if (s > e) break;
            }
            bool split = false;
            for (int i = 1; i < 4; ++i) {
                uint32_t mx = max_scalar(i);
                if (s <= mx && mx < e) {
                    stack.push_back({mx + 1, e});
                    e = mx;
                    split = true;
                    break;
                }
            }
            if (split) continue;
            if (e <= 0x7F) {
                out.push_back({{static_cast<uint8_t>(s), static_cast<uint8_t>(e)}});
                break;
            }
            for (int i = 1; i < 4; ++i) {
                uint32_t m = (1u << (6 * i)) - 1;
                if ((s & ~m) != (e & ~m)) {
                    if ((s & m) != 0) {
                        stack.push_back({(s | m) + 1, e});
                        e = s | m;
                        split = true;
                        break;
                    }
                    if ((e & m) != m) {
                        stack.push_back({e & ~m, e});
                        e = (e & ~m) - 1;
                        split = true;
                        break;
                    }
                }
            }
            if (split) continue;
            uint8_t a[4], b[4];
            size_t n = encode_utf8(s, a);
            encode_utf8(e, b);
            Utf8Seq seq;
            for (size_t k = 0; k < n; ++k) seq.push_back({a[k], b[k]});
            out.push_back(std::move(seq));
            break;
        }
    }
    return out;
}

struct TransVecHash {
    size_t operator()(const std::vector<Trans>& v) const {
        size_t h = 1469598103934665603ull;
        for (auto& t : v) {
            h ^= (static_cast<size_t>(t.lo) << 40) ^ (static_cast<size_t>(t.hi) << 32) ^ t.next;
            h *= 1099511628211ull;
        }
        return h;
    }
};

class Compiler {
public:
    Compiler(Program& p, bool reverse, size_t limit) : p_(p), reverse_(reverse), limit_(limit) {}

    uint32_t compile(const Hir& h, uint32_t next) {
        switch (h.kind) {
            case Hir::Kind::Empty:
                return next;
            case Hir::Kind::Class:
                return compile_class(h, next);
            case Hir::Kind::Look: {
                p_.look_mask |= 1u << static_cast<unsigned>(h.look);
                if (look_is_unicode_word(h.look)) p_.has_unicode_word = true;
                Inst in;
                in.op = Inst::Op::Look;
                in.look = h.look;
                in.next = next;
                return emit(in);
            }
            case Hir::Kind::Concat: {
                uint32_t n = next;
                if (reverse_) {
                    for (size_t i = 0; i < h.subs.size(); ++i) n = compile(h.subs[i], n);
                } else {
                    for (size_t i = h.subs.size(); i-- > 0;) n = compile(h.subs[i], n);
                }
                return n;
            }
            case Hir::Kind::Alt: {
                std::vector<uint32_t> entries;
                entries.reserve(h.subs.size());
                for (auto& s : h.subs) entries.push_back(compile(s, next));
                return emit_union(entries);
            }
            case Hir::Kind::Repeat:
                return compile_repeat(h, next);
        }
        return next;
    }

    uint32_t emit(const Inst& in) {
        if (p_.insts.size() + p_.trans.size() >= limit_) throw SizeLimitExceeded{};
        p_.insts.push_back(in);
        return static_cast<uint32_t>(p_.insts.size() - 1);
    }

    uint32_t emit_union(const std::vector<uint32_t>& alts) {
        if (alts.size() == 1) return alts[0];
        Inst in;
        in.op = Inst::Op::Union;
        in.a = static_cast<uint32_t>(p_.alts.size());
        in.n = static_cast<uint32_t>(alts.size());
        p_.alts.insert(p_.alts.end(), alts.begin(), alts.end());
        return emit(in);
    }

    uint32_t emit_sparse(const std::vector<Trans>& t) {
        if (t.empty()) return emit_fail();
        Inst in;
        in.op = Inst::Op::Sparse;
        in.a = static_cast<uint32_t>(p_.trans.size());
        in.n = static_cast<uint32_t>(t.size());
        p_.trans.insert(p_.trans.end(), t.begin(), t.end());
        return emit(in);
    }

    uint32_t emit_fail() {
        Inst in;
        in.op = Inst::Op::Fail;
        return emit(in);
    }

    uint32_t emit_match() {
        Inst in;
        in.op = Inst::Op::Match;
        return emit(in);
    }

private:
    Program& p_;
    bool reverse_;
    size_t limit_;

    // Union placeholder filled in after its body is compiled (loops refer back to it).
    uint32_t emit_union_placeholder() {
        Inst in;
        in.op = Inst::Op::Union;
        return emit(in);
    }
    void fill_union(uint32_t id, uint32_t first, uint32_t second) {
        p_.insts[id].a = static_cast<uint32_t>(p_.alts.size());
        p_.insts[id].n = 2;
        p_.alts.push_back(first);
        p_.alts.push_back(second);
    }

    uint32_t compile_repeat(const Hir& h, uint32_t next) {
        const Hir& sub = h.subs[0];
        uint32_t n = next;
        if (h.max == Hir::kInf) {
            uint32_t loop = emit_union_placeholder();
            uint32_t body = compile(sub, loop);
            if (h.greedy) fill_union(loop, body, next);
            else fill_union(loop, next, body);
            n = loop;
        } else {
            for (uint32_t k = h.min; k < h.max; ++k) {
                uint32_t u = emit_union_placeholder();
                uint32_t body = compile(sub, n);
                if (h.greedy) fill_union(u, body, next);
                else fill_union(u, next, body);
                n = u;
            }
        }
        for (uint32_t k = 0; k < h.min; ++k) n = compile(sub, n);
        return n;
    }

    uint32_t compile_class(const Hir& h, uint32_t next) {
        const auto& rs = h.set.ranges();
        if (rs.empty()) return emit_fail();
        if (h.bytes || rs.back().hi < 0x80) {
            std::vector<Trans> t;
            for (auto r : rs) {
                if (r.lo > 0xFF) break;
                t.push_back({static_cast<uint8_t>(r.lo), static_cast<uint8_t>(std::min<uint32_t>(r.hi, 0xFF)), next});
            }
            return emit_sparse(t);
        }
        std::vector<Utf8Seq> seqs;
        for (auto r : rs) {
            auto s = utf8_sequences(r.lo, r.hi);
            seqs.insert(seqs.end(), s.begin(), s.end());
        }
        return reverse_ ? compile_utf8_reverse(seqs, next) : compile_utf8_forward(seqs, next);
    }

    // ---- forward: incremental trie with suffix sharing --------------------------------------
    struct Node {
        std::vector<Trans> trans;
        bool has_last = false;
        Utf8Range last{0, 0};
    };

    uint32_t compile_utf8_forward(const std::vector<Utf8Seq>& seqs, uint32_t target) {
        std::unordered_map<std::vector<Trans>, uint32_t, TransVecHash> memo;
        std::vector<Node> stack(1);
        auto freeze = [&](const std::vector<Trans>& t) -> uint32_t {
            auto it = memo.find(t);
            if (it != memo.end()) return it->second;
            uint32_t id = emit_sparse(t);
            memo.emplace(t, id);
            return id;
        };
        auto set_last = [&](Node& node, uint32_t next) {
            if (node.has_last) {
                node.trans.push_back({node.last.lo, node.last.hi, next});
                node.has_last = false;
            }
        };
        auto compile_from = [&](size_t from) {
            uint32_t next = target;
            while (from + 1 < stack.size()) {
                Node node = std::move(stack.back());
                stack.pop_back();
                set_last(node, next);
                next = freeze(node.trans);
            }
            set_last(stack.back(), next);
        };
        for (auto& seq : seqs) {
            size_t prefix = 0;
            while (prefix < seq.size() && prefix < stack.size() && stack[prefix].has_last &&
                   stack[prefix].last == seq[prefix])
                ++prefix;
            compile_from(prefix);
            stack.back().has_last = true;
            stack.back().last = seq[prefix];
            for (size_t k = prefix + 1; k < seq.size(); ++k) {
                Node n;
                n.has_last = true;
                n.last = seq[k];
                stack.push_back(std::move(n));
            }
        }
        compile_from(0);
        Node root = std::move(stack.back());
        return freeze(root.trans);
    }

    // ---- reverse: chains consuming the last byte first, suffix-shared ------------------------
    uint32_t compile_utf8_reverse(const std::vector<Utf8Seq>& seqs, uint32_t target) {
        std::map<std::tuple<uint8_t, uint8_t, uint32_t>, uint32_t> memo;
        std::vector<uint32_t> entries;
        std::vector<Trans> single_byte;  // 1-byte sequences merge into one Sparse
        for (auto& seq : seqs) {
            if (seq.size() == 1) {
                single_byte.push_back({seq[0].lo, seq[0].hi, target});
                continue;
            }
            uint32_t n = target;
            for (size_t k = 0; k < seq.size(); ++k) {
                auto key = std::make_tuple(seq[k].lo, seq[k].hi, n);
                auto it = memo.find(key);
                if (it != memo.end()) {
                    n = it->second;
                } else {
                    uint32_t id = emit_sparse({{seq[k].lo, seq[k].hi, n}});
                    memo.emplace(key, id);
                    n = id;
                }
            }
            if (std::find(entries.begin(), entries.end(), n) == entries.end()) entries.push_back(n);
        }
        // Merge entries whose single transition targets differ but ranges are disjoint is not
        // needed for correctness; the DFA determinizes the union.
        if (!single_byte.empty()) entries.insert(entries.begin(), emit_sparse(single_byte));
        return emit_union(entries);
    }
};

void compute_byte_classes(Program& p) {
    std::array<bool, 257> boundary{};
    auto mark = [&](unsigned lo, unsigned hi) {
        boundary[lo] = true;
        boundary[hi + 1] = true;
    };
    for (auto& t : p.trans) mark(t.lo, t.hi);
    if (p.look_mask) {
        mark('\n', '\n');
        mark('\r', '\r');
        mark('0', '9');
        mark('A', 'Z');
        mark('_', '_');
        mark('a', 'z');
        mark(0x80, 0xFF);
    }
    uint8_t cls = 0;
    for (unsigned b = 0; b < 256; ++b) {
        if (b > 0 && boundary[b]) ++cls;
        p.byte_class[b] = cls;
    }
    p.num_byte_classes = static_cast<uint32_t>(cls) + 1;
}

} // namespace

bool compile_program(const Hir& hir, bool reverse, size_t size_limit, Program& out, std::string& error) {
    out = Program{};
    out.reverse = reverse;
    try {
        Compiler c(out, reverse, size_limit);
        uint32_t match = c.emit_match();
        uint32_t start = c.compile(hir, match);
        out.start_anchored = start;
        // Unanchored prefix: (?s-u:.)*? with lowest priority, so earlier starts win.
        Inst u;
        u.op = Inst::Op::Union;
        uint32_t loop = c.emit(u);
        uint32_t any = c.emit_sparse({{0x00, 0xFF, loop}});
        out.insts[loop].a = static_cast<uint32_t>(out.alts.size());
        out.insts[loop].n = 2;
        out.alts.push_back(start);
        out.alts.push_back(any);
        out.start_unanchored = loop;
    } catch (const SizeLimitExceeded&) {
        error = "compiled regex exceeds size limit";
        return false;
    }
    compute_byte_classes(out);
    return true;
}

} // namespace bro::search::rx
