#!/usr/bin/env bash
# Live differential runner: brosearch-cli grep vs ripgrep.
#
#   scripts/diff_grep.sh [--update] [--real DIR]... [--timing]
#
# Corpus mode (always): materializes the adversarial corpus (tests/grep_oracle.h), runs every case
# of tests/fixtures/grep/cases.txt through rg and through brosearch-cli inside it, and diffs.
# --update rewrites tests/fixtures/grep/<name>.out from rg's output (what ctest checks against).
#
# Real-tree mode (--real DIR): runs tests/fixtures/grep/real_queries.txt over DIR with -n
# --column, comparing sorted output, and with --timing reports wall time (best of 3) for rg
# (parallel, unsorted) and brosearch-cli (parallel, sorted), both piped through cat: rg sends
# nothing when stdout is /dev/null (it stops at the first match, like -q), so timing it with
# output discarded measures a different search.
#
# Env: BROSEARCH_CLI (path to brosearch-cli), RG (path to rg).
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
cli=${BROSEARCH_CLI:-}
if [ -z "$cli" ]; then
    for c in build/tools/Release/brosearch-cli.exe build-release/tools/brosearch-cli build/tools/brosearch-cli; do
        if [ -x "$here/$c" ]; then cli=$here/$c; break; fi
    done
fi
[ -n "$cli" ] || { echo "brosearch-cli not found; set BROSEARCH_CLI" >&2; exit 2; }
rg=${RG:-rg}
export MSYS_NO_PATHCONV=1
fix=$here/tests/fixtures/grep
# Native form for arguments handed to the CLI (MSYS path conversion is disabled below).
fix_native=$(cygpath -m "$fix" 2>/dev/null || echo "$fix")
update=0
timing=0
real=()
while [ $# -gt 0 ]; do
    case "$1" in
        --update) update=1 ;;
        --timing) timing=1 ;;
        --real) shift; real+=("$1") ;;
        *) echo "unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

corpus=$(mktemp -d)
trap 'rm -rf "$corpus"' EXIT
# Native path for the CLI (MSYS path conversion is off, so convert explicitly on Windows).
corpus_native=$(cygpath -m "$corpus" 2>/dev/null || echo "$corpus")
"$cli" grep --materialize-corpus "$corpus_native"
[ -f "$corpus/plain.txt" ] || { echo "corpus was not materialized in $corpus" >&2; exit 2; }

pass=0
fail=0
while IFS=$'\t' read -r name args; do
    case "$name" in ''|\#*) continue ;; esac
    # explicit_* cases name their files; the rest search the whole corpus.
    where=.
    case "$name" in explicit_*) where= ;; esac
    run_rg() { (cd "$corpus" && eval "timeout -s KILL 60 \"$rg\" --sort path --no-heading --path-separator / $args $where" 2>&1); }
    run_us() { (cd "$corpus" && eval "timeout -s KILL 60 \"$cli\" grep $args $where" 2>&1); }
    if [ "$update" = 1 ]; then
        # Piped straight through (command substitution would drop NUL bytes).
        (cd "$corpus" && eval "\"$rg\" --sort path --no-heading --path-separator / $args $where" 2>&1) |
            "$cli" grep --write-fixture "$fix_native/$name.out"
    fi
    # Byte-exact comparison (NULs included).
    if cmp -s <(run_rg) <(run_us); then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "### $name: rg $args"
        diff -a <(run_rg | cut -c1-200) <(run_us | cut -c1-200) | head -20
    fi
done < "$fix/cases.txt"
echo "corpus: $pass agree, $fail differ"

# BSD date (macOS) has no %N; fall back to perl there.
if [ -n "$(date +%N | tr -d 0-9)" ]; then now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }
else now_ms() { date +%s%N | cut -b1-13; }; fi
best_of_3() {
    local best=999999999 t0 t1
    for _ in 1 2 3; do
        t0=$(now_ms); "$@" 2> /dev/null | cat > /dev/null; t1=$(now_ms)
        [ $((t1 - t0)) -lt "$best" ] && best=$((t1 - t0))
    done
    echo "$best"
}

for dir in "${real[@]}"; do
    rpass=0
    rfail=0
    while IFS=$'\t' read -r name args; do
        case "$name" in ''|\#*) continue ;; esac
        a=$(eval "timeout -s KILL 120 \"$rg\" --sort path --no-heading --path-separator / -n --column $args \"$dir\"" 2>/dev/null)
        b=$(eval "timeout -s KILL 120 \"$cli\" grep -n --column $args \"$dir\"" 2>/dev/null)
        if [ "$a" == "$b" ]; then
            rpass=$((rpass + 1)); verdict=agree
        else
            rfail=$((rfail + 1)); verdict=DIFFER
            diff <(printf '%s\n' "$a" | cut -c1-160) <(printf '%s\n' "$b" | cut -c1-160) | head -8
        fi
        lines=$(printf '%s' "$a" | grep -c '' || true)
        if [ "$timing" = 1 ]; then
            trg=$(eval "best_of_3 \"$rg\" -n --column $args \"$dir\"")
            tus=$(eval "best_of_3 \"$cli\" grep -n --column $args \"$dir\"")
            printf '%-24s %-6s lines=%-7s rg=%5sms brosearch=%5sms\n' "$name" "$verdict" "$lines" "$trg" "$tus"
        else
            printf '%-24s %-6s lines=%s\n' "$name" "$verdict" "$lines"
        fi
    done < "$fix/real_queries.txt"
    echo "$dir: $rpass agree, $rfail differ"
done
[ "$fail" = 0 ]
