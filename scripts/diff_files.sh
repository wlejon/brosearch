#!/usr/bin/env bash
# Live differential runner for the ignore matcher + walker.
#
#   scripts/diff_files.sh [--update] [--cli PATH] [SPEC...]     spec trees vs git / rg
#   scripts/diff_files.sh --trees [--cli PATH] DIR...           real trees vs `rg --files`, timed
#
# Spec mode: each tests/fixtures/walk/*.spec is materialized in a temp dir; repositories named
# by @git get a real `git init` (plus the spec's core.ignorecase). The oracle named by @oracle
# runs with a private HOME (so only the spec's @global excludes apply):
#   git: git ls-files -z --others --exclude-standard   (from the @root dir)
#   rg:  rg --files <flags from the spec's @options>
# and its sorted output is compared with `brosearch-cli files --run-spec`. --update rewrites the
# spec's @expect block from the oracle (that block is what the ctest `walk` suite checks).
#
# Needs: git, rg, and a built brosearch-cli (default: newest of build*/{Release,Debug}/ or build*/).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI=""
UPDATE=0
TREES=0
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --update) UPDATE=1 ;;
        --trees) TREES=1 ;;
        --cli) CLI="$2"; shift ;;
        *) ARGS+=("$1") ;;
    esac
    shift
done
if [ -z "$CLI" ]; then
    CLI=$(ls -t "$ROOT"/build*/Release/brosearch-cli* "$ROOT"/build*/brosearch-cli "$ROOT"/build*/tools/brosearch-cli \
          "$ROOT"/build*/tools/Release/brosearch-cli.exe 2>/dev/null | head -1)
fi
[ -x "$CLI" ] || { echo "brosearch-cli not found (use --cli)"; exit 2; }
CLI="$(cd "$(dirname "$CLI")" && pwd)/$(basename "$CLI")"
RG=${RG:-rg}
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac
# BSD date (macOS) has no %N; fall back to perl there.
if [ -n "$(date +%N | tr -d 0-9)" ]; then now_ns() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1e9'; }
else now_ns() { date +%s%N; }; fi

if [ $TREES = 1 ]; then
    status=0
    for d in "${ARGS[@]}"; do
        a=$(cd "$d" && "$RG" --files | tr '\\' '/' | LC_ALL=C sort)
        # rg matches ignore patterns case-sensitively and never precomposes names; the library
        # defaults (auto) follow the repository's core.ignorecase / core.precomposeUnicode, which
        # differ wherever a pattern matches only by case or (macOS) only after NFD -> NFC.
        b=$(cd "$d" && "$CLI" files --sort --case=sensitive --precompose=off --dialect=rg)
        na=$(printf '%s\n' "$a" | grep -c .)
        nb=$(printf '%s\n' "$b" | grep -c .)
        if [ "$a" == "$b" ]; then echo "SAME  $d ($na files)"; else
            echo "DIFF  $d (rg $na, brosearch $nb)"; status=1
            diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") | head -20
        fi
        # Timing: best of 5 for each (rg output discarded, ours counted in-process).
        best=999999
        for _ in 1 2 3 4 5; do
            s=$(now_ns); (cd "$d" && "$RG" --files >/dev/null); e=$(now_ns)
            t=$(( (e - s) / 1000000 )); [ $t -lt $best ] && best=$t
        done
        best_cli=999999
        for _ in 1 2 3 4 5; do
            s=$(now_ns); (cd "$d" && "$CLI" files >/dev/null); e=$(now_ns)
            t=$(( (e - s) / 1000000 )); [ $t -lt $best_cli ] && best_cli=$t
        done
        echo "      rg --files ${best} ms   brosearch-cli files ${best_cli} ms (process wall, best of 5)"
        (cd "$d" && "$CLI" files --bench=5)
    done
    exit $status
fi

SPECS=("${ARGS[@]}")
[ ${#SPECS[@]} -eq 0 ] && SPECS=("$ROOT"/tests/fixtures/walk/*.spec)
WORK=$(mktemp -d)
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT  # @unreadable dirs are mode 000
pass=0; fail=0; skip=0
for spec in "${SPECS[@]}"; do
    name=$(basename "$spec" .spec)
    if [ $WINDOWS = 1 ] && grep -q '^@posix' "$spec"; then skip=$((skip + 1)); echo "SKIP  $name (posix)"; continue; fi
    tree="$WORK/$name"
    meta=$("$CLI" files --materialize "$spec" "$tree"); rc=$?
    if [ $rc = 3 ]; then skip=$((skip + 1)); echo "SKIP  $name (${meta#skip })"; continue; fi
    [ $rc = 0 ] || { echo "ERROR $name: materialize"; fail=$((fail + 1)); continue; }
    home="$tree.home"; mkdir -p "$home"
    oracle=""; rootrel="."
    # A real `git init` (on macOS it also probes and writes core.ignorecase / precomposeUnicode;
    # the spec's own values are applied after it, and brosearch reads the resulting config).
    while read -r kw a b c; do
        case "$kw" in
            git) (cd "$tree/$a" && git init -q . 2>/dev/null && { [ "$b" = "-" ] || git config core.ignorecase "$b"; } \
                  && { [ "${c:--}" = "-" ] || git config core.precomposeunicode "$c"; }) ;;
            root) rootrel="$a" ;;
            oracle) oracle="$a" ;;
        esac
    done <<< "$meta"
    wroot="$tree/$rootrel"
    if [ "$oracle" = git ]; then
        expect=$(cd "$wroot" && HOME="$home" USERPROFILE="$home" XDG_CONFIG_HOME= GIT_CONFIG_NOSYSTEM=1 \
                 git ls-files -z --others --exclude-standard | tr '\0' '\n' | LC_ALL=C sort)
    else
        rgargs=()
        while IFS= read -r a; do rgargs+=("$a"); done < <("$CLI" files --rg-args "$spec" | tr -d '\r')
        expect=$(cd "$wroot" && HOME="$home" USERPROFILE="$home" XDG_CONFIG_HOME= \
                 "$RG" --files ${rgargs[@]+"${rgargs[@]}"} 2>"$tree.oracle.err" | tr '\\' '/' | LC_ALL=C sort)
    fi
    ours=$("$CLI" files --run-spec "$spec" "$tree" 2>"$tree.ours.err")
    # @unreadable specs: the error messages must match too (rg prefixes "rg: ", we "brosearch-cli: ").
    errdiff=""
    if [ "$oracle" = rg ] && grep -q '^@unreadable' "$spec"; then
        e1=$(sed 's/^rg: //' "$tree.oracle.err" | tr '\\' '/' | LC_ALL=C sort)
        e2=$(sed 's/^brosearch-cli: //' "$tree.ours.err" | LC_ALL=C sort)
        [ "$e1" == "$e2" ] || errdiff=$(diff <(printf '%s\n' "$e1") <(printf '%s\n' "$e2"))
    fi
    if [ "$expect" == "$ours" ] && [ -z "$errdiff" ]; then
        pass=$((pass + 1)); echo "SAME  $name ($oracle)"
    else
        fail=$((fail + 1)); echo "DIFF  $name ($oracle)   < $oracle   > brosearch"
        diff <(printf '%s\n' "$expect") <(printf '%s\n' "$ours") | head -30
        [ -z "$errdiff" ] || { echo "  errors:"; printf '%s\n' "$errdiff" | head -20; }
    fi
    if [ $UPDATE = 1 ]; then printf '%s\n' "$expect" | "$CLI" files --update-spec "$spec"; fi
done
echo "spec trees: $pass same, $fail different, $skip skipped"
[ $fail -eq 0 ]
