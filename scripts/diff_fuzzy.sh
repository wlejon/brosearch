#!/usr/bin/env bash
# Live differential test of brosearch's fuzzy matcher against fzf (`fzf --filter`).
#
#   scripts/diff_fuzzy.sh [--cli PATH] [--fzf PATH] [--tree DIR] [--record]
#
#   --cli     brosearch-cli binary (default: build/Release/... or build/tools/...)
#   --fzf     fzf binary (default: $FZF, else fzf on PATH, else ~/go/bin/fzf)
#   --tree    a source tree whose `rg --files` listing becomes an extra, live corpus
#             (default: ../bro if present); also used for the 100k-item speed comparison
#   --record  rewrite the ctest fixtures (tests/fixtures/fuzzy/*.expected) from fzf's output.
#             The fixtures are recorded on Windows (path scheme treats '\' as a delimiter
#             there); the tests pin that behaviour.
#
# Every query in tests/fixtures/fuzzy/queries_*.txt is run through fzf and brosearch; the
# runner (brosearch-cli fuzzy --oracle) reports set and order agreement and checks that the
# incremental FuzzyIndex, fed the query one keystroke at a time while items are still being
# appended, returns exactly what a cold search returns.
set -euo pipefail
export MSYS_NO_PATHCONV=1

# Native path on Windows (Git Bash's /d/... is not understood by the Windows binaries).
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
fixtures="$here/tests/fixtures/fuzzy"
cli="" fzf="${FZF:-}" tree="" record=0
while [ $# -gt 0 ]; do
    case "$1" in
        --cli) cli="$2"; shift 2 ;;
        --fzf) fzf="$2"; shift 2 ;;
        --tree) tree="$2"; shift 2 ;;
        --record) record=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$cli" ]; then
    for c in "$here/build/tools/Release/brosearch-cli.exe" "$here/build/tools/brosearch-cli" \
             "$here/build-release/tools/brosearch-cli"; do
        [ -x "$c" ] && { cli="$c"; break; }
    done
fi
[ -n "$cli" ] || { echo "brosearch-cli not found; pass --cli" >&2; exit 2; }
if [ -z "$fzf" ]; then
    fzf="$(command -v fzf || true)"
    [ -n "$fzf" ] || fzf="$HOME/go/bin/fzf"
fi
# Git Bash: the CLI launches fzf with CreateProcessW, which needs a Windows path.
if command -v cygpath >/dev/null 2>&1; then
    [ -e "$fzf" ] || [ ! -e "$fzf.exe" ] || fzf="$fzf.exe"
    fzf="$(cygpath -m "$fzf")"
fi
[ -n "$tree" ] || { [ -d "$here/../bro/src" ] && tree="$here/../bro"; } || true

status=0
rec() { if [ "$record" = 1 ]; then echo "--record=$fixtures/$1"; fi; }

echo "== fixture corpora (fzf: $("$fzf" --version))"
"$cli" fuzzy --oracle --fzf="$fzf" --corpus="$fixtures/paths.corpus" \
    --queries="$fixtures/queries_paths.txt" $(rec paths.expected) || status=1
"$cli" fuzzy --oracle --fzf="$fzf" --gen=unicode \
    --queries="$fixtures/queries_unicode.txt" $(rec unicode.expected) || status=1
"$cli" fuzzy --oracle --fzf="$fzf" --gen=long \
    --queries="$fixtures/queries_long.txt" $(rec long.expected) || status=1

if [ -n "$tree" ] && command -v rg >/dev/null; then
    echo "== live corpus: rg --files $tree"
    (cd "$tree" && rg --files --path-separator / | sort) |
        "$cli" fuzzy --oracle --fzf="$fzf" --queries="$fixtures/queries_paths.txt" || status=1

    echo "== speed: 100k items (rg --files --no-ignore --hidden), fzf --bench vs brosearch --bench"
    list="$(cd "$tree" && { rg --files --no-ignore --hidden --path-separator / | sort | head -100000; } 2>/dev/null || true)"
    set +eo pipefail  # fzf and brosearch-cli exit 1 when nothing matches
    for q in a sc rend rendr src/rend webglscene "scene !test" zzzqqq; do
        f=$(printf '%s\n' "$list" | "$fzf" --filter "$q" --bench 1s | tail -1 | sed -E 's/.*avg: ([0-9.]+ms).*matches: ([0-9]+).*/avg \1, \2 matches/')
        b=$(printf '%s\n' "$list" | "$cli" fuzzy --bench=10 "$q" 2>&1 >/dev/null | sed -E 's/.*matches=([0-9]+) best=([0-9.]+ms) avg=([0-9.]+ms)/avg \3 (best \2), \1 matches/')
        same=$([ "$(printf '%s\n' "$list" | "$fzf" --filter "$q" | md5sum)" = \
                 "$(printf '%s\n' "$list" | "$cli" fuzzy "$q" | md5sum)" ] && echo identical || echo DIFFERENT)
        printf '%-14s fzf %-28s brosearch %-36s output %s\n' "'$q'" "$f" "$b" "$same"
        [ "$same" = identical ] || status=1
    done
fi
exit $status
