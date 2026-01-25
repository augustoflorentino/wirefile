#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

[ $# -eq 2 ] || { echo "usage: $0 <lib.so> <header>" >&2; exit 2; }
lib=$1
header=$2

exported=$(nm -D --defined-only "$lib" | awk '$2 ~ /^[TDBR]$/ {print $3}' | sort)
declared=$(tr '\n' ' ' < "$header" | grep -oE 'PCW_API[^;(]*\(' \
    | grep -oE '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\($' | tr -d ' (' | grep '^pcw_' | sort)

if [ "$exported" != "$declared" ]; then
    echo "exported symbols differ from the header (< exported, > header):" >&2
    diff <(echo "$exported") <(echo "$declared") >&2 || true
    exit 1
fi
echo "symbols ok: $(echo "$exported" | wc -l)"
