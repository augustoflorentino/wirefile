#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

[ $# -eq 2 ] || { echo "usage: $0 save|check <lib.so>" >&2; exit 2; }
mode=$1
lib=$2
root=$(cd "$(dirname "$0")/.." && pwd)
baseline=$root/abi/wirefile.abi

major=$(sed -n 's/^project(wirefile VERSION \([0-9]*\)\..*/\1/p' "$root/CMakeLists.txt")
soname=$(readelf -d "$lib" | sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')
if [ "$soname" != "libwirefile.so.$major" ]; then
    echo "soname $soname does not match major version $major" >&2
    exit 1
fi

if [ "$mode" = save ]; then
    mkdir -p "$(dirname "$baseline")"
    abidw --out-file "$baseline" "$lib"
    echo "baseline saved: $baseline"
    exit 0
fi

if [ ! -f "$baseline" ]; then
    echo "no baseline yet (before 1.0.0): abi check skipped"
    exit 0
fi

base_soname=$(grep -o "soname='[^']*'" "$baseline" | head -1 | cut -d"'" -f2)
if [ "$base_soname" != "$soname" ]; then
    echo "major version bumped ($base_soname -> $soname): abi check skipped"
    exit 0
fi

set +e
abidiff --no-added-syms "$baseline" "$lib"
status=$?
set -e
if (( status & 3 )); then
    echo "abidiff failed to run" >&2
    exit 1
fi
if (( status & 12 )); then
    echo "ABI changed without a major version bump; review the report above" >&2
    exit 1
fi
echo "abi ok against $base_soname"
