#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/wirefile/wirefile.h}
mkdir -p "$(dirname "$out")"

{
    cat "$root/include/wirefile/wirefile.h"
    echo
    echo "#if defined(PCW_IMPLEMENTATION) && !defined(PCW_IMPLEMENTATION_DONE)"
    echo "#define PCW_IMPLEMENTATION_DONE"
    for src in "$root"/src/*.h "$root"/src/*.c; do
        [ -f "$src" ] && grep -v '^#include "' "$src"
    done
    echo "#endif"
} > "$out"
echo "$out"
