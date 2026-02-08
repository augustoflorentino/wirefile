#!/usr/bin/env bash
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
build=${1:?usage: run.sh BUILDDIR CAPTURE...}
shift
work=$(mktemp -d -p "$build")
trap 'rm -rf "$work"' EXIT
cc -O1 -o "$work/libpcap_dump" "$here/libpcap_dump.c" -lpcap || exit 1
failed=0

strip_phdr() {
    awk -F '\t' -v OFS='\t' '{ $2 -= 4; $3 -= 4; $4 = substr($4, 9); print }' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

compare() {
    if ! cmp -s "$work/pcw" "$work/$2"; then
        echo "DIFF $2 $1"
        diff "$work/pcw" "$work/$2" | head -4 | cut -c1-120
        failed=1
    fi
}

for f in "$@"; do
    "$build/pcwdump" --packets "$f" > "$work/pcw" 2> "$work/err"
    "$build/pcwdump" --packets --mem "$f" > "$work/mem" 2>/dev/null
    cmp -s "$work/pcw" "$work/mem" || { echo "DIFF mem $f"; failed=1; }
    if grep -q 'flags=0x[0-9a-f]*[13579bdf] ' <("$build/pcwdump" "$f" 2>/dev/null); then
        head -n -1 "$work/pcw" > "$work/pcw.tmp" && mv "$work/pcw.tmp" "$work/pcw"
    fi
    cp "$work/pcw" "$work/pcw-raw"
    python3 -I "$here/tshark_dump.py" "$f" > "$work/tshark"
    "$build/pcwdump" "$f" 2>/dev/null | grep -q 'linktype=201 ' && strip_phdr "$work/pcw"
    compare "$f" tshark
    cp "$work/pcw-raw" "$work/pcw"
    if "$work/libpcap_dump" "$f" > "$work/libpcap" 2>/dev/null; then
        sed -i 's/^\t/0.000000000\t/' "$work/pcw"
        compare "$f" libpcap
    fi
    for format in pcap pcapng; do
        "$build/pcwcopy" "$format" "$f" "$work/copy" 2>/dev/null || continue
        [ -s "$work/copy" ] || continue
        "$build/pcwdump" --packets "$work/copy" > "$work/copied"
        "$build/pcwdump" "$work/copy" | grep -q 'linktype=201 ' && strip_phdr "$work/copied"
        python3 -I "$here/tshark_dump.py" "$work/copy" > "$work/copied-tshark"
        cmp -s "$work/copied" "$work/copied-tshark" || { echo "DIFF copy $format $f"; failed=1; }
    done
done
[ "$failed" = 0 ] && echo "oracle: $# files ok"
exit "$failed"
