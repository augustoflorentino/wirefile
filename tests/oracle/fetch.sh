#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: fetch.sh OUTDIR}
base=https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures
mkdir -p "$out"
while read -r _ name; do
    [ -f "$out/$name" ] || curl -fsSL -o "$out/$name" "$base/$name"
done < "$here/captures.sha256"
(cd "$out" && sha256sum -c --quiet "$here/captures.sha256")
