#!/usr/bin/env bash
set -euo pipefail

out=${1:?usage: generate.sh OUTDIR}
mkdir -p "$out"
hex=$(mktemp -p "$out")
trap 'rm -f "$hex"' EXIT

write_hex() {
    local sec
    : > "$hex"
    for sec in 1 2 3; do
        printf '1700000%03d.%06d\n' "$sec" "$((sec * 123457))" >> "$hex"
        printf '0000  %s\n' "$1" >> "$hex"
    done
}

make_capture() {
    local name=$1 linktype=$2 bytes=$3
    write_hex "$bytes"
    text2pcap -q -t '%s.%f' -l "$linktype" -F pcapng "$hex" "$out/$name.pcapng"
    text2pcap -q -t '%s.%f' -l "$linktype" -F pcap "$hex" "$out/$name.pcap"
    editcap -F nsecpcap "$out/$name.pcap" "$out/$name-nano.pcap"
    editcap -s 4 "$out/$name.pcapng" "$out/$name-snap.pcapng"
}

make_capture user0 147 "a1 01 80 80 7f 7f 00 08 01"
make_capture user15 162 "01 02 03 04 05"
make_capture h4 187 "04 0e 04 01 03 0c 00"
make_capture h4-phdr 201 "04 0e 04 01 03 0c 00"
make_capture usbmon 189 "$(printf '%s ' 00 11 22 33 44 55 66 77 43 01 81 02 00 00 2d 00 $(for _ in $(seq 32); do printf '00 '; done) 08 00 00 00 08 00 00 00 a1 01 80 80 7f 7f 00 08)"
make_capture usbmon-mmapped 220 "$(printf '%s ' 00 11 22 33 44 55 66 77 43 01 81 02 00 00 2d 00 $(for _ in $(seq 48); do printf '00 '; done) a1 01)"
make_capture usbpcap 249 "1b 00 10 20 30 40 00 00 00 00 00 00 00 00 01 00 01 00 81 01 08 00 00 00 a1 01 80 80"

for f in user0.pcap user0.pcapng usbpcap.pcapng; do
    size=$(stat -c %s "$out/$f")
    head -c "$((size - 3))" "$out/$f" > "$out/cut-$f"
done
