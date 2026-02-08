import json, subprocess, sys
base = ["tshark", "-r", sys.argv[1], "--disable-all-protocols", "--enable-protocol", "frame"]
fields = subprocess.run(base + ["-T", "fields", "-e", "frame.time_epoch", "-e", "frame.cap_len", "-e", "frame.len", "-e", "frame.cb_pen"], capture_output=True, text=True).stdout.splitlines()
packets = json.loads(subprocess.run(base + ["-T", "json", "-x"], capture_output=True, text=True).stdout or "[]")
for line, pkt in zip(fields, packets):
    time, caplen, length, pen = line.split("	")
    if pen:
        continue
    line = f"{time}	{caplen}	{length}"
    raw = pkt["_source"]["layers"].get("frame_raw", [""])
    print(f'{line}\t{raw[0] if isinstance(raw, list) else raw}')
if len(fields) != len(packets):
    sys.exit("tshark field and json counts differ")
