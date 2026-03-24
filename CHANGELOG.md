# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

Fixes, no API change.

- security: on 32-bit builds a pcap record length near 4 GiB wrapped the size computation;
  the reader returned the same packet forever with `data_len` past the end of the buffer.
  It is now read as a truncated packet
- on 32-bit builds the pcapng writer did not reject a packet over 4 GiB and wrote a block
  with a wrong length
- a pcapng interface block that failed to parse was skipped, so packets of the next interfaces
  were reported with the wrong interface and link type. A broken interface block now stops the
  reader with `PCW_ERR_FORMAT`, as Wireshark does

## 0.1.0 - 2026-02-20

First release.

- reader for pcap (both byte orders, micro and nano) and pcapng (SHB with several sections,
  IDB, EPB, SPB, the obsolete PB, NRB, ISB; custom and unknown blocks returned, not rejected)
- block options and name records, unknown ones kept
- streaming through a read callback with one bounded buffer, or zero-copy from memory
- a file cut in the middle of a packet returns that packet flagged as truncated
- writer for pcap and pcapng with the timestamp resolution you choose, and block copy for
  conversion between them
- link types USER0-15, Bluetooth HCI H4, Linux usbmon and USBPcap tested
