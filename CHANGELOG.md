# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

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
