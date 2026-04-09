# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.2.0 - 2026-04-09

Adds to the API; existing code builds and links unchanged.

- `pcw_block_fcs_len` gives the FCS length from a pcap file header, a pcapng `if_fcslen`
  option or a packet's `epb_flags`; `PCW_OPT_IF_FCSLEN` names the option
- converting between pcap and pcapng keeps the FCS length, so Wireshark still shows the FCS
  instead of a trailer
- `pcwdump` prints the FCS length when the block has one
- a pcap file header with reserved link type bits set is rejected with `PCW_ERR_FORMAT`, as
  libpcap and Wireshark do; before, those bits ended up in `linktype`
- the pcap writer rejects a link type over 65535 with `PCW_ERR_ARG` instead of writing it
  into the reserved bits
- the ABI baseline no longer records build paths

## 0.1.1 - 2026-03-29

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
