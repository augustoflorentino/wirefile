# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 1.0.0 - 2026-04-17

Incompatible change: the writer takes pcapng options. From this release on the API and ABI
are stable within 1.x, checked against the baseline in `abi/`.

- `pcw_writer_add_interface` takes a list of options in place of `name`, and
  `pcw_writer_packet` takes one too. Before, the interface name was the only option a new
  capture could have: no description, speed, FCS length or OS, and no packet direction,
  comment or flags, which a capture of HID or USB traffic needs to tell host to device from
  device to host. Numbers in fixed size options go in host byte order and come out in the
  file's
- `pcw_option_t`, `PCW_EPB_INBOUND`, `PCW_EPB_OUTBOUND` and names for the other options of
  the spec (`PCW_OPT_IF_SPEED`, `PCW_OPT_IF_OS`, `PCW_OPT_EPB_PACKETID` and so on)
- soname `libwirefile.so.1`

### Upgrading

- `pcw_writer_add_interface(w, lt, snap, resol, "eth0", &id)` becomes
  `pcw_writer_add_interface(w, lt, snap, resol, &name, 1, &id)` with
  `pcw_option_t name = {PCW_OPT_IF_NAME, "eth0", 4};`, or `NULL, 0` where the name was `NULL`
- add `, NULL, 0` at the end of each `pcw_writer_packet` call
- rebuild; programs linked to `libwirefile.so.0` keep using the old library

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
