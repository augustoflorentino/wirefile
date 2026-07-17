# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 2.1.1 - 2026-07-17

- `pcw_writer_section` starts a pcapng section with options of its own, such as
  `shb_userappl`, `shb_os` and `shb_hardware`, which a new capture could not have before, so
  tools showed nothing for the application that wrote it. Called again, it starts a new
  section in the same file, with its interfaces numbered from 0
- `pcwcopy` skips a broken or oversized block with a message and copies the rest; before, the
  first one stopped the copy and left the output cut there. It still exits with 1 when a
  block was skipped or reading stopped on an error

## 2.0.0 - 2026-05-29

Incompatible change: an error that stops the reader is returned once. Before, every later
call to `pcw_reader_next` returned it again, so the reading loop this README showed, which
skips errors and stops at `PCW_END`, never ended on a file with a broken interface block or
on an I/O error. Programs had to compare offsets between errors to get out, as `pcwdump` did.

- after an error that stops it, `pcw_reader_next` returns `PCW_END`
- `pcw_reader_error` returns the error that stopped the reader, or `PCW_OK` while reading
  goes on and after a clean end or a truncated last packet
- `PCW_NAME_EUI48` and `PCW_NAME_EUI64` name the other two record types of a name block
- `pcwdump` exits with 1 when reading stopped on an error
- soname `libwirefile.so.2`

### Upgrading

- a loop that skips errors and stops at `PCW_END` needs no change; it now ends on every input.
  Call `pcw_reader_error` after it to know whether the input was read to the end
- a loop that stopped on the second identical error, or on an error at an unchanged
  `pcw_reader_offset`, can drop that check
- code that called `pcw_reader_next` again after an error to see whether it repeats must call
  `pcw_reader_error` instead: a nonzero result means the reader stopped
- rebuild; programs linked to `libwirefile.so.1` keep using the old library

## 1.3.0 - 2026-05-28

- Blocks copied from a pcapng source in the other byte order, as when merging captures made
  on machines of different endianness, keep what the spec lets a writer reorder: every
  option of interfaces and packets, name records of the four known types, and interface
  statistics with their options. Before, the copy kept only the packet bytes and timestamps,
  and dropped name and statistics blocks. Custom options keep their data as is, with the
  enterprise number reordered, as the spec asks
- A stream reader that skips an oversized block cut short by the end of the input now counts
  the skipped bytes in `pcw_reader_trailing`; before it reported 0, as if the file ended
  cleanly
- The fuzzer also copies into a section of the host byte order, which runs the conversion

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
