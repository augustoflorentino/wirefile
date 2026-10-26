# wirefile

> A C99 library for the capture files Wireshark opens: pcap and pcapng, read as a stream in
> bounded memory and written back block for block, through callbacks instead of stdio.

[Releases](https://github.com/augustoflorentino/wirefile/releases) · [Changelog](CHANGELOG.md) · [Security](SECURITY.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/dump-dark.svg">
  <img src="docs/images/dump-light.svg" alt="Hexdump of the 192-byte pcapng file written by examples/basic.c, with the section header, the interface block and three packet blocks marked" width="728">
</picture>

The three HID reports that [`examples/basic.c`](examples/basic.c) writes, as they land on disk.

## Formats

| | pcap | pcapng |
|---|---|---|
| byte orders | both, detected from the magic | both, per section |
| timestamps | micro or nano | any `if_tsresol`, binary ones included, plus `if_tsoffset` |
| interfaces | one, in the file header | any number, per section |
| blocks | packets | section, interface, enhanced and simple packets, name records, statistics, custom |
| FCS length | file header | `if_fcslen` and `epb_flags` |

Link types pass through untouched. `PCW_LINKTYPE_*` names the ones the tests cover: `USER0` to
`USER15` (147 to 162, handy for raw HID reports), Bluetooth HCI H4 (187, and 201 with the
direction header), Linux usbmon (189, 220) and USBPcap (249). A pcap header with reserved link
type bits set is refused with `PCW_ERR_FORMAT`, as libpcap and Wireshark refuse it.

The library never opens a file. It pulls bytes from a read callback or a memory buffer and
pushes them to a write callback, so it works the same over a socket, a pipe or a flash page.

## Reading

```c
pcw_reader_t *reader;
const pcw_block_t *block;
int status;

pcw_reader_create(NULL, NULL, NULL, &reader);
pcw_reader_open_stream(reader, my_read, my_ctx);
while ((status = pcw_reader_next(reader, &block)) != PCW_END) {
    if (status != PCW_OK)
        continue;
    if (block->kind == PCW_KIND_PACKET)
        handle(block->ts_sec, block->ts_nsec, block->data, block->data_len);
}
status = pcw_reader_error(reader);
pcw_reader_destroy(reader);
```

`my_read(ctx, buf, buf_len, &out_read)` fills up to `buf_len` bytes and returns 0; zero bytes
read is the end of the input, a nonzero return becomes `PCW_ERR_IO`. `pcw_reader_open_mem`
reads a buffer instead, with no copy and no block size limit: blocks point into your data.

Each call yields one `pcw_block_t`, valid until the next call:

| field | meaning |
|---|---|
| `kind` | `PCW_KIND_SECTION`, `INTERFACE`, `PACKET`, `NAMES`, `STATS` or `OTHER` |
| `type` | pcapng block type (`PCW_BLOCK_*`); 0 for pcap |
| `format` | `PCW_FORMAT_PCAP` or `PCW_FORMAT_PCAPNG` |
| `flags` | `PCW_FLAG_TRUNCATED`, `PCW_FLAG_BIG_ENDIAN`, `PCW_FLAG_NO_TIMESTAMP` |
| `section` | section number, from 0 |
| `interface_id`, `linktype`, `snaplen` | the interface the block belongs to |
| `version_major`, `version_minor` | section version |
| `ts_resol` | as in `if_tsresol`: 6 is micro, 9 is nano, bit 7 set means a power of two |
| `ts_offset` | `if_tsoffset`, in seconds |
| `ts_raw` | the timestamp as stored, in `ts_resol` units |
| `ts_sec`, `ts_nsec` | the timestamp in seconds and nanoseconds, offset applied |
| `orig_len` | original packet length |
| `section_len` | section length, -1 when unknown |
| `data`, `data_len` | packet bytes, or the records of a `NAMES` block |
| `options`, `options_len` | the block's raw options |
| `body`, `body_len` | the whole block body as stored |

Sections come first and interfaces precede the packets that use them. Simple packet blocks
carry `PCW_FLAG_NO_TIMESTAMP` and a zero time; custom and unknown blocks arrive as
`PCW_KIND_OTHER` with their body.

Options are walked with `pcw_option_next` or looked up with `pcw_option_find`, name records
with `pcw_name_next`; all three return `PCW_END` when done. Numbers inside options keep the
file's byte order, so read them with `pcw_get_u16`, `pcw_get_u32` and `pcw_get_u64`, which take
the block. `pcw_block_fcs_len` gives the FCS length in bits, or `PCW_END` when the file does not
say.

What goes wrong, and what happens next:

- a block with broken content returns `PCW_ERR_FORMAT` and is skipped; the next call goes on
- a broken file header, section header, interface block, block length or trailing length
  stops the reader. The stopping error is returned once, later calls return `PCW_END`, and
  `pcw_reader_error` keeps it. After a clean end, or one cut inside a packet, it is `PCW_OK`,
  so the loop above always ends and one check after it tells a full read from a stopped one
- a file cut inside a packet yields that packet with `PCW_FLAG_TRUNCATED` and the bytes that
  are there; cut anywhere else, `pcw_reader_trailing` counts the bytes left over
- in stream mode the reader holds one buffer of `max_block_len` (512 KiB) and up to
  `max_interfaces` interfaces (1024); `pcw_reader_set_limits` changes both before opening. A
  packet or statistics block over the limit is skipped with `PCW_ERR_LIMIT`; a section or
  interface block over it, or one interface too many, stops the reader
- `pcw_reader_offset` is the input position after the last block

## Writing

```c
pcw_writer_t *writer;
uint32_t iface;
uint32_t flags = PCW_EPB_INBOUND;
pcw_option_t name = {PCW_OPT_IF_NAME, "hid0", 4};
pcw_option_t direction = {PCW_OPT_EPB_FLAGS, &flags, sizeof(flags)};

pcw_writer_create(NULL, NULL, NULL, &writer);
pcw_writer_open(writer, PCW_FORMAT_PCAPNG, my_write, my_ctx);
pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, &name, 1, &iface);
pcw_writer_packet(writer, iface, ts_sec, ts_nsec, data, data_len, orig_len, &direction, 1);
pcw_writer_destroy(writer);
```

`my_write(ctx, data, data_len)` returns 0 on success and receives each block whole, in one
call, so a failing sink never leaves half a block behind; after one failure every call returns
`PCW_ERR_IO`. New files use the host byte order.

- `pcw_writer_section` gives a pcapng section its options (`shb_userappl`, `shb_os`,
  `shb_hardware`, a comment) before the first interface, or opens a new section later, with
  interfaces numbered from 0 again. pcap has no sections and returns `PCW_ERR_ARG`
- times are stored in the interface resolution, truncated. pcap takes only micro or nano and
  one interface. `pcw_writer_packet_units` takes the time as a count of interface units since
  1970, for resolutions finer than a nanosecond or binary ones
- options are `{code, value, value_len}` lists, or `NULL, 0`. Options the spec gives a fixed
  size (`if_speed`, `if_tzone`, `if_fcslen`, `if_txspeed`, `if_rxspeed`, `epb_flags`,
  `epb_dropcount`, `epb_packetid`, `epb_queue`, `epb_processid_threadid`) are passed in host
  order and written in the file's; everything else, custom options too, goes out as given.
  Code 0, values over 65535 bytes, a fixed-size option of the wrong size, `if_tsresol` and
  `if_tsoffset` are refused with `PCW_ERR_ARG` before anything is written
- `pcw_writer_block` writes a block a reader returned, so copying and converting are a loop of
  `pcw_reader_next` and `pcw_writer_block`. pcapng to pcapng and pcap to pcap are byte
  identical. pcap to pcapng gives one section and one interface; pcapng to pcap keeps the
  packets of the first interface, fails at an interface with another link type, and drops
  what pcap cannot hold. The FCS length crosses both ways
- blocks from a source in the other byte order are rewritten in the writer's: interfaces,
  packets, name records and statistics keep every option the spec defines, custom options get
  their enterprise number swapped and their data copied as is. Unknown options and blocks,
  `epb_verdict` and custom blocks are dropped, since nobody can swap bytes they do not
  understand
- to change a block on the way, copy the struct, edit the copy (time, data, lengths, link type,
  snaplen) and write the copy; the writer rebuilds what changed
- `pcw_writer_offset` counts the bytes written

## Tools

Two of the examples are small programs worth keeping around. `pcwdump` lists the blocks of a
file, here the capture from the picture:

```console
$ pcwdump hid.pcapng
section type=0x0a0d0d0a section=0 if=0 linktype=0 snaplen=0 flags=0x0
interface type=0x00000001 section=0 if=0 linktype=147 snaplen=0 flags=0x0
  option 2 (7 bytes): 67616d65706164
  option 9 (1 bytes): 09
packet type=0x00000006 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000000.000000000 caplen=8 len=8
packet type=0x00000006 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000001.250000000 caplen=8 len=8
packet type=0x00000006 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000002.500000000 caplen=8 len=8
$ pcwdump --packets hid.pcapng
1700000000.000000000	8	8	a10180807f7f0008
1700000001.250000000	8	8	a10180807f7f0008
1700000002.500000000	8	8	a10180807f7f0008
```

`--mem` reads the whole file through `pcw_reader_open_mem`, `--limit BYTES` sets the block size
limit. `pcwcopy` converts between the formats, skipping broken blocks with a message and exiting
with 1 if it had to:

```console
$ pcwcopy pcap hid.pcapng hid.pcap
$ pcwdump hid.pcap
section type=0x00000000 section=0 if=0 linktype=147 snaplen=0 flags=0x0
packet type=0x00000000 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000000.000000000 caplen=8 len=8
packet type=0x00000000 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000001.250000000 caplen=8 len=8
packet type=0x00000000 section=0 if=0 linktype=147 snaplen=0 flags=0x0 ts=1700000002.500000000 caplen=8 len=8
```

## Building

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DWIREFILE_BUILD_EXAMPLES=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Link with `find_package(wirefile REQUIRED)` and `wirefile::wirefile`, or with
`pkg-config --cflags --libs wirefile`. `scripts/amalgamate.sh` produces the single header
`dist/wirefile/wirefile.h`; one `.c` file defines `PCW_IMPLEMENTATION` before including it, and
`PCW_STATIC` keeps the functions private to that file.

Every fallible call returns `PCW_OK` or a negative code that `pcw_strerror` describes. Objects
from `pcw_*_create` are freed by the matching `pcw_*_destroy`, which accepts `NULL`; the library
never takes ownership of what you pass, and the allocator is yours if you hand one to the create
calls. Compatible releases bump the minor version, incompatible ones the major version and the
soname.

## Tests and fuzzing

```sh
cmake --preset dev && cmake --build build/dev && ctest --preset dev
cmake --preset fuzz && cmake --build build/fuzz
```

- unit tests, with an allocation failure injected at every point
- the [pcapng-test-generator](tests/data/pcapng-test-generator/SOURCE) corpus in both byte
  orders, read whole and in 1 and 13 byte chunks, and copied back byte for byte
- `fuzz_read` drives the reader, the writer and a reread of what was written
- `tests/oracle/run.sh` compares every packet (time, lengths, bytes) with tshark and libpcap,
  on Wireshark's own test captures and on generated ones:

```sh
tests/oracle/fetch.sh build/oracle/ws
tests/oracle/generate.sh build/oracle/gen
tests/oracle/run.sh build build/oracle/ws/* build/oracle/gen/* tests/data/pcapng-test-generator/*/*.pcapng
```

CI adds an i386 run, MSVC, install checks on Linux, macOS and Windows, and an ABI comparison
with the baseline in `abi/`. MIT licensed, see [LICENSE](LICENSE).
