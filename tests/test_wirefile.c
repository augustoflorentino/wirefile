#include "test_util.h"

typedef struct {
    membuf_t buf;
    int big;
} builder_t;

typedef struct {
    size_t live;
    size_t calls;
    size_t fail_at;
} alloc_state_t;

static void free_fn_only(void *ctx, void *ptr);

static const unsigned char payload[] = {0xa1, 0x01, 0x80, 0x80, 0x7f, 0x7f, 0x00, 0x08, 0x01};

static void put_bytes(builder_t *b, const void *data, size_t len)
{
    CHECK(membuf_write(&b->buf, data, len) == 0);
}

static void put_uint(builder_t *b, uint64_t value, size_t width)
{
    unsigned char out[8];
    size_t i;

    for (i = 0; i < width; i++)
        out[b->big ? width - 1 - i : i] = (unsigned char)(value >> (8 * i));
    put_bytes(b, out, width);
}

static void put_pad(builder_t *b)
{
    static const unsigned char zeros[4] = {0};

    put_bytes(b, zeros, (4 - b->buf.len % 4) % 4);
}

static void put_option(builder_t *b, uint16_t code, const void *value, size_t len)
{
    put_uint(b, code, 2);
    put_uint(b, len, 2);
    put_bytes(b, value, len);
    put_pad(b);
}

static void put_block(builder_t *b, uint32_t type, const builder_t *body)
{
    size_t total = 12 + body->buf.len;

    CHECK(body->buf.len % 4 == 0);
    put_uint(b, type, 4);
    put_uint(b, total, 4);
    put_bytes(b, body->buf.data, body->buf.len);
    put_uint(b, total, 4);
}

static builder_t body_of(const builder_t *b)
{
    builder_t body = {{NULL, 0, 0}, b->big};

    return body;
}

static void put_shb(builder_t *b)
{
    builder_t body = body_of(b);

    put_uint(&body, 0x1A2B3C4D, 4);
    put_uint(&body, 1, 2);
    put_uint(&body, 0, 2);
    put_uint(&body, UINT64_MAX, 8);
    put_option(&body, PCW_OPT_SHB_USERAPPL, "test", 4);
    put_option(&body, PCW_OPT_END, NULL, 0);
    put_block(b, PCW_BLOCK_SHB, &body);
    free(body.buf.data);
}

static void put_idb(builder_t *b, uint32_t linktype, uint32_t snaplen, int with_options)
{
    static const unsigned char tsresol = 0x83;
    static const unsigned char unknown[3] = {1, 2, 3};
    builder_t body = body_of(b);
    builder_t offset = body_of(b);

    put_uint(&offset, 10, 8);
    put_uint(&body, linktype, 2);
    put_uint(&body, 0, 2);
    put_uint(&body, snaplen, 4);
    if (with_options) {
        put_option(&body, PCW_OPT_IF_NAME, "usb0", 4);
        put_option(&body, PCW_OPT_IF_TSRESOL, &tsresol, 1);
        put_option(&body, PCW_OPT_IF_TSOFFSET, offset.buf.data, 8);
        put_option(&body, 0x8001, unknown, sizeof(unknown));
        put_option(&body, PCW_OPT_END, NULL, 0);
    }
    put_block(b, PCW_BLOCK_IDB, &body);
    free(body.buf.data);
    free(offset.buf.data);
}

static void put_epb(builder_t *b, uint32_t interface_id, uint64_t units, size_t caplen, uint32_t orig_len)
{
    static const unsigned char hash[5] = {2, 0xde, 0xad, 0xbe, 0xef};
    builder_t body = body_of(b);
    builder_t flags = body_of(b);

    put_uint(&flags, 1, 4);
    put_uint(&body, interface_id, 4);
    put_uint(&body, units >> 32, 4);
    put_uint(&body, units & 0xFFFFFFFFu, 4);
    put_uint(&body, caplen, 4);
    put_uint(&body, orig_len, 4);
    put_bytes(&body, payload, caplen);
    put_pad(&body);
    put_option(&body, PCW_OPT_COMMENT, "hi", 2);
    put_option(&body, PCW_OPT_EPB_FLAGS, flags.buf.data, 4);
    put_option(&body, PCW_OPT_EPB_HASH, hash, sizeof(hash));
    put_option(&body, 99, "zz", 2);
    put_option(&body, PCW_OPT_END, NULL, 0);
    put_block(b, PCW_BLOCK_EPB, &body);
    free(body.buf.data);
    free(flags.buf.data);
}

static void put_nrb(builder_t *b)
{
    static const unsigned char record[] = {192, 168, 0, 1, 'p', 'a', 'd', 0};
    builder_t body = body_of(b);

    put_option(&body, PCW_NAME_IPV4, record, sizeof(record));
    put_option(&body, PCW_NAME_END, NULL, 0);
    put_block(b, PCW_BLOCK_NRB, &body);
    free(body.buf.data);
}

static void put_spb(builder_t *b, uint32_t orig_len, size_t stored)
{
    builder_t body = body_of(b);

    put_uint(&body, orig_len, 4);
    put_bytes(&body, payload, stored);
    put_pad(&body);
    put_block(b, PCW_BLOCK_SPB, &body);
    free(body.buf.data);
}

static void put_custom(builder_t *b)
{
    builder_t body = body_of(b);

    put_uint(&body, 0xDEADBEEF, 4);
    put_block(b, 0x00000BAD, &body);
    free(body.buf.data);
}

static builder_t crafted_pcapng(int big)
{
    builder_t b = {{NULL, 0, 0}, big};

    put_shb(&b);
    put_idb(&b, PCW_LINKTYPE_USBPCAP, 0, 1);
    put_epb(&b, 0, 12, 5, 7);
    put_nrb(&b);
    put_custom(&b);
    put_idb(&b, PCW_LINKTYPE_BLUETOOTH_HCI_H4, 4, 0);
    put_spb(&b, 9, sizeof(payload));
    return b;
}

static void check_epb_options(const pcw_block_t *block)
{
    const unsigned char *value;
    size_t len;
    size_t pos = 0;
    uint16_t code;
    int count = 0;

    CHECK_STATUS(pcw_option_find(block, PCW_OPT_COMMENT, &value, &len), PCW_OK);
    CHECK(len == 2 && memcmp(value, "hi", 2) == 0);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_FLAGS, &value, &len), PCW_OK);
    CHECK(len == 4 && pcw_get_u32(block, value) == 1);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_HASH, &value, &len), PCW_OK);
    CHECK(len == 5 && value[0] == 2 && value[4] == 0xef);
    CHECK_STATUS(pcw_option_find(block, 99, &value, &len), PCW_OK);
    CHECK_STATUS(pcw_option_find(block, 77, &value, &len), PCW_END);
    while (pcw_option_next(block, &pos, &code, &value, &len) == PCW_OK)
        count++;
    CHECK(count == 4);
}

static void check_interface(const pcw_block_t *block)
{
    const unsigned char *value;
    size_t len;

    CHECK(block->kind == PCW_KIND_INTERFACE);
    CHECK(block->linktype == PCW_LINKTYPE_USBPCAP && block->ts_resol == 0x83 && block->ts_offset == 10);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_IF_NAME, &value, &len), PCW_OK);
    CHECK(len == 4 && memcmp(value, "usb0", 4) == 0);
    CHECK_STATUS(pcw_option_find(block, 0x8001, &value, &len), PCW_OK);
    CHECK(len == 3 && value[2] == 3);
}

static void check_names(const pcw_block_t *block)
{
    const unsigned char *value;
    size_t len;
    size_t pos = 0;
    uint16_t type;

    CHECK(block->kind == PCW_KIND_NAMES);
    CHECK_STATUS(pcw_name_next(block, &pos, &type, &value, &len), PCW_OK);
    CHECK(type == PCW_NAME_IPV4 && len == 8 && value[0] == 192 && strcmp((const char *)value + 4, "pad") == 0);
    CHECK_STATUS(pcw_name_next(block, &pos, &type, &value, &len), PCW_END);
}

static void check_crafted_blocks(pcw_reader_t *reader, int big)
{
    const pcw_block_t *block;

    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_SECTION && block->version_major == 1 && block->section_len == -1);
    CHECK(((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == big);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    check_interface(block);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_PACKET && block->type == PCW_BLOCK_EPB && block->linktype == PCW_LINKTYPE_USBPCAP);
    CHECK(block->ts_raw == 12 && block->ts_sec == 11 && block->ts_nsec == 500000000u);
    CHECK(block->data_len == 5 && block->orig_len == 7 && memcmp(block->data, payload, 5) == 0);
    check_epb_options(block);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    check_names(block);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_OTHER && block->type == 0x00000BAD && block->body_len == 4);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_INTERFACE && block->interface_id == 1 && block->ts_resol == PCW_TSRESOL_MICRO);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->type == PCW_BLOCK_SPB && (block->flags & PCW_FLAG_NO_TIMESTAMP) && block->interface_id == 0);
    CHECK(block->data_len == sizeof(payload) && block->orig_len == 9);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
}

static int next_packet(pcw_reader_t *reader, const pcw_block_t **out_block)
{
    int status;

    while ((status = pcw_reader_next(reader, out_block)) == PCW_OK && (*out_block)->kind != PCW_KIND_PACKET)
        ;
    return status;
}

static void compare_packets(const membuf_t *a, const membuf_t *b)
{
    pcw_reader_t *reader_a = open_mem_reader(a->data, a->len);
    pcw_reader_t *reader_b = open_mem_reader(b->data, b->len);
    const pcw_block_t *pa;
    const pcw_block_t *pb;
    int status;

    while ((status = next_packet(reader_a, &pa)) == PCW_OK) {
        CHECK_STATUS(next_packet(reader_b, &pb), PCW_OK);
        CHECK(pa->ts_sec == pb->ts_sec && pa->ts_nsec == pb->ts_nsec && pa->orig_len == pb->orig_len);
        CHECK(pa->linktype == pb->linktype && pa->interface_id == pb->interface_id);
        CHECK(same_bytes(pa->data, pa->data_len, pb->data, pb->data_len));
    }
    CHECK_STATUS(status, PCW_END);
    CHECK_STATUS(next_packet(reader_b, &pb), PCW_END);
    pcw_reader_destroy(reader_b);
    pcw_reader_destroy(reader_a);
}

static void test_invalid_interface(void)
{
    static const unsigned char bad_resol = 0x40;
    int big;

    for (big = 0; big <= 1; big++) {
        builder_t b = {{NULL, 0, 0}, big};
        builder_t idb = body_of(&b);
        pcw_reader_t *reader;
        const pcw_block_t *block;

        put_shb(&b);
        put_uint(&idb, PCW_LINKTYPE_ETHERNET, 2);
        put_uint(&idb, 0, 6);
        put_option(&idb, PCW_OPT_IF_TSRESOL, &bad_resol, 1);
        put_option(&idb, PCW_OPT_END, NULL, 0);
        put_block(&b, PCW_BLOCK_IDB, &idb);
        put_idb(&b, PCW_LINKTYPE_USER0, 0, 0);
        put_epb(&b, 0, 1, 2, 2);
        put_epb(&b, 1, 1, 2, 2);
        reader = open_mem_reader(b.buf.data, b.buf.len);
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_ERR_FORMAT);
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
        CHECK_STATUS(pcw_reader_error(reader), PCW_ERR_FORMAT);
        pcw_reader_destroy(reader);
        free(idb.buf.data);
        free(b.buf.data);
    }
}

static void test_pcapng_crafted(void)
{
    int big;

    for (big = 0; big <= 1; big++) {
        builder_t b = crafted_pcapng(big);
        pcw_reader_t *reader = open_mem_reader(b.buf.data, b.buf.len);
        membuf_t copy = {NULL, 0, 0};

        check_crafted_blocks(reader, big);
        pcw_reader_destroy(reader);
        copy_capture(b.buf.data, b.buf.len, PCW_FORMAT_PCAPNG, &copy);
        CHECK(same_bytes(copy.data, copy.len, b.buf.data, b.buf.len));
        compare_packets(&b.buf, &copy);
        free(copy.data);
        free(b.buf.data);
    }
}

static void write_simple(uint32_t format, uint32_t linktype, uint32_t ts_resol, membuf_t *out)
{
    static const pcw_option_t if_name = {PCW_OPT_IF_NAME, "hid0", 4};
    pcw_writer_t *writer = NULL;
    uint32_t iface = 99;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, format, membuf_write, out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, linktype, 65535, ts_resol, &if_name, 1, &iface), PCW_OK);
    CHECK(iface == 0);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1700000000, 123456789u, payload, sizeof(payload), sizeof(payload), NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1700000001, 999999999u, payload, 4, sizeof(payload), NULL, 0), PCW_OK);
    CHECK(pcw_writer_offset(writer) == out->len);
    pcw_writer_destroy(writer);
}

static void check_simple(const membuf_t *in, uint32_t linktype, uint32_t ts_resol)
{
    pcw_reader_t *reader = open_mem_reader(in->data, in->len);
    const pcw_block_t *block;
    uint32_t keep = ts_resol == PCW_TSRESOL_NANO ? 1 : 1000;

    do
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    while (block->kind != PCW_KIND_PACKET);
    CHECK(block->linktype == linktype && block->ts_resol == ts_resol);
    CHECK(block->ts_sec == 1700000000 && block->ts_nsec == 123456789u / keep * keep);
    CHECK(same_bytes(block->data, block->data_len, payload, sizeof(payload)));
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->ts_sec == 1700000001 && block->ts_nsec == 999999999u / keep * keep);
    CHECK(block->data_len == 4 && block->orig_len == sizeof(payload));
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK(pcw_reader_offset(reader) == in->len);
    pcw_reader_destroy(reader);
}

static void test_writer_roundtrip(void)
{
    static const uint32_t linktypes[] = {PCW_LINKTYPE_USER0, PCW_LINKTYPE_USER0 + 15, PCW_LINKTYPE_BLUETOOTH_HCI_H4, PCW_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR, PCW_LINKTYPE_USB_LINUX, PCW_LINKTYPE_USB_LINUX_MMAPPED, PCW_LINKTYPE_USBPCAP};
    static const uint32_t resols[] = {PCW_TSRESOL_MICRO, PCW_TSRESOL_NANO};
    uint32_t format;
    size_t l;
    size_t r;

    for (format = PCW_FORMAT_PCAP; format <= PCW_FORMAT_PCAPNG; format++) {
        for (l = 0; l < sizeof(linktypes) / sizeof(linktypes[0]); l++) {
            for (r = 0; r < 2; r++) {
                membuf_t out = {NULL, 0, 0};

                write_simple(format, linktypes[l], resols[r], &out);
                check_simple(&out, linktypes[l], resols[r]);
                free(out.data);
            }
        }
    }
}

static void test_conversion(void)
{
    membuf_t original = {NULL, 0, 0};
    membuf_t ng = {NULL, 0, 0};
    membuf_t back = {NULL, 0, 0};
    uint32_t resol;

    for (resol = PCW_TSRESOL_MICRO; resol <= PCW_TSRESOL_NANO; resol += 3) {
        write_simple(PCW_FORMAT_PCAP, PCW_LINKTYPE_USER0, resol, &original);
        copy_capture(original.data, original.len, PCW_FORMAT_PCAPNG, &ng);
        check_simple(&ng, PCW_LINKTYPE_USER0, resol);
        copy_capture(ng.data, ng.len, PCW_FORMAT_PCAP, &back);
        CHECK(same_bytes(original.data, original.len, back.data, back.len));
        free(original.data);
        free(ng.data);
        free(back.data);
        memset(&original, 0, sizeof(original));
        memset(&ng, 0, sizeof(ng));
        memset(&back, 0, sizeof(back));
    }
}

static builder_t big_endian_pcap(void)
{
    builder_t b = {{NULL, 0, 0}, 1};

    put_uint(&b, 0xA1B23C4D, 4);
    put_uint(&b, 2, 2);
    put_uint(&b, 4, 2);
    put_uint(&b, 0, 8);
    put_uint(&b, 262144, 4);
    put_uint(&b, 0x10000000u | PCW_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR, 4);
    put_uint(&b, 1600000000, 4);
    put_uint(&b, 42, 4);
    put_uint(&b, sizeof(payload), 4);
    put_uint(&b, sizeof(payload), 4);
    put_bytes(&b, payload, sizeof(payload));
    return b;
}

static void test_pcap_big_endian(void)
{
    builder_t b = big_endian_pcap();
    pcw_reader_t *reader = open_mem_reader(b.buf.data, b.buf.len);
    const pcw_block_t *block;
    membuf_t copy = {NULL, 0, 0};

    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_SECTION && block->format == PCW_FORMAT_PCAP && (block->flags & PCW_FLAG_BIG_ENDIAN));
    CHECK(block->linktype == PCW_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR && block->snaplen == 262144 && block->ts_resol == PCW_TSRESOL_NANO);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->ts_sec == 1600000000 && block->ts_nsec == 42 && block->data_len == sizeof(payload));
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
    b.buf.data[21] = 0x01;
    reader = open_mem_reader(b.buf.data, b.buf.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_ERR_FORMAT);
    pcw_reader_destroy(reader);
    b.buf.data[21] = 0x00;
    copy_capture(b.buf.data, b.buf.len, PCW_FORMAT_PCAP, &copy);
    CHECK(same_bytes(copy.data, copy.len, b.buf.data, b.buf.len));
    free(copy.data);
    free(b.buf.data);
}

static builder_t fcs_pcap(uint32_t linktype_field)
{
    builder_t b = {{NULL, 0, 0}, 0};

    put_uint(&b, 0xA1B2C3D4, 4);
    put_uint(&b, 2, 2);
    put_uint(&b, 4, 2);
    put_uint(&b, 0, 8);
    put_uint(&b, 65535, 4);
    put_uint(&b, linktype_field, 4);
    put_uint(&b, 1600000000, 4);
    put_uint(&b, 7, 4);
    put_uint(&b, sizeof(payload), 4);
    put_uint(&b, sizeof(payload), 4);
    put_bytes(&b, payload, sizeof(payload));
    return b;
}

static uint32_t first_fcs(const membuf_t *in, uint32_t kind)
{
    pcw_reader_t *reader = open_mem_reader(in->data, in->len);
    const pcw_block_t *block;
    uint32_t bits = UINT32_MAX;

    while (pcw_reader_next(reader, &block) == PCW_OK) {
        if (block->kind == kind) {
            CHECK(block->linktype == PCW_LINKTYPE_ETHERNET);
            if (pcw_block_fcs_len(block, &bits) != PCW_OK)
                bits = 0;
            break;
        }
    }
    pcw_reader_destroy(reader);
    return bits;
}

static void test_fcs(void)
{
    builder_t with = fcs_pcap(0x24000000u | PCW_LINKTYPE_ETHERNET);
    builder_t without = fcs_pcap(0x10000000u | PCW_LINKTYPE_ETHERNET);
    builder_t reserved = fcs_pcap(0x00010000u | PCW_LINKTYPE_ETHERNET);
    membuf_t ng = {NULL, 0, 0};
    membuf_t back = {NULL, 0, 0};
    pcw_reader_t *reader;
    const pcw_block_t *block;
    uint32_t bits;

    CHECK(first_fcs(&with.buf, PCW_KIND_SECTION) == 32);
    CHECK(first_fcs(&without.buf, PCW_KIND_SECTION) == 0);
    copy_capture(with.buf.data, with.buf.len, PCW_FORMAT_PCAPNG, &ng);
    CHECK(first_fcs(&ng, PCW_KIND_INTERFACE) == 32);
    copy_capture(ng.data, ng.len, PCW_FORMAT_PCAP, &back);
    CHECK(same_bytes(with.buf.data, with.buf.len, back.data, back.len));
    reader = open_mem_reader(reserved.buf.data, reserved.buf.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_ERR_FORMAT);
    pcw_reader_destroy(reader);
    CHECK_STATUS(pcw_block_fcs_len(NULL, &bits), PCW_ERR_ARG);
    free(with.buf.data);
    free(without.buf.data);
    free(reserved.buf.data);
    free(ng.data);
    free(back.data);
}

static void test_epb_fcs(void)
{
    static const unsigned char fcs_flags[4] = {0x80, 0, 0, 0};
    builder_t b = {{NULL, 0, 0}, 0};
    builder_t body = body_of(&b);
    pcw_reader_t *reader;
    const pcw_block_t *block;
    uint32_t bits = 0;

    put_shb(&b);
    put_idb(&b, PCW_LINKTYPE_ETHERNET, 0, 0);
    put_epb(&b, 0, 1, 2, 2);
    put_uint(&body, 0, 4);
    put_uint(&body, 0, 8);
    put_uint(&body, 0, 8);
    put_option(&body, PCW_OPT_EPB_FLAGS, fcs_flags, sizeof(fcs_flags));
    put_option(&body, PCW_OPT_END, NULL, 0);
    put_block(&b, PCW_BLOCK_EPB, &body);
    reader = open_mem_reader(b.buf.data, b.buf.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_block_fcs_len(block, &bits), PCW_END);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_block_fcs_len(block, &bits), PCW_END);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_block_fcs_len(block, &bits), PCW_OK);
    CHECK(bits == 32);
    pcw_reader_destroy(reader);
    free(body.buf.data);
    free(b.buf.data);
}

static void write_with_options(pcw_writer_t *writer)
{
    static const unsigned char fcs = 32;
    static const char comment[] = "left stick";
    uint64_t speed = 12000000;
    uint32_t flags = PCW_EPB_INBOUND;
    uint64_t packet_id = 0x0102030405060708u;
    uint32_t process_thread[2] = {4242, 7};
    pcw_option_t iface_opts[4];
    pcw_option_t packet_opts[4];
    uint32_t iface = 99;

    iface_opts[0].code = PCW_OPT_IF_NAME;
    iface_opts[0].value = "hid0";
    iface_opts[0].value_len = 4;
    iface_opts[1].code = PCW_OPT_IF_DESCRIPTION;
    iface_opts[1].value = "gamepad";
    iface_opts[1].value_len = 7;
    iface_opts[2].code = PCW_OPT_IF_SPEED;
    iface_opts[2].value = &speed;
    iface_opts[2].value_len = sizeof(speed);
    iface_opts[3].code = PCW_OPT_IF_FCSLEN;
    iface_opts[3].value = &fcs;
    iface_opts[3].value_len = 1;
    packet_opts[0].code = PCW_OPT_EPB_FLAGS;
    packet_opts[0].value = &flags;
    packet_opts[0].value_len = sizeof(flags);
    packet_opts[1].code = PCW_OPT_COMMENT;
    packet_opts[1].value = comment;
    packet_opts[1].value_len = sizeof(comment) - 1;
    packet_opts[2].code = PCW_OPT_EPB_PACKETID;
    packet_opts[2].value = &packet_id;
    packet_opts[2].value_len = sizeof(packet_id);
    packet_opts[3].code = PCW_OPT_EPB_PROCESSID_THREADID;
    packet_opts[3].value = process_thread;
    packet_opts[3].value_len = sizeof(process_thread);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_ETHERNET, 0, PCW_TSRESOL_NANO, iface_opts, 4, &iface), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, iface, 1, 2, payload, sizeof(payload), sizeof(payload), packet_opts, 4), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, iface, 1, 3, payload, sizeof(payload), sizeof(payload), NULL, 0), PCW_OK);
}

static int option_is(const pcw_block_t *block, uint16_t code, const void *value, size_t value_len)
{
    const unsigned char *found;
    size_t found_len;

    return pcw_option_find(block, code, &found, &found_len) == PCW_OK && found_len == value_len && memcmp(found, value, value_len) == 0;
}

static void check_with_options(const membuf_t *in, int big)
{
    pcw_reader_t *reader = open_mem_reader(in->data, in->len);
    const pcw_block_t *block;
    const unsigned char *value;
    size_t value_len;
    uint32_t bits = 0;

    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == big);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_INTERFACE && block->ts_resol == PCW_TSRESOL_NANO);
    CHECK(option_is(block, PCW_OPT_IF_NAME, "hid0", 4) && option_is(block, PCW_OPT_IF_DESCRIPTION, "gamepad", 7));
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_IF_SPEED, &value, &value_len), PCW_OK);
    CHECK(value_len == 8 && pcw_get_u64(block, value) == 12000000);
    CHECK_STATUS(pcw_block_fcs_len(block, &bits), PCW_OK);
    CHECK(bits == 32);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_PACKET && block->ts_sec == 1 && block->ts_nsec == 2);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_FLAGS, &value, &value_len), PCW_OK);
    CHECK(value_len == 4 && pcw_get_u32(block, value) == PCW_EPB_INBOUND);
    CHECK(option_is(block, PCW_OPT_COMMENT, "left stick", 10));
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_PACKETID, &value, &value_len), PCW_OK);
    CHECK(value_len == 8 && pcw_get_u64(block, value) == 0x0102030405060708u);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_PROCESSID_THREADID, &value, &value_len), PCW_OK);
    CHECK(value_len == 8 && pcw_get_u32(block, value) == 4242 && pcw_get_u32(block, value + 4) == 7);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->options_len == 0);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
}

static void test_writer_options(void)
{
    membuf_t out = {NULL, 0, 0};
    builder_t b = {{NULL, 0, 0}, 1};
    pcw_reader_t *reader;
    pcw_writer_t *writer = NULL;
    const pcw_block_t *block;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    write_with_options(writer);
    pcw_writer_destroy(writer);
    check_with_options(&out, (*(const unsigned char *)&(uint16_t){1}) == 0);
    free(out.data);
    memset(&out, 0, sizeof(out));
    put_shb(&b);
    reader = open_mem_reader(b.buf.data, b.buf.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_block(writer, block), PCW_OK);
    write_with_options(writer);
    pcw_writer_destroy(writer);
    pcw_reader_destroy(reader);
    check_with_options(&out, 1);
    free(out.data);
    free(b.buf.data);
}

static void test_writer_options_pcap(void)
{
    static const unsigned char fcs = 32;
    pcw_option_t opts[2] = {{PCW_OPT_IF_NAME, "eth0", 4}, {PCW_OPT_IF_FCSLEN, &fcs, 1}};
    pcw_option_t comment = {PCW_OPT_COMMENT, "dropped", 7};
    membuf_t out = {NULL, 0, 0};
    pcw_writer_t *writer = NULL;
    uint32_t bits = 0;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAP, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_ETHERNET, 0, PCW_TSRESOL_MICRO, opts, 2, NULL), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1, 0, payload, sizeof(payload), sizeof(payload), &comment, 1), PCW_OK);
    pcw_writer_destroy(writer);
    CHECK(out.len == 24 + 16 + sizeof(payload));
    {
        pcw_reader_t *reader = open_mem_reader(out.data, out.len);
        const pcw_block_t *block;

        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
        CHECK_STATUS(pcw_block_fcs_len(block, &bits), PCW_OK);
        CHECK(bits == 32 && block->linktype == PCW_LINKTYPE_ETHERNET);
        pcw_reader_destroy(reader);
    }
    free(out.data);
}

static void test_writer_bad_options(void)
{
    static const unsigned char one = 6;
    uint32_t flags = 0;
    pcw_option_t bad[] = {
        {PCW_OPT_END, NULL, 0},
        {PCW_OPT_IF_TSRESOL, &one, 1},
        {PCW_OPT_IF_TSOFFSET, &flags, 8},
        {PCW_OPT_IF_FCSLEN, &flags, 4},
        {PCW_OPT_IF_NAME, NULL, 3},
        {PCW_OPT_IF_NAME, payload, 70000},
    };
    pcw_option_t bad_packet[] = {
        {PCW_OPT_END, NULL, 0},
        {PCW_OPT_EPB_FLAGS, &flags, 2},
        {PCW_OPT_EPB_PACKETID, &flags, 4},
        {PCW_OPT_COMMENT, NULL, 1},
    };
    membuf_t out = {NULL, 0, 0};
    pcw_writer_t *writer = NULL;
    size_t written;
    size_t i;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, &bad[i], 1, NULL), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 1, NULL), PCW_ERR_ARG);
    CHECK(out.len == 0);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_OK);
    written = out.len;
    for (i = 0; i < sizeof(bad_packet) / sizeof(bad_packet[0]); i++)
        CHECK_STATUS(pcw_writer_packet(writer, 0, 1, 0, payload, 1, 1, &bad_packet[i], 1), PCW_ERR_ARG);
    CHECK(out.len == written);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1, 0, payload, 1, 1, &bad[1], 1), PCW_OK);
    pcw_writer_destroy(writer);
    free(out.data);
}

static void put_numbers_option(builder_t *body, uint16_t code, uint64_t first, size_t first_width, uint64_t second, size_t second_width, const char *text)
{
    builder_t value = body_of(body);

    put_uint(&value, first, first_width);
    if (second_width > 0)
        put_uint(&value, second, second_width);
    if (text != NULL)
        put_bytes(&value, text, strlen(text));
    put_option(body, code, value.buf.data, value.buf.len);
    free(value.buf.data);
}

static builder_t big_endian_extras(void)
{
    builder_t b = {{NULL, 0, 0}, 1};
    builder_t idb = body_of(&b);
    builder_t epb = body_of(&b);
    builder_t isb = body_of(&b);

    put_shb(&b);
    put_uint(&idb, PCW_LINKTYPE_USER0, 2);
    put_uint(&idb, 0, 6);
    put_numbers_option(&idb, 2988, 0x7ED9, 4, 0, 0, "hi");
    put_numbers_option(&idb, PCW_OPT_IF_SPEED, 12000000, 8, 0, 0, NULL);
    put_option(&idb, PCW_OPT_END, NULL, 0);
    put_block(&b, PCW_BLOCK_IDB, &idb);
    put_uint(&epb, 0, 4);
    put_uint(&epb, 0, 4);
    put_uint(&epb, 5, 4);
    put_uint(&epb, 1, 4);
    put_uint(&epb, 1, 4);
    put_bytes(&epb, payload, 1);
    put_pad(&epb);
    put_numbers_option(&epb, PCW_OPT_EPB_FLAGS, PCW_EPB_OUTBOUND, 4, 0, 0, NULL);
    put_numbers_option(&epb, 7, 2, 1, 0, 0, NULL);
    put_option(&epb, PCW_OPT_END, NULL, 0);
    put_block(&b, PCW_BLOCK_EPB, &epb);
    put_uint(&isb, 0, 4);
    put_uint(&isb, 0, 4);
    put_uint(&isb, 9, 4);
    put_numbers_option(&isb, 2, 0, 4, 3, 4, NULL);
    put_numbers_option(&isb, 4, 77, 8, 0, 0, NULL);
    put_option(&isb, PCW_OPT_END, NULL, 0);
    put_block(&b, PCW_BLOCK_ISB, &isb);
    free(idb.buf.data);
    free(epb.buf.data);
    free(isb.buf.data);
    return b;
}

static void check_converted_extras(const membuf_t *out)
{
    static const unsigned char custom[6] = {0xD9, 0x7E, 0, 0, 'h', 'i'};
    pcw_reader_t *reader = open_mem_reader(out->data, out->len);
    const pcw_block_t *block;
    const unsigned char *value;
    size_t value_len;

    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(!(block->flags & PCW_FLAG_BIG_ENDIAN));
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_INTERFACE && option_is(block, 2988, custom, sizeof(custom)));
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_IF_SPEED, &value, &value_len), PCW_OK);
    CHECK(pcw_get_u64(block, value) == 12000000);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_PACKET && block->ts_nsec == 5000 && block->data_len == 1);
    CHECK_STATUS(pcw_option_find(block, PCW_OPT_EPB_FLAGS, &value, &value_len), PCW_OK);
    CHECK(pcw_get_u32(block, value) == PCW_EPB_OUTBOUND);
    CHECK_STATUS(pcw_option_find(block, 7, &value, &value_len), PCW_END);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_STATS && block->ts_nsec == 9000);
    CHECK_STATUS(pcw_option_find(block, 2, &value, &value_len), PCW_OK);
    CHECK(value_len == 8 && pcw_get_u32(block, value) == 0 && pcw_get_u32(block, value + 4) == 3);
    CHECK_STATUS(pcw_option_find(block, 4, &value, &value_len), PCW_OK);
    CHECK(pcw_get_u64(block, value) == 77);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
}

static void write_two_sections(membuf_t *out)
{
    pcw_option_t first[2] = {{PCW_OPT_SHB_USERAPPL, "wirefile test", 13}, {PCW_OPT_SHB_OS, "Linux", 5}};
    pcw_option_t second = {PCW_OPT_COMMENT, "second", 6};
    pcw_writer_t *writer = NULL;
    uint32_t id;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, out), PCW_OK);
    CHECK_STATUS(pcw_writer_section(writer, first, 2), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, NULL, 0, &id), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, id, 1, 0, payload, 3, 3, NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_section(writer, &second, 1), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, id, 2, 0, payload, 3, 3, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0 + 1, 0, PCW_TSRESOL_MICRO, NULL, 0, &id), PCW_OK);
    CHECK(id == 0);
    CHECK_STATUS(pcw_writer_packet(writer, id, 2, 0, payload, 3, 3, NULL, 0), PCW_OK);
    pcw_writer_destroy(writer);
}

static void test_writer_units(void)
{
    membuf_t out = {NULL, 0, 0};
    pcw_writer_t *writer = NULL;
    pcw_reader_t *reader;
    const pcw_block_t *block;
    uint32_t pico;
    uint32_t binary;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, 12, NULL, 0, &pico), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, 0x80u | 40u, NULL, 0, &binary), PCW_OK);
    CHECK_STATUS(pcw_writer_packet_units(writer, pico, 1000000000123ull, payload, 3, 3, NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_packet_units(writer, binary, (3ull << 40) + 1, payload, 3, 3, NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_packet_units(writer, 2, 1, payload, 3, 3, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_packet_units(writer, pico, 1, payload, 3, 2, NULL, 0), PCW_ERR_ARG);
    pcw_writer_destroy(writer);
    reader = open_mem_reader(out.data, out.len);
    while (pcw_reader_next(reader, &block) == PCW_OK && block->kind != PCW_KIND_PACKET)
        continue;
    CHECK(block->ts_raw == 1000000000123ull && block->ts_sec == 1 && block->ts_nsec == 0 && block->ts_resol == 12);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->ts_raw == (3ull << 40) + 1 && block->ts_sec == 3 && block->interface_id == binary);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
    free(out.data);
    out = (membuf_t){NULL, 0, 0};
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAP, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 0, &pico), PCW_OK);
    CHECK_STATUS(pcw_writer_packet_units(writer, pico, 1500000, payload, 3, 3, NULL, 0), PCW_OK);
    pcw_writer_destroy(writer);
    reader = open_mem_reader(out.data, out.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->ts_sec == 1 && block->ts_nsec == 500000000);
    pcw_reader_destroy(reader);
    free(out.data);
}

static void test_writer_sections(void)
{
    static const uint32_t kinds[] = {PCW_KIND_SECTION, PCW_KIND_INTERFACE, PCW_KIND_PACKET, PCW_KIND_SECTION, PCW_KIND_INTERFACE, PCW_KIND_PACKET};
    membuf_t out = {NULL, 0, 0};
    pcw_reader_t *reader;
    const pcw_block_t *block;
    pcw_writer_t *pcap = NULL;
    size_t i;

    write_two_sections(&out);
    reader = open_mem_reader(out.data, out.len);
    for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
        CHECK(block->kind == kinds[i] && block->section == (i < 3 ? 0u : 1u));
        if (i == 0)
            CHECK(option_is(block, PCW_OPT_SHB_USERAPPL, "wirefile test", 13) && option_is(block, PCW_OPT_SHB_OS, "Linux", 5));
        if (i == 3)
            CHECK(option_is(block, PCW_OPT_COMMENT, "second", 6));
        if (i == 5)
            CHECK(block->linktype == PCW_LINKTYPE_USER0 + 1 && block->ts_sec == 2);
    }
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
    free(out.data);
    out = (membuf_t){NULL, 0, 0};
    CHECK_STATUS(pcw_writer_section(NULL, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &pcap), PCW_OK);
    CHECK_STATUS(pcw_writer_section(pcap, NULL, 0), PCW_ERR_STATE);
    CHECK_STATUS(pcw_writer_open(pcap, PCW_FORMAT_PCAP, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_section(pcap, NULL, 0), PCW_ERR_ARG);
    pcw_writer_destroy(pcap);
    CHECK(out.len == 0);
    free(out.data);
}

static void test_cross_order_copy(void)
{
    builder_t source = big_endian_extras();
    builder_t section = {{NULL, 0, 0}, 0};
    pcw_reader_t *section_reader;
    pcw_reader_t *reader;
    pcw_writer_t *writer = NULL;
    const pcw_block_t *block;
    membuf_t out = {NULL, 0, 0};

    put_shb(&section);
    section_reader = open_mem_reader(section.buf.data, section.buf.len);
    CHECK_STATUS(pcw_reader_next(section_reader, &block), PCW_OK);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_block(writer, block), PCW_OK);
    reader = open_mem_reader(source.buf.data, source.buf.len);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    while (pcw_reader_next(reader, &block) == PCW_OK)
        CHECK_STATUS(pcw_writer_block(writer, block), PCW_OK);
    pcw_writer_destroy(writer);
    pcw_reader_destroy(reader);
    pcw_reader_destroy(section_reader);
    check_converted_extras(&out);
    free(out.data);
    free(source.buf.data);
    free(section.buf.data);
}

static void expect_truncated(const membuf_t *in, size_t cut, size_t data_len, size_t trailing)
{
    pcw_reader_t *reader = open_mem_reader(in->data, in->len - cut);
    const pcw_block_t *block;
    int packets = 0;
    int status;

    while ((status = pcw_reader_next(reader, &block)) == PCW_OK) {
        if (block->kind != PCW_KIND_PACKET)
            continue;
        packets++;
        if (block->flags & PCW_FLAG_TRUNCATED)
            CHECK(block->data_len == data_len && block->orig_len == sizeof(payload));
    }
    CHECK_STATUS(status, PCW_END);
    CHECK(packets == (data_len > 0 ? 2 : 1));
    CHECK(pcw_reader_trailing(reader) == trailing);
    pcw_reader_destroy(reader);
}

static void test_truncated(void)
{
    membuf_t pcap = {NULL, 0, 0};
    membuf_t ng = {NULL, 0, 0};

    write_simple(PCW_FORMAT_PCAP, PCW_LINKTYPE_USER0, PCW_TSRESOL_NANO, &pcap);
    expect_truncated(&pcap, 2, 2, 0);
    expect_truncated(&pcap, 4 + 16 - 5, 0, 5);
    write_simple(PCW_FORMAT_PCAPNG, PCW_LINKTYPE_USER0, PCW_TSRESOL_NANO, &ng);
    expect_truncated(&ng, 4 + 1, 3, 0);
    expect_truncated(&ng, 4 + 4 + 1, 0, 36 - 9);
    free(pcap.data);
    free(ng.data);
}

static void expect_open_error(const unsigned char *data, size_t len, int expected)
{
    pcw_reader_t *reader = open_mem_reader(data, len);
    const pcw_block_t *block;

    CHECK_STATUS(pcw_reader_next(reader, &block), expected);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK_STATUS(pcw_reader_error(reader), expected);
    pcw_reader_destroy(reader);
}

static void test_reader_error(void)
{
    membuf_t out = {NULL, 0, 0};
    pcw_reader_t *reader;
    const pcw_block_t *block;
    int status;

    CHECK_STATUS(pcw_reader_error(NULL), PCW_ERR_ARG);
    write_simple(PCW_FORMAT_PCAPNG, PCW_LINKTYPE_USER0, PCW_TSRESOL_NANO, &out);
    reader = open_mem_reader(out.data, out.len - 1);
    CHECK_STATUS(pcw_reader_error(reader), PCW_OK);
    while ((status = pcw_reader_next(reader, &block)) == PCW_OK)
        continue;
    CHECK_STATUS(status, PCW_END);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK_STATUS(pcw_reader_error(reader), PCW_OK);
    pcw_reader_destroy(reader);
    free(out.data);
}

static void test_bad_input(void)
{
    builder_t b = crafted_pcapng(0);
    unsigned char junk[64];

    memset(junk, 0x55, sizeof(junk));
    expect_open_error(junk, 0, PCW_ERR_FORMAT);
    expect_open_error(junk, 3, PCW_ERR_FORMAT);
    expect_open_error(junk, sizeof(junk), PCW_ERR_FORMAT);
    b.buf.data[12] = 2;
    expect_open_error(b.buf.data, b.buf.len, PCW_ERR_FORMAT);
    b.buf.data[12] = 1;
    b.buf.data[b.buf.len - 1] ^= 0x40;
    {
        pcw_reader_t *reader = open_mem_reader(b.buf.data, b.buf.len);
        const pcw_block_t *block;
        int status;

        while ((status = pcw_reader_next(reader, &block)) == PCW_OK)
            ;
        CHECK_STATUS(status, PCW_ERR_FORMAT);
        pcw_reader_destroy(reader);
    }
    free(b.buf.data);
}

static int failing_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    (void)ctx;
    (void)buf;
    *out_read = buf_len + 1;
    return 0;
}

static int erroring_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    (void)ctx;
    (void)buf;
    (void)buf_len;
    *out_read = 0;
    return -1;
}

static void expect_stream_status(pcw_read_fn read_fn, int expected)
{
    pcw_reader_t *reader = NULL;
    const pcw_block_t *block;

    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, &reader), PCW_OK);
    CHECK_STATUS(pcw_reader_open_stream(reader, read_fn, NULL), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), expected);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK_STATUS(pcw_reader_error(reader), expected);
    pcw_reader_destroy(reader);
}

static void test_read_callback_errors(void)
{
    expect_stream_status(failing_read, PCW_ERR_IO);
    expect_stream_status(erroring_read, PCW_ERR_IO);
}

static pcw_reader_t *open_stream_reader(source_t *src, size_t max_block_len, uint32_t max_interfaces)
{
    pcw_reader_t *reader = NULL;

    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, &reader), PCW_OK);
    CHECK_STATUS(pcw_reader_set_limits(reader, max_block_len, max_interfaces), PCW_OK);
    CHECK_STATUS(pcw_reader_open_stream(reader, source_read, src), PCW_OK);
    CHECK_STATUS(pcw_reader_set_limits(reader, max_block_len, max_interfaces), PCW_ERR_STATE);
    return reader;
}

static void write_with_big_packet(uint32_t format, membuf_t *out)
{
    static unsigned char big[300];
    pcw_writer_t *writer = NULL;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, format, membuf_write, out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0 + 1, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1, 0, payload, 3, 3, NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 2, 0, big, sizeof(big), sizeof(big), NULL, 0), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 3, 0, payload, 3, 3, NULL, 0), PCW_OK);
    pcw_writer_destroy(writer);
}

static void test_limit_at_end(void)
{
    uint32_t format;

    for (format = PCW_FORMAT_PCAP; format <= PCW_FORMAT_PCAPNG; format++) {
        membuf_t out = {NULL, 0, 0};
        source_t src;
        pcw_reader_t *reader;
        const pcw_block_t *block;
        int status;

        write_with_big_packet(format, &out);
        src = (source_t){out.data, out.len - 200, 0, 7};
        reader = open_stream_reader(&src, 64, 4);
        while ((status = pcw_reader_next(reader, &block)) == PCW_OK)
            continue;
        CHECK_STATUS(status, PCW_END);
        CHECK(pcw_reader_trailing(reader) > 0);
        pcw_reader_destroy(reader);
        free(out.data);
    }
}

static void test_limits(void)
{
    uint32_t format;

    for (format = PCW_FORMAT_PCAP; format <= PCW_FORMAT_PCAPNG; format++) {
        membuf_t out = {NULL, 0, 0};
        source_t src;
        pcw_reader_t *reader;
        const pcw_block_t *block;
        int64_t secs[2];
        int n = 0;
        int limits = 0;
        int status;

        write_with_big_packet(format, &out);
        src = (source_t){out.data, out.len, 0, 1};
        reader = open_stream_reader(&src, 64, 4);
        while ((status = pcw_reader_next(reader, &block)) != PCW_END) {
            if (status == PCW_ERR_LIMIT)
                limits++;
            else if (block->kind == PCW_KIND_PACKET)
                secs[n++] = block->ts_sec;
        }
        CHECK(limits == 1 && n == 2 && secs[0] == 1 && secs[1] == 3);
        pcw_reader_destroy(reader);
        free(out.data);
    }
}

static void test_huge_lengths(void)
{
    static const unsigned char file[24 + 16 + 4] = {
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff, 4, 0, 0, 0, 1, 2, 3, 4,
    };
    source_t src = {file, sizeof(file), 0, 3};
    pcw_reader_t *reader = open_mem_reader(file, sizeof(file));
    pcw_writer_t *writer = NULL;
    membuf_t out = {NULL, 0, 0};
    const pcw_block_t *block;
    size_t written;

    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK(block->kind == PCW_KIND_PACKET && block->data_len == 4 && (block->flags & PCW_FLAG_TRUNCATED));
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
    reader = open_stream_reader(&src, 64, 4);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    pcw_reader_destroy(reader);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_OK);
    written = out.len;
    CHECK_STATUS(pcw_writer_packet(writer, 0, 1, 0, payload, 0xfffffff0u, 0xfffffff0u, NULL, 0), PCW_ERR_ARG);
    CHECK(out.len == written);
    pcw_writer_destroy(writer);
    free(out.data);
}

static void test_interface_limit(void)
{
    builder_t b = crafted_pcapng(0);
    source_t src = {b.buf.data, b.buf.len, 0, 0};
    pcw_reader_t *reader = open_stream_reader(&src, 4096, 1);
    const pcw_block_t *block;
    int status;

    while ((status = pcw_reader_next(reader, &block)) == PCW_OK)
        ;
    CHECK_STATUS(status, PCW_ERR_LIMIT);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK_STATUS(pcw_reader_error(reader), PCW_ERR_LIMIT);
    pcw_reader_destroy(reader);
    free(b.buf.data);
}

static int failing_write(void *ctx, const unsigned char *data, size_t data_len)
{
    (void)ctx;
    (void)data;
    (void)data_len;
    return -1;
}

static void test_writer_errors(void)
{
    pcw_writer_t *writer = NULL;
    membuf_t out = {NULL, 0, 0};

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 0, 0, payload, 1, 1, NULL, 0), PCW_ERR_STATE);
    CHECK_STATUS(pcw_writer_open(writer, 7, membuf_write, &out), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAP, membuf_write, &out), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAP, membuf_write, &out), PCW_ERR_STATE);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, 3, NULL, 0, NULL), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_add_interface(writer, 0x10000u | PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_ERR_ARG);
    CHECK(out.len == 0);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0 + 1, 0, PCW_TSRESOL_MICRO, NULL, 0, NULL), PCW_ERR_STATE);
    CHECK_STATUS(pcw_writer_packet(writer, 1, 0, 0, payload, 1, 1, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 0, 0, payload, 2, 1, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_packet(writer, 0, -1, 0, payload, 1, 1, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_packet(writer, 0, (int64_t)UINT32_MAX + 1, 0, payload, 1, 1, NULL, 0), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 0, 0, NULL, 1, 1, NULL, 0), PCW_ERR_ARG);
    pcw_writer_destroy(writer);
    free(out.data);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, failing_write, NULL), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, NULL, 0, NULL), PCW_ERR_IO);
    CHECK_STATUS(pcw_writer_packet(writer, 0, 0, 0, payload, 1, 1, NULL, 0), PCW_ERR_IO);
    pcw_writer_destroy(writer);
}

static void test_arguments(void)
{
    pcw_reader_t *reader = NULL;
    const pcw_block_t *block;
    int status;

    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, NULL), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_create(NULL, free_fn_only, NULL, &reader), PCW_ERR_ARG);
    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, NULL), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_next(NULL, &block), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, &reader), PCW_OK);
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_ERR_STATE);
    CHECK_STATUS(pcw_reader_set_limits(reader, 10, 1), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_open_mem(reader, NULL, 4), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_open_stream(reader, NULL, NULL), PCW_ERR_ARG);
    CHECK_STATUS(pcw_reader_open_mem(reader, payload, sizeof(payload)), PCW_OK);
    CHECK_STATUS(pcw_reader_open_mem(reader, payload, sizeof(payload)), PCW_ERR_STATE);
    CHECK_STATUS(pcw_reader_next(reader, NULL), PCW_ERR_ARG);
    status = pcw_option_find(NULL, 1, NULL, NULL);
    CHECK_STATUS(status, PCW_ERR_ARG);
    pcw_reader_destroy(reader);
    pcw_reader_destroy(NULL);
    pcw_writer_destroy(NULL);
    CHECK(pcw_reader_offset(NULL) == 0 && pcw_reader_trailing(NULL) == 0 && pcw_writer_offset(NULL) == 0);
}

static void test_strerror(void)
{
    int status;

    for (status = PCW_ERR_STATE; status <= PCW_END; status++)
        CHECK(pcw_strerror(status) != NULL && pcw_strerror(status)[0] != '\0');
    CHECK(strcmp(pcw_strerror(-100), pcw_strerror(100)) == 0);
}

static void *counting_alloc(void *ctx, size_t size)
{
    alloc_state_t *state = ctx;

    if (state->calls++ == state->fail_at)
        return NULL;
    state->live++;
    return malloc(size);
}

static void counting_free(void *ctx, void *ptr)
{
    alloc_state_t *state = ctx;

    if (ptr == NULL)
        return;
    state->live--;
    free(ptr);
}

static void free_fn_only(void *ctx, void *ptr)
{
    (void)ctx;
    (void)ptr;
}

typedef struct {
    membuf_t out;
    int calls;
    int whole;
} block_sink_t;

static int block_sink_write(void *ctx, const unsigned char *data, size_t data_len)
{
    block_sink_t *sink = ctx;

    sink->calls++;
    sink->whole += data_len >= 12 && memcmp(data + 4, data + data_len - 4, 4) == 0 && (pcw_get_u32(NULL, data + 4) == data_len || data[4] == 0);
    return membuf_write(&sink->out, data, data_len);
}

static void test_block_writes(void)
{
    static unsigned char big[3000];
    block_sink_t sink = {{NULL, 0, 0}, 0, 0};
    pcw_option_t comment = {PCW_OPT_COMMENT, "one call", 8};
    pcw_writer_t *writer = NULL;
    uint32_t id;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, block_sink_write, &sink), PCW_OK);
    CHECK_STATUS(pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, NULL, 0, &id), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, id, 1, 0, payload, 3, 3, &comment, 1), PCW_OK);
    CHECK_STATUS(pcw_writer_packet(writer, id, 2, 0, big, sizeof(big), sizeof(big), NULL, 0), PCW_OK);
    CHECK(pcw_writer_offset(writer) == sink.out.len);
    pcw_writer_destroy(writer);
    CHECK(sink.calls == 4 && sink.whole == 4);
    free(sink.out.data);
}

static int alloc_write(alloc_state_t *state, membuf_t *out)
{
    static const pcw_option_t if_name = {PCW_OPT_IF_NAME, "hid", 3};
    pcw_writer_t *writer = NULL;
    int status = pcw_writer_create(counting_alloc, counting_free, state, &writer);
    uint32_t i;

    if (status == PCW_OK)
        status = pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, out);
    for (i = 0; i < 6 && status == PCW_OK; i++)
        status = pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0 + i, 0, PCW_TSRESOL_NANO, &if_name, 1, NULL);
    for (i = 0; i < 6 && status == PCW_OK; i++)
        status = pcw_writer_packet(writer, i, i, i, payload, sizeof(payload), sizeof(payload), NULL, 0);
    pcw_writer_destroy(writer);
    return status;
}

static int alloc_read(alloc_state_t *state, const membuf_t *in)
{
    pcw_reader_t *reader = NULL;
    source_t src = {in->data, in->len, 0, 7};
    const pcw_block_t *block;
    int status = pcw_reader_create(counting_alloc, counting_free, state, &reader);

    if (status == PCW_OK)
        status = pcw_reader_set_limits(reader, 256, 64);
    if (status == PCW_OK)
        status = pcw_reader_open_stream(reader, source_read, &src);
    while (status == PCW_OK)
        status = pcw_reader_next(reader, &block);
    pcw_reader_destroy(reader);
    return status == PCW_END ? PCW_OK : status;
}

static int alloc_cycle(size_t fail_at)
{
    alloc_state_t state = {0, 0, fail_at};
    membuf_t out = {NULL, 0, 0};
    int status = alloc_write(&state, &out);

    if (status == PCW_OK)
        status = alloc_read(&state, &out);
    CHECK(state.live == 0);
    CHECK(status == PCW_OK || status == PCW_ERR_NOMEM);
    free(out.data);
    return status == PCW_OK && state.calls <= fail_at;
}

static void test_alloc_failure(void)
{
    size_t fail_at = 0;

    while (!alloc_cycle(fail_at))
        fail_at++;
    CHECK(fail_at > 3);
}

int main(void)
{
    test_arguments();
    test_strerror();
    test_writer_roundtrip();
    test_conversion();
    test_pcap_big_endian();
    test_fcs();
    test_epb_fcs();
    test_writer_options();
    test_writer_options_pcap();
    test_writer_bad_options();
    test_cross_order_copy();
    test_writer_sections();
    test_writer_units();
    test_pcapng_crafted();
    test_invalid_interface();
    test_truncated();
    test_bad_input();
    test_reader_error();
    test_read_callback_errors();
    test_limits();
    test_limit_at_end();
    test_huge_lengths();
    test_interface_limit();
    test_writer_errors();
    test_alloc_failure();
    test_block_writes();
    printf("wirefile: all tests passed\n");
    return 0;
}
