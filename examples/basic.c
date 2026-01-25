#include <wirefile/wirefile.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} membuf_t;

static int membuf_write(void *ctx, const unsigned char *data, size_t data_len)
{
    membuf_t *buf = ctx;
    unsigned char *grown;

    if (buf->len + data_len > buf->cap) {
        buf->cap = (buf->len + data_len) * 2;
        grown = realloc(buf->data, buf->cap);
        if (grown == NULL)
            return -1;
        buf->data = grown;
    }
    memcpy(buf->data + buf->len, data, data_len);
    buf->len += data_len;
    return 0;
}

static int write_capture(membuf_t *out)
{
    static const unsigned char report[] = {0xa1, 0x01, 0x80, 0x80, 0x7f, 0x7f, 0x00, 0x08};
    pcw_writer_t *writer = NULL;
    uint32_t iface = 0;
    int status;
    int i;

    status = pcw_writer_create(NULL, NULL, NULL, &writer);
    if (status == PCW_OK)
        status = pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, out);
    if (status == PCW_OK)
        status = pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, "gamepad", &iface);
    for (i = 0; i < 3 && status == PCW_OK; i++)
        status = pcw_writer_packet(writer, iface, 1700000000 + i, 250000000u * (uint32_t)i, report, sizeof(report), sizeof(report));
    pcw_writer_destroy(writer);
    return status;
}

static int read_capture(const membuf_t *in)
{
    pcw_reader_t *reader = NULL;
    const pcw_block_t *block;
    int status;

    status = pcw_reader_create(NULL, NULL, NULL, &reader);
    if (status == PCW_OK)
        status = pcw_reader_open_mem(reader, in->data, in->len);
    while (status == PCW_OK && (status = pcw_reader_next(reader, &block)) == PCW_OK) {
        if (block->kind == PCW_KIND_PACKET)
            printf("%lld.%09u linktype %u, %zu bytes\n", (long long)block->ts_sec, (unsigned)block->ts_nsec, (unsigned)block->linktype, block->data_len);
    }
    pcw_reader_destroy(reader);
    return status == PCW_END ? PCW_OK : status;
}

int main(void)
{
    membuf_t buf = {NULL, 0, 0};
    int status = write_capture(&buf);

    if (status == PCW_OK)
        status = read_capture(&buf);
    free(buf.data);
    if (status != PCW_OK) {
        fprintf(stderr, "error: %s\n", pcw_strerror(status));
        return 1;
    }
    return 0;
}
