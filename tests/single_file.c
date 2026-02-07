#define PCW_IMPLEMENTATION
#include "wirefile/wirefile.h"

#include <string.h>

typedef struct {
    unsigned char data[256];
    size_t len;
} sink_t;

static int sink_write(void *ctx, const unsigned char *data, size_t data_len)
{
    sink_t *sink = ctx;

    if (sink->len + data_len > sizeof(sink->data))
        return -1;
    memcpy(sink->data + sink->len, data, data_len);
    sink->len += data_len;
    return 0;
}

static int write_one(sink_t *sink)
{
    pcw_writer_t *writer = NULL;
    int status = pcw_writer_create(NULL, NULL, NULL, &writer);

    if (status == PCW_OK)
        status = pcw_writer_open(writer, PCW_FORMAT_PCAPNG, sink_write, sink);
    if (status == PCW_OK)
        status = pcw_writer_add_interface(writer, PCW_LINKTYPE_USER0, 0, PCW_TSRESOL_NANO, "hid", NULL);
    if (status == PCW_OK)
        status = pcw_writer_packet(writer, 0, 1, 2, "abc", 3, 3);
    pcw_writer_destroy(writer);
    return status;
}

int main(void)
{
    sink_t sink = {{0}, 0};
    pcw_reader_t *reader = NULL;
    const pcw_block_t *block = NULL;
    int packets = 0;
    int status = write_one(&sink);

    if (status == PCW_OK)
        status = pcw_reader_create(NULL, NULL, NULL, &reader);
    if (status == PCW_OK)
        status = pcw_reader_open_mem(reader, sink.data, sink.len);
    while (status == PCW_OK && (status = pcw_reader_next(reader, &block)) == PCW_OK)
        packets += block->kind == PCW_KIND_PACKET && block->ts_nsec == 2 && block->data_len == 3;
    pcw_reader_destroy(reader);
    return status == PCW_END && packets == 1 && pcw_strerror(status) != NULL ? 0 : 1;
}
