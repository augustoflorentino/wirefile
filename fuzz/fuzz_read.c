#include "wirefile/wirefile.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} source_t;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} sink_t;

static int source_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    source_t *src = ctx;
    size_t take = src->len - src->pos;

    if (take > buf_len)
        take = buf_len;
    if (take > 3)
        take = 3;
    if (take > 0)
        memcpy(buf, src->data + src->pos, take);
    src->pos += take;
    *out_read = take;
    return 0;
}

static int sink_write(void *ctx, const unsigned char *data, size_t data_len)
{
    sink_t *sink = ctx;
    unsigned char *grown;

    if (data_len == 0)
        return 0;
    if (sink->len + data_len > sink->cap) {
        sink->cap = (sink->len + data_len) * 2;
        grown = realloc(sink->data, sink->cap);
        if (grown == NULL)
            return -1;
        sink->data = grown;
    }
    memcpy(sink->data + sink->len, data, data_len);
    sink->len += data_len;
    return 0;
}

static void walk_block(const pcw_block_t *block)
{
    const unsigned char *value;
    size_t value_len;
    size_t pos = 0;
    uint16_t code;
    volatile unsigned sum = 0;

    while (pcw_option_next(block, &pos, &code, &value, &value_len) == PCW_OK)
        sum += value_len ? value[value_len - 1] : code;
    pos = 0;
    while (block->kind == PCW_KIND_NAMES && pcw_name_next(block, &pos, &code, &value, &value_len) == PCW_OK)
        sum += value_len ? value[0] : code;
    if (block->data_len > 0)
        sum += block->data[block->data_len - 1];
}

static int drain(pcw_reader_t *reader, pcw_writer_t *writer, int skip_sections)
{
    const pcw_block_t *block;
    uint64_t last_error = UINT64_MAX;
    int format_errors = 0;
    int status;
    int rounds;

    for (rounds = 0; rounds < 100000; rounds++) {
        status = pcw_reader_next(reader, &block);
        if (status == PCW_END)
            break;
        if (status == PCW_ERR_FORMAT)
            format_errors++;
        if (status != PCW_OK && pcw_reader_offset(reader) == last_error)
            break;
        if (status != PCW_OK) {
            last_error = pcw_reader_offset(reader);
            continue;
        }
        walk_block(block);
        if (writer != NULL && !(skip_sections && block->kind == PCW_KIND_SECTION))
            pcw_writer_block(writer, block);
    }
    if (rounds == 100000)
        abort();
    return format_errors;
}

static void read_stream(const uint8_t *data, size_t size)
{
    source_t src = {data, size, 0};
    pcw_reader_t *reader = NULL;

    if (pcw_reader_create(NULL, NULL, NULL, &reader) != PCW_OK)
        return;
    pcw_reader_set_limits(reader, 64, 4);
    pcw_reader_open_stream(reader, source_read, &src);
    drain(reader, NULL, 0);
    pcw_reader_destroy(reader);
}

static void reread(const sink_t *sink)
{
    pcw_reader_t *reader = NULL;

    if (sink->len == 0 || pcw_reader_create(NULL, NULL, NULL, &reader) != PCW_OK)
        return;
    pcw_reader_open_mem(reader, sink->data, sink->len);
    if (drain(reader, NULL, 0) != 0)
        abort();
    pcw_reader_destroy(reader);
}

static void copy_mem(const uint8_t *data, size_t size, uint32_t format, int own_section)
{
    pcw_reader_t *reader = NULL;
    pcw_writer_t *writer = NULL;
    sink_t sink = {NULL, 0, 0};

    if (pcw_reader_create(NULL, NULL, NULL, &reader) == PCW_OK && pcw_writer_create(NULL, NULL, NULL, &writer) == PCW_OK) {
        pcw_reader_open_mem(reader, data, size);
        pcw_writer_open(writer, format, sink_write, &sink);
        if (own_section)
            pcw_writer_add_interface(writer, 147, 0, 9, NULL, 0, NULL);
        drain(reader, writer, own_section);
        reread(&sink);
    }
    pcw_writer_destroy(writer);
    pcw_reader_destroy(reader);
    free(sink.data);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    read_stream(data, size);
    copy_mem(data, size, PCW_FORMAT_PCAP, 0);
    copy_mem(data, size, PCW_FORMAT_PCAPNG, 0);
    copy_mem(data, size, PCW_FORMAT_PCAPNG, 1);
    return 0;
}
