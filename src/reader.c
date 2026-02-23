#include "wirefile_internal.h"

#include <string.h>

#define PCW_MIN_BLOCK_LIMIT 64u

typedef char pcw_block_head_check[offsetof(pcw_block_t, data) == 88 ? 1 : -1];
typedef char pcw_block_size_check[sizeof(pcw_block_t) == 88 + 3 * sizeof(const unsigned char *) + 3 * sizeof(size_t) ? 1 : -1];

int pcw_reader_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_reader_t **out_reader)
{
    pcw_mem_t mem;
    pcw_reader_t *reader;

    if (out_reader == NULL)
        return PCW_ERR_ARG;
    *out_reader = NULL;
    if (pcw_mem_init(&mem, alloc_fn, free_fn, alloc_ctx) != PCW_OK)
        return PCW_ERR_ARG;
    reader = mem.alloc_fn(mem.ctx, sizeof(*reader));
    if (reader == NULL)
        return PCW_ERR_NOMEM;
    memset(reader, 0, sizeof(*reader));
    reader->mem = mem;
    reader->max_block_len = PCW_DEFAULT_MAX_BLOCK;
    reader->ifaces.max = PCW_DEFAULT_MAX_INTERFACES;
    *out_reader = reader;
    return PCW_OK;
}

void pcw_reader_destroy(pcw_reader_t *reader)
{
    if (reader == NULL)
        return;
    pcw_iface_free(&reader->mem, &reader->ifaces);
    if (reader->buf != NULL)
        reader->mem.free_fn(reader->mem.ctx, reader->buf);
    reader->mem.free_fn(reader->mem.ctx, reader);
}

int pcw_reader_set_limits(pcw_reader_t *reader, size_t max_block_len, uint32_t max_interfaces)
{
    if (reader == NULL || max_block_len < PCW_MIN_BLOCK_LIMIT || max_interfaces == 0)
        return PCW_ERR_ARG;
    if (reader->opened)
        return PCW_ERR_STATE;
    reader->max_block_len = max_block_len;
    reader->ifaces.max = max_interfaces;
    return PCW_OK;
}

int pcw_reader_open_stream(pcw_reader_t *reader, pcw_read_fn read_fn, void *read_ctx)
{
    if (reader == NULL || read_fn == NULL)
        return PCW_ERR_ARG;
    if (reader->opened)
        return PCW_ERR_STATE;
    reader->buf = reader->mem.alloc_fn(reader->mem.ctx, reader->max_block_len);
    if (reader->buf == NULL)
        return PCW_ERR_NOMEM;
    reader->data = reader->buf;
    reader->read_fn = read_fn;
    reader->read_ctx = read_ctx;
    reader->stream = 1;
    reader->opened = 1;
    return PCW_OK;
}

int pcw_reader_open_mem(pcw_reader_t *reader, const void *data, size_t data_len)
{
    if (reader == NULL || (data == NULL && data_len > 0))
        return PCW_ERR_ARG;
    if (reader->opened)
        return PCW_ERR_STATE;
    reader->data = data;
    reader->end = data_len;
    reader->eof = 1;
    reader->opened = 1;
    return PCW_OK;
}

static int pcw_detect(pcw_reader_t *reader)
{
    uint32_t magic;
    int status = pcw_fill(reader, 4);

    if (status == PCW_END)
        return pcw_stop(reader, PCW_ERR_FORMAT);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    magic = pcw_rd32(reader->data + reader->pos, 0);
    if (magic == PCW_BLOCK_SHB) {
        reader->format = PCW_FORMAT_PCAPNG;
        return pcw_read_pcapng_block(reader);
    }
    return pcw_read_pcap_header(reader);
}

int pcw_reader_next(pcw_reader_t *reader, const pcw_block_t **out_block)
{
    int status;

    if (reader == NULL || out_block == NULL)
        return PCW_ERR_ARG;
    *out_block = NULL;
    if (!reader->opened)
        return PCW_ERR_STATE;
    if (reader->fatal != PCW_OK)
        return reader->fatal;
    memset(&reader->block, 0, sizeof(reader->block));
    if (reader->format == 0)
        status = pcw_detect(reader);
    else if (reader->format == PCW_FORMAT_PCAP)
        status = pcw_read_pcap_record(reader);
    else
        status = pcw_read_pcapng_block(reader);
    if (status == PCW_OK)
        *out_block = &reader->block;
    return status;
}

uint64_t pcw_reader_offset(const pcw_reader_t *reader)
{
    return reader ? reader->offset : 0;
}

size_t pcw_reader_trailing(const pcw_reader_t *reader)
{
    return reader ? reader->trailing : 0;
}

static int pcw_read_more(pcw_reader_t *reader)
{
    size_t got = 0;

    if (reader->pos > 0) {
        memmove(reader->buf, reader->buf + reader->pos, reader->end - reader->pos);
        reader->end -= reader->pos;
        reader->pos = 0;
    }
    if (reader->read_fn(reader->read_ctx, reader->buf + reader->end, reader->max_block_len - reader->end, &got) != 0)
        return PCW_ERR_IO;
    if (got > reader->max_block_len - reader->end)
        return PCW_ERR_IO;
    if (got == 0)
        reader->eof = 1;
    reader->end += got;
    return PCW_OK;
}

int pcw_fill(pcw_reader_t *reader, size_t need)
{
    int status;

    while (reader->end - reader->pos < need) {
        if (reader->eof)
            return PCW_END;
        if (need > reader->max_block_len)
            return PCW_ERR_LIMIT;
        status = pcw_read_more(reader);
        if (status != PCW_OK)
            return status;
    }
    return PCW_OK;
}

void pcw_consume(pcw_reader_t *reader, size_t len)
{
    reader->pos += len;
    reader->offset += len;
}

int pcw_skip(pcw_reader_t *reader, size_t len)
{
    size_t take;
    int status;

    while (len > 0) {
        if (reader->end == reader->pos) {
            if (reader->eof)
                return PCW_END;
            status = pcw_read_more(reader);
            if (status != PCW_OK)
                return status;
            continue;
        }
        take = reader->end - reader->pos < len ? reader->end - reader->pos : len;
        pcw_consume(reader, take);
        len -= take;
    }
    return PCW_OK;
}

int pcw_stop(pcw_reader_t *reader, int status)
{
    reader->fatal = status;
    return status;
}

int pcw_stop_trailing(pcw_reader_t *reader)
{
    reader->trailing = reader->end - reader->pos;
    pcw_consume(reader, reader->trailing);
    return pcw_stop(reader, PCW_END);
}
