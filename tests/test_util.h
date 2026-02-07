#ifndef WIREFILE_TEST_UTIL_H
#define WIREFILE_TEST_UTIL_H

#include "wirefile/wirefile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);    \
            exit(1);                                                             \
        }                                                                        \
    } while (0)

#define CHECK_STATUS(expr, expected)                                             \
    do {                                                                         \
        int check_status_ = (expr);                                              \
        if (check_status_ != (expected)) {                                       \
            fprintf(stderr, "%s:%d: %s = %d (%s), expected %d\n", __FILE__,      \
                    __LINE__, #expr, check_status_, pcw_strerror(check_status_), \
                    (expected));                                                 \
            exit(1);                                                             \
        }                                                                        \
    } while (0)

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} membuf_t;

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
    size_t chunk;
} source_t;

static inline int membuf_write(void *ctx, const unsigned char *data, size_t data_len)
{
    membuf_t *buf = ctx;
    unsigned char *grown;

    if (data_len == 0)
        return 0;
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

static inline int source_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    source_t *src = ctx;
    size_t take = src->len - src->pos;

    if (take > buf_len)
        take = buf_len;
    if (src->chunk > 0 && take > src->chunk)
        take = src->chunk;
    memcpy(buf, src->data + src->pos, take);
    src->pos += take;
    *out_read = take;
    return 0;
}

static inline unsigned char *load_file(const char *path, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    unsigned char *data;
    long size;

    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0);
    size = ftell(file);
    CHECK(size >= 0 && fseek(file, 0, SEEK_SET) == 0);
    data = malloc((size_t)size + 1);
    CHECK(data != NULL);
    CHECK(fread(data, 1, (size_t)size, file) == (size_t)size);
    fclose(file);
    *out_len = (size_t)size;
    return data;
}

static inline int same_bytes(const unsigned char *a, size_t a_len, const unsigned char *b, size_t b_len)
{
    return a_len == b_len && (a_len == 0 || memcmp(a, b, a_len) == 0);
}

static inline int same_block(const pcw_block_t *a, const pcw_block_t *b)
{
    return a->kind == b->kind && a->type == b->type && a->format == b->format
        && (a->flags & ~PCW_FLAG_TRUNCATED) == (b->flags & ~PCW_FLAG_TRUNCATED)
        && a->section == b->section && a->interface_id == b->interface_id
        && a->linktype == b->linktype && a->snaplen == b->snaplen
        && a->version_major == b->version_major && a->version_minor == b->version_minor
        && a->ts_resol == b->ts_resol && a->ts_offset == b->ts_offset && a->ts_raw == b->ts_raw
        && a->ts_sec == b->ts_sec && a->ts_nsec == b->ts_nsec && a->orig_len == b->orig_len
        && a->section_len == b->section_len
        && same_bytes(a->data, a->data_len, b->data, b->data_len)
        && same_bytes(a->options, a->options_len, b->options, b->options_len);
}

static inline pcw_reader_t *open_mem_reader(const unsigned char *data, size_t len)
{
    pcw_reader_t *reader = NULL;

    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, &reader), PCW_OK);
    CHECK_STATUS(pcw_reader_open_mem(reader, data, len), PCW_OK);
    return reader;
}

static inline void copy_capture(const unsigned char *data, size_t len, uint32_t format, membuf_t *out)
{
    pcw_reader_t *reader = open_mem_reader(data, len);
    pcw_writer_t *writer = NULL;
    const pcw_block_t *block;
    int status;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, format, membuf_write, out), PCW_OK);
    while ((status = pcw_reader_next(reader, &block)) == PCW_OK)
        CHECK_STATUS(pcw_writer_block(writer, block), PCW_OK);
    CHECK_STATUS(status, PCW_END);
    CHECK(pcw_writer_offset(writer) == out->len);
    pcw_writer_destroy(writer);
    pcw_reader_destroy(reader);
}

static inline size_t compare_readers(pcw_reader_t *a, pcw_reader_t *b)
{
    const pcw_block_t *block_a;
    const pcw_block_t *block_b;
    size_t count = 0;
    int status_a;
    int status_b;

    for (;;) {
        status_a = pcw_reader_next(a, &block_a);
        status_b = pcw_reader_next(b, &block_b);
        CHECK_STATUS(status_b, status_a);
        if (status_a != PCW_OK)
            return count;
        CHECK(same_block(block_a, block_b));
        count++;
    }
}

#endif
