#include "wirefile/wirefile.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct pcw_buf {
    pcw_alloc_fn alloc_fn;
    pcw_free_fn free_fn;
    void *alloc_ctx;
    unsigned char *data;
    size_t len;
    size_t cap;
};

static void *pcw_default_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void pcw_default_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

int pcw_buf_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_buf_t **out_buf)
{
    pcw_buf_t *buf;

    if (out_buf == NULL || (alloc_fn == NULL) != (free_fn == NULL))
        return PCW_ERR_ARG;
    *out_buf = NULL;
    if (alloc_fn == NULL) {
        alloc_fn = pcw_default_alloc;
        free_fn = pcw_default_free;
    }
    buf = alloc_fn(alloc_ctx, sizeof(*buf));
    if (buf == NULL)
        return PCW_ERR_NOMEM;
    memset(buf, 0, sizeof(*buf));
    buf->alloc_fn = alloc_fn;
    buf->free_fn = free_fn;
    buf->alloc_ctx = alloc_ctx;
    *out_buf = buf;
    return PCW_OK;
}

void pcw_buf_destroy(pcw_buf_t *buf)
{
    if (buf == NULL)
        return;
    if (buf->data != NULL)
        buf->free_fn(buf->alloc_ctx, buf->data);
    buf->free_fn(buf->alloc_ctx, buf);
}

static int pcw_buf_reserve(pcw_buf_t *buf, size_t needed)
{
    size_t cap;
    unsigned char *data;

    if (needed <= buf->cap)
        return PCW_OK;
    cap = buf->cap ? buf->cap : 64;
    while (cap < needed)
        cap = cap > SIZE_MAX / 2 ? needed : cap * 2;
    data = buf->alloc_fn(buf->alloc_ctx, cap);
    if (data == NULL)
        return PCW_ERR_NOMEM;
    if (buf->len > 0)
        memcpy(data, buf->data, buf->len);
    if (buf->data != NULL)
        buf->free_fn(buf->alloc_ctx, buf->data);
    buf->data = data;
    buf->cap = cap;
    return PCW_OK;
}

int pcw_buf_append(pcw_buf_t *buf, const unsigned char *data, size_t data_len)
{
    int status;

    if (buf == NULL || (data == NULL && data_len > 0))
        return PCW_ERR_ARG;
    if (data_len == 0)
        return PCW_OK;
    if (data_len > SIZE_MAX - buf->len)
        return PCW_ERR_NOMEM;
    status = pcw_buf_reserve(buf, buf->len + data_len);
    if (status != PCW_OK)
        return status;
    memcpy(buf->data + buf->len, data, data_len);
    buf->len += data_len;
    return PCW_OK;
}

size_t pcw_buf_len(const pcw_buf_t *buf)
{
    return buf ? buf->len : 0;
}

const unsigned char *pcw_buf_data(const pcw_buf_t *buf)
{
    return buf ? buf->data : NULL;
}

int pcw_buf_split(const pcw_buf_t *buf, unsigned char sep, pcw_piece_fn piece_fn, void *piece_ctx)
{
    size_t start = 0;
    size_t i;

    if (buf == NULL || piece_fn == NULL)
        return PCW_ERR_ARG;
    for (i = 0; i < buf->len; i++) {
        if (buf->data[i] != sep)
            continue;
        if (piece_fn(piece_ctx, buf->data + start, i - start) != 0)
            return PCW_OK;
        start = i + 1;
    }
    if (start < buf->len)
        piece_fn(piece_ctx, buf->data + start, buf->len - start);
    return PCW_OK;
}

const char *pcw_strerror(int status)
{
    switch (status) {
    case PCW_OK:
        return "ok";
    case PCW_ERR_ARG:
        return "invalid argument";
    case PCW_ERR_NOMEM:
        return "out of memory";
    default:
        return "unknown status";
    }
}
