#include "wirefile_internal.h"

#include <stdlib.h>

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

int pcw_mem_init(pcw_mem_t *mem, pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *ctx)
{
    if ((alloc_fn == NULL) != (free_fn == NULL))
        return PCW_ERR_ARG;
    mem->alloc_fn = alloc_fn ? alloc_fn : pcw_default_alloc;
    mem->free_fn = free_fn ? free_fn : pcw_default_free;
    mem->ctx = ctx;
    return PCW_OK;
}

uint16_t pcw_rd16(const unsigned char *src, int big_endian)
{
    if (big_endian)
        return (uint16_t)((unsigned)src[0] << 8 | src[1]);
    return (uint16_t)((unsigned)src[1] << 8 | src[0]);
}

uint32_t pcw_rd32(const unsigned char *src, int big_endian)
{
    uint32_t hi = pcw_rd16(src + (big_endian ? 0 : 2), big_endian);
    uint32_t lo = pcw_rd16(src + (big_endian ? 2 : 0), big_endian);

    return hi << 16 | lo;
}

uint64_t pcw_rd64(const unsigned char *src, int big_endian)
{
    uint64_t hi = pcw_rd32(src + (big_endian ? 0 : 4), big_endian);
    uint64_t lo = pcw_rd32(src + (big_endian ? 4 : 0), big_endian);

    return hi << 32 | lo;
}

void pcw_wr16(unsigned char *dst, uint16_t value, int big_endian)
{
    dst[big_endian ? 0 : 1] = (unsigned char)(value >> 8);
    dst[big_endian ? 1 : 0] = (unsigned char)(value & 0xff);
}

void pcw_wr32(unsigned char *dst, uint32_t value, int big_endian)
{
    pcw_wr16(dst + (big_endian ? 0 : 2), (uint16_t)(value >> 16), big_endian);
    pcw_wr16(dst + (big_endian ? 2 : 0), (uint16_t)(value & 0xffff), big_endian);
}

void pcw_wr64(unsigned char *dst, uint64_t value, int big_endian)
{
    pcw_wr32(dst + (big_endian ? 0 : 4), (uint32_t)(value >> 32), big_endian);
    pcw_wr32(dst + (big_endian ? 4 : 0), (uint32_t)(value & 0xffffffffu), big_endian);
}

int pcw_host_big_endian(void)
{
    const uint16_t probe = 1;

    return *(const unsigned char *)&probe == 0;
}

size_t pcw_pad4(size_t len)
{
    return (4 - (len & 3)) & 3;
}

int pcw_iface_add(const pcw_mem_t *mem, pcw_iface_table_t *table, const pcw_iface_t *iface)
{
    pcw_iface_t *items;
    uint32_t cap;
    uint32_t i;

    if (table->count >= table->max)
        return PCW_ERR_LIMIT;
    if (table->count == table->cap) {
        cap = table->cap ? table->cap * 2 : 4;
        if (cap > table->max)
            cap = table->max;
        items = mem->alloc_fn(mem->ctx, (size_t)cap * sizeof(*items));
        if (items == NULL)
            return PCW_ERR_NOMEM;
        for (i = 0; i < table->count; i++)
            items[i] = table->items[i];
        pcw_iface_free(mem, table);
        table->items = items;
        table->cap = cap;
    }
    table->items[table->count++] = *iface;
    return PCW_OK;
}

const pcw_iface_t *pcw_iface_get(const pcw_iface_table_t *table, uint32_t id)
{
    return id < table->count ? &table->items[id] : NULL;
}

void pcw_iface_free(const pcw_mem_t *mem, pcw_iface_table_t *table)
{
    if (table->items != NULL)
        mem->free_fn(mem->ctx, table->items);
    table->items = NULL;
    table->cap = 0;
}

const char *pcw_strerror(int status)
{
    switch (status) {
    case PCW_OK:
        return "ok";
    case PCW_END:
        return "end of capture";
    case PCW_ERR_ARG:
        return "invalid argument";
    case PCW_ERR_NOMEM:
        return "out of memory";
    case PCW_ERR_IO:
        return "read or write callback failed";
    case PCW_ERR_FORMAT:
        return "malformed capture data";
    case PCW_ERR_LIMIT:
        return "configured limit exceeded";
    case PCW_ERR_STATE:
        return "call not valid in the current state";
    default:
        return "unknown status";
    }
}
