#include "wirefile_internal.h"

#include <string.h>

#define PCW_ANY_BLOCK 0u
#define PCW_OPT_CUSTOM_STR 2988u
#define PCW_OPT_CUSTOM_BIN 2989u
#define PCW_OPT_CUSTOM_STR_LOCAL 19372u
#define PCW_OPT_CUSTOM_BIN_LOCAL 19373u
#define PCW_OPT_ISB_STARTTIME 2u
#define PCW_OPT_ISB_ENDTIME 3u

typedef struct {
    uint32_t block_type;
    uint16_t code;
    unsigned char width;
    unsigned char count;
    unsigned char prefix;
    unsigned char portable;
} pcw_opt_shape_t;

static const pcw_opt_shape_t pcw_opt_shapes[] = {
    {PCW_ANY_BLOCK, PCW_OPT_COMMENT, 0, 0, 0, 1},
    {PCW_ANY_BLOCK, PCW_OPT_CUSTOM_STR, 4, 1, 1, 1},
    {PCW_ANY_BLOCK, PCW_OPT_CUSTOM_STR_LOCAL, 4, 1, 1, 1},
    {PCW_ANY_BLOCK, PCW_OPT_CUSTOM_BIN, 4, 1, 1, 1},
    {PCW_ANY_BLOCK, PCW_OPT_CUSTOM_BIN_LOCAL, 4, 1, 1, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_NAME, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_DESCRIPTION, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, 4, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, 5, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, 6, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, 7, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_SPEED, 8, 1, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_TZONE, 4, 1, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_FILTER, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_OS, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_FCSLEN, 1, 1, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_HARDWARE, 0, 0, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_TXSPEED, 8, 1, 0, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_RXSPEED, 8, 1, 0, 1},
    {PCW_BLOCK_IDB, 18, 0, 0, 0, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_FLAGS, 4, 1, 0, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_HASH, 0, 0, 0, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_DROPCOUNT, 8, 1, 0, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_PACKETID, 8, 1, 0, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_QUEUE, 4, 1, 0, 1},
    {PCW_BLOCK_EPB, 7, 0, 0, 0, 0},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_PROCESSID_THREADID, 4, 2, 0, 1},
    {PCW_BLOCK_ISB, PCW_OPT_ISB_STARTTIME, 4, 2, 0, 1},
    {PCW_BLOCK_ISB, PCW_OPT_ISB_ENDTIME, 4, 2, 0, 1},
    {PCW_BLOCK_ISB, 4, 8, 1, 0, 1},
    {PCW_BLOCK_ISB, 5, 8, 1, 0, 1},
    {PCW_BLOCK_ISB, 6, 8, 1, 0, 1},
    {PCW_BLOCK_ISB, 7, 8, 1, 0, 1},
    {PCW_BLOCK_ISB, 8, 8, 1, 0, 1},
    {PCW_BLOCK_NRB, 2, 0, 0, 0, 1},
    {PCW_BLOCK_NRB, 3, 0, 0, 0, 1},
    {PCW_BLOCK_NRB, 4, 0, 0, 0, 1},
};

static const pcw_opt_shape_t *pcw_opt_shape(uint32_t block_type, uint16_t code)
{
    const pcw_opt_shape_t *any = NULL;
    size_t i;

    for (i = 0; i < sizeof(pcw_opt_shapes) / sizeof(pcw_opt_shapes[0]); i++) {
        if (pcw_opt_shapes[i].code != code)
            continue;
        if (pcw_opt_shapes[i].block_type == block_type)
            return &pcw_opt_shapes[i];
        if (pcw_opt_shapes[i].block_type == PCW_ANY_BLOCK)
            any = &pcw_opt_shapes[i];
    }
    return any;
}

static size_t pcw_opt_fixed(const pcw_opt_shape_t *shape)
{
    return shape != NULL ? (size_t)shape->width * shape->count : 0;
}

static int pcw_opt_fits(const pcw_opt_shape_t *shape, size_t value_len)
{
    if (shape == NULL || shape->width == 0)
        return 1;
    return shape->prefix ? value_len >= pcw_opt_fixed(shape) : value_len == pcw_opt_fixed(shape);
}

static int pcw_opt_valid(const pcw_optlist_t *list, const pcw_option_t *opt)
{
    if (opt->code == PCW_OPT_END || opt->value_len > UINT16_MAX)
        return 0;
    if (opt->value == NULL && opt->value_len > 0)
        return 0;
    return pcw_opt_fits(pcw_opt_shape(list->block_type, opt->code), opt->value_len);
}

int pcw_optlist_user_check(const pcw_optlist_t *list)
{
    const pcw_option_t *found;
    size_t unused;

    if (pcw_optlist_check(list, &unused) != PCW_OK)
        return PCW_ERR_ARG;
    if (list->block_type == PCW_BLOCK_IDB && (pcw_optlist_find(list, PCW_OPT_IF_TSRESOL, &found) == PCW_OK || pcw_optlist_find(list, PCW_OPT_IF_TSOFFSET, &found) == PCW_OK))
        return PCW_ERR_ARG;
    return PCW_OK;
}

int pcw_optlist_check(const pcw_optlist_t *list, size_t *out_len)
{
    size_t total = 0;
    size_t i;

    *out_len = 0;
    if (list == NULL || list->count == 0)
        return PCW_OK;
    if (list->items == NULL)
        return PCW_ERR_ARG;
    for (i = 0; i < list->count; i++) {
        if (!pcw_opt_valid(list, &list->items[i]))
            return PCW_ERR_ARG;
        total += 4 + list->items[i].value_len + pcw_pad4(list->items[i].value_len);
    }
    *out_len = total + 4;
    return PCW_OK;
}

static void pcw_opt_order(unsigned char *dst, const unsigned char *src, unsigned width, int big)
{
    uint16_t v16;
    uint32_t v32;
    uint64_t v64;

    if (width == 2) {
        memcpy(&v16, src, 2);
        pcw_wr16(dst, v16, big);
    } else if (width == 4) {
        memcpy(&v32, src, 4);
        pcw_wr32(dst, v32, big);
    } else if (width == 8) {
        memcpy(&v64, src, 8);
        pcw_wr64(dst, v64, big);
    } else {
        memcpy(dst, src, width);
    }
}

static int pcw_opt_emit(pcw_writer_t *writer, uint32_t block_type, const pcw_option_t *opt)
{
    const pcw_opt_shape_t *shape = pcw_opt_shape(block_type, opt->code);
    const unsigned char *value = opt->value;
    size_t fixed = pcw_opt_fixed(shape);
    unsigned char head[16];
    unsigned i;
    int status;

    pcw_wr16(head, opt->code, writer->big_endian);
    pcw_wr16(head + 2, (uint16_t)opt->value_len, writer->big_endian);
    status = pcw_emit(writer, head, 4);
    for (i = 0; fixed > 0 && i < shape->count; i++)
        pcw_opt_order(head + i * shape->width, value + i * shape->width, shape->width, writer->big_endian);
    if (status == PCW_OK)
        status = pcw_emit(writer, head, fixed);
    if (status == PCW_OK && opt->value_len > fixed)
        status = pcw_emit(writer, value + fixed, opt->value_len - fixed);
    if (status == PCW_OK)
        status = pcw_emit_zeros(writer, pcw_pad4(opt->value_len));
    return status;
}

int pcw_optlist_emit(pcw_writer_t *writer, const pcw_optlist_t *list)
{
    static const unsigned char end[4];
    size_t i;
    int status = PCW_OK;

    if (list == NULL || list->count == 0)
        return PCW_OK;
    for (i = 0; i < list->count && status == PCW_OK; i++)
        status = pcw_opt_emit(writer, list->block_type, &list->items[i]);
    if (status == PCW_OK)
        status = pcw_emit(writer, end, sizeof(end));
    return status;
}

int pcw_optlist_find(const pcw_optlist_t *list, uint16_t code, const pcw_option_t **out_opt)
{
    size_t i;

    for (i = 0; list != NULL && i < list->count; i++) {
        if (list->items[i].code == code) {
            *out_opt = &list->items[i];
            return PCW_OK;
        }
    }
    return PCW_END;
}

static void pcw_opt_to_host(unsigned char *dst, const unsigned char *src, unsigned width, int big)
{
    uint16_t v16;
    uint32_t v32;
    uint64_t v64;

    if (width == 2) {
        v16 = pcw_rd16(src, big);
        memcpy(dst, &v16, 2);
    } else if (width == 4) {
        v32 = pcw_rd32(src, big);
        memcpy(dst, &v32, 4);
    } else if (width == 8) {
        v64 = pcw_rd64(src, big);
        memcpy(dst, &v64, 8);
    } else {
        memcpy(dst, src, width);
    }
}

static int pcw_opt_portable(uint32_t block_type, uint16_t code, size_t value_len, int keep_times)
{
    const pcw_opt_shape_t *shape = pcw_opt_shape(block_type, code);

    if (shape == NULL || !shape->portable || !pcw_opt_fits(shape, value_len))
        return 0;
    if (block_type == PCW_BLOCK_IDB && (code == PCW_OPT_IF_TSRESOL || code == PCW_OPT_IF_TSOFFSET))
        return 0;
    return keep_times || block_type != PCW_BLOCK_ISB || (code != PCW_OPT_ISB_STARTTIME && code != PCW_OPT_ISB_ENDTIME);
}

static void pcw_opt_copy_host(pcw_option_t *dst, unsigned char *buf, uint32_t block_type, uint16_t code, const unsigned char *value, size_t value_len, int big)
{
    const pcw_opt_shape_t *shape = pcw_opt_shape(block_type, code);
    size_t fixed = pcw_opt_fixed(shape);
    unsigned i;

    for (i = 0; fixed > 0 && i < shape->count; i++)
        pcw_opt_to_host(buf + i * shape->width, value + i * shape->width, shape->width, big);
    if (value_len > fixed)
        memcpy(buf + fixed, value + fixed, value_len - fixed);
    dst->code = code;
    dst->value = buf;
    dst->value_len = value_len;
}

static size_t pcw_opt_count(const pcw_block_t *block)
{
    size_t pos = 0;
    size_t count = 0;
    uint16_t code;
    const unsigned char *value;
    size_t value_len;

    while (pcw_option_next(block, &pos, &code, &value, &value_len) == PCW_OK)
        count++;
    return count;
}

int pcw_optlist_reorder(const pcw_mem_t *mem, const pcw_block_t *block, uint32_t block_type, int keep_times, pcw_optlist_t *out, void **out_mem)
{
    size_t count = pcw_opt_count(block);
    int big = (block->flags & PCW_FLAG_BIG_ENDIAN) != 0;
    pcw_option_t *items;
    unsigned char *buf;
    size_t pos = 0;
    uint16_t code;
    const unsigned char *value;
    size_t value_len;

    out->block_type = block_type;
    out->items = NULL;
    out->count = 0;
    *out_mem = NULL;
    if (count == 0)
        return PCW_OK;
    if (count > (SIZE_MAX - block->options_len) / sizeof(*items))
        return PCW_ERR_NOMEM;
    items = mem->alloc_fn(mem->ctx, count * sizeof(*items) + block->options_len);
    if (items == NULL)
        return PCW_ERR_NOMEM;
    buf = (unsigned char *)(items + count);
    while (pcw_option_next(block, &pos, &code, &value, &value_len) == PCW_OK) {
        if (!pcw_opt_portable(block_type, code, value_len, keep_times))
            continue;
        pcw_opt_copy_host(&items[out->count++], buf, block_type, code, value, value_len, big);
        buf += value_len;
    }
    out->items = items;
    *out_mem = items;
    return PCW_OK;
}
