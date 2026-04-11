#include "wirefile_internal.h"

#include <string.h>

typedef struct {
    uint32_t block_type;
    uint16_t code;
    unsigned char width;
    unsigned char count;
} pcw_opt_shape_t;

static const pcw_opt_shape_t pcw_opt_shapes[] = {
    {PCW_BLOCK_IDB, PCW_OPT_IF_SPEED, 8, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_TZONE, 4, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_FCSLEN, 1, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_TXSPEED, 8, 1},
    {PCW_BLOCK_IDB, PCW_OPT_IF_RXSPEED, 8, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_FLAGS, 4, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_DROPCOUNT, 8, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_PACKETID, 8, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_QUEUE, 4, 1},
    {PCW_BLOCK_EPB, PCW_OPT_EPB_PROCESSID_THREADID, 4, 2},
};

static const pcw_opt_shape_t *pcw_opt_shape(uint32_t block_type, uint16_t code)
{
    size_t i;

    for (i = 0; i < sizeof(pcw_opt_shapes) / sizeof(pcw_opt_shapes[0]); i++) {
        if (pcw_opt_shapes[i].block_type == block_type && pcw_opt_shapes[i].code == code)
            return &pcw_opt_shapes[i];
    }
    return NULL;
}


static int pcw_opt_valid(const pcw_optlist_t *list, const pcw_option_t *opt)
{
    const pcw_opt_shape_t *shape = pcw_opt_shape(list->block_type, opt->code);

    if (opt->code == PCW_OPT_END || opt->value_len > UINT16_MAX)
        return 0;
    if (opt->value == NULL && opt->value_len > 0)
        return 0;
    return shape == NULL || opt->value_len == (size_t)shape->width * shape->count;
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
    unsigned char head[16];
    unsigned i;
    int status;

    pcw_wr16(head, opt->code, writer->big_endian);
    pcw_wr16(head + 2, (uint16_t)opt->value_len, writer->big_endian);
    status = pcw_emit(writer, head, 4);
    if (status != PCW_OK || shape == NULL) {
        if (status == PCW_OK)
            status = pcw_emit(writer, opt->value, opt->value_len);
    } else {
        for (i = 0; i < shape->count; i++)
            pcw_opt_order(head + i * shape->width, (const unsigned char *)opt->value + i * shape->width, shape->width, writer->big_endian);
        status = pcw_emit(writer, head, opt->value_len);
    }
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
