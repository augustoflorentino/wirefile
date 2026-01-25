#include "wirefile_internal.h"

int pcw_tlv_next(const unsigned char *area, size_t area_len, int big_endian, size_t *io_pos, uint16_t *out_code, const unsigned char **out_value, size_t *out_value_len)
{
    size_t pos = *io_pos;
    size_t len;
    size_t step;

    if (pos > area_len || area_len - pos < 4)
        return PCW_END;
    *out_code = pcw_rd16(area + pos, big_endian);
    len = pcw_rd16(area + pos + 2, big_endian);
    if (*out_code == PCW_OPT_END)
        return PCW_END;
    if (len > area_len - pos - 4)
        return PCW_ERR_FORMAT;
    step = 4 + len + pcw_pad4(len);
    *out_value = area + pos + 4;
    *out_value_len = len;
    *io_pos = step > area_len - pos ? area_len : pos + step;
    return PCW_OK;
}

int pcw_tlv_check(const unsigned char *area, size_t area_len, int big_endian, size_t *out_used)
{
    size_t pos = 0;
    uint16_t code;
    const unsigned char *value;
    size_t value_len;
    int status;

    while ((status = pcw_tlv_next(area, area_len, big_endian, &pos, &code, &value, &value_len)) == PCW_OK)
        continue;
    if (status != PCW_END)
        return status;
    *out_used = area_len - pos >= 4 ? pos + 4 : area_len;
    return PCW_OK;
}

int pcw_option_next(const pcw_block_t *block, size_t *io_pos, uint16_t *out_code, const unsigned char **out_value, size_t *out_value_len)
{
    if (block == NULL || io_pos == NULL || out_code == NULL || out_value == NULL || out_value_len == NULL)
        return PCW_ERR_ARG;
    return pcw_tlv_next(block->options, block->options_len, (block->flags & PCW_FLAG_BIG_ENDIAN) != 0, io_pos, out_code, out_value, out_value_len);
}

int pcw_option_find(const pcw_block_t *block, uint16_t code, const unsigned char **out_value, size_t *out_value_len)
{
    size_t pos = 0;
    uint16_t found;
    int status;

    if (block == NULL || out_value == NULL || out_value_len == NULL)
        return PCW_ERR_ARG;
    while ((status = pcw_option_next(block, &pos, &found, out_value, out_value_len)) == PCW_OK) {
        if (found == code)
            return PCW_OK;
    }
    return status;
}

int pcw_name_next(const pcw_block_t *block, size_t *io_pos, uint16_t *out_type, const unsigned char **out_value, size_t *out_value_len)
{
    if (block == NULL || io_pos == NULL || out_type == NULL || out_value == NULL || out_value_len == NULL)
        return PCW_ERR_ARG;
    if (block->kind != PCW_KIND_NAMES)
        return PCW_ERR_ARG;
    return pcw_tlv_next(block->data, block->data_len, (block->flags & PCW_FLAG_BIG_ENDIAN) != 0, io_pos, out_type, out_value, out_value_len);
}

uint16_t pcw_get_u16(const pcw_block_t *block, const unsigned char *src)
{
    return pcw_rd16(src, block != NULL && (block->flags & PCW_FLAG_BIG_ENDIAN) != 0);
}

uint32_t pcw_get_u32(const pcw_block_t *block, const unsigned char *src)
{
    return pcw_rd32(src, block != NULL && (block->flags & PCW_FLAG_BIG_ENDIAN) != 0);
}

uint64_t pcw_get_u64(const pcw_block_t *block, const unsigned char *src)
{
    return pcw_rd64(src, block != NULL && (block->flags & PCW_FLAG_BIG_ENDIAN) != 0);
}
