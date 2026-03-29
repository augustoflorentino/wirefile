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

static int pcw_pcap_fcs_len(const pcw_block_t *block, uint32_t *out_bits)
{
    uint32_t raw;

    if (block->body == NULL || block->body_len < 24)
        return PCW_END;
    raw = pcw_get_u32(block, block->body + 20);
    if (!(raw & 0x04000000u))
        return PCW_END;
    *out_bits = (raw >> 28) * 16;
    return PCW_OK;
}

static int pcw_ng_fcs_len(const pcw_block_t *block, uint32_t *out_bits)
{
    const unsigned char *value;
    size_t value_len;
    uint32_t octets;

    if (block->kind == PCW_KIND_INTERFACE) {
        if (pcw_option_find(block, PCW_OPT_IF_FCSLEN, &value, &value_len) != PCW_OK || value_len != 1)
            return PCW_END;
        *out_bits = value[0];
        return PCW_OK;
    }
    if (block->type != PCW_BLOCK_EPB || pcw_option_find(block, PCW_OPT_EPB_FLAGS, &value, &value_len) != PCW_OK || value_len != 4)
        return PCW_END;
    octets = (pcw_get_u32(block, value) >> 5) & 0xFu;
    if (octets == 0)
        return PCW_END;
    *out_bits = octets * 8;
    return PCW_OK;
}

int pcw_block_fcs_len(const pcw_block_t *block, uint32_t *out_bits)
{
    if (block == NULL || out_bits == NULL)
        return PCW_ERR_ARG;
    if (block->format == PCW_FORMAT_PCAP && block->kind == PCW_KIND_SECTION)
        return pcw_pcap_fcs_len(block, out_bits);
    if (block->format == PCW_FORMAT_PCAPNG && (block->kind == PCW_KIND_INTERFACE || block->kind == PCW_KIND_PACKET))
        return pcw_ng_fcs_len(block, out_bits);
    return PCW_END;
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
