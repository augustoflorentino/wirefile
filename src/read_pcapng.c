#include "wirefile_internal.h"

#define PCW_SHB_FIXED 16u
#define PCW_IDB_FIXED 8u
#define PCW_EPB_FIXED 20u
#define PCW_SPB_FIXED 4u
#define PCW_ISB_FIXED 12u

static void pcw_ng_common(pcw_reader_t *reader, uint32_t type, const unsigned char *body, size_t body_len)
{
    pcw_block_t *block = &reader->block;

    block->format = PCW_FORMAT_PCAPNG;
    block->type = type;
    block->section = reader->section_count - 1;
    block->flags = reader->big_endian ? PCW_FLAG_BIG_ENDIAN : 0;
    block->section_len = -1;
    block->body = body;
    block->body_len = body_len;
}

static int pcw_ng_options(pcw_reader_t *reader, const unsigned char *area, size_t area_len)
{
    size_t used;
    int status = pcw_tlv_check(area, area_len, reader->big_endian, &used);

    if (status != PCW_OK)
        return status;
    reader->block.options = area;
    reader->block.options_len = area_len;
    return PCW_OK;
}

static int pcw_ng_bind(pcw_reader_t *reader, uint32_t interface_id, uint64_t ts_raw)
{
    const pcw_iface_t *iface = pcw_iface_get(&reader->ifaces, interface_id);
    pcw_block_t *block = &reader->block;

    if (iface == NULL)
        return PCW_ERR_FORMAT;
    block->interface_id = interface_id;
    block->linktype = iface->linktype;
    block->snaplen = iface->snaplen;
    block->ts_resol = iface->ts_resol;
    block->ts_offset = iface->ts_offset;
    block->ts_raw = ts_raw;
    pcw_ts_split(ts_raw, iface->ts_resol, iface->ts_offset, &block->ts_sec, &block->ts_nsec);
    return PCW_OK;
}

static uint64_t pcw_ng_ts(const pcw_reader_t *reader, const unsigned char *src)
{
    uint64_t hi = pcw_rd32(src, reader->big_endian);

    return hi << 32 | pcw_rd32(src + 4, reader->big_endian);
}

static int pcw_ng_shb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    pcw_block_t *block = &reader->block;

    if (body_len < PCW_SHB_FIXED || pcw_rd16(body + 4, reader->big_endian) != 1)
        return pcw_stop(reader, PCW_ERR_FORMAT);
    reader->section_count++;
    reader->ifaces.count = 0;
    pcw_ng_common(reader, PCW_BLOCK_SHB, body, body_len);
    block->kind = PCW_KIND_SECTION;
    block->version_major = 1;
    block->version_minor = pcw_rd16(body + 6, reader->big_endian);
    block->section_len = (int64_t)pcw_rd64(body + 8, reader->big_endian);
    return pcw_ng_options(reader, body + PCW_SHB_FIXED, body_len - PCW_SHB_FIXED);
}

static int pcw_ng_iface_options(const pcw_block_t *block, pcw_iface_t *iface)
{
    const unsigned char *value;
    size_t value_len;

    if (pcw_option_find(block, PCW_OPT_IF_TSRESOL, &value, &value_len) == PCW_OK && value_len == 1)
        iface->ts_resol = value[0];
    if (pcw_option_find(block, PCW_OPT_IF_TSOFFSET, &value, &value_len) == PCW_OK && value_len == 8)
        iface->ts_offset = (int64_t)pcw_get_u64(block, value);
    return pcw_ts_resol_valid(iface->ts_resol) ? PCW_OK : PCW_ERR_FORMAT;
}

static int pcw_ng_idb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    pcw_block_t *block = &reader->block;
    pcw_iface_t iface = {0};
    int status;

    if (body_len < PCW_IDB_FIXED)
        return PCW_ERR_FORMAT;
    status = pcw_ng_options(reader, body + PCW_IDB_FIXED, body_len - PCW_IDB_FIXED);
    if (status != PCW_OK)
        return status;
    iface.linktype = pcw_rd16(body, reader->big_endian);
    iface.snaplen = pcw_rd32(body + 4, reader->big_endian);
    iface.ts_resol = PCW_TSRESOL_MICRO;
    status = pcw_ng_iface_options(block, &iface);
    if (status != PCW_OK)
        return status;
    status = pcw_iface_add(&reader->mem, &reader->ifaces, &iface);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    block->kind = PCW_KIND_INTERFACE;
    block->interface_id = reader->ifaces.count - 1;
    block->linktype = iface.linktype;
    block->snaplen = iface.snaplen;
    block->ts_resol = iface.ts_resol;
    block->ts_offset = iface.ts_offset;
    return PCW_OK;
}

static int pcw_ng_epb_packet(pcw_reader_t *reader, const unsigned char *body, size_t caplen)
{
    pcw_block_t *block = &reader->block;
    uint32_t interface_id;
    int status;

    interface_id = block->type == PCW_BLOCK_PB ? pcw_rd16(body, reader->big_endian) : pcw_rd32(body, reader->big_endian);
    status = pcw_ng_bind(reader, interface_id, pcw_ng_ts(reader, body + 4));
    if (status != PCW_OK)
        return status;
    block->kind = PCW_KIND_PACKET;
    block->orig_len = pcw_rd32(body + 16, reader->big_endian);
    block->data = body + PCW_EPB_FIXED;
    block->data_len = caplen;
    return PCW_OK;
}

static int pcw_ng_epb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    size_t caplen;
    size_t opts;
    int status;

    if (body_len < PCW_EPB_FIXED)
        return PCW_ERR_FORMAT;
    caplen = pcw_rd32(body + 12, reader->big_endian);
    if (caplen > body_len - PCW_EPB_FIXED)
        return PCW_ERR_FORMAT;
    status = pcw_ng_epb_packet(reader, body, caplen);
    if (status != PCW_OK)
        return status;
    opts = PCW_EPB_FIXED + caplen + pcw_pad4(caplen);
    if (opts > body_len)
        opts = body_len;
    return pcw_ng_options(reader, body + opts, body_len - opts);
}

static int pcw_ng_spb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    pcw_block_t *block = &reader->block;
    size_t caplen;
    int status;

    if (body_len < PCW_SPB_FIXED)
        return PCW_ERR_FORMAT;
    status = pcw_ng_bind(reader, 0, 0);
    if (status != PCW_OK)
        return status;
    block->kind = PCW_KIND_PACKET;
    block->flags |= PCW_FLAG_NO_TIMESTAMP;
    block->ts_sec = 0;
    block->ts_nsec = 0;
    block->orig_len = pcw_rd32(body, reader->big_endian);
    caplen = body_len - PCW_SPB_FIXED;
    if (block->orig_len < caplen)
        caplen = (size_t)block->orig_len;
    if (block->snaplen != 0 && block->snaplen < caplen)
        caplen = block->snaplen;
    block->data = body + PCW_SPB_FIXED;
    block->data_len = caplen;
    return PCW_OK;
}

static int pcw_ng_nrb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    pcw_block_t *block = &reader->block;
    size_t used;
    int status = pcw_tlv_check(body, body_len, reader->big_endian, &used);

    if (status != PCW_OK)
        return status;
    block->kind = PCW_KIND_NAMES;
    block->data = body;
    block->data_len = used;
    return pcw_ng_options(reader, body + used, body_len - used);
}

static int pcw_ng_isb(pcw_reader_t *reader, const unsigned char *body, size_t body_len)
{
    int status;

    if (body_len < PCW_ISB_FIXED)
        return PCW_ERR_FORMAT;
    status = pcw_ng_bind(reader, pcw_rd32(body, reader->big_endian), pcw_ng_ts(reader, body + 4));
    if (status != PCW_OK)
        return status;
    reader->block.kind = PCW_KIND_STATS;
    return pcw_ng_options(reader, body + PCW_ISB_FIXED, body_len - PCW_ISB_FIXED);
}

static int pcw_ng_dispatch(pcw_reader_t *reader, uint32_t type, const unsigned char *body, size_t body_len)
{
    if (type == PCW_BLOCK_SHB)
        return pcw_ng_shb(reader, body, body_len);
    pcw_ng_common(reader, type, body, body_len);
    switch (type) {
    case PCW_BLOCK_IDB:
        return pcw_ng_idb(reader, body, body_len);
    case PCW_BLOCK_EPB:
    case PCW_BLOCK_PB:
        return pcw_ng_epb(reader, body, body_len);
    case PCW_BLOCK_SPB:
        return pcw_ng_spb(reader, body, body_len);
    case PCW_BLOCK_NRB:
        return pcw_ng_nrb(reader, body, body_len);
    case PCW_BLOCK_ISB:
        return pcw_ng_isb(reader, body, body_len);
    default:
        reader->block.kind = PCW_KIND_OTHER;
        return PCW_OK;
    }
}

static int pcw_ng_header(pcw_reader_t *reader, uint32_t *out_type, uint32_t *out_len)
{
    const unsigned char *src = reader->data + reader->pos;

    if (pcw_rd32(src, 0) == PCW_BLOCK_SHB) {
        if (pcw_rd32(src + 8, 0) == PCW_SHB_MAGIC)
            reader->big_endian = 0;
        else if (pcw_rd32(src + 8, 1) == PCW_SHB_MAGIC)
            reader->big_endian = 1;
        else
            return PCW_ERR_FORMAT;
    } else if (reader->section_count == 0) {
        return PCW_ERR_FORMAT;
    }
    *out_type = pcw_rd32(src, reader->big_endian);
    *out_len = pcw_rd32(src + 4, reader->big_endian);
    if (*out_len < PCW_BLOCK_MIN_LEN || (*out_len & 3) != 0)
        return PCW_ERR_FORMAT;
    return PCW_OK;
}

static int pcw_ng_truncated_packet(pcw_reader_t *reader, uint32_t type, const unsigned char *body, size_t body_len)
{
    size_t caplen;

    pcw_ng_common(reader, type, body, body_len);
    if (type == PCW_BLOCK_SPB)
        return body_len >= PCW_SPB_FIXED ? pcw_ng_spb(reader, body, body_len) : PCW_ERR_FORMAT;
    if ((type != PCW_BLOCK_EPB && type != PCW_BLOCK_PB) || body_len < PCW_EPB_FIXED)
        return PCW_ERR_FORMAT;
    caplen = pcw_rd32(body + 12, reader->big_endian);
    if (caplen > body_len - PCW_EPB_FIXED)
        caplen = body_len - PCW_EPB_FIXED;
    if (pcw_ng_epb_packet(reader, body, caplen) != PCW_OK)
        return PCW_ERR_FORMAT;
    reader->block.options = NULL;
    reader->block.options_len = 0;
    return PCW_OK;
}

static int pcw_ng_truncated(pcw_reader_t *reader, uint32_t type)
{
    size_t avail = reader->end - reader->pos;
    const unsigned char *body = reader->data + reader->pos + 8;

    if (pcw_ng_truncated_packet(reader, type, body, avail - 8) != PCW_OK)
        return pcw_stop_trailing(reader);
    reader->block.flags |= PCW_FLAG_TRUNCATED;
    pcw_consume(reader, avail);
    reader->fatal = PCW_END;
    return PCW_OK;
}

static int pcw_ng_oversize(pcw_reader_t *reader, uint32_t type, uint32_t len)
{
    int status;

    if (type == PCW_BLOCK_SHB || type == PCW_BLOCK_IDB)
        return pcw_stop(reader, PCW_ERR_LIMIT);
    status = pcw_skip(reader, len);
    if (status == PCW_OK)
        return PCW_ERR_LIMIT;
    return pcw_stop(reader, status);
}

int pcw_read_pcapng_block(pcw_reader_t *reader)
{
    uint32_t type;
    uint32_t len;
    const unsigned char *src;
    int status = pcw_fill(reader, PCW_BLOCK_MIN_LEN);

    if (status == PCW_END)
        return pcw_stop_trailing(reader);
    if (status == PCW_OK)
        status = pcw_ng_header(reader, &type, &len);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    if (reader->stream && len > reader->max_block_len)
        return pcw_ng_oversize(reader, type, len);
    status = pcw_fill(reader, len);
    if (status == PCW_END)
        return pcw_ng_truncated(reader, type);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    src = reader->data + reader->pos;
    if (pcw_rd32(src + len - 4, reader->big_endian) != len)
        return pcw_stop(reader, PCW_ERR_FORMAT);
    status = pcw_ng_dispatch(reader, type, src + 8, len - PCW_BLOCK_MIN_LEN);
    pcw_consume(reader, len);
    return status;
}
