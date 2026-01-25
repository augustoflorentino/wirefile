#include "wirefile_internal.h"

#define PCW_PCAP_MAGIC_MICRO 0xA1B2C3D4u
#define PCW_PCAP_MAGIC_NANO 0xA1B23C4Du
#define PCW_PCAP_LINKTYPE_MASK 0x03FFFFFFu

static int pcw_pcap_magic(const unsigned char *src, int *out_big_endian, uint32_t *out_ts_resol)
{
    uint32_t magic;
    int big;

    for (big = 0; big <= 1; big++) {
        magic = pcw_rd32(src, big);
        if (magic != PCW_PCAP_MAGIC_MICRO && magic != PCW_PCAP_MAGIC_NANO)
            continue;
        *out_big_endian = big;
        *out_ts_resol = magic == PCW_PCAP_MAGIC_MICRO ? PCW_TSRESOL_MICRO : PCW_TSRESOL_NANO;
        return PCW_OK;
    }
    return PCW_ERR_FORMAT;
}

static void pcw_pcap_section(pcw_reader_t *reader, const unsigned char *src, uint32_t ts_resol)
{
    pcw_block_t *block = &reader->block;
    int big = reader->big_endian;

    block->kind = PCW_KIND_SECTION;
    block->format = PCW_FORMAT_PCAP;
    block->flags = big ? PCW_FLAG_BIG_ENDIAN : 0;
    block->version_major = pcw_rd16(src + 4, big);
    block->version_minor = pcw_rd16(src + 6, big);
    block->snaplen = pcw_rd32(src + 16, big);
    block->linktype = pcw_rd32(src + 20, big) & PCW_PCAP_LINKTYPE_MASK;
    block->ts_resol = ts_resol;
    block->section_len = -1;
    block->body = src;
    block->body_len = PCW_PCAP_HEADER_LEN;
}

int pcw_read_pcap_header(pcw_reader_t *reader)
{
    pcw_iface_t iface = {0};
    const unsigned char *src;
    uint32_t ts_resol;
    int status = pcw_fill(reader, PCW_PCAP_HEADER_LEN);

    if (status != PCW_OK)
        return pcw_stop(reader, status == PCW_END ? PCW_ERR_FORMAT : status);
    src = reader->data + reader->pos;
    if (pcw_pcap_magic(src, &reader->big_endian, &ts_resol) != PCW_OK)
        return pcw_stop(reader, PCW_ERR_FORMAT);
    reader->format = PCW_FORMAT_PCAP;
    reader->section_count = 1;
    pcw_pcap_section(reader, src, ts_resol);
    iface.linktype = reader->block.linktype;
    iface.snaplen = reader->block.snaplen;
    iface.ts_resol = ts_resol;
    status = pcw_iface_add(&reader->mem, &reader->ifaces, &iface);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    pcw_consume(reader, PCW_PCAP_HEADER_LEN);
    return PCW_OK;
}

static void pcw_pcap_packet(pcw_reader_t *reader, const unsigned char *src, size_t data_len)
{
    const pcw_iface_t *iface = pcw_iface_get(&reader->ifaces, 0);
    pcw_block_t *block = &reader->block;
    int big = reader->big_endian;
    uint64_t sec = pcw_rd32(src, big);

    block->kind = PCW_KIND_PACKET;
    block->format = PCW_FORMAT_PCAP;
    block->flags = big ? PCW_FLAG_BIG_ENDIAN : 0;
    block->linktype = iface->linktype;
    block->snaplen = iface->snaplen;
    block->ts_resol = iface->ts_resol;
    block->ts_raw = sec * pcw_pow10(iface->ts_resol) + pcw_rd32(src + 4, big);
    pcw_ts_split(block->ts_raw, iface->ts_resol, 0, &block->ts_sec, &block->ts_nsec);
    block->orig_len = pcw_rd32(src + 12, big);
    block->data = src + PCW_PCAP_RECORD_LEN;
    block->data_len = data_len;
    block->body = src;
    block->body_len = PCW_PCAP_RECORD_LEN + data_len;
}

static int pcw_pcap_truncated(pcw_reader_t *reader)
{
    size_t avail = reader->end - reader->pos;

    pcw_pcap_packet(reader, reader->data + reader->pos, avail - PCW_PCAP_RECORD_LEN);
    reader->block.flags |= PCW_FLAG_TRUNCATED;
    pcw_consume(reader, avail);
    reader->fatal = PCW_END;
    return PCW_OK;
}

int pcw_read_pcap_record(pcw_reader_t *reader)
{
    size_t total;
    int status = pcw_fill(reader, PCW_PCAP_RECORD_LEN);

    if (status == PCW_END)
        return pcw_stop_trailing(reader);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    total = PCW_PCAP_RECORD_LEN + (size_t)pcw_rd32(reader->data + reader->pos + 8, reader->big_endian);
    if (reader->stream && total > reader->max_block_len) {
        status = pcw_skip(reader, total);
        return status == PCW_OK ? PCW_ERR_LIMIT : pcw_stop(reader, status == PCW_END ? PCW_END : status);
    }
    status = pcw_fill(reader, total);
    if (status == PCW_END)
        return pcw_pcap_truncated(reader);
    if (status != PCW_OK)
        return pcw_stop(reader, status);
    pcw_pcap_packet(reader, reader->data + reader->pos, total - PCW_PCAP_RECORD_LEN);
    pcw_consume(reader, total);
    return PCW_OK;
}
