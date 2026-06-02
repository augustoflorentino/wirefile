#include "wirefile_internal.h"

#include <string.h>

#define PCW_PCAP_VERSION_MAJOR 2u
#define PCW_PCAP_VERSION_MINOR 4u
#define PCW_ZEROS_LEN 64u

int pcw_emit(pcw_writer_t *writer, const void *data, size_t data_len)
{
    if (data_len == 0)
        return PCW_OK;
    if (writer->write_fn(writer->write_ctx, data, data_len) != 0) {
        writer->status = PCW_ERR_IO;
        return PCW_ERR_IO;
    }
    writer->offset += data_len;
    return PCW_OK;
}

int pcw_emit_zeros(pcw_writer_t *writer, size_t len)
{
    static const unsigned char zeros[PCW_ZEROS_LEN];
    size_t take;
    int status = PCW_OK;

    while (len > 0 && status == PCW_OK) {
        take = len < PCW_ZEROS_LEN ? len : PCW_ZEROS_LEN;
        status = pcw_emit(writer, zeros, take);
        len -= take;
    }
    return status;
}

static uint32_t pcw_pcap_linktype_field(const pcw_iface_t *iface)
{
    if (!iface->has_fcs || iface->fcs_bits % 16 != 0 || iface->fcs_bits / 16 > 15)
        return iface->linktype;
    return iface->linktype | 0x04000000u | (iface->fcs_bits / 16) << 28;
}

int pcw_write_pcap_header(pcw_writer_t *writer, const pcw_iface_t *iface)
{
    unsigned char header[PCW_PCAP_HEADER_LEN] = {0};
    int big = writer->big_endian;

    pcw_wr32(header, iface->ts_resol == PCW_TSRESOL_NANO ? 0xA1B23C4Du : 0xA1B2C3D4u, big);
    pcw_wr16(header + 4, PCW_PCAP_VERSION_MAJOR, big);
    pcw_wr16(header + 6, PCW_PCAP_VERSION_MINOR, big);
    pcw_wr32(header + 16, iface->snaplen, big);
    pcw_wr32(header + 20, pcw_pcap_linktype_field(iface), big);
    return pcw_emit(writer, header, sizeof(header));
}

int pcw_write_pcap_record(pcw_writer_t *writer, uint64_t units, const unsigned char *data, size_t data_len, uint64_t orig_len)
{
    unsigned char header[PCW_PCAP_RECORD_LEN];
    uint64_t scale = pcw_pow10(writer->ifaces.items[0].ts_resol);
    int big = writer->big_endian;
    int status;

    if (units / scale > UINT32_MAX || data_len > UINT32_MAX || orig_len > UINT32_MAX)
        return PCW_ERR_ARG;
    pcw_wr32(header, (uint32_t)(units / scale), big);
    pcw_wr32(header + 4, (uint32_t)(units % scale), big);
    pcw_wr32(header + 8, (uint32_t)data_len, big);
    pcw_wr32(header + 12, (uint32_t)orig_len, big);
    status = pcw_emit(writer, header, sizeof(header));
    if (status == PCW_OK)
        status = pcw_emit(writer, data, data_len);
    return status;
}

static int pcw_write_framed(pcw_writer_t *writer, uint32_t type, const unsigned char *fixed, size_t fixed_len, const unsigned char *data, size_t data_len, const unsigned char *opts, size_t opts_len, const pcw_optlist_t *list)
{
    unsigned char word[8];
    size_t list_len;
    uint64_t total;
    int status = pcw_optlist_check(list, &list_len);

    if (status != PCW_OK)
        return status;
    total = (uint64_t)12u + fixed_len + data_len + pcw_pad4(data_len) + opts_len + pcw_pad4(opts_len) + list_len;
    if (total > UINT32_MAX)
        return PCW_ERR_ARG;
    pcw_wr32(word, type, writer->big_endian);
    pcw_wr32(word + 4, (uint32_t)total, writer->big_endian);
    status = pcw_emit(writer, word, 8);
    if (status == PCW_OK)
        status = pcw_emit(writer, fixed, fixed_len);
    if (status == PCW_OK)
        status = pcw_emit(writer, data, data_len);
    if (status == PCW_OK)
        status = pcw_emit_zeros(writer, pcw_pad4(data_len));
    if (status == PCW_OK)
        status = pcw_emit(writer, opts, opts_len);
    if (status == PCW_OK)
        status = pcw_emit_zeros(writer, pcw_pad4(opts_len));
    if (status == PCW_OK)
        status = pcw_optlist_emit(writer, list);
    if (status == PCW_OK)
        status = pcw_emit(writer, word + 4, 4);
    return status;
}

static int pcw_same_order(const pcw_writer_t *writer, const pcw_block_t *block)
{
    return block != NULL && block->format == PCW_FORMAT_PCAPNG && ((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == writer->big_endian;
}

int pcw_write_shb(pcw_writer_t *writer, const pcw_block_t *block, const pcw_optlist_t *list)
{
    unsigned char fixed[16];
    int copy = block != NULL && block->format == PCW_FORMAT_PCAPNG;
    int big;

    writer->big_endian = copy ? (block->flags & PCW_FLAG_BIG_ENDIAN) != 0 : pcw_host_big_endian();
    big = writer->big_endian;
    pcw_wr32(fixed, PCW_SHB_MAGIC, big);
    pcw_wr16(fixed + 4, 1, big);
    pcw_wr16(fixed + 6, copy ? block->version_minor : 0, big);
    pcw_wr64(fixed + 8, copy ? (uint64_t)block->section_len : UINT64_MAX, big);
    if (!copy)
        return pcw_write_framed(writer, PCW_BLOCK_SHB, fixed, sizeof(fixed), NULL, 0, NULL, 0, list);
    return pcw_write_framed(writer, PCW_BLOCK_SHB, fixed, sizeof(fixed), NULL, 0, block->options, block->options_len, NULL);
}

static int pcw_write_idb_fresh(pcw_writer_t *writer, const unsigned char *fixed, const pcw_iface_t *iface, const pcw_optlist_t *list)
{
    pcw_optlist_t all = {PCW_BLOCK_IDB, NULL, 0};
    pcw_option_t *items;
    size_t given = list != NULL ? list->count : 0;
    size_t unused;
    unsigned char resol = (unsigned char)iface->ts_resol;
    int status = pcw_optlist_check(list, &unused);

    if (status != PCW_OK)
        return status;
    items = writer->mem.alloc_fn(writer->mem.ctx, (given + 1) * sizeof(*items));
    if (items == NULL)
        return PCW_ERR_NOMEM;
    if (given > 0)
        memcpy(items, list->items, given * sizeof(*items));
    all.items = items;
    all.count = given;
    if (iface->ts_resol != PCW_TSRESOL_MICRO) {
        items[given].code = PCW_OPT_IF_TSRESOL;
        items[given].value = &resol;
        items[given].value_len = 1;
        all.count++;
    }
    status = pcw_write_framed(writer, PCW_BLOCK_IDB, fixed, 8, NULL, 0, NULL, 0, &all);
    writer->mem.free_fn(writer->mem.ctx, items);
    return status;
}

int pcw_write_idb(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_optlist_t *list, const pcw_block_t *block)
{
    unsigned char fixed[8] = {0};

    if (iface->linktype > UINT16_MAX)
        return PCW_ERR_ARG;
    pcw_wr16(fixed, (uint16_t)iface->linktype, writer->big_endian);
    pcw_wr32(fixed + 4, iface->snaplen, writer->big_endian);
    if (pcw_same_order(writer, block))
        return pcw_write_framed(writer, PCW_BLOCK_IDB, fixed, sizeof(fixed), NULL, 0, block->options, block->options_len, NULL);
    return pcw_write_idb_fresh(writer, fixed, iface, list);
}

int pcw_write_epb(pcw_writer_t *writer, uint32_t interface_id, uint64_t units, const pcw_block_t *block, const pcw_optlist_t *list)
{
    unsigned char fixed[20];
    int big = writer->big_endian;
    int keep_options = pcw_same_order(writer, block) && !(block->flags & PCW_FLAG_TRUNCATED);

    if (block->data_len > UINT32_MAX || block->orig_len > UINT32_MAX)
        return PCW_ERR_ARG;
    pcw_wr32(fixed, interface_id, big);
    pcw_wr32(fixed + 4, (uint32_t)(units >> 32), big);
    pcw_wr32(fixed + 8, (uint32_t)(units & 0xffffffffu), big);
    pcw_wr32(fixed + 12, (uint32_t)block->data_len, big);
    pcw_wr32(fixed + 16, (uint32_t)block->orig_len, big);
    if (!keep_options)
        return pcw_write_framed(writer, PCW_BLOCK_EPB, fixed, sizeof(fixed), block->data, block->data_len, NULL, 0, list);
    return pcw_write_framed(writer, PCW_BLOCK_EPB, fixed, sizeof(fixed), block->data, block->data_len, block->options, block->options_len, NULL);
}

int pcw_write_spb(pcw_writer_t *writer, const pcw_block_t *block)
{
    unsigned char fixed[4];

    if (block->orig_len > UINT32_MAX)
        return PCW_ERR_ARG;
    pcw_wr32(fixed, (uint32_t)block->orig_len, writer->big_endian);
    return pcw_write_framed(writer, PCW_BLOCK_SPB, fixed, sizeof(fixed), block->data, block->data_len, NULL, 0, NULL);
}

int pcw_write_listed(pcw_writer_t *writer, uint32_t type, const unsigned char *fixed, size_t fixed_len, const unsigned char *data, size_t data_len, const pcw_optlist_t *list)
{
    return pcw_write_framed(writer, type, fixed, fixed_len, data, data_len, NULL, 0, list);
}

int pcw_write_raw(pcw_writer_t *writer, uint32_t type, const unsigned char *body, size_t body_len)
{
    return pcw_write_framed(writer, type, NULL, 0, body, body_len, NULL, 0, NULL);
}
