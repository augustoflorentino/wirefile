#include "wirefile_internal.h"

#include <string.h>

int pcw_writer_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_writer_t **out_writer)
{
    pcw_mem_t mem;
    pcw_writer_t *writer;

    if (out_writer == NULL)
        return PCW_ERR_ARG;
    *out_writer = NULL;
    if (pcw_mem_init(&mem, alloc_fn, free_fn, alloc_ctx) != PCW_OK)
        return PCW_ERR_ARG;
    writer = mem.alloc_fn(mem.ctx, sizeof(*writer));
    if (writer == NULL)
        return PCW_ERR_NOMEM;
    memset(writer, 0, sizeof(*writer));
    writer->mem = mem;
    writer->ifaces.max = UINT32_MAX / 2;
    *out_writer = writer;
    return PCW_OK;
}

void pcw_writer_destroy(pcw_writer_t *writer)
{
    if (writer == NULL)
        return;
    pcw_iface_free(&writer->mem, &writer->ifaces);
    writer->mem.free_fn(writer->mem.ctx, writer);
}

int pcw_writer_open(pcw_writer_t *writer, uint32_t format, pcw_write_fn write_fn, void *write_ctx)
{
    if (writer == NULL || write_fn == NULL || (format != PCW_FORMAT_PCAP && format != PCW_FORMAT_PCAPNG))
        return PCW_ERR_ARG;
    if (writer->opened)
        return PCW_ERR_STATE;
    writer->format = format;
    writer->write_fn = write_fn;
    writer->write_ctx = write_ctx;
    writer->big_endian = pcw_host_big_endian();
    writer->opened = 1;
    return PCW_OK;
}

uint64_t pcw_writer_offset(const pcw_writer_t *writer)
{
    return writer ? writer->offset : 0;
}

static int pcw_writer_ready(const pcw_writer_t *writer)
{
    if (writer == NULL)
        return PCW_ERR_ARG;
    if (!writer->opened)
        return PCW_ERR_STATE;
    return writer->status;
}

static int pcw_pcap_resol(uint32_t ts_resol)
{
    return ts_resol == PCW_TSRESOL_MICRO || ts_resol == PCW_TSRESOL_NANO;
}

static int pcw_writer_pcap_iface(pcw_writer_t *writer, const pcw_iface_t *iface)
{
    int status;

    if (writer->started)
        return PCW_ERR_STATE;
    if (!pcw_pcap_resol(iface->ts_resol) || iface->linktype > UINT16_MAX)
        return PCW_ERR_ARG;
    status = pcw_iface_add(&writer->mem, &writer->ifaces, iface);
    if (status != PCW_OK)
        return status;
    writer->started = 1;
    return pcw_write_pcap_header(writer, iface);
}

static int pcw_writer_begin_section(pcw_writer_t *writer, const pcw_block_t *block)
{
    writer->ifaces.count = 0;
    writer->started = 1;
    return pcw_write_shb(writer, block);
}

static int pcw_writer_ng_iface(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_optlist_t *list, const pcw_block_t *block)
{
    int status;

    if (iface->linktype > UINT16_MAX)
        return PCW_ERR_ARG;
    if (!writer->started) {
        status = pcw_writer_begin_section(writer, NULL);
        if (status != PCW_OK)
            return status;
    }
    status = pcw_iface_add(&writer->mem, &writer->ifaces, iface);
    if (status != PCW_OK)
        return status;
    return pcw_write_idb(writer, iface, list, block);
}

static int pcw_writer_ng_iface_converted(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_block_t *block)
{
    int status;

    if (iface->linktype > UINT16_MAX)
        return PCW_ERR_ARG;
    status = pcw_iface_add(&writer->mem, &writer->ifaces, iface);
    if (status != PCW_OK)
        return status;
    return pcw_write_idb_converted(writer, iface, block);
}

static int pcw_writer_ng_copy_iface(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_block_t *block)
{
    unsigned char bits = (unsigned char)iface->fcs_bits;
    pcw_option_t fcs = {PCW_OPT_IF_FCSLEN, &bits, 1};
    pcw_optlist_t list = {PCW_BLOCK_IDB, &fcs, 0};

    list.count = iface->has_fcs && iface->fcs_bits <= UINT8_MAX;
    return pcw_writer_ng_iface(writer, iface, &list, block);
}

int pcw_writer_add_interface(pcw_writer_t *writer, uint32_t linktype, uint32_t snaplen, uint32_t ts_resol, const pcw_option_t *options, size_t options_count, uint32_t *out_interface_id)
{
    pcw_optlist_t list = {PCW_BLOCK_IDB, options, options_count};
    const pcw_option_t *fcs;
    pcw_iface_t iface = {0};
    int status = pcw_writer_ready(writer);

    if (status != PCW_OK)
        return status;
    if (!pcw_ts_resol_valid(ts_resol) || pcw_optlist_user_check(&list) != PCW_OK)
        return PCW_ERR_ARG;
    iface.linktype = linktype;
    iface.snaplen = snaplen;
    iface.ts_resol = ts_resol;
    if (pcw_optlist_find(&list, PCW_OPT_IF_FCSLEN, &fcs) == PCW_OK) {
        iface.has_fcs = 1;
        iface.fcs_bits = *(const unsigned char *)fcs->value;
    }
    if (writer->format == PCW_FORMAT_PCAP)
        status = pcw_writer_pcap_iface(writer, &iface);
    else
        status = pcw_writer_ng_iface(writer, &iface, &list, NULL);
    if (status == PCW_OK && out_interface_id != NULL)
        *out_interface_id = writer->ifaces.count - 1;
    return status;
}

int pcw_writer_units(const pcw_iface_t *iface, const pcw_block_t *block, uint64_t *out_units)
{
    if (block->format != 0 && block->ts_resol == iface->ts_resol && block->ts_offset == iface->ts_offset) {
        *out_units = block->ts_raw;
        return PCW_OK;
    }
    return pcw_ts_join(block->ts_sec, block->ts_nsec, iface->ts_resol, iface->ts_offset, out_units);
}

static int pcw_writer_ng_packet(pcw_writer_t *writer, uint32_t interface_id, uint64_t units, const pcw_block_t *block, const pcw_optlist_t *list)
{
    int same_order = block->format == PCW_FORMAT_PCAPNG && ((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == writer->big_endian;
    int truncated = (block->flags & PCW_FLAG_TRUNCATED) != 0;

    if (block->format == PCW_FORMAT_PCAPNG && block->type == PCW_BLOCK_SPB && interface_id == 0)
        return pcw_write_spb(writer, block);
    if (block->type == PCW_BLOCK_PB && same_order && !truncated)
        return pcw_write_raw(writer, PCW_BLOCK_PB, block->body, block->body_len);
    if (block->format == PCW_FORMAT_PCAPNG && !same_order && !truncated)
        return pcw_write_epb_converted(writer, interface_id, units, block);
    return pcw_write_epb(writer, interface_id, units, block, list);
}

static int pcw_writer_put_packet(pcw_writer_t *writer, uint32_t interface_id, const pcw_block_t *block, const pcw_optlist_t *list)
{
    const pcw_iface_t *iface = pcw_iface_get(&writer->ifaces, interface_id);
    uint64_t units;
    int status;

    if (iface == NULL)
        return PCW_ERR_ARG;
    if (block->data == NULL && block->data_len > 0)
        return PCW_ERR_ARG;
    status = pcw_writer_units(iface, block, &units);
    if (status != PCW_OK)
        return status;
    if (writer->format == PCW_FORMAT_PCAP)
        return pcw_write_pcap_record(writer, units, block->data, block->data_len, block->orig_len);
    return pcw_writer_ng_packet(writer, interface_id, units, block, list);
}

int pcw_writer_packet(pcw_writer_t *writer, uint32_t interface_id, int64_t ts_sec, uint32_t ts_nsec, const void *data, size_t data_len, uint64_t orig_len, const pcw_option_t *options, size_t options_count)
{
    pcw_optlist_t list = {PCW_BLOCK_EPB, options, options_count};
    pcw_block_t block = {0};
    int status = pcw_writer_ready(writer);

    if (status != PCW_OK)
        return status;
    if (orig_len < data_len || pcw_optlist_user_check(&list) != PCW_OK)
        return PCW_ERR_ARG;
    block.kind = PCW_KIND_PACKET;
    block.ts_sec = ts_sec;
    block.ts_nsec = ts_nsec;
    block.data = data;
    block.data_len = data_len;
    block.orig_len = orig_len;
    return pcw_writer_put_packet(writer, interface_id, &block, &list);
}

static pcw_iface_t pcw_iface_of(const pcw_block_t *block)
{
    pcw_iface_t iface = {0};

    iface.linktype = block->linktype;
    iface.snaplen = block->snaplen;
    iface.ts_resol = block->ts_resol;
    iface.ts_offset = block->ts_offset;
    iface.has_fcs = pcw_block_fcs_len(block, &iface.fcs_bits) == PCW_OK;
    return iface;
}

static int pcw_writer_pcap_section(pcw_writer_t *writer, const pcw_block_t *block)
{
    pcw_iface_t iface = pcw_iface_of(block);
    int status;

    if (block->format != PCW_FORMAT_PCAP)
        return PCW_OK;
    if (writer->started)
        return PCW_ERR_STATE;
    if (block->body == NULL || block->body_len != PCW_PCAP_HEADER_LEN || !pcw_pcap_resol(iface.ts_resol))
        return pcw_writer_pcap_iface(writer, &iface);
    status = pcw_iface_add(&writer->mem, &writer->ifaces, &iface);
    if (status != PCW_OK)
        return status;
    writer->big_endian = (block->flags & PCW_FLAG_BIG_ENDIAN) != 0;
    writer->started = 1;
    return pcw_emit(writer, block->body, block->body_len);
}

static int pcw_writer_ng_section(pcw_writer_t *writer, const pcw_block_t *block)
{
    pcw_iface_t iface = pcw_iface_of(block);
    int status;

    if (block->format == PCW_FORMAT_PCAPNG)
        return pcw_writer_begin_section(writer, block);
    status = pcw_writer_begin_section(writer, NULL);
    if (status != PCW_OK)
        return status;
    iface.ts_offset = 0;
    return pcw_writer_ng_copy_iface(writer, &iface, NULL);
}

static int pcw_writer_interface(pcw_writer_t *writer, const pcw_block_t *block)
{
    pcw_iface_t iface = pcw_iface_of(block);
    int same_order = block->format == PCW_FORMAT_PCAPNG && ((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == writer->big_endian;

    if (writer->format == PCW_FORMAT_PCAPNG) {
        if (!writer->started)
            return PCW_ERR_STATE;
        if (same_order)
            return pcw_writer_ng_copy_iface(writer, &iface, block);
        iface.ts_offset = 0;
        if (block->format != PCW_FORMAT_PCAPNG)
            return pcw_writer_ng_copy_iface(writer, &iface, NULL);
        return pcw_writer_ng_iface_converted(writer, &iface, block);
    }
    if (writer->started)
        return writer->ifaces.items[0].linktype == iface.linktype ? PCW_OK : PCW_ERR_FORMAT;
    if (!pcw_pcap_resol(iface.ts_resol))
        iface.ts_resol = PCW_TSRESOL_NANO;
    iface.ts_offset = 0;
    return pcw_writer_pcap_iface(writer, &iface);
}

static int pcw_writer_extra(pcw_writer_t *writer, const pcw_block_t *block)
{
    int same_order = block->format == PCW_FORMAT_PCAPNG && ((block->flags & PCW_FLAG_BIG_ENDIAN) != 0) == writer->big_endian;

    if (writer->format == PCW_FORMAT_PCAP || block->format != PCW_FORMAT_PCAPNG)
        return PCW_OK;
    if (!writer->started)
        return PCW_ERR_STATE;
    if (!same_order)
        return pcw_write_extra_converted(writer, block);
    return pcw_write_raw(writer, block->type, block->body, block->body_len);
}

int pcw_writer_block(pcw_writer_t *writer, const pcw_block_t *block)
{
    int status = pcw_writer_ready(writer);

    if (status != PCW_OK)
        return status;
    if (block == NULL)
        return PCW_ERR_ARG;
    switch (block->kind) {
    case PCW_KIND_SECTION:
        if (writer->format == PCW_FORMAT_PCAP)
            return pcw_writer_pcap_section(writer, block);
        return pcw_writer_ng_section(writer, block);
    case PCW_KIND_INTERFACE:
        return pcw_writer_interface(writer, block);
    case PCW_KIND_PACKET:
        if (!writer->started)
            return PCW_ERR_STATE;
        return pcw_writer_put_packet(writer, writer->format == PCW_FORMAT_PCAP ? 0 : block->interface_id, block, NULL);
    default:
        return pcw_writer_extra(writer, block);
    }
}
