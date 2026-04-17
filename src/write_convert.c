#include "wirefile_internal.h"

#include <string.h>

#define PCW_NAME_EUI48 3u
#define PCW_NAME_EUI64 4u

static void pcw_convert_free(pcw_writer_t *writer, void *mem)
{
    if (mem != NULL)
        writer->mem.free_fn(writer->mem.ctx, mem);
}

int pcw_write_epb_converted(pcw_writer_t *writer, uint32_t interface_id, uint64_t units, const pcw_block_t *block)
{
    pcw_optlist_t list;
    void *mem;
    int status = pcw_optlist_reorder(&writer->mem, block, PCW_BLOCK_EPB, 1, &list, &mem);

    if (status == PCW_OK)
        status = pcw_write_epb(writer, interface_id, units, block, &list);
    pcw_convert_free(writer, mem);
    return status;
}

int pcw_write_idb_converted(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_block_t *block)
{
    pcw_optlist_t list;
    void *mem;
    int status = pcw_optlist_reorder(&writer->mem, block, PCW_BLOCK_IDB, 1, &list, &mem);

    if (status == PCW_OK)
        status = pcw_write_idb(writer, iface, &list, NULL);
    pcw_convert_free(writer, mem);
    return status;
}

static int pcw_convert_isb(pcw_writer_t *writer, const pcw_block_t *block)
{
    const pcw_iface_t *iface = pcw_iface_get(&writer->ifaces, block->interface_id);
    unsigned char fixed[12];
    pcw_optlist_t list;
    uint64_t units;
    void *mem;
    int status;

    if (iface == NULL)
        return PCW_ERR_ARG;
    status = pcw_writer_units(iface, block, &units);
    if (status != PCW_OK)
        return status;
    status = pcw_optlist_reorder(&writer->mem, block, PCW_BLOCK_ISB, block->ts_resol == iface->ts_resol && block->ts_offset == iface->ts_offset, &list, &mem);
    if (status != PCW_OK)
        return status;
    pcw_wr32(fixed, block->interface_id, writer->big_endian);
    pcw_wr32(fixed + 4, (uint32_t)(units >> 32), writer->big_endian);
    pcw_wr32(fixed + 8, (uint32_t)(units & 0xffffffffu), writer->big_endian);
    status = pcw_write_listed(writer, PCW_BLOCK_ISB, fixed, sizeof(fixed), NULL, 0, &list);
    pcw_convert_free(writer, mem);
    return status;
}

static size_t pcw_convert_records(const pcw_writer_t *writer, const pcw_block_t *block, unsigned char *dst)
{
    size_t pos = 0;
    size_t used = 0;
    uint16_t type;
    const unsigned char *value;
    size_t value_len;

    while (pcw_name_next(block, &pos, &type, &value, &value_len) == PCW_OK) {
        if (type < PCW_NAME_IPV4 || type > PCW_NAME_EUI64)
            continue;
        pcw_wr16(dst + used, type, writer->big_endian);
        pcw_wr16(dst + used + 2, (uint16_t)value_len, writer->big_endian);
        memcpy(dst + used + 4, value, value_len);
        memset(dst + used + 4 + value_len, 0, pcw_pad4(value_len));
        used += 4 + value_len + pcw_pad4(value_len);
    }
    memset(dst + used, 0, 4);
    return used + 4;
}

static int pcw_convert_nrb(pcw_writer_t *writer, const pcw_block_t *block)
{
    unsigned char *records;
    pcw_optlist_t list;
    size_t records_len;
    void *mem;
    int status;

    if (block->data_len > SIZE_MAX - 4)
        return PCW_ERR_NOMEM;
    records = writer->mem.alloc_fn(writer->mem.ctx, block->data_len + 4);
    if (records == NULL)
        return PCW_ERR_NOMEM;
    records_len = pcw_convert_records(writer, block, records);
    status = pcw_optlist_reorder(&writer->mem, block, PCW_BLOCK_NRB, 1, &list, &mem);
    if (status == PCW_OK)
        status = pcw_write_listed(writer, PCW_BLOCK_NRB, NULL, 0, records, records_len, &list);
    pcw_convert_free(writer, mem);
    writer->mem.free_fn(writer->mem.ctx, records);
    return status;
}

int pcw_write_extra_converted(pcw_writer_t *writer, const pcw_block_t *block)
{
    if (block->type == PCW_BLOCK_ISB)
        return pcw_convert_isb(writer, block);
    if (block->type == PCW_BLOCK_NRB)
        return pcw_convert_nrb(writer, block);
    return PCW_OK;
}
