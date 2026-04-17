#ifndef WIREFILE_INTERNAL_H
#define WIREFILE_INTERNAL_H

#include "wirefile/wirefile.h"

#if defined(PCW_STATIC) && defined(__GNUC__)
#define PCW_LOCAL static __attribute__((unused))
#elif defined(PCW_STATIC)
#define PCW_LOCAL static
#else
#define PCW_LOCAL
#endif

#define PCW_PCAP_HEADER_LEN 24u
#define PCW_PCAP_RECORD_LEN 16u
#define PCW_BLOCK_MIN_LEN 12u
#define PCW_SHB_MAGIC 0x1A2B3C4Du
#define PCW_DEFAULT_MAX_BLOCK (512u * 1024u)
#define PCW_DEFAULT_MAX_INTERFACES 1024u

typedef struct pcw_mem {
    pcw_alloc_fn alloc_fn;
    pcw_free_fn free_fn;
    void *ctx;
} pcw_mem_t;

typedef struct pcw_iface {
    uint32_t linktype;
    uint32_t snaplen;
    uint32_t ts_resol;
    int64_t ts_offset;
    int has_fcs;
    uint32_t fcs_bits;
} pcw_iface_t;

typedef struct pcw_optlist {
    uint32_t block_type;
    const pcw_option_t *items;
    size_t count;
} pcw_optlist_t;

typedef struct pcw_iface_table {
    pcw_iface_t *items;
    uint32_t count;
    uint32_t cap;
    uint32_t max;
} pcw_iface_table_t;

struct pcw_reader {
    pcw_mem_t mem;
    pcw_read_fn read_fn;
    void *read_ctx;
    size_t max_block_len;
    unsigned char *buf;
    const unsigned char *data;
    size_t pos;
    size_t end;
    uint64_t offset;
    size_t trailing;
    int opened;
    int stream;
    int eof;
    int fatal;
    int big_endian;
    uint32_t format;
    uint32_t section_count;
    pcw_iface_table_t ifaces;
    pcw_block_t block;
};

struct pcw_writer {
    pcw_mem_t mem;
    pcw_write_fn write_fn;
    void *write_ctx;
    uint32_t format;
    int opened;
    int started;
    int big_endian;
    int status;
    uint64_t offset;
    pcw_iface_table_t ifaces;
};

PCW_LOCAL int pcw_mem_init(pcw_mem_t *mem, pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *ctx);
PCW_LOCAL uint16_t pcw_rd16(const unsigned char *src, int big_endian);
PCW_LOCAL uint32_t pcw_rd32(const unsigned char *src, int big_endian);
PCW_LOCAL uint64_t pcw_rd64(const unsigned char *src, int big_endian);
PCW_LOCAL void pcw_wr16(unsigned char *dst, uint16_t value, int big_endian);
PCW_LOCAL void pcw_wr32(unsigned char *dst, uint32_t value, int big_endian);
PCW_LOCAL void pcw_wr64(unsigned char *dst, uint64_t value, int big_endian);
PCW_LOCAL int pcw_host_big_endian(void);
PCW_LOCAL size_t pcw_pad4(size_t len);

PCW_LOCAL uint64_t pcw_pow10(uint32_t exp);
PCW_LOCAL int pcw_ts_resol_valid(uint32_t ts_resol);
PCW_LOCAL void pcw_ts_split(uint64_t units, uint32_t ts_resol, int64_t ts_offset, int64_t *out_sec, uint32_t *out_nsec);
PCW_LOCAL int pcw_ts_join(int64_t sec, uint32_t nsec, uint32_t ts_resol, int64_t ts_offset, uint64_t *out_units);

PCW_LOCAL int pcw_tlv_next(const unsigned char *area, size_t area_len, int big_endian, size_t *io_pos, uint16_t *out_code, const unsigned char **out_value, size_t *out_value_len);
PCW_LOCAL int pcw_tlv_check(const unsigned char *area, size_t area_len, int big_endian, size_t *out_used);

PCW_LOCAL int pcw_iface_add(const pcw_mem_t *mem, pcw_iface_table_t *table, const pcw_iface_t *iface);
PCW_LOCAL const pcw_iface_t *pcw_iface_get(const pcw_iface_table_t *table, uint32_t id);
PCW_LOCAL void pcw_iface_free(const pcw_mem_t *mem, pcw_iface_table_t *table);

PCW_LOCAL int pcw_fill(pcw_reader_t *reader, size_t need);
PCW_LOCAL void pcw_consume(pcw_reader_t *reader, size_t len);
PCW_LOCAL int pcw_skip(pcw_reader_t *reader, size_t len);
PCW_LOCAL int pcw_stop(pcw_reader_t *reader, int status);
PCW_LOCAL int pcw_stop_trailing(pcw_reader_t *reader);

PCW_LOCAL int pcw_read_pcap_header(pcw_reader_t *reader);
PCW_LOCAL int pcw_read_pcap_record(pcw_reader_t *reader);
PCW_LOCAL int pcw_read_pcapng_block(pcw_reader_t *reader);

PCW_LOCAL int pcw_emit(pcw_writer_t *writer, const void *data, size_t data_len);
PCW_LOCAL int pcw_emit_zeros(pcw_writer_t *writer, size_t len);
PCW_LOCAL int pcw_write_pcap_header(pcw_writer_t *writer, const pcw_iface_t *iface);
PCW_LOCAL int pcw_write_pcap_record(pcw_writer_t *writer, uint64_t units, const unsigned char *data, size_t data_len, uint64_t orig_len);
PCW_LOCAL int pcw_write_shb(pcw_writer_t *writer, const pcw_block_t *block);
PCW_LOCAL int pcw_write_idb(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_optlist_t *list, const pcw_block_t *block);
PCW_LOCAL int pcw_write_epb(pcw_writer_t *writer, uint32_t interface_id, uint64_t units, const pcw_block_t *block, const pcw_optlist_t *list);
PCW_LOCAL int pcw_write_spb(pcw_writer_t *writer, const pcw_block_t *block);
PCW_LOCAL int pcw_write_listed(pcw_writer_t *writer, uint32_t type, const unsigned char *fixed, size_t fixed_len, const unsigned char *data, size_t data_len, const pcw_optlist_t *list);
PCW_LOCAL int pcw_write_epb_converted(pcw_writer_t *writer, uint32_t interface_id, uint64_t units, const pcw_block_t *block);
PCW_LOCAL int pcw_write_idb_converted(pcw_writer_t *writer, const pcw_iface_t *iface, const pcw_block_t *block);
PCW_LOCAL int pcw_write_extra_converted(pcw_writer_t *writer, const pcw_block_t *block);
PCW_LOCAL int pcw_writer_units(const pcw_iface_t *iface, const pcw_block_t *block, uint64_t *out_units);
PCW_LOCAL int pcw_write_raw(pcw_writer_t *writer, uint32_t type, const unsigned char *body, size_t body_len);

PCW_LOCAL int pcw_optlist_user_check(const pcw_optlist_t *list);
PCW_LOCAL int pcw_optlist_check(const pcw_optlist_t *list, size_t *out_len);
PCW_LOCAL int pcw_optlist_emit(pcw_writer_t *writer, const pcw_optlist_t *list);
PCW_LOCAL int pcw_optlist_reorder(const pcw_mem_t *mem, const pcw_block_t *block, uint32_t block_type, int keep_times, pcw_optlist_t *out, void **out_mem);
PCW_LOCAL int pcw_optlist_find(const pcw_optlist_t *list, uint16_t code, const pcw_option_t **out_opt);

#endif
