#ifndef WIREFILE_H
#define WIREFILE_H

#include <stddef.h>
#include <stdint.h>

#if defined(PCW_STATIC) && defined(__GNUC__)
#define PCW_API static __attribute__((unused))
#elif defined(PCW_STATIC)
#define PCW_API static
#elif defined(_WIN32) && defined(PCW_BUILD_SHARED)
#define PCW_API __declspec(dllexport)
#elif defined(_WIN32) && defined(PCW_SHARED)
#define PCW_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(PCW_BUILD_SHARED)
#define PCW_API __attribute__((visibility("default")))
#else
#define PCW_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PCW_OK 0
#define PCW_END 1
#define PCW_ERR_ARG (-1)
#define PCW_ERR_NOMEM (-2)
#define PCW_ERR_IO (-3)
#define PCW_ERR_FORMAT (-4)
#define PCW_ERR_LIMIT (-5)
#define PCW_ERR_STATE (-6)

#define PCW_FORMAT_PCAP 1u
#define PCW_FORMAT_PCAPNG 2u

#define PCW_KIND_SECTION 1u
#define PCW_KIND_INTERFACE 2u
#define PCW_KIND_PACKET 3u
#define PCW_KIND_NAMES 4u
#define PCW_KIND_STATS 5u
#define PCW_KIND_OTHER 6u

#define PCW_BLOCK_SHB 0x0A0D0D0Au
#define PCW_BLOCK_IDB 0x00000001u
#define PCW_BLOCK_PB 0x00000002u
#define PCW_BLOCK_SPB 0x00000003u
#define PCW_BLOCK_NRB 0x00000004u
#define PCW_BLOCK_ISB 0x00000005u
#define PCW_BLOCK_EPB 0x00000006u

#define PCW_FLAG_TRUNCATED 0x1u
#define PCW_FLAG_BIG_ENDIAN 0x2u
#define PCW_FLAG_NO_TIMESTAMP 0x4u

#define PCW_TSRESOL_MICRO 6u
#define PCW_TSRESOL_NANO 9u

#define PCW_OPT_END 0u
#define PCW_OPT_COMMENT 1u
#define PCW_OPT_SHB_HARDWARE 2u
#define PCW_OPT_SHB_OS 3u
#define PCW_OPT_SHB_USERAPPL 4u
#define PCW_OPT_IF_NAME 2u
#define PCW_OPT_IF_DESCRIPTION 3u
#define PCW_OPT_IF_SPEED 8u
#define PCW_OPT_IF_TSRESOL 9u
#define PCW_OPT_IF_TZONE 10u
#define PCW_OPT_IF_FILTER 11u
#define PCW_OPT_IF_OS 12u
#define PCW_OPT_IF_FCSLEN 13u
#define PCW_OPT_IF_TSOFFSET 14u
#define PCW_OPT_IF_HARDWARE 15u
#define PCW_OPT_IF_TXSPEED 16u
#define PCW_OPT_IF_RXSPEED 17u
#define PCW_OPT_EPB_FLAGS 2u
#define PCW_OPT_EPB_HASH 3u
#define PCW_OPT_EPB_DROPCOUNT 4u
#define PCW_OPT_EPB_PACKETID 5u
#define PCW_OPT_EPB_QUEUE 6u
#define PCW_OPT_EPB_PROCESSID_THREADID 8u

#define PCW_EPB_INBOUND 0x1u
#define PCW_EPB_OUTBOUND 0x2u

#define PCW_NAME_END 0u
#define PCW_NAME_IPV4 1u
#define PCW_NAME_IPV6 2u
#define PCW_NAME_EUI48 3u
#define PCW_NAME_EUI64 4u

#define PCW_LINKTYPE_ETHERNET 1u
#define PCW_LINKTYPE_USER0 147u
#define PCW_LINKTYPE_USER15 162u
#define PCW_LINKTYPE_BLUETOOTH_HCI_H4 187u
#define PCW_LINKTYPE_USB_LINUX 189u
#define PCW_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR 201u
#define PCW_LINKTYPE_USB_LINUX_MMAPPED 220u
#define PCW_LINKTYPE_USBPCAP 249u

typedef struct pcw_reader pcw_reader_t;
typedef struct pcw_writer pcw_writer_t;

typedef void *(*pcw_alloc_fn)(void *ctx, size_t size);
typedef void (*pcw_free_fn)(void *ctx, void *ptr);
typedef int (*pcw_read_fn)(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read);
typedef int (*pcw_write_fn)(void *ctx, const unsigned char *data, size_t data_len);

typedef struct pcw_block {
    uint32_t kind;
    uint32_t type;
    uint32_t format;
    uint32_t flags;
    uint32_t section;
    uint32_t interface_id;
    uint32_t linktype;
    uint32_t snaplen;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t ts_resol;
    int64_t ts_offset;
    uint64_t ts_raw;
    int64_t ts_sec;
    uint32_t ts_nsec;
    uint32_t reserved;
    uint64_t orig_len;
    int64_t section_len;
    const unsigned char *data;
    size_t data_len;
    const unsigned char *options;
    size_t options_len;
    const unsigned char *body;
    size_t body_len;
} pcw_block_t;

typedef struct pcw_option {
    uint16_t code;
    const void *value;
    size_t value_len;
} pcw_option_t;

PCW_API int pcw_reader_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_reader_t **out_reader);
PCW_API void pcw_reader_destroy(pcw_reader_t *reader);
PCW_API int pcw_reader_set_limits(pcw_reader_t *reader, size_t max_block_len, uint32_t max_interfaces);
PCW_API int pcw_reader_open_stream(pcw_reader_t *reader, pcw_read_fn read_fn, void *read_ctx);
PCW_API int pcw_reader_open_mem(pcw_reader_t *reader, const void *data, size_t data_len);
PCW_API int pcw_reader_next(pcw_reader_t *reader, const pcw_block_t **out_block);
PCW_API uint64_t pcw_reader_offset(const pcw_reader_t *reader);
PCW_API size_t pcw_reader_trailing(const pcw_reader_t *reader);
PCW_API int pcw_reader_error(const pcw_reader_t *reader);

PCW_API int pcw_option_next(const pcw_block_t *block, size_t *io_pos, uint16_t *out_code, const unsigned char **out_value, size_t *out_value_len);
PCW_API int pcw_option_find(const pcw_block_t *block, uint16_t code, const unsigned char **out_value, size_t *out_value_len);
PCW_API int pcw_name_next(const pcw_block_t *block, size_t *io_pos, uint16_t *out_type, const unsigned char **out_value, size_t *out_value_len);
PCW_API int pcw_block_fcs_len(const pcw_block_t *block, uint32_t *out_bits);
PCW_API uint16_t pcw_get_u16(const pcw_block_t *block, const unsigned char *src);
PCW_API uint32_t pcw_get_u32(const pcw_block_t *block, const unsigned char *src);
PCW_API uint64_t pcw_get_u64(const pcw_block_t *block, const unsigned char *src);

PCW_API int pcw_writer_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_writer_t **out_writer);
PCW_API void pcw_writer_destroy(pcw_writer_t *writer);
PCW_API int pcw_writer_open(pcw_writer_t *writer, uint32_t format, pcw_write_fn write_fn, void *write_ctx);
PCW_API int pcw_writer_section(pcw_writer_t *writer, const pcw_option_t *options, size_t options_count);
PCW_API int pcw_writer_add_interface(pcw_writer_t *writer, uint32_t linktype, uint32_t snaplen, uint32_t ts_resol, const pcw_option_t *options, size_t options_count, uint32_t *out_interface_id);
PCW_API int pcw_writer_packet(pcw_writer_t *writer, uint32_t interface_id, int64_t ts_sec, uint32_t ts_nsec, const void *data, size_t data_len, uint64_t orig_len, const pcw_option_t *options, size_t options_count);
PCW_API int pcw_writer_block(pcw_writer_t *writer, const pcw_block_t *block);
PCW_API uint64_t pcw_writer_offset(const pcw_writer_t *writer);

PCW_API const char *pcw_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
