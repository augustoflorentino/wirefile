#include <wirefile/wirefile.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int packets_only;
    int in_memory;
    size_t limit;
    const char *path;
} options_t;

static const char *kind_name(uint32_t kind)
{
    static const char *const names[] = {"?", "section", "interface", "packet", "names", "stats", "other"};

    return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "?";
}

static int file_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    *out_read = fread(buf, 1, buf_len, ctx);
    return ferror((FILE *)ctx) ? -1 : 0;
}

static void print_hex(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static void print_packet_line(const pcw_block_t *block)
{
    if (!(block->flags & PCW_FLAG_NO_TIMESTAMP))
        printf("%lld.%09u", (long long)block->ts_sec, (unsigned)block->ts_nsec);
    printf("\t%zu\t%llu\t", block->data_len, (unsigned long long)block->orig_len);
    print_hex(block->data, block->data_len);
    printf("\n");
}

static void print_options(const pcw_block_t *block)
{
    size_t pos = 0;
    uint16_t code;
    const unsigned char *value;
    size_t value_len;

    while (pcw_option_next(block, &pos, &code, &value, &value_len) == PCW_OK) {
        printf("  option %u (%zu bytes): ", (unsigned)code, value_len);
        print_hex(value, value_len);
        printf("\n");
    }
}

static void print_block(const pcw_block_t *block)
{
    uint32_t fcs_bits;

    printf("%s type=0x%08x section=%u if=%u linktype=%u snaplen=%u flags=0x%x", kind_name(block->kind), (unsigned)block->type, (unsigned)block->section, (unsigned)block->interface_id, (unsigned)block->linktype, (unsigned)block->snaplen, (unsigned)block->flags);
    if (block->kind == PCW_KIND_PACKET || block->kind == PCW_KIND_STATS)
        printf(" ts=%lld.%09u", (long long)block->ts_sec, (unsigned)block->ts_nsec);
    if (block->kind == PCW_KIND_PACKET)
        printf(" caplen=%zu len=%llu", block->data_len, (unsigned long long)block->orig_len);
    if (pcw_block_fcs_len(block, &fcs_bits) == PCW_OK)
        printf(" fcs=%u", (unsigned)fcs_bits);
    printf("\n");
    print_options(block);
}

static int dump(pcw_reader_t *reader, const options_t *opts)
{
    const pcw_block_t *block;
    uint64_t last_offset = UINT64_MAX;
    int status;

    while ((status = pcw_reader_next(reader, &block)) != PCW_END) {
        if (status != PCW_OK) {
            fprintf(stderr, "pcwdump: %s at offset %llu\n", pcw_strerror(status), (unsigned long long)pcw_reader_offset(reader));
            if (pcw_reader_offset(reader) == last_offset)
                return 1;
            last_offset = pcw_reader_offset(reader);
            continue;
        }
        if (block->kind == PCW_KIND_PACKET && opts->packets_only)
            print_packet_line(block);
        else if (!opts->packets_only)
            print_block(block);
    }
    if (pcw_reader_trailing(reader) > 0)
        fprintf(stderr, "pcwdump: %zu trailing bytes ignored\n", pcw_reader_trailing(reader));
    return 0;
}

static unsigned char *load_file(FILE *file, size_t *out_len)
{
    unsigned char *data = NULL;
    long size;

    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0)
        return NULL;
    data = malloc(size > 0 ? (size_t)size : 1);
    if (data != NULL && fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        return NULL;
    }
    *out_len = (size_t)size;
    return data;
}

static int parse_args(int argc, char **argv, options_t *opts)
{
    int i;

    memset(opts, 0, sizeof(*opts));
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--packets") == 0)
            opts->packets_only = 1;
        else if (strcmp(argv[i], "--mem") == 0)
            opts->in_memory = 1;
        else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc)
            opts->limit = strtoul(argv[++i], NULL, 10);
        else if (opts->path == NULL)
            opts->path = argv[i];
        else
            return -1;
    }
    return opts->path ? 0 : -1;
}

static int open_reader(pcw_reader_t *reader, const options_t *opts, FILE *file, unsigned char **out_data)
{
    size_t len = 0;

    if (opts->limit > 0 && pcw_reader_set_limits(reader, opts->limit, 1024) != PCW_OK)
        return PCW_ERR_ARG;
    if (!opts->in_memory)
        return pcw_reader_open_stream(reader, file_read, file);
    *out_data = load_file(file, &len);
    if (*out_data == NULL)
        return PCW_ERR_IO;
    return pcw_reader_open_mem(reader, *out_data, len);
}

int main(int argc, char **argv)
{
    options_t opts;
    pcw_reader_t *reader = NULL;
    unsigned char *data = NULL;
    FILE *file;
    int status;
    int rc;

    if (parse_args(argc, argv, &opts) != 0) {
        fprintf(stderr, "usage: pcwdump [--packets] [--mem] [--limit BYTES] FILE\n");
        return 2;
    }
    file = fopen(opts.path, "rb");
    if (file == NULL) {
        perror(opts.path);
        return 1;
    }
    status = pcw_reader_create(NULL, NULL, NULL, &reader);
    if (status == PCW_OK)
        status = open_reader(reader, &opts, file, &data);
    rc = status == PCW_OK ? dump(reader, &opts) : 1;
    if (status != PCW_OK)
        fprintf(stderr, "pcwdump: %s\n", pcw_strerror(status));
    pcw_reader_destroy(reader);
    free(data);
    fclose(file);
    return rc;
}
