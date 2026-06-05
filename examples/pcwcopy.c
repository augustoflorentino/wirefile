#include <wirefile/wirefile.h>

#include <stdio.h>
#include <string.h>

static int file_read(void *ctx, unsigned char *buf, size_t buf_len, size_t *out_read)
{
    *out_read = fread(buf, 1, buf_len, ctx);
    return ferror((FILE *)ctx) ? -1 : 0;
}

static int file_write(void *ctx, const unsigned char *data, size_t data_len)
{
    return fwrite(data, 1, data_len, ctx) == data_len ? 0 : -1;
}

static int copy_blocks(pcw_reader_t *reader, pcw_writer_t *writer)
{
    const pcw_block_t *block;
    int skipped = 0;
    int status;

    while ((status = pcw_reader_next(reader, &block)) != PCW_END) {
        if (status != PCW_OK) {
            fprintf(stderr, "pcwcopy: %s at offset %llu, block skipped\n", pcw_strerror(status), (unsigned long long)pcw_reader_offset(reader));
            skipped = 1;
            continue;
        }
        status = pcw_writer_block(writer, block);
        if (status != PCW_OK)
            return status;
    }
    status = pcw_reader_error(reader);
    if (status == PCW_OK && skipped)
        status = PCW_ERR_FORMAT;
    return status;
}

static int copy_file(FILE *in, FILE *out, uint32_t format)
{
    pcw_reader_t *reader = NULL;
    pcw_writer_t *writer = NULL;
    int status;

    status = pcw_reader_create(NULL, NULL, NULL, &reader);
    if (status == PCW_OK)
        status = pcw_reader_open_stream(reader, file_read, in);
    if (status == PCW_OK)
        status = pcw_writer_create(NULL, NULL, NULL, &writer);
    if (status == PCW_OK)
        status = pcw_writer_open(writer, format, file_write, out);
    if (status == PCW_OK)
        status = copy_blocks(reader, writer);
    pcw_writer_destroy(writer);
    pcw_reader_destroy(reader);
    return status;
}

int main(int argc, char **argv)
{
    uint32_t format;
    FILE *in;
    FILE *out;
    int status;

    if (argc != 4 || (strcmp(argv[1], "pcap") != 0 && strcmp(argv[1], "pcapng") != 0)) {
        fprintf(stderr, "usage: pcwcopy pcap|pcapng IN OUT\n");
        return 2;
    }
    format = strcmp(argv[1], "pcap") == 0 ? PCW_FORMAT_PCAP : PCW_FORMAT_PCAPNG;
    in = fopen(argv[2], "rb");
    out = in ? fopen(argv[3], "wb") : NULL;
    if (in == NULL || out == NULL) {
        perror(in ? argv[3] : argv[2]);
        if (in)
            fclose(in);
        return 1;
    }
    status = copy_file(in, out, format);
    fclose(in);
    if (fclose(out) != 0 && status == PCW_OK)
        status = PCW_ERR_IO;
    if (status != PCW_OK) {
        fprintf(stderr, "pcwcopy: %s\n", pcw_strerror(status));
        return 1;
    }
    return 0;
}
