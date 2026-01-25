#include "test_util.h"

#define MAX_BLOCKS 64
#define PATH_LEN 1024

static uint32_t kind_of(const char *name, size_t len)
{
    static const struct {
        const char *name;
        uint32_t kind;
    } names[] = {
        {"SHB", PCW_KIND_SECTION}, {"IDB", PCW_KIND_INTERFACE}, {"EPB", PCW_KIND_PACKET},
        {"SPB", PCW_KIND_PACKET}, {"PB", PCW_KIND_PACKET}, {"NRB", PCW_KIND_NAMES},
        {"ISB", PCW_KIND_STATS}, {"CB", PCW_KIND_OTHER}, {"DCB", PCW_KIND_OTHER},
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (strlen(names[i].name) == len && memcmp(names[i].name, name, len) == 0)
            return names[i].kind;
    }
    return 0;
}

static size_t expected_kinds(const char *txt_path, uint32_t *kinds)
{
    size_t len;
    char *text = (char *)load_file(txt_path, &len);
    char *cursor;
    size_t count = 0;
    size_t word;

    text[len] = '\0';
    cursor = strstr(text, "Block sequence:");
    CHECK(cursor != NULL);
    cursor += strlen("Block sequence:");
    while (*cursor != '\0' && *cursor != '\n' && *cursor != '\r') {
        cursor += strspn(cursor, " ,\t");
        word = strcspn(cursor, " ,\t\r\n");
        if (word == 0)
            break;
        CHECK(count < MAX_BLOCKS);
        kinds[count] = kind_of(cursor, word);
        CHECK(kinds[count] != 0);
        count++;
        cursor += word;
    }
    free(text);
    return count;
}

static void check_sequence(const unsigned char *data, size_t len, const uint32_t *kinds, size_t count)
{
    pcw_reader_t *reader = open_mem_reader(data, len);
    const pcw_block_t *block;
    size_t i;

    for (i = 0; i < count; i++) {
        CHECK_STATUS(pcw_reader_next(reader, &block), PCW_OK);
        CHECK(block->kind == kinds[i]);
    }
    CHECK_STATUS(pcw_reader_next(reader, &block), PCW_END);
    CHECK(pcw_reader_trailing(reader) == 0);
    pcw_reader_destroy(reader);
}

static void check_stream(const unsigned char *data, size_t len, size_t chunk)
{
    pcw_reader_t *mem = open_mem_reader(data, len);
    pcw_reader_t *stream = NULL;
    source_t src = {data, len, 0, chunk};

    CHECK_STATUS(pcw_reader_create(NULL, NULL, NULL, &stream), PCW_OK);
    CHECK_STATUS(pcw_reader_set_limits(stream, 4096, 16), PCW_OK);
    CHECK_STATUS(pcw_reader_open_stream(stream, source_read, &src), PCW_OK);
    compare_readers(mem, stream);
    pcw_reader_destroy(stream);
    pcw_reader_destroy(mem);
}

static void check_roundtrip(const unsigned char *data, size_t len)
{
    membuf_t copy = {NULL, 0, 0};
    pcw_reader_t *original;
    pcw_reader_t *copied;

    copy_capture(data, len, PCW_FORMAT_PCAPNG, &copy);
    CHECK(same_bytes(copy.data, copy.len, data, len));
    original = open_mem_reader(data, len);
    copied = open_mem_reader(copy.data, copy.len);
    compare_readers(original, copied);
    pcw_reader_destroy(copied);
    pcw_reader_destroy(original);
    free(copy.data);
}

static void check_file(const char *dir, const char *name)
{
    char path[PATH_LEN];
    uint32_t kinds[MAX_BLOCKS];
    unsigned char *data;
    size_t len;
    size_t count;

    CHECK(snprintf(path, sizeof(path), "%s/%s", dir, name) < (int)sizeof(path));
    data = load_file(path, &len);
    memcpy(path + strlen(path) - strlen("pcapng"), "txt", 4);
    count = expected_kinds(path, kinds);
    check_sequence(data, len, kinds, count);
    check_stream(data, len, 1);
    check_stream(data, len, 13);
    check_roundtrip(data, len);
    free(data);
}

int main(int argc, char **argv)
{
    char dir[PATH_LEN];
    char line[PATH_LEN];
    FILE *manifest;
    int files = 0;

    CHECK(argc == 2);
    CHECK(snprintf(dir, sizeof(dir), "%s/pcapng-test-generator", argv[1]) < (int)sizeof(dir));
    CHECK(snprintf(line, sizeof(line), "%s/MANIFEST", dir) < (int)sizeof(line));
    manifest = fopen(line, "r");
    CHECK(manifest != NULL);
    while (fgets(line, sizeof(line), manifest) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;
        check_file(dir, line);
        files++;
    }
    fclose(manifest);
    CHECK(files == 48);
    printf("corpus: %d files ok\n", files);
    return 0;
}
