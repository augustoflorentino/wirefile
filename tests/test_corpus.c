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

static int ignored_option(const pcw_block_t *block, uint16_t code)
{
    if (code == 2988 || code == 2989 || code == 19372 || code == 19373)
        return 1;
    if (block->kind == PCW_KIND_SECTION)
        return 0;
    if (block->kind == PCW_KIND_INTERFACE)
        return code > 18 || code == PCW_OPT_IF_TSOFFSET;
    if (block->kind == PCW_KIND_PACKET)
        return code > 8 || code == 7;
    if (block->kind == PCW_KIND_NAMES)
        return code > 4;
    return code > 8 || (block->ts_offset != 0 && (code == 2 || code == 3));
}

static int has_option(const pcw_block_t *block, uint16_t code, const unsigned char *value, size_t value_len)
{
    size_t pos = 0;
    uint16_t found;
    const unsigned char *found_value;
    size_t found_len;

    while (pcw_option_next(block, &pos, &found, &found_value, &found_len) == PCW_OK) {
        if (found == code && same_bytes(found_value, found_len, value, value_len))
            return 1;
    }
    return 0;
}

static size_t kept_options(const pcw_block_t *block, const pcw_block_t *other)
{
    size_t pos = 0;
    size_t kept = 0;
    uint16_t code;
    const unsigned char *value;
    size_t value_len;

    while (pcw_option_next(block, &pos, &code, &value, &value_len) == PCW_OK) {
        if (ignored_option(block, code))
            continue;
        CHECK(has_option(other, code, value, value_len));
        kept++;
    }
    return kept;
}

static int next_known_name(const pcw_block_t *block, size_t *pos, uint16_t *type, const unsigned char **value, size_t *value_len)
{
    int status;

    while ((status = pcw_name_next(block, pos, type, value, value_len)) == PCW_OK && (*type < 1 || *type > 4))
        continue;
    return status;
}

static void check_same_names(const pcw_block_t *want, const pcw_block_t *got)
{
    size_t want_pos = 0;
    size_t got_pos = 0;
    uint16_t want_type;
    uint16_t got_type;
    const unsigned char *want_value;
    const unsigned char *got_value;
    size_t want_len;
    size_t got_len;
    int status;

    while ((status = next_known_name(want, &want_pos, &want_type, &want_value, &want_len)) == PCW_OK) {
        CHECK_STATUS(next_known_name(got, &got_pos, &got_type, &got_value, &got_len), PCW_OK);
        CHECK(want_type == got_type && same_bytes(want_value, want_len, got_value, got_len));
    }
    CHECK_STATUS(next_known_name(got, &got_pos, &got_type, &got_value, &got_len), status);
}

static void check_same_content(const pcw_block_t *want, const pcw_block_t *got)
{
    CHECK(want->kind == got->kind && want->interface_id == got->interface_id);
    CHECK(want->linktype == got->linktype && want->snaplen == got->snaplen && want->ts_resol == got->ts_resol);
    CHECK(want->ts_sec == got->ts_sec && want->ts_nsec == got->ts_nsec && want->orig_len == got->orig_len);
    if (want->kind == PCW_KIND_NAMES)
        check_same_names(want, got);
    else
        CHECK(same_bytes(want->data, want->data_len, got->data, got->data_len));
    CHECK(kept_options(want, got) == kept_options(got, want));
}

static void write_cross_order(const unsigned char *le, size_t le_len, const unsigned char *be, size_t be_len, membuf_t *out)
{
    pcw_reader_t *le_reader = open_mem_reader(le, le_len);
    pcw_reader_t *be_reader = open_mem_reader(be, be_len);
    pcw_writer_t *writer = NULL;
    const pcw_block_t *le_block;
    const pcw_block_t *be_block;

    CHECK_STATUS(pcw_writer_create(NULL, NULL, NULL, &writer), PCW_OK);
    CHECK_STATUS(pcw_writer_open(writer, PCW_FORMAT_PCAPNG, membuf_write, out), PCW_OK);
    while (pcw_reader_next(le_reader, &le_block) == PCW_OK) {
        CHECK_STATUS(pcw_reader_next(be_reader, &be_block), PCW_OK);
        CHECK_STATUS(pcw_writer_block(writer, le_block->kind == PCW_KIND_SECTION ? le_block : be_block), PCW_OK);
    }
    pcw_writer_destroy(writer);
    pcw_reader_destroy(be_reader);
    pcw_reader_destroy(le_reader);
}

static void check_cross_order(const unsigned char *le, size_t le_len, const unsigned char *be, size_t be_len)
{
    membuf_t out = {NULL, 0, 0};
    pcw_reader_t *want;
    pcw_reader_t *got;
    const pcw_block_t *want_block;
    const pcw_block_t *got_block;

    write_cross_order(le, le_len, be, be_len, &out);
    want = open_mem_reader(le, le_len);
    got = open_mem_reader(out.data, out.len);
    while (pcw_reader_next(want, &want_block) == PCW_OK) {
        if (want_block->kind == PCW_KIND_OTHER)
            continue;
        CHECK_STATUS(pcw_reader_next(got, &got_block), PCW_OK);
        CHECK((got_block->flags & PCW_FLAG_BIG_ENDIAN) == (want_block->flags & PCW_FLAG_BIG_ENDIAN));
        check_same_content(want_block, got_block);
    }
    CHECK_STATUS(pcw_reader_next(got, &got_block), PCW_END);
    pcw_reader_destroy(got);
    pcw_reader_destroy(want);
    free(out.data);
}

static void check_pair(const char *dir, const char *name)
{
    char path[PATH_LEN];
    unsigned char *le;
    unsigned char *be;
    size_t le_len;
    size_t be_len;

    if (strncmp(name, "be/", 3) != 0)
        return;
    CHECK(snprintf(path, sizeof(path), "%s/%s", dir, name) < (int)sizeof(path));
    be = load_file(path, &be_len);
    CHECK(snprintf(path, sizeof(path), "%s/le/%s", dir, name + 3) < (int)sizeof(path));
    le = load_file(path, &le_len);
    check_cross_order(le, le_len, be, be_len);
    free(le);
    free(be);
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
        check_pair(dir, line);
        files++;
    }
    fclose(manifest);
    CHECK(files == 48);
    printf("corpus: %d files ok\n", files);
    return 0;
}
