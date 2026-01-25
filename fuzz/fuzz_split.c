#include "wirefile/wirefile.h"

#include <stdint.h>

static int consume_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    size_t *total = ctx;

    *total += piece_len + (piece_len > 0 ? piece[0] : 0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pcw_buf_t *buf = NULL;
    size_t total = 0;

    if (pcw_buf_create(NULL, NULL, NULL, &buf) != PCW_OK)
        return 0;
    if (pcw_buf_append(buf, data, size) == PCW_OK && size > 0)
        pcw_buf_split(buf, data[0], consume_piece, &total);
    pcw_buf_destroy(buf);
    return 0;
}
