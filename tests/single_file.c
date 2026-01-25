#define PCW_IMPLEMENTATION
#include "wirefile.h"

static int count_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    (void)piece;
    (void)piece_len;
    (*(int *)ctx)++;
    return 0;
}

int main(void)
{
    pcw_buf_t *buf = NULL;
    int pieces = 0;
    int status;

    status = pcw_buf_create(NULL, NULL, NULL, &buf);
    if (status == PCW_OK)
        status = pcw_buf_append(buf, (const unsigned char *)"a\nb", 3);
    if (status == PCW_OK)
        status = pcw_buf_split(buf, '\n', count_piece, &pieces);
    if (pcw_buf_len(buf) != 3 || pcw_buf_data(buf) == NULL || pcw_strerror(status) == NULL)
        status = PCW_ERR_ARG;
    pcw_buf_destroy(buf);
    return status == PCW_OK && pieces == 2 ? 0 : 1;
}
