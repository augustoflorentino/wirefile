#include "wirefile/wirefile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                    \
        }                                                               \
    } while (0)

typedef struct {
    int remaining;
    int live;
} failing_alloc_t;

static void *failing_alloc(void *ctx, size_t size)
{
    failing_alloc_t *fa = ctx;

    if (fa->remaining-- == 0)
        return NULL;
    fa->live++;
    return malloc(size);
}

static void failing_free(void *ctx, void *ptr)
{
    failing_alloc_t *fa = ctx;

    fa->live--;
    free(ptr);
}

static int count_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    (void)piece;
    (void)piece_len;
    (*(int *)ctx)++;
    return 0;
}

static void test_append(void)
{
    pcw_buf_t *buf = NULL;

    CHECK(pcw_buf_create(NULL, NULL, NULL, &buf) == PCW_OK);
    CHECK(pcw_buf_append(buf, (const unsigned char *)"abc", 3) == PCW_OK);
    CHECK(pcw_buf_append(buf, NULL, 0) == PCW_OK);
    CHECK(pcw_buf_len(buf) == 3);
    CHECK(memcmp(pcw_buf_data(buf), "abc", 3) == 0);
    pcw_buf_destroy(buf);
}

static void test_split(void)
{
    pcw_buf_t *buf = NULL;
    int pieces = 0;

    CHECK(pcw_buf_create(NULL, NULL, NULL, &buf) == PCW_OK);
    CHECK(pcw_buf_append(buf, (const unsigned char *)"a\nbb\n\nc", 7) == PCW_OK);
    CHECK(pcw_buf_split(buf, '\n', count_piece, &pieces) == PCW_OK);
    CHECK(pieces == 4);
    pcw_buf_destroy(buf);
}

static void test_bad_args(void)
{
    pcw_buf_t *buf = NULL;

    CHECK(pcw_buf_create(failing_alloc, NULL, NULL, &buf) == PCW_ERR_ARG);
    CHECK(pcw_buf_create(NULL, NULL, NULL, NULL) == PCW_ERR_ARG);
    CHECK(pcw_buf_append(NULL, NULL, 0) == PCW_ERR_ARG);
    CHECK(pcw_buf_split(NULL, '\n', count_piece, NULL) == PCW_ERR_ARG);
    CHECK(pcw_strerror(-1) != NULL);
    pcw_buf_destroy(NULL);
}

static int run_with_failure(failing_alloc_t *fa)
{
    pcw_buf_t *buf = NULL;
    int status;
    int i;

    status = pcw_buf_create(failing_alloc, failing_free, fa, &buf);
    for (i = 0; i < 100 && status == PCW_OK; i++)
        status = pcw_buf_append(buf, (const unsigned char *)"abcdefgh", 8);
    pcw_buf_destroy(buf);
    return status;
}

static void test_alloc_failure(void)
{
    int n;

    for (n = 0;; n++) {
        failing_alloc_t fa = {n, 0};
        int status = run_with_failure(&fa);

        CHECK(fa.live == 0);
        if (status == PCW_OK)
            break;
        CHECK(status == PCW_ERR_NOMEM);
    }
    CHECK(n > 1);
}

int main(void)
{
    test_append();
    test_split();
    test_bad_args();
    test_alloc_failure();
    return 0;
}
