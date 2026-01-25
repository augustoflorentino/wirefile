#ifndef WIREFILE_H
#define WIREFILE_H

#include <stddef.h>

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
#define PCW_ERR_ARG 1
#define PCW_ERR_NOMEM 2

typedef struct pcw_buf pcw_buf_t;

typedef void *(*pcw_alloc_fn)(void *ctx, size_t size);
typedef void (*pcw_free_fn)(void *ctx, void *ptr);
typedef int (*pcw_piece_fn)(void *ctx, const unsigned char *piece, size_t piece_len);

PCW_API int pcw_buf_create(pcw_alloc_fn alloc_fn, pcw_free_fn free_fn, void *alloc_ctx, pcw_buf_t **out_buf);
PCW_API void pcw_buf_destroy(pcw_buf_t *buf);
PCW_API int pcw_buf_append(pcw_buf_t *buf, const unsigned char *data, size_t data_len);
PCW_API size_t pcw_buf_len(const pcw_buf_t *buf);
PCW_API const unsigned char *pcw_buf_data(const pcw_buf_t *buf);
PCW_API int pcw_buf_split(const pcw_buf_t *buf, unsigned char sep, pcw_piece_fn piece_fn, void *piece_ctx);
PCW_API const char *pcw_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
