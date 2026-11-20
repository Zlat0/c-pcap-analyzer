#ifndef PA_CORE_VEC_H
#define PA_CORE_VEC_H

#include <stddef.h>

#include "core/status.h"

typedef struct {
    void *data;
    size_t len, cap, elem_size;
} pa_vec_t;

/** Prepares an empty vector; storage is owned by the vector (release with pa_vec_free). */
void pa_vec_init(pa_vec_t *v, size_t elem_size);
pa_status_t pa_vec_reserve(pa_vec_t *v, size_t cap);
/** Copies *elem into the vector. */
pa_status_t pa_vec_push(pa_vec_t *v, const void *elem);
void *pa_vec_at(const pa_vec_t *v, size_t i);
/** Grows (zero-filled) or shrinks the vector to n elements. */
pa_status_t pa_vec_resize_zero(pa_vec_t *v, size_t n);
void pa_vec_truncate(pa_vec_t *v, size_t n);
/** Deep-copies src into dst, replacing any previous content of dst. */
pa_status_t pa_vec_copy(const pa_vec_t *src, pa_vec_t *dst);
void pa_vec_free(pa_vec_t *v);

#endif
