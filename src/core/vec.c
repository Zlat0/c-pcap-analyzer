#include "core/vec.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void pa_vec_init(pa_vec_t *v, size_t elem_size) {
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
    v->elem_size = elem_size;
}

pa_status_t pa_vec_reserve(pa_vec_t *v, size_t cap) {
    size_t ncap;
    void *nd;

    if (cap <= v->cap) {
        return PA_OK;
    }
    ncap = v->cap ? v->cap : 16;
    while (ncap < cap) {
        ncap *= 2;
    }
    if (v->elem_size == 0 || ncap > SIZE_MAX / v->elem_size) {
        return PA_ERR_NOMEM;
    }
    nd = realloc(v->data, ncap * v->elem_size);
    if (!nd) {
        return PA_ERR_NOMEM;
    }
    v->data = nd;
    v->cap = ncap;
    return PA_OK;
}

void *pa_vec_at(const pa_vec_t *v, size_t i) { return (char *)v->data + i * v->elem_size; }

pa_status_t pa_vec_push(pa_vec_t *v, const void *elem) {
    pa_status_t st = pa_vec_reserve(v, v->len + 1);
    if (st != PA_OK) {
        return st;
    }
    memcpy(pa_vec_at(v, v->len), elem, v->elem_size);
    v->len++;
    return PA_OK;
}

pa_status_t pa_vec_resize_zero(pa_vec_t *v, size_t n) {
    pa_status_t st = pa_vec_reserve(v, n);
    if (st != PA_OK) {
        return st;
    }
    if (n > v->len) {
        memset(pa_vec_at(v, v->len), 0, (n - v->len) * v->elem_size);
    }
    v->len = n;
    return PA_OK;
}

void pa_vec_truncate(pa_vec_t *v, size_t n) {
    if (n < v->len) {
        v->len = n;
    }
}

pa_status_t pa_vec_copy(const pa_vec_t *src, pa_vec_t *dst) {
    pa_status_t st;

    pa_vec_free(dst);
    pa_vec_init(dst, src->elem_size);
    if (src->len == 0) {
        return PA_OK;
    }
    st = pa_vec_reserve(dst, src->len);
    if (st != PA_OK) {
        return st;
    }
    memcpy(dst->data, src->data, src->len * src->elem_size);
    dst->len = src->len;
    return PA_OK;
}

void pa_vec_free(pa_vec_t *v) {
    if (!v) {
        return;
    }
    free(v->data);
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
}
