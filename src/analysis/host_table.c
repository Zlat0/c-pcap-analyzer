#include "analysis/host_table.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "core/hash.h"

#define PA_WSET_MIN_CAP 64
#define PA_HOST_MIN_CAP 64
#define PA_RATE_BINS 8

int pa_wset_add(pa_window_set_t *s, uint64_t key, uint16_t port, double ts, double window_sec) {
    size_t mask;
    size_t i;

    key |= 1ULL; /* 0 marks an empty slot */
    if (s->count > 0 && (ts - s->start_ts > window_sec || ts < s->start_ts)) {
        memset(s->e, 0, s->cap * sizeof *s->e);
        s->count = 0;
    }
    if (s->count == 0) {
        s->start_ts = ts;
    }
    if ((s->count + 1) * 2 > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : PA_WSET_MIN_CAP;
        pa_wentry_t *ne = calloc(ncap, sizeof *ne);

        if (!ne) {
            return -1;
        }
        for (size_t j = 0; j < s->cap; j++) {
            if (s->e[j].key) {
                size_t k = (size_t)pa_hash_mix(s->e[j].key) & (ncap - 1);
                while (ne[k].key) {
                    k = (k + 1) & (ncap - 1);
                }
                ne[k] = s->e[j];
            }
        }
        free(s->e);
        s->e = ne;
        s->cap = ncap;
    }
    mask = s->cap - 1;
    i = (size_t)pa_hash_mix(key) & mask;
    while (s->e[i].key) {
        if (s->e[i].key == key) {
            return 0;
        }
        i = (i + 1) & mask;
    }
    s->e[i].key = key;
    s->e[i].port = port;
    s->e[i].ts = ts;
    s->count++;
    return 1;
}

size_t pa_wset_count_port(const pa_window_set_t *s, uint16_t port) {
    size_t n = 0;

    for (size_t i = 0; i < s->cap; i++) {
        if (s->e[i].key && s->e[i].port == port) {
            n++;
        }
    }
    return n;
}

void pa_wset_free(pa_window_set_t *s) {
    free(s->e);
    s->e = NULL;
    s->cap = s->count = 0;
}

uint32_t pa_rate_add(pa_rate_t *r, double ts) {
    int64_t sec = (int64_t)floor(ts);
    int64_t base = (int64_t)r->base_ts;

    if (base == 0) {
        base = sec;
    }
    if (sec > base) {
        if (sec - base >= PA_RATE_BINS) {
            memset(r->bins, 0, sizeof r->bins);
        } else {
            for (int64_t s = base + 1; s <= sec; s++) {
                r->bins[s % PA_RATE_BINS] = 0;
            }
        }
        base = sec;
    } else if (base - sec >= PA_RATE_BINS) {
        return 0; /* too old to account */
    }
    r->base_ts = (double)base;
    r->bins[sec % PA_RATE_BINS]++;
    return r->bins[sec % PA_RATE_BINS];
}

struct pa_host_table {
    pa_host_stats_t **slots;
    size_t cap, count;
};

static size_t addr_slot(pa_host_stats_t *const *slots, size_t cap, const pa_addr_t *a) {
    uint64_t h = pa_hash_bytes(&a->family, 1, PA_HASH_SEED);
    size_t mask = cap - 1;
    size_t i;

    h = pa_hash_mix(pa_hash_bytes(a->bytes, sizeof a->bytes, h));
    i = (size_t)h & mask;
    while (slots[i] && !(slots[i]->addr.family == a->family &&
                         memcmp(slots[i]->addr.bytes, a->bytes, sizeof a->bytes) == 0)) {
        i = (i + 1) & mask;
    }
    return i;
}

pa_status_t pa_host_table_create(size_t initial_cap, pa_host_table_t **out) {
    pa_host_table_t *t;
    size_t cap = PA_HOST_MIN_CAP;

    if (!out) {
        return PA_ERR_ARGS;
    }
    while (cap < initial_cap) {
        cap <<= 1;
    }
    t = calloc(1, sizeof *t);
    if (!t) {
        return PA_ERR_NOMEM;
    }
    t->slots = calloc(cap, sizeof *t->slots);
    if (!t->slots) {
        free(t);
        return PA_ERR_NOMEM;
    }
    t->cap = cap;
    *out = t;
    return PA_OK;
}

static pa_status_t grow(pa_host_table_t *t) {
    size_t ncap = t->cap * 2;
    pa_host_stats_t **ns = calloc(ncap, sizeof *ns);

    if (!ns) {
        return PA_ERR_NOMEM;
    }
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i]) {
            ns[addr_slot(ns, ncap, &t->slots[i]->addr)] = t->slots[i];
        }
    }
    free(t->slots);
    t->slots = ns;
    t->cap = ncap;
    return PA_OK;
}

pa_status_t pa_host_table_get_or_insert(pa_host_table_t *t, const pa_addr_t *addr,
                                        pa_host_stats_t **out) {
    size_t i;
    pa_host_stats_t *h;

    if (!t || !addr || !out) {
        return PA_ERR_ARGS;
    }
    i = addr_slot(t->slots, t->cap, addr);
    if (t->slots[i]) {
        *out = t->slots[i];
        return PA_OK;
    }
    if ((t->count + 1) * 10 > t->cap * 7) {
        if (grow(t) != PA_OK) {
            return PA_ERR_NOMEM;
        }
        i = addr_slot(t->slots, t->cap, addr);
    }
    h = calloc(1, sizeof *h);
    if (!h) {
        return PA_ERR_NOMEM;
    }
    h->addr = *addr;
    t->slots[i] = h;
    t->count++;
    *out = h;
    return PA_OK;
}

pa_host_stats_t *pa_host_table_lookup(const pa_host_table_t *t, const pa_addr_t *addr) {
    return t->slots[addr_slot(t->slots, t->cap, addr)];
}

void pa_host_table_foreach(const pa_host_table_t *t, void (*fn)(const pa_host_stats_t *, void *),
                           void *ud) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i]) {
            fn(t->slots[i], ud);
        }
    }
}

size_t pa_host_table_size(const pa_host_table_t *t) { return t->count; }

void pa_host_table_destroy(pa_host_table_t *t) {
    if (!t) {
        return;
    }
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i]) {
            pa_wset_free(&t->slots[i]->dst_ports);
            pa_wset_free(&t->slots[i]->dst_hosts);
            free(t->slots[i]);
        }
    }
    free(t->slots);
    free(t);
}
