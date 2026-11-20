#include "flow/flow_table.h"

#include <stdlib.h>

#include "analysis/tcp_analyzer.h"
#include "core/vec.h"

#define PA_FLOW_MIN_CAP 16
#define PA_FLOW_LOAD_NUM 7
#define PA_FLOW_LOAD_DEN 10

struct pa_flow_table {
    pa_flow_t **slots; /* open addressing, never deleted from */
    size_t cap, count;
    uint64_t next_id;
    pa_vec_t retired; /* pa_flow_t*: closed flows whose key was reused */
};

static size_t round_pow2(size_t n) {
    size_t c = PA_FLOW_MIN_CAP;
    while (c < n) {
        c <<= 1;
    }
    return c;
}

static size_t find_slot(pa_flow_t *const *slots, size_t cap, const pa_flow_key_t *key) {
    size_t mask = cap - 1;
    size_t i = (size_t)pa_flow_key_hash(key) & mask;

    while (slots[i] && !pa_flow_key_equal(&slots[i]->key, key)) {
        i = (i + 1) & mask;
    }
    return i;
}

pa_status_t pa_flow_table_create(size_t initial_cap, pa_flow_table_t **out) {
    pa_flow_table_t *t;

    if (!out) {
        return PA_ERR_ARGS;
    }
    t = calloc(1, sizeof *t);
    if (!t) {
        return PA_ERR_NOMEM;
    }
    t->cap = round_pow2(initial_cap);
    t->slots = calloc(t->cap, sizeof *t->slots);
    if (!t->slots) {
        free(t);
        return PA_ERR_NOMEM;
    }
    t->next_id = 1;
    pa_vec_init(&t->retired, sizeof(pa_flow_t *));
    *out = t;
    return PA_OK;
}

static void free_flow(pa_flow_t *f) {
    if (f) {
        free(f->tcp);
        free(f);
    }
}

void pa_flow_table_destroy(pa_flow_table_t *t) {
    if (!t) {
        return;
    }
    for (size_t i = 0; i < t->cap; i++) {
        free_flow(t->slots[i]);
    }
    for (size_t i = 0; i < t->retired.len; i++) {
        free_flow(*(pa_flow_t **)pa_vec_at(&t->retired, i));
    }
    pa_vec_free(&t->retired);
    free(t->slots);
    free(t);
}

static pa_flow_t *new_flow(pa_flow_table_t *t, const pa_flow_key_t *key, const pa_packet_t *p,
                           pa_dir_t d) {
    pa_flow_t *f = calloc(1, sizeof *f);

    if (!f) {
        return NULL;
    }
    if (key->proto == PA_L4_TCP) {
        f->tcp = calloc(1, sizeof *f->tcp);
        if (!f->tcp) {
            free(f);
            return NULL;
        }
    }
    f->id = t->next_id++;
    f->key = *key;
    f->initiator = d;
    if (key->proto == PA_L4_TCP && (p->tcp_flags & PA_TCP_SYN) && (p->tcp_flags & PA_TCP_ACK)) {
        f->initiator = d == PA_DIR_A_TO_B ? PA_DIR_B_TO_A : PA_DIR_A_TO_B;
    }
    f->first_ts = f->last_ts = p->ts;
    return f;
}

/* A closed flow is replaced when a new SYN arrives or when it ended by timeout. */
static int should_restart(const pa_flow_t *f, const pa_packet_t *p) {
    if (!f->closed) {
        return 0;
    }
    if (f->end_reason == PA_FLOW_END_TIMEOUT) {
        return 1;
    }
    return p->l4 == PA_L4_TCP && (p->tcp_flags & PA_TCP_SYN) && !(p->tcp_flags & PA_TCP_ACK);
}

static pa_status_t grow(pa_flow_table_t *t) {
    size_t ncap = t->cap * 2;
    pa_flow_t **ns = calloc(ncap, sizeof *ns);

    if (!ns) {
        return PA_ERR_NOMEM;
    }
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i]) {
            ns[find_slot(ns, ncap, &t->slots[i]->key)] = t->slots[i];
        }
    }
    free(t->slots);
    t->slots = ns;
    t->cap = ncap;
    return PA_OK;
}

static pa_status_t place(pa_flow_table_t *t, const pa_flow_key_t *key, const pa_packet_t *p,
                         pa_dir_t d, pa_flow_t **out) {
    size_t i;
    pa_flow_t *old, *nf;

    if ((t->count + 1) * PA_FLOW_LOAD_DEN > t->cap * PA_FLOW_LOAD_NUM && grow(t) != PA_OK) {
        return PA_ERR_NOMEM;
    }
    i = find_slot(t->slots, t->cap, key);
    old = t->slots[i];
    nf = new_flow(t, key, p, d);
    if (!nf) {
        return PA_ERR_NOMEM;
    }
    if (old && pa_vec_push(&t->retired, &old) != PA_OK) {
        free_flow(nf);
        return PA_ERR_NOMEM;
    }
    t->slots[i] = nf;
    if (!old) {
        t->count++;
    }
    *out = nf;
    return PA_OK;
}

pa_status_t pa_flow_table_get_or_insert(pa_flow_table_t *t, const pa_packet_t *p, pa_flow_t **flow,
                                        pa_dir_t *dir, int *is_new) {
    pa_flow_key_t key;
    pa_dir_t d;
    pa_flow_t *f;

    if (!t || !p || !flow || !dir || !is_new) {
        return PA_ERR_ARGS;
    }
    pa_flow_key_from_packet(p, &key, &d);
    f = t->slots[find_slot(t->slots, t->cap, &key)];
    *is_new = 0;
    if (!f || should_restart(f, p)) {
        pa_status_t st = place(t, &key, p, d, &f);
        if (st != PA_OK) {
            return st;
        }
        *is_new = 1;
    }
    if (p->ts > f->last_ts) {
        f->last_ts = p->ts;
    }
    f->dir[d].packets++;
    f->dir[d].bytes += p->wire_len;
    f->dir[d].payload_bytes += p->l4_payload_len;
    *flow = f;
    *dir = d;
    return PA_OK;
}

void pa_flow_table_expire(pa_flow_table_t *t, double now, const pa_config_t *cfg,
                          void (*on_end)(pa_flow_t *, void *), void *ud) {
    for (size_t i = 0; i < t->cap; i++) {
        pa_flow_t *f = t->slots[i];
        double timeout;

        if (!f || f->closed) {
            continue;
        }
        timeout = f->key.proto == PA_L4_TCP ? cfg->tcp_timeout_sec : cfg->udp_timeout_sec;
        if (now - f->last_ts > timeout) {
            f->closed = 1;
            f->end_reason = PA_FLOW_END_TIMEOUT;
            if (on_end) {
                on_end(f, ud);
            }
        }
    }
}

void pa_flow_table_close_all(pa_flow_table_t *t, void (*on_end)(pa_flow_t *, void *), void *ud) {
    for (size_t i = 0; i < t->cap; i++) {
        pa_flow_t *f = t->slots[i];

        if (f && !f->closed) {
            f->closed = 1;
            f->end_reason = PA_FLOW_END_EOF;
            if (on_end) {
                on_end(f, ud);
            }
        }
    }
}

void pa_flow_table_foreach(const pa_flow_table_t *t, void (*fn)(const pa_flow_t *, void *),
                           void *ud) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i]) {
            fn(t->slots[i], ud);
        }
    }
    for (size_t i = 0; i < t->retired.len; i++) {
        fn(*(pa_flow_t **)pa_vec_at(&t->retired, i), ud);
    }
}

size_t pa_flow_table_size(const pa_flow_table_t *t) { return t->count + t->retired.len; }

void pa_flow_endpoints(const pa_flow_t *f, pa_addr_t *src, pa_addr_t *dst, uint16_t *dport) {
    if (f->initiator == PA_DIR_A_TO_B) {
        *src = f->key.addr_a;
        *dst = f->key.addr_b;
        *dport = f->key.port_b;
    } else {
        *src = f->key.addr_b;
        *dst = f->key.addr_a;
        *dport = f->key.port_a;
    }
}
