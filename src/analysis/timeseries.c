#include "analysis/timeseries.h"

#include <math.h>
#include <stdlib.h>

#include "analysis/analyzer.h"

#define PA_MAX_BINS 1000000u

enum { SER_TCP_BYTES, SER_UDP_BYTES, SER_TCP_PKTS, SER_UDP_PKTS, SER__COUNT };

typedef struct {
    pa_series_t s[SER__COUNT];
    int started;
} ts_state_t;

static const char *const k_names[SER__COUNT] = {"tcp_bytes", "udp_bytes", "tcp_packets",
                                                "udp_packets"};

static pa_status_t ts_init(pa_analysis_ctx_t *ctx, void **state) {
    ts_state_t *t = calloc(1, sizeof *t);

    if (!t) {
        return PA_ERR_NOMEM;
    }
    for (int i = 0; i < SER__COUNT; i++) {
        t->s[i].name = k_names[i];
        t->s[i].bin_sec = ctx->cfg->bin_sec;
        pa_vec_init(&t->s[i].values, sizeof(double));
    }
    *state = t;
    return PA_OK;
}

static void ts_destroy(void *state) {
    ts_state_t *t = state;

    if (!t) {
        return;
    }
    for (int i = 0; i < SER__COUNT; i++) {
        pa_vec_free(&t->s[i].values);
    }
    free(t);
}

static void add_to(pa_series_t *s, size_t idx, double v) {
    if (idx >= s->values.len && pa_vec_resize_zero(&s->values, idx + 1) != PA_OK) {
        return;
    }
    *(double *)pa_vec_at(&s->values, idx) += v;
}

static void ts_on_packet(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p,
                         pa_flow_t *flow, pa_dir_t dir) {
    ts_state_t *t = state;
    size_t idx, b, k;
    double rel;

    (void)flow;
    (void)dir;
    if (!t->started) {
        for (int i = 0; i < SER__COUNT; i++) {
            t->s[i].start_ts = p->ts;
        }
        t->started = 1;
    }
    if (p->l4 != PA_L4_TCP && p->l4 != PA_L4_UDP) {
        return;
    }
    rel = (p->ts - t->s[0].start_ts) / ctx->cfg->bin_sec;
    idx = rel > 0.0 ? (size_t)floor(rel) : 0;
    if (idx >= PA_MAX_BINS) {
        return;
    }
    b = p->l4 == PA_L4_TCP ? SER_TCP_BYTES : SER_UDP_BYTES;
    k = p->l4 == PA_L4_TCP ? SER_TCP_PKTS : SER_UDP_PKTS;
    add_to(&t->s[b], idx, (double)p->wire_len);
    add_to(&t->s[k], idx, 1.0);
}

static pa_status_t ts_finalize(void *state, pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    ts_state_t *t = state;
    pa_series_t *dst[SER__COUNT] = {&rep->tcp_bytes, &rep->udp_bytes, &rep->tcp_packets,
                                    &rep->udp_packets};
    size_t n = 0;

    (void)ctx;
    for (int i = 0; i < SER__COUNT; i++) {
        if (t->s[i].values.len > n) {
            n = t->s[i].values.len;
        }
    }
    for (int i = 0; i < SER__COUNT; i++) {
        pa_status_t st = pa_vec_resize_zero(&t->s[i].values, n); /* equal lengths for charts */

        if (st != PA_OK) {
            return st;
        }
        dst[i]->name = t->s[i].name;
        dst[i]->start_ts = t->s[i].start_ts;
        dst[i]->bin_sec = t->s[i].bin_sec;
        st = pa_vec_copy(&t->s[i].values, &dst[i]->values);
        if (st != PA_OK) {
            return st;
        }
    }
    return PA_OK;
}

const pa_analyzer_ops_t pa_timeseries_analyzer_ops = {"timeseries", ts_init,     ts_on_packet,
                                                      NULL,         ts_finalize, ts_destroy};
