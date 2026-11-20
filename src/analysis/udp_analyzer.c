#include "analysis/udp_analyzer.h"

#include <stdlib.h>
#include <string.h>

#include "analysis/analyzer.h"

#define PA_DNS_PORT 53

typedef struct {
    pa_histogram_t dgram_size;
} udp_state_t;

static pa_status_t udp_init(pa_analysis_ctx_t *ctx, void **state) {
    udp_state_t *s = calloc(1, sizeof *s);

    (void)ctx;
    if (!s) {
        return PA_ERR_NOMEM;
    }
    if (pa_hist_init(&s->dgram_size, 0.0, 1536.0, 24, 0) != PA_OK) {
        free(s);
        return PA_ERR_NOMEM;
    }
    *state = s;
    return PA_OK;
}

static void udp_destroy(void *state) {
    udp_state_t *s = state;

    if (s) {
        pa_hist_free(&s->dgram_size);
        free(s);
    }
}

static void udp_on_packet(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p,
                          pa_flow_t *flow, pa_dir_t dir) {
    udp_state_t *s = state;

    (void)flow;
    (void)dir;
    if (p->l4 != PA_L4_UDP || p->malformed) {
        return;
    }
    pa_hist_add(&s->dgram_size, (double)p->l4_payload_len);
    if (p->sport == PA_DNS_PORT || p->dport == PA_DNS_PORT) {
        ctx->global->udp_dns_packets++;
    }
}

typedef struct {
    pa_vec_t rows;
    pa_status_t st;
} udp_collect_t;

static void collect_flow(const pa_flow_t *f, void *ud) {
    udp_collect_t *c = ud;
    pa_flow_row_t row;

    if (f->key.proto != PA_L4_UDP || c->st != PA_OK) {
        return;
    }
    pa_flow_row_fill(&row, f);
    c->st = pa_vec_push(&c->rows, &row);
}

static int cmp_bytes_desc(const void *x, const void *y) {
    const pa_flow_row_t *a = x, *b = y;

    return (a->bytes < b->bytes) - (a->bytes > b->bytes);
}

static pa_status_t udp_finalize(void *state, pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    udp_state_t *s = state;
    udp_collect_t c;

    c.st = PA_OK;
    pa_vec_init(&c.rows, sizeof(pa_flow_row_t));
    pa_flow_table_foreach(ctx->flows, collect_flow, &c);
    if (c.st == PA_OK && c.rows.len > 1) {
        qsort(c.rows.data, c.rows.len, sizeof(pa_flow_row_t), cmp_bytes_desc);
    }
    if (c.st == PA_OK) {
        pa_vec_truncate(&c.rows, ctx->cfg->top_n);
        rep->top_udp_flows = c.rows;
        c.rows.data = NULL; /* ownership moved to the report */
        rep->udp_dgram_size = s->dgram_size;
        memset(&s->dgram_size, 0, sizeof s->dgram_size);
    }
    pa_vec_free(&c.rows);
    return c.st;
}

const pa_analyzer_ops_t pa_udp_analyzer_ops = {"udp", udp_init, udp_on_packet, NULL, udp_finalize,
                                               udp_destroy};
