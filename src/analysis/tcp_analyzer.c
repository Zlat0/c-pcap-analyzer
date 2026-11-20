#include "analysis/tcp_analyzer.h"

#include <stdlib.h>
#include <string.h>

#include "analysis/analyzer.h"

typedef struct {
    pa_histogram_t rtt_ms;
} tcp_state_t;

static pa_status_t tcp_init(pa_analysis_ctx_t *ctx, void **state) {
    tcp_state_t *s = calloc(1, sizeof *s);

    (void)ctx;
    if (!s) {
        return PA_ERR_NOMEM;
    }
    if (pa_hist_init(&s->rtt_ms, 0.1, 10000.0, 20, 1) != PA_OK) {
        free(s);
        return PA_ERR_NOMEM;
    }
    *state = s;
    return PA_OK;
}

static void tcp_destroy(void *state) {
    tcp_state_t *s = state;

    if (s) {
        pa_hist_free(&s->rtt_ms);
        free(s);
    }
}

static void credit_responder(pa_analysis_ctx_t *ctx, const pa_flow_t *f) {
    const pa_addr_t *resp =
        f->initiator == PA_DIR_A_TO_B ? &f->key.addr_b : &f->key.addr_a;
    pa_host_stats_t *h;

    if (pa_host_table_get_or_insert(ctx->hosts, resp, &h) == PA_OK) {
        h->hs_complete_in++;
    }
}

static void track_handshake(pa_analysis_ctx_t *ctx, pa_flow_t *f, pa_dir_t dir,
                            const pa_packet_t *p) {
    pa_tcp_state_t *t = f->tcp;
    int syn = (p->tcp_flags & PA_TCP_SYN) != 0;
    int ack = (p->tcp_flags & PA_TCP_ACK) != 0;

    if (syn && !ack) {
        if (t->hs == PA_HS_NONE) {
            t->hs = PA_HS_SYN;
            t->syn_ts = p->ts;
        }
    } else if (syn) {
        ctx->global->tcp_synack_packets++;
        if (t->hs == PA_HS_SYN) {
            t->hs = PA_HS_SYNACK;
            t->synack_ts = p->ts;
        } else if (t->hs == PA_HS_NONE) {
            t->hs = PA_HS_MIDSTREAM;
        }
    } else if (t->hs == PA_HS_NONE) {
        t->hs = PA_HS_MIDSTREAM;
    } else if (t->hs == PA_HS_SYNACK && ack && dir == f->initiator) {
        t->hs = PA_HS_COMPLETE;
        t->ack_ts = p->ts;
        credit_responder(ctx, f);
    }
}

/* Compares seq against the next expected value of the direction (modulo 2^32). */
static void track_seq(pa_analysis_ctx_t *ctx, pa_tcp_state_t *t, size_t d, const pa_packet_t *p) {
    uint32_t len = p->l4_payload_len;
    uint32_t adv = len + ((p->tcp_flags & PA_TCP_SYN) ? 1u : 0u) +
                   ((p->tcp_flags & PA_TCP_FIN) ? 1u : 0u);

    if (!t->seq_valid[d]) {
        if (p->tcp_flags & PA_TCP_SYN) {
            t->isn[d] = p->seq;
        }
        t->next_seq[d] = p->seq + adv;
        t->seq_valid[d] = 1;
        return;
    }
    if (len > 0) {
        int32_t diff = (int32_t)(p->seq - t->next_seq[d]);

        if (diff < 0) {
            t->retrans[d]++;
            ctx->global->tcp_retrans++;
            if ((int32_t)(p->seq + adv - t->next_seq[d]) > 0) {
                t->next_seq[d] = p->seq + adv;
            }
        } else {
            if (diff > 0) {
                t->out_of_order[d]++;
            }
            t->next_seq[d] = p->seq + adv;
        }
    } else if (adv > 0 && p->seq == t->next_seq[d]) {
        t->next_seq[d] += adv; /* SYN and FIN consume one sequence number */
    }
}

static void tcp_on_packet(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p,
                          pa_flow_t *flow, pa_dir_t dir) {
    pa_tcp_state_t *t;
    size_t d = (size_t)dir;

    (void)state;
    if (!flow || !flow->tcp || p->l4 != PA_L4_TCP || p->malformed) {
        return;
    }
    t = flow->tcp;
    for (unsigned b = 0; b < 8; b++) {
        if ((p->tcp_flags >> b) & 1u) {
            t->flag_counts[b]++;
        }
    }
    track_handshake(ctx, flow, dir, p);
    if (p->wscale != 0xFF) {
        t->wscale[d] = p->wscale;
    }
    if (p->l4_payload_len > 0) {
        t->data_segments[d]++;
        ctx->global->tcp_segments_with_data++;
    }
    track_seq(ctx, t, d, p);
    if (p->window == 0 && !(p->tcp_flags & (PA_TCP_RST | PA_TCP_SYN))) {
        t->zero_window[d]++;
    }
    if (p->tcp_flags & PA_TCP_FIN) {
        t->fin_seen[d] = 1;
    }
}

static double rtt_of(const pa_tcp_state_t *t) {
    if (t->hs == PA_HS_COMPLETE && t->syn_ts > 0.0 && t->ack_ts >= t->syn_ts) {
        return (t->ack_ts - t->syn_ts) * 1000.0;
    }
    return -1.0;
}

static void tcp_on_flow_end(void *state, pa_analysis_ctx_t *ctx, const pa_flow_t *f) {
    tcp_state_t *s = state;
    double rtt;

    if (!f->tcp) {
        return;
    }
    switch (f->tcp->hs) {
    case PA_HS_COMPLETE:
        ctx->global->tcp_hs_complete++;
        rtt = rtt_of(f->tcp);
        if (rtt >= 0.0) {
            pa_hist_add(&s->rtt_ms, rtt);
        }
        break;
    case PA_HS_SYN:
        ctx->global->tcp_hs_syn_only++;
        break;
    case PA_HS_SYNACK:
        ctx->global->tcp_hs_no_ack++;
        break;
    default:
        break;
    }
}

typedef struct {
    pa_report_t *rep;
    pa_vec_t rows;
    pa_status_t st;
} tcp_collect_t;

static void collect_flow(const pa_flow_t *f, void *ud) {
    tcp_collect_t *c = ud;
    const pa_tcp_state_t *t = f->tcp;
    uint32_t segs, retr, zw;
    pa_flow_row_t row;

    if (!t) {
        return;
    }
    for (size_t i = 0; i < 8; i++) {
        c->rep->tcp_flag_totals[i] += t->flag_counts[i];
    }
    segs = t->data_segments[0] + t->data_segments[1];
    retr = t->retrans[0] + t->retrans[1];
    zw = t->zero_window[0] + t->zero_window[1];
    if ((retr == 0 && zw == 0) || c->st != PA_OK) {
        return;
    }
    pa_flow_row_fill(&row, f);
    row.rtt_ms = rtt_of(t);
    row.retrans_ratio = segs ? (double)retr / (double)segs : 0.0;
    row.zero_window = zw;
    c->st = pa_vec_push(&c->rows, &row);
}

static int cmp_rows(const void *x, const void *y) {
    const pa_flow_row_t *a = x, *b = y;

    if (a->retrans_ratio != b->retrans_ratio) {
        return a->retrans_ratio < b->retrans_ratio ? 1 : -1;
    }
    return (a->bytes < b->bytes) - (a->bytes > b->bytes);
}

static pa_status_t tcp_finalize(void *state, pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    tcp_state_t *s = state;
    tcp_collect_t c;

    c.rep = rep;
    c.st = PA_OK;
    pa_vec_init(&c.rows, sizeof(pa_flow_row_t));
    pa_flow_table_foreach(ctx->flows, collect_flow, &c);
    if (c.st == PA_OK && c.rows.len > 1) {
        qsort(c.rows.data, c.rows.len, sizeof(pa_flow_row_t), cmp_rows);
    }
    if (c.st == PA_OK) {
        pa_vec_truncate(&c.rows, ctx->cfg->top_n);
        rep->worst_tcp_flows = c.rows;
        c.rows.data = NULL; /* ownership moved to the report */
        rep->tcp_rtt_ms = s->rtt_ms;
        memset(&s->rtt_ms, 0, sizeof s->rtt_ms);
    }
    pa_vec_free(&c.rows);
    return c.st;
}

const pa_analyzer_ops_t pa_tcp_analyzer_ops = {"tcp",          tcp_init,     tcp_on_packet,
                                               tcp_on_flow_end, tcp_finalize, tcp_destroy};
