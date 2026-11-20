#include "analysis/stats.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analysis/analyzer.h"
#include "report/format.h"

#define PA_PORT_COUNT 65536

pa_status_t pa_hist_init(pa_histogram_t *h, double lo, double hi, uint32_t n_bins,
                         uint8_t log_scale) {
    memset(h, 0, sizeof *h);
    if (n_bins == 0 || n_bins > PA_HIST_MAX_BINS || !(hi > lo) || (log_scale && lo <= 0.0)) {
        return PA_ERR_ARGS;
    }
    h->counts = calloc((size_t)n_bins + 2, sizeof *h->counts);
    if (!h->counts) {
        return PA_ERR_NOMEM;
    }
    h->lo = lo;
    h->hi = hi;
    h->n_bins = n_bins;
    h->log_scale = log_scale;
    return PA_OK;
}

void pa_hist_add(pa_histogram_t *h, double v) {
    size_t idx;

    if (!h || !h->counts) {
        return;
    }
    if (v < h->lo) {
        idx = 0;
    } else if (v >= h->hi) {
        idx = (size_t)h->n_bins + 1;
    } else {
        double frac = h->log_scale ? log(v / h->lo) / log(h->hi / h->lo)
                                   : (v - h->lo) / (h->hi - h->lo);
        idx = 1 + (size_t)(frac * (double)h->n_bins);
        if (idx > h->n_bins) {
            idx = h->n_bins;
        }
    }
    h->counts[idx]++;
    if (h->n == 0 || v < h->min) {
        h->min = v;
    }
    if (h->n == 0 || v > h->max) {
        h->max = v;
    }
    h->sum += v;
    h->sum_sq += v * v;
    h->n++;
}

double pa_hist_edge(const pa_histogram_t *h, uint32_t i) {
    double frac = (double)i / (double)h->n_bins;

    return h->log_scale ? h->lo * pow(h->hi / h->lo, frac) : h->lo + frac * (h->hi - h->lo);
}

void pa_hist_free(pa_histogram_t *h) {
    if (h) {
        free(h->counts);
        h->counts = NULL;
    }
}

typedef struct {
    pa_histogram_t pkt_size, flow_duration, flow_bytes;
    pa_port_stats_t *ports[2]; /* [0] tcp, [1] udp, indexed by service port */
} stats_state_t;

static pa_status_t stats_init(pa_analysis_ctx_t *ctx, void **state) {
    stats_state_t *s = calloc(1, sizeof *s);

    (void)ctx;
    if (!s) {
        return PA_ERR_NOMEM;
    }
    s->ports[0] = calloc(PA_PORT_COUNT, sizeof *s->ports[0]);
    s->ports[1] = calloc(PA_PORT_COUNT, sizeof *s->ports[1]);
    if (!s->ports[0] || !s->ports[1] || pa_hist_init(&s->pkt_size, 0.0, 1536.0, 24, 0) != PA_OK ||
        pa_hist_init(&s->flow_duration, 1e-3, 1e4, 21, 1) != PA_OK ||
        pa_hist_init(&s->flow_bytes, 1.0, 1e10, 20, 1) != PA_OK) {
        pa_hist_free(&s->pkt_size);
        pa_hist_free(&s->flow_duration);
        pa_hist_free(&s->flow_bytes);
        free(s->ports[0]);
        free(s->ports[1]);
        free(s);
        return PA_ERR_NOMEM;
    }
    *state = s;
    return PA_OK;
}

static void stats_destroy(void *state) {
    stats_state_t *s = state;

    if (!s) {
        return;
    }
    pa_hist_free(&s->pkt_size);
    pa_hist_free(&s->flow_duration);
    pa_hist_free(&s->flow_bytes);
    free(s->ports[0]);
    free(s->ports[1]);
    free(s);
}

static size_t l4_index(pa_l4_proto_t l4) {
    switch (l4) {
    case PA_L4_TCP:
        return 0;
    case PA_L4_UDP:
        return 1;
    case PA_L4_ICMP:
        return 2;
    case PA_L4_ICMP6:
        return 3;
    default:
        return 4;
    }
}

static void update_hosts(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    pa_host_stats_t *s, *d;
    uint8_t f = p->tcp_flags;

    if (p->ip_version == 0 || pa_host_table_get_or_insert(ctx->hosts, &p->src, &s) != PA_OK ||
        pa_host_table_get_or_insert(ctx->hosts, &p->dst, &d) != PA_OK) {
        return;
    }
    s->tx_packets++;
    s->tx_bytes += p->wire_len;
    d->rx_packets++;
    d->rx_bytes += p->wire_len;
    if (p->l4 != PA_L4_TCP || p->malformed) {
        return;
    }
    if ((f & PA_TCP_SYN) && !(f & PA_TCP_ACK)) {
        s->syn_sent++;
        d->syn_recv++;
    } else if (f & PA_TCP_SYN) {
        d->synack_recv++;
    }
    if (f & PA_TCP_RST) {
        s->rst_sent++;
        d->rst_recv++;
    }
}

static void stats_on_packet(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p,
                            pa_flow_t *flow, pa_dir_t dir) {
    stats_state_t *s = state;
    pa_global_stats_t *g = ctx->global;
    size_t li = l4_index(p->l4);

    (void)flow;
    (void)dir;
    if (g->packets == 0 || p->ts < g->first_ts) {
        g->first_ts = p->ts;
    }
    if (p->ts > g->last_ts) {
        g->last_ts = p->ts;
    }
    g->packets++;
    g->bytes += p->wire_len;
    g->pkts_by_l4[li]++;
    g->bytes_by_l4[li] += p->wire_len;
    if (p->ip_version == 4) {
        g->ipv4_packets++;
    } else if (p->ip_version == 6) {
        g->ipv6_packets++;
    } else {
        g->non_ip_packets++;
    }
    if (p->malformed) {
        g->malformed_packets++;
    }
    pa_hist_add(&s->pkt_size, (double)p->wire_len);
    update_hosts(ctx, p);
}

static void stats_on_flow_end(void *state, pa_analysis_ctx_t *ctx, const pa_flow_t *f) {
    stats_state_t *s = state;
    size_t pi = f->key.proto == PA_L4_TCP ? 0 : 1;
    pa_addr_t src, dst;
    uint16_t port;
    pa_host_stats_t *h;
    pa_port_stats_t *ps;

    if (pi == 0) {
        ctx->global->tcp_flows++;
    } else {
        ctx->global->udp_flows++;
    }
    pa_hist_add(&s->flow_duration, f->last_ts - f->first_ts);
    pa_hist_add(&s->flow_bytes, (double)(f->dir[0].bytes + f->dir[1].bytes));
    pa_flow_endpoints(f, &src, &dst, &port);
    ps = &s->ports[pi][port];
    ps->packets += f->dir[0].packets + f->dir[1].packets;
    ps->bytes += f->dir[0].bytes + f->dir[1].bytes;
    ps->flows++;
    if (pa_host_table_get_or_insert(ctx->hosts, &src, &h) == PA_OK) {
        h->flows_initiated++;
    }
    if (pa_host_table_get_or_insert(ctx->hosts, &dst, &h) == PA_OK) {
        h->flows_accepted++;
    }
}

static int cmp_top_desc(const void *a, const void *b) {
    const pa_top_entry_t *x = a, *y = b;

    return (x->bytes < y->bytes) - (x->bytes > y->bytes);
}

/* Sorts tmp by bytes, keeps the first top_n entries in dst and fills the shares. */
static pa_status_t emit_top(pa_vec_t *tmp, pa_vec_t *dst, uint32_t top_n, uint64_t total) {
    size_t n = tmp->len < top_n ? tmp->len : top_n;

    if (tmp->len > 1) {
        qsort(tmp->data, tmp->len, sizeof(pa_top_entry_t), cmp_top_desc);
    }
    for (size_t i = 0; i < n; i++) {
        pa_top_entry_t e = *(pa_top_entry_t *)pa_vec_at(tmp, i);
        pa_status_t st;

        e.share = total ? (double)e.bytes / (double)total : 0.0;
        if (e.share > 1.0) {
            e.share = 1.0;
        }
        st = pa_vec_push(dst, &e);
        if (st != PA_OK) {
            return st;
        }
    }
    return PA_OK;
}

typedef struct {
    pa_vec_t *v;
    pa_status_t st;
} collect_t;

static void collect_host(const pa_host_stats_t *h, void *ud) {
    collect_t *c = ud;
    pa_top_entry_t e;

    memset(&e, 0, sizeof e);
    pa_format_addr(&h->addr, e.label, sizeof e.label);
    e.packets = h->tx_packets + h->rx_packets;
    e.bytes = h->tx_bytes + h->rx_bytes;
    if (c->st == PA_OK) {
        c->st = pa_vec_push(c->v, &e);
    }
}

typedef struct {
    pa_addr_t a, b;
    uint64_t packets, bytes;
} conv_t;

typedef struct {
    pa_vec_t *v; /* conv_t */
    pa_status_t st;
} conv_collect_t;

static void collect_conv(const pa_flow_t *f, void *ud) {
    conv_collect_t *c = ud;
    conv_t e;
    int swap = pa_addr_cmp(&f->key.addr_a, &f->key.addr_b) > 0;

    e.a = swap ? f->key.addr_b : f->key.addr_a;
    e.b = swap ? f->key.addr_a : f->key.addr_b;
    e.packets = f->dir[0].packets + f->dir[1].packets;
    e.bytes = f->dir[0].bytes + f->dir[1].bytes;
    if (c->st == PA_OK) {
        c->st = pa_vec_push(c->v, &e);
    }
}

static int cmp_conv(const void *x, const void *y) {
    const conv_t *a = x, *b = y;
    int c = pa_addr_cmp(&a->a, &b->a);

    return c ? c : pa_addr_cmp(&a->b, &b->b);
}

static pa_status_t top_conversations(const pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    pa_vec_t convs, merged;
    conv_collect_t cc = {&convs, PA_OK};
    pa_status_t st;

    pa_vec_init(&convs, sizeof(conv_t));
    pa_vec_init(&merged, sizeof(pa_top_entry_t));
    pa_flow_table_foreach(ctx->flows, collect_conv, &cc);
    st = cc.st;
    if (st == PA_OK && convs.len > 0) {
        qsort(convs.data, convs.len, sizeof(conv_t), cmp_conv);
    }
    for (size_t i = 0; st == PA_OK && i < convs.len;) {
        conv_t *first = pa_vec_at(&convs, i);
        pa_top_entry_t e;
        char a[48], b[48];

        memset(&e, 0, sizeof e);
        for (; i < convs.len && cmp_conv(first, pa_vec_at(&convs, i)) == 0; i++) {
            e.packets += ((conv_t *)pa_vec_at(&convs, i))->packets;
            e.bytes += ((conv_t *)pa_vec_at(&convs, i))->bytes;
        }
        pa_format_addr(&first->a, a, sizeof a);
        pa_format_addr(&first->b, b, sizeof b);
        snprintf(e.label, sizeof e.label, "%.24s <-> %.24s", a, b);
        st = pa_vec_push(&merged, &e);
    }
    if (st == PA_OK) {
        st = emit_top(&merged, &rep->top_conversations, ctx->cfg->top_n, ctx->global->bytes);
    }
    pa_vec_free(&convs);
    pa_vec_free(&merged);
    return st;
}

static pa_status_t top_ports(const stats_state_t *s, size_t pi, const pa_analysis_ctx_t *ctx,
                             pa_vec_t *dst) {
    pa_vec_t tmp;
    pa_status_t st = PA_OK;

    pa_vec_init(&tmp, sizeof(pa_top_entry_t));
    for (size_t port = 0; st == PA_OK && port < PA_PORT_COUNT; port++) {
        const pa_port_stats_t *ps = &s->ports[pi][port];
        pa_top_entry_t e;

        if (ps->packets == 0) {
            continue;
        }
        memset(&e, 0, sizeof e);
        snprintf(e.label, sizeof e.label, "%zu/%s", port, pi == 0 ? "tcp" : "udp");
        e.packets = ps->packets;
        e.bytes = ps->bytes;
        st = pa_vec_push(&tmp, &e);
    }
    if (st == PA_OK) {
        st = emit_top(&tmp, dst, ctx->cfg->top_n, ctx->global->bytes);
    }
    pa_vec_free(&tmp);
    return st;
}

static pa_status_t top_hosts(const pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    pa_vec_t tmp;
    collect_t c = {&tmp, PA_OK};
    pa_status_t st;

    pa_vec_init(&tmp, sizeof(pa_top_entry_t));
    pa_host_table_foreach(ctx->hosts, collect_host, &c);
    st = c.st;
    if (st == PA_OK) {
        st = emit_top(&tmp, &rep->top_hosts, ctx->cfg->top_n, ctx->global->bytes);
    }
    pa_vec_free(&tmp);
    return st;
}

static pa_status_t stats_finalize(void *state, pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    stats_state_t *s = state;
    pa_status_t st;

    rep->global = *ctx->global;
    rep->pkt_size = s->pkt_size; /* ownership of the counts moves to the report */
    rep->flow_duration = s->flow_duration;
    rep->flow_bytes = s->flow_bytes;
    memset(&s->pkt_size, 0, sizeof s->pkt_size);
    memset(&s->flow_duration, 0, sizeof s->flow_duration);
    memset(&s->flow_bytes, 0, sizeof s->flow_bytes);

    st = top_hosts(ctx, rep);
    if (st == PA_OK) {
        st = top_ports(s, 0, ctx, &rep->top_tcp_ports);
    }
    if (st == PA_OK) {
        st = top_ports(s, 1, ctx, &rep->top_udp_ports);
    }
    if (st == PA_OK) {
        st = top_conversations(ctx, rep);
    }
    return st;
}

const pa_analyzer_ops_t pa_stats_analyzer_ops = {"stats",         stats_init,     stats_on_packet,
                                                 stats_on_flow_end, stats_finalize, stats_destroy};
