#include "analysis/anomaly.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analysis/analyzer.h"
#include "analysis/tcp_analyzer.h"
#include "core/hash.h"
#include "report/format.h"

#define PA_SEV_MEDIUM_RATIO 2.0
#define PA_SEV_HIGH_RATIO 5.0

const char *pa_anomaly_type_name(pa_anomaly_type_t t) {
    static const char *const names[PA_ANOM__COUNT] = {
        "PORT_SCAN",  "HOST_SCAN",  "SYN_FLOOD", "HIGH_RETRANS",     "RST_STORM",
        "ZERO_WINDOW", "UDP_FLOOD", "MALFORMED", "SUSPICIOUS_FLAGS"};

    return (unsigned)t < PA_ANOM__COUNT ? names[t] : "UNKNOWN";
}

const char *pa_severity_name(pa_severity_t s) {
    static const char *const names[] = {"LOW", "MEDIUM", "HIGH"};

    return (unsigned)s < 3 ? names[s] : "?";
}

static int same_addr(const pa_addr_t *a, const pa_addr_t *b) {
    return a->family == b->family && memcmp(a->bytes, b->bytes, sizeof a->bytes) == 0;
}

pa_status_t pa_anomaly_add(pa_vec_t *vec, const pa_anomaly_t *a) {
    for (size_t i = 0; i < vec->len; i++) {
        pa_anomaly_t *e = pa_vec_at(vec, i);

        if (e->type != a->type || e->dport != a->dport || !same_addr(&e->src, &a->src) ||
            !same_addr(&e->dst, &a->dst)) {
            continue;
        }
        if (a->ts_end > e->ts_end) {
            e->ts_end = a->ts_end;
        }
        if (a->metric > e->metric) {
            e->metric = a->metric;
            e->severity = a->severity;
            memcpy(e->desc, a->desc, sizeof e->desc);
        }
        return PA_OK;
    }
    if (vec->len >= PA_ANOM_MAX) {
        return PA_OK;
    }
    return pa_vec_push(vec, a);
}

static void init_anom(pa_anomaly_t *a, pa_anomaly_type_t type, double ts, double metric,
                      double thr) {
    double ratio = thr > 0.0 ? metric / thr : 1.0;

    memset(a, 0, sizeof *a);
    a->type = type;
    a->ts_start = a->ts_end = ts;
    a->metric = metric;
    a->threshold = thr;
    a->severity = ratio >= PA_SEV_HIGH_RATIO
                      ? PA_SEV_HIGH
                      : (ratio >= PA_SEV_MEDIUM_RATIO ? PA_SEV_MEDIUM : PA_SEV_LOW);
}

static void check_flags(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    uint8_t f = p->tcp_flags;
    const char *kind = NULL;
    pa_anomaly_t a;
    char s[48], d[48];

    if (f == 0) {
        kind = "NULL scan (no flags)";
    } else if ((f & (PA_TCP_FIN | PA_TCP_PSH | PA_TCP_URG)) ==
               (PA_TCP_FIN | PA_TCP_PSH | PA_TCP_URG)) {
        kind = "XMAS scan (FIN+PSH+URG)";
    } else if ((f & PA_TCP_SYN) && (f & (PA_TCP_FIN | PA_TCP_RST))) {
        kind = "illegal SYN+FIN/RST combination";
    }
    if (!kind) {
        return;
    }
    init_anom(&a, PA_ANOM_SUSPICIOUS_FLAGS, p->ts, 1.0, 1.0);
    a.severity = PA_SEV_MEDIUM;
    a.src = p->src;
    a.dst = p->dst;
    pa_format_addr(&p->src, s, sizeof s);
    pa_format_addr(&p->dst, d, sizeof d);
    snprintf(a.desc, sizeof a.desc, "%s from %s to %s", kind, s, d);
    (void)pa_anomaly_add(ctx->anomalies, &a);
}

static void check_scans(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    const pa_thresholds_t *th = &ctx->cfg->th;
    pa_host_stats_t *h;
    pa_anomaly_t a;
    uint8_t tail[3];
    uint64_t key;
    char s[48];

    if (pa_host_table_get_or_insert(ctx->hosts, &p->src, &h) != PA_OK) {
        return;
    }
    tail[0] = (uint8_t)(p->dport >> 8);
    tail[1] = (uint8_t)(p->dport & 0xFF);
    tail[2] = p->dst.family;
    key = pa_hash_mix(pa_hash_bytes(tail, sizeof tail, pa_hash_bytes(p->dst.bytes, 16, 1)));
    (void)pa_wset_add(&h->dst_ports, key, p->dport, p->ts, th->window_sec);
    pa_format_addr(&p->src, s, sizeof s);
    if (h->dst_ports.count >= th->port_scan_ports) {
        init_anom(&a, PA_ANOM_PORT_SCAN, p->ts, (double)h->dst_ports.count,
                  (double)th->port_scan_ports);
        a.src = p->src;
        snprintf(a.desc, sizeof a.desc, "%s probed %zu distinct (host,port) targets within %.0f s",
                 s, h->dst_ports.count, th->window_sec);
        (void)pa_anomaly_add(ctx->anomalies, &a);
    }
    if (pa_wset_add(&h->dst_hosts, key, p->dport, p->ts, th->window_sec) == 1 &&
        h->dst_hosts.count >= th->host_scan_hosts) {
        size_t n = pa_wset_count_port(&h->dst_hosts, p->dport);

        if (n >= th->host_scan_hosts) {
            init_anom(&a, PA_ANOM_HOST_SCAN, p->ts, (double)n, (double)th->host_scan_hosts);
            a.src = p->src;
            a.dport = p->dport;
            snprintf(a.desc, sizeof a.desc, "%s probed %zu distinct hosts on port %u", s, n,
                     (unsigned)p->dport);
            (void)pa_anomaly_add(ctx->anomalies, &a);
        }
    }
}

static void check_syn_flood(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    pa_host_stats_t *h;
    pa_anomaly_t a;
    uint32_t n;
    char d[48];

    if (pa_host_table_get_or_insert(ctx->hosts, &p->dst, &h) != PA_OK) {
        return;
    }
    n = pa_rate_add(&h->syn_in_rate, p->ts);
    if (n != ctx->cfg->th.syn_flood_rate) {
        return;
    }
    init_anom(&a, PA_ANOM_SYN_FLOOD, p->ts, (double)n, (double)ctx->cfg->th.syn_flood_rate);
    a.dst = p->dst;
    a.dport = p->dport;
    pa_format_addr(&p->dst, d, sizeof d);
    snprintf(a.desc, sizeof a.desc, "%u SYN/s towards %s:%u", (unsigned)n, d, (unsigned)p->dport);
    (void)pa_anomaly_add(ctx->anomalies, &a);
}

static void rst_for(pa_analysis_ctx_t *ctx, const pa_addr_t *addr, double ts) {
    pa_host_stats_t *h;
    pa_anomaly_t a;
    char s[48];
    uint32_t n;

    if (pa_host_table_get_or_insert(ctx->hosts, addr, &h) != PA_OK) {
        return;
    }
    n = pa_rate_add(&h->rst_rate, ts);
    if (n != ctx->cfg->th.rst_storm_rate) {
        return;
    }
    init_anom(&a, PA_ANOM_RST_STORM, ts, (double)n, (double)ctx->cfg->th.rst_storm_rate);
    a.src = *addr;
    pa_format_addr(addr, s, sizeof s);
    snprintf(a.desc, sizeof a.desc, "%u RST/s from or to %s", (unsigned)n, s);
    (void)pa_anomaly_add(ctx->anomalies, &a);
}

static void check_tcp(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    uint8_t f = p->tcp_flags;

    check_flags(ctx, p);
    if ((f & PA_TCP_SYN) && !(f & PA_TCP_ACK)) {
        check_scans(ctx, p);
        check_syn_flood(ctx, p);
    }
    if (f & PA_TCP_RST) {
        rst_for(ctx, &p->src, p->ts);
        rst_for(ctx, &p->dst, p->ts);
    }
}

static void check_udp(pa_analysis_ctx_t *ctx, const pa_packet_t *p) {
    const pa_thresholds_t *th = &ctx->cfg->th;
    pa_host_stats_t *h;
    pa_anomaly_t a;
    int64_t sec = (int64_t)floor(p->ts);
    char d[48];
    uint32_t n;

    if (pa_host_table_get_or_insert(ctx->hosts, &p->dst, &h) != PA_OK) {
        return;
    }
    n = pa_rate_add(&h->udp_in_rate, p->ts);
    if (n != th->udp_flood_pps) {
        return;
    }
    if (h->udp_hot_streak > 0 && h->udp_hot_sec == sec - 1) {
        h->udp_hot_streak++;
    } else {
        h->udp_hot_streak = 1;
        h->udp_hot_start = p->ts;
    }
    h->udp_hot_sec = sec;
    if ((double)h->udp_hot_streak < th->udp_flood_min_sec) {
        return;
    }
    init_anom(&a, PA_ANOM_UDP_FLOOD, h->udp_hot_start, (double)n, (double)th->udp_flood_pps);
    a.ts_end = p->ts;
    a.dst = p->dst;
    pa_format_addr(&p->dst, d, sizeof d);
    snprintf(a.desc, sizeof a.desc, ">= %u UDP pkt/s towards %s for %u s", (unsigned)n, d,
             (unsigned)h->udp_hot_streak);
    (void)pa_anomaly_add(ctx->anomalies, &a);
}

static pa_status_t anomaly_init(pa_analysis_ctx_t *ctx, void **state) {
    (void)ctx;
    *state = NULL;
    return PA_OK;
}

static void anomaly_on_packet(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p,
                              pa_flow_t *flow, pa_dir_t dir) {
    (void)state;
    (void)flow;
    (void)dir;
    if (p->ip_version == 0 || p->malformed) {
        return; /* malformed packets are aggregated in finalize */
    }
    if (p->l4 == PA_L4_TCP) {
        check_tcp(ctx, p);
    } else if (p->l4 == PA_L4_UDP) {
        check_udp(ctx, p);
    }
}

/* SYN flood needs the final handshake ratio, so candidates are filtered here. */
static void drop_completed_syn_floods(pa_analysis_ctx_t *ctx) {
    pa_vec_t *v = ctx->anomalies;
    size_t out = 0;

    for (size_t i = 0; i < v->len; i++) {
        pa_anomaly_t *a = pa_vec_at(v, i);
        int keep = 1;

        if (a->type == PA_ANOM_SYN_FLOOD) {
            const pa_host_stats_t *h = pa_host_table_lookup(ctx->hosts, &a->dst);
            double ratio = h && h->syn_recv ? (double)h->hs_complete_in / (double)h->syn_recv : 0.0;

            keep = ratio < ctx->cfg->th.syn_flood_complete_ratio;
        }
        if (keep) {
            if (out != i) {
                memcpy(pa_vec_at(v, out), a, sizeof *a);
            }
            out++;
        }
    }
    pa_vec_truncate(v, out);
}

static void flow_anomalies(const pa_flow_t *f, void *ud) {
    pa_analysis_ctx_t *ctx = ud;
    const pa_thresholds_t *th = &ctx->cfg->th;
    const pa_tcp_state_t *t = f->tcp;
    pa_anomaly_t a;
    uint32_t segs, retr, zw;
    char ep[48];

    if (!t) {
        return;
    }
    segs = t->data_segments[0] + t->data_segments[1];
    retr = t->retrans[0] + t->retrans[1];
    zw = t->zero_window[0] + t->zero_window[1];
    if (segs >= th->retrans_min_segments && (double)retr / (double)segs > th->retrans_ratio) {
        init_anom(&a, PA_ANOM_HIGH_RETRANS, f->first_ts, (double)retr / (double)segs,
                  th->retrans_ratio);
        a.ts_end = f->last_ts;
        a.flow_id = f->id;
        pa_flow_endpoints(f, &a.src, &a.dst, &a.dport);
        pa_format_endpoint(&a.dst, a.dport, ep, sizeof ep);
        snprintf(a.desc, sizeof a.desc, "%.1f%% retransmissions (%u of %u segments) to %s",
                 100.0 * a.metric, (unsigned)retr, (unsigned)segs, ep);
        (void)pa_anomaly_add(ctx->anomalies, &a);
    }
    if (zw >= th->zero_window_events) {
        init_anom(&a, PA_ANOM_ZERO_WINDOW, f->first_ts, (double)zw, (double)th->zero_window_events);
        a.ts_end = f->last_ts;
        a.flow_id = f->id;
        pa_flow_endpoints(f, &a.src, &a.dst, &a.dport);
        pa_format_endpoint(&a.dst, a.dport, ep, sizeof ep);
        snprintf(a.desc, sizeof a.desc, "%u zero-window events in flow to %s", (unsigned)zw, ep);
        (void)pa_anomaly_add(ctx->anomalies, &a);
    }
}

static void malformed_anomaly(pa_analysis_ctx_t *ctx) {
    const pa_global_stats_t *g = ctx->global;
    pa_anomaly_t a;

    if (g->malformed_packets == 0) {
        return;
    }
    init_anom(&a, PA_ANOM_MALFORMED, g->first_ts, (double)g->malformed_packets, 1.0);
    a.ts_end = g->last_ts;
    a.severity = (double)g->malformed_packets > 0.01 * (double)g->packets ? PA_SEV_MEDIUM
                                                                          : PA_SEV_LOW;
    snprintf(a.desc, sizeof a.desc, "%llu malformed or truncated packets",
             (unsigned long long)g->malformed_packets);
    (void)pa_anomaly_add(ctx->anomalies, &a);
}

static int cmp_anom(const void *x, const void *y) {
    const pa_anomaly_t *a = x, *b = y;

    if (a->severity != b->severity) {
        return a->severity < b->severity ? 1 : -1;
    }
    return (a->ts_start > b->ts_start) - (a->ts_start < b->ts_start);
}

static pa_status_t anomaly_finalize(void *state, pa_analysis_ctx_t *ctx, pa_report_t *rep) {
    pa_status_t st;

    (void)state;
    drop_completed_syn_floods(ctx);
    pa_flow_table_foreach(ctx->flows, flow_anomalies, ctx);
    malformed_anomaly(ctx);
    if (ctx->anomalies->len > 1) {
        qsort(ctx->anomalies->data, ctx->anomalies->len, sizeof(pa_anomaly_t), cmp_anom);
    }
    st = pa_vec_copy(ctx->anomalies, &rep->anomalies);
    for (size_t i = 0; st == PA_OK && i < rep->anomalies.len; i++) {
        const pa_anomaly_t *a = pa_vec_at(&rep->anomalies, i);

        rep->anomaly_counts[a->type]++;
    }
    return st;
}

const pa_analyzer_ops_t pa_anomaly_analyzer_ops = {"anomaly",       anomaly_init, anomaly_on_packet,
                                                   NULL, anomaly_finalize, NULL};
