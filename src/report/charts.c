#include "report/charts.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fsutil.h"
#include "core/log.h"
#include "report/format.h"
#include "report/plot.h"

#define PA_CHART_W 1200
#define PA_CHART_H 700
#define PA_PATH_BUF 1024
#define PA_TOP_LEFT_MARGIN 300.0
#define PA_DEFAULT_LEFT_MARGIN 100.0

typedef struct {
    const char *file;
    const char *title;
    double left;
    pa_status_t (*draw)(pa_plot_t *pl, const pa_report_t *r);
} chart_desc_t;

static pa_status_t chart_protocol_share(pa_plot_t *pl, const pa_report_t *r) {
    static const char *const labels[5] = {"TCP", "UDP", "ICMP", "ICMPv6", "Other"};
    static const char *const names[2] = {"Packets, %", "Bytes, %"};
    const pa_global_stats_t *g = &r->global;
    double pk[5], by[5];
    const double *series[2] = {pk, by};

    for (size_t i = 0; i < 5; i++) {
        pk[i] = g->packets ? 100.0 * (double)g->pkts_by_l4[i] / (double)g->packets : 0.0;
        by[i] = g->bytes ? 100.0 * (double)g->bytes_by_l4[i] / (double)g->bytes : 0.0;
    }
    pa_plot_yaxis(pl, 100.0, "share, %");
    pa_plot_bars(pl, labels, 5, series, 2, 100.0);
    pa_plot_legend(pl, names, 2);
    return PA_OK;
}

/* Draws TCP vs UDP lines of two series; scale converts a bin value into a plotted value. */
static pa_status_t draw_rate_chart(pa_plot_t *pl, const pa_series_t *tcp, const pa_series_t *udp,
                                   double scale, const char *ylabel) {
    static const char *const names[2] = {"TCP", "UDP"};
    size_t n = tcp->values.len;
    double *a = malloc((n ? n : 1) * sizeof *a), *b = malloc((n ? n : 1) * sizeof *b);
    const double *series[2];
    double ymax = 0.0;

    if (!a || !b) {
        free(a);
        free(b);
        return PA_ERR_NOMEM;
    }
    for (size_t i = 0; i < n; i++) {
        a[i] = *(double *)pa_vec_at(&tcp->values, i) * scale / tcp->bin_sec;
        b[i] = *(double *)pa_vec_at(&udp->values, i) * scale / udp->bin_sec;
        ymax = fmax(ymax, fmax(a[i], b[i]));
    }
    series[0] = a;
    series[1] = b;
    ymax = pa_plot_nice_max(ymax * 1.05);
    pa_plot_yaxis(pl, ymax, ylabel);
    pa_plot_lines(pl, series, 2, n, ymax);
    pa_plot_xticks(pl, 0.0, (double)n * tcp->bin_sec, "s");
    pa_plot_legend(pl, names, 2);
    free(a);
    free(b);
    return PA_OK;
}

static pa_status_t chart_throughput(pa_plot_t *pl, const pa_report_t *r) {
    return draw_rate_chart(pl, &r->tcp_bytes, &r->udp_bytes, 8.0, "bit/s");
}

static pa_status_t chart_packet_rate(pa_plot_t *pl, const pa_report_t *r) {
    return draw_rate_chart(pl, &r->tcp_packets, &r->udp_packets, 1.0, "packets/s");
}

/* Histogram as bars: optional underflow, in-range bins labelled by lower edge, optional overflow. */
static pa_status_t draw_hist(pa_plot_t *pl, const pa_histogram_t *h, const char *ylabel) {
    char lab[PA_HIST_MAX_BINS + 2][24];
    const char *lp[PA_HIST_MAX_BINS + 2];
    double v[PA_HIST_MAX_BINS + 2];
    const double *series[1] = {v};
    size_t n = 0;
    double ymax = 0.0;

    if (!h->counts || h->n == 0) {
        pa_plot_nodata(pl);
        return PA_OK;
    }
    if (h->counts[0] > 0) {
        char t[16];
        pa_format_si(h->lo, t, sizeof t);
        snprintf(lab[n], sizeof lab[n], "<%s", t);
        v[n++] = (double)h->counts[0];
    }
    for (uint32_t i = 0; i < h->n_bins; i++) {
        pa_format_si(pa_hist_edge(h, i), lab[n], sizeof lab[n]);
        v[n++] = (double)h->counts[i + 1];
    }
    if (h->counts[h->n_bins + 1] > 0) {
        char t[16];
        pa_format_si(h->hi, t, sizeof t);
        snprintf(lab[n], sizeof lab[n], ">=%s", t);
        v[n++] = (double)h->counts[h->n_bins + 1];
    }
    for (size_t i = 0; i < n; i++) {
        lp[i] = lab[i];
        ymax = fmax(ymax, v[i]);
    }
    ymax = pa_plot_nice_max(ymax * 1.05);
    pa_plot_yaxis(pl, ymax, ylabel);
    pa_plot_bars(pl, lp, n, series, 1, ymax);
    return PA_OK;
}

static pa_status_t chart_packet_size(pa_plot_t *pl, const pa_report_t *r) {
    return draw_hist(pl, &r->pkt_size, "packets per size bin (bytes)");
}

static pa_status_t chart_rtt(pa_plot_t *pl, const pa_report_t *r) {
    return draw_hist(pl, &r->tcp_rtt_ms, "handshakes per RTT bin (ms)");
}

static pa_status_t chart_flow_duration(pa_plot_t *pl, const pa_report_t *r) {
    return draw_hist(pl, &r->flow_duration, "flows per duration bin (s)");
}

static int cmp_top_desc(const void *x, const void *y) {
    const pa_top_entry_t *a = x, *b = y;

    return (a->bytes < b->bytes) - (a->bytes > b->bytes);
}

static pa_status_t draw_top(pa_plot_t *pl, const pa_top_entry_t *e, size_t n) {
    const char *labels[1000];
    double vals[1000];

    if (n > 1000) {
        n = 1000;
    }
    for (size_t i = 0; i < n; i++) {
        labels[i] = e[i].label;
        vals[i] = (double)e[i].bytes;
    }
    pa_plot_hbars_bytes(pl, labels, vals, n);
    return PA_OK;
}

static pa_status_t chart_top_talkers(pa_plot_t *pl, const pa_report_t *r) {
    return draw_top(pl, r->top_hosts.data, r->top_hosts.len);
}

static pa_status_t chart_top_ports(pa_plot_t *pl, const pa_report_t *r) {
    size_t nt = r->top_tcp_ports.len, nu = r->top_udp_ports.len;
    pa_top_entry_t *all = malloc((nt + nu + 1) * sizeof *all);
    size_t n = nt + nu;
    pa_status_t st;

    if (!all) {
        return PA_ERR_NOMEM;
    }
    if (nt) {
        memcpy(all, r->top_tcp_ports.data, nt * sizeof *all);
    }
    if (nu) {
        memcpy(all + nt, r->top_udp_ports.data, nu * sizeof *all);
    }
    if (n > 1) {
        qsort(all, n, sizeof *all, cmp_top_desc);
    }
    if (n > 15) {
        n = 15;
    }
    st = draw_top(pl, all, n);
    free(all);
    return st;
}

static pa_status_t chart_tcp_flags(pa_plot_t *pl, const pa_report_t *r) {
    static const char *const labels[6] = {"SYN", "SYN-ACK", "FIN", "RST", "PSH", "URG"};
    const uint64_t *t = r->tcp_flag_totals;
    uint64_t synack = r->global.tcp_synack_packets;
    uint64_t syn = t[1] > synack ? t[1] - synack : 0;
    double v[6] = {(double)syn, (double)synack, (double)t[0], (double)t[2], (double)t[3],
                   (double)t[5]};
    const double *series[1] = {v};
    double ymax = 0.0;

    for (size_t i = 0; i < 6; i++) {
        ymax = fmax(ymax, v[i]);
    }
    ymax = pa_plot_nice_max(ymax * 1.1);
    pa_plot_yaxis(pl, ymax, "packets");
    pa_plot_bars(pl, labels, 6, series, 1, ymax);
    return PA_OK;
}

static pa_status_t chart_anomalies(pa_plot_t *pl, const pa_report_t *r) {
    cairo_t *cr = pl->cr;
    double t0 = r->global.first_ts, span = r->global.last_ts - r->global.first_ts;
    double rowh = (pl->bottom - pl->top) / PA_ANOM__COUNT;

    if (r->anomalies.len == 0) {
        pa_plot_nodata(pl);
        return PA_OK;
    }
    if (span <= 0.0) {
        span = 1.0;
    }
    for (int i = 0; i < PA_ANOM__COUNT; i++) {
        double y = pl->top + rowh * (i + 0.5);

        cairo_set_source_rgb(cr, 0.9, 0.9, 0.9);
        cairo_move_to(cr, pl->left, y);
        cairo_line_to(cr, pl->right, y);
        cairo_stroke(cr);
        cairo_set_source_rgb(cr, 0.2, 0.2, 0.2);
        pa_plot_text(cr, pl->left - 10.0, y + 5.0, 14.0, PA_ALIGN_RIGHT,
                     pa_anomaly_type_name((pa_anomaly_type_t)i));
    }
    for (size_t i = 0; i < r->anomalies.len; i++) {
        const pa_anomaly_t *a = pa_vec_at(&r->anomalies, i);
        double x = pl->left + (a->ts_start - t0) / span * (pl->right - pl->left);
        double y = pl->top + rowh * ((double)a->type + 0.5);

        cairo_set_source_rgb(cr, a->severity == PA_SEV_HIGH ? 0.84 : (a->severity == PA_SEV_MEDIUM ? 1.0 : 0.17),
                             a->severity == PA_SEV_HIGH ? 0.15 : (a->severity == PA_SEV_MEDIUM ? 0.5 : 0.63),
                             a->severity == PA_SEV_HIGH ? 0.16 : (a->severity == PA_SEV_MEDIUM ? 0.05 : 0.17));
        cairo_arc(cr, x, y, 6.0, 0.0, 6.2831853);
        cairo_fill(cr);
    }
    pa_plot_xticks(pl, 0.0, span, "s");
    return PA_OK;
}

static const chart_desc_t k_charts[] = {
    {"protocol_share.png", "Protocol share", PA_DEFAULT_LEFT_MARGIN, chart_protocol_share},
    {"throughput.png", "Throughput over time", PA_DEFAULT_LEFT_MARGIN, chart_throughput},
    {"packet_rate.png", "Packet rate over time", PA_DEFAULT_LEFT_MARGIN, chart_packet_rate},
    {"packet_size_hist.png", "Packet size distribution", PA_DEFAULT_LEFT_MARGIN,
     chart_packet_size},
    {"top_talkers.png", "Top talkers (bytes)", PA_TOP_LEFT_MARGIN, chart_top_talkers},
    {"top_ports.png", "Top destination ports (bytes)", 200.0, chart_top_ports},
    {"tcp_flags.png", "TCP flags", PA_DEFAULT_LEFT_MARGIN, chart_tcp_flags},
    {"tcp_rtt_hist.png", "TCP handshake RTT", PA_DEFAULT_LEFT_MARGIN, chart_rtt},
    {"flow_duration_hist.png", "Flow duration", PA_DEFAULT_LEFT_MARGIN, chart_flow_duration},
    {"anomalies_timeline.png", "Anomalies timeline", 220.0, chart_anomalies},
};

size_t pa_charts_count(void) { return sizeof k_charts / sizeof k_charts[0]; }

const char *pa_charts_filename(size_t i) { return i < pa_charts_count() ? k_charts[i].file : NULL; }

static pa_status_t render_one(const chart_desc_t *c, const pa_report_t *r, const char *dir) {
    char path[PA_PATH_BUF + 64];
    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, PA_CHART_W, PA_CHART_H);
    cairo_t *cr = NULL;
    pa_plot_t pl;
    pa_status_t st = PA_ERR_RENDER;

    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        goto cleanup;
    }
    cr = cairo_create(surf);
    pa_plot_begin(&pl, cr, PA_CHART_W, PA_CHART_H, c->title, c->left);
    st = c->draw(&pl, r);
    if (st != PA_OK) {
        goto cleanup;
    }
    snprintf(path, sizeof path, "%s/%s", dir, c->file);
    if (cairo_status(cr) != CAIRO_STATUS_SUCCESS ||
        cairo_surface_write_to_png(surf, path) != CAIRO_STATUS_SUCCESS) {
        PA_LOG_ERROR("cannot render chart '%s'", path);
        st = PA_ERR_RENDER;
    }

cleanup:
    if (cr) {
        cairo_destroy(cr);
    }
    cairo_surface_destroy(surf);
    return st;
}

pa_status_t pa_charts_render_all(const pa_report_t *r, const char *out_dir) {
    char dir[PA_PATH_BUF];
    pa_status_t st;

    if (!r || !out_dir) {
        return PA_ERR_ARGS;
    }
    snprintf(dir, sizeof dir, "%s/charts", out_dir);
    st = pa_mkdir_p(dir);
    for (size_t i = 0; st == PA_OK && i < pa_charts_count(); i++) {
        st = render_one(&k_charts[i], r, dir);
    }
    return st;
}
