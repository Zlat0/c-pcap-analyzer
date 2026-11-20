#include "report/pdf_report.h"

#include <cairo-pdf.h>
#include <cairo.h>
#include <stdio.h>
#include <string.h>

#include "core/log.h"
#include "core/timeutil.h"
#include "report/charts.h"
#include "report/format.h"
#include "report/plot.h"

#define PG_W 595.0
#define PG_H 842.0
#define MARGIN 40.0
#define CONTENT_W (PG_W - 2.0 * MARGIN)
#define ROW_H 14.0
#define MAX_ANOM_ROWS 300

typedef struct {
    cairo_t *cr;
    double y;
    const char *charts_dir;
} pdf_t;

typedef struct {
    const char *title;
    double w;
} col_t;

static void font(pdf_t *p, double size, int bold) {
    cairo_select_font_face(p->cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(p->cr, size);
}

static void new_page(pdf_t *p) {
    cairo_show_page(p->cr);
    p->y = MARGIN;
}

static void ensure(pdf_t *p, double h) {
    if (p->y + h > PG_H - MARGIN) {
        new_page(p);
    }
}

static void heading(pdf_t *p, const char *text, double size) {
    ensure(p, size * 2.5);
    font(p, size, 1);
    cairo_set_source_rgb(p->cr, 0.1, 0.1, 0.1);
    p->y += size * 1.2;
    cairo_move_to(p->cr, MARGIN, p->y);
    cairo_show_text(p->cr, text);
    p->y += size * 0.8;
}

static void kv(pdf_t *p, const char *key, const char *val) {
    ensure(p, ROW_H + 2);
    font(p, 10, 0);
    cairo_set_source_rgb(p->cr, 0.35, 0.35, 0.35);
    cairo_move_to(p->cr, MARGIN, p->y + ROW_H - 3);
    cairo_show_text(p->cr, key);
    cairo_set_source_rgb(p->cr, 0.0, 0.0, 0.0);
    cairo_move_to(p->cr, MARGIN + 200.0, p->y + ROW_H - 3);
    cairo_show_text(p->cr, val);
    p->y += ROW_H + 2;
}

static void kv_u64(pdf_t *p, const char *key, uint64_t v) {
    char buf[32];

    snprintf(buf, sizeof buf, "%llu", (unsigned long long)v);
    kv(p, key, buf);
}

static void cell(pdf_t *p, double x, double w, const char *text) {
    cairo_save(p->cr);
    cairo_rectangle(p->cr, x, p->y, w - 3.0, ROW_H);
    cairo_clip(p->cr);
    cairo_move_to(p->cr, x, p->y + ROW_H - 4.0);
    cairo_show_text(p->cr, text);
    cairo_restore(p->cr);
}

static void table_header(pdf_t *p, const col_t *c, size_t n) {
    double x = MARGIN;

    ensure(p, ROW_H * 3);
    cairo_set_source_rgb(p->cr, 0.9, 0.92, 0.96);
    cairo_rectangle(p->cr, MARGIN, p->y, CONTENT_W, ROW_H);
    cairo_fill(p->cr);
    font(p, 8, 1);
    cairo_set_source_rgb(p->cr, 0.1, 0.1, 0.1);
    for (size_t i = 0; i < n; i++) {
        cell(p, x + 2.0, c[i].w, c[i].title);
        x += c[i].w;
    }
    p->y += ROW_H;
}

static void table_row(pdf_t *p, const col_t *c, size_t n, const char *const *cells) {
    double x = MARGIN;

    ensure(p, ROW_H);
    font(p, 8, 0);
    cairo_set_source_rgb(p->cr, 0.0, 0.0, 0.0);
    for (size_t i = 0; i < n; i++) {
        cell(p, x + 2.0, c[i].w, cells[i]);
        x += c[i].w;
    }
    cairo_set_source_rgb(p->cr, 0.88, 0.88, 0.88);
    cairo_set_line_width(p->cr, 0.4);
    cairo_move_to(p->cr, MARGIN, p->y + ROW_H);
    cairo_line_to(p->cr, MARGIN + CONTENT_W, p->y + ROW_H);
    cairo_stroke(p->cr);
    p->y += ROW_H;
}

static void note(pdf_t *p, const char *text) {
    ensure(p, ROW_H);
    font(p, 9, 0);
    cairo_set_source_rgb(p->cr, 0.4, 0.4, 0.4);
    cairo_move_to(p->cr, MARGIN, p->y + ROW_H - 3);
    cairo_show_text(p->cr, text);
    p->y += ROW_H + 4;
}

static void chart(pdf_t *p, const char *file) {
    char path[1024];
    cairo_surface_t *img;
    double h = CONTENT_W * 700.0 / 1200.0, scale = CONTENT_W / 1200.0;

    snprintf(path, sizeof path, "%s/%s", p->charts_dir, file);
    img = cairo_image_surface_create_from_png(path);
    if (cairo_surface_status(img) != CAIRO_STATUS_SUCCESS) {
        PA_LOG_WARN("chart '%s' is not available, skipped in PDF", path);
        cairo_surface_destroy(img);
        return;
    }
    ensure(p, h + 6.0);
    cairo_save(p->cr);
    cairo_translate(p->cr, MARGIN, p->y);
    cairo_scale(p->cr, scale, scale);
    cairo_set_source_surface(p->cr, img, 0.0, 0.0);
    cairo_paint(p->cr);
    cairo_restore(p->cr);
    cairo_surface_destroy(img);
    p->y += h + 6.0;
}

static void title_page(pdf_t *p, const pa_report_t *r) {
    char buf[128];

    p->y = 120.0;
    heading(p, "pcapan - PCAP Traffic Report", 24);
    p->y += 10.0;
    kv(p, "Generated at", r->generated_at);
    kv(p, "Version", r->version);
    p->y += 16.0;
    heading(p, "Input files", 14);
    for (size_t i = 0; i < r->captures.len; i++) {
        const pa_capture_info_t *c = pa_vec_at(&r->captures, i);
        char a[32], t0[32], t1[32];

        pa_format_bytes((double)c->file_size, a, sizeof a);
        pa_time_format_iso(c->first_ts, t0, sizeof t0);
        pa_time_format_iso(c->last_ts, t1, sizeof t1);
        kv(p, "File", c->path);
        snprintf(buf, sizeof buf, "%s, %llu packets", a, (unsigned long long)c->packets);
        kv(p, "  size", buf);
        snprintf(buf, sizeof buf, "%s  ->  %s", t0, t1);
        kv(p, "  capture time", buf);
        p->y += 6.0;
    }
}

static void summary_page(pdf_t *p, const pa_report_t *r) {
    const pa_global_stats_t *g = &r->global;
    double dur = g->last_ts - g->first_ts;
    char buf[64];

    new_page(p);
    heading(p, "Summary", 18);
    pa_format_duration(dur, buf, sizeof buf);
    kv(p, "Capture duration", buf);
    kv_u64(p, "Packets", g->packets);
    pa_format_bytes((double)g->bytes, buf, sizeof buf);
    kv(p, "Bytes", buf);
    snprintf(buf, sizeof buf, "%.1f", dur > 0.0 ? (double)g->packets / dur : 0.0);
    kv(p, "Average packets/s", buf);
    pa_format_bps(dur > 0.0 ? (double)g->bytes * 8.0 / dur : 0.0, buf, sizeof buf);
    kv(p, "Average throughput", buf);
    kv_u64(p, "TCP packets", g->pkts_by_l4[0]);
    kv_u64(p, "UDP packets", g->pkts_by_l4[1]);
    kv_u64(p, "ICMP/ICMPv6 packets", g->pkts_by_l4[2] + g->pkts_by_l4[3]);
    kv_u64(p, "Other L4 packets", g->pkts_by_l4[4]);
    snprintf(buf, sizeof buf, "%llu / %llu / %llu", (unsigned long long)g->ipv4_packets,
             (unsigned long long)g->ipv6_packets, (unsigned long long)g->non_ip_packets);
    kv(p, "IPv4 / IPv6 / non-IP", buf);
    kv_u64(p, "Malformed packets", g->malformed_packets);
    kv_u64(p, "TCP flows", g->tcp_flows);
    kv_u64(p, "UDP flows", g->udp_flows);
    kv_u64(p, "Handshakes complete", g->tcp_hs_complete);
    kv_u64(p, "Handshakes SYN only", g->tcp_hs_syn_only);
    kv_u64(p, "Handshakes without final ACK", g->tcp_hs_no_ack);
    kv_u64(p, "TCP retransmissions", g->tcp_retrans);
    kv_u64(p, "TCP data segments", g->tcp_segments_with_data);
    kv_u64(p, "DNS packets (UDP/53)", g->udp_dns_packets);
    snprintf(buf, sizeof buf, "%zu", r->anomalies.len);
    kv(p, "Anomalies", buf);
}

static void top_table(pdf_t *p, const char *title, const pa_vec_t *v) {
    static const col_t cols[] = {{"#", 25}, {"Label", 270}, {"Packets", 70}, {"Bytes", 90},
                                 {"Share", 60}};
    char num[24], pk[24], by[32], sh[16];

    heading(p, title, 12);
    table_header(p, cols, 5);
    for (size_t i = 0; i < v->len; i++) {
        const pa_top_entry_t *e = pa_vec_at(v, i);
        const char *cells[5] = {num, e->label, pk, by, sh};

        snprintf(num, sizeof num, "%zu", i + 1);
        snprintf(pk, sizeof pk, "%llu", (unsigned long long)e->packets);
        pa_format_bytes((double)e->bytes, by, sizeof by);
        snprintf(sh, sizeof sh, "%.1f%%", e->share * 100.0);
        table_row(p, cols, 5, cells);
    }
    if (v->len == 0) {
        note(p, "(no data)");
    }
}

static void flow_table(pdf_t *p, const char *title, const pa_vec_t *v, int tcp) {
    static const col_t cols[] = {{"Flow", 190}, {"Packets", 50}, {"Bytes", 65}, {"Duration", 60},
                                 {"RTT", 50},   {"Retrans", 50}, {"ZeroWin", 50}};
    char pk[24], by[32], du[32], rtt[24], rt[24], zw[16];

    heading(p, title, 12);
    table_header(p, cols, 7);
    for (size_t i = 0; i < v->len; i++) {
        const pa_flow_row_t *f = pa_vec_at(v, i);
        const char *cells[7] = {f->label, pk, by, du, rtt, rt, zw};

        snprintf(pk, sizeof pk, "%llu", (unsigned long long)f->packets);
        pa_format_bytes((double)f->bytes, by, sizeof by);
        pa_format_duration(f->duration, du, sizeof du);
        if (tcp && f->rtt_ms >= 0.0) {
            snprintf(rtt, sizeof rtt, "%.1f ms", f->rtt_ms);
        } else {
            snprintf(rtt, sizeof rtt, "-");
        }
        snprintf(rt, sizeof rt, "%.1f%%", f->retrans_ratio * 100.0);
        snprintf(zw, sizeof zw, "%u", (unsigned)f->zero_window);
        table_row(p, cols, 7, cells);
    }
    if (v->len == 0) {
        note(p, "(no data)");
    }
}

static void anomaly_table(pdf_t *p, const pa_report_t *r) {
    static const col_t cols[] = {{"Type", 78}, {"Sev", 40},  {"Source", 78},
                                 {"Destination", 78}, {"Time", 50}, {"Description", 191}};
    char s[48], d[48], t[16];

    heading(p, "Detected anomalies", 12);
    table_header(p, cols, 6);
    for (size_t i = 0; i < r->anomalies.len && i < MAX_ANOM_ROWS; i++) {
        const pa_anomaly_t *a = pa_vec_at(&r->anomalies, i);
        const char *cells[6] = {pa_anomaly_type_name(a->type), pa_severity_name(a->severity), s, d, t,
                                a->desc};

        pa_format_addr(&a->src, s, sizeof s);
        pa_format_addr(&a->dst, d, sizeof d);
        pa_time_format_clock(a->ts_start, t, sizeof t);
        table_row(p, cols, 6, cells);
    }
    if (r->anomalies.len == 0) {
        note(p, "No anomalies detected.");
    } else if (r->anomalies.len > MAX_ANOM_ROWS) {
        note(p, "... list truncated, see the log for the remaining entries.");
    }
}

static void build(pdf_t *p, const pa_report_t *r) {
    title_page(p, r);
    summary_page(p, r);
    new_page(p);
    heading(p, "Protocols and throughput", 18);
    chart(p, "protocol_share.png");
    chart(p, "throughput.png");
    chart(p, "packet_rate.png");
    new_page(p);
    heading(p, "Hosts and ports", 18);
    chart(p, "top_talkers.png");
    chart(p, "top_ports.png");
    top_table(p, "Top hosts", &r->top_hosts);
    top_table(p, "Top conversations", &r->top_conversations);
    top_table(p, "Top TCP ports", &r->top_tcp_ports);
    top_table(p, "Top UDP ports", &r->top_udp_ports);
    new_page(p);
    heading(p, "TCP", 18);
    chart(p, "tcp_flags.png");
    chart(p, "tcp_rtt_hist.png");
    chart(p, "flow_duration_hist.png");
    flow_table(p, "Worst TCP flows (retransmissions / zero window)", &r->worst_tcp_flows, 1);
    new_page(p);
    heading(p, "UDP", 18);
    flow_table(p, "Top UDP flows by bytes", &r->top_udp_flows, 0);
    chart(p, "packet_size_hist.png");
    new_page(p);
    heading(p, "Anomalies", 18);
    chart(p, "anomalies_timeline.png");
    anomaly_table(p, r);
}

pa_status_t pa_pdf_render(const pa_report_t *r, const char *charts_dir, const char *pdf_path) {
    cairo_surface_t *surf;
    pdf_t p;
    pa_status_t st = PA_OK;

    if (!r || !charts_dir || !pdf_path) {
        return PA_ERR_ARGS;
    }
    surf = cairo_pdf_surface_create(pdf_path, PG_W, PG_H);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        PA_LOG_ERROR("cannot create PDF '%s'", pdf_path);
        cairo_surface_destroy(surf);
        return PA_ERR_IO;
    }
    p.cr = cairo_create(surf);
    p.y = MARGIN;
    p.charts_dir = charts_dir;
    build(&p, r);
    if (cairo_status(p.cr) != CAIRO_STATUS_SUCCESS) {
        PA_LOG_ERROR("PDF rendering failed: %s", cairo_status_to_string(cairo_status(p.cr)));
        st = PA_ERR_RENDER;
    }
    cairo_destroy(p.cr);
    cairo_surface_finish(surf);
    if (st == PA_OK && cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        st = PA_ERR_RENDER;
    }
    cairo_surface_destroy(surf);
    return st;
}
