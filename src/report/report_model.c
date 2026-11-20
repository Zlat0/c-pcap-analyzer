#include "report/report_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/config.h"
#include "core/timeutil.h"
#include "report/format.h"

pa_status_t pa_report_create(pa_report_t **out) {
    pa_report_t *r;

    if (!out) {
        return PA_ERR_ARGS;
    }
    r = calloc(1, sizeof *r);
    if (!r) {
        return PA_ERR_NOMEM;
    }
    r->version = PA_VERSION;
    pa_time_now_iso(r->generated_at, sizeof r->generated_at);
    pa_vec_init(&r->captures, sizeof(pa_capture_info_t));
    pa_vec_init(&r->top_hosts, sizeof(pa_top_entry_t));
    pa_vec_init(&r->top_tcp_ports, sizeof(pa_top_entry_t));
    pa_vec_init(&r->top_udp_ports, sizeof(pa_top_entry_t));
    pa_vec_init(&r->top_conversations, sizeof(pa_top_entry_t));
    pa_vec_init(&r->worst_tcp_flows, sizeof(pa_flow_row_t));
    pa_vec_init(&r->top_udp_flows, sizeof(pa_flow_row_t));
    pa_vec_init(&r->anomalies, sizeof(pa_anomaly_t));
    pa_vec_init(&r->tcp_bytes.values, sizeof(double));
    pa_vec_init(&r->udp_bytes.values, sizeof(double));
    pa_vec_init(&r->tcp_packets.values, sizeof(double));
    pa_vec_init(&r->udp_packets.values, sizeof(double));
    *out = r;
    return PA_OK;
}

void pa_report_destroy(pa_report_t *r) {
    if (!r) {
        return;
    }
    pa_vec_free(&r->captures);
    pa_vec_free(&r->top_hosts);
    pa_vec_free(&r->top_tcp_ports);
    pa_vec_free(&r->top_udp_ports);
    pa_vec_free(&r->top_conversations);
    pa_vec_free(&r->worst_tcp_flows);
    pa_vec_free(&r->top_udp_flows);
    pa_vec_free(&r->anomalies);
    pa_vec_free(&r->tcp_bytes.values);
    pa_vec_free(&r->udp_bytes.values);
    pa_vec_free(&r->tcp_packets.values);
    pa_vec_free(&r->udp_packets.values);
    pa_hist_free(&r->pkt_size);
    pa_hist_free(&r->flow_duration);
    pa_hist_free(&r->flow_bytes);
    pa_hist_free(&r->tcp_rtt_ms);
    pa_hist_free(&r->udp_dgram_size);
    free(r);
}

void pa_flow_row_fill(pa_flow_row_t *row, const pa_flow_t *f) {
    char a[48], b[48];

    memset(row, 0, sizeof *row);
    pa_format_endpoint(&f->key.addr_a, f->key.port_a, a, sizeof a);
    pa_format_endpoint(&f->key.addr_b, f->key.port_b, b, sizeof b);
    snprintf(row->label, sizeof row->label, "%.44s <-> %.44s", a, b);
    row->packets = f->dir[0].packets + f->dir[1].packets;
    row->bytes = f->dir[0].bytes + f->dir[1].bytes;
    row->duration = f->last_ts - f->first_ts;
    row->rtt_ms = -1.0;
    row->end_reason = f->end_reason;
}
