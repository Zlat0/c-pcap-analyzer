#ifndef PA_REPORT_REPORT_MODEL_H
#define PA_REPORT_REPORT_MODEL_H

#include <stdint.h>

#include "analysis/anomaly.h"
#include "analysis/stats.h"
#include "analysis/timeseries.h"
#include "core/status.h"
#include "core/vec.h"
#include "flow/flow_table.h"

typedef struct {
    char path[256];
    uint64_t file_size, packets;
    double first_ts, last_ts;
    int dlt;
} pa_capture_info_t;

typedef struct {
    char label[96]; /* "a:port <-> b:port" */
    uint64_t packets, bytes;
    double duration, rtt_ms; /* rtt_ms < 0: unknown */
    double retrans_ratio;
    uint32_t zero_window;
    pa_flow_end_t end_reason;
} pa_flow_row_t;

typedef struct pa_report {
    char generated_at[32]; /* ISO 8601 */
    const char *version;
    pa_vec_t captures; /* pa_capture_info_t */
    pa_global_stats_t global;
    pa_series_t tcp_bytes, udp_bytes, tcp_packets, udp_packets;
    pa_histogram_t pkt_size, flow_duration, flow_bytes, tcp_rtt_ms, udp_dgram_size;
    uint64_t tcp_flag_totals[8];
    pa_vec_t top_hosts; /* pa_top_entry_t, <= top_n */
    pa_vec_t top_tcp_ports, top_udp_ports, top_conversations;
    pa_vec_t worst_tcp_flows; /* pa_flow_row_t, sorted by retrans_ratio */
    pa_vec_t top_udp_flows;   /* pa_flow_row_t, sorted by bytes */
    pa_vec_t anomalies;       /* pa_anomaly_t, severity desc, ts asc */
    uint32_t anomaly_counts[PA_ANOM__COUNT];
} pa_report_t;

/** Allocates an empty report; the caller releases it with pa_report_destroy(). */
pa_status_t pa_report_create(pa_report_t **out);
/** Frees the report and everything it owns (strings, vectors, histograms). NULL is safe. */
void pa_report_destroy(pa_report_t *r);
/** Fills the common columns of a flow row (rtt unknown, no retransmissions). */
void pa_flow_row_fill(pa_flow_row_t *row, const pa_flow_t *f);

#endif
