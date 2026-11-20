#ifndef PA_ANALYSIS_STATS_H
#define PA_ANALYSIS_STATS_H

#include <stdint.h>

#include "core/status.h"

#define PA_HIST_MAX_BINS 32

typedef struct {
    uint64_t packets, bytes;
    uint64_t pkts_by_l4[5], bytes_by_l4[5]; /* TCP, UDP, ICMP, ICMP6, OTHER */
    uint64_t ipv4_packets, ipv6_packets, non_ip_packets;
    uint64_t malformed_packets;
    uint64_t tcp_flows, udp_flows;
    uint64_t tcp_hs_complete, tcp_hs_syn_only, tcp_hs_no_ack;
    uint64_t tcp_retrans, tcp_segments_with_data;
    uint64_t tcp_synack_packets; /* SYN+ACK segments, to split them from plain SYN in charts */
    uint64_t udp_dns_packets;    /* UDP packets with port 53 on either side */
    double first_ts, last_ts;
} pa_global_stats_t;

typedef struct {
    double lo, hi;
    uint32_t n_bins;
    uint8_t log_scale;
    uint64_t *counts; /* n_bins + 2: [0] underflow, [1..n_bins], [n_bins+1] overflow */
    double sum, sum_sq, min, max;
    uint64_t n;
} pa_histogram_t;

typedef struct {
    char label[64];
    uint64_t packets, bytes;
    double share; /* 0..1 of total bytes */
} pa_top_entry_t;

typedef struct {
    uint64_t packets, bytes, flows;
} pa_port_stats_t;

/** Allocates h->counts; release with pa_hist_free(). */
pa_status_t pa_hist_init(pa_histogram_t *h, double lo, double hi, uint32_t n_bins,
                         uint8_t log_scale);
void pa_hist_add(pa_histogram_t *h, double v);
/** Lower edge of in-range bin i (0-based); i == n_bins gives hi. */
double pa_hist_edge(const pa_histogram_t *h, uint32_t i);
void pa_hist_free(pa_histogram_t *h);

struct pa_analyzer_ops;
extern const struct pa_analyzer_ops pa_stats_analyzer_ops;

#endif
