#ifndef PA_ANALYSIS_HOST_TABLE_H
#define PA_ANALYSIS_HOST_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "core/status.h"
#include "decode/decoder.h"

typedef struct {
    uint64_t key; /* 0 = empty slot */
    double ts;
    uint16_t port;
} pa_wentry_t;

/* Hash set of unique keys per tumbling window of window_sec (cleared when the window ends). */
typedef struct {
    pa_wentry_t *e;
    size_t cap, count;
    double start_ts;
} pa_window_set_t;

/* Ring buffer of the last 8 one-second bins. */
typedef struct {
    uint32_t bins[8];
    double base_ts;
} pa_rate_t;

typedef struct {
    pa_addr_t addr;
    uint64_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    uint32_t flows_initiated, flows_accepted;
    uint32_t syn_sent, synack_recv, rst_sent, rst_recv;
    uint32_t syn_recv, hs_complete_in; /* SYN-flood ratio: completed handshakes / SYNs received */
    pa_window_set_t dst_ports;         /* unique (dst_ip,dst_port) probed by SYN */
    pa_window_set_t dst_hosts;         /* same keys, queried per port for host scans */
    pa_rate_t syn_in_rate, rst_rate, udp_in_rate;
    int64_t udp_hot_sec;
    uint32_t udp_hot_streak;
    double udp_hot_start;
} pa_host_stats_t;

typedef struct pa_host_table pa_host_table_t;

/** Returns 1 if the key is new in the window, 0 if present, -1 on allocation failure. */
int pa_wset_add(pa_window_set_t *s, uint64_t key, uint16_t port, double ts, double window_sec);
size_t pa_wset_count_port(const pa_window_set_t *s, uint16_t port);
void pa_wset_free(pa_window_set_t *s);
/** Counts an event at ts and returns the number of events in that second. */
uint32_t pa_rate_add(pa_rate_t *r, double ts);

pa_status_t pa_host_table_create(size_t initial_cap, pa_host_table_t **out);
/** Entries are individually allocated and stay valid until pa_host_table_destroy(). */
pa_status_t pa_host_table_get_or_insert(pa_host_table_t *t, const pa_addr_t *addr,
                                        pa_host_stats_t **out);
pa_host_stats_t *pa_host_table_lookup(const pa_host_table_t *t, const pa_addr_t *addr);
void pa_host_table_foreach(const pa_host_table_t *t, void (*fn)(const pa_host_stats_t *, void *),
                           void *ud);
size_t pa_host_table_size(const pa_host_table_t *t);
void pa_host_table_destroy(pa_host_table_t *t);

#endif
