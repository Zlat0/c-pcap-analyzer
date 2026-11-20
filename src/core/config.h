#ifndef PA_CORE_CONFIG_H
#define PA_CORE_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define PA_MAX_INPUTS 32
#define PA_VERSION "0.1.0"

typedef struct {
    double window_sec;
    uint32_t port_scan_ports;
    uint32_t host_scan_hosts;
    uint32_t syn_flood_rate;
    double syn_flood_complete_ratio;
    uint32_t retrans_min_segments;
    double retrans_ratio;
    uint32_t rst_storm_rate;
    uint32_t zero_window_events;
    uint32_t udp_flood_pps;
    double udp_flood_min_sec;
} pa_thresholds_t;

typedef struct {
    const char *inputs[PA_MAX_INPUTS];
    size_t n_inputs;
    const char *out_dir;
    const char *bpf_filter;
    double bin_sec;
    uint32_t top_n;
    uint8_t make_pdf, make_png;
    int log_level;
    double tcp_timeout_sec;
    double udp_timeout_sec;
    pa_thresholds_t th;
} pa_config_t;

void pa_config_defaults(pa_config_t *cfg);

#endif
