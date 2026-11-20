#include "core/config.h"

#include <string.h>

#include "core/log.h"

void pa_config_defaults(pa_config_t *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->bin_sec = 1.0;
    cfg->top_n = 10;
    cfg->make_pdf = 1;
    cfg->make_png = 1;
    cfg->log_level = PA_LVL_INFO;
    cfg->tcp_timeout_sec = 300.0;
    cfg->udp_timeout_sec = 60.0;
    cfg->th.window_sec = 60.0;
    cfg->th.port_scan_ports = 100;
    cfg->th.host_scan_hosts = 50;
    cfg->th.syn_flood_rate = 200;
    cfg->th.syn_flood_complete_ratio = 0.20;
    cfg->th.retrans_min_segments = 20;
    cfg->th.retrans_ratio = 0.05;
    cfg->th.rst_storm_rate = 100;
    cfg->th.zero_window_events = 3;
    cfg->th.udp_flood_pps = 1000;
    cfg->th.udp_flood_min_sec = 3.0;
}
