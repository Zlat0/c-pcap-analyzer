#ifndef PA_ANALYSIS_TIMESERIES_H
#define PA_ANALYSIS_TIMESERIES_H

#include "core/vec.h"

typedef struct {
    const char *name; /* "tcp_bytes", "udp_packets", ... */
    double start_ts, bin_sec;
    pa_vec_t values; /* double per bin */
} pa_series_t;

struct pa_analyzer_ops;
extern const struct pa_analyzer_ops pa_timeseries_analyzer_ops;

#endif
