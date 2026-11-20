#include "analysis/analyzer.h"
#include "analysis/anomaly.h"
#include "analysis/tcp_analyzer.h"
#include "analysis/timeseries.h"
#include "analysis/udp_analyzer.h"

/* anomaly must stay last: its finalize reads the results of the others. */
static const pa_analyzer_ops_t *const g_registry[] = {
    &pa_stats_analyzer_ops, &pa_timeseries_analyzer_ops, &pa_tcp_analyzer_ops,
    &pa_udp_analyzer_ops,   &pa_anomaly_analyzer_ops,
};

const pa_analyzer_ops_t *const *pa_analyzer_registry(size_t *count) {
    *count = sizeof g_registry / sizeof g_registry[0];
    return g_registry;
}
