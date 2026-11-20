#ifndef PA_ANALYSIS_ANALYZER_H
#define PA_ANALYSIS_ANALYZER_H

#include <stddef.h>

#include "analysis/host_table.h"
#include "analysis/stats.h"
#include "core/config.h"
#include "core/status.h"
#include "core/vec.h"
#include "decode/decoder.h"
#include "flow/flow_table.h"
#include "report/report_model.h"

typedef struct {
    const pa_config_t *cfg;
    pa_flow_table_t *flows;
    pa_host_table_t *hosts;
    pa_global_stats_t *global;
    pa_vec_t *anomalies; /* of pa_anomaly_t */
} pa_analysis_ctx_t;

typedef struct pa_analyzer_ops {
    const char *name;
    pa_status_t (*init)(pa_analysis_ctx_t *ctx, void **state);
    /* flow == NULL for packets that are not TCP/UDP */
    void (*on_packet)(void *state, pa_analysis_ctx_t *ctx, const pa_packet_t *p, pa_flow_t *flow,
                      pa_dir_t dir);
    void (*on_flow_end)(void *state, pa_analysis_ctx_t *ctx, const pa_flow_t *flow);
    pa_status_t (*finalize)(void *state, pa_analysis_ctx_t *ctx, pa_report_t *report);
    void (*destroy)(void *state);
} pa_analyzer_ops_t;

/** Returns the analyzers in call order (stats, timeseries, tcp, udp, anomaly). */
const pa_analyzer_ops_t *const *pa_analyzer_registry(size_t *count);

#endif
