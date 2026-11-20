#ifndef PA_ANALYSIS_ANOMALY_H
#define PA_ANALYSIS_ANOMALY_H

#include <stdint.h>

#include "core/status.h"
#include "core/vec.h"
#include "decode/decoder.h"

#define PA_ANOM_MAX 5000

typedef enum {
    PA_ANOM_PORT_SCAN = 0,
    PA_ANOM_HOST_SCAN,
    PA_ANOM_SYN_FLOOD,
    PA_ANOM_HIGH_RETRANS,
    PA_ANOM_RST_STORM,
    PA_ANOM_ZERO_WINDOW,
    PA_ANOM_UDP_FLOOD,
    PA_ANOM_MALFORMED,
    PA_ANOM_SUSPICIOUS_FLAGS,
    PA_ANOM__COUNT
} pa_anomaly_type_t;

typedef enum { PA_SEV_LOW = 0, PA_SEV_MEDIUM, PA_SEV_HIGH } pa_severity_t;

typedef struct {
    pa_anomaly_type_t type;
    pa_severity_t severity;
    double ts_start, ts_end;
    pa_addr_t src, dst; /* family = 0: not applicable */
    uint16_t dport;     /* 0: not applicable */
    uint64_t flow_id;   /* 0: host-level or global */
    double metric;
    double threshold;
    char desc[160];
} pa_anomaly_t;

const char *pa_anomaly_type_name(pa_anomaly_type_t t);
const char *pa_severity_name(pa_severity_t s);
/**
 * Appends an anomaly, or merges it into an existing one with the same (type, src, dst, dport):
 * ts_end is extended and metric keeps the maximum. Silently drops entries beyond PA_ANOM_MAX.
 */
pa_status_t pa_anomaly_add(pa_vec_t *vec, const pa_anomaly_t *a);

struct pa_analyzer_ops;
extern const struct pa_analyzer_ops pa_anomaly_analyzer_ops;

#endif
