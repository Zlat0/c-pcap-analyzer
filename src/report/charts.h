#ifndef PA_REPORT_CHARTS_H
#define PA_REPORT_CHARTS_H

#include <stddef.h>

#include "core/status.h"
#include "report/report_model.h"

/** Renders all PNG charts into out_dir/charts/ (created if missing). */
pa_status_t pa_charts_render_all(const pa_report_t *r, const char *out_dir);
size_t pa_charts_count(void);
/** File name (without directory) of chart i, e.g. "throughput.png". */
const char *pa_charts_filename(size_t i);

#endif
