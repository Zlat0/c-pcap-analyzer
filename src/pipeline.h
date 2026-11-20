#ifndef PA_PIPELINE_H
#define PA_PIPELINE_H

#include "core/config.h"
#include "core/status.h"
#include "report/report_model.h"

/** Reads all input files in a single pass through every analyzer and fills *report. */
pa_status_t pa_pipeline_run(const pa_config_t *cfg, pa_report_t *report);

#endif
