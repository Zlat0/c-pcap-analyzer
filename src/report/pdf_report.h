#ifndef PA_REPORT_PDF_REPORT_H
#define PA_REPORT_PDF_REPORT_H

#include "core/status.h"
#include "report/report_model.h"

/** Builds a multi-page A4 PDF at pdf_path, embedding the PNG charts found in charts_dir. */
pa_status_t pa_pdf_render(const pa_report_t *r, const char *charts_dir, const char *pdf_path);

#endif
