#ifndef PA_REPORT_FORMAT_H
#define PA_REPORT_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "decode/decoder.h"

/** All formatters write at most n bytes including the terminating NUL. */
void pa_format_addr(const pa_addr_t *a, char *buf, size_t n);
void pa_format_endpoint(const pa_addr_t *a, uint16_t port, char *buf, size_t n);
/** "1.50 MB" style, base 1024. */
void pa_format_bytes(double bytes, char *buf, size_t n);
/** "1.50k" style compact number for chart axes, base 1000. */
void pa_format_si(double v, char *buf, size_t n);
/** "850 ms", "12.5 s", "3 m 05 s", "1 h 02 m". */
void pa_format_duration(double sec, char *buf, size_t n);
/** "12.3 Mbit/s" style. */
void pa_format_bps(double bps, char *buf, size_t n);

#endif
