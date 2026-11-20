#ifndef PA_CORE_TIMEUTIL_H
#define PA_CORE_TIMEUTIL_H

#include <stddef.h>

double pa_time_from_parts(long sec, long usec);
/** Writes "YYYY-MM-DDTHH:MM:SSZ" (UTC), or "-" for ts <= 0. */
void pa_time_format_iso(double ts, char *buf, size_t n);
/** Writes "HH:MM:SS" (UTC). */
void pa_time_format_clock(double ts, char *buf, size_t n);
void pa_time_now_iso(char *buf, size_t n);

#endif
