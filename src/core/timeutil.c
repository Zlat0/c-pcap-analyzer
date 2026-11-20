#include "core/timeutil.h"

#include <stdio.h>
#include <time.h>

double pa_time_from_parts(long sec, long usec) { return (double)sec + (double)usec / 1e6; }

static void format_with(double ts, const char *fmt, char *buf, size_t n) {
    time_t t;
    struct tm tmv;

    if (n == 0) {
        return;
    }
    if (ts <= 0.0) {
        snprintf(buf, n, "-");
        return;
    }
    t = (time_t)ts;
    if (!gmtime_r(&t, &tmv) || strftime(buf, n, fmt, &tmv) == 0) {
        snprintf(buf, n, "-");
    }
}

void pa_time_format_iso(double ts, char *buf, size_t n) {
    format_with(ts, "%Y-%m-%dT%H:%M:%SZ", buf, n);
}

void pa_time_format_clock(double ts, char *buf, size_t n) { format_with(ts, "%H:%M:%S", buf, n); }

void pa_time_now_iso(char *buf, size_t n) { pa_time_format_iso((double)time(NULL), buf, n); }
