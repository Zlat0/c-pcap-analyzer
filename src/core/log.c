#include "core/log.h"

#include <stdarg.h>
#include <stdio.h>

static int g_level = PA_LVL_INFO;

void pa_log_set_level(int level) { g_level = level; }

void pa_log_write(int level, const char *file, int line, const char *fmt, ...) {
    static const char *const names[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    va_list ap;

    if (level > g_level || level < 0 || level > PA_LVL_DEBUG) {
        return;
    }
    if (level == PA_LVL_ERROR || level == PA_LVL_DEBUG) {
        fprintf(stderr, "[%s] %s:%d: ", names[level], file, line);
    } else {
        fprintf(stderr, "[%s] ", names[level]);
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
