#include "report/format.h"

#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <sys/socket.h>

void pa_format_addr(const pa_addr_t *a, char *buf, size_t n) {
    if (n == 0) {
        return;
    }
    if (a->family == 4) {
        if (!inet_ntop(AF_INET, a->bytes, buf, (socklen_t)n)) {
            snprintf(buf, n, "?");
        }
    } else if (a->family == 6) {
        if (!inet_ntop(AF_INET6, a->bytes, buf, (socklen_t)n)) {
            snprintf(buf, n, "?");
        }
    } else {
        snprintf(buf, n, "-");
    }
}

void pa_format_endpoint(const pa_addr_t *a, uint16_t port, char *buf, size_t n) {
    char ip[48];

    pa_format_addr(a, ip, sizeof ip);
    if (a->family == 6) {
        snprintf(buf, n, "[%s]:%u", ip, (unsigned)port);
    } else {
        snprintf(buf, n, "%s:%u", ip, (unsigned)port);
    }
}

void pa_format_bytes(double bytes, char *buf, size_t n) {
    static const char *const units[] = {"B", "KB", "MB", "GB", "TB"};
    size_t u = 0;

    while (bytes >= 1024.0 && u < 4) {
        bytes /= 1024.0;
        u++;
    }
    if (u == 0) {
        snprintf(buf, n, "%.0f B", bytes);
    } else {
        snprintf(buf, n, "%.2f %s", bytes, units[u]);
    }
}

void pa_format_si(double v, char *buf, size_t n) {
    double av = fabs(v);

    if (av >= 1e9) {
        snprintf(buf, n, "%.3gG", v / 1e9);
    } else if (av >= 1e6) {
        snprintf(buf, n, "%.3gM", v / 1e6);
    } else if (av >= 1e3) {
        snprintf(buf, n, "%.3gk", v / 1e3);
    } else {
        snprintf(buf, n, "%.3g", v);
    }
}

void pa_format_duration(double sec, char *buf, size_t n) {
    if (sec < 1.0) {
        snprintf(buf, n, "%.0f ms", sec * 1000.0);
    } else if (sec < 60.0) {
        snprintf(buf, n, "%.2f s", sec);
    } else if (sec < 3600.0) {
        snprintf(buf, n, "%d m %02d s", (int)(sec / 60.0), (int)fmod(sec, 60.0));
    } else {
        snprintf(buf, n, "%d h %02d m", (int)(sec / 3600.0), (int)fmod(sec / 60.0, 60.0));
    }
}

void pa_format_bps(double bps, char *buf, size_t n) {
    static const char *const units[] = {"bit/s", "kbit/s", "Mbit/s", "Gbit/s"};
    size_t u = 0;

    while (bps >= 1000.0 && u < 3) {
        bps /= 1000.0;
        u++;
    }
    snprintf(buf, n, "%.2f %s", bps, units[u]);
}
