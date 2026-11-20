#include "core/status.h"

const char *pa_status_str(pa_status_t s) {
    switch (s) {
    case PA_OK:
        return "ok";
    case PA_ERR_ARGS:
        return "invalid arguments";
    case PA_ERR_IO:
        return "I/O error";
    case PA_ERR_FORMAT:
        return "bad format";
    case PA_ERR_TRUNCATED:
        return "truncated data";
    case PA_ERR_UNSUPPORTED:
        return "unsupported";
    case PA_ERR_NOMEM:
        return "out of memory";
    case PA_ERR_RENDER:
        return "render error";
    case PA_ERR_INTERNAL:
        return "internal error";
    }
    return "unknown";
}
