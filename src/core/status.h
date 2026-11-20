#ifndef PA_CORE_STATUS_H
#define PA_CORE_STATUS_H

typedef enum {
    PA_OK = 0,
    PA_ERR_ARGS,
    PA_ERR_IO,
    PA_ERR_FORMAT,
    PA_ERR_TRUNCATED,
    PA_ERR_UNSUPPORTED,
    PA_ERR_NOMEM,
    PA_ERR_RENDER,
    PA_ERR_INTERNAL
} pa_status_t;

/** Returns a static string, never NULL. */
const char *pa_status_str(pa_status_t s);

#endif
