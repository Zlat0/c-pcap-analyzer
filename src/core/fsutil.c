#include "core/fsutil.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "core/log.h"

#define PA_PATH_MAX 1024

static pa_status_t make_one(const char *p) {
    if (mkdir(p, 0777) != 0 && errno != EEXIST) {
        PA_LOG_ERROR("cannot create directory '%s': %s", p, strerror(errno));
        return PA_ERR_IO;
    }
    return PA_OK;
}

pa_status_t pa_mkdir_p(const char *path) {
    char buf[PA_PATH_MAX];
    size_t len;

    if (!path || !*path) {
        return PA_ERR_ARGS;
    }
    len = strlen(path);
    if (len >= sizeof buf) {
        return PA_ERR_ARGS;
    }
    memcpy(buf, path, len + 1);
    for (size_t i = 1; i < len; i++) {
        if (buf[i] == '/') {
            buf[i] = '\0';
            if (make_one(buf) != PA_OK) {
                return PA_ERR_IO;
            }
            buf[i] = '/';
        }
    }
    return make_one(buf);
}
