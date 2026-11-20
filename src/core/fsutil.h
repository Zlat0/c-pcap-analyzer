#ifndef PA_CORE_FSUTIL_H
#define PA_CORE_FSUTIL_H

#include "core/status.h"

/** Creates a directory and all missing parents (like mkdir -p). */
pa_status_t pa_mkdir_p(const char *path);

#endif
