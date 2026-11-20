#ifndef PA_CLI_CLI_H
#define PA_CLI_CLI_H

#include <stdio.h>

#include "core/config.h"
#include "core/status.h"

#define PA_CLI_RUN 0
#define PA_CLI_EXIT_HELP 1
#define PA_CLI_EXIT_VERSION 2

/**
 * Parses argv into cfg (pointers refer into argv). *action tells main whether to run or to
 * print help/version and exit successfully.
 */
pa_status_t pa_cli_parse(int argc, char **argv, pa_config_t *cfg, int *action);
void pa_cli_usage(FILE *out);

#endif
