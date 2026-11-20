#include "cli/cli.h"

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "core/log.h"

#define PA_MAX_TOP_N 1000

static const struct option k_long[] = {{"input", required_argument, NULL, 'i'},
                                       {"output", required_argument, NULL, 'o'},
                                       {"filter", required_argument, NULL, 'f'},
                                       {"bin", required_argument, NULL, 'b'},
                                       {"top", required_argument, NULL, 'n'},
                                       {"no-pdf", no_argument, NULL, 1000},
                                       {"no-png", no_argument, NULL, 1001},
                                       {"verbose", no_argument, NULL, 'v'},
                                       {"quiet", no_argument, NULL, 'q'},
                                       {"help", no_argument, NULL, 'h'},
                                       {"version", no_argument, NULL, 1002},
                                       {NULL, 0, NULL, 0}};

void pa_cli_usage(FILE *out) {
    fputs("Usage: pcapan -i <file.pcap> [-i <file2.pcap> ...] -o <out_dir>\n"
          "              [-f \"<bpf filter>\"] [-b <bin_sec=1.0>] [-n <top_n=10>]\n"
          "              [--no-pdf] [--no-png] [-v | -q] [-h] [--version]\n",
          out);
}

static pa_status_t parse_double(const char *s, double *out) {
    char *end = NULL;

    errno = 0;
    *out = strtod(s, &end);
    return (errno == 0 && end != s && *end == '\0') ? PA_OK : PA_ERR_ARGS;
}

static pa_status_t parse_u32(const char *s, uint32_t *out) {
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > PA_MAX_TOP_N) {
        return PA_ERR_ARGS;
    }
    *out = (uint32_t)v;
    return PA_OK;
}

static pa_status_t handle_opt(int c, const char *arg, pa_config_t *cfg, int *action) {
    switch (c) {
    case 'i':
        if (cfg->n_inputs >= PA_MAX_INPUTS) {
            PA_LOG_ERROR("too many input files (max %d)", PA_MAX_INPUTS);
            return PA_ERR_ARGS;
        }
        cfg->inputs[cfg->n_inputs++] = arg;
        return PA_OK;
    case 'o':
        cfg->out_dir = arg;
        return PA_OK;
    case 'f':
        cfg->bpf_filter = arg;
        return PA_OK;
    case 'b':
        return parse_double(arg, &cfg->bin_sec);
    case 'n':
        return parse_u32(arg, &cfg->top_n);
    case 1000:
        cfg->make_pdf = 0;
        return PA_OK;
    case 1001:
        cfg->make_png = 0;
        return PA_OK;
    case 'v':
        cfg->log_level = PA_LVL_DEBUG;
        return PA_OK;
    case 'q':
        cfg->log_level = PA_LVL_ERROR;
        return PA_OK;
    case 'h':
        *action = PA_CLI_EXIT_HELP;
        return PA_OK;
    case 1002:
        *action = PA_CLI_EXIT_VERSION;
        return PA_OK;
    default:
        return PA_ERR_ARGS;
    }
}

pa_status_t pa_cli_parse(int argc, char **argv, pa_config_t *cfg, int *action) {
    int c;

    *action = PA_CLI_RUN;
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:o:f:b:n:vqh", k_long, NULL)) != -1) {
        if (handle_opt(c, optarg, cfg, action) != PA_OK) {
            PA_LOG_ERROR("invalid argument (option -%c / code %d)", c > 255 ? '-' : c, c);
            return PA_ERR_ARGS;
        }
    }
    if (*action != PA_CLI_RUN) {
        return PA_OK;
    }
    if (cfg->n_inputs == 0 || !cfg->out_dir) {
        PA_LOG_ERROR("both -i <file> and -o <out_dir> are required");
        return PA_ERR_ARGS;
    }
    if (!(cfg->bin_sec > 0.0) || cfg->top_n == 0) {
        PA_LOG_ERROR("-b must be > 0 and -n must be in 1..%d", PA_MAX_TOP_N);
        return PA_ERR_ARGS;
    }
    return PA_OK;
}
