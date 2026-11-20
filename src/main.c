#include <stdio.h>
#include <string.h>

#include "cli/cli.h"
#include "core/config.h"
#include "core/log.h"
#include "core/status.h"
#include "pipeline.h"
#include "report/charts.h"
#include "report/format.h"
#include "report/pdf_report.h"
#include "report/report_model.h"

#define PA_PATH_BUF 1024

static int exit_code(pa_status_t st) {
    switch (st) {
    case PA_OK:
        return 0;
    case PA_ERR_ARGS:
        return 1;
    case PA_ERR_IO:
    case PA_ERR_FORMAT:
    case PA_ERR_TRUNCATED:
    case PA_ERR_UNSUPPORTED:
        return 2;
    case PA_ERR_RENDER:
        return 3;
    default:
        return 4;
    }
}

static void remove_pngs(const char *out_dir) {
    char path[PA_PATH_BUF];

    for (size_t i = 0; i < pa_charts_count(); i++) {
        snprintf(path, sizeof path, "%s/charts/%s", out_dir, pa_charts_filename(i));
        (void)remove(path);
    }
    snprintf(path, sizeof path, "%s/charts", out_dir);
    (void)remove(path);
}

static pa_status_t render_outputs(const pa_config_t *cfg, const pa_report_t *rep) {
    char charts_dir[PA_PATH_BUF], pdf_path[PA_PATH_BUF];
    pa_status_t st;

    if (!cfg->make_png && !cfg->make_pdf) {
        return PA_OK;
    }
    st = pa_charts_render_all(rep, cfg->out_dir); /* the PDF embeds these PNGs */
    if (st != PA_OK) {
        return st;
    }
    snprintf(charts_dir, sizeof charts_dir, "%s/charts", cfg->out_dir);
    snprintf(pdf_path, sizeof pdf_path, "%s/report.pdf", cfg->out_dir);
    if (cfg->make_pdf) {
        st = pa_pdf_render(rep, charts_dir, pdf_path);
    }
    if (!cfg->make_png) {
        remove_pngs(cfg->out_dir);
    }
    return st;
}

static void print_summary(const pa_config_t *cfg, const pa_report_t *rep) {
    const pa_global_stats_t *g = &rep->global;
    char bytes[32];

    pa_format_bytes((double)g->bytes, bytes, sizeof bytes);
    printf("Files:      %zu\n", rep->captures.len);
    printf("Packets:    %llu (%s)\n", (unsigned long long)g->packets, bytes);
    printf("TCP / UDP:  %llu / %llu packets, %llu / %llu flows\n",
           (unsigned long long)g->pkts_by_l4[0], (unsigned long long)g->pkts_by_l4[1],
           (unsigned long long)g->tcp_flows, (unsigned long long)g->udp_flows);
    printf("Malformed:  %llu\n", (unsigned long long)g->malformed_packets);
    printf("Anomalies:  %zu\n", rep->anomalies.len);
    for (int t = 0; t < PA_ANOM__COUNT; t++) {
        if (rep->anomaly_counts[t]) {
            printf("  %-18s %u\n", pa_anomaly_type_name((pa_anomaly_type_t)t),
                   (unsigned)rep->anomaly_counts[t]);
        }
    }
    if (cfg->make_pdf) {
        printf("PDF:        %s/report.pdf\n", cfg->out_dir);
    }
    if (cfg->make_png) {
        printf("Charts:     %s/charts/\n", cfg->out_dir);
    }
}

int main(int argc, char **argv) {
    pa_config_t cfg;
    pa_report_t *report = NULL;
    int action = PA_CLI_RUN;
    pa_status_t st;

    pa_config_defaults(&cfg);
    st = pa_cli_parse(argc, argv, &cfg, &action);
    if (st != PA_OK) {
        pa_cli_usage(stderr);
        return exit_code(st);
    }
    if (action == PA_CLI_EXIT_HELP) {
        pa_cli_usage(stdout);
        return 0;
    }
    if (action == PA_CLI_EXIT_VERSION) {
        printf("pcapan %s\n", PA_VERSION);
        return 0;
    }
    pa_log_set_level(cfg.log_level);

    st = pa_report_create(&report);
    if (st == PA_OK) {
        st = pa_pipeline_run(&cfg, report);
    }
    if (st == PA_OK) {
        st = render_outputs(&cfg, report);
    }
    if (st == PA_OK) {
        print_summary(&cfg, report);
    } else {
        PA_LOG_ERROR("failed: %s", pa_status_str(st));
    }
    pa_report_destroy(report);
    return exit_code(st);
}
