#include "pipeline.h"

#include <stdio.h>
#include <string.h>

#include "analysis/analyzer.h"
#include "analysis/tcp_analyzer.h"
#include "capture/pcap_reader.h"
#include "core/log.h"
#include "decode/decoder.h"

#define PA_MAX_ANALYZERS 16
#define PA_EXPIRE_INTERVAL_SEC 1.0
#define PA_FLOW_INITIAL_CAP 1024
#define PA_HOST_INITIAL_CAP 256

typedef struct {
    const pa_config_t *cfg;
    pa_analysis_ctx_t ctx;
    pa_global_stats_t global;
    pa_vec_t anomalies;
    const pa_analyzer_ops_t *const *ops;
    size_t n_ops;
    void *states[PA_MAX_ANALYZERS];
    size_t n_init;
    double last_expire;
} pipeline_t;

static void flow_end_cb(pa_flow_t *f, void *ud) {
    pipeline_t *pl = ud;

    for (size_t i = 0; i < pl->n_ops; i++) {
        if (pl->ops[i]->on_flow_end) {
            pl->ops[i]->on_flow_end(pl->states[i], &pl->ctx, f);
        }
    }
}

static void pl_destroy(pipeline_t *pl) {
    for (size_t i = 0; i < pl->n_init; i++) {
        if (pl->ops[i]->destroy) {
            pl->ops[i]->destroy(pl->states[i]);
        }
    }
    pa_vec_free(&pl->anomalies);
    pa_flow_table_destroy(pl->ctx.flows);
    pa_host_table_destroy(pl->ctx.hosts);
}

static pa_status_t pl_init(pipeline_t *pl, const pa_config_t *cfg) {
    pa_status_t st;

    memset(pl, 0, sizeof *pl);
    pl->cfg = cfg;
    pl->ops = pa_analyzer_registry(&pl->n_ops);
    pa_vec_init(&pl->anomalies, sizeof(pa_anomaly_t));
    pl->ctx.cfg = cfg;
    pl->ctx.global = &pl->global;
    pl->ctx.anomalies = &pl->anomalies;
    st = pa_flow_table_create(PA_FLOW_INITIAL_CAP, &pl->ctx.flows);
    if (st == PA_OK) {
        st = pa_host_table_create(PA_HOST_INITIAL_CAP, &pl->ctx.hosts);
    }
    for (size_t i = 0; st == PA_OK && i < pl->n_ops && i < PA_MAX_ANALYZERS; i++) {
        st = pl->ops[i]->init(&pl->ctx, &pl->states[i]);
        if (st == PA_OK) {
            pl->n_init++;
        }
    }
    if (st != PA_OK) {
        pl_destroy(pl);
    }
    return st;
}

/* RST closes a flow immediately; FIN closes it once both sides have sent one. */
static void maybe_close(pipeline_t *pl, pa_flow_t *f, const pa_packet_t *p) {
    pa_flow_end_t why = PA_FLOW_END_NONE;

    if (f->closed || !f->tcp) {
        return;
    }
    if (p->tcp_flags & PA_TCP_RST) {
        why = PA_FLOW_END_RST;
    } else if (f->tcp->fin_seen[0] && f->tcp->fin_seen[1]) {
        why = PA_FLOW_END_FIN;
    }
    if (why != PA_FLOW_END_NONE) {
        f->closed = 1;
        f->end_reason = why;
        flow_end_cb(f, pl);
    }
}

static pa_status_t pl_packet(pipeline_t *pl, const uint8_t *frame, uint32_t cap_len,
                             uint32_t wire_len, int dlt, double ts) {
    pa_packet_t p;
    pa_flow_t *flow = NULL;
    pa_dir_t dir = PA_DIR_A_TO_B;
    int is_new = 0;

    (void)pa_decode(frame, cap_len, wire_len, dlt, ts, &p); /* errors are flagged in p.malformed */
    if (!p.malformed && p.ip_version != 0 && (p.l4 == PA_L4_TCP || p.l4 == PA_L4_UDP)) {
        pa_status_t st = pa_flow_table_get_or_insert(pl->ctx.flows, &p, &flow, &dir, &is_new);

        if (st != PA_OK) {
            return st;
        }
    }
    for (size_t i = 0; i < pl->n_ops; i++) {
        pl->ops[i]->on_packet(pl->states[i], &pl->ctx, &p, flow, dir);
    }
    if (flow && p.l4 == PA_L4_TCP) {
        maybe_close(pl, flow, &p);
    }
    if (ts - pl->last_expire >= PA_EXPIRE_INTERVAL_SEC || ts < pl->last_expire) {
        pa_flow_table_expire(pl->ctx.flows, ts, pl->cfg, flow_end_cb, pl);
        pl->last_expire = ts;
    }
    return PA_OK;
}

static pa_status_t pl_file(pipeline_t *pl, const char *path, pa_report_t *report) {
    pa_reader_t *rd = NULL;
    pa_capture_info_t ci;
    pa_status_t st = pa_reader_open(path, pl->cfg->bpf_filter, &rd);

    if (st != PA_OK) {
        return st;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.path, sizeof ci.path, "%s", path);
    ci.file_size = pa_reader_file_size(rd);
    ci.dlt = pa_reader_dlt(rd);
    for (;;) {
        const uint8_t *data = NULL;
        uint32_t cap = 0, wire = 0;
        double ts = 0.0;

        st = pa_reader_next(rd, &ts, &data, &cap, &wire);
        if (st != PA_OK || !data) {
            break;
        }
        if (ci.packets == 0 || ts < ci.first_ts) {
            ci.first_ts = ts;
        }
        if (ts > ci.last_ts) {
            ci.last_ts = ts;
        }
        ci.packets++;
        st = pl_packet(pl, data, cap, wire, ci.dlt, ts);
        if (st != PA_OK) {
            break;
        }
    }
    pa_reader_close(rd);
    if (st == PA_OK) {
        PA_LOG_INFO("%s: %llu packets", path, (unsigned long long)ci.packets);
        st = pa_vec_push(&report->captures, &ci);
    }
    return st;
}

static pa_status_t pl_finish(pipeline_t *pl, pa_report_t *report) {
    pa_status_t st = PA_OK;

    pa_flow_table_close_all(pl->ctx.flows, flow_end_cb, pl);
    for (size_t i = 0; st == PA_OK && i < pl->n_ops; i++) {
        if (pl->ops[i]->finalize) {
            st = pl->ops[i]->finalize(pl->states[i], &pl->ctx, report);
        }
    }
    return st;
}

pa_status_t pa_pipeline_run(const pa_config_t *cfg, pa_report_t *report) {
    pipeline_t pl;
    pa_status_t st;

    if (!cfg || !report || cfg->n_inputs == 0) {
        return PA_ERR_ARGS;
    }
    st = pl_init(&pl, cfg);
    if (st != PA_OK) {
        return st;
    }
    for (size_t i = 0; st == PA_OK && i < cfg->n_inputs; i++) {
        st = pl_file(&pl, cfg->inputs[i], report);
    }
    if (st == PA_OK) {
        st = pl_finish(&pl, report);
    }
    pl_destroy(&pl);
    return st;
}
