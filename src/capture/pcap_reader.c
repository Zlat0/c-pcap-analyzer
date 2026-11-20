/* libpcap headers use BSD types (u_char, u_int) that glibc hides in strict POSIX mode. */
#define _DEFAULT_SOURCE 1

#include "capture/pcap_reader.h"

#include <pcap/pcap.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "core/log.h"
#include "core/timeutil.h"
#include "decode/decoder.h"

struct pa_reader {
    pcap_t *pc;
    struct bpf_program prog;
    int has_prog;
    int dlt;
    uint64_t file_size;
};

static int dlt_supported(int dlt) {
    return dlt == PA_DLT_EN10MB || dlt == PA_DLT_LINUX_SLL || dlt == PA_DLT_RAW ||
           dlt == PA_DLT_RAW_LINKTYPE;
}

static pa_status_t apply_filter(pa_reader_t *r, const char *bpf) {
    if (!bpf) {
        return PA_OK;
    }
    if (pcap_compile(r->pc, &r->prog, bpf, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        PA_LOG_ERROR("invalid BPF filter '%s': %s", bpf, pcap_geterr(r->pc));
        return PA_ERR_ARGS;
    }
    r->has_prog = 1;
    if (pcap_setfilter(r->pc, &r->prog) != 0) {
        PA_LOG_ERROR("cannot apply BPF filter: %s", pcap_geterr(r->pc));
        return PA_ERR_ARGS;
    }
    return PA_OK;
}

pa_status_t pa_reader_open(const char *path, const char *bpf, pa_reader_t **out) {
    char err[PCAP_ERRBUF_SIZE];
    struct stat sb;
    pa_reader_t *r;
    pa_status_t st;

    if (!path || !out) {
        return PA_ERR_ARGS;
    }
    r = calloc(1, sizeof *r);
    if (!r) {
        return PA_ERR_NOMEM;
    }
    r->pc = pcap_open_offline(path, err);
    if (!r->pc) {
        PA_LOG_ERROR("cannot open '%s': %s", path, err);
        free(r);
        return PA_ERR_IO;
    }
    r->dlt = pcap_datalink(r->pc);
    if (!dlt_supported(r->dlt)) {
        PA_LOG_ERROR("'%s': unsupported link type %d", path, r->dlt);
        st = PA_ERR_UNSUPPORTED;
        goto cleanup;
    }
    st = apply_filter(r, bpf);
    if (st != PA_OK) {
        goto cleanup;
    }
    r->file_size = stat(path, &sb) == 0 ? (uint64_t)sb.st_size : 0;
    *out = r;
    return PA_OK;

cleanup:
    pa_reader_close(r);
    return st;
}

pa_status_t pa_reader_next(pa_reader_t *r, double *ts, const uint8_t **data, uint32_t *cap_len,
                           uint32_t *wire_len) {
    struct pcap_pkthdr *hdr;
    const u_char *buf;
    int rc;

    do {
        rc = pcap_next_ex(r->pc, &hdr, &buf);
    } while (rc == 0);
    if (rc == PCAP_ERROR_BREAK) {
        *data = NULL;
        return PA_OK;
    }
    if (rc != 1) {
        PA_LOG_ERROR("read error: %s", pcap_geterr(r->pc));
        return PA_ERR_FORMAT;
    }
    *ts = pa_time_from_parts((long)hdr->ts.tv_sec, (long)hdr->ts.tv_usec);
    *data = buf;
    *cap_len = hdr->caplen;
    *wire_len = hdr->len;
    return PA_OK;
}

int pa_reader_dlt(const pa_reader_t *r) { return r->dlt; }

uint64_t pa_reader_file_size(const pa_reader_t *r) { return r->file_size; }

void pa_reader_close(pa_reader_t *r) {
    if (!r) {
        return;
    }
    if (r->has_prog) {
        pcap_freecode(&r->prog);
    }
    if (r->pc) {
        pcap_close(r->pc);
    }
    free(r);
}
