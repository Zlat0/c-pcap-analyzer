#ifndef PA_CAPTURE_PCAP_READER_H
#define PA_CAPTURE_PCAP_READER_H

#include <stdint.h>

#include "core/status.h"

typedef struct pa_reader pa_reader_t;

/** Opens a .pcap/.pcapng file with an optional BPF filter; release with pa_reader_close(). */
pa_status_t pa_reader_open(const char *path, const char *bpf, pa_reader_t **out);
/**
 * Reads the next frame. At end of file returns PA_OK with *data == NULL. The returned buffer
 * belongs to libpcap and is valid only until the next call.
 */
pa_status_t pa_reader_next(pa_reader_t *r, double *ts, const uint8_t **data, uint32_t *cap_len,
                           uint32_t *wire_len);
int pa_reader_dlt(const pa_reader_t *r);
uint64_t pa_reader_file_size(const pa_reader_t *r);
void pa_reader_close(pa_reader_t *r);

#endif
