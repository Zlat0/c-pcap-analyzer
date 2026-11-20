#ifndef PA_ANALYSIS_TCP_ANALYZER_H
#define PA_ANALYSIS_TCP_ANALYZER_H

#include <stdint.h>

typedef enum {
    PA_HS_NONE = 0,
    PA_HS_SYN,
    PA_HS_SYNACK,
    PA_HS_COMPLETE,
    PA_HS_MIDSTREAM /* the beginning of the connection was not captured */
} pa_handshake_t;

struct pa_tcp_state {
    pa_handshake_t hs;
    double syn_ts, synack_ts, ack_ts; /* RTT = ack_ts - syn_ts; 0 = unknown */
    uint32_t isn[2];
    uint32_t next_seq[2];
    uint8_t seq_valid[2];
    uint8_t wscale[2];
    uint32_t flag_counts[8]; /* per PA_TCP_* bit */
    uint32_t retrans[2];
    uint32_t out_of_order[2];
    uint32_t zero_window[2];
    uint32_t data_segments[2];
    uint8_t fin_seen[2];
};

struct pa_analyzer_ops;
extern const struct pa_analyzer_ops pa_tcp_analyzer_ops;

#endif
