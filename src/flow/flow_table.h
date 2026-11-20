#ifndef PA_FLOW_FLOW_TABLE_H
#define PA_FLOW_FLOW_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "core/config.h"
#include "core/status.h"
#include "decode/decoder.h"
#include "flow/flow_key.h"

typedef enum {
    PA_FLOW_END_NONE = 0,
    PA_FLOW_END_FIN,
    PA_FLOW_END_RST,
    PA_FLOW_END_TIMEOUT,
    PA_FLOW_END_EOF
} pa_flow_end_t;

typedef struct {
    uint64_t packets, bytes, payload_bytes;
} pa_dir_stats_t;

typedef struct pa_tcp_state pa_tcp_state_t;
typedef struct pa_flow_table pa_flow_table_t;

typedef struct {
    uint64_t id; /* monotonic, from 1 */
    pa_flow_key_t key;
    pa_dir_t initiator;
    double first_ts, last_ts;
    pa_dir_stats_t dir[2];
    pa_flow_end_t end_reason;
    uint8_t closed;
    pa_tcp_state_t *tcp; /* NULL for UDP; owned by the flow table */
} pa_flow_t;

/** Creates a table; the caller releases it with pa_flow_table_destroy(). */
pa_status_t pa_flow_table_create(size_t initial_cap, pa_flow_table_t **out);
/**
 * Finds or creates the flow of a packet and accounts the packet in it. *flow is owned by the
 * table and stays valid until destroy.
 */
pa_status_t pa_flow_table_get_or_insert(pa_flow_table_t *t, const pa_packet_t *p, pa_flow_t **flow,
                                        pa_dir_t *dir, int *is_new);
/** Closes open flows idle for longer than the configured timeout, calling on_end for each. */
void pa_flow_table_expire(pa_flow_table_t *t, double now, const pa_config_t *cfg,
                          void (*on_end)(pa_flow_t *, void *), void *ud);
/** Closes every still-open flow with reason EOF. */
void pa_flow_table_close_all(pa_flow_table_t *t, void (*on_end)(pa_flow_t *, void *), void *ud);
void pa_flow_table_foreach(const pa_flow_table_t *t, void (*fn)(const pa_flow_t *, void *),
                           void *ud);
size_t pa_flow_table_size(const pa_flow_table_t *t);
void pa_flow_table_destroy(pa_flow_table_t *t);

/** Resolves initiator/responder addresses and the responder (service) port of a flow. */
void pa_flow_endpoints(const pa_flow_t *f, pa_addr_t *src, pa_addr_t *dst, uint16_t *dport);

#endif
