#ifndef PA_FLOW_FLOW_KEY_H
#define PA_FLOW_FLOW_KEY_H

#include <stdint.h>

#include "decode/decoder.h"

/* Normalized key: (addr_a,port_a) <= (addr_b,port_b), so both directions map to one flow. */
typedef struct {
    pa_addr_t addr_a, addr_b;
    uint16_t port_a, port_b;
    pa_l4_proto_t proto;
} pa_flow_key_t;

typedef enum { PA_DIR_A_TO_B = 0, PA_DIR_B_TO_A = 1 } pa_dir_t;

/** Three-way compare of two addresses (family first, then bytes). */
int pa_addr_cmp(const pa_addr_t *a, const pa_addr_t *b);
void pa_flow_key_from_packet(const pa_packet_t *p, pa_flow_key_t *key, pa_dir_t *dir);
int pa_flow_key_equal(const pa_flow_key_t *a, const pa_flow_key_t *b);
uint64_t pa_flow_key_hash(const pa_flow_key_t *k);

#endif
