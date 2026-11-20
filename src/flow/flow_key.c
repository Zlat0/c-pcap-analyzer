#include "flow/flow_key.h"

#include <string.h>

#include "core/hash.h"

int pa_addr_cmp(const pa_addr_t *a, const pa_addr_t *b) {
    if (a->family != b->family) {
        return a->family < b->family ? -1 : 1;
    }
    return memcmp(a->bytes, b->bytes, sizeof a->bytes);
}

void pa_flow_key_from_packet(const pa_packet_t *p, pa_flow_key_t *key, pa_dir_t *dir) {
    int c = pa_addr_cmp(&p->src, &p->dst);

    if (c == 0) {
        c = (p->sport > p->dport) - (p->sport < p->dport);
    }
    memset(key, 0, sizeof *key);
    key->proto = p->l4;
    if (c <= 0) {
        key->addr_a = p->src;
        key->addr_b = p->dst;
        key->port_a = p->sport;
        key->port_b = p->dport;
        *dir = PA_DIR_A_TO_B;
    } else {
        key->addr_a = p->dst;
        key->addr_b = p->src;
        key->port_a = p->dport;
        key->port_b = p->sport;
        *dir = PA_DIR_B_TO_A;
    }
}

int pa_flow_key_equal(const pa_flow_key_t *a, const pa_flow_key_t *b) {
    return a->proto == b->proto && a->port_a == b->port_a && a->port_b == b->port_b &&
           pa_addr_cmp(&a->addr_a, &b->addr_a) == 0 && pa_addr_cmp(&a->addr_b, &b->addr_b) == 0;
}

uint64_t pa_flow_key_hash(const pa_flow_key_t *k) {
    uint8_t tail[5];
    uint64_t h = PA_HASH_SEED;

    h = pa_hash_bytes(&k->addr_a.family, 1, h);
    h = pa_hash_bytes(k->addr_a.bytes, sizeof k->addr_a.bytes, h);
    h = pa_hash_bytes(&k->addr_b.family, 1, h);
    h = pa_hash_bytes(k->addr_b.bytes, sizeof k->addr_b.bytes, h);
    tail[0] = (uint8_t)(k->port_a >> 8);
    tail[1] = (uint8_t)(k->port_a & 0xFF);
    tail[2] = (uint8_t)(k->port_b >> 8);
    tail[3] = (uint8_t)(k->port_b & 0xFF);
    tail[4] = (uint8_t)k->proto;
    h = pa_hash_bytes(tail, sizeof tail, h);
    return pa_hash_mix(h);
}
