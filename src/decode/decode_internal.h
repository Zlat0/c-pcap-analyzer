#ifndef PA_DECODE_DECODE_INTERNAL_H
#define PA_DECODE_DECODE_INTERNAL_H

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "decode/decoder.h"

#define PA_ETHERTYPE_IPV4 0x0800
#define PA_ETHERTYPE_IPV6 0x86DD

typedef struct {
    size_t l4_off;       /* offset of the L4 header */
    size_t claimed_end;  /* end of the IP payload according to the IP header */
    uint8_t proto;       /* L4 protocol number */
    uint8_t has_l4;      /* 0 for non-first fragments */
} pa_l3_info_t;

/* Headers are never cast to structs: fields are copied out with memcpy. */
static inline uint16_t pa_rd16(const uint8_t *d, size_t off) {
    uint16_t v;
    memcpy(&v, d + off, sizeof v);
    return ntohs(v);
}

static inline uint32_t pa_rd32(const uint8_t *d, size_t off) {
    uint32_t v;
    memcpy(&v, d + off, sizeof v);
    return ntohl(v);
}

pa_status_t pa_decode_l2(const uint8_t *d, size_t len, int dlt, size_t *off, uint16_t *ethertype);
pa_status_t pa_decode_l3(const uint8_t *d, size_t len, size_t off, uint16_t ethertype,
                         pa_packet_t *p, pa_l3_info_t *info);
pa_status_t pa_decode_tcp(const uint8_t *d, size_t len, const pa_l3_info_t *l3, pa_packet_t *p);
pa_status_t pa_decode_udp(const uint8_t *d, size_t len, const pa_l3_info_t *l3, pa_packet_t *p);

#endif
