#ifndef PA_DECODE_DECODER_H
#define PA_DECODE_DECODER_H

#include <stddef.h>
#include <stdint.h>

#include "core/status.h"

/* Link-layer types (libpcap DLT_* values, duplicated to keep decode free of libpcap). */
#define PA_DLT_EN10MB 1
#define PA_DLT_RAW 12
#define PA_DLT_RAW_LINKTYPE 101
#define PA_DLT_LINUX_SLL 113

typedef struct {
    uint8_t family; /* 4 or 6 */
    uint8_t bytes[16];
} pa_addr_t;

typedef enum {
    PA_L4_OTHER = 0,
    PA_L4_TCP = 6,
    PA_L4_UDP = 17,
    PA_L4_ICMP = 1,
    PA_L4_ICMP6 = 58
} pa_l4_proto_t;

enum {
    PA_TCP_FIN = 0x01,
    PA_TCP_SYN = 0x02,
    PA_TCP_RST = 0x04,
    PA_TCP_PSH = 0x08,
    PA_TCP_ACK = 0x10,
    PA_TCP_URG = 0x20,
    PA_TCP_ECE = 0x40,
    PA_TCP_CWR = 0x80
};

/* Lives only during one callback; l4_payload points into the libpcap buffer. */
typedef struct {
    double ts;
    uint32_t wire_len;
    uint32_t cap_len;
    uint8_t ip_version;
    pa_addr_t src, dst;
    uint8_t ttl;
    pa_l4_proto_t l4;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t tcp_flags;
    uint16_t window;
    uint8_t wscale;
    uint16_t mss;
    uint32_t l4_payload_len;
    const uint8_t *l4_payload;
    uint8_t malformed;
} pa_packet_t;

/**
 * Decodes one frame into *out. Truncated/invalid headers set out->malformed and return an error
 * status; the caller keeps processing. Nothing is allocated.
 */
pa_status_t pa_decode(const uint8_t *frame, uint32_t cap_len, uint32_t wire_len, int dlt, double ts,
                      pa_packet_t *out);

#endif
