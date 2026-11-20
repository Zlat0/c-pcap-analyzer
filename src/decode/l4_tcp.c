#include "decode/decode_internal.h"

#define PA_TCP_MIN_HDR 20
#define PA_TCPOPT_END 0
#define PA_TCPOPT_NOP 1
#define PA_TCPOPT_MSS 2
#define PA_TCPOPT_WSCALE 3

static void parse_options(const uint8_t *d, size_t i, size_t end, pa_packet_t *p) {
    while (i < end) {
        uint8_t kind = d[i];
        size_t olen;

        if (kind == PA_TCPOPT_END) {
            break;
        }
        if (kind == PA_TCPOPT_NOP) {
            i++;
            continue;
        }
        if (i + 2 > end) {
            break;
        }
        olen = d[i + 1];
        if (olen < 2 || i + olen > end) {
            break;
        }
        if (kind == PA_TCPOPT_MSS && olen == 4) {
            p->mss = pa_rd16(d, i + 2);
        } else if (kind == PA_TCPOPT_WSCALE && olen == 3) {
            p->wscale = d[i + 2];
        }
        i += olen;
    }
}

pa_status_t pa_decode_tcp(const uint8_t *d, size_t len, const pa_l3_info_t *l3, pa_packet_t *p) {
    size_t o = l3->l4_off, doff, pay;

    if (len < o + PA_TCP_MIN_HDR) {
        return PA_ERR_TRUNCATED;
    }
    doff = (size_t)(d[o + 12] >> 4) * 4;
    if (doff < PA_TCP_MIN_HDR) {
        return PA_ERR_FORMAT;
    }
    if (len < o + doff) {
        return PA_ERR_TRUNCATED;
    }
    pay = o + doff;
    if (l3->claimed_end < pay) {
        return PA_ERR_FORMAT;
    }
    p->sport = pa_rd16(d, o);
    p->dport = pa_rd16(d, o + 2);
    p->seq = pa_rd32(d, o + 4);
    p->ack = pa_rd32(d, o + 8);
    p->tcp_flags = d[o + 13];
    p->window = pa_rd16(d, o + 14);
    parse_options(d, o + PA_TCP_MIN_HDR, pay, p);
    p->l4_payload_len = (uint32_t)(l3->claimed_end - pay);
    p->l4_payload = pay < len ? d + pay : NULL;
    return PA_OK;
}
