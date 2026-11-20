#include "decode/decode_internal.h"

#define PA_UDP_HDR 8

pa_status_t pa_decode_udp(const uint8_t *d, size_t len, const pa_l3_info_t *l3, pa_packet_t *p) {
    size_t o = l3->l4_off, ulen, pay, avail, plen;

    if (len < o + PA_UDP_HDR) {
        return PA_ERR_TRUNCATED;
    }
    ulen = pa_rd16(d, o + 4);
    if (ulen < PA_UDP_HDR) {
        return PA_ERR_FORMAT;
    }
    pay = o + PA_UDP_HDR;
    avail = l3->claimed_end > pay ? l3->claimed_end - pay : 0;
    plen = ulen - PA_UDP_HDR;
    if (plen > avail) {
        plen = avail;
    }
    p->sport = pa_rd16(d, o);
    p->dport = pa_rd16(d, o + 2);
    p->l4_payload_len = (uint32_t)plen;
    p->l4_payload = pay < len ? d + pay : NULL;
    return PA_OK;
}
