#include "decode/decoder.h"

#include <string.h>

#include "core/log.h"
#include "decode/decode_internal.h"

static pa_status_t decode_l4(const uint8_t *d, size_t len, const pa_l3_info_t *l3,
                             pa_packet_t *out) {
    switch (out->l4) {
    case PA_L4_TCP:
        return pa_decode_tcp(d, len, l3, out);
    case PA_L4_UDP:
        return pa_decode_udp(d, len, l3, out);
    default:
        out->l4_payload_len =
            l3->claimed_end > l3->l4_off ? (uint32_t)(l3->claimed_end - l3->l4_off) : 0;
        return PA_OK;
    }
}

pa_status_t pa_decode(const uint8_t *frame, uint32_t cap_len, uint32_t wire_len, int dlt, double ts,
                      pa_packet_t *out) {
    size_t off = 0, len = cap_len;
    uint16_t ethertype = 0;
    pa_l3_info_t l3;
    pa_status_t st;

    memset(out, 0, sizeof *out);
    memset(&l3, 0, sizeof l3);
    out->ts = ts;
    out->wire_len = wire_len;
    out->cap_len = cap_len;
    out->wscale = 0xFF;

    st = pa_decode_l2(frame, len, dlt, &off, &ethertype);
    if (st != PA_OK) {
        goto malformed;
    }
    if (ethertype != PA_ETHERTYPE_IPV4 && ethertype != PA_ETHERTYPE_IPV6) {
        return PA_OK; /* non-IP traffic is only counted */
    }
    st = pa_decode_l3(frame, len, off, ethertype, out, &l3);
    if (st != PA_OK) {
        goto malformed;
    }
    st = decode_l4(frame, len, &l3, out);
    if (st != PA_OK) {
        goto malformed;
    }
    return PA_OK;

malformed:
    out->malformed = 1;
    out->sport = out->dport = 0;
    PA_LOG_DEBUG("malformed packet (ts=%.6f, len=%u): %s", ts, (unsigned)cap_len,
                 pa_status_str(st));
    return st;
}
