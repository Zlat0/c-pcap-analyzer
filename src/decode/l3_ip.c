#include "decode/decode_internal.h"

#define PA_IPV4_MIN_HDR 20
#define PA_IPV6_HDR 40
#define PA_MAX_EXT_HDRS 8

static pa_l4_proto_t map_proto(uint8_t proto) {
    switch (proto) {
    case 1:
        return PA_L4_ICMP;
    case 6:
        return PA_L4_TCP;
    case 17:
        return PA_L4_UDP;
    case 58:
        return PA_L4_ICMP6;
    default:
        return PA_L4_OTHER;
    }
}

static pa_status_t decode_ipv4(const uint8_t *d, size_t len, size_t off, pa_packet_t *p,
                               pa_l3_info_t *info) {
    size_t ihl, total;
    uint16_t frag;

    if (len < off + PA_IPV4_MIN_HDR) {
        return PA_ERR_TRUNCATED;
    }
    ihl = (size_t)(d[off] & 0x0F) * 4;
    if (ihl < PA_IPV4_MIN_HDR) {
        return PA_ERR_FORMAT;
    }
    if (len < off + ihl) {
        return PA_ERR_TRUNCATED;
    }
    total = pa_rd16(d, off + 2);
    if (total == 0) {
        total = len - off; /* TSO-offloaded captures report 0 */
    }
    if (total < ihl) {
        return PA_ERR_FORMAT;
    }
    frag = pa_rd16(d, off + 6);
    p->ip_version = 4;
    p->ttl = d[off + 8];
    p->src.family = 4;
    p->dst.family = 4;
    memcpy(p->src.bytes, d + off + 12, 4);
    memcpy(p->dst.bytes, d + off + 16, 4);
    info->proto = d[off + 9];
    info->l4_off = off + ihl;
    info->claimed_end = off + total;
    info->has_l4 = (frag & 0x1FFF) == 0;
    return PA_OK;
}

/* Skips hop-by-hop, routing, destination, fragment and AH headers. */
static pa_status_t skip_ext_headers(const uint8_t *d, size_t len, uint8_t *next, size_t *cur,
                                    uint8_t *has_l4) {
    for (int i = 0; i < PA_MAX_EXT_HDRS; i++) {
        uint8_t nh;
        if (*next == 0 || *next == 43 || *next == 60) {
            if (len < *cur + 2) {
                return PA_ERR_TRUNCATED;
            }
            nh = d[*cur];
            *cur += ((size_t)d[*cur + 1] + 1) * 8;
        } else if (*next == 44) {
            if (len < *cur + 8) {
                return PA_ERR_TRUNCATED;
            }
            nh = d[*cur];
            if ((pa_rd16(d, *cur + 2) >> 3) != 0) {
                *has_l4 = 0;
            }
            *cur += 8;
        } else if (*next == 51) {
            if (len < *cur + 2) {
                return PA_ERR_TRUNCATED;
            }
            nh = d[*cur];
            *cur += ((size_t)d[*cur + 1] + 2) * 4;
        } else {
            break;
        }
        *next = nh;
    }
    return PA_OK;
}

static pa_status_t decode_ipv6(const uint8_t *d, size_t len, size_t off, pa_packet_t *p,
                               pa_l3_info_t *info) {
    size_t plen, cur;
    uint8_t next;
    pa_status_t st;

    if (len < off + PA_IPV6_HDR) {
        return PA_ERR_TRUNCATED;
    }
    plen = pa_rd16(d, off + 4);
    next = d[off + 6];
    p->ip_version = 6;
    p->ttl = d[off + 7];
    p->src.family = 6;
    p->dst.family = 6;
    memcpy(p->src.bytes, d + off + 8, 16);
    memcpy(p->dst.bytes, d + off + 24, 16);
    info->claimed_end = plen ? off + PA_IPV6_HDR + plen : len;
    info->has_l4 = 1;
    cur = off + PA_IPV6_HDR;
    st = skip_ext_headers(d, len, &next, &cur, &info->has_l4);
    if (st != PA_OK) {
        return st;
    }
    if (cur > len) {
        return PA_ERR_TRUNCATED;
    }
    if (info->claimed_end < cur) {
        return PA_ERR_FORMAT;
    }
    info->proto = next;
    info->l4_off = cur;
    return PA_OK;
}

pa_status_t pa_decode_l3(const uint8_t *d, size_t len, size_t off, uint16_t ethertype,
                         pa_packet_t *p, pa_l3_info_t *info) {
    pa_status_t st;

    if (ethertype == PA_ETHERTYPE_IPV4) {
        st = decode_ipv4(d, len, off, p, info);
    } else if (ethertype == PA_ETHERTYPE_IPV6) {
        st = decode_ipv6(d, len, off, p, info);
    } else {
        return PA_ERR_UNSUPPORTED;
    }
    if (st != PA_OK) {
        return st;
    }
    p->l4 = info->has_l4 ? map_proto(info->proto) : PA_L4_OTHER;
    return PA_OK;
}
