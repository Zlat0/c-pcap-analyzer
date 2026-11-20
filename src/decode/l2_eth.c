#include "decode/decode_internal.h"

#define PA_ETH_HDR_LEN 14
#define PA_SLL_HDR_LEN 16
#define PA_VLAN_TAG_LEN 4
#define PA_MAX_VLAN_TAGS 4

static int is_vlan(uint16_t et) { return et == 0x8100 || et == 0x88A8 || et == 0x9100; }

static pa_status_t decode_eth(const uint8_t *d, size_t len, size_t *off, uint16_t *ethertype) {
    size_t o = PA_ETH_HDR_LEN;
    uint16_t et;

    if (len < o) {
        return PA_ERR_TRUNCATED;
    }
    et = pa_rd16(d, 12);
    for (int i = 0; i < PA_MAX_VLAN_TAGS && is_vlan(et); i++) {
        if (len < o + PA_VLAN_TAG_LEN) {
            return PA_ERR_TRUNCATED;
        }
        et = pa_rd16(d, o + 2);
        o += PA_VLAN_TAG_LEN;
    }
    *off = o;
    *ethertype = et;
    return PA_OK;
}

pa_status_t pa_decode_l2(const uint8_t *d, size_t len, int dlt, size_t *off, uint16_t *ethertype) {
    switch (dlt) {
    case PA_DLT_EN10MB:
        return decode_eth(d, len, off, ethertype);
    case PA_DLT_LINUX_SLL:
        if (len < PA_SLL_HDR_LEN) {
            return PA_ERR_TRUNCATED;
        }
        *ethertype = pa_rd16(d, 14);
        *off = PA_SLL_HDR_LEN;
        return PA_OK;
    case PA_DLT_RAW:
    case PA_DLT_RAW_LINKTYPE: {
        unsigned ver;
        if (len < 1) {
            return PA_ERR_TRUNCATED;
        }
        ver = (unsigned)(d[0] >> 4);
        *ethertype = ver == 4 ? PA_ETHERTYPE_IPV4 : (ver == 6 ? PA_ETHERTYPE_IPV6 : 0);
        *off = 0;
        return PA_OK;
    }
    default:
        return PA_ERR_UNSUPPORTED;
    }
}
