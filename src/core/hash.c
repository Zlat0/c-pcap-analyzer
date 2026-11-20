#include "core/hash.h"

#define PA_FNV_PRIME 1099511628211ULL

uint64_t pa_hash_bytes(const void *data, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = seed;

    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= PA_FNV_PRIME;
    }
    return h;
}

uint64_t pa_hash_mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}
