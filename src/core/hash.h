#ifndef PA_CORE_HASH_H
#define PA_CORE_HASH_H

#include <stddef.h>
#include <stdint.h>

#define PA_HASH_SEED 14695981039346656037ULL

/** FNV-1a over a byte range, chainable through the seed. */
uint64_t pa_hash_bytes(const void *data, size_t len, uint64_t seed);
/** Murmur3 finalizer: spreads low-entropy FNV bits before masking. */
uint64_t pa_hash_mix(uint64_t x);

#endif
