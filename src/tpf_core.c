/*
 * tpf_core.c — C acceleration core for the TPF cipher.
 *
 * TODO: swap in the real tpf_core.c from the project root.
 * This placeholder exposes the ABI the Python reference expects, so the
 * shared library builds and links cleanly via `make build`.
 *
 * Build:
 *   gcc -O3 -march=native -shared -fPIC -o tpf_core.so tpf_core.c
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ----- 2D parallel-prefix XOR diffusion ----------------------------------- */

void tpf_prefix_xor_diffuse(uint8_t *buf, size_t h, size_t w) {
    /* row-wise prefix XOR */
    for (size_t i = 0; i < h; ++i) {
        uint8_t *row = buf + i * w;
        for (size_t j = 1; j < w; ++j) row[j] ^= row[j - 1];
    }
    /* column-wise prefix XOR */
    for (size_t j = 0; j < w; ++j) {
        for (size_t i = 1; i < h; ++i) {
            buf[i * w + j] ^= buf[(i - 1) * w + j];
        }
    }
}

void tpf_inv_prefix_xor_diffuse(uint8_t *buf, size_t h, size_t w) {
    /* inverse column-wise: subtract above row */
    for (size_t j = 0; j < w; ++j) {
        for (size_t i = h; i-- > 1; ) {
            buf[i * w + j] ^= buf[(i - 1) * w + j];
        }
    }
    /* inverse row-wise */
    for (size_t i = 0; i < h; ++i) {
        uint8_t *row = buf + i * w;
        for (size_t j = w; j-- > 1; ) row[j] ^= row[j - 1];
    }
}

/* ----- keystream-driven Fisher–Yates row/col permutation ------------------ */

/* xorshift64* PRNG seeded from a 64-bit key chunk. */
static inline uint64_t xs64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

void tpf_fisher_yates_u32(uint32_t *arr, size_t n, uint64_t seed) {
    uint64_t s = seed ? seed : 0x9E3779B97F4A7C15ULL;
    for (size_t i = n; i-- > 1; ) {
        size_t j = (size_t)(xs64(&s) % (uint64_t)(i + 1));
        uint32_t t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
}

/* Apply a row permutation in place: out[i] = in[perm[i]]. */
void tpf_apply_row_perm(const uint8_t *in, uint8_t *out,
                        const uint32_t *perm, size_t h, size_t w) {
    for (size_t i = 0; i < h; ++i) {
        memcpy(out + i * w, in + (size_t)perm[i] * w, w);
    }
}

/* ----- S-box substitution ------------------------------------------------- */

void tpf_sbox_apply(uint8_t *buf, size_t n, const uint8_t sbox[256]) {
    for (size_t i = 0; i < n; ++i) buf[i] = sbox[buf[i]];
}

/* ----- byte-wise XOR (utility) -------------------------------------------- */

void tpf_xor_buf(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; ++i) dst[i] ^= src[i];
}
