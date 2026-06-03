/*
 * TPF Cipher v5 — C acceleration core
 *
 * Performance-critical operations:
 *   - PRNG (splitmix64)
 *   - Fisher-Yates permutation
 *   - S-box generation + application
 *   - Parallel prefix XOR + inverse
 *   - Key-byte generation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Splitmix64 PRNG ────────────────────────────────────────────── */

typedef struct { uint64_t state; } prng_t;

static inline uint64_t prng_next(prng_t *rng) {
    rng->state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ── Fisher-Yates Permutation ───────────────────────────────────── */

void fisher_yates(int64_t *perm, int n, uint64_t seed) {
    prng_t rng = { seed };
    for (int i = 0; i < n; i++) perm[i] = i;
    for (int i = n - 1; i > 0; i--) {
        uint64_t j = prng_next(&rng) % (i + 1);
        int64_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

void inverse_perm(int64_t *inv, const int64_t *perm, int n) {
    for (int i = 0; i < n; i++) inv[perm[i]] = i;
}

/* ── S-Box Generation ───────────────────────────────────────────── */

void gen_sbox(uint8_t *sbox, uint64_t seed) {
    prng_t rng = { seed };
    for (int i = 0; i < 256; i++) sbox[i] = (uint8_t)i;
    for (int i = 255; i > 0; i--) {
        uint64_t j = prng_next(&rng) % (i + 1);
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
}

void gen_inv_sbox(uint8_t *inv, const uint8_t *sbox) {
    for (int i = 0; i < 256; i++) inv[sbox[i]] = (uint8_t)i;
}

void apply_sbox(uint8_t *out, const uint8_t *in, const uint8_t *sbox, int n) {
    for (int i = 0; i < n; i++) out[i] = sbox[in[i]];
}

/* ── Key-byte Generation ────────────────────────────────────────── */

void gen_keybytes(uint8_t *out, int n, uint64_t seed) {
    prng_t rng = { seed };
    for (int i = 0; i < n; i++) out[i] = (uint8_t)(prng_next(&rng) & 0xFF);
}

/* ── XOR Arrays ─────────────────────────────────────────────────── */

void xor_arrays(uint8_t *out, const uint8_t *a, const uint8_t *b, int n) {
    for (int i = 0; i < n; i++) out[i] = a[i] ^ b[i];
}

/* ── Parallel Prefix XOR ────────────────────────────────────────── */

void prefix_xor(uint8_t *data, int n) {
    /* Brent-Kung parallel prefix: log(n) passes */
    uint8_t *prev = (uint8_t *)malloc(n);
    int stride = 1;
    while (stride < n) {
        memcpy(prev, data, n);
        for (int i = stride; i < n; i++) {
            data[i] ^= prev[i - stride];
        }
        stride <<= 1;
    }
    free(prev);
}

void inv_prefix_xor(uint8_t *out, const uint8_t *in, int n) {
    out[0] = in[0];
    for (int i = 1; i < n; i++) {
        out[i] = in[i] ^ in[i - 1];
    }
}

/* ── Apply Permutation to Data ──────────────────────────────────── */

void apply_perm(uint8_t *out, const uint8_t *in, const int64_t *perm, int n) {
    for (int i = 0; i < n; i++) out[i] = in[perm[i]];
}

void apply_inv_perm(uint8_t *out, const uint8_t *in, const int64_t *perm, int n) {
    for (int i = 0; i < n; i++) out[perm[i]] = in[i];
}

/* ── Full 2D Diffusion (row + col + full prefix with key mixing) ─ */

void diffuse_2d(uint8_t *data, int h, int w,
                uint64_t row_seed, uint64_t col_seed, uint64_t full_seed) {
    uint8_t *keybuf = (uint8_t *)malloc(h > w ? h : w);
    uint8_t *tmp;
    int n = h * w;

    /* Row-wise prefix XOR */
    prng_t rng_r = { row_seed };
    for (int i = 0; i < h; i++) {
        uint8_t *row = data + i * w;
        /* Generate row key bytes inline */
        for (int j = 0; j < w; j++) keybuf[j] = (uint8_t)(prng_next(&rng_r) & 0xFF);
        for (int j = 0; j < w; j++) row[j] ^= keybuf[j];
        /* In-place prefix XOR for this row */
        for (int j = 1; j < w; j++) row[j] ^= row[j-1];
    }

    /* Column-wise prefix XOR */
    prng_t rng_c = { col_seed };
    for (int j = 0; j < w; j++) {
        /* Generate column key bytes */
        for (int i = 0; i < h; i++) keybuf[i] = (uint8_t)(prng_next(&rng_c) & 0xFF);
        for (int i = 0; i < h; i++) data[i * w + j] ^= keybuf[i];
        for (int i = 1; i < h; i++) data[i * w + j] ^= data[(i-1) * w + j];
    }

    /* Full-image prefix XOR */
    tmp = (uint8_t *)malloc(n);
    gen_keybytes(tmp, n, full_seed);
    for (int i = 0; i < n; i++) data[i] ^= tmp[i];
    prefix_xor(data, n);
    free(tmp);
    free(keybuf);
}

void inv_diffuse_2d(uint8_t *data, int h, int w,
                    uint64_t row_seed, uint64_t col_seed, uint64_t full_seed) {
    int n = h * w;
    uint8_t *tmp = (uint8_t *)malloc(n);
    uint8_t *keybuf = (uint8_t *)malloc(h > w ? h : w);

    /* Pre-generate all keys (must match encrypt order) */
    /* Row keys */
    uint8_t **rkeys = (uint8_t **)malloc(h * sizeof(uint8_t*));
    prng_t rng_r = { row_seed };
    for (int i = 0; i < h; i++) {
        rkeys[i] = (uint8_t *)malloc(w);
        for (int j = 0; j < w; j++) rkeys[i][j] = (uint8_t)(prng_next(&rng_r) & 0xFF);
    }
    /* Col keys */
    uint8_t **ckeys = (uint8_t **)malloc(w * sizeof(uint8_t*));
    prng_t rng_c = { col_seed };
    for (int j = 0; j < w; j++) {
        ckeys[j] = (uint8_t *)malloc(h);
        for (int i = 0; i < h; i++) ckeys[j][i] = (uint8_t)(prng_next(&rng_c) & 0xFF);
    }
    /* Full key */
    uint8_t *fkey = (uint8_t *)malloc(n);
    gen_keybytes(fkey, n, full_seed);

    /* Reverse full prefix */
    inv_prefix_xor(tmp, data, n);
    for (int i = 0; i < n; i++) tmp[i] ^= fkey[i];
    memcpy(data, tmp, n);

    /* Reverse column prefix */
    for (int j = 0; j < w; j++) {
        /* Extract column */
        for (int i = 0; i < h; i++) keybuf[i] = data[i * w + j];
        /* Inv prefix */
        uint8_t first = keybuf[0];
        for (int i = h-1; i >= 1; i--) keybuf[i] = keybuf[i] ^ keybuf[i-1];
        keybuf[0] = first;
        /* Remove key */
        for (int i = 0; i < h; i++) keybuf[i] ^= ckeys[j][i];
        for (int i = 0; i < h; i++) data[i * w + j] = keybuf[i];
    }

    /* Reverse row prefix */
    for (int i = 0; i < h; i++) {
        uint8_t *row = data + i * w;
        uint8_t first = row[0];
        for (int j = w-1; j >= 1; j--) row[j] = row[j] ^ row[j-1];
        row[0] = first;
        for (int j = 0; j < w; j++) row[j] ^= rkeys[i][j];
    }

    /* Cleanup */
    for (int i = 0; i < h; i++) free(rkeys[i]);
    free(rkeys);
    for (int j = 0; j < w; j++) free(ckeys[j]);
    free(ckeys);
    free(fkey);
    free(tmp);
    free(keybuf);
}
