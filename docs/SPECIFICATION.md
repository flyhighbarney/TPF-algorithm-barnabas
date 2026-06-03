# TPF Cipher — Specification

> TODO: replace with the formal .docx specification once converted to Markdown.
> Outline below mirrors the implemented v5 pipeline.

## 1. Notation

- `P` — plaintext image, shape `H × W × 3`, `uint8` RGB.
- `K` — user key, exactly 16 bytes (128 bits).
- `H(·)` — SHA-256. `HMAC(·,·)` — HMAC-SHA-256.
- `R = 2` rounds.

## 2. Key expansion

```
img_hash = H(P)
EK       = H(K || img_hash)
```

`img_hash` is transmitted alongside the ciphertext as a nonce. The HMAC tag
covers both the ciphertext and `img_hash`.

## 3. Per-round pipeline

For round `r ∈ {0, 1}` with `round_seed = H(EK || r)`:

1. **2D permutation** (per channel): keystream-seeded Fisher–Yates row
   permutation, column permutation, and per-row intra-row shuffle.
2. **S-box substitution**: a key-dependent 8-bit permutation derived from
   `round_seed`. Measured non-linearity ≈ 99.6 %.
3. **Parallel-prefix XOR diffusion**: row-wise prefix XOR, then column-wise
   prefix XOR. Each output pixel depends on every preceding pixel in its
   row and column.
4. **Cross-channel RGB entanglement**: pairwise XORs at three key-derived
   rotation offsets `(δR, δG, δB)`.

## 4. Authentication

```
tag = HMAC(EK, ciphertext_bytes || img_hash)
```

Decryption MUST verify the tag in constant time before any inverse step.

## 5. Complexity

- Time: `O(n log n)` where `n = H·W` (dominated by the keystream-driven
  Fisher–Yates over rows and columns).
- Space: `O(n)`. Zero size expansion.

## 6. C ABI (see `src/tpf_core.c`)

```
void tpf_prefix_xor_diffuse(uint8_t *buf, size_t h, size_t w);
void tpf_inv_prefix_xor_diffuse(uint8_t *buf, size_t h, size_t w);
void tpf_fisher_yates_u32(uint32_t *arr, size_t n, uint64_t seed);
void tpf_apply_row_perm(const uint8_t *in, uint8_t *out,
                        const uint32_t *perm, size_t h, size_t w);
void tpf_sbox_apply(uint8_t *buf, size_t n, const uint8_t sbox[256]);
void tpf_xor_buf(uint8_t *dst, const uint8_t *src, size_t n);
```
