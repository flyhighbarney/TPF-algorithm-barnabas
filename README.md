# TPF Cipher

> An educational symmetric image-encryption scheme combining a treap-style
> 2D permutation with parallel-prefix XOR diffusion, written from scratch in
> Python with a C-accelerated core.

```
┌─────────────────────────────────────────────────────────────────┐
│ What this is:    A learning project in cryptographic            │
│                  engineering — design, implementation,          │
│                  empirical statistical testing, and             │
│                  performance optimization (Python + C).         │
│                                                                 │
│ What this isn't: A production cipher. It has not been peer-     │
│                  reviewed, has no formal security proof, and    │
│                  has not been subjected to public cryptanalysis.│
│                  For real-world use, use AES-GCM or             │
│                  ChaCha20-Poly1305 from a vetted library.       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Visual demo

| Original | Encrypted | Decrypted |
| :---: | :---: | :---: |
| ![original](assets/original.png) | ![encrypted](assets/encrypted.png) | ![decrypted](assets/decrypted.png) |

<sub>(Run `python examples/demo.py` to regenerate these images on your own input.)</sub>

---

## Live web demo

A pure-client-side JavaScript port of the cipher ships in [`web/`](web/) and
is auto-deployed to GitHub Pages by [`.github/workflows/pages.yml`](.github/workflows/pages.yml).

Once you've enabled Pages (Settings → Pages → "GitHub Actions" as source), the
demo lives at `https://<your-username>.github.io/<repo-name>/`. It runs
entirely in the browser — no image ever leaves your machine.

The web port is functionally faithful but ~30–50× slower than the C core;
keep images ≤ 512×512 for a snappy experience.

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/<you>/tpf-cipher.git
cd tpf-cipher

# 2. Install Python deps
pip install -r requirements.txt

# 3. Build the C acceleration core (produces tpf_core.so)
make build

# 4. Run the demo
python examples/demo.py --in assets/original.png --out assets/encrypted.png
```

Requires Python 3.9+ and a C99 compiler (`gcc` or `clang`). On Windows, use
WSL or MSYS2 / mingw-w64.

---

## How it works

TPF stands for **T**reap **P**ermutation + **F**enwick/parallel-prefix
diffusion. Each color channel is processed independently for **2 rounds** of:

```
  plaintext image
         │
         ▼
  ┌─────────────────────────────────────────┐
  │ 1. Plaintext-dependent key expansion    │  SHA-256(image) mixed into K
  ├─────────────────────────────────────────┤
  │ 2. 2D permutation                       │  row + col + intra-row
  │    (Fisher–Yates, keystream-seeded)     │  shuffles
  ├─────────────────────────────────────────┤
  │ 3. Key-dependent S-box substitution     │  ~99.6% non-linearity
  ├─────────────────────────────────────────┤
  │ 4. 2D parallel-prefix XOR diffusion     │  row-wise, col-wise,
  │                                         │  full-image
  ├─────────────────────────────────────────┤
  │ 5. Cross-channel RGB entanglement       │  XOR at key-derived
  │                                         │  rotated offsets
  ├─────────────────────────────────────────┤
  │ 6. HMAC-SHA256 authentication tag       │
  └─────────────────────────────────────────┘
         │
         ▼
   ciphertext + tag + image-hash nonce
```

- **Key size:** 128 bits
- **Time complexity:** `O(n log n)` for an `n`-pixel image
- **Space complexity:** `O(n)`
- **Size expansion:** zero (ciphertext is the same dimensions as the plaintext)

See [docs/SPECIFICATION.md](docs/SPECIFICATION.md) for the full per-stage
description.

---

## Results

All numbers below come from `tests/test_suite_v5.py` run on standard test
images (Lena, Baboon, Peppers, 512×512 RGB):

| Metric | Measured | Ideal / Threshold |
| --- | ---: | ---: |
| Shannon entropy | **7.997** | 8.000 |
| NPCR (differential attack) | **99.60 %** | ≥ 99.6094 % |
| UACI (differential attack) | **33.45 %** | ≈ 33.4635 % |
| Adjacent-pixel correlation (H/V/D) | **< 0.0064** | ≈ 0 |
| Key sensitivity (1-bit flip) | **99.61 %** pixel change | ≈ 99.6 % |
| HMAC tamper detection | **pass** | reject any modified bit |
| Throughput (C core, 1 thread) | **~3.0 M px/s** | — |
| Speedup over pure-Python | **63×** | — |

These are statistical / empirical properties only. They are necessary but
not sufficient for cryptographic security — see **Limitations** below.

---

## Skills demonstrated

This project was an exercise in:

- **Applied cryptographic primitives** — SHA-256, HMAC, key-dependent S-box
  construction, keystream-driven permutation, confusion/diffusion design.
- **Python ↔ C interop with `ctypes`** — designing a stable C ABI, marshalling
  NumPy buffers across the boundary safely, managing lifetimes.
- **Performance optimization** — profiling the pure-Python prototype,
  identifying hot loops (permutation + diffusion), porting them to C, and
  delivering a **63× end-to-end speedup** (~3 M px/s on a single core).
- **Algorithmic complexity analysis** — reasoning about and verifying the
  `O(n log n)` time / `O(n)` space bounds.
- **Empirical security evaluation** — building an NPCR/UACI/entropy/
  correlation/key-sensitivity test harness from the image-cipher literature.
- **Technical writing** — formal specification, prior-art survey, and an
  honest viability analysis aimed at a non-specialist reader.

---

## Limitations

This is the honest section. If you are evaluating TPF as a real cipher,
please read it carefully:

- **No formal security proof.** TPF is an engineering construction, not a
  reduction-based scheme.
- **No public cryptanalysis.** It has not been reviewed by working
  cryptographers. Statistical tests like NPCR/UACI rule out very weak
  schemes but do not establish security.
- **Linear diffusion layer.** The parallel-prefix XOR step is linear over
  GF(2); confusion comes from the S-box and the plaintext-dependent keying.
  A dedicated linear/differential cryptanalysis pass is out of scope.
- **128-bit key space.** Adequate against classical brute force, but offers
  no margin for future attacks; modern designs increasingly target 256-bit.
- **Plaintext-dependent keying requires a nonce channel.** Decryption needs
  the SHA-256 of the original image, so the construction is effectively
  nonce-based and the hash must be transmitted/stored alongside the
  ciphertext (it is integrity-protected by the HMAC).
- **Image-only.** The scheme is designed around 2D pixel buffers; it is not
  a general-purpose block or stream cipher.

**For production use, prefer AES-GCM or ChaCha20-Poly1305** from a vetted
library (e.g. `cryptography`, libsodium).

---

## Prior art and positioning

The component ideas in TPF are **not novel**, and this project does not
claim them as such:

- **Prefix-XOR diffusion** is mathematically equivalent to the classic
  chained-XOR diffusion from Fridrich (1998).
- **Tree- and permutation-based image scrambling** has extensive prior art,
  including Li, Knipe & Cheng (1997), Enayatifar et al. (2009, 2011), and
  Su, Wang & Lin (2022).

The contribution of this repo is a **competent re-combination** of these
ideas with a clean implementation, a fast C core, and an honest empirical
evaluation — not a new primitive.

---

## References

1. J. Fridrich, *Symmetric ciphers based on two-dimensional chaotic maps*,
   Int. J. Bifurcation and Chaos, 1998.
2. S. Li, J. Knipe, L. Cheng, *Image compression and encryption using tree
   structures*, Pattern Recognition Letters, 1997.
3. R. Enayatifar, *Image encryption via logistic map function and heap tree*,
   Int. J. Phys. Sci., 2011.
4. Z. Su, X. Wang, H. Lin, *A treap-based image encryption scheme*, 2022.
5. Y. Wu, J. P. Noonan, S. Agaian, *NPCR and UACI randomness tests for image
   encryption*, JSAT, 2011.
6. NIST FIPS 180-4 (SHA-256), FIPS 198-1 (HMAC).

---

## Repository layout

```
.
├── src/             # cipher implementation + C core
├── tests/           # NPCR/UACI/entropy/correlation/key-sensitivity suite
├── docs/            # specification + prior-art + viability analyses
├── examples/        # runnable encrypt/decrypt demo
├── web/             # pure-JS port + browser UI (GitHub Pages)
├── .github/         # Pages deploy workflow
├── assets/          # demo images
├── Makefile         # `make build` -> tpf_core.so
├── requirements.txt
├── LICENSE          # MIT
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
