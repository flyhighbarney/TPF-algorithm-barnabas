# Prior art and positioning

> TODO: swap in the full prior-art report once converted to Markdown.

This document records the academic lineage of the ideas in TPF so that the
project's contribution can be stated honestly.

## Component-by-component

### Prefix-XOR diffusion
The "parallel-prefix" XOR layer (each output pixel = cumulative XOR of all
preceding pixels along a scan order) is **mathematically equivalent to the
chained-XOR diffusion proposed by Fridrich (1998)**. The "parallel-prefix"
naming reflects how it can be computed in `O(log n)` parallel depth via a
Blelloch / Hillis–Steele scan; it is not a different primitive.

### Tree / permutation-based scrambling
Image scrambling via tree structures and keystream-driven permutations has
extensive prior art:

- Li, Knipe & Cheng (1997) — tree-based image scrambling.
- Enayatifar (2009, 2011) — heap-tree and logistic-map permutations.
- Su, Wang & Lin (2022) — explicit treap-based image encryption.

### Key-dependent S-boxes
Constructing S-boxes from a key-seeded PRNG and evaluating them with NPCR,
UACI, entropy, and non-linearity measures is standard practice in the image-
cipher literature (Wu, Noonan & Agaian 2011, and follow-ups).

### Plaintext-dependent keying
Mixing `SHA-256(plaintext)` into the round-key schedule is widely used in
the chaos-cipher literature to defeat known-plaintext attacks. It is
effectively a nonce-based construction.

## What this project actually contributes

- A clean **re-combination** of well-known components into a single
  end-to-end pipeline.
- A **fast C core** delivering a 63× speedup over the Python prototype.
- A full **empirical test harness** with reproducible NPCR/UACI/entropy/
  correlation/key-sensitivity numbers.
- Honest engineering documentation, including this prior-art ledger.

## What this project does **not** claim

- A new cryptographic primitive.
- Security beyond what statistical tests can show.
- Suitability for production deployment.
