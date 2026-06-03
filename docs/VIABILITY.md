# Viability analysis

> TODO: swap in the full viability/analysis report. Summary below.

## Verdict

TPF Cipher is a **competent educational construction**. It is not a
production cipher and is not proposed as one.

## What the evidence supports

The empirical results (entropy ≈ 7.997, NPCR ≈ 99.60 %, UACI ≈ 33.45 %,
adjacent-pixel correlation < 0.0064, key sensitivity ≈ 99.61 %) are
**necessary** conditions for an image cipher. TPF clears them by margins
comparable to published chaos-based schemes.

## What the evidence does **not** support

These metrics are **not sufficient** for cryptographic security:

- They are statistical and do not rule out structured attacks.
- The diffusion layer is linear over GF(2); a dedicated linear /
  differential cryptanalysis pass is not in scope.
- There is no formal security reduction, and no public cryptanalysis.

## Honest comparison to AES-GCM / ChaCha20-Poly1305

| Property | AES-GCM / ChaCha20-Poly1305 | TPF |
| --- | --- | --- |
| Peer-reviewed | yes | no |
| Formal analysis / proofs | yes | no |
| Deployed at scale | yes | no |
| Side-channel hardened impls | yes | not analyzed |
| Key size | 128 / 256 | 128 |
| Use for real data? | **yes** | **no** |

## Recommendation

Use TPF as a learning artifact and a portfolio piece demonstrating
crypto-engineering, performance optimization, and empirical testing skills.
Do not use it to protect anything that matters.
