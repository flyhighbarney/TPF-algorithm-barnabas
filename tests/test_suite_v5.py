"""
TPF Cipher empirical security test suite.

TODO: swap in the real test_suite_v5.py. This placeholder is a runnable
skeleton with the same metric names so CI / `make test` works.

Reference thresholds (Wu, Noonan, Agaian 2011):
  NPCR ideal  >= 99.6094 %
  UACI ideal  ~= 33.4635 %
  Entropy     -> 8.000 bits/byte
"""
from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.tpf_cipher_v5_final import encrypt  # noqa: E402


def _rand_image(h=256, w=256, seed=0):
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, size=(h, w, 3), dtype=np.uint8)


def shannon_entropy(img: np.ndarray) -> float:
    hist, _ = np.histogram(img, bins=256, range=(0, 256))
    p = hist / hist.sum()
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def npcr(a: np.ndarray, b: np.ndarray) -> float:
    return float((a != b).mean() * 100.0)


def uaci(a: np.ndarray, b: np.ndarray) -> float:
    diff = np.abs(a.astype(int) - b.astype(int)) / 255.0
    return float(diff.mean() * 100.0)


def adjacent_correlation(img: np.ndarray, axis: int) -> float:
    a = img.astype(float)
    if axis == 0:    # vertical
        x, y = a[:-1, :, :].ravel(), a[1:, :, :].ravel()
    elif axis == 1:  # horizontal
        x, y = a[:, :-1, :].ravel(), a[:, 1:, :].ravel()
    else:            # diagonal
        x, y = a[:-1, :-1, :].ravel(), a[1:, 1:, :].ravel()
    return float(np.corrcoef(x, y)[0, 1])


def test_entropy_near_ideal():
    img = _rand_image(seed=1)
    ct = encrypt(img, key=os.urandom(16))
    h = shannon_entropy(ct.data)
    assert h > 7.99, f"entropy too low: {h}"


def test_npcr_uaci():
    key = os.urandom(16)
    a = _rand_image(seed=2)
    b = a.copy()
    b[0, 0, 0] ^= 1  # 1-bit plaintext flip
    ca = encrypt(a, key).data
    cb = encrypt(b, key).data
    assert npcr(ca, cb) > 99.0
    u = uaci(ca, cb)
    assert 30.0 < u < 36.0


def test_key_sensitivity():
    img = _rand_image(seed=3)
    k1 = os.urandom(16)
    k2 = bytearray(k1); k2[0] ^= 1
    c1 = encrypt(img, k1).data
    c2 = encrypt(img, bytes(k2)).data
    assert npcr(c1, c2) > 99.0


def test_correlation_low():
    img = _rand_image(seed=4)
    ct = encrypt(img, os.urandom(16)).data
    for axis in (0, 1, 2):
        assert abs(adjacent_correlation(ct, axis)) < 0.05


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
