"""
TPF Cipher v5 empirical security test suite.

TODO: swap in the full test_suite_v5.py from the project root for the
extended Lena/Baboon/Peppers battery. This file is the runnable smoke
subset used by `make test`.

Reference thresholds (Wu, Noonan, Agaian 2011):
  NPCR ideal  >= 99.6094 %
  UACI ideal  ~= 33.4635 %
  Entropy     -> 8.000 bits/byte
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.tpf_cipher_v5_final import (  # noqa: E402
    encrypt,
    encrypt_authenticated,
    decrypt_authenticated,
)


def _rand_image(h=128, w=128, seed=0):
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
    if axis == 0:
        x, y = a[:-1, :, :].ravel(), a[1:, :, :].ravel()
    elif axis == 1:
        x, y = a[:, :-1, :].ravel(), a[:, 1:, :].ravel()
    else:
        x, y = a[:-1, :-1, :].ravel(), a[1:, 1:, :].ravel()
    return float(np.corrcoef(x, y)[0, 1])


def test_entropy_near_ideal():
    img = _rand_image(seed=1)
    enc = encrypt(img, key=os.urandom(16))
    h = shannon_entropy(enc)
    assert h > 7.99, f"entropy too low: {h}"


def test_npcr_uaci_plaintext_sensitivity():
    key = os.urandom(16)
    a = _rand_image(seed=2)
    b = a.copy()
    b[0, 0, 0] ^= 1
    ca = encrypt(a, key)
    cb = encrypt(b, key)
    assert npcr(ca, cb) > 99.0
    assert 30.0 < uaci(ca, cb) < 36.0


def test_key_sensitivity():
    img = _rand_image(seed=3)
    k1 = os.urandom(16)
    k2 = bytearray(k1); k2[0] ^= 1
    c1 = encrypt(img, k1)
    c2 = encrypt(img, bytes(k2))
    assert npcr(c1, c2) > 99.0


def test_correlation_low():
    img = _rand_image(seed=4)
    enc = encrypt(img, os.urandom(16))
    for axis in (0, 1, 2):
        assert abs(adjacent_correlation(enc, axis)) < 0.05


def test_authenticated_roundtrip():
    img = _rand_image(seed=5)
    key = os.urandom(16)
    enc, h, tag = encrypt_authenticated(img, key)
    dec = decrypt_authenticated(enc, key, h, tag)
    assert np.array_equal(dec, img)


def test_hmac_tamper_detection():
    img = _rand_image(seed=6)
    key = os.urandom(16)
    enc, h, tag = encrypt_authenticated(img, key)
    enc[0, 0, 0] ^= 1  # flip one bit
    try:
        decrypt_authenticated(enc, key, h, tag)
    except ValueError:
        return
    raise AssertionError("HMAC failed to detect tamper")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
