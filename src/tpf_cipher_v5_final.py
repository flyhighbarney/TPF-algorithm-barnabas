"""
TPF Cipher — reference implementation (Python + C-accelerated core).

TODO: swap in the real tpf_cipher_v5_final.py from the project root.
This placeholder mirrors the public API documented in docs/SPECIFICATION.md
so that examples/demo.py and tests/test_suite_v5.py import cleanly.
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

_LIB_PATH = Path(__file__).with_name("tpf_core.so")
_lib = ctypes.CDLL(str(_LIB_PATH)) if _LIB_PATH.exists() else None

ROUNDS = 2
KEY_BYTES = 16  # 128-bit key


@dataclass
class Ciphertext:
    data: np.ndarray        # uint8 HxWx3
    image_hash: bytes       # SHA-256 of plaintext (nonce)
    tag: bytes              # HMAC-SHA256


def _expand_key(key: bytes, image: np.ndarray) -> bytes:
    """Plaintext-dependent key expansion: SHA-256(key || SHA-256(image))."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    img_hash = hashlib.sha256(image.tobytes()).digest()
    return hashlib.sha256(key + img_hash).digest(), img_hash


def _keystream(seed: bytes, n: int) -> np.ndarray:
    """Counter-mode SHA-256 keystream -> n bytes."""
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(seed + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return np.frombuffer(bytes(out[:n]), dtype=np.uint8)


def _permute_channel(ch: np.ndarray, seed: bytes) -> np.ndarray:
    # TODO: replace with C-core call when tpf_core.so is built.
    h, w = ch.shape
    rng = np.random.default_rng(int.from_bytes(seed[:8], "big"))
    row_perm = rng.permutation(h)
    col_perm = rng.permutation(w)
    out = ch[row_perm][:, col_perm]
    for i in range(h):
        out[i] = out[i][rng.permutation(w)]
    return out


def _sbox(seed: bytes) -> np.ndarray:
    rng = np.random.default_rng(int.from_bytes(seed[8:16], "big"))
    return rng.permutation(256).astype(np.uint8)


def _inv_sbox(sbox: np.ndarray) -> np.ndarray:
    inv = np.zeros(256, dtype=np.uint8)
    inv[sbox] = np.arange(256, dtype=np.uint8)
    return inv


def _prefix_xor_diffuse(ch: np.ndarray) -> np.ndarray:
    out = ch.copy()
    out = np.bitwise_xor.accumulate(out, axis=1)
    out = np.bitwise_xor.accumulate(out, axis=0)
    return out


def _inv_prefix_xor_diffuse(ch: np.ndarray) -> np.ndarray:
    out = ch.copy()
    out[1:, :] ^= ch[:-1, :]
    out[:, 1:] ^= out[:, :-1].copy()
    return out


def _rgb_entangle(img: np.ndarray, seed: bytes) -> np.ndarray:
    offsets = [seed[i] for i in range(3)]
    r, g, b = img[..., 0], img[..., 1], img[..., 2]
    r = r ^ np.roll(g, offsets[0])
    g = g ^ np.roll(b, offsets[1])
    b = b ^ np.roll(r, offsets[2])
    return np.stack([r, g, b], axis=-1)


def encrypt(image: np.ndarray, key: bytes) -> Ciphertext:
    if image.ndim != 3 or image.shape[2] != 3:
        raise ValueError("expected HxWx3 uint8 RGB image")
    img = image.astype(np.uint8)
    ek, img_hash = _expand_key(key, img)

    for r in range(ROUNDS):
        round_seed = hashlib.sha256(ek + r.to_bytes(2, "big")).digest()
        sbox = _sbox(round_seed)
        channels = []
        for c in range(3):
            ch = img[..., c]
            ch = _permute_channel(ch, round_seed + bytes([c]))
            ch = sbox[ch]
            ch = _prefix_xor_diffuse(ch)
            channels.append(ch)
        img = np.stack(channels, axis=-1)
        img = _rgb_entangle(img, round_seed)

    tag = hmac.new(ek, img.tobytes() + img_hash, hashlib.sha256).digest()
    return Ciphertext(data=img, image_hash=img_hash, tag=tag)


def decrypt(ct: Ciphertext, key: bytes) -> np.ndarray:
    # TODO: full inverse pipeline. Placeholder verifies HMAC and image hash.
    ek = hashlib.sha256(key + ct.image_hash).digest()
    expected = hmac.new(ek, ct.data.tobytes() + ct.image_hash, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, ct.tag):
        raise ValueError("HMAC verification failed — ciphertext tampered")
    raise NotImplementedError("TODO: wire in the real inverse pipeline")


__all__ = ["encrypt", "decrypt", "Ciphertext", "ROUNDS", "KEY_BYTES"]
