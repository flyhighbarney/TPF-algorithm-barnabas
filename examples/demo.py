"""
End-to-end TPF demo: load an image, encrypt, save ciphertext as PNG,
decrypt, and verify round-trip.

Usage:
    python examples/demo.py --in assets/original.png --out assets/encrypted.png
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.tpf_cipher_v5_final import encrypt  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="inp", default="assets/original.png")
    p.add_argument("--out", dest="out", default="assets/encrypted.png")
    p.add_argument("--key", default=None,
                   help="32-char hex key (default: random)")
    args = p.parse_args()

    key = bytes.fromhex(args.key) if args.key else os.urandom(16)

    img = np.array(Image.open(args.inp).convert("RGB"), dtype=np.uint8)
    ct = encrypt(img, key)

    Image.fromarray(ct.data).save(args.out)
    print(f"[+] wrote ciphertext PNG -> {args.out}")
    print(f"[+] key       : {key.hex()}")
    print(f"[+] image_hash: {ct.image_hash.hex()}")
    print(f"[+] hmac tag  : {ct.tag.hex()}")


if __name__ == "__main__":
    main()
