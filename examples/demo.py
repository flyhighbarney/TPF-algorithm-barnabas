"""
End-to-end TPF demo: load an image, encrypt (authenticated), save the
ciphertext as PNG, then decrypt and verify the round-trip.

Usage:
    python examples/demo.py --in assets/original.png \
                            --enc assets/encrypted.png \
                            --dec assets/decrypted.png
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.tpf_cipher_v5_final import encrypt_authenticated, decrypt_authenticated  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in",  dest="inp", default="assets/original.png")
    p.add_argument("--enc", dest="enc", default="assets/encrypted.png")
    p.add_argument("--dec", dest="dec", default="assets/decrypted.png")
    p.add_argument("--key", default=None, help="32-char hex key (default: random)")
    args = p.parse_args()

    key = bytes.fromhex(args.key) if args.key else os.urandom(16)

    img = np.array(Image.open(args.inp).convert("RGB"), dtype=np.uint8)
    enc, img_hash, tag = encrypt_authenticated(img, key)

    Image.fromarray(enc).save(args.enc)
    print(f"[+] wrote ciphertext -> {args.enc}")
    print(f"[+] key        : {key.hex()}")
    print(f"[+] image_hash : {img_hash.hex()}")
    print(f"[+] hmac tag   : {tag.hex()}")

    # Round-trip verification
    dec = decrypt_authenticated(enc, key, img_hash, tag)
    Image.fromarray(dec).save(args.dec)
    match = np.array_equal(dec, img)
    print(f"[+] wrote plaintext  -> {args.dec}")
    print(f"[+] round-trip match : {match}")
    if not match:
        sys.exit(1)


if __name__ == "__main__":
    main()
