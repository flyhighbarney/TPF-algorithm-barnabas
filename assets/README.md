# Demo assets

Place a sample image at `assets/original.png`, then run:

```
python examples/demo.py --in assets/original.png --out assets/encrypted.png
```

The README expects three files in this directory:

- `original.png` — the plaintext image (any RGB PNG you have rights to use).
- `encrypted.png` — produced by `examples/demo.py`.
- `decrypted.png` — produced by the inverse pipeline once wired in.

TODO: drop in a Lena / Baboon / Peppers test image you have permission to
redistribute. The classic Lena image is **not** redistribution-clean; prefer
the USC-SIPI "Baboon" or a CC0 photo from Unsplash.
