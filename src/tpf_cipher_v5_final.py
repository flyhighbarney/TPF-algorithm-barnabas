"""
TPF Cipher v5 — C-Accelerated + HMAC Authentication

All three limitations resolved:
  1. S-box non-linear substitution (v4)
  2. C-accelerated core operations (v5)
  3. HMAC-SHA256 authenticated encryption (v5)

Pipeline per channel (2 rounds):
  Permute2D → S-Box → Diffuse2D → [repeat] → Entangle → HMAC
"""
import hashlib, struct, hmac as hmac_mod, os, ctypes
import numpy as np
from pathlib import Path

# ── Load C library ────────────────────────────────────────────────────────────

_lib_path = Path(__file__).parent / "tpf_core.so"
_C = ctypes.CDLL(str(_lib_path))

# ctypes setup
_u8p = ctypes.POINTER(ctypes.c_uint8)
_i64p = ctypes.POINTER(ctypes.c_int64)
_int = ctypes.c_int
_u64 = ctypes.c_uint64

_C.fisher_yates.argtypes = [_i64p, _int, _u64]
_C.inverse_perm.argtypes = [_i64p, _i64p, _int]
_C.gen_sbox.argtypes = [_u8p, _u64]
_C.gen_inv_sbox.argtypes = [_u8p, _u8p]
_C.apply_sbox.argtypes = [_u8p, _u8p, _u8p, _int]
_C.gen_keybytes.argtypes = [_u8p, _int, _u64]
_C.xor_arrays.argtypes = [_u8p, _u8p, _u8p, _int]
_C.prefix_xor.argtypes = [_u8p, _int]
_C.inv_prefix_xor.argtypes = [_u8p, _u8p, _int]
_C.apply_perm.argtypes = [_u8p, _u8p, _i64p, _int]
_C.apply_inv_perm.argtypes = [_u8p, _u8p, _i64p, _int]
_C.diffuse_2d.argtypes = [_u8p, _int, _int, _u64, _u64, _u64]
_C.inv_diffuse_2d.argtypes = [_u8p, _int, _int, _u64, _u64, _u64]

def _ptr8(arr):
    return arr.ctypes.data_as(_u8p)
def _ptr64(arr):
    return arr.ctypes.data_as(_i64p)


# ── Key Expansion ─────────────────────────────────────────────────────────────

def _expand(key, imghash):
    m = b""
    c = key + imghash
    for i in range(8):
        m += hashlib.sha256(c + struct.pack(">I", i)).digest()
    g = lambda o, l: int.from_bytes(m[o:o+l], "big") & 0xFFFFFFFFFFFFFFFF
    return {
        "r1_row":g(0,8),"r1_col":g(8,8),"g1_row":g(16,8),"g1_col":g(24,8),
        "b1_row":g(32,8),"b1_col":g(40,8),
        "r2_row":g(48,8),"r2_col":g(56,8),"g2_row":g(64,8),"g2_col":g(72,8),
        "b2_row":g(80,8),"b2_col":g(88,8),
        "r_dr":g(96,8),"r_dc":g(104,8),"r_df":g(112,8),
        "g_dr":g(120,8),"g_dc":g(128,8),"g_df":g(136,8),
        "b_dr":g(144,8),"b_dc":g(152,8),"b_df":g(160,8),
        "r_dr2":g(168,8),"r_dc2":g(176,8),"r_df2":g(184,8),
        "g_dr2":g(192,8),"g_dc2":g(200,8),"g_df2":g(208,8),
        "b_dr2":g(216,8),"b_dc2":g(224,8),"b_df2":g(232,8),
        "mode":int.from_bytes(m[240:242],"big"),
        "r_sb1":g(242,8),"r_sb2":g(250,8),
        "g_sb1":g(130,8)^g(0,8),"g_sb2":g(138,8)^g(8,8),
        "b_sb1":g(146,8)^g(16,8),"b_sb2":g(154,8)^g(24,8),
        "hmac_key": m[160:192],  # 32 bytes for HMAC
    }

def expand_key(key, img):
    return _expand(key, hashlib.sha256(img.tobytes()).digest())
def expand_key_from_hash(key, h):
    return _expand(key, h)


# ── C-Accelerated Primitives ──────────────────────────────────────────────────

def c_permute_2d(ch, rs, cs):
    """2D permutation using C Fisher-Yates."""
    h, w = ch.shape
    r = ch.copy()

    # Row shuffle
    rp = np.empty(h, dtype=np.int64)
    _C.fisher_yates(_ptr64(rp), h, rs)
    r = r[rp, :]

    # Col shuffle
    cp = np.empty(w, dtype=np.int64)
    _C.fisher_yates(_ptr64(cp), w, cs)
    r = r[:, cp]

    # Intra-row shuffle
    for i in range(h):
        ip = np.empty(w, dtype=np.int64)
        _C.fisher_yates(_ptr64(ip), w, rs ^ cs ^ i)
        tmp = np.empty(w, dtype=np.uint8)
        _C.apply_perm(_ptr8(tmp), _ptr8(np.ascontiguousarray(r[i, :])), _ptr64(ip), w)
        r[i, :] = tmp

    return r

def c_inv_permute_2d(ch, rs, cs):
    """Inverse 2D permutation."""
    h, w = ch.shape
    r = ch.copy()

    rp = np.empty(h, dtype=np.int64); _C.fisher_yates(_ptr64(rp), h, rs)
    cp = np.empty(w, dtype=np.int64); _C.fisher_yates(_ptr64(cp), w, cs)

    # Reverse intra-row
    for i in range(h):
        ip = np.empty(w, dtype=np.int64)
        _C.fisher_yates(_ptr64(ip), w, rs ^ cs ^ i)
        inv = np.empty(w, dtype=np.int64)
        _C.inverse_perm(_ptr64(inv), _ptr64(ip), w)
        tmp = np.empty(w, dtype=np.uint8)
        _C.apply_perm(_ptr8(tmp), _ptr8(np.ascontiguousarray(r[i, :])), _ptr64(inv), w)
        r[i, :] = tmp

    # Reverse col
    inv_c = np.empty(w, dtype=np.int64); _C.inverse_perm(_ptr64(inv_c), _ptr64(cp), w)
    r = r[:, inv_c]
    # Reverse row
    inv_r = np.empty(h, dtype=np.int64); _C.inverse_perm(_ptr64(inv_r), _ptr64(rp), h)
    r = r[inv_r, :]
    return r

def c_sbox(data, seed):
    """Apply S-box using C."""
    sbox = np.empty(256, dtype=np.uint8)
    _C.gen_sbox(_ptr8(sbox), seed)
    flat = np.ascontiguousarray(data.ravel())
    out = np.empty_like(flat)
    _C.apply_sbox(_ptr8(out), _ptr8(flat), _ptr8(sbox), len(flat))
    return out.reshape(data.shape)

def c_inv_sbox(data, seed):
    """Inverse S-box using C."""
    sbox = np.empty(256, dtype=np.uint8)
    _C.gen_sbox(_ptr8(sbox), seed)
    inv = np.empty(256, dtype=np.uint8)
    _C.gen_inv_sbox(_ptr8(inv), _ptr8(sbox))
    flat = np.ascontiguousarray(data.ravel())
    out = np.empty_like(flat)
    _C.apply_sbox(_ptr8(out), _ptr8(flat), _ptr8(inv), len(flat))
    return out.reshape(data.shape)

def c_diffuse_2d(data, sr, sc, sf):
    """2D diffusion in C."""
    h, w = data.shape
    buf = np.ascontiguousarray(data.ravel().copy())
    _C.diffuse_2d(_ptr8(buf), h, w, sr, sc, sf)
    return buf.reshape(h, w)

def c_inv_diffuse_2d(data, sr, sc, sf):
    """Inverse 2D diffusion in C."""
    h, w = data.shape
    buf = np.ascontiguousarray(data.ravel().copy())
    _C.inv_diffuse_2d(_ptr8(buf), h, w, sr, sc, sf)
    return buf.reshape(h, w)


# ── Cross-Channel Entanglement ────────────────────────────────────────────────

def entangle(r, g, b, mode):
    n = len(r); r1 = max(1,(mode&0xFF)%n); r2 = max(1,((mode>>8)&0xFF)%n)
    rf = r ^ np.roll(b, r1); gf = g ^ np.roll(rf, r2); bf = b ^ np.roll(gf, r1+r2)
    return rf, gf, bf

def disentangle(rf, gf, bf, mode):
    n = len(rf); r1 = max(1,(mode&0xFF)%n); r2 = max(1,((mode>>8)&0xFF)%n)
    b = bf ^ np.roll(gf, r1+r2); g = gf ^ np.roll(rf, r2); r = rf ^ np.roll(b, r1)
    return r, g, b


# ── Per-Channel Encrypt/Decrypt ───────────────────────────────────────────────

def _enc_ch(ch, K, p):
    h, w = ch.shape
    # Round 1: permute → sbox → diffuse
    x = c_permute_2d(ch, K[f"{p}1_row"], K[f"{p}1_col"])
    x = c_sbox(x, K[f"{p}_sb1"])
    x = c_diffuse_2d(x, K[f"{p}_dr"], K[f"{p}_dc"], K[f"{p}_df"])
    # Round 2
    x = c_permute_2d(x, K[f"{p}2_row"], K[f"{p}2_col"])
    x = c_sbox(x, K[f"{p}_sb2"])
    x = c_diffuse_2d(x, K[f"{p}_dr2"], K[f"{p}_dc2"], K[f"{p}_df2"])
    return x.ravel()

def _dec_ch(flat, h, w, K, p):
    # Reverse round 2
    x = c_inv_diffuse_2d(flat.reshape(h,w), K[f"{p}_dr2"], K[f"{p}_dc2"], K[f"{p}_df2"])
    x = c_inv_sbox(x, K[f"{p}_sb2"])
    x = c_inv_permute_2d(x, K[f"{p}2_row"], K[f"{p}2_col"])
    # Reverse round 1
    x = c_inv_diffuse_2d(x, K[f"{p}_dr"], K[f"{p}_dc"], K[f"{p}_df"])
    x = c_inv_sbox(x, K[f"{p}_sb1"])
    x = c_inv_permute_2d(x, K[f"{p}1_row"], K[f"{p}1_col"])
    return x


# ── HMAC Authentication ───────────────────────────────────────────────────────

def compute_hmac(data_bytes: bytes, hmac_key: bytes) -> bytes:
    """Compute HMAC-SHA256 tag (32 bytes)."""
    return hmac_mod.new(hmac_key, data_bytes, hashlib.sha256).digest()

def verify_hmac(data_bytes: bytes, hmac_key: bytes, tag: bytes) -> bool:
    """Verify HMAC tag. Uses constant-time comparison."""
    expected = hmac_mod.new(hmac_key, data_bytes, hashlib.sha256).digest()
    return hmac_mod.compare_digest(expected, tag)


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt(image, key):
    """Encrypt image. Returns (encrypted_image, no authentication)."""
    assert image.ndim == 3 and image.shape[2] == 3 and len(key) == 16
    h, w, _ = image.shape; K = expand_key(key, image)
    re = _enc_ch(image[:,:,0], K, "r")
    ge = _enc_ch(image[:,:,1], K, "g")
    be = _enc_ch(image[:,:,2], K, "b")
    rf, gf, bf = entangle(re, ge, be, K["mode"])
    return np.stack([rf.reshape(h,w), gf.reshape(h,w), bf.reshape(h,w)], axis=2).astype(np.uint8)

def decrypt(image, key, original):
    """Decrypt using original image for key derivation."""
    K = expand_key(key, original); return _dec(image, K)

def encrypt_authenticated(image, key):
    """
    Encrypt + authenticate.
    Returns (encrypted_image, image_hash, hmac_tag).
    Send all three; recipient needs hash + tag + key to decrypt.
    """
    assert image.ndim == 3 and image.shape[2] == 3 and len(key) == 16
    image_hash = hashlib.sha256(image.tobytes()).digest()
    enc = encrypt(image, key)
    K = _expand(key, image_hash)
    tag = compute_hmac(enc.tobytes(), K["hmac_key"])
    return enc, image_hash, tag

def decrypt_authenticated(image, key, image_hash, tag):
    """
    Verify HMAC, then decrypt.
    Raises ValueError if authentication fails (tampered data).
    """
    K = expand_key_from_hash(key, image_hash)
    if not verify_hmac(image.tobytes(), K["hmac_key"], tag):
        raise ValueError("HMAC verification failed: encrypted image has been tampered with")
    return _dec(image, K)

def encrypt_with_hash(image, key):
    """Legacy API: encrypt + return hash."""
    h = hashlib.sha256(image.tobytes()).digest()
    return encrypt(image, key), h

def decrypt_with_hash(image, key, image_hash):
    """Legacy API: decrypt using hash."""
    K = expand_key_from_hash(key, image_hash)
    return _dec(image, K)

def _dec(image, K):
    h, w, _ = image.shape
    rf = image[:,:,0].ravel().astype(np.uint8)
    gf = image[:,:,1].ravel().astype(np.uint8)
    bf = image[:,:,2].ravel().astype(np.uint8)
    re, ge, be = disentangle(rf, gf, bf, K["mode"])
    ro = _dec_ch(re, h, w, K, "r")
    go = _dec_ch(ge, h, w, K, "g")
    bo = _dec_ch(be, h, w, K, "b")
    return np.stack([ro, go, bo], axis=2).astype(np.uint8)
