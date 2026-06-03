// tpf.js — pure-JavaScript port of the TPF v5 cipher.
//
// Faithful port of src/tpf_cipher_v5_final.py + src/tpf_core.c, designed
// to round-trip in the browser. Not constant-time, not hardened, not for
// real-world use — see the project README.

const MASK64 = (1n << 64n) - 1n;

// ── splitmix64 PRNG ──────────────────────────────────────────────────────────

class SplitMix64 {
  constructor(seed) {
    this.state = BigInt.asUintN(64, typeof seed === "bigint" ? seed : BigInt(seed));
  }
  next() {
    this.state = (this.state + 0x9E3779B97F4A7C15n) & MASK64;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xBF58476D1CE4E5B9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94D049BB133111EBn) & MASK64;
    return z ^ (z >> 31n);
  }
  nextByte() { return Number(this.next() & 0xFFn); }
  nextMod(m) { return Number(this.next() % BigInt(m)); }
}

// ── Fisher–Yates ─────────────────────────────────────────────────────────────

function fisherYates(n, seed) {
  const perm = new Int32Array(n);
  for (let i = 0; i < n; i++) perm[i] = i;
  const rng = new SplitMix64(seed);
  for (let i = n - 1; i > 0; i--) {
    const j = rng.nextMod(i + 1);
    const t = perm[i]; perm[i] = perm[j]; perm[j] = t;
  }
  return perm;
}

function inversePerm(perm) {
  const inv = new Int32Array(perm.length);
  for (let i = 0; i < perm.length; i++) inv[perm[i]] = i;
  return inv;
}

// ── S-box ────────────────────────────────────────────────────────────────────

function genSbox(seed) {
  const sbox = new Uint8Array(256);
  for (let i = 0; i < 256; i++) sbox[i] = i;
  const rng = new SplitMix64(seed);
  for (let i = 255; i > 0; i--) {
    const j = rng.nextMod(i + 1);
    const t = sbox[i]; sbox[i] = sbox[j]; sbox[j] = t;
  }
  return sbox;
}

function invSbox(sbox) {
  const inv = new Uint8Array(256);
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  return inv;
}

function applySbox(data, sbox) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = sbox[data[i]];
  return out;
}

// ── SHA-256 / HMAC via WebCrypto ─────────────────────────────────────────────

export async function sha256(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  const h = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(h);
}

async function hmacSha256(key, data) {
  // Copy into a plain ArrayBuffer view to keep WebCrypto happy across browsers.
  const keyBuf = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
  const k = await crypto.subtle.importKey(
    "raw", keyBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, data);
  return new Uint8Array(sig);
}

function constTimeEq(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── 64-bit big-endian read from a byte slice (matches Python int.from_bytes) ─

function readBE(bytes, off, len = 8) {
  let v = 0n;
  const end = Math.min(off + len, bytes.length);
  for (let i = off; i < end; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

// ── Key expansion (mirror of Python _expand) ─────────────────────────────────

export async function expandKeyFromHash(key, imghash) {
  const c = new Uint8Array(key.length + imghash.length);
  c.set(key, 0); c.set(imghash, key.length);

  const m = new Uint8Array(256);
  for (let i = 0; i < 8; i++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, i, false); // big-endian
    const part = await sha256(c, ctr);
    m.set(part, i * 32);
  }

  const g = (o, l = 8) => readBE(m, o, l);

  return {
    r1_row: g(0),    r1_col: g(8),    g1_row: g(16),   g1_col: g(24),
    b1_row: g(32),   b1_col: g(40),
    r2_row: g(48),   r2_col: g(56),   g2_row: g(64),   g2_col: g(72),
    b2_row: g(80),   b2_col: g(88),
    r_dr:  g(96),    r_dc:  g(104),   r_df:  g(112),
    g_dr:  g(120),   g_dc:  g(128),   g_df:  g(136),
    b_dr:  g(144),   b_dc:  g(152),   b_df:  g(160),
    r_dr2: g(168),   r_dc2: g(176),   r_df2: g(184),
    g_dr2: g(192),   g_dc2: g(200),   g_df2: g(208),
    b_dr2: g(216),   b_dc2: g(224),   b_df2: g(232),
    mode:  (m[240] << 8) | m[241],
    r_sb1: g(242),   r_sb2: g(250),
    g_sb1: g(130) ^ g(0),   g_sb2: g(138) ^ g(8),
    b_sb1: g(146) ^ g(16),  b_sb2: g(154) ^ g(24),
    hmac_key: m.slice(160, 192),
  };
}

export async function expandKey(key, rgbBytes) {
  const imghash = await sha256(rgbBytes);
  const K = await expandKeyFromHash(key, imghash);
  return { K, imghash };
}

// ── 2D permutation ───────────────────────────────────────────────────────────

function permute2d(ch, h, w, rs, cs) {
  const rp = fisherYates(h, rs);
  const cp = fisherYates(w, cs);

  // Row shuffle: out[i] = ch[rp[i]]
  const rowShuffled = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    rowShuffled.set(ch.subarray(rp[i] * w, rp[i] * w + w), i * w);
  }

  // Col shuffle: out[i][j] = rowShuffled[i][cp[j]]
  const colShuffled = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    const off = i * w;
    for (let j = 0; j < w; j++) colShuffled[off + j] = rowShuffled[off + cp[j]];
  }

  // Intra-row shuffle
  const out = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    const ip = fisherYates(w, rs ^ cs ^ BigInt(i));
    const off = i * w;
    for (let j = 0; j < w; j++) out[off + j] = colShuffled[off + ip[j]];
  }
  return out;
}

function invPermute2d(ch, h, w, rs, cs) {
  const rp = fisherYates(h, rs);
  const cp = fisherYates(w, cs);

  // Reverse intra-row
  const intraDone = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    const ip = fisherYates(w, rs ^ cs ^ BigInt(i));
    const inv = inversePerm(ip);
    const off = i * w;
    for (let j = 0; j < w; j++) intraDone[off + j] = ch[off + inv[j]];
  }

  // Reverse col shuffle
  const invC = inversePerm(cp);
  const colDone = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    const off = i * w;
    for (let j = 0; j < w; j++) colDone[off + j] = intraDone[off + invC[j]];
  }

  // Reverse row shuffle
  const invR = inversePerm(rp);
  const out = new Uint8Array(h * w);
  for (let i = 0; i < h; i++) {
    out.set(colDone.subarray(invR[i] * w, invR[i] * w + w), i * w);
  }
  return out;
}

// ── 2D diffusion (in-place; mirrors tpf_core.c) ──────────────────────────────

function diffuse2d(data, h, w, rowSeed, colSeed, fullSeed) {
  const n = h * w;

  // Row-wise: per row, XOR key bytes then prefix-XOR along the row.
  const rngR = new SplitMix64(rowSeed);
  for (let i = 0; i < h; i++) {
    const off = i * w;
    for (let j = 0; j < w; j++) data[off + j] ^= rngR.nextByte();
    for (let j = 1; j < w; j++) data[off + j] ^= data[off + j - 1];
  }

  // Column-wise: per column.
  const rngC = new SplitMix64(colSeed);
  for (let j = 0; j < w; j++) {
    for (let i = 0; i < h; i++) data[i * w + j] ^= rngC.nextByte();
    for (let i = 1; i < h; i++) data[i * w + j] ^= data[(i - 1) * w + j];
  }

  // Full-image: XOR keystream, then cumulative XOR over the flat buffer.
  const rngF = new SplitMix64(fullSeed);
  for (let i = 0; i < n; i++) data[i] ^= rngF.nextByte();
  for (let i = 1; i < n; i++) data[i] ^= data[i - 1];
}

function invDiffuse2d(data, h, w, rowSeed, colSeed, fullSeed) {
  const n = h * w;

  // Pre-generate keystreams to match encrypt-side allocation order.
  const rkeys = new Uint8Array(h * w);
  const rngR = new SplitMix64(rowSeed);
  for (let i = 0; i < h * w; i++) rkeys[i] = rngR.nextByte();

  const ckeys = new Uint8Array(w * h); // ckeys[j*h + i] = byte for col j, row i
  const rngC = new SplitMix64(colSeed);
  for (let i = 0; i < w * h; i++) ckeys[i] = rngC.nextByte();

  const fkey = new Uint8Array(n);
  const rngF = new SplitMix64(fullSeed);
  for (let i = 0; i < n; i++) fkey[i] = rngF.nextByte();

  // Reverse full prefix XOR (walk backwards in place).
  for (let i = n - 1; i >= 1; i--) data[i] ^= data[i - 1];
  for (let i = 0; i < n; i++) data[i] ^= fkey[i];

  // Reverse column prefix XOR.
  for (let j = 0; j < w; j++) {
    for (let i = h - 1; i >= 1; i--) data[i * w + j] ^= data[(i - 1) * w + j];
    for (let i = 0; i < h; i++) data[i * w + j] ^= ckeys[j * h + i];
  }

  // Reverse row prefix XOR.
  for (let i = 0; i < h; i++) {
    const off = i * w;
    for (let j = w - 1; j >= 1; j--) data[off + j] ^= data[off + j - 1];
    for (let j = 0; j < w; j++) data[off + j] ^= rkeys[i * w + j];
  }
}

// ── Cross-channel entanglement ───────────────────────────────────────────────

function roll(arr, shift) {
  const n = arr.length;
  shift = ((shift % n) + n) % n;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[(i + shift) % n] = arr[i];
  return out;
}

function entangle(r, g, b, mode) {
  const n = r.length;
  const r1 = Math.max(1, (mode & 0xFF) % n);
  const r2 = Math.max(1, ((mode >> 8) & 0xFF) % n);
  const rolledB = roll(b, r1);
  const rf = new Uint8Array(n);
  for (let i = 0; i < n; i++) rf[i] = r[i] ^ rolledB[i];
  const rolledRf = roll(rf, r2);
  const gf = new Uint8Array(n);
  for (let i = 0; i < n; i++) gf[i] = g[i] ^ rolledRf[i];
  const rolledGf = roll(gf, r1 + r2);
  const bf = new Uint8Array(n);
  for (let i = 0; i < n; i++) bf[i] = b[i] ^ rolledGf[i];
  return [rf, gf, bf];
}

function disentangle(rf, gf, bf, mode) {
  const n = rf.length;
  const r1 = Math.max(1, (mode & 0xFF) % n);
  const r2 = Math.max(1, ((mode >> 8) & 0xFF) % n);
  const rolledGf = roll(gf, r1 + r2);
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = bf[i] ^ rolledGf[i];
  const rolledRf = roll(rf, r2);
  const g = new Uint8Array(n);
  for (let i = 0; i < n; i++) g[i] = gf[i] ^ rolledRf[i];
  const rolledB = roll(b, r1);
  const r = new Uint8Array(n);
  for (let i = 0; i < n; i++) r[i] = rf[i] ^ rolledB[i];
  return [r, g, b];
}

// ── Per-channel encrypt / decrypt ────────────────────────────────────────────

function encryptChannel(ch, h, w, K, p) {
  let x = permute2d(ch, h, w, K[`${p}1_row`], K[`${p}1_col`]);
  x = applySbox(x, genSbox(K[`${p}_sb1`]));
  diffuse2d(x, h, w, K[`${p}_dr`], K[`${p}_dc`], K[`${p}_df`]);
  x = permute2d(x, h, w, K[`${p}2_row`], K[`${p}2_col`]);
  x = applySbox(x, genSbox(K[`${p}_sb2`]));
  diffuse2d(x, h, w, K[`${p}_dr2`], K[`${p}_dc2`], K[`${p}_df2`]);
  return x;
}

function decryptChannel(ch, h, w, K, p) {
  const x = ch.slice();
  invDiffuse2d(x, h, w, K[`${p}_dr2`], K[`${p}_dc2`], K[`${p}_df2`]);
  let y = applySbox(x, invSbox(genSbox(K[`${p}_sb2`])));
  y = invPermute2d(y, h, w, K[`${p}2_row`], K[`${p}2_col`]);
  invDiffuse2d(y, h, w, K[`${p}_dr`], K[`${p}_dc`], K[`${p}_df`]);
  y = applySbox(y, invSbox(genSbox(K[`${p}_sb1`])));
  y = invPermute2d(y, h, w, K[`${p}1_row`], K[`${p}1_col`]);
  return y;
}

// ── Public API: yield to the UI between channels via `progress` callback ────

function splitChannels(rgb, n) {
  const r = new Uint8Array(n), g = new Uint8Array(n), b = new Uint8Array(n);
  for (let i = 0; i < n; i++) { r[i] = rgb[i*3]; g[i] = rgb[i*3+1]; b[i] = rgb[i*3+2]; }
  return [r, g, b];
}
function joinChannels(r, g, b, n) {
  const out = new Uint8Array(n * 3);
  for (let i = 0; i < n; i++) { out[i*3] = r[i]; out[i*3+1] = g[i]; out[i*3+2] = b[i]; }
  return out;
}

const yieldToUI = () => new Promise(res => setTimeout(res, 0));

export async function encryptAuthenticated(rgbBytes, h, w, key, progress = () => {}) {
  if (key.length !== 16) throw new Error("key must be 16 bytes (128 bits)");
  const { K, imghash } = await expandKey(key, rgbBytes);
  const n = h * w;
  const [r, g, b] = splitChannels(rgbBytes, n);

  progress("encrypt R channel"); await yieldToUI();
  const re = encryptChannel(r, h, w, K, "r");
  progress("encrypt G channel"); await yieldToUI();
  const ge = encryptChannel(g, h, w, K, "g");
  progress("encrypt B channel"); await yieldToUI();
  const be = encryptChannel(b, h, w, K, "b");

  progress("entangle + HMAC"); await yieldToUI();
  const [rf, gf, bf] = entangle(re, ge, be, K.mode);
  const enc = joinChannels(rf, gf, bf, n);
  const tag = await hmacSha256(K.hmac_key, enc);
  return { enc, imghash, tag };
}

export async function decryptAuthenticated(rgbBytes, h, w, key, imghash, tag, progress = () => {}) {
  if (key.length !== 16) throw new Error("key must be 16 bytes (128 bits)");
  if (imghash.length !== 32) throw new Error("image_hash must be 32 bytes");
  if (tag.length !== 32) throw new Error("hmac_tag must be 32 bytes");

  const K = await expandKeyFromHash(key, imghash);

  progress("verify HMAC"); await yieldToUI();
  const expected = await hmacSha256(K.hmac_key, rgbBytes);
  if (!constTimeEq(expected, tag)) {
    throw new Error("HMAC verification failed — ciphertext tampered, or wrong key/hash");
  }

  const n = h * w;
  const [rf, gf, bf] = splitChannels(rgbBytes, n);
  const [re, ge, be] = disentangle(rf, gf, bf, K.mode);

  progress("decrypt R channel"); await yieldToUI();
  const r = decryptChannel(re, h, w, K, "r");
  progress("decrypt G channel"); await yieldToUI();
  const g = decryptChannel(ge, h, w, K, "g");
  progress("decrypt B channel"); await yieldToUI();
  const b = decryptChannel(be, h, w, K, "b");

  return joinChannels(r, g, b, n);
}

// ── Animated variants: yield intermediate RGB snapshots per stage ────────────

export async function encryptAnimated(rgbBytes, h, w, key, onStage) {
  if (key.length !== 16) throw new Error("key must be 16 bytes (128 bits)");
  const { K, imghash } = await expandKey(key, rgbBytes);
  const n = h * w;
  let [R, G, B] = splitChannels(rgbBytes, n);

  await onStage({
    label: "Plaintext",
    desc: "Original image, decomposed into independent R, G, B channels.",
    rgb: joinChannels(R, G, B, n),
  });

  for (let round = 1; round <= 2; round++) {
    const suf = round === 1 ? "" : "2";

    R = permute2d(R, h, w, K[`r${round}_row`], K[`r${round}_col`]);
    G = permute2d(G, h, w, K[`g${round}_row`], K[`g${round}_col`]);
    B = permute2d(B, h, w, K[`b${round}_row`], K[`b${round}_col`]);
    await onStage({
      label: `Round ${round} · 2D permutation`,
      desc: "Fisher–Yates shuffles rows, then columns, then within each row — destroys spatial correlation without changing pixel values.",
      rgb: joinChannels(R, G, B, n),
    });

    R = applySbox(R, genSbox(K[`r_sb${round}`]));
    G = applySbox(G, genSbox(K[`g_sb${round}`]));
    B = applySbox(B, genSbox(K[`b_sb${round}`]));
    await onStage({
      label: `Round ${round} · S-box`,
      desc: "Key-dependent 8-bit non-linear substitution: every pixel byte is replaced by sbox[byte]. Adds confusion.",
      rgb: joinChannels(R, G, B, n),
    });

    const Rd = R.slice(), Gd = G.slice(), Bd = B.slice();
    diffuse2d(Rd, h, w, K[`r_dr${suf}`], K[`r_dc${suf}`], K[`r_df${suf}`]);
    diffuse2d(Gd, h, w, K[`g_dr${suf}`], K[`g_dc${suf}`], K[`g_df${suf}`]);
    diffuse2d(Bd, h, w, K[`b_dr${suf}`], K[`b_dc${suf}`], K[`b_df${suf}`]);
    R = Rd; G = Gd; B = Bd;
    await onStage({
      label: `Round ${round} · prefix-XOR diffusion`,
      desc: "Row, column, and full-image prefix-XOR with a keystream. After this stage, every output byte depends on every preceding byte and on the key.",
      rgb: joinChannels(R, G, B, n),
    });
  }

  const [Rf, Gf, Bf] = entangle(R, G, B, K.mode);
  const enc = joinChannels(Rf, Gf, Bf, n);
  await onStage({
    label: "Cross-channel entanglement",
    desc: "R, G, B are XOR-mixed at key-derived rotated offsets — flipping a bit in one channel propagates to all three.",
    rgb: enc,
  });

  const tag = await hmacSha256(K.hmac_key, enc);
  await onStage({
    label: "Authenticated ciphertext",
    desc: "HMAC-SHA-256 tag computed over the ciphertext. The image hash + tag travel alongside the ciphertext for integrity.",
    rgb: enc,
    final: true,
  });

  return { enc, imghash, tag };
}

export async function decryptAnimated(rgbBytes, h, w, key, imghash, tag, onStage) {
  if (key.length !== 16) throw new Error("key must be 16 bytes (128 bits)");
  const K = await expandKeyFromHash(key, imghash);

  const expected = await hmacSha256(K.hmac_key, rgbBytes);
  if (!constTimeEq(expected, tag)) {
    throw new Error("HMAC verification failed — ciphertext tampered, or wrong key/hash");
  }

  const n = h * w;
  await onStage({
    label: "Ciphertext (HMAC verified)",
    desc: "HMAC tag matches — the ciphertext is intact and we can safely invert the pipeline.",
    rgb: rgbBytes.slice(),
  });

  const [Rf, Gf, Bf] = splitChannels(rgbBytes, n);
  let [R, G, B] = disentangle(Rf, Gf, Bf, K.mode);
  await onStage({
    label: "Disentanglement",
    desc: "Undo the cross-channel XOR mixing, recovering the pre-entanglement R, G, B.",
    rgb: joinChannels(R, G, B, n),
  });

  for (let round = 2; round >= 1; round--) {
    const suf = round === 1 ? "" : "2";

    const Rd = R.slice(), Gd = G.slice(), Bd = B.slice();
    invDiffuse2d(Rd, h, w, K[`r_dr${suf}`], K[`r_dc${suf}`], K[`r_df${suf}`]);
    invDiffuse2d(Gd, h, w, K[`g_dr${suf}`], K[`g_dc${suf}`], K[`g_df${suf}`]);
    invDiffuse2d(Bd, h, w, K[`b_dr${suf}`], K[`b_dc${suf}`], K[`b_df${suf}`]);
    R = Rd; G = Gd; B = Bd;
    await onStage({
      label: `Round ${round}⁻¹ · diffusion`,
      desc: "Reverse the row + column + full-image prefix-XOR and strip the keystream.",
      rgb: joinChannels(R, G, B, n),
    });

    R = applySbox(R, invSbox(genSbox(K[`r_sb${round}`])));
    G = applySbox(G, invSbox(genSbox(K[`g_sb${round}`])));
    B = applySbox(B, invSbox(genSbox(K[`b_sb${round}`])));
    await onStage({
      label: `Round ${round}⁻¹ · S-box`,
      desc: "Apply the inverse S-box — substitution undone.",
      rgb: joinChannels(R, G, B, n),
    });

    R = invPermute2d(R, h, w, K[`r${round}_row`], K[`r${round}_col`]);
    G = invPermute2d(G, h, w, K[`g${round}_row`], K[`g${round}_col`]);
    B = invPermute2d(B, h, w, K[`b${round}_row`], K[`b${round}_col`]);
    await onStage({
      label: `Round ${round}⁻¹ · permutation`,
      desc: "Reverse the row + column + intra-row shuffles. Pixels return to their original positions.",
      rgb: joinChannels(R, G, B, n),
      final: round === 1,
    });
  }

  return joinChannels(R, G, B, n);
}

// ── Hex helpers ──────────────────────────────────────────────────────────────

export function bytesToHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}
export function hexToBytes(hex) {
  hex = hex.trim().toLowerCase().replace(/\s+/g, "");
  if (hex.length % 2 !== 0) throw new Error("hex string must have even length");
  if (!/^[0-9a-f]*$/.test(hex)) throw new Error("hex string contains non-hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i*2, 2), 16);
  return out;
}
export function randomKeyHex() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}
