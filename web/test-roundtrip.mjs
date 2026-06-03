// Node round-trip test for tpf.js — verifies the JS cipher in isolation
// from the browser canvas / PNG layer. Run with: node web/test-roundtrip.mjs

import {
  encryptAuthenticated,
  decryptAuthenticated,
  bytesToHex,
  hexToBytes,
  randomKeyHex,
} from "./tpf.js";

// Node 19+ exposes WebCrypto as globalThis.crypto. Older Node would need
// `globalThis.crypto = (await import("crypto")).webcrypto;`

function makeImage(w, h, seed = 1) {
  const rgb = new Uint8Array(w * h * 3);
  let s = seed >>> 0;
  for (let i = 0; i < rgb.length; i++) {
    s = (s * 1664525 + 1013904223) >>> 0; // LCG
    rgb[i] = s & 0xFF;
  }
  return rgb;
}

function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return i;
  return -1;
}

async function runCase(w, h, label) {
  const rgb = makeImage(w, h);
  const key = hexToBytes(randomKeyHex());
  const t0 = performance.now();
  const { enc, imghash, tag } = await encryptAuthenticated(rgb, h, w, key);
  const t1 = performance.now();
  const dec = await decryptAuthenticated(enc, h, w, key, imghash, tag);
  const t2 = performance.now();

  const diff = bytesEq(rgb, dec);
  const ok = diff === -1;
  console.log(
    `[${label.padEnd(10)}] ${w}x${h}  enc=${(t1-t0).toFixed(0)}ms  ` +
    `dec=${(t2-t1).toFixed(0)}ms  hash=${bytesToHex(imghash).slice(0,12)}…  ` +
    `tag=${bytesToHex(tag).slice(0,12)}…  ${ok ? "✓ round-trip OK" : "✗ MISMATCH at byte " + diff}`
  );
  return ok;
}

async function runTamper() {
  const w = 16, h = 16;
  const rgb = makeImage(w, h, 42);
  const key = hexToBytes(randomKeyHex());
  const { enc, imghash, tag } = await encryptAuthenticated(rgb, h, w, key);

  const tampered = enc.slice();
  tampered[0] ^= 1;
  try {
    await decryptAuthenticated(tampered, h, w, key, imghash, tag);
    console.log("[tamper    ] ✗ should have thrown");
    return false;
  } catch (e) {
    const ok = /HMAC/i.test(e.message);
    console.log(`[tamper    ] ${ok ? "✓" : "✗"} caught: ${e.message}`);
    return ok;
  }
}

async function runWrongKey() {
  const w = 16, h = 16;
  const rgb = makeImage(w, h, 7);
  const key = hexToBytes(randomKeyHex());
  const wrongKey = hexToBytes(randomKeyHex());
  const { enc, imghash, tag } = await encryptAuthenticated(rgb, h, w, key);
  try {
    await decryptAuthenticated(enc, h, w, wrongKey, imghash, tag);
    console.log("[wrong-key ] ✗ should have thrown");
    return false;
  } catch (e) {
    const ok = /HMAC/i.test(e.message);
    console.log(`[wrong-key ] ${ok ? "✓" : "✗"} caught: ${e.message}`);
    return ok;
  }
}

const results = [];
results.push(await runCase(8,   8,   "tiny"));
results.push(await runCase(16,  16,  "small"));
results.push(await runCase(32,  32,  "medium"));
results.push(await runCase(64,  64,  "large"));
results.push(await runTamper());
results.push(await runWrongKey());

const passed = results.filter(Boolean).length;
console.log(`\n${passed}/${results.length} tests passed`);
process.exit(passed === results.length ? 0 : 1);
