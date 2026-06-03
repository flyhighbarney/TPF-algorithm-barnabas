// app.js — UI controller for the TPF web demo.

import {
  encryptAuthenticated,
  decryptAuthenticated,
  bytesToHex,
  hexToBytes,
  randomKeyHex,
} from "./tpf.js";

const $ = (id) => document.getElementById(id);

// ── Tabs ─────────────────────────────────────────────────────────────────────

for (const btn of document.querySelectorAll(".tab")) {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b === btn));
    const target = btn.dataset.tab;
    document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === target));
  });
}

// ── Image <-> canvas helpers ─────────────────────────────────────────────────

// Decode the file into an ImageBitmap with *no* color-space conversion.
// Plain <img> + drawImage will silently apply the browser's color management
// (sRGB ↔ display-P3 etc.), which mangles bytes for a byte-exact cipher —
// causing spurious HMAC failures on what should be a clean PNG round-trip.
async function loadImageFile(file) {
  return await createImageBitmap(file, {
    colorSpaceConversion: "none",
    premultiplyAlpha: "none",
  });
}

function imageToCanvasRGB(bitmap, canvas) {
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", {
    willReadFrequently: true,
    colorSpace: "srgb",
  });
  ctx.imageSmoothingEnabled = false;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(bitmap, 0, 0);
  const id = ctx.getImageData(0, 0, canvas.width, canvas.height, {
    colorSpace: "srgb",
  });
  const n = canvas.width * canvas.height;
  const rgb = new Uint8Array(n * 3);
  for (let i = 0; i < n; i++) {
    rgb[i*3]   = id.data[i*4];
    rgb[i*3+1] = id.data[i*4+1];
    rgb[i*3+2] = id.data[i*4+2];
  }
  return { rgb, w: canvas.width, h: canvas.height };
}

function rgbToCanvas(rgb, w, h, canvas) {
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext("2d", {
    willReadFrequently: true,
    colorSpace: "srgb",
  });
  const id = ctx.createImageData(w, h, { colorSpace: "srgb" });
  const n = w * h;
  for (let i = 0; i < n; i++) {
    id.data[i*4]   = rgb[i*3];
    id.data[i*4+1] = rgb[i*3+1];
    id.data[i*4+2] = rgb[i*3+2];
    id.data[i*4+3] = 255;
  }
  ctx.putImageData(id, 0, 0);
}

function canvasToBlob(canvas, type = "image/png") {
  return new Promise(res => canvas.toBlob(res, type));
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ── Drag-drop wiring ─────────────────────────────────────────────────────────

function wireDrop(dropEl, fileEl, onFile) {
  dropEl.addEventListener("click", () => fileEl.click());
  fileEl.addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (f) onFile(f);
  });
  ["dragenter", "dragover"].forEach(ev => dropEl.addEventListener(ev, (e) => {
    e.preventDefault(); dropEl.classList.add("over");
  }));
  ["dragleave", "drop"].forEach(ev => dropEl.addEventListener(ev, (e) => {
    e.preventDefault(); dropEl.classList.remove("over");
  }));
  dropEl.addEventListener("drop", (e) => {
    const f = e.dataTransfer?.files?.[0];
    if (f) onFile(f);
  });
}

// ── State ────────────────────────────────────────────────────────────────────

const state = {
  enc: { rgb: null, w: 0, h: 0, output: null, hash: null, tag: null },
  dec: { rgb: null, w: 0, h: 0 },
};

function setStatus(el, msg, kind = "") {
  el.className = "status" + (kind ? " " + kind : "");
  el.textContent = msg;
}

// ── ENCRYPT tab ──────────────────────────────────────────────────────────────

const encDrop = $("enc-drop"), encFile = $("enc-file"),
      encPreview = $("enc-preview"), encMeta = $("enc-meta"),
      encKey = $("enc-key"), encRun = $("enc-run"), encStatus = $("enc-status"),
      encOut = $("enc-out"), encOutput = $("enc-output"),
      encHash = $("enc-hash"), encTag = $("enc-tag");

wireDrop(encDrop, encFile, async (f) => {
  try {
    const img = await loadImageFile(f);
    const { rgb, w, h } = imageToCanvasRGB(img, encPreview);
    encPreview.hidden = false;
    encMeta.textContent = `${f.name} — ${w}×${h} (${(rgb.length/1024).toFixed(1)} KB RGB)`;
    state.enc = { rgb, w, h, output: null, hash: null, tag: null };
    encOut.hidden = true; encOutput.hidden = true;
    refreshEncBtn();
  } catch (e) {
    setStatus(encStatus, "could not load image: " + e.message, "err");
  }
});

$("enc-key-rand").addEventListener("click", () => {
  encKey.value = randomKeyHex();
  refreshEncBtn();
});
encKey.addEventListener("input", refreshEncBtn);

function refreshEncBtn() {
  const keyOk = /^[0-9a-fA-F]{32}$/.test(encKey.value.trim());
  const ready = state.enc.rgb && keyOk;
  encRun.disabled = !ready;
  const selftest = $("enc-selftest");
  if (selftest) selftest.disabled = !ready;
}

encRun.addEventListener("click", async () => {
  encRun.disabled = true;
  try {
    const key = hexToBytes(encKey.value);
    const t0 = performance.now();
    const { enc, imghash, tag } = await encryptAuthenticated(
      state.enc.rgb, state.enc.h, state.enc.w, key,
      (msg) => setStatus(encStatus, msg + " …", "busy"),
    );
    const dt = ((performance.now() - t0) / 1000).toFixed(2);

    state.enc.output = enc;
    state.enc.hash = imghash;
    state.enc.tag = tag;

    rgbToCanvas(enc, state.enc.w, state.enc.h, encOut);
    encOut.hidden = false;
    encHash.textContent = bytesToHex(imghash);
    encTag.textContent = bytesToHex(tag);
    encOutput.hidden = false;
    setStatus(encStatus, `done in ${dt}s — save the hash + tag, you need them to decrypt`, "ok");
  } catch (e) {
    setStatus(encStatus, "error: " + e.message, "err");
  } finally {
    refreshEncBtn();
  }
});

$("enc-selftest").addEventListener("click", async () => {
  const btn = $("enc-selftest");
  btn.disabled = true; encRun.disabled = true;
  try {
    setStatus(encStatus, "self-test: encrypting in memory …", "busy");
    const key = hexToBytes(encKey.value);
    const { enc, imghash, tag } = await encryptAuthenticated(
      state.enc.rgb, state.enc.h, state.enc.w, key,
      (m) => setStatus(encStatus, "self-test: " + m + " …", "busy"));
    setStatus(encStatus, "self-test: decrypting in memory …", "busy");
    const dec = await decryptAuthenticated(
      enc, state.enc.h, state.enc.w, key, imghash, tag,
      (m) => setStatus(encStatus, "self-test: " + m + " …", "busy"));
    let mismatch = -1;
    for (let i = 0; i < dec.length; i++) {
      if (dec[i] !== state.enc.rgb[i]) { mismatch = i; break; }
    }
    if (mismatch === -1) {
      setStatus(encStatus,
        `self-test ✓  encrypt+decrypt round-trip is byte-exact (${dec.length} bytes)`, "ok");
    } else {
      setStatus(encStatus,
        `self-test ✗  mismatch at byte ${mismatch} — cipher bug, please file an issue`, "err");
    }
  } catch (e) {
    setStatus(encStatus, "self-test error: " + e.message, "err");
  } finally {
    refreshEncBtn();
  }
});

$("enc-dl-png").addEventListener("click", async () => {
  const blob = await canvasToBlob(encOut, "image/png");
  downloadBlob(blob, "tpf-encrypted.png");
});

$("enc-dl-bundle").addEventListener("click", async () => {
  const blob = await canvasToBlob(encOut, "image/png");
  const buf = new Uint8Array(await blob.arrayBuffer());
  const bundle = {
    format: "tpf-v5-bundle",
    width: state.enc.w, height: state.enc.h,
    image_hash: bytesToHex(state.enc.hash),
    hmac_tag:   bytesToHex(state.enc.tag),
    ciphertext_png_b64: btoa(String.fromCharCode(...buf)),
  };
  downloadBlob(new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }),
               "tpf-encrypted.json");
});

// Copy buttons
document.querySelectorAll(".copy").forEach(btn => {
  btn.addEventListener("click", async () => {
    const id = btn.dataset.copy;
    await navigator.clipboard.writeText($(id).textContent);
    const orig = btn.textContent;
    btn.textContent = "copied!";
    setTimeout(() => { btn.textContent = orig; }, 1200);
  });
});

// ── DECRYPT tab ──────────────────────────────────────────────────────────────

const decDrop = $("dec-drop"), decFile = $("dec-file"),
      decPreview = $("dec-preview"), decMeta = $("dec-meta"),
      decKey = $("dec-key"), decHash = $("dec-hash"), decTag = $("dec-tag"),
      decRun = $("dec-run"), decStatus = $("dec-status"),
      decOut = $("dec-out"), decDl = $("dec-dl-png");

wireDrop(decDrop, decFile, async (f) => {
  try {
    if (f.name.endsWith(".json")) {
      const text = await f.text();
      const bundle = JSON.parse(text);
      if (bundle.format !== "tpf-v5-bundle") throw new Error("not a TPF bundle");
      const binStr = atob(bundle.ciphertext_png_b64);
      const buf = new Uint8Array(binStr.length);
      for (let i = 0; i < binStr.length; i++) buf[i] = binStr.charCodeAt(i);
      const img = await loadImageFile(new File([buf], "ct.png", { type: "image/png" }));
      const { rgb, w, h } = imageToCanvasRGB(img, decPreview);
      state.dec = { rgb, w, h };
      decPreview.hidden = false;
      decMeta.textContent = `bundle — ${w}×${h}`;
      decHash.value = bundle.image_hash || "";
      decTag.value  = bundle.hmac_tag || "";
    } else {
      const img = await loadImageFile(f);
      const { rgb, w, h } = imageToCanvasRGB(img, decPreview);
      state.dec = { rgb, w, h };
      decPreview.hidden = false;
      decMeta.textContent = `${f.name} — ${w}×${h}`;
    }
    refreshDecBtn();
  } catch (e) {
    setStatus(decStatus, "could not load: " + e.message, "err");
  }
});

[decKey, decHash, decTag].forEach(el => el.addEventListener("input", refreshDecBtn));
function refreshDecBtn() {
  const keyOk  = /^[0-9a-fA-F]{32}$/.test(decKey.value.trim());
  const hashOk = /^[0-9a-fA-F]{64}$/.test(decHash.value.trim());
  const tagOk  = /^[0-9a-fA-F]{64}$/.test(decTag.value.trim());
  decRun.disabled = !(state.dec.rgb && keyOk && hashOk && tagOk);
}

decRun.addEventListener("click", async () => {
  decRun.disabled = true;
  try {
    const key  = hexToBytes(decKey.value);
    const hash = hexToBytes(decHash.value);
    const tag  = hexToBytes(decTag.value);
    const t0 = performance.now();
    const out = await decryptAuthenticated(
      state.dec.rgb, state.dec.h, state.dec.w, key, hash, tag,
      (msg) => setStatus(decStatus, msg + " …", "busy"),
    );
    const dt = ((performance.now() - t0) / 1000).toFixed(2);

    rgbToCanvas(out, state.dec.w, state.dec.h, decOut);
    decOut.hidden = false;
    decDl.hidden = false;
    setStatus(decStatus, `decrypted in ${dt}s — HMAC verified`, "ok");
  } catch (e) {
    setStatus(decStatus, "error: " + e.message, "err");
  } finally {
    refreshDecBtn();
  }
});

decDl.addEventListener("click", async () => {
  const blob = await canvasToBlob(decOut, "image/png");
  downloadBlob(blob, "tpf-decrypted.png");
});

// ── repo link: leave generic, user customises after fork ─────────────────────
const repo = $("repo-link");
if (repo) {
  // best-effort: derive from current location if on github.io
  const m = location.hostname.match(/^([^.]+)\.github\.io$/);
  if (m) {
    const user = m[1];
    const path = location.pathname.split("/").filter(Boolean)[0] || "tpf-cipher";
    repo.href = `https://github.com/${user}/${path}`;
  }
}
