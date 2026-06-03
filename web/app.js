// app.js — UI controller for the TPF web demo.

import {
  encryptAuthenticated,
  decryptAuthenticated,
  encryptAnimated,
  decryptAnimated,
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

// ─────────────────────────────────────────────────────────────────────────────
// ANIMATE tab
// ─────────────────────────────────────────────────────────────────────────────

const ANI_MAX_DIM = 256;  // downscale uploads so animation stays interactive

const aniState = {
  input: null,           // { rgb, w, h }
  direction: "enc",      // "enc" | "dec"
  stages: [],            // [{label, desc, rgb, final?}, ...]
  current: 0,
  playing: false,
  speedMs: 1000,
  encResult: null,       // cached encrypt output for decrypt animation
  keyForResult: null,    // hex key that produced encResult
};

const aniEls = {
  input: $("ani-input"), meta: $("ani-meta"), key: $("ani-key"),
  play: $("ani-play"), step: $("ani-step"), reset: $("ani-reset"),
  canvas: $("ani-canvas"), label: $("ani-stage-label"), desc: $("ani-stage-desc"),
  status: $("ani-status"), strip: $("ani-strip"),
  speed: $("ani-speed"), speedLabel: $("ani-speed-label"),
  dirEnc: $("ani-dir-enc"), dirDec: $("ani-dir-dec"),
};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function hsvToRgb(h, s, v) {
  const i = Math.floor(h * 6), f = h * 6 - i;
  const p = v * (1 - s), q = v * (1 - f * s), t = v * (1 - (1 - f) * s);
  let r, g, b;
  switch (i % 6) {
    case 0: r=v; g=t; b=p; break;
    case 1: r=q; g=v; b=p; break;
    case 2: r=p; g=v; b=t; break;
    case 3: r=p; g=q; b=v; break;
    case 4: r=t; g=p; b=v; break;
    default: r=v; g=p; b=q;
  }
  return [Math.round(r*255), Math.round(g*255), Math.round(b*255)];
}

function generateDemoImage(w = 224, h = 224) {
  // HSV wheel + radial stripes + "TPF" overlay — visually distinctive so the
  // scrambling stages stand out.
  const cx = w / 2, cy = h / 2;
  const tmp = document.createElement("canvas");
  tmp.width = w; tmp.height = h;
  const ctx = tmp.getContext("2d", { colorSpace: "srgb" });
  const id = ctx.createImageData(w, h, { colorSpace: "srgb" });
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const dx = x - cx, dy = y - cy;
      const angle = Math.atan2(dy, dx);
      const rad = Math.sqrt(dx*dx + dy*dy) / Math.min(cx, cy);
      const hue = (angle / Math.PI + 1) / 2;
      const sat = Math.min(1, rad);
      const stripe = 0.85 + 0.15 * Math.sin(rad * 18);
      const [r, g, b] = hsvToRgb(hue, sat, stripe);
      const i = (y * w + x) * 4;
      id.data[i] = r; id.data[i+1] = g; id.data[i+2] = b; id.data[i+3] = 255;
    }
  }
  ctx.putImageData(id, 0, 0);
  ctx.font = "bold 88px ui-sans-serif, system-ui, sans-serif";
  ctx.fillStyle = "#fff";
  ctx.strokeStyle = "rgba(0,0,0,0.85)";
  ctx.lineWidth = 5;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.strokeText("TPF", cx, cy);
  ctx.fillText("TPF", cx, cy);
  const out = ctx.getImageData(0, 0, w, h, { colorSpace: "srgb" });
  const rgb = new Uint8Array(w * h * 3);
  for (let i = 0; i < w*h; i++) {
    rgb[i*3] = out.data[i*4]; rgb[i*3+1] = out.data[i*4+1]; rgb[i*3+2] = out.data[i*4+2];
  }
  return { rgb, w, h };
}

aniEls.dirEnc.addEventListener("click", () => setDirection("enc"));
aniEls.dirDec.addEventListener("click", () => setDirection("dec"));
function setDirection(d) {
  aniState.direction = d;
  aniEls.dirEnc.classList.toggle("primary", d === "enc");
  aniEls.dirEnc.classList.toggle("ghost",   d !== "enc");
  aniEls.dirDec.classList.toggle("primary", d === "dec");
  aniEls.dirDec.classList.toggle("ghost",   d !== "dec");
  resetStages();
}

aniEls.speed.addEventListener("input", () => {
  aniState.speedMs = +aniEls.speed.value;
  aniEls.speedLabel.textContent = `${(aniState.speedMs / 1000).toFixed(1)}s / step`;
});

$("ani-demo").addEventListener("click", () => {
  const { rgb, w, h } = generateDemoImage();
  setAniInput(rgb, w, h, `synthetic demo pattern — ${w}×${h}`);
});

$("ani-upload-btn").addEventListener("click", () => $("ani-file").click());
$("ani-file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  if (!f) return;
  try {
    setAniStatus("loading image…", "busy");
    const bitmap = await loadImageFile(f);
    let { width: w, height: h } = bitmap;
    const longest = Math.max(w, h);
    if (longest > ANI_MAX_DIM) {
      const s = ANI_MAX_DIM / longest;
      w = Math.max(8, Math.floor(w * s));
      h = Math.max(8, Math.floor(h * s));
    }
    const tmp = document.createElement("canvas");
    tmp.width = w; tmp.height = h;
    const ctx = tmp.getContext("2d", { willReadFrequently: true, colorSpace: "srgb" });
    ctx.imageSmoothingEnabled = true;
    ctx.drawImage(bitmap, 0, 0, w, h);
    const id = ctx.getImageData(0, 0, w, h, { colorSpace: "srgb" });
    const rgb = new Uint8Array(w * h * 3);
    for (let i = 0; i < w * h; i++) {
      rgb[i*3]   = id.data[i*4];
      rgb[i*3+1] = id.data[i*4+1];
      rgb[i*3+2] = id.data[i*4+2];
    }
    setAniInput(rgb, w, h, `${f.name} — scaled to ${w}×${h} for animation`);
    setAniStatus("", "");
  } catch (err) {
    setAniStatus("could not load image: " + err.message, "err");
  }
});

function setAniInput(rgb, w, h, metaText) {
  aniState.input = { rgb, w, h };
  aniState.encResult = null;
  aniState.keyForResult = null;
  rgbToCanvas(rgb, w, h, aniEls.input);
  aniEls.input.hidden = false;
  aniEls.meta.textContent = metaText;
  rgbToCanvas(rgb, w, h, aniEls.canvas);
  aniEls.label.textContent = "Press Play to begin";
  aniEls.desc.textContent = "";
  resetStages();
  refreshAniButtons();
}

$("ani-key-rand").addEventListener("click", () => {
  aniEls.key.value = randomKeyHex();
  resetStages();
  refreshAniButtons();
});
aniEls.key.addEventListener("input", () => {
  resetStages();
  refreshAniButtons();
});

function refreshAniButtons() {
  const keyOk = /^[0-9a-fA-F]{32}$/.test(aniEls.key.value.trim());
  const ready = !!aniState.input && keyOk;
  aniEls.play.disabled  = !ready;
  aniEls.step.disabled  = !ready;
  aniEls.reset.disabled = !ready;
}

function setAniStatus(msg, kind = "") {
  aniEls.status.className = "status" + (kind ? " " + kind : "");
  aniEls.status.textContent = msg;
}

function resetStages() {
  aniState.stages = [];
  aniState.current = 0;
  aniState.playing = false;
  aniEls.play.textContent = "▶ Play";
  aniEls.strip.innerHTML = "";
  if (aniState.input) {
    rgbToCanvas(aniState.input.rgb, aniState.input.w, aniState.input.h, aniEls.canvas);
    aniEls.label.textContent = "Press Play to begin";
    aniEls.desc.textContent = "";
  }
}

aniEls.reset.addEventListener("click", resetStages);

async function ensureStages() {
  if (aniState.stages.length > 0) return;

  const key = hexToBytes(aniEls.key.value);
  const keyHex = aniEls.key.value.toLowerCase();
  const { rgb, w, h } = aniState.input;

  if (aniState.direction === "enc") {
    setAniStatus("computing encrypt stages…", "busy");
    await sleep(0);
    aniState.encResult = await encryptAnimated(rgb, h, w, key, async (s) => {
      aniState.stages.push(s);
    });
    aniState.keyForResult = keyHex;
  } else {
    if (!aniState.encResult || aniState.keyForResult !== keyHex) {
      setAniStatus("encrypting first to produce ciphertext…", "busy");
      await sleep(0);
      aniState.encResult = await encryptAuthenticated(rgb, h, w, key);
      aniState.keyForResult = keyHex;
    }
    setAniStatus("computing decrypt stages…", "busy");
    await sleep(0);
    const { enc, imghash, tag } = aniState.encResult;
    await decryptAnimated(enc, h, w, key, imghash, tag, async (s) => {
      aniState.stages.push(s);
    });
  }

  buildFilmstrip();
  setAniStatus(`${aniState.stages.length} stages ready`, "ok");
}

function buildFilmstrip() {
  const strip = aniEls.strip;
  strip.innerHTML = "";
  const { w, h } = aniState.input;
  aniState.stages.forEach((s, idx) => {
    const div = document.createElement("div");
    div.className = "frame";
    const c = document.createElement("canvas");
    const thumbW = 72;
    c.width = thumbW;
    c.height = Math.max(1, Math.round(h * thumbW / w));
    const big = document.createElement("canvas");
    big.width = w; big.height = h;
    rgbToCanvas(s.rgb, w, h, big);
    const ctx = c.getContext("2d", { colorSpace: "srgb" });
    ctx.imageSmoothingEnabled = true;
    ctx.drawImage(big, 0, 0, c.width, c.height);
    div.appendChild(c);
    const lbl = document.createElement("div");
    lbl.className = "frame-label";
    lbl.textContent = String(idx + 1);
    div.appendChild(lbl);
    div.title = s.label;
    div.addEventListener("click", () => {
      aniState.playing = false;
      aniEls.play.textContent = "▶ Play";
      aniState.current = idx;
      showStage(idx);
    });
    strip.appendChild(div);
  });
}

function showStage(i) {
  const s = aniState.stages[i];
  if (!s) return;
  const { w, h } = aniState.input;
  aniEls.label.innerHTML = `${i + 1} / ${aniState.stages.length} · <em>${s.label}</em>`;
  aniEls.desc.textContent = s.desc;
  rgbToCanvas(s.rgb, w, h, aniEls.canvas);
  aniEls.canvas.classList.remove("flash");
  // force reflow so animation restarts
  void aniEls.canvas.offsetWidth;
  aniEls.canvas.classList.add("flash");
  document.querySelectorAll("#ani-strip .frame").forEach((f, j) => {
    f.classList.toggle("current", j === i);
  });
  // Auto-scroll filmstrip to keep current frame in view
  const cur = aniEls.strip.children[i];
  if (cur) cur.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
}

aniEls.play.addEventListener("click", async () => {
  if (aniState.playing) {
    aniState.playing = false;
    aniEls.play.textContent = "▶ Play";
    return;
  }
  try {
    aniEls.play.disabled = true;
    await ensureStages();
  } catch (e) {
    setAniStatus("error: " + e.message, "err");
    aniEls.play.disabled = false;
    return;
  }
  aniEls.play.disabled = false;
  if (aniState.stages.length === 0) return;

  // Start from current; if at the end, restart from 0
  if (aniState.current >= aniState.stages.length - 1) aniState.current = 0;
  showStage(aniState.current);

  aniState.playing = true;
  aniEls.play.textContent = "❚❚ Pause";
  while (aniState.playing && aniState.current < aniState.stages.length - 1) {
    await sleep(aniState.speedMs);
    if (!aniState.playing) break;
    aniState.current++;
    showStage(aniState.current);
  }
  aniState.playing = false;
  aniEls.play.textContent = "▶ Play";
});

aniEls.step.addEventListener("click", async () => {
  try {
    await ensureStages();
  } catch (e) {
    setAniStatus("error: " + e.message, "err");
    return;
  }
  if (aniState.current < aniState.stages.length - 1) {
    aniState.current++;
  } else {
    aniState.current = 0;
  }
  showStage(aniState.current);
});

// Auto-load demo image so the tab is useful immediately on first visit.
window.addEventListener("DOMContentLoaded", () => {
  const { rgb, w, h } = generateDemoImage();
  setAniInput(rgb, w, h, `synthetic demo pattern — ${w}×${h} (click Upload to use your own)`);
  aniEls.key.value = randomKeyHex();
  refreshAniButtons();
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
