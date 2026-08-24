// Regenerate the app icon set + titlebar logo from logo.png (repo root).
//
//   node scripts/make-icons.js [out.b64]
//
// Writes crates/vpn-desktop/icons/* and prints the titlebar logo as base64 —
// paste that into the .brand img in crates/vpn-desktop/ui/index.html. This box
// has no ImageMagick/PIL/sharp, hence the hand-rolled PNG+ICO codec below.
// Pure Node (no sharp/ImageMagick available): decode PNG, recolour the wordmark
// for dark UI, resample with a scaled Catmull-Rom kernel, re-encode PNG, pack ICO.
const fs = require('fs'), zlib = require('zlib'), path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ICONS = path.join(ROOT, 'crates/vpn-desktop/icons');

/* ---------- PNG decode (8-bit, non-interlaced, color type 0/2/4/6) ---------- */
function decodePNG(buf) {
  let pos = 8, w = 0, h = 0, depth = 0, ct = 0, idat = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos), type = buf.toString('ascii', pos + 4, pos + 8);
    const data = buf.slice(pos + 8, pos + 8 + len);
    if (type === 'IHDR') {
      w = data.readUInt32BE(0); h = data.readUInt32BE(4); depth = data[8]; ct = data[9];
      if (depth !== 8 || data[12] !== 0) throw new Error('only 8-bit non-interlaced PNG supported');
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    pos += 12 + len;
  }
  const chans = { 0: 1, 2: 3, 4: 2, 6: 4 }[ct];
  if (!chans) throw new Error('unsupported color type ' + ct);
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const bpp = chans, stride = w * bpp;
  const out = Buffer.alloc(w * h * 4);
  let prev = Buffer.alloc(stride), cur = Buffer.alloc(stride), rp = 0;
  for (let y = 0; y < h; y++) {
    const ft = raw[rp++];
    raw.copy(cur, 0, rp, rp + stride); rp += stride;
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
      let v = cur[i];
      if (ft === 1) v += a;
      else if (ft === 2) v += b;
      else if (ft === 3) v += (a + b) >> 1;
      else if (ft === 4) {
        const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
        v += (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c);
      }
      cur[i] = v & 0xff;
    }
    for (let x = 0; x < w; x++) {
      const s = x * bpp, d = (y * w + x) * 4;
      if (ct === 6) { out[d] = cur[s]; out[d + 1] = cur[s + 1]; out[d + 2] = cur[s + 2]; out[d + 3] = cur[s + 3]; }
      else if (ct === 2) { out[d] = cur[s]; out[d + 1] = cur[s + 1]; out[d + 2] = cur[s + 2]; out[d + 3] = 255; }
      else if (ct === 4) { out[d] = out[d + 1] = out[d + 2] = cur[s]; out[d + 3] = cur[s + 1]; }
      else { out[d] = out[d + 1] = out[d + 2] = cur[s]; out[d + 3] = 255; }
    }
    const t = prev; prev = cur; cur = t;
  }
  return { w, h, data: out };
}

/* ---------- PNG encode (8-bit RGBA, Sub filter) ---------- */
const CRC_T = (() => { const t = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c; } return t; })();
function crc(b) { let c = -1; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 0xff] ^ (c >>> 8); return c ^ -1; }
function encodePNG(img) {
  const { w, h, data } = img, stride = w * 4;
  const raw = Buffer.alloc(h * (stride + 1));
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 1; // Sub: cheap and effective for flat icon art
    for (let i = 0; i < stride; i++) {
      const v = data[y * stride + i], left = i >= 4 ? data[y * stride + i - 4] : 0;
      raw[y * (stride + 1) + 1 + i] = (v - left) & 0xff;
    }
  }
  const chunk = (type, body) => {
    const b = Buffer.alloc(8 + body.length + 4);
    b.writeUInt32BE(body.length, 0); b.write(type, 4, 'ascii'); body.copy(b, 8);
    b.writeUInt32BE(crc(b.slice(4, 8 + body.length)) >>> 0, 8 + body.length);
    return b;
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* ---------- resample: Catmull-Rom, support widened when downscaling ---------- */
function kernel(x) {
  x = Math.abs(x);
  if (x < 1) return 1.5 * x * x * x - 2.5 * x * x + 1;
  if (x < 2) return -0.5 * x * x * x + 2.5 * x * x - 4 * x + 2;
  return 0;
}
function weights(sn, dn) {
  const scale = dn / sn, sup = scale < 1 ? 2 / scale : 2, rows = [];
  for (let d = 0; d < dn; d++) {
    const center = (d + 0.5) / scale;
    const lo = Math.max(0, Math.ceil(center - sup - 0.5)), hi = Math.min(sn - 1, Math.floor(center + sup - 0.5));
    const idx = [], wts = []; let sum = 0;
    for (let s = lo; s <= hi; s++) {
      const wv = kernel((s + 0.5 - center) * Math.min(1, scale));
      if (wv !== 0) { idx.push(s); wts.push(wv); sum += wv; }
    }
    for (let i = 0; i < wts.length; i++) wts[i] /= sum;
    rows.push({ idx, wts });
  }
  return rows;
}
// Resamples in premultiplied alpha, so transparent pixels can't bleed their
// (black) colour into the wordmark's antialiased edges.
function resize(img, dw, dh) {
  const { w, h, data } = img;
  const pm = new Float32Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const a = data[i * 4 + 3] / 255;
    pm[i * 4] = data[i * 4] * a; pm[i * 4 + 1] = data[i * 4 + 1] * a;
    pm[i * 4 + 2] = data[i * 4 + 2] * a; pm[i * 4 + 3] = data[i * 4 + 3];
  }
  const hx = weights(w, dw), tmp = new Float32Array(dw * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < dw; x++) {
    const { idx, wts } = hx[x]; let r = 0, g = 0, b = 0, a = 0;
    for (let i = 0; i < idx.length; i++) { const s = (y * w + idx[i]) * 4, k = wts[i]; r += pm[s] * k; g += pm[s + 1] * k; b += pm[s + 2] * k; a += pm[s + 3] * k; }
    const d = (y * dw + x) * 4; tmp[d] = r; tmp[d + 1] = g; tmp[d + 2] = b; tmp[d + 3] = a;
  }
  const vy = weights(h, dh), out = Buffer.alloc(dw * dh * 4);
  const cl = v => v < 0 ? 0 : v > 255 ? 255 : Math.round(v);
  for (let y = 0; y < dh; y++) for (let x = 0; x < dw; x++) {
    const { idx, wts } = vy[y]; let r = 0, g = 0, b = 0, a = 0;
    for (let i = 0; i < idx.length; i++) { const s = (idx[i] * dw + x) * 4, k = wts[i]; r += tmp[s] * k; g += tmp[s + 1] * k; b += tmp[s + 2] * k; a += tmp[s + 3] * k; }
    const d = (y * dw + x) * 4, af = a / 255;
    out[d] = af === 0 ? 0 : cl(r / af); out[d + 1] = af === 0 ? 0 : cl(g / af);
    out[d + 2] = af === 0 ? 0 : cl(b / af); out[d + 3] = cl(a);
  }
  return { w: dw, h: dh, data: out };
}

/* ---------- composition helpers ---------- */
function bbox(img) {
  let x0 = img.w, y0 = img.h, x1 = -1, y1 = -1;
  for (let y = 0; y < img.h; y++) for (let x = 0; x < img.w; x++) {
    if (img.data[(y * img.w + x) * 4 + 3] > 8) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
  }
  return { x0, y0, w: x1 - x0 + 1, h: y1 - y0 + 1 };
}
function crop(img, b) {
  const out = Buffer.alloc(b.w * b.h * 4);
  for (let y = 0; y < b.h; y++) for (let x = 0; x < b.w; x++) {
    const s = ((y + b.y0) * img.w + (x + b.x0)) * 4, d = (y * b.w + x) * 4;
    out[d] = img.data[s]; out[d + 1] = img.data[s + 1]; out[d + 2] = img.data[s + 2]; out[d + 3] = img.data[s + 3];
  }
  return { w: b.w, h: b.h, data: out };
}
// The source wordmark is near-black on transparency. Repaint the dark ink white
// and leave the red underbar alone; alpha carries the antialiasing either way.
function invertInk(img) {
  const out = Buffer.from(img.data);
  for (let i = 0; i < img.w * img.h; i++) {
    const r = out[i * 4], g = out[i * 4 + 1], b = out[i * 4 + 2], a = out[i * 4 + 3];
    if (a === 0) continue;
    const isRed = r > 110 && r > g * 1.6 && r > b * 1.6;
    if (!isRed) { out[i * 4] = 255; out[i * 4 + 1] = 255; out[i * 4 + 2] = 255; }
  }
  return { w: img.w, h: img.h, data: out };
}
// Rounded-rect card in a solid colour on a transparent canvas (4x4 supersampled).
function card(w, h, radius, rgb) {
  const data = Buffer.alloc(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    let hits = 0;
    for (let sy = 0; sy < 4; sy++) for (let sx = 0; sx < 4; sx++) {
      const px = x + (sx + 0.5) / 4, py = y + (sy + 0.5) / 4;
      const cx = Math.min(Math.max(px, radius), w - radius), cy = Math.min(Math.max(py, radius), h - radius);
      const dx = px - cx, dy = py - cy;
      if (dx * dx + dy * dy <= radius * radius) hits++;
    }
    const d = (y * w + x) * 4;
    data[d] = rgb[0]; data[d + 1] = rgb[1]; data[d + 2] = rgb[2]; data[d + 3] = Math.round(255 * hits / 16);
  }
  return { w, h, data };
}
function paste(dst, src, ox, oy) {
  for (let y = 0; y < src.h; y++) for (let x = 0; x < src.w; x++) {
    const dx = ox + x, dy = oy + y;
    if (dx < 0 || dy < 0 || dx >= dst.w || dy >= dst.h) continue;
    const s = (y * src.w + x) * 4, d = (dy * dst.w + dx) * 4;
    const sa = src.data[s + 3] / 255, da = dst.data[d + 3] / 255, oa = sa + da * (1 - sa);
    for (let c = 0; c < 3; c++) dst.data[d + c] = oa === 0 ? 0 : Math.round((src.data[s + c] * sa + dst.data[d + c] * da * (1 - sa)) / oa);
    dst.data[d + 3] = Math.round(oa * 255);
  }
}

/* ---------- build ---------- */
const src = decodePNG(fs.readFileSync(path.join(ROOT, 'logo.png')));
const logo = invertInk(crop(src, bbox(src)));   // white ITM + red bar, transparent bg
console.log('logo content box: ' + logo.w + 'x' + logo.h);

// The app's own surfaces, so the icon reads as part of the dark UI.
const CARD = [0x16, 0x21, 0x2f];   // --surface / titlebar top
const EDGE = [0x2c, 0x3b, 0x4f];   // hairline so the tile keeps an edge on a dark taskbar

// Square app icon: dark rounded card, hairline edge, wordmark at 76% width.
function makeIcon(size) {
  const small = size <= 48;
  const radius = size * (small ? 0.16 : 0.2);
  const c = card(size, size, radius, EDGE);
  const inset = Math.max(1, Math.round(size / 64));
  paste(c, card(size - inset * 2, size - inset * 2, Math.max(1, radius - inset), CARD), inset, inset);
  const lw = Math.round(size * (small ? 0.88 : 0.76)), lh = Math.max(1, Math.round(lw * logo.h / logo.w));
  paste(c, resize(logo, lw, lh), Math.round((size - lw) / 2), Math.round((size - lh) / 2));
  return c;
}
for (const [name, size] of [['32x32.png', 32], ['128x128.png', 128], ['128x128@2x.png', 256], ['256x256.png', 256], ['icon.png', 512]]) {
  fs.writeFileSync(path.join(ICONS, name), encodePNG(makeIcon(size)));
  console.log('wrote icons/' + name + ' (' + size + ')');
}

// ICO: BMP (BITMAPINFOHEADER + BGRA + AND mask) entries, same flavour the
// previous icon.ico used, so NSIS/WiX keep grokking it.
function icoEntry(img) {
  const { w, h, data } = img, maskStride = ((w + 31) >> 5) * 4;
  const bmp = Buffer.alloc(40 + w * h * 4 + maskStride * h);
  bmp.writeUInt32LE(40, 0); bmp.writeInt32LE(w, 4); bmp.writeInt32LE(h * 2, 8);
  bmp.writeUInt16LE(1, 12); bmp.writeUInt16LE(32, 14);
  bmp.writeUInt32LE(w * h * 4 + maskStride * h, 20);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const s = ((h - 1 - y) * w + x) * 4, d = 40 + (y * w + x) * 4;
    bmp[d] = data[s + 2]; bmp[d + 1] = data[s + 1]; bmp[d + 2] = data[s]; bmp[d + 3] = data[s + 3];
    if (data[s + 3] < 128) bmp[40 + w * h * 4 + y * maskStride + (x >> 3)] |= 0x80 >> (x & 7);
  }
  return bmp;
}
const icoSizes = [16, 24, 32, 48, 64, 128, 256];
const entries = icoSizes.map(s => ({ s, bmp: icoEntry(makeIcon(s)) }));
const dir = Buffer.alloc(6 + entries.length * 16);
dir.writeUInt16LE(0, 0); dir.writeUInt16LE(1, 2); dir.writeUInt16LE(entries.length, 4);
let off = dir.length;
entries.forEach((e, i) => {
  const o = 6 + i * 16;
  dir[o] = e.s & 0xff; dir[o + 1] = e.s & 0xff;
  dir.writeUInt16LE(1, o + 4); dir.writeUInt16LE(32, o + 6);
  dir.writeUInt32LE(e.bmp.length, o + 8); dir.writeUInt32LE(off, o + 12);
  off += e.bmp.length;
});
fs.writeFileSync(path.join(ICONS, 'icon.ico'), Buffer.concat([dir].concat(entries.map(e => e.bmp))));
console.log('wrote icons/icon.ico (' + icoSizes.join(',') + ')');

// Titlebar logo: no card at all — the white wordmark sits straight on the bar,
// rendered at 3x the 21px on-screen height for crisp HiDPI.
const th = 63, tw = Math.round(th * logo.w / logo.h);
const chipPng = encodePNG(resize(logo, tw, th));
fs.writeFileSync(path.join(ICONS, 'titlebar-logo.png'), chipPng);
fs.writeFileSync(process.argv[2] || path.join(ICONS, 'titlebar-logo.b64'), chipPng.toString('base64'));
console.log('titlebar logo: ' + tw + 'x' + th + ', png ' + chipPng.length + ' B, base64 ' + chipPng.toString('base64').length + ' B');
