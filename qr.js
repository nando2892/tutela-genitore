// QR Code encoder (0.15) for the pairing code: byte mode, versions 1-40, levels L/M/Q/H, automatic mask.
// Same algorithm and tables as QrCode.java in the Android apps (checked by tools/crosscheck: identical modules).
// No library, no network: the QR is drawn as an inline SVG.

const ECC = { L: { i: 0, bits: 1 }, M: { i: 1, bits: 0 }, Q: { i: 2, bits: 3 }, H: { i: 3, bits: 2 } };
const ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]];
const NUM_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]];

function rawDataModules(v) {
  let r = (16 * v + 128) * v + 64;
  if (v >= 2) { const n = Math.floor(v / 7) + 2; r -= (25 * n - 10) * n - 55; if (v >= 7) r -= 36; }
  return r;
}
const dataCodewords = (v, e) => Math.floor(rawDataModules(v) / 8) - ECC_PER_BLOCK[e.i][v] * NUM_BLOCKS[e.i][v];

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) { z = ((z << 1) ^ ((z >>> 7) * 0x11D)) & 0xFF; z ^= ((y >>> i) & 1) * x; }
  return z;
}
function rsDivisor(degree) {
  const r = new Uint8Array(degree); r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) { r[j] = gfMul(r[j], root); if (j + 1 < degree) r[j] ^= r[j + 1]; }
    root = gfMul(root, 2);
  }
  return r;
}
function rsRemainder(data, div) {
  const r = new Uint8Array(div.length);
  for (const b of data) {
    const f = b ^ r[0];
    r.copyWithin(0, 1); r[r.length - 1] = 0;
    for (let i = 0; i < r.length; i++) r[i] ^= gfMul(div[i], f);
  }
  return r;
}
function alignmentPositions(v) {
  if (v === 1) return [];
  const n = Math.floor(v / 7) + 2, size = v * 4 + 17;
  const step = Math.floor((v * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
  const r = new Array(n); r[0] = 6;
  for (let i = n - 1, pos = size - 7; i >= 1; i--, pos -= step) r[i] = pos;
  return r;
}
function formatBits(e, mask) {
  const data = e.bits << 3 | mask; let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return (data << 10 | rem) ^ 0x5412;
}
function versionBits(v) {
  let rem = v;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
  return v << 12 | rem;
}
function maskBit(m, x, y) {
  switch (m) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return x * y % 2 + x * y % 3 === 0;
    case 6: return (x * y % 2 + x * y % 3) % 2 === 0;
    default: return ((x + y) % 2 + x * y % 3) % 2 === 0;
  }
}

function build(v, e, bytes) {
  const size = v * 4 + 17;
  const mod = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, d) => { mod[y][x] = d; fn[y][x] = true; };
  const bit = (x, i) => ((x >>> i) & 1) !== 0;
  const drawFormat = m => {
    const b = formatBits(e, m);
    for (let i = 0; i <= 5; i++) set(8, i, bit(b, i));
    set(8, 7, bit(b, 6)); set(8, 8, bit(b, 7)); set(7, 8, bit(b, 8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(b, i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(b, i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(b, i));
    set(8, size - 8, true);
  };
  // function patterns
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const d = Math.max(Math.abs(dx), Math.abs(dy)), x = cx + dx, y = cy + dy;
      if (x >= 0 && y >= 0 && x < size && y < size) set(x, y, d !== 2 && d !== 4);
    }
  }
  const pos = alignmentPositions(v), n = pos.length;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
    if (i === 0 && j === 0 || i === 0 && j === n - 1 || i === n - 1 && j === 0) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  drawFormat(0);
  if (v >= 7) {
    const b = versionBits(v);
    for (let i = 0; i < 18; i++) { const d = bit(b, i), a = size - 11 + i % 3, c = Math.floor(i / 3); set(a, c, d); set(c, a, d); }
  }
  // data codewords
  const capacity = dataCodewords(v, e) * 8;
  const bits = [];
  const append = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  append(4, 4); append(bytes.length, v <= 9 ? 8 : 16);
  for (const b of bytes) append(b, 8);
  append(0, Math.min(4, capacity - bits.length));
  append(0, (8 - bits.length % 8) % 8);
  for (let pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) append(pad, 8);
  const data = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i++) data[i >>> 3] |= bits[i] << (7 - (i & 7));
  // ECC + interleave
  const numBlocks = NUM_BLOCKS[e.i][v], eccLen = ECC_PER_BLOCK[e.i][v];
  const raw = Math.floor(rawDataModules(v) / 8), numShort = numBlocks - raw % numBlocks, shortLen = Math.floor(raw / numBlocks);
  const div = rsDivisor(eccLen), blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const block = new Uint8Array(shortLen + 1);
    block.set(dat);
    block.set(rsRemainder(dat, div), shortLen + 1 - eccLen);
    blocks.push(block);
  }
  const cw = [];
  for (let i = 0; i < shortLen + 1; i++) for (let j = 0; j < numBlocks; j++) if (i !== shortLen - eccLen || j >= numShort) cw.push(blocks[j][i]);
  // zigzag placement
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? size - 1 - vert : vert;
      if (fn[y][x]) continue;
      if (i < cw.length * 8) mod[y][x] = ((cw[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
      i++;
    }
  }
  const applyMask = m => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && maskBit(m, x, y)) mod[y][x] = !mod[y][x]; };
  let best = 0, min = Infinity;
  for (let m = 0; m < 8; m++) {
    applyMask(m); drawFormat(m);
    const p = penalty(mod, size);
    if (p < min) { min = p; best = m; }
    applyMask(m);
  }
  applyMask(best); drawFormat(best);
  return { version: v, ecc: e === ECC.L ? 'L' : e === ECC.M ? 'M' : e === ECC.Q ? 'Q' : 'H', mask: best, size, dark: (x, y) => x >= 0 && y >= 0 && x < size && y < size && mod[y][x] };
}

const FL = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1], FR = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
function penalty(mod, size) {
  let p = 0;
  const at = (pass, a, b) => pass === 0 ? mod[a][b] : mod[b][a];
  for (let pass = 0; pass < 2; pass++) for (let a = 0; a < size; a++) {
    let run = 0, last = false;
    for (let b = 0; b < size; b++) {
      const c = at(pass, a, b);
      if (b > 0 && c === last) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
      else { run = 1; last = c; }
    }
    for (let b = 0; b + 11 <= size; b++) {
      let l = true, r = true;
      for (let i = 0; i < 11; i++) { const c = at(pass, a, b + i) ? 1 : 0; if (c !== FL[i]) l = false; if (c !== FR[i]) r = false; }
      if (l || r) p += 40;
    }
  }
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
    const c = mod[y][x];
    if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) p += 3;
  }
  let dark = 0;
  for (const row of mod) for (const c of row) if (c) dark++;
  const total = size * size, k = Math.floor((Math.abs(dark * 20 - total * 10) + total - 1) / total) - 1;
  if (k > 0) p += k * 10;
  return p;
}

/** Smallest QR for the text (UTF-8), at least level `min`, raised for free when it still fits. */
export function encode(text, min = 'M') {
  const bytes = new TextEncoder().encode(text);
  const order = ['L', 'M', 'Q', 'H'];
  for (let v = 1; v <= 40; v++) {
    const need = 4 + (v <= 9 ? 8 : 16) + bytes.length * 8;
    if (need > dataCodewords(v, ECC[min]) * 8) continue;
    let e = min;
    for (const better of order.slice(order.indexOf(min) + 1)) if (need <= dataCodewords(v, ECC[better]) * 8) e = better;
    return build(v, ECC[e], bytes);
  }
  throw new Error('Testo troppo lungo per un QR');
}

/** Text picture ('#' dark, '.' light), same as QrCode.ascii() in Java: used by the cross check. */
export function ascii(q) {
  let s = '';
  for (let y = 0; y < q.size; y++) { for (let x = 0; x < q.size; x++) s += q.dark(x, y) ? '#' : '.'; s += '\n'; }
  return s;
}

/** SVG markup (one path, 4-module quiet zone). Only fixed characters: safe to insert as markup. */
export function svg(q) {
  let d = '';
  for (let y = 0; y < q.size; y++) for (let x = 0; x < q.size; x++) if (q.dark(x, y)) d += `M${x + 4} ${y + 4}h1v1h-1z`;
  const n = q.size + 8;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="QR del codice di abbinamento"><rect width="${n}" height="${n}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}
