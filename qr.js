/**
 * qr.js - a QR Code generator, byte mode, versions 1-40, no dependencies.
 *
 * Implements ISO/IEC 18004: Reed-Solomon error correction over GF(256) with
 * the primitive polynomial 0x11D, the eight data masks, and the BCH-coded
 * format and version information.
 *
 * The error-correction level doubles as the durability knob: a higher level
 * survives more damage, and is what makes a centre logo safe, because the
 * logo is simply damage the code can already absorb.
 */

/** L 7%, M 15%, Q 25%, H 30% of codewords recoverable. */
export const ECC_LEVELS = ['L', 'M', 'Q', 'H'];
const ECC_BITS = { L: 1, M: 0, Q: 3, H: 2 };

/** Total codewords per version, 1-40. */
const TOTAL_CODEWORDS = [
  26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
  1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611, 2761, 2876, 3034,
  3196, 3362, 3532, 3706,
];

/**
 * Per version and level: [ecCodewordsPerBlock, group1Blocks, group2Blocks].
 * Group 2 blocks hold one more data codeword than group 1.
 */
const ECC_TABLE = {
  L: [
    [7,1,0],[10,1,0],[15,1,0],[20,1,0],[26,1,0],[18,2,0],[20,2,0],[24,2,0],[30,2,0],[18,2,2],
    [20,4,0],[24,2,2],[26,4,0],[30,3,1],[22,5,1],[24,5,1],[28,1,5],[30,5,1],[28,3,4],[28,3,5],
    [28,4,4],[28,2,7],[30,4,5],[30,6,4],[26,8,4],[28,10,2],[30,8,4],[30,3,10],[30,7,7],[30,5,10],
    [30,13,3],[30,17,0],[30,17,1],[30,13,6],[30,12,7],[30,6,14],[30,17,4],[30,4,18],[30,20,4],[30,19,6],
  ],
  M: [
    [10,1,0],[16,1,0],[26,1,0],[18,2,0],[24,2,0],[16,4,0],[18,4,0],[22,2,2],[22,3,2],[26,4,1],
    [30,1,4],[22,6,2],[22,8,1],[24,4,5],[24,5,5],[28,7,3],[28,10,1],[26,9,4],[26,3,11],[26,3,13],
    [26,17,0],[28,17,0],[28,4,14],[28,6,14],[28,8,13],[28,19,4],[28,22,3],[28,3,23],[28,21,7],[28,19,10],
    [28,2,29],[28,10,23],[28,14,21],[28,14,23],[28,12,26],[28,6,34],[28,29,14],[28,13,32],[28,40,7],[28,18,31],
  ],
  Q: [
    [13,1,0],[22,1,0],[18,2,0],[26,2,0],[18,2,2],[24,4,0],[18,2,4],[22,4,2],[20,4,4],[24,6,2],
    [28,4,4],[26,4,6],[24,8,4],[20,11,5],[30,5,7],[24,15,2],[28,1,15],[28,17,1],[26,17,4],[30,15,5],
    [28,17,6],[30,7,16],[30,11,14],[30,11,16],[30,7,22],[28,28,6],[30,8,26],[30,4,31],[30,1,37],[30,15,25],
    [30,42,1],[30,10,35],[30,29,19],[30,44,7],[30,39,14],[30,46,10],[30,49,10],[30,48,14],[30,43,22],[30,34,34],
  ],
  H: [
    [17,1,0],[28,1,0],[22,2,0],[16,4,0],[22,2,2],[28,4,0],[26,4,1],[26,4,2],[24,4,4],[28,6,2],
    [24,3,8],[28,7,4],[22,12,4],[24,11,5],[24,11,7],[30,3,13],[28,2,17],[28,2,19],[26,9,16],[28,15,10],
    [30,19,6],[24,34,0],[30,16,14],[30,30,2],[30,22,13],[30,33,4],[30,12,28],[30,11,31],[30,19,26],[30,23,25],
    [30,23,28],[30,19,35],[30,11,46],[30,59,1],[30,22,41],[30,2,64],[30,24,46],[30,42,32],[30,10,67],[30,20,61],
  ],
};

/** Row/column centres of the alignment patterns, by version. */
const ALIGNMENT = [
  [], [], [6,18], [6,22], [6,26], [6,30], [6,34], [6,22,38], [6,24,42], [6,26,46], [6,28,50],
  [6,30,54], [6,32,58], [6,34,62], [6,26,46,66], [6,26,48,70], [6,26,50,74], [6,30,54,78],
  [6,30,56,82], [6,30,58,86], [6,34,62,90], [6,28,50,72,94], [6,26,50,74,98], [6,30,54,78,102],
  [6,28,54,80,106], [6,32,58,84,110], [6,30,58,86,114], [6,34,62,90,118], [6,26,50,74,98,122],
  [6,30,54,78,102,126], [6,26,52,78,104,130], [6,30,56,82,108,134], [6,34,60,86,112,138],
  [6,30,58,86,114,142], [6,34,62,90,118,146], [6,30,54,78,102,126,150], [6,24,50,76,102,128,154],
  [6,28,54,80,106,132,158], [6,32,58,84,110,136,162], [6,26,54,82,110,138,166], [6,30,58,86,114,142,170],
];

/* ------------------------------------------------------------- GF(256) */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/** The generator polynomial for `degree` error-correction codewords. */
function generatorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

/** Remainder of `data` divided by the generator polynomial: the EC codewords. */
export function reedSolomon(data, ecLength) {
  const gen = generatorPoly(ecLength);
  const out = new Array(ecLength).fill(0);
  for (const byte of data) {
    const factor = byte ^ out[0];
    out.shift();
    out.push(0);
    for (let i = 0; i < ecLength; i++) out[i] ^= gfMul(gen[i + 1], factor);
  }
  return out;
}

/* ---------------------------------------------------------- bit stream */

class BitBuffer {
  constructor() {
    this.bits = [];
  }
  put(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  get length() {
    return this.bits.length;
  }
  toBytes() {
    const out = [];
    for (let i = 0; i < this.bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | (this.bits[i + j] || 0);
      out.push(byte);
    }
    return out;
  }
}

/** Data codewords available at this version and level, before EC. */
function dataCapacity(version, level) {
  const [ecPerBlock, g1, g2] = ECC_TABLE[level][version - 1];
  return TOTAL_CODEWORDS[version - 1] - ecPerBlock * (g1 + g2);
}

/** Bits used by the character-count field in byte mode. */
function countBits(version) {
  return version < 10 ? 8 : 16;
}

/** The smallest version that holds `byteLength` bytes at this level. */
function pickVersion(byteLength, level, minVersion = 1) {
  for (let v = Math.max(1, minVersion); v <= 40; v++) {
    const needed = 4 + countBits(v) + byteLength * 8;
    if (needed <= dataCapacity(v, level) * 8) return v;
  }
  return null;
}

/** Encode the payload into the full codeword sequence, interleaved. */
function buildCodewords(bytes, version, level) {
  const capacity = dataCapacity(version, level);
  const buf = new BitBuffer();
  buf.put(0b0100, 4);                       // byte mode
  buf.put(bytes.length, countBits(version));
  for (const b of bytes) buf.put(b, 8);

  // Terminator, then pad to a byte boundary, then the alternating pad bytes.
  const limit = capacity * 8;
  buf.put(0, Math.min(4, limit - buf.length));
  while (buf.length % 8 !== 0) buf.bits.push(0);
  const data = buf.toBytes();
  for (let i = 0; data.length < capacity; i++) data.push(i % 2 === 0 ? 0xec : 0x11);

  const [ecPerBlock, g1, g2] = ECC_TABLE[level][version - 1];
  const blocks = g1 + g2;
  const shortLen = Math.floor(capacity / blocks);

  const dataBlocks = [];
  const ecBlocks = [];
  let at = 0;
  for (let i = 0; i < blocks; i++) {
    const len = i < g1 ? shortLen : shortLen + 1;
    const block = data.slice(at, at + len);
    at += len;
    dataBlocks.push(block);
    ecBlocks.push(reedSolomon(block, ecPerBlock));
  }

  // Interleave: one codeword from each block in turn, data then EC.
  const out = [];
  const longest = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < longest; i++) {
    for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const block of ecBlocks) out.push(block[i]);
  }
  return out;
}

/* ------------------------------------------------------------- matrix */

function emptyMatrix(size) {
  return Array.from({ length: size }, () => new Array(size).fill(null));
}

function placeFinder(m, row, col) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || cc < 0 || rr >= m.length || cc >= m.length) continue;
      const inRing = r >= 0 && r <= 6 && c >= 0 && c <= 6;
      const edge = r === 0 || r === 6 || c === 0 || c === 6;
      const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      m[rr][cc] = inRing && (edge || core) ? 1 : 0;
    }
  }
}

function placeAlignment(m, version) {
  const centres = ALIGNMENT[version];
  for (const r of centres) {
    for (const c of centres) {
      // Not over the three finder patterns.
      if (m[r][c] !== null) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const ring = Math.max(Math.abs(dr), Math.abs(dc));
          m[r + dr][c + dc] = ring === 1 ? 0 : 1;
        }
      }
    }
  }
}

function placeTiming(m) {
  for (let i = 8; i < m.length - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0;
    if (m[6][i] === null) m[6][i] = bit;
    if (m[i][6] === null) m[i][6] = bit;
  }
}

/** Cells reserved for format and version information, filled in later. */
function reserve(m, version) {
  const size = m.length;
  for (let i = 0; i < 9; i++) {
    if (m[8][i] === null) m[8][i] = 0;
    if (m[i][8] === null) m[i][8] = 0;
  }
  for (let i = 0; i < 8; i++) {
    if (m[8][size - 1 - i] === null) m[8][size - 1 - i] = 0;
    if (m[size - 1 - i][8] === null) m[size - 1 - i][8] = 0;
  }
  m[size - 8][8] = 1; // the always-dark module
  if (version >= 7) {
    for (let i = 0; i < 6; i++) {
      for (let j = 0; j < 3; j++) {
        m[size - 11 + j][i] = 0;
        m[i][size - 11 + j] = 0;
      }
    }
  }
}

/** Walk the data region bottom-right to top-left in two-column strips. */
function placeData(m, codewords) {
  const size = m.length;
  let bit = 0;
  const total = codewords.length * 8;
  const next = () => {
    if (bit >= total) return 0;
    const v = (codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1;
    bit++;
    return v;
  };

  let upward = true;
  for (let right = size - 1; right > 0; right -= 2) {
    if (right === 6) right = 5; // the vertical timing column is skipped
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (let c = 0; c < 2; c++) {
        const col = right - c;
        if (m[row][col] !== null) continue;
        m[row][col] = next();
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

/** BCH(15,5) format information, with the 0x5412 mask applied. */
function formatBits(level, mask) {
  const data = (ECC_BITS[level] << 3) | mask;
  let rem = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >>> i) & 1) rem ^= 0x537 << (i - 10);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

/** BCH(18,6) version information, versions 7 and up. */
function versionBits(version) {
  let rem = version << 12;
  for (let i = 17; i >= 12; i--) {
    if ((rem >>> i) & 1) rem ^= 0x1f25 << (i - 12);
  }
  return (version << 12) | rem;
}

/**
 * Write both copies of the format information.
 *
 * Bit 0 is the least significant. The first copy runs down the column beside
 * the top-left finder, skipping the timing row; the second runs right to left
 * along row 8 from the far edge, so the two copies read in opposite
 * directions and either one alone is enough to recover the format.
 */
function applyFormat(m, level, mask) {
  const size = m.length;
  const bits = formatBits(level, mask);
  const at = (i) => (bits >>> i) & 1;

  for (let i = 0; i < 15; i++) {
    const bit = at(i);
    if (i < 6) m[i][8] = bit;
    else if (i < 8) m[i + 1][8] = bit;
    else m[size - 15 + i][8] = bit;
  }
  for (let i = 0; i < 15; i++) {
    const bit = at(i);
    if (i < 8) m[8][size - 1 - i] = bit;
    else if (i === 8) m[8][7] = bit;
    else m[8][14 - i] = bit;
  }
  m[size - 8][8] = 1;
}

function applyVersion(m, version) {
  if (version < 7) return;
  const size = m.length;
  const bits = versionBits(version);
  for (let i = 0; i < 18; i++) {
    const bit = (bits >>> i) & 1;
    const r = Math.floor(i / 3);
    const c = i % 3;
    m[size - 11 + c][r] = bit;
    m[r][size - 11 + c] = bit;
  }
}

/** The penalty score from the specification, used to choose the mask. */
function penalty(m) {
  const size = m.length;
  let score = 0;

  // Rule 1: runs of five or more of the same colour.
  for (let i = 0; i < size; i++) {
    for (const line of [m[i], m.map((row) => row[i])]) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        if (line[j] === line[j - 1]) {
          run++;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) score += 3;
    }
  }

  // Rule 3: the finder-like 1:1:3:1:1 pattern with four light modules.
  const a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const b = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const matches = (line, at, pat) => pat.every((v, k) => line[at + k] === v);
  for (let i = 0; i < size; i++) {
    const row = m[i];
    const col = m.map((r) => r[i]);
    for (const line of [row, col]) {
      for (let j = 0; j + 11 <= size; j++) {
        if (matches(line, j, a) || matches(line, j, b)) score += 40;
      }
    }
  }

  // Rule 4: deviation from an even balance of dark and light.
  let dark = 0;
  for (const row of m) for (const v of row) if (v) dark++;
  const ratio = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(ratio - 50) / 5) * 10;
  return score;
}

/**
 * Build the module matrix for `text`.
 *
 * Returns { size, modules, version, level } where `modules` is an array of
 * rows of 0 and 1. The mask is chosen by the specification's penalty score.
 */
export function encode(text, { level = 'M', minVersion = 1 } = {}) {
  const lvl = ECC_LEVELS.includes(level) ? level : 'M';
  const bytes = Array.from(new TextEncoder().encode(String(text)));
  const version = pickVersion(bytes.length, lvl, minVersion);
  if (!version) throw new Error('Too much data for a QR code at this error-correction level.');

  const codewords = buildCodewords(bytes, version, lvl);
  const size = version * 4 + 17;

  // The function patterns are identical for every mask, so they are laid out
  // once and each candidate works on a copy.
  const base = emptyMatrix(size);
  placeFinder(base, 0, 0);
  placeFinder(base, 0, size - 7);
  placeFinder(base, size - 7, 0);
  placeAlignment(base, version);
  placeTiming(base);
  const functionCells = base.map((row) => row.map((v) => v !== null));
  reserve(base, version);
  const reservedCells = base.map((row) => row.map((v) => v !== null));
  placeData(base, codewords);

  let best = null;
  for (let mask = 0; mask < 8; mask++) {
    const candidate = base.map((row, r) =>
      row.map((v, c) => (reservedCells[r][c] ? v : v ^ (MASKS[mask](r, c) ? 1 : 0)))
    );
    applyFormat(candidate, lvl, mask);
    applyVersion(candidate, version);
    const score = penalty(candidate);
    if (!best || score < best.score) best = { score, modules: candidate, mask };
  }

  return { size, modules: best.modules, version, level: lvl, mask: best.mask, functionCells };
}

/* ---------------------------------------------------------------- SVG */

/**
 * Error correction a centre logo can safely eat, as a fraction of the
 * symbol's area. The published recovery rates are of codewords, not of area,
 * and a decoder needs headroom for ordinary wear on top of the logo, so
 * these sit well under the nominal figures.
 */
export const LOGO_BUDGET = { L: 0.06, M: 0.12, Q: 0.18, H: 0.22 };

/** The smallest level that can carry a logo of this area fraction. */
export function levelForLogo(fraction) {
  for (const level of ECC_LEVELS) {
    if (fraction <= LOGO_BUDGET[level]) return level;
  }
  return 'H';
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

/**
 * Render a QR code as a standalone SVG document.
 *
 * `logo` is an already-inlined SVG fragment or a data: URI. It is never a
 * remote URL: an SVG rendered as an image cannot load external resources, so
 * a remote reference would silently produce a hole in the middle of the code.
 */
export function toSvg(text, options = {}) {
  const {
    size = 512,
    margin = 4,
    dark = '#000000',
    light = '#ffffff',
    logo = null,
    logoScale = 0.2,
    label = '',
  } = options;

  const fraction = logo ? Math.min(0.3, Math.max(0.08, logoScale)) : 0;
  const level = options.level || (logo ? levelForLogo(fraction * fraction) : 'M');
  const qr = encode(text, { level, minVersion: options.minVersion || 1 });

  const quiet = Math.max(0, Math.min(16, margin));
  const span = qr.size + quiet * 2;

  // One path for every dark module keeps the document small and renders
  // crisply at any size, with no gaps between neighbouring modules.
  const parts = [];
  for (let r = 0; r < qr.size; r++) {
    let run = 0;
    for (let c = 0; c <= qr.size; c++) {
      const on = c < qr.size && qr.modules[r][c] === 1;
      if (on) {
        run++;
        continue;
      }
      if (run) {
        parts.push(`M${c - run + quiet} ${r + quiet}h${run}v1h-${run}z`);
        run = 0;
      }
    }
  }

  const centre = span / 2;
  const logoSide = span * fraction;
  const pad = Math.max(0.6, logoSide * 0.08);
  const plate = logoSide + pad * 2;
  const logoMarkup = logo
    ? `<rect x="${(centre - plate / 2).toFixed(3)}" y="${(centre - plate / 2).toFixed(3)}"
      width="${plate.toFixed(3)}" height="${plate.toFixed(3)}" rx="${(plate * 0.12).toFixed(3)}" fill="${esc(light)}"/>
  <g transform="translate(${(centre - logoSide / 2).toFixed(3)} ${(centre - logoSide / 2).toFixed(3)}) scale(${(
        logoSide / 512
      ).toFixed(6)})">${logo}</g>`
    : '';

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${span} ${span}"
     shape-rendering="crispEdges" role="img" aria-label="${esc(label || text)}">
  <rect width="${span}" height="${span}" fill="${esc(light)}"/>
  <path fill="${esc(dark)}" d="${parts.join('')}"/>
  ${logoMarkup}
</svg>`;
}
