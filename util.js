/**
 * util.js - small shared helpers with no dependencies on other project modules.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

export const te = enc;
export const td = dec;

/** Current unix time in seconds. */
export function now() {
  return Math.floor(Date.now() / 1000);
}

/** Escape a value for interpolation into HTML text or a quoted attribute. */
export function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function b64urlEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Cryptographically random url-safe id. */
export function randomId(bytes = 24) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64urlEncode(buf);
}

/** Uniformly distributed random integer in [0, max). */
export function randomInt(max) {
  if (max <= 0) throw new RangeError('max must be positive');
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let v;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

export async function sha256Hex(input) {
  const data = typeof input === 'string' ? enc.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Parse a boolean-ish env value. Unset falls back to `fallback`. */
export function boolEnv(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'on', 'enabled'].includes(String(value).trim().toLowerCase());
}

/** Parse an integer env value, clamped, with a fallback. */
export function intEnv(value, fallback, min = -Infinity, max = Infinity) {
  const n = Number.parseInt(String(value ?? '').trim(), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/** Split a comma/space/semicolon separated list into trimmed lowercase entries. */
export function listEnv(value, fallback = []) {
  if (value === undefined || value === null || value === '') return [...fallback];
  return String(value)
    .split(/[,;\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/** Stable, human friendly timestamp for the UI. */
export function fmtTime(unix) {
  if (!unix) return '—';
  return new Date(unix * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}
