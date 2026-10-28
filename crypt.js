/**
 * crypt.js - reversible encryption at rest for the few values that have to
 * be readable again.
 *
 * Almost everything secret here is hashed, which is right when the only
 * question is "does this match". Two things are different: a one-time code
 * has to be re-sent as-is if someone asks for it again, and a link password
 * has to be shown to the person who set it, because they have to tell
 * somebody what it is.
 *
 * Those are stored encrypted rather than in the clear, so a dump of the KV
 * namespace on its own reveals neither. The key is derived from AUTH_SECRET,
 * which lives outside KV, so reading them needs both.
 *
 * AES-GCM with a random 96-bit nonce per value. The purpose string is bound
 * in as additional data, so a sealed login code cannot be swapped into a
 * field that expects a sealed password.
 */

import { b64urlDecode, b64urlEncode, te } from './util.js';

/**
 * Derived keys are cached because HKDF on every call would be wasteful on a
 * hot path. The cache is keyed by the secret as well as the purpose: an
 * installation only ever has one secret, but a test process runs several,
 * and a cache that ignored it would hand back the wrong key.
 */
const keyCache = new Map();

async function keyFor(secret, purpose) {
  const cacheKey = purpose + '\u0000' + secret;
  if (keyCache.has(cacheKey)) return keyCache.get(cacheKey);
  const base = await crypto.subtle.importKey('raw', te.encode(secret), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('slink-crypt'), info: te.encode(purpose) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  keyCache.set(cacheKey, key);
  return key;
}

/** Encrypt `value`, returning a compact string safe to store in JSON. */
export async function seal(secret, purpose, value) {
  if (value === null || value === undefined || value === '') return '';
  const key = await keyFor(secret, purpose);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: te.encode(purpose) },
    key,
    te.encode(String(value))
  );
  return b64urlEncode(nonce) + '.' + b64urlEncode(new Uint8Array(cipher));
}

/** Decrypt a value produced by seal. Returns '' for anything unreadable. */
export async function open(secret, purpose, sealed) {
  if (typeof sealed !== 'string' || !sealed) return '';
  const dot = sealed.indexOf('.');
  if (dot <= 0) return '';
  try {
    const nonce = b64urlDecode(sealed.slice(0, dot));
    const cipher = b64urlDecode(sealed.slice(dot + 1));
    const key = await keyFor(secret, purpose);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: te.encode(purpose) },
      key,
      cipher
    );
    return new TextDecoder().decode(plain);
  } catch {
    // A wrong key, a tampered value or one sealed for another purpose all
    // land here. None of them is recoverable, and none should throw into
    // the request.
    return '';
  }
}
