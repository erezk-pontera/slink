/**
 * otp.js - the six-digit sign-in code.
 *
 * The code is never stored. What is stored is an HMAC of the code bound to a
 * per-challenge salt and to the login id held in the browser's cookie, so a
 * code is only usable in the browser session that requested it and a dump of
 * the KV namespace does not yield usable codes.
 */

import { K } from './kv.js';
import { hmac, timingSafeEqualStr } from './security.js';
import { now, randomId, randomInt, sha256Hex } from './util.js';

/** A uniformly random numeric code of `length` digits. */
export function generateCode(length = 6) {
  let out = '';
  for (let i = 0; i < length; i++) out += String(randomInt(10));
  return out;
}

async function hashCode(cfg, { loginId, salt, code }) {
  return hmac(cfg.authSecret, 'otp', [loginId, salt, code].join('|'));
}

/**
 * Create and store a challenge. Returns { loginId, code, record } - the
 * plaintext code is returned once so it can be emailed, and is not persisted.
 */
export async function createChallenge(cfg, { email, emailNorm, host, next, ip, geo }) {
  const loginId = randomId(24);
  const salt = randomId(12);
  const length = cfg.settings.otpLength || 6;
  const code = generateCode(length);
  const ttl = cfg.settings.otpTtlSeconds || 600;
  const ts = now();

  const record = {
    emailNorm,
    email,
    host,
    next: next || '/admin',
    salt,
    codeHash: await hashCode(cfg, { loginId, salt, code }),
    createdAt: ts,
    expiresAt: ts + ttl,
    attempts: 0,
    maxAttempts: cfg.settings.otpMaxAttempts || 5,
    consumed: false,
    resentAt: 0,
    resendCount: 0,
    ipHash: ip ? (await sha256Hex(ip)).slice(0, 32) : null,
    country: geo ? geo.country : null,
  };

  // The KV record outlives the code slightly so an expired attempt reports
  // "expired" rather than "unknown challenge".
  await cfg.store.put(K.otp(loginId), record, { ttl: ttl + 300 });
  return { loginId, code, record };
}

export async function getChallenge(cfg, loginId) {
  if (!loginId || typeof loginId !== 'string' || loginId.length > 64) return null;
  return cfg.store.get(K.otp(loginId));
}

export async function putChallenge(cfg, loginId, record) {
  const ttl = Math.max(60, record.expiresAt - now() + 300);
  await cfg.store.put(K.otp(loginId), record, { ttl });
}

export async function deleteChallenge(cfg, loginId) {
  await cfg.store.delete(K.otp(loginId));
}

/**
 * Issue a fresh code for an existing challenge, keeping the same loginId so
 * the browser cookie stays valid. Returns null when a resend is too soon.
 */
export async function resendChallenge(cfg, loginId, record) {
  const minGap = cfg.settings.otpResendSeconds || 45;
  const ts = now();
  if (record.resentAt && ts - record.resentAt < minGap) return null;
  if (record.resendCount >= 5) return null;

  const salt = randomId(12);
  const code = generateCode(cfg.settings.otpLength || 6);
  const ttl = cfg.settings.otpTtlSeconds || 600;
  record.salt = salt;
  record.codeHash = await hashCode(cfg, { loginId, salt, code });
  record.expiresAt = ts + ttl;
  record.attempts = 0;
  record.consumed = false;
  record.resentAt = ts;
  record.resendCount = (record.resendCount || 0) + 1;
  await putChallenge(cfg, loginId, record);
  return { code, record };
}

export const VERIFY = {
  ok: 'ok',
  unknown: 'unknown',
  expired: 'expired',
  consumed: 'consumed',
  locked: 'locked',
  mismatch: 'mismatch',
};

/**
 * Check a submitted code. The attempt is recorded before the comparison, so a
 * crash or a dropped write cannot hand an attacker a free guess.
 */
export async function verifyChallenge(cfg, loginId, submitted) {
  const record = await getChallenge(cfg, loginId);
  if (!record) return { status: VERIFY.unknown, record: null };
  if (record.consumed) return { status: VERIFY.consumed, record };
  if (record.expiresAt <= now()) return { status: VERIFY.expired, record };
  if (record.attempts >= record.maxAttempts) return { status: VERIFY.locked, record };

  record.attempts += 1;
  await putChallenge(cfg, loginId, record);

  const clean = String(submitted ?? '').replace(/\D+/g, '');
  if (!clean) return { status: VERIFY.mismatch, record };

  const candidate = await hashCode(cfg, { loginId, salt: record.salt, code: clean });
  if (!timingSafeEqualStr(candidate, record.codeHash)) {
    const remaining = Math.max(0, record.maxAttempts - record.attempts);
    return { status: remaining === 0 ? VERIFY.locked : VERIFY.mismatch, record, remaining };
  }

  record.consumed = true;
  await putChallenge(cfg, loginId, record);
  return { status: VERIFY.ok, record };
}

/** Message shown for each failure mode; never reveals whether a code existed. */
export function verifyMessage(status, remaining) {
  switch (status) {
    case VERIFY.expired:
      return 'That code has expired. Request a new one.';
    case VERIFY.consumed:
      return 'That code has already been used. Request a new one.';
    case VERIFY.locked:
      return 'Too many incorrect attempts. Request a new code.';
    case VERIFY.unknown:
      return 'Your sign-in session has expired. Start again.';
    default:
      return remaining > 0
        ? `That code is not correct. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
        : 'That code is not correct.';
  }
}
