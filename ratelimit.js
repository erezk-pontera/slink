/**
 * ratelimit.js - KV-backed counters.
 *
 * KV offers no compare-and-swap, so a burst spread across colocations can
 * overshoot a limit. These counters are therefore a throttle, not a hard
 * guarantee: the real brute-force defences are Turnstile on every sign-in
 * surface, a per-challenge attempt counter stored with the OTP itself, and a
 * short OTP lifetime. Limits are set low enough that overshoot is harmless.
 */

import { sha256Hex } from './util.js';

/** Hash identifiers before they become KV keys so raw IPs are not stored. */
export async function bucketId(parts) {
  return (await sha256Hex(parts.filter(Boolean).join('|'))).slice(0, 32);
}

/**
 * Consume one unit from a bucket. Returns
 * { allowed, count, limit, retryAfter }.
 */
export async function consume(cfg, name, identity, limit, windowSeconds) {
  const id = await bucketId([name, identity]);
  const rec = await cfg.store.bump(name + ':' + id, windowSeconds);
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    allowed: rec.n <= limit,
    count: rec.n,
    limit,
    retryAfter: Math.max(1, rec.reset - nowSec),
  };
}

/** Clear a bucket, used after a successful sign-in. */
export async function clear(cfg, name, identity) {
  const id = await bucketId([name, identity]);
  return cfg.store.reset(name + ':' + id);
}
