/**
 * linkpass.js - a password in front of a link.
 *
 * The password is stored encrypted rather than hashed, because the person
 * who set it has to be able to read it back: they are going to tell someone
 * what it is, and a shared link password nobody can recover is a link
 * nobody can use. Encryption at rest still means a dump of the KV namespace
 * alone does not reveal it — see crypt.js.
 *
 * A correct answer mints a short-lived signed token naming that one link
 * and that one browser. It is a cookie scoped to the link's path, so
 * unlocking one link does not unlock another.
 */

import { open, seal } from './crypt.js';
import { signToken, timingSafeEqualStr, verifyToken } from './security.js';
import { sha256Hex } from './util.js';

export const PURPOSE = 'link-password';
export const COOKIE_PREFIX = '__Host-slink_lp_';

/** How long an unlocked link stays unlocked in that browser. */
export const UNLOCK_TTL_SECONDS = 3600;

export const MAX_PASSWORD = 128;

/**
 * The fragment that carries a password in a shared link:
 * `https://host/shortcut#ptrap=secret`.
 *
 * A fragment is never sent to the server — the worker sees `/shortcut` and
 * nothing more. That is why this is handled in the page rather than here,
 * and it is also the reason to prefer a fragment over a query string: the
 * password never reaches a server log, a Referer header or an upstream
 * proxy. The page reads it, clears it from the address bar before doing
 * anything else, and submits it the way a person typing it would.
 */
/** The parameter name a link password travels under, in the fragment. */
export const PASSWORD_PARAM = 'ptrap';
export const HASH_PREFIX = PASSWORD_PARAM + '=';

/**
 * Pull the password out of a location fragment, or '' when there is none.
 * Accepts the fragment with or without its leading `#`, and tolerates it
 * sitting among other `&`-separated parts.
 */
export function passwordFromHash(hash) {
  const raw = String(hash || '').replace(/^#/, '');
  if (!raw) return '';
  for (const part of raw.split('&')) {
    if (!part.startsWith(HASH_PREFIX)) continue;
    const value = part.slice(HASH_PREFIX.length);
    try {
      return decodeURIComponent(value.replace(/\+/g, ' '));
    } catch {
      // A fragment that is not valid percent-encoding is taken literally
      // rather than thrown away: the password may simply contain a '%'.
      return value;
    }
  }
  return '';
}

/** The link to share when the password should travel with it. */
export function shareableUrl(host, path, password) {
  return 'https://' + host + '/' + path + '#' + HASH_PREFIX + encodeURIComponent(password);
}

/** Is a password actually set on this link? */
export function hasPassword(link) {
  return !!(link && typeof link.password === 'string' && link.password.length > 0);
}

/** Store a password on a link, or clear it when given nothing. */
export async function setPassword(cfg, link, raw) {
  const value = String(raw === null || raw === undefined ? '' : raw);
  if (!value) {
    link.password = '';
    return { ok: true, cleared: true };
  }
  if (value.length > MAX_PASSWORD) {
    return { ok: false, error: 'That password is too long.' };
  }
  // A password made only of spaces is a password nobody can type reliably.
  if (!value.trim()) return { ok: false, error: 'That password is only whitespace.' };
  link.password = await seal(cfg.authSecret, PURPOSE, value);
  return { ok: true, cleared: false };
}

/** Read the password back, for the people allowed to see it. */
export async function readPassword(cfg, link) {
  if (!hasPassword(link)) return '';
  return open(cfg.authSecret, PURPOSE, link.password);
}

/** Does `submitted` match? Compared in constant time. */
export async function passwordMatches(cfg, link, submitted) {
  const expected = await readPassword(cfg, link);
  if (!expected) return false;
  const a = await sha256Hex(expected);
  const b = await sha256Hex(String(submitted === null || submitted === undefined ? '' : submitted));
  return timingSafeEqualStr(a, b);
}

/**
 * The cookie name for one link. The path is hashed into it so the name
 * itself cannot be used to enumerate shortcuts out of a cookie jar, and so
 * it stays a legal cookie name whatever the shortcut contains.
 */
export async function cookieName(host, pathLc) {
  return COOKIE_PREFIX + (await sha256Hex(host + ':' + pathLc)).slice(0, 24);
}

/**
 * Mint the token that records this browser answered correctly. It names the
 * link and the password currently set, so changing the password turns every
 * outstanding unlock into a prompt again.
 */
export async function mintUnlock(cfg, link) {
  const iat = Math.floor(Date.now() / 1000);
  return signToken(cfg.authSecret, PURPOSE, {
    h: link.host,
    p: link.pathLc,
    v: (await sha256Hex(link.password)).slice(0, 16),
    iat,
    exp: iat + UNLOCK_TTL_SECONDS,
  });
}

/** Has this browser already answered for this link? */
export async function isUnlocked(cfg, link, token) {
  if (!token) return false;
  const payload = await verifyToken(cfg.authSecret, PURPOSE, token, {
    maxAgeSeconds: UNLOCK_TTL_SECONDS,
  });
  if (!payload) return false;
  if (payload.h !== link.host || payload.p !== link.pathLc) return false;
  return payload.v === (await sha256Hex(link.password)).slice(0, 16);
}
