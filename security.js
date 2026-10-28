/**
 * security.js - crypto primitives, cookies, CSRF and response hardening.
 *
 * Every signed value in the app (sessions, SSO tokens, CSRF tokens, OTP hashes)
 * is derived from AUTH_SECRET through a labelled HKDF-ish sub-key so that a
 * token minted for one purpose can never be replayed as another.
 */

import { b64urlDecode, b64urlEncode, isSafeKey, randomId, te } from './util.js';

/**
 * Derived keys are cached because deriving one on every signature would be
 * wasteful on a hot path.
 *
 * The cache is keyed by the secret as well as the purpose. Keying it by
 * purpose alone looked harmless - an installation only ever has one secret
 * - but a Workers isolate outlives a deployment, so after AUTH_SECRET was
 * rotated the isolate went on signing and verifying with the key derived
 * from the *old* one until it happened to recycle. A rotation is usually a
 * response to a leak, and that made it quietly do nothing.
 */
const keyCache = new Map();

/** Keep the cache bounded; there are only a few purposes and one secret. */
const MAX_CACHED_KEYS = 64;

/** Import a purpose-scoped HMAC key derived from the master secret. */
async function hmacKey(secret, purpose) {
  const cacheKey = purpose + '\u0000' + secret;
  const cached = keyCache.get(cacheKey);
  if (cached) return cached;
  const master = await crypto.subtle.importKey(
    'raw',
    te.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const derived = await crypto.subtle.sign('HMAC', master, te.encode('slink/v1/' + purpose));
  const key = await crypto.subtle.importKey(
    'raw',
    derived,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  if (keyCache.size >= MAX_CACHED_KEYS) keyCache.clear();
  keyCache.set(cacheKey, key);
  return key;
}

/** Raw HMAC-SHA256 over `message`, returned base64url. */
export async function hmac(secret, purpose, message) {
  const key = await hmacKey(secret, purpose);
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(message));
  return b64urlEncode(new Uint8Array(sig));
}

/** Constant-time string comparison. */
export function timingSafeEqualStr(a, b) {
  const ab = te.encode(String(a ?? ''));
  const bb = te.encode(String(b ?? ''));
  if (ab.byteLength !== bb.byteLength) {
    // Still burn a comparison so length leaks nothing beyond the length itself.
    try {
      crypto.subtle.timingSafeEqual(ab, ab);
    } catch {
      /* not available locally */
    }
    return false;
  }
  if (crypto.subtle && typeof crypto.subtle.timingSafeEqual === 'function') {
    return crypto.subtle.timingSafeEqual(ab, bb);
  }
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/** Sign an arbitrary payload object into a compact `body.sig` token. */
export async function signToken(secret, purpose, payload) {
  const body = b64urlEncode(te.encode(JSON.stringify(payload)));
  const sig = await hmac(secret, purpose, body);
  return body + '.' + sig;
}

/** Verify and decode a token produced by signToken. Returns null when invalid. */
export async function verifyToken(secret, purpose, token, { maxAgeSeconds } = {}) {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmac(secret, purpose, body);
  if (!timingSafeEqualStr(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
  } catch {
    return null;
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && payload.exp < nowSec) return null;
  if (maxAgeSeconds && typeof payload.iat === 'number' && payload.iat + maxAgeSeconds < nowSec) {
    return null;
  }
  return payload;
}

/* ------------------------------------------------------------------ cookies */

/** Parse a Cookie header into a plain object. */
export function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const out = Object.create(null);
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      if (isSafeKey(name)) out[name] = decodeURIComponent(value);
    } catch {
      if (isSafeKey(name)) out[name] = value;
    }
  }
  return out;
}

/**
 * Serialize a cookie. Defaults are the hardened set: Host-prefixed cookies are
 * Secure, Path=/ and carry no Domain, so they cannot be injected by a sibling
 * subdomain.
 */
/**
 * The content security policy for a page whose whole job is to show one
 * other site in a frame. Everything stays locked down except `frame-src`,
 * which is narrowed to that single origin rather than opened to the web.
 */
export function frameCsp(target) {
  let origin = "'none'";
  try {
    origin = new URL(target).origin;
  } catch {
    origin = "'none'";
  }
  return [
    "default-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    `frame-src ${origin}`,
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
  ].join('; ');
}

/** Attach Set-Cookie headers to a response without rebuilding it by hand. */
export function withCookies(response, cookies) {
  const list = (cookies || []).filter(Boolean);
  if (list.length === 0) return response;
  const out = new Response(response.body, response);
  for (const cookie of list) out.headers.append('Set-Cookie', cookie);
  return out;
}

export function serializeCookie(name, value, opts = {}) {
  const { maxAge, sameSite = 'Lax', httpOnly = true, secure = true, path = '/' } = opts;
  let out = name + '=' + encodeURIComponent(value);
  out += '; Path=' + path;
  if (maxAge !== undefined) out += '; Max-Age=' + Math.max(0, Math.floor(maxAge));
  if (httpOnly) out += '; HttpOnly';
  if (secure) out += '; Secure';
  if (sameSite) out += '; SameSite=' + sameSite;
  return out;
}

/** Expire a cookie immediately. */
export function clearCookie(name, opts = {}) {
  return serializeCookie(name, '', { ...opts, maxAge: 0 });
}

/* --------------------------------------------------------------------- CSRF */

/**
 * CSRF uses a signed double-submit token bound to a browser-held nonce cookie
 * (and to the session id once one exists), plus a strict Origin check. The
 * token is scoped by `form` so a token minted for one action cannot be
 * replayed against another.
 */
export async function csrfToken(secret, binding, form) {
  return hmac(secret, 'csrf', (binding || '-') + '|' + (form || '-'));
}

export async function csrfValid(secret, binding, form, submitted) {
  if (!submitted) return false;
  const expected = await csrfToken(secret, binding, form);
  return timingSafeEqualStr(submitted, expected);
}

/** The value a browser must echo back; created fresh when absent. */
export function csrfNonce(cookies, cookieName) {
  return cookies[cookieName] || randomId(18);
}

/**
 * Reject cross-origin state changes. Returns null when the request is fine, or
 * a reason string when it must be refused.
 *
 * A header that is present must match. A header that is absent is not treated
 * as an attack: several browsers omit `Origin` on a same-origin form post,
 * and privacy extensions and corporate proxies strip both headers, so
 * refusing on absence locks real people out of every form.
 *
 * What actually stops cross-site requests here does not depend on these
 * headers. The CSRF token is an HMAC over a value held in an HttpOnly cookie
 * (or the session id), so an attacker can neither read the input nor compute
 * the token, and every cookie is SameSite=Lax, which keeps the browser from
 * attaching them to a cross-site POST at all. The header check is a third
 * layer on top of those two, and is applied whenever the evidence exists.
 */
export function originCheck(request, expectedOrigin) {
  const origin = request.headers.get('Origin');
  if (origin) {
    // An opaque origin arrives as the literal "null" and never matches.
    return origin === expectedOrigin ? null : 'origin-mismatch';
  }
  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === expectedOrigin ? null : 'referer-mismatch';
    } catch {
      return 'bad-referer';
    }
  }
  return null;
}

/* ---------------------------------------------------------------- responses */

/**
 * Apply the standard security headers.
 *
 * The CSP is strict where it matters: no inline script at all. Every script
 * and stylesheet this app serves is a same-origin asset, and page-specific
 * values reach the client through `data-` attributes rather than an inline
 * script block, so `script-src` needs neither 'unsafe-inline' nor a nonce.
 *
 * `style-src` does allow 'unsafe-inline' because the Turnstile widget sets
 * inline styles on the container it injects. All HTML this app emits is
 * escaped, so there is no path by which a user-supplied value becomes a style
 * attribute; the real injection risk, script execution, stays locked down.
 */
export function harden(
  response,
  { turnstile = false, store = false, referrerPolicy = 'same-origin', externalImages = false } = {}
) {
  const h = response.headers;
  h.set('X-Content-Type-Options', 'nosniff');
  // 'same-origin' keeps the referrer off every cross-origin request while
  // still sending it within the site, which is what lets originCheck fall
  // back to Referer when a browser omits Origin. Redirect responses pass
  // 'no-referrer' so a destination never learns which shortcut was followed.
  h.set('Referrer-Policy', referrerPolicy);
  h.set('X-Frame-Options', 'DENY');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
  h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  // Everything is denied outright except the two WebAuthn features, which
  // are allowed to this origin alone: the hub needs them to register and
  // use a passkey, and `self` still refuses to delegate them to an embedded
  // cross-origin page, which is what the directive is really guarding.
  h.set(
    'Permissions-Policy',
    'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), ' +
      'fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), ' +
      'midi=(), payment=(), publickey-credentials-create=(self), publickey-credentials-get=(self), ' +
      'screen-wake-lock=(), usb=(), xr-spatial-tracking=()'
  );
  if (!store) h.set('Cache-Control', 'no-store, max-age=0');
  h.set('X-Robots-Tag', 'noindex, nofollow, noarchive');

  const CF = 'https://challenges.cloudflare.com';
  h.set(
    'Content-Security-Policy',
    [
      `default-src 'none'`,
      `base-uri 'none'`,
      `form-action 'self'`,
      `frame-ancestors 'none'`,
      `script-src 'self'` + (turnstile ? ' ' + CF : ''),
      `style-src 'self' 'unsafe-inline'`,
      // The link editor renders the card's image, which is an arbitrary
      // https URL by nature. Images cannot execute, and this is not relaxed
      // anywhere else.
      externalImages ? `img-src 'self' data: https:` : `img-src 'self' data:`,
      `font-src 'self'`,
      `connect-src 'self'` + (turnstile ? ' ' + CF : ''),
      `frame-src ` + (turnstile ? CF : `'none'`),
      `object-src 'none'`,
      `manifest-src 'none'`,
      `upgrade-insecure-requests`,
    ].join('; ')
  );
  return response;
}
