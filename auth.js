/**
 * auth.js - sessions, the one-time-code sign-in flow, cross-host SSO and
 * sign-out.
 *
 * Sessions are server-side records in KV keyed by the SHA-256 of a random
 * session id; the cookie carries only the id, so a KV dump yields nothing
 * replayable. Cookies use the `__Host-` prefix, which forces Secure, Path=/
 * and no Domain attribute, so a sibling host cannot plant one.
 *
 * Each host holds its own session. A host that requires authentication but is
 * not the hub bounces the visitor through a signed, nonce-bound handshake on
 * the hub, so a user signs in once and is known on every host.
 */

import { audit, EVENTS } from './audit.js';
import { authDomainsFor } from './domains.js';
import { clientIp, geoCheck, geoMessage } from './geo.js';
import { K } from './kv.js';
import { sendOtpEmail } from './mailer.js';
import {
  createChallenge,
  deleteChallenge,
  getChallenge,
  resendChallenge,
  VERIFY,
  verifyChallenge,
  verifyMessage,
} from './otp.js';
import { domainAllowed, normalizeEmail, ValidationError } from './paths.js';
import * as rl from './ratelimit.js';
import {
  clearCookie,
  csrfToken,
  csrfValid,
  originCheck,
  parseCookies,
  serializeCookie,
  signToken,
  verifyToken,
} from './security.js';
import { turnstileVerifyOrFail } from './turnstile.js';
import { findOrCreateUser, getUserById, isAdmin, putUser } from './users.js';
import { now, randomId, sha256Hex } from './util.js';

export const COOKIE = {
  session: '__Host-slink_sess',
  login: '__Host-slink_login',
  csrf: '__Host-slink_csrf',
  sso: '__Host-slink_sso',
};

/** Only same-origin absolute paths may be used as a post-login destination. */
export function safeNext(value, fallback = '/admin') {
  const raw = String(value || '');
  if (!raw.startsWith('/')) return fallback;
  if (raw.startsWith('//') || raw.startsWith('/\\')) return fallback;
  if (/[\r\n]/.test(raw)) return fallback;
  if (raw.length > 512) return fallback;
  return raw;
}

/* ----------------------------------------------------------------- session */

export async function createSession(cfg, { user, host, request }) {
  const sid = randomId(32);
  const sidHash = await sha256Hex(sid);
  const ip = clientIp(request);
  const ttl = cfg.sessionTtl;
  const ts = now();
  const record = {
    userId: user.id,
    emailNorm: user.emailNorm,
    host,
    createdAt: ts,
    expiresAt: ts + ttl,
    lastSeenAt: ts,
    ipHash: ip ? (await sha256Hex(ip)).slice(0, 32) : null,
    uaHash: (await sha256Hex(request.headers.get('User-Agent') || '')).slice(0, 32),
    country: (request.cf && request.cf.country) || null,
  };
  await cfg.store.put(K.session(sidHash), record, { ttl });
  await cfg.store.put(K.userSession(user.id, sidHash), { host, expiresAt: record.expiresAt }, { ttl });
  return {
    sid,
    record,
    cookie: serializeCookie(COOKIE.session, sid, { maxAge: ttl, sameSite: 'Lax' }),
  };
}

/** Resolve the signed-in user for this host, or null. */
export async function readSession(cfg, request, host) {
  const cookies = parseCookies(request);
  const sid = cookies[COOKIE.session];
  if (!sid || sid.length > 128) return null;
  const sidHash = await sha256Hex(sid);
  const record = await cfg.store.get(K.session(sidHash));
  if (!record) return null;

  const ts = now();
  if (record.expiresAt <= ts) {
    await destroySession(cfg, sidHash, record.userId);
    return null;
  }
  if (record.host !== host) return null;

  const idle = cfg.settings.sessionIdleSeconds || 0;
  if (idle > 0 && record.lastSeenAt && ts - record.lastSeenAt > idle) {
    await destroySession(cfg, sidHash, record.userId);
    return null;
  }
  if (cfg.settings.bindSessionToUa) {
    const ua = (await sha256Hex(request.headers.get('User-Agent') || '')).slice(0, 32);
    if (record.uaHash && record.uaHash !== ua) return null;
  }
  if (cfg.settings.bindSessionToIp) {
    const ip = clientIp(request);
    const ipHash = ip ? (await sha256Hex(ip)).slice(0, 32) : null;
    if (record.ipHash && ipHash && record.ipHash !== ipHash) return null;
  }

  const user = await getUserById(cfg, record.userId);
  if (!user || user.disabled) return null;

  // Touch at most once a minute; KV tolerates about one write per second per key.
  let touched = null;
  if (ts - (record.lastSeenAt || 0) > 60) {
    record.lastSeenAt = ts;
    touched = cfg.store.put(K.session(sidHash), record, { ttl: Math.max(60, record.expiresAt - ts) });
  }

  user.isAdminEffective = isAdmin(cfg, user);
  return { sid, sidHash, record, user, touched };
}

export async function destroySession(cfg, sidHash, userId) {
  await cfg.store.delete(K.session(sidHash));
  if (userId) await cfg.store.delete(K.userSession(userId, sidHash));
}

/** Revoke every session a user holds, on every host. */
export async function destroyAllSessions(cfg, userId) {
  const keys = await cfg.store.listAll(K.userSessionPrefix(userId), { max: 500 });
  const prefix = K.userSessionPrefix(userId);
  for (const key of keys) {
    await cfg.store.delete(K.session(key.name.slice(prefix.length)));
    await cfg.store.delete(key.name);
  }
  return keys.length;
}

/* -------------------------------------------------------------- CSRF glue */

/**
 * The value a CSRF token is bound to: the session when there is one, and the
 * browser-held nonce cookie before sign-in.
 */
export function csrfBinding(ctx) {
  if (ctx.session) return 's:' + ctx.session.sidHash;
  return 'n:' + ctx.csrfNonce;
}

export async function tokenFor(ctx, form) {
  return csrfToken(ctx.cfg.authSecret, csrfBinding(ctx), form);
}

/**
 * Validate a state-changing request: same origin, and a CSRF token minted for
 * this browser and this form.
 */
export async function checkCsrf(ctx, form, body) {
  const bad = originCheck(ctx.request, ctx.origin);
  if (bad) return { ok: false, reason: bad };
  const ok = await csrfValid(ctx.cfg.authSecret, csrfBinding(ctx), form, body.get('_csrf'));
  return ok ? { ok: true } : { ok: false, reason: 'csrf-invalid' };
}

/** Ensure the browser carries a CSRF nonce cookie. */
export function csrfCookie(ctx) {
  if (ctx.csrfNonceIsNew) {
    return serializeCookie(COOKIE.csrf, ctx.csrfNonce, { maxAge: 3600, sameSite: 'Lax' });
  }
  return null;
}

/* ------------------------------------------------------------ sign-in flow */

/** Is this address allowed to authenticate on this host? */
export function mayAuthenticate(cfg, domain, emailNorm) {
  const emailDomain = emailNorm.slice(emailNorm.lastIndexOf('@') + 1);
  const allowed = authDomainsFor(cfg, domain);
  if (!allowed || allowed.length === 0) return false;
  return domainAllowed(emailDomain, allowed);
}

/**
 * Step one: accept an address, mint a challenge and email the code.
 * Returns { ok, error, cookies, next } - never reveals whether the address
 * already has an account.
 */
export async function beginLogin(ctx, body) {
  const { cfg, request, host } = ctx;
  const ip = clientIp(request);

  const geo = geoCheck(cfg, request, 'login');
  if (!geo.allowed) {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginBlocked,
        host,
        ip,
        outcome: 'blocked',
        detail: { reason: geo.reason, country: geo.geo.country },
      })
    );
    return { ok: false, error: geoMessage(geo.reason) };
  }

  const turn = await turnstileVerifyOrFail(ctx, body, 'login');
  if (!turn.ok) return { ok: false, error: turn.error };

  let parsed;
  try {
    parsed = normalizeEmail(body.get('email'), cfg.emailOpts);
  } catch (err) {
    if (err instanceof ValidationError) return { ok: false, error: err.message };
    throw err;
  }

  const limits = cfg.settings.rateLimits;
  const byIp = await rl.consume(cfg, 'otp-ip', ip || 'none', limits.otpRequestPerIp, limits.otpWindowSeconds);
  const byEmail = await rl.consume(
    cfg,
    'otp-email',
    parsed.emailNorm,
    limits.otpRequestPerEmail,
    limits.otpWindowSeconds
  );
  if (!byIp.allowed || !byEmail.allowed) {
    ctx.waitUntil(
      audit(cfg, { event: EVENTS.loginBlocked, host, ip, outcome: 'ratelimited', detail: { email: parsed.emailNorm } })
    );
    return { ok: false, error: 'Too many sign-in attempts. Try again later.' };
  }

  if (!mayAuthenticate(cfg, ctx.domain, parsed.emailNorm)) {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginFailed,
        host,
        ip,
        outcome: 'denied',
        detail: { email: parsed.emailNorm, reason: 'domain-not-allowed' },
      })
    );
    return { ok: false, error: 'That email address is not permitted to sign in here.' };
  }

  const next = safeNext(body.get('next'), '/admin');
  const challenge = await createChallenge(cfg, {
    email: parsed.email,
    emailNorm: parsed.emailNorm,
    host,
    next,
    ip,
    geo: geo.geo,
  });

  try {
    await sendOtpEmail(cfg, {
      to: parsed.email,
      code: challenge.code,
      host,
      ip,
      country: geo.geo.country,
    });
  } catch (err) {
    await deleteChallenge(cfg, challenge.loginId);
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginFailed,
        host,
        ip,
        outcome: 'mail-error',
        detail: { email: parsed.emailNorm, error: String(err && err.message).slice(0, 300) },
      })
    );
    return {
      ok: false,
      error: 'We could not send the code. Contact an administrator if this continues.',
    };
  }

  ctx.waitUntil(
    audit(cfg, { event: EVENTS.loginRequested, host, ip, detail: { email: parsed.emailNorm } })
  );

  return {
    ok: true,
    cookies: [
      serializeCookie(COOKIE.login, challenge.loginId, {
        maxAge: (cfg.settings.otpTtlSeconds || 600) + 300,
        sameSite: 'Lax',
      }),
    ],
  };
}

/** Step two: check the submitted code and open a session. */
export async function completeLogin(ctx, body) {
  const { cfg, request, host } = ctx;
  const ip = clientIp(request);
  const cookies = parseCookies(request);
  const loginId = cookies[COOKIE.login];

  if (!loginId) {
    return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };
  }

  const turn = await turnstileVerifyOrFail(ctx, body, 'otp');
  if (!turn.ok) return { ok: false, error: turn.error };

  const limits = cfg.settings.rateLimits;
  const guard = await rl.consume(cfg, 'otp-verify', loginId, limits.otpVerifyPerLogin, limits.otpWindowSeconds);
  if (!guard.allowed) {
    await deleteChallenge(cfg, loginId);
    return { ok: false, error: 'Too many attempts. Request a new code.', restart: true };
  }

  const result = await verifyChallenge(cfg, loginId, body.get('code'));
  if (result.status !== VERIFY.ok) {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginFailed,
        host,
        ip,
        outcome: result.status,
        detail: { email: result.record ? result.record.emailNorm : null },
      })
    );
    return {
      ok: false,
      error: verifyMessage(result.status, result.remaining),
      restart: [VERIFY.unknown, VERIFY.expired, VERIFY.locked, VERIFY.consumed].includes(result.status),
    };
  }

  // The challenge is spent; remove it so the code cannot be reused at all.
  await deleteChallenge(cfg, loginId);

  const { user } = await findOrCreateUser(cfg, result.record.email);
  if (user.disabled) {
    return { ok: false, error: 'This account is disabled.', restart: true };
  }

  user.lastLoginAt = now();
  user.loginCount = (user.loginCount || 0) + 1;
  await putUser(cfg, user);

  const session = await createSession(cfg, { user, host, request });
  await rl.clear(cfg, 'otp-email', user.emailNorm);

  ctx.waitUntil(audit(cfg, { event: EVENTS.loginSucceeded, actor: user, host, ip }));

  return {
    ok: true,
    user,
    next: safeNext(result.record.next, '/admin'),
    cookies: [session.cookie, clearCookie(COOKIE.login), clearCookie(COOKIE.csrf)],
  };
}

/** Re-send a code for the challenge the browser already holds. */
export async function resendLogin(ctx) {
  const { cfg, request, host } = ctx;
  const cookies = parseCookies(request);
  const loginId = cookies[COOKIE.login];
  if (!loginId) return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };

  const record = await getChallenge(cfg, loginId);
  if (!record) return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };

  const issued = await resendChallenge(cfg, loginId, record);
  if (!issued) return { ok: false, error: 'Please wait a moment before requesting another code.' };

  try {
    await sendOtpEmail(cfg, {
      to: record.email,
      code: issued.code,
      host,
      ip: clientIp(request),
      country: record.country,
    });
  } catch {
    return { ok: false, error: 'We could not send the code. Try again shortly.' };
  }
  return { ok: true, info: 'A new code is on its way.' };
}

/** Sign out: revoke this session, and every other session the user holds. */
export async function signOut(ctx, { everywhere = true } = {}) {
  const { cfg, host } = ctx;
  if (!ctx.session) return { cookies: [clearCookie(COOKIE.session)] };
  const { sidHash, user } = ctx.session;
  if (everywhere) await destroyAllSessions(cfg, user.id);
  else await destroySession(cfg, sidHash, user.id);
  ctx.waitUntil(
    audit(cfg, { event: EVENTS.logout, actor: user, host, ip: clientIp(ctx.request), detail: { everywhere } })
  );
  return {
    cookies: [clearCookie(COOKIE.session), clearCookie(COOKIE.login), clearCookie(COOKIE.csrf)],
  };
}

/* ----------------------------------------------------------------- SSO */

const SSO_TTL = 120;

/** On a non-hub host: start the handshake and remember a nonce. */
export function ssoStart(ctx, returnPath) {
  const nonce = randomId(18);
  const target = new URL('https://' + ctx.cfg.hubHost + '/sso/authorize');
  target.searchParams.set('h', ctx.host);
  target.searchParams.set('r', safeNext(returnPath, '/'));
  target.searchParams.set('n', nonce);
  return {
    location: target.toString(),
    cookie: serializeCookie(COOKIE.sso, nonce, { maxAge: SSO_TTL, sameSite: 'Lax' }),
  };
}

/** On the hub: mint a short-lived token for the target host. */
export async function ssoAuthorize(ctx, { targetHost, returnPath, nonce }) {
  if (!ctx.session) return { ok: false, reason: 'no-session' };
  if (!targetHost || !ctx.cfg.knownHosts.includes(targetHost)) {
    return { ok: false, reason: 'unknown-host' };
  }
  const token = await signToken(ctx.cfg.authSecret, 'sso', {
    sub: ctx.session.user.id,
    aud: targetHost,
    r: safeNext(returnPath, '/'),
    n: String(nonce || ''),
    iat: now(),
    exp: now() + SSO_TTL,
  });
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.ssoIssued,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      detail: { target: targetHost },
    })
  );
  const url = new URL('https://' + targetHost + '/__slink/sso/callback');
  url.searchParams.set('t', token);
  return { ok: true, location: url.toString() };
}

/** On the target host: accept the token and open a local session. */
export async function ssoCallback(ctx, token) {
  const { cfg, request, host } = ctx;
  const payload = await verifyToken(cfg.authSecret, 'sso', token, { maxAgeSeconds: SSO_TTL });
  if (!payload) return { ok: false, error: 'This sign-in link is invalid or has expired.' };
  if (payload.aud !== host) return { ok: false, error: 'This sign-in link was issued for another site.' };

  const cookies = parseCookies(request);
  const nonce = cookies[COOKIE.sso];
  if (!nonce || nonce !== payload.n) {
    return { ok: false, error: 'This sign-in link is invalid or has expired.' };
  }

  const user = await getUserById(cfg, payload.sub);
  if (!user || user.disabled) return { ok: false, error: 'This account cannot sign in here.' };
  if (!mayAuthenticate(cfg, ctx.domain, user.emailNorm)) {
    return { ok: false, error: 'That account is not permitted to sign in here.' };
  }

  const session = await createSession(cfg, { user, host, request });
  ctx.waitUntil(
    audit(cfg, { event: EVENTS.ssoAccepted, actor: user, host, ip: clientIp(request) })
  );
  return {
    ok: true,
    next: safeNext(payload.r, '/'),
    cookies: [session.cookie, clearCookie(COOKIE.sso)],
  };
}
