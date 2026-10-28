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
  RESEND,
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
import {
  authorizeUrl,
  exchangeCode,
  fetchEmail,
  methodsFor,
  oauthReady,
  pkcePair,
  STATE_TTL_SECONDS,
} from './oauth.js';
import { turnstileVerifyOrFail } from './turnstile.js';
import {
  findOrCreateUser,
  getUserById,
  getUserByNorm,
  isAdmin,
  isRootAdmin,
  putUser,
} from './users.js';
import { now, randomId, sha256Hex } from './util.js';

export const COOKIE = {
  session: '__Host-slink_sess',
  login: '__Host-slink_login',
  csrf: '__Host-slink_csrf',
  sso: '__Host-slink_sso',
  oauth: '__Host-slink_oauth',
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
/**
 * Is this address an administrator? Used before anyone is signed in, so it
 * has to go to the record rather than to a session. A root administrator
 * counts even with no account yet, which is what makes a first sign-in on a
 * host with the code switched off possible at all.
 */
export async function isAdminAddress(cfg, emailNorm) {
  if (isRootAdmin(cfg, emailNorm)) return true;
  const user = await getUserByNorm(cfg, emailNorm);
  return !!(user && !user.disabled && isAdmin(cfg, user));
}

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

  // Where the host has switched the emailed code off, it stays available to
  // administrators and to nobody else. The page cannot know who is asking
  // before they type an address, so the rule is enforced here, where it can.
  // A refusal is silent for the same reason the rest of this flow is: saying
  // "not an administrator" would turn the sign-in form into a way of asking
  // who the administrators are.
  if (!methodsFor(cfg, ctx.domain, { isAdmin: await isAdminAddress(cfg, parsed.emailNorm) }).otp) {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginBlocked,
        host,
        ip,
        outcome: 'denied',
        detail: { email: parsed.emailNorm, reason: 'otp-disabled-on-domain' },
      })
    );
    return { ok: true, cookies: [] };
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
    // Same reasoning as the Turnstile path: if delivery is broken nobody can
    // sign in, so the reason must be visible in `wrangler tail`. The address
    // is left out; the provider's message is what an operator needs.
    console.error('sign-in email failed:', String(err && err.message).slice(0, 300));
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
export async function resendLogin(ctx, body) {
  const { cfg, request, host } = ctx;
  const cookies = parseCookies(request);
  const loginId = cookies[COOKIE.login];
  if (!loginId) return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };

  // A resend sends mail, so it is a challenge of its own rather than a
  // free button: without this, the page is a way to have us email somebody
  // repeatedly on request.
  const turn = await turnstileVerifyOrFail(ctx, body, 'resend');
  if (!turn.ok) return { ok: false, error: turn.error };

  const record = await getChallenge(cfg, loginId);
  if (!record) return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };

  const issued = await resendChallenge(cfg, loginId, record);
  if (issued.status === RESEND.expired || issued.status === RESEND.lost) {
    return { ok: false, error: 'Your sign-in session has expired. Start again.', restart: true };
  }
  if (issued.status === RESEND.tooSoon) {
    return { ok: false, error: 'Please wait a moment before requesting the code again.' };
  }
  if (issued.status === RESEND.tooMany) {
    return { ok: false, error: 'That code has been sent several times already. Start again.' };
  }

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
  // Deliberately the same code: one already in transit stays valid.
  return { ok: true, info: 'We have sent the same code again. It is still the one to use.' };
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

/* ------------------------------------------- external identity provider */

/**
 * Begin an authorization-code exchange.
 *
 * The state and the PKCE verifier travel in a signed cookie rather than in
 * storage, so an abandoned attempt costs nothing and expires by itself. The
 * cookie is `__Host-`, SameSite=Lax and short lived, so the callback can only
 * be completed by the browser that started it.
 */
export async function oauthBegin(ctx, returnPath) {
  const { cfg, domain, origin } = ctx;
  if (!oauthReady(cfg, domain)) return { ok: false, error: 'Single sign-on is not configured here.' };

  const state = randomId(18);
  const { verifier, challenge } = await pkcePair();
  const token = await signToken(cfg.authSecret, 'oauth-state', {
    s: state,
    v: verifier,
    r: safeNext(returnPath, '/admin'),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
  });

  return {
    ok: true,
    location: authorizeUrl(domain, { origin, state, challenge }),
    cookie: serializeCookie(COOKIE.oauth, token, {
      maxAge: STATE_TTL_SECONDS,
      sameSite: 'Lax',
    }),
  };
}

/**
 * Complete the exchange and sign the person in.
 *
 * The provider establishes an address and nothing more: the host's
 * allowed-domain list still decides whether that address may sign in, and a
 * disabled account is still refused.
 */
export async function oauthComplete(ctx, { code, state }) {
  const { cfg, domain, host, request, origin } = ctx;
  const ip = clientIp(request);
  const fail = (error) => ({ ok: false, error, cookies: [clearCookie(COOKIE.oauth)] });

  if (!oauthReady(cfg, domain)) return fail('Single sign-on is not configured here.');

  const cookies = parseCookies(request);
  const payload = await verifyToken(cfg.authSecret, 'oauth-state', cookies[COOKIE.oauth], {
    maxAgeSeconds: STATE_TTL_SECONDS,
  });
  if (!payload) return fail('That sign-in took too long. Please try again.');
  // Constant-time is unnecessary here: both values are random and single
  // use, and a mismatch reveals nothing about either.
  if (!state || state !== payload.s) return fail('That sign-in could not be verified.');
  if (!code) return fail('The identity provider did not return a code.');

  const token = await exchangeCode(cfg, domain, { code, verifier: payload.v, origin });
  if (!token.ok) return fail(token.error);

  const profile = await fetchEmail(domain, token.accessToken);
  if (!profile.ok) return fail(profile.error);

  let parsed;
  try {
    parsed = normalizeEmail(profile.email, cfg.emailOpts);
  } catch {
    return fail('The identity provider supplied an address we cannot use.');
  }

  if (!mayAuthenticate(cfg, domain, parsed.emailNorm)) {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginBlocked,
        host,
        ip,
        detail: { via: 'oauth', reason: 'domain-not-allowed' },
        outcome: 'denied',
      })
    );
    return fail('That address may not sign in to this domain.');
  }

  const { user } = await findOrCreateUser(cfg, parsed.email);
  if (!user || user.disabled) {
    ctx.waitUntil(
      audit(cfg, { event: EVENTS.loginBlocked, actor: user, host, ip, detail: { via: 'oauth' }, outcome: 'denied' })
    );
    return fail('That account is disabled.');
  }

  user.lastLoginAt = now();
  user.loginCount = (user.loginCount || 0) + 1;
  await putUser(cfg, user);

  const session = await createSession(cfg, { user, host, request });
  ctx.waitUntil(
    audit(cfg, { event: EVENTS.loginSucceeded, actor: user, host, ip, detail: { via: 'oauth' } })
  );

  return {
    ok: true,
    user,
    next: safeNext(payload.r, '/admin'),
    cookies: [session.cookie, clearCookie(COOKIE.oauth), clearCookie(COOKIE.csrf)],
  };
}

/** On a non-hub host: start the handshake and remember a nonce. */
export function ssoStart(ctx, returnPath, { quiet = false } = {}) {
  const nonce = randomId(18);
  const target = new URL('https://' + ctx.cfg.hubHost + '/sso/authorize');
  target.searchParams.set('h', ctx.host);
  target.searchParams.set('r', safeNext(returnPath, '/'));
  target.searchParams.set('n', nonce);
  // A quiet handshake is one started on the visitor's behalf rather than
  // because they asked to sign in. If they have no session on the hub, they
  // are sent back where they came from instead of being shown a sign-in
  // page for a link they may simply have been handed.
  if (quiet) target.searchParams.set('q', '1');
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
