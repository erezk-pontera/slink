/**
 * oauth.js - signing in through an external identity provider.
 *
 * Authorization Code with PKCE, which is the flow a confidential web client
 * should use today: the code is useless without the verifier, so a code
 * intercepted in a redirect cannot be redeemed by anyone else.
 *
 * What comes back is only ever used to establish an email address. The
 * provider does not decide who may sign in — the host's allowed-domain list
 * still does, and an address the provider asserts but does not mark verified
 * is refused outright.
 */

import { b64urlEncode, randomId, sha256Bytes } from './util.js';

/** Sign-in methods a host can offer. */
export const METHODS = ['otp', 'passkey', 'oauth'];

/** How long an in-flight authorization may take to come back. */
export const STATE_TTL_SECONDS = 600;

export function defaultOauth(overrides = {}) {
  return {
    enabled: false,
    label: 'Single sign-on',
    clientId: '',
    authorizeUrl: '',
    tokenUrl: '',
    userinfoUrl: '',
    scope: 'openid email profile',
    /** Where in the userinfo response the address lives. */
    emailField: 'email',
    verifiedField: 'email_verified',
    /** Accept an address the provider does not mark as verified. */
    allowUnverified: false,
    ...overrides,
  };
}

export function normalizeOauth(raw) {
  const o = raw && typeof raw === 'object' ? raw : {};
  const url = (v) => {
    const s = String(v || '').trim();
    if (!s) return '';
    try {
      const parsed = new URL(s);
      // An endpoint reached over anything but HTTPS would leak the code.
      return parsed.protocol === 'https:' ? parsed.toString() : '';
    } catch {
      return '';
    }
  };
  return defaultOauth({
    enabled: !!o.enabled,
    label: String(o.label || 'Single sign-on').slice(0, 60),
    clientId: String(o.clientId || '').slice(0, 300),
    authorizeUrl: url(o.authorizeUrl),
    tokenUrl: url(o.tokenUrl),
    userinfoUrl: url(o.userinfoUrl),
    scope: String(o.scope || 'openid email profile').slice(0, 300),
    emailField: String(o.emailField || 'email').slice(0, 60),
    verifiedField: String(o.verifiedField || 'email_verified').slice(0, 60),
    allowUnverified: !!o.allowUnverified,
  });
}

/** Is the provider configured well enough to be offered? */
export function oauthReady(cfg, domain) {
  const o = normalizeOauth(domain && domain.oauth);
  if (!o.enabled) return false;
  if (!o.clientId || !o.authorizeUrl || !o.tokenUrl || !o.userinfoUrl) return false;
  return !!(cfg.oauthSecret && String(cfg.oauthSecret).length);
}

/**
 * Which sign-in methods this host offers to this person.
 *
 * A host may switch off the one-time code, the passkey, or both, once
 * single sign-on is working. That never applies to an administrator: taking
 * away every other route would mean an outage at the identity provider
 * locks the people who could fix it out of their own hub.
 */
export function methodsFor(cfg, domain, { isAdmin = false } = {}) {
  const sso = oauthReady(cfg, domain);
  const disabled = new Set(
    sso && !isAdmin && Array.isArray(domain && domain.disabledMethods)
      ? domain.disabledMethods.filter((m) => m !== 'oauth')
      : []
  );
  return {
    oauth: sso,
    otp: !disabled.has('otp'),
    passkey: !disabled.has('passkey'),
  };
}

/** Normalize the stored list, which may never disable single sign-on itself. */
export function normalizeDisabledMethods(raw) {
  const parts = Array.isArray(raw) ? raw : String(raw || '').split(/[\s,;]+/);
  const out = [];
  for (const part of parts) {
    const v = String(part).trim().toLowerCase();
    if (v && v !== 'oauth' && METHODS.includes(v) && !out.includes(v)) out.push(v);
  }
  return out;
}

/* --------------------------------------------------------------- flow */

/** A PKCE verifier and its S256 challenge. */
export async function pkcePair() {
  const verifier = randomId(43);
  const digest = await sha256Bytes(verifier);
  return { verifier, challenge: b64urlEncode(digest) };
}

export function redirectUri(origin) {
  return origin + '/__slink/oauth/callback';
}

/**
 * The URL to send the browser to. `state` and the verifier are held by the
 * caller in a signed cookie, so nothing about the attempt is stored server
 * side and a stale attempt simply fails to resolve.
 */
export function authorizeUrl(domain, { origin, state, challenge }) {
  const o = normalizeOauth(domain.oauth);
  const url = new URL(o.authorizeUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', o.clientId);
  url.searchParams.set('redirect_uri', redirectUri(origin));
  url.searchParams.set('scope', o.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

/** Exchange the code for an access token. */
export async function exchangeCode(cfg, domain, { code, verifier, origin }) {
  const o = normalizeOauth(domain.oauth);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(origin),
    client_id: o.clientId,
    code_verifier: verifier,
  });
  // The secret goes in the body rather than the URL so it cannot end up in
  // a log line on the provider's side.
  if (cfg.oauthSecret) body.set('client_secret', cfg.oauthSecret);

  const res = await fetch(o.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
  });
  if (!res.ok) return { ok: false, error: 'The identity provider refused the sign-in.' };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ok: false, error: 'The identity provider sent an unreadable reply.' };
  }
  if (!json || !json.access_token) {
    return { ok: false, error: 'The identity provider sent no access token.' };
  }
  return { ok: true, accessToken: String(json.access_token) };
}

/** Read the address the provider holds for this person. */
export async function fetchEmail(domain, accessToken) {
  const o = normalizeOauth(domain.oauth);
  const res = await fetch(o.userinfoUrl, {
    headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/json' },
  });
  if (!res.ok) return { ok: false, error: 'Could not read your profile from the identity provider.' };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ok: false, error: 'The identity provider sent an unreadable profile.' };
  }

  const email = json && json[o.emailField];
  if (!email || typeof email !== 'string') {
    return { ok: false, error: 'The identity provider did not supply an email address.' };
  }
  const verified = json[o.verifiedField];
  // An unverified address is someone's claim, not the provider's. Accepting
  // it would let anyone who can set a profile field take over an account.
  if (!o.allowUnverified && verified !== true && verified !== 'true') {
    return { ok: false, error: 'Your email address is not verified with the identity provider.' };
  }
  return { ok: true, email };
}
