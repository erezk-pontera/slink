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
    ...overrides,
  };
}

/**
 * Hostnames an identity provider is never legitimately on.
 *
 * These endpoints are fetched by the Worker with the client secret attached,
 * so a wrong one is a way to send that secret somewhere it should not go.
 * Only an administrator can set them, which makes this defence in depth
 * rather than a boundary — and it is only a literal check: a public name
 * that resolves to a private address still gets through, because a Worker
 * cannot resolve a name and pin the result before fetching it.
 */
export function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.internal') || h.endsWith('.local')) return true;

  // IPv4 literals, including the ranges a metadata service tends to sit on.
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 127 || a === 0 || a === 10) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  // IPv6 loopback, unspecified, unique-local and link-local.
  if (h === '::1' || h === '::') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(h)) return true;
  return false;
}

export function normalizeOauth(raw) {
  const o = raw && typeof raw === 'object' ? raw : {};
  const url = (v) => {
    const s = String(v || '').trim();
    if (!s) return '';
    try {
      const parsed = new URL(s);
      // An endpoint reached over anything but HTTPS would leak the code.
      if (parsed.protocol !== 'https:') return '';
      if (isPrivateHost(parsed.hostname)) return '';
      return parsed.toString();
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
  });
}

/** Is the provider configured well enough to be offered? */
/**
 * The provider, which is one setting for the whole installation.
 *
 * Signing in is not a per-domain thing: it happens on the hub and the
 * other hosts come through the handshake, so a provider configured on one
 * domain and not another was a distinction without a difference.
 */
export function oauthSettings(cfg) {
  return normalizeOauth(cfg && cfg.settings && cfg.settings.oauth);
}

export function oauthReady(cfg) {
  const o = oauthSettings(cfg);
  if (!o.enabled) return false;
  if (!o.clientId || !o.authorizeUrl || !o.tokenUrl || !o.userinfoUrl) return false;
  return !!(cfg.oauthSecret && String(cfg.oauthSecret).length);
}

/**
 * The sign-in routes this installation switches off.
 *
 * One setting for the whole installation, which is what it always
 * effectively was: signing in happens on the hub and every other host hands
 * it there, so only the hub's copy of the old per-domain list ever decided
 * anything. Until the settings screen is saved once, that copy is still what
 * is read - `domain` here is the host being signed in to - so moving the
 * control changes where it is edited and not what it currently says.
 */
export function disabledMethodsFor(cfg, domain) {
  const chosen = cfg && cfg.settings && cfg.settings.disabledMethodsSet;
  const raw = chosen ? cfg.settings.disabledMethods : domain && domain.disabledMethods;
  return normalizeDisabledMethods(raw);
}

/**
 * Which sign-in methods this installation offers to this person.
 *
 * It may switch off the one-time code, the passkey, or both, once single
 * sign-on is working. That never applies to an administrator: taking away
 * every other route would mean an outage at the identity provider locks the
 * people who could fix it out of their own hub.
 */
export function methodsFor(cfg, domain, { isAdmin = false } = {}) {
  const sso = oauthReady(cfg);
  const disabled = new Set(sso && !isAdmin ? disabledMethodsFor(cfg, domain) : []);
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
export function authorizeUrl(cfg, { origin, state, challenge }) {
  const o = oauthSettings(cfg);
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
export async function exchangeCode(cfg, { code, verifier, origin }) {
  const o = oauthSettings(cfg);
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
export async function fetchEmail(cfg, accessToken) {
  const o = oauthSettings(cfg);
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
  // The provider's own verification flag is not consulted. Letting somebody
  // through its sign-in is the provider saying who they are; it says
  // nothing about what they may do here, which this service decides on its
  // own from the allowed sign-in domains and the account's record. Every
  // account created this way is an ordinary one.
  return { ok: true, email };
}
