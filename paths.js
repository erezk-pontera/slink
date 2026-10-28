/**
 * paths.js - validation and canonicalisation of the three user-supplied
 * string types: shortcut paths, destinations and email addresses.
 */

/** Shortcuts are A-Za-z0-9_- per segment; comparison is case-insensitive. */
const SEGMENT_RE = /^[A-Za-z0-9_-]+$/;
const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

export const MAX_SEGMENT = 64;
export const MAX_PATH = 255;
export const MAX_SEGMENTS = 8;
export const MAX_DESTINATION = 2048;

/**
 * Schemes that are never allowed as a destination, whatever the configuration
 * says. They execute in the origin of whatever page renders the link, so the
 * delay interstitial would otherwise become a stored-XSS sink.
 */
export const HARD_BLOCKED_SCHEMES = ['javascript', 'data', 'vbscript', 'blob', 'file'];

/** Reserved first segments on the admin host; never usable as a shortcut. */
export const RESERVED_PATHS = [
  'admin',
  'login',
  'logout',
  'sso',
  'health',
  'favicon.ico',
  'robots.txt',
  '__slink',
];

export class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'ValidationError';
    this.field = field || null;
  }
}

/** Strip a leading `www.`, lowercase, drop any port. Apex and www are one host. */
export function canonicalHost(hostHeader) {
  let host = String(hostHeader || '').trim().toLowerCase();
  const colon = host.lastIndexOf(':');
  if (colon > -1 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon);
  if (host.startsWith('www.')) host = host.slice(4);
  return host;
}

/**
 * Validate and canonicalise a shortcut path such as `aaa` or `pub/deck`.
 * Returns { path, pathLc, segments }.
 */
export function parsePath(raw, { reserved = RESERVED_PATHS, allowReserved = false } = {}) {
  let value = String(raw ?? '').trim();
  value = value.replace(/^\/+/, '').replace(/\/+$/, '');
  if (!value) throw new ValidationError('Shortcut is required.', 'path');
  if (value.length > MAX_PATH) throw new ValidationError('Shortcut is too long.', 'path');
  if (value.includes('//')) throw new ValidationError('Shortcut has an empty segment.', 'path');

  const segments = value.split('/');
  if (segments.length > MAX_SEGMENTS) {
    throw new ValidationError('Shortcut has too many segments.', 'path');
  }
  for (const seg of segments) {
    if (!SEGMENT_RE.test(seg)) {
      throw new ValidationError(
        'Shortcut segments may only contain letters, digits, underscore and hyphen.',
        'path'
      );
    }
    if (seg.length > MAX_SEGMENT) throw new ValidationError('Shortcut segment is too long.', 'path');
  }

  // Shortcuts are case-agnostic, so the stored form is the lowercase one and
  // that is what gets displayed too: a shortcut never renders in a case that
  // differs from the one the redirect actually matches on.
  const path = segments.join('/').toLowerCase();
  const pathLc = path;
  if (!allowReserved && reserved.includes(segments[0].toLowerCase())) {
    throw new ValidationError('That name is reserved.', 'path');
  }
  return { path, pathLc, segments };
}

/**
 * Canonicalise a destination. A bare value gets an https:// prefix; anything
 * carrying an explicit scheme (`mailto:`, `slack://`, `ts3server:`) is kept.
 */
export function parseDestination(raw, { blockedSchemes = [] } = {}) {
  const value = String(raw ?? '').trim();
  if (!value) throw new ValidationError('Destination is required.', 'target');
  if (value.length > MAX_DESTINATION) throw new ValidationError('Destination is too long.', 'target');
  if (/[\x00-\x1f\x7f]/.test(value)) {
    throw new ValidationError('Destination contains control characters.', 'target');
  }

  let out;
  if (SCHEME_RE.test(value)) out = value;
  else if (value.startsWith('//')) out = 'https:' + value;
  else out = 'https://' + value;

  // The scheme and the host are case-insensitive, so they are normalised to
  // lowercase. Everything after the host is left exactly as typed, because a
  // path, query or fragment is case-sensitive and lowercasing it would send
  // people somewhere other than where the link was meant to go.
  const scheme = out.slice(0, out.indexOf(':')).toLowerCase();
  out = scheme + out.slice(scheme.length);
  if (HARD_BLOCKED_SCHEMES.includes(scheme)) {
    throw new ValidationError('That destination scheme is not allowed.', 'target');
  }
  const extra = (blockedSchemes || []).map((s) => String(s).toLowerCase().replace(/:$/, ''));
  if (extra.includes(scheme)) {
    throw new ValidationError('That destination scheme is blocked by policy.', 'target');
  }

  // For hierarchical URLs, round-trip through URL so a malformed authority is
  // rejected here rather than emitted into a Location header.
  if (out.slice(scheme.length + 1).startsWith('//')) {
    let parsed;
    try {
      parsed = new URL(out);
    } catch {
      throw new ValidationError('Destination is not a valid URL.', 'target');
    }
    if (!parsed.hostname) throw new ValidationError('Destination has no host.', 'target');
    out = parsed.toString();
  }

  // A header value must not be able to inject a second header.
  if (/[\r\n]/.test(out)) throw new ValidationError('Destination is not valid.', 'target');
  return { target: out, scheme };
}

/* -------------------------------------------------------------------- email */

/**
 * An address we will treat as an identity.
 *
 * The local part is the set RFC 5322 allows unquoted, and nothing else.
 * It was a negated class before, which accepted any character that was not
 * explicitly listed — including control characters, and including letters
 * from other scripts. The second of those matters: an address whose local
 * part is Cyrillic can be pixel-identical to a colleague's while being a
 * different account, and these addresses are what directory grants, link
 * ownership and the administrator list are keyed on. Someone reading a
 * grant list has no way to tell the two apart.
 *
 * Internationalised addresses are real, but this is an internal tool gated
 * on a company domain, and the trade is not close: confusable identities in
 * an authorization decision are worse than turning away an address nobody
 * here has. The domain part was already ASCII-only, so only the local part
 * changes.
 */
const EMAIL_RE =
  /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]{1,64}@[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;

/**
 * Normalise an address for identity purposes.
 *   ignoreDot  - remove every `.` from the local part
 *   ignorePlus - drop everything from the first `+` up to the `@`
 * Both may apply at once: `a.a+tag@cc.com` -> `aa@cc.com`.
 */
export function normalizeEmail(raw, { ignoreDot = false, ignorePlus = false } = {}) {
  const value = String(raw ?? '').trim().toLowerCase();
  if (value.length > 254) throw new ValidationError('That email address is too long.', 'email');
  // Said separately so someone with a perfectly ordinary address in another
  // script is told why, rather than being left to guess at "invalid".
  if (/[^\x20-\x7e]/.test(value)) {
    throw new ValidationError('Email addresses here must use ASCII characters only.', 'email');
  }
  if (!value || !EMAIL_RE.test(value)) throw new ValidationError('Enter a valid email address.', 'email');
  const at = value.lastIndexOf('@');
  let local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (ignorePlus) {
    const plus = local.indexOf('+');
    if (plus > -1) local = local.slice(0, plus);
  }
  if (ignoreDot) local = local.split('.').join('');
  if (!local) throw new ValidationError('Enter a valid email address.', 'email');
  return { email: value, emailNorm: local + '@' + domain, domain };
}

/** Tolerant variant for config values such as ADMIN. */
export function tryNormalizeEmail(raw, opts) {
  try {
    return normalizeEmail(raw, opts);
  } catch {
    return null;
  }
}

/**
 * Does `domain` satisfy an allow list? Entries may be exact (`pontera.com`),
 * wildcard subdomain (`*.pontera.com`) or `*` for any.
 */
export function domainAllowed(domain, allowList) {
  if (!Array.isArray(allowList) || allowList.length === 0) return false;
  const d = String(domain || '').toLowerCase();
  for (const raw of allowList) {
    const entry = String(raw || '').trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;
    if (entry === d) return true;
    if (entry.startsWith('*.') && (d === entry.slice(2) || d.endsWith(entry.slice(1)))) return true;
  }
  return false;
}

/** The longest directory path that is a parent of `pathLc`, from a known set. */
export function parentDirectory(pathLc, knownDirsLc) {
  const segments = pathLc.split('/');
  for (let i = segments.length - 1; i >= 1; i--) {
    const candidate = segments.slice(0, i).join('/');
    if (knownDirsLc.has(candidate)) return candidate;
  }
  return null;
}
