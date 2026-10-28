/**
 * geo.js - where a sign-in may originate.
 *
 * Cloudflare reports the client country in `request.cf.country`. Tor exits are
 * reported as `T1`; `XX` (and a missing value) mean the country could not be
 * determined. Both are refused by default, and an administrator can add an
 * allow list or a block list on top.
 */

export const TOR_CODE = 'T1';

/** Extract what Cloudflare knows about the client. */
export function clientGeo(request) {
  const cf = request.cf || {};
  const country = String(cf.country || '').toUpperCase();
  return {
    country,
    isTor: country === TOR_CODE,
    isUnknown: !country || country === 'XX',
    colo: cf.colo || null,
    asn: cf.asn || null,
    asOrganization: cf.asOrganization || null,
  };
}

/** The client IP, as Cloudflare sees it. */
export function clientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Real-IP') ||
    ''
  );
}

/**
 * Apply the configured policy. Returns { allowed, reason, geo }.
 * `surface` is 'login' or 'access'; policy.applyTo decides whether the rules
 * cover sign-in only or every authenticated request.
 */
export function geoCheck(cfg, request, surface = 'login') {
  const geo = clientGeo(request);
  const policy = cfg.settings.geo || {};

  if (policy.applyTo !== 'all' && surface !== 'login') {
    return { allowed: true, reason: null, geo };
  }

  if (policy.blockTor !== false && geo.isTor) {
    return { allowed: false, reason: 'tor', geo };
  }
  if (policy.blockUnknown !== false && geo.isUnknown) {
    return { allowed: false, reason: 'unknown-country', geo };
  }

  const list = (policy.countries || []).map((c) => String(c).toUpperCase()).filter(Boolean);
  if (policy.mode === 'allow') {
    if (list.length === 0) return { allowed: true, reason: null, geo };
    if (!list.includes(geo.country)) return { allowed: false, reason: 'country-not-allowed', geo };
  } else if (policy.mode === 'block') {
    if (list.includes(geo.country)) return { allowed: false, reason: 'country-blocked', geo };
  }

  return { allowed: true, reason: null, geo };
}

/** Wording shown to a refused visitor; deliberately vague. */
export function geoMessage(reason) {
  switch (reason) {
    case 'tor':
      return 'Sign-in is not available over this network.';
    case 'unknown-country':
      return 'Sign-in is not available from this location.';
    default:
      return 'Sign-in is not available from this location.';
  }
}
