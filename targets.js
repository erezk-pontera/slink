/**
 * targets.js - choosing which destination a visitor gets.
 *
 * A link always has one mandatory destination. It may additionally carry a
 * destination per device class, and any of those slots - including the
 * default - may carry country rules.
 *
 * Resolution is deliberately simple to reason about:
 *
 *   1. Pick the slot for the visitor's device. A slot that has been left
 *      empty is skipped entirely, so configuring only "mobile Android" is
 *      perfectly normal and everything else falls through.
 *   2. Inside that slot, the first country rule that matches wins.
 *   3. Otherwise the slot's own URL.
 *   4. Otherwise the same two steps against the default slot.
 *
 * Country comes from Cloudflare's view of the client, which is also what the
 * sign-in geography checks use.
 */

export const DEVICE_SLOTS = ['mobileAndroid', 'mobileIos', 'tabletAndroid', 'tabletIos'];
export const ALL_SLOTS = ['default', ...DEVICE_SLOTS];

export const SLOT_LABELS = {
  default: 'Everyone else',
  mobileAndroid: 'Android phone',
  mobileIos: 'iPhone',
  tabletAndroid: 'Android tablet',
  tabletIos: 'iPad',
};

/** An empty routing table: every optional slot unset. */
export function emptyRouting() {
  const out = { default: { url: '', rules: [] } };
  for (const slot of DEVICE_SLOTS) out[slot] = { url: '', rules: [] };
  return out;
}

/** Normalise a stored or submitted routing table. */
export function normalizeRouting(raw) {
  const out = emptyRouting();
  const src = raw && typeof raw === 'object' ? raw : {};
  for (const slot of ALL_SLOTS) {
    const entry = src[slot] && typeof src[slot] === 'object' ? src[slot] : {};
    out[slot] = {
      url: typeof entry.url === 'string' ? entry.url : '',
      rules: Array.isArray(entry.rules)
        ? entry.rules
            .map((r) => ({
              countries: Array.isArray(r && r.countries)
                ? r.countries
                    .map((c) => String(c).trim().toUpperCase())
                    .filter((c) => /^[A-Z]{2}$/.test(c))
                : [],
              url: typeof (r && r.url) === 'string' ? r.url : '',
            }))
            .filter((r) => r.url && r.countries.length)
        : [],
    };
  }
  return out;
}

/** Does this routing table do anything beyond the mandatory destination? */
export function hasRouting(routing) {
  if (!routing) return false;
  const r = normalizeRouting(routing);
  if (r.default.rules.length) return true;
  return DEVICE_SLOTS.some((s) => r[s].url || r[s].rules.length);
}

/**
 * The device class of a request.
 *
 * Client hints come first where the browser sends them: `Sec-CH-UA-Mobile`
 * and `Sec-CH-UA-Platform` are low-entropy and sent by default by Chromium,
 * and are far more dependable than reading the user-agent string. Safari
 * sends neither, so the user-agent remains the fallback.
 *
 * One honest limitation: an iPad on iPadOS 13 or later presents itself as a
 * Mac by default, so it is seen as a desktop unless the user has asked for
 * the mobile site. There is no reliable server-side way around that.
 */
export function deviceClass(request) {
  const h = request.headers;
  const platform = String(h.get('Sec-CH-UA-Platform') || '').replace(/"/g, '').toLowerCase();
  const mobileHint = String(h.get('Sec-CH-UA-Mobile') || '');
  const ua = String(h.get('User-Agent') || '');

  if (platform === 'android') return mobileHint === '?1' ? 'mobileAndroid' : 'tabletAndroid';
  if (platform === 'ios') return mobileHint === '?0' ? 'tabletIos' : 'mobileIos';

  if (/\biPad\b/i.test(ua)) return 'tabletIos';
  if (/\biPhone\b|\biPod\b/i.test(ua)) return 'mobileIos';
  if (/\bAndroid\b/i.test(ua)) return /\bMobile\b/i.test(ua) ? 'mobileAndroid' : 'tabletAndroid';

  return 'desktop';
}

function matchCountry(rules, country) {
  if (!country) return null;
  const c = String(country).toUpperCase();
  for (const rule of rules || []) {
    if (rule.countries.includes(c)) return rule.url;
  }
  return null;
}

/**
 * The destination for one visitor. Returns { url, slot, byCountry } so the
 * caller can say why, which the admin preview uses.
 */
export function resolveTarget(link, { device = 'desktop', country = '' } = {}) {
  const routing = normalizeRouting(link && link.routing);
  const fallback = (link && link.target) || '';

  if (device !== 'desktop') {
    const slot = routing[device];
    if (slot && (slot.url || slot.rules.length)) {
      const byCountry = matchCountry(slot.rules, country);
      if (byCountry) return { url: byCountry, slot: device, byCountry: true };
      if (slot.url) return { url: slot.url, slot: device, byCountry: false };
    }
  }

  const byCountry = matchCountry(routing.default.rules, country);
  if (byCountry) return { url: byCountry, slot: 'default', byCountry: true };
  return { url: routing.default.url || fallback, slot: 'default', byCountry: false };
}

/** Every distinct destination a link can send someone to. */
export function allDestinations(link) {
  const routing = normalizeRouting(link && link.routing);
  const out = new Set();
  if (link && link.target) out.add(link.target);
  for (const slot of ALL_SLOTS) {
    if (routing[slot].url) out.add(routing[slot].url);
    for (const rule of routing[slot].rules) out.add(rule.url);
  }
  return [...out];
}
