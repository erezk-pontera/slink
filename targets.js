/**
 * targets.js - choosing which destination a visitor gets.
 *
 * A link always has one mandatory destination, and may additionally carry
 * one per device class.
 *
 * Resolution is deliberately simple to reason about:
 *
 *   1. Pick the slot for the visitor's device. A slot that has been left
 *      empty is skipped entirely, so configuring only "mobile Android" is
 *      perfectly normal and everything else falls through.
 *   2. Otherwise the default slot.
 *
 * Destinations used to be able to branch on the visitor's country as well.
 * That is gone: the sign-in geography gate in geo.js is a different thing
 * and stays.
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
  const out = { default: { url: '' } };
  for (const slot of DEVICE_SLOTS) out[slot] = { url: '' };
  return out;
}

/**
 * Normalise a stored or submitted routing table.
 *
 * A record written before country rules were removed still carries a
 * `rules` array; it is dropped here rather than migrated, so an old link
 * resolves by device alone from the first request.
 */
export function normalizeRouting(raw) {
  const out = emptyRouting();
  const src = raw && typeof raw === 'object' ? raw : {};
  for (const slot of ALL_SLOTS) {
    const entry = src[slot] && typeof src[slot] === 'object' ? src[slot] : {};
    out[slot] = { url: typeof entry.url === 'string' ? entry.url : '' };
  }
  return out;
}

/** Does this routing table do anything beyond the mandatory destination? */
export function hasRouting(routing) {
  if (!routing) return false;
  const r = normalizeRouting(routing);
  return DEVICE_SLOTS.some((slot) => !!r[slot].url);
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

/**
 * Should this slot be shown in a frame rather than redirected to? Stored per
 * slot, so a link can frame its mobile destination and redirect for the rest.
 */
export function shouldFrame(link, slot) {
  const map = link && link.frame;
  if (!map || typeof map !== 'object') return false;
  return map[slot] === true;
}

/** Keep only the known slots, as booleans. */
export function normalizeFrame(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const slot of ALL_SLOTS) if (raw[slot] === true) out[slot] = true;
  return out;
}

/**
 * The destination for one visitor. Returns { url, slot } so the caller can
 * say which slot answered, which the admin preview uses.
 */
export function resolveTarget(link, { device = 'desktop' } = {}) {
  const routing = normalizeRouting(link && link.routing);
  const fallback = (link && link.target) || '';

  if (device !== 'desktop' && routing[device] && routing[device].url) {
    return { url: routing[device].url, slot: device };
  }
  return { url: routing.default.url || fallback, slot: 'default' };
}

/** Every distinct destination a link can send someone to. */
export function allDestinations(link) {
  const routing = normalizeRouting(link && link.routing);
  const out = new Set();
  if (link && link.target) out.add(link.target);
  for (const slot of ALL_SLOTS) if (routing[slot].url) out.add(routing[slot].url);
  return [...out];
}
