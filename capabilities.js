/**
 * capabilities.js - features a host may allow, a directory may withdraw, and
 * an administrator may settle for one person.
 *
 * Two things so far work this way: framing a destination instead of
 * redirecting to it, and putting a password on a link. Both are the same
 * shape, so the shape lives here once rather than twice.
 *
 * The question is always "may this person use this feature on this link".
 * It is answered in a fixed order, most specific first:
 *
 *   1. An administrator may always use it. The point of these switches is to
 *      shape what everyone else can do, not to lock out the people who set
 *      them.
 *   2. A ruling an administrator recorded against this person, for this host
 *      or for every host. That is the per-user allow and block, and it wins
 *      over the host and the directory, in both directions.
 *   3. The directory, which may withdraw what the host allows but cannot
 *      grant what the host withholds. A directory cannot hand out more than
 *      it was given.
 *   4. The host.
 *   5. The capability's own default.
 *
 * Everything is stored as a tri-state: true, false, or absent meaning
 * "nothing said here, ask the next level". `undefined` and `null` both mean
 * absent, because a form that submits nothing and a record written before a
 * capability existed should behave the same way.
 */

import { isAdmin } from './users.js';

/** Every host, in the per-user table. */
export const ANY_HOST = '*';

export const CAPABILITIES = {
  /** Show the destination inside a frame rather than redirecting to it. */
  frame: {
    label: 'Frame the destination',
    hint: 'Shows the destination inside this domain instead of sending the visitor to it.',
    default: true,
  },
  /** Require a password before the link resolves. */
  password: {
    label: 'Password-protect a link',
    hint: 'Asks for a password before the link resolves, on any domain.',
    default: true,
  },
};

export const CAPABILITY_KEYS = Object.keys(CAPABILITIES);

export function isCapability(name) {
  return Object.prototype.hasOwnProperty.call(CAPABILITIES, name);
}

/** Read a tri-state out of a stored map, treating anything unset as absent. */
function tri(map, key) {
  if (!map || typeof map !== 'object') return undefined;
  const v = map[key];
  if (v === true || v === false) return v;
  return undefined;
}

/**
 * Normalize a host or directory capability map: only known keys, only
 * booleans. Anything else is dropped rather than stored as a surprise.
 */
export function normalizeCapabilities(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const key of CAPABILITY_KEYS) {
    const v = raw[key];
    if (v === true || v === false) out[key] = v;
  }
  return out;
}

/**
 * Normalize the per-user table: host (or '*') to a capability map. A host
 * with nothing left to say is dropped so the record does not accumulate
 * empty objects.
 */
export function normalizeUserCapabilities(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [host, map] of Object.entries(raw)) {
    const key = host === ANY_HOST ? ANY_HOST : String(host).toLowerCase();
    const caps = normalizeCapabilities(map);
    if (Object.keys(caps).length) out[key] = caps;
  }
  return out;
}

/**
 * The ruling recorded against this person for this capability, if any.
 * A host-specific entry is more specific than the every-host one, so it is
 * consulted first — including when it says the opposite.
 */
export function userRuling(user, host, capability) {
  const table = user && user.capabilities;
  if (!table) return undefined;
  const perHost = tri(table[String(host || '').toLowerCase()], capability);
  if (perHost !== undefined) return perHost;
  return tri(table[ANY_HOST], capability);
}

/**
 * May `user` use `capability` here?
 *
 * Returns { allowed, source } where source says which level decided, so a
 * screen can explain itself rather than just refusing.
 */
export function capabilityAllowed(cfg, capability, { user, domain, dir } = {}) {
  if (!isCapability(capability)) return { allowed: false, source: 'unknown' };

  if (user && isAdmin(cfg, user)) return { allowed: true, source: 'admin' };

  const ruling = userRuling(user, domain && domain.host, capability);
  if (ruling !== undefined) return { allowed: ruling, source: 'user' };

  const host = tri(domain && domain.capabilities, capability);
  const fromHost = host === undefined ? CAPABILITIES[capability].default : host;

  // A directory narrows. It may withdraw what the host allows; it cannot
  // grant what the host does not.
  const inDir = tri(dir && dir.capabilities, capability);
  if (inDir === false) return { allowed: false, source: 'directory' };
  if (inDir === true && !fromHost) return { allowed: false, source: 'domain' };

  return { allowed: fromHost, source: host === undefined ? 'default' : 'domain' };
}

/** A sentence for a screen that has just refused, or is about to. */
export function describeCapability(cfg, capability, context) {
  const { allowed, source } = capabilityAllowed(cfg, capability, context);
  const name = CAPABILITIES[capability] ? CAPABILITIES[capability].label.toLowerCase() : capability;
  if (allowed) {
    if (source === 'admin') return `You may ${name} anywhere, as an administrator.`;
    if (source === 'user') return `An administrator has allowed you to ${name} here.`;
    return `This domain allows you to ${name}.`;
  }
  if (source === 'user') return `An administrator has blocked you from being able to ${name} here.`;
  if (source === 'directory') return `This directory does not allow you to ${name}.`;
  return `This domain does not allow you to ${name}.`;
}

/** Read a capability map out of a submitted form, as a tri-state per key. */
export function readCapabilityForm(body, prefix) {
  const out = {};
  for (const key of CAPABILITY_KEYS) {
    const v = String(body.get(prefix + key) || '');
    if (v === 'allow') out[key] = true;
    else if (v === 'deny') out[key] = false;
  }
  return out;
}

/** The three choices a capability select offers. */
export const TRI_OPTIONS = [
  { value: '', label: 'Inherit' },
  { value: 'allow', label: 'Allowed' },
  { value: 'deny', label: 'Not allowed' },
];

/** The stored tri-state as the value a select should show. */
export function triValue(map, key) {
  const v = tri(map, key);
  return v === true ? 'allow' : v === false ? 'deny' : '';
}
