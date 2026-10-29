/**
 * links.js - shortcut records, their indexes and lookup.
 *
 * `lnk:<host>:<pathLc>` is the record; `own:<userId>:<host>:<pathLc>` is the
 * owner index carrying a summary in its KV metadata so "my links" renders
 * without a read per row. Links inside a directory need no extra index: a link
 * under `pub` has a path starting `pub/`, so the `lnk:<host>:pub/` prefix
 * finds them.
 */

import { K } from './kv.js';
import { REDIRECT_STATUSES } from './domains.js';
import { emptyPreview } from './preview.js';
import { emptyRouting } from './targets.js';
import { isSafeKey, now } from './util.js';

export const MAX_DELAY_SECONDS = 60;

export function newLink(host, parsed, target, owner, overrides = {}) {
  const ts = now();
  return {
    host,
    path: parsed.path,
    pathLc: parsed.pathLc,
    target,
    status: 302,
    /** Seconds of countdown. 0 means "use the policy default". */
    delay: 0,
    /** An uploaded image for the centre of the QR code. See qrlogo.js. */
    qrLogo: null,
    /** null inherits the policy; true or false overrides it where allowed. */
    countdown: null,
    showTarget: null,
    /** Optional per-device and per-country destinations. See targets.js. */
    routing: emptyRouting(),
    /** Which destination slots are shown inside a frame rather than
     *  redirected to. One flag per slot; see targets.js for the slots. */
    frame: {},
    /** Encrypted link password, empty when the link is open. See
     *  linkpass.js. */
    password: '',
    /** Optional unfurling card, public domains only. See preview.js. */
    preview: emptyPreview(),
    ownerId: owner ? owner.id : null,
    ownerEmail: owner ? owner.emailNorm : null,
    /** Read-only links may only be changed by administrators. */
    readonly: false,
    enabled: true,
    note: '',
    /** Unix seconds before which the link is not yet live. 0 means now. */
    activeFrom: 0,
    expiresAt: 0,
    createdAt: ts,
    updatedAt: ts,
    createdBy: owner ? owner.emailNorm : null,
    ...overrides,
  };
}

/** Compact summary stored in the owner index metadata (KV caps it at 1 KiB). */
function summary(link) {
  return {
    p: link.path,
    t: String(link.target || '').slice(0, 300),
    s: link.status,
    d: link.delay,
    ro: link.readonly ? 1 : 0,
    en: link.enabled ? 1 : 0,
    u: link.updatedAt,
  };
}

export async function getLink(cfg, host, pathLc, { fresh = true } = {}) {
  if (!pathLc) return null;
  return cfg.store.get(K.link(host, pathLc), { fresh });
}

export async function putLink(cfg, link, { previousOwnerId } = {}) {
  link.updatedAt = now();
  await cfg.store.put(K.link(link.host, link.pathLc), link, { metadata: summary(link) });
  if (previousOwnerId && previousOwnerId !== link.ownerId) {
    await cfg.store.delete(K.owner(previousOwnerId, link.host, link.pathLc));
  }
  if (link.ownerId) {
    await cfg.store.put(K.owner(link.ownerId, link.host, link.pathLc), { p: link.pathLc }, {
      metadata: summary(link),
    });
  }
  return link;
}

export async function deleteLink(cfg, link) {
  await cfg.store.delete(K.link(link.host, link.pathLc));
  if (link.ownerId) await cfg.store.delete(K.owner(link.ownerId, link.host, link.pathLc));
  await cfg.store.delete(K.clicks(link.host, link.pathLc));
}

/** One page of links on a host, optionally scoped to a directory prefix. */
export async function listLinks(cfg, host, { dirPathLc = '', cursor, limit = 50 } = {}) {
  const prefix = K.linkPrefix(host, dirPathLc ? dirPathLc + '/' : '');
  const page = await cfg.store.listPage(prefix, { cursor, limit });
  const strip = K.linkPrefix(host, '');
  return {
    items: page.keys.map((k) => ({
      pathLc: k.name.slice(strip.length),
      meta: k.metadata || null,
      key: k.name,
    })),
    cursor: page.cursor,
    done: page.done,
  };
}

/** One page of a user's own links, across every host. */
export async function listOwnedLinks(cfg, userId, { cursor, limit = 50 } = {}) {
  const prefix = K.ownerPrefix(userId);
  const page = await cfg.store.listPage(prefix, { cursor, limit });
  return {
    items: page.keys.map((k) => {
      const rest = k.name.slice(prefix.length);
      const sep = rest.indexOf(':');
      return {
        host: rest.slice(0, sep),
        pathLc: rest.slice(sep + 1),
        meta: k.metadata || null,
      };
    }),
    cursor: page.cursor,
    done: page.done,
  };
}

/** Hydrate index rows into full records. */
export async function hydrate(cfg, host, rows) {
  const keys = rows.map((r) => K.link(r.host || host, r.pathLc));
  const records = await cfg.store.getMany(keys);
  return records.filter(Boolean);
}

/** Has the link passed its expiry? */
export function isExpired(link, at = now()) {
  return !!(link && link.expiresAt && link.expiresAt > 0 && link.expiresAt <= at);
}

/** Is the link scheduled to start later than now? */
export function isPending(link, at = now()) {
  return !!(link && link.activeFrom && link.activeFrom > 0 && link.activeFrom > at);
}

/** Is the link servable right now? */
export function isServable(link, at = now()) {
  return !!link && link.enabled !== false && !isExpired(link, at) && !isPending(link, at);
}

/** Clamp a redirect status to the supported set. */
export function clampStatus(value, fallback = 302) {
  const n = Number.parseInt(value, 10);
  return REDIRECT_STATUSES.includes(n) ? n : fallback;
}

/** Clamp an interstitial delay in seconds. */
export function clampDelay(value, fallback = 0) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.min(MAX_DELAY_SECONDS, n);
}

/**
 * Approximate click counting. KV allows roughly one write per second per key,
 * so concurrent hits on a hot link undercount; the figure is a usage signal,
 * not an analytics source of truth. Failures are swallowed on purpose: a
 * counter must never break a redirect.
 */
/** Days of per-day history kept alongside the running total. */
export const CLICK_HISTORY_DAYS = 90;

/** The UTC day a timestamp falls in, as YYYY-MM-DD. */
export function clickDay(at = now()) {
  return new Date(at * 1000).toISOString().slice(0, 10);
}

/**
 * Count one arrival.
 *
 * History lives in the same record as the total, so a hit still costs one
 * read and one write; KV tolerates about one write per second per key and
 * splitting the buckets into their own keys would not change that.
 *
 * This is a read-modify-write on one key, and KV has no compare-and-set,
 * so simultaneous arrivals overwrite each other: twenty at once were
 * measured to record one. The number is therefore a floor, not a count,
 * and the screens say so. Counting every hit needs a primitive that can
 * increment - a Durable Object, or Analytics Engine - which is a
 * deployment change rather than a code one. Nothing else depends on this
 * figure, so it is left as the cheap approximation it is.
 */
export async function bumpClicks(cfg, host, pathLc) {
  try {
    const key = K.clicks(host, pathLc);
    const cur = (await cfg.store.get(key, { fresh: false })) || { n: 0 };
    const at = now();
    const today = clickDay(at);
    const days = { ...(cur.days || {}) };
    days[today] = (days[today] || 0) + 1;
    await cfg.store.put(key, { n: (cur.n || 0) + 1, at, days: pruneDays(days, today) });
  } catch {
    /* counting is best effort */
  }
}

/** Keep the window bounded so the record cannot grow without limit. */
function pruneDays(days, today) {
  const keys = Object.keys(days).sort();
  if (keys.length <= CLICK_HISTORY_DAYS) return days;
  const out = {};
  for (const k of keys.slice(-CLICK_HISTORY_DAYS)) if (isSafeKey(k)) out[k] = days[k];
  if (!(today in out)) out[today] = days[today] || 0;
  return out;
}

export async function readClicks(cfg, host, pathLc) {
  const rec = await cfg.store.get(K.clicks(host, pathLc), { fresh: false });
  return rec && rec.n ? rec.n : 0;
}

/**
 * The running total plus one entry per day for the last `days` days, oldest
 * first and including the days with no hits, so a chart has a flat baseline
 * rather than gaps.
 */
export async function readClickHistory(cfg, host, pathLc, { days = 30 } = {}) {
  const rec = (await cfg.store.get(K.clicks(host, pathLc), { fresh: false })) || {};
  const stored = rec.days || {};
  const span = Math.max(1, Math.min(days, CLICK_HISTORY_DAYS));
  const out = [];
  const startOfToday = Math.floor(now() / 86400) * 86400;
  for (let i = span - 1; i >= 0; i--) {
    const day = clickDay(startOfToday - i * 86400);
    out.push({ day, n: stored[day] || 0 });
  }
  return { total: rec.n || 0, lastAt: rec.at || 0, series: out };
}
