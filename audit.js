/**
 * audit.js - append-only activity log.
 *
 * Entries are keyed by an inverted timestamp so a plain prefix listing returns
 * them newest first, and they expire on the configured retention period.
 */

import { invTs, K } from './kv.js';
import { now, randomId, sha256Hex } from './util.js';

export const EVENTS = {
  loginRequested: 'login.requested',
  loginFailed: 'login.failed',
  loginSucceeded: 'login.succeeded',
  loginBlocked: 'login.blocked',
  logout: 'logout',
  ssoIssued: 'sso.issued',
  ssoAccepted: 'sso.accepted',
  linkCreated: 'link.created',
  linkUpdated: 'link.updated',
  linkDeleted: 'link.deleted',
  linkTransferred: 'link.transferred',
  dirCreated: 'dir.created',
  dirUpdated: 'dir.updated',
  dirDeleted: 'dir.deleted',
  dirTransferred: 'dir.transferred',
  grantAdded: 'grant.added',
  grantRemoved: 'grant.removed',
  domainCreated: 'domain.created',
  domainUpdated: 'domain.updated',
  domainDeleted: 'domain.deleted',
  userUpdated: 'user.updated',
  impersonationStarted: 'user.impersonated',
  userDeleted: 'user.deleted',
  settingsUpdated: 'settings.updated',
  denied: 'access.denied',
};

/**
 * Record an event. Never throws: an audit failure must not fail the action it
 * was describing, but it is surfaced in the response via `ctx.waitUntil`.
 */
export async function audit(cfg, { event, actor, host, ip, object, detail, outcome = 'ok' }) {
  try {
    const ts = now();
    const entry = {
      ts,
      event,
      outcome,
      actor: actor ? actor.emailNorm || actor.email || actor.id : null,
      actorId: actor ? actor.id : null,
      host: host || null,
      object: object || null,
      detail: detail || null,
      ipHash: ip ? (await sha256Hex(ip)).slice(0, 32) : null,
      // An action taken inside an impersonated view records both identities,
      // so the log never credits it to the person being viewed alone.
      via: actor && actor.impersonatedBy ? actor.impersonatedBy : null,
    };
    const ttl = Math.max(3600, (cfg.settings.auditRetentionDays || 180) * 86400);
    await cfg.store.put(K.audit(invTs(ts), randomId(6)), entry, { ttl, metadata: {
      e: event,
      o: outcome,
      a: entry.actor ? String(entry.actor).slice(0, 80) : null,
      h: entry.host,
      t: ts,
    } });
  } catch {
    /* auditing is best effort and must never break the request */
  }
}

/** One page of audit entries, newest first. */
/**
 * How many keys one purge pass will delete. KV operations count against the
 * request's subrequest budget, so a pass stays well inside it and reports
 * when more is left to do.
 */
export const PURGE_LIMIT = 400;

/**
 * Delete entries older than the retention period.
 *
 * A KV expiry is fixed when the entry is written, so shortening retention
 * does not shorten the entries already stored: they have to be removed.
 * Keys carry an inverted timestamp, so a listing runs newest first and every
 * key after the first expired one is also expired.
 *
 * Returns { deleted, more } — `more` when the limit was reached and another
 * pass would remove further entries.
 */
export async function purgeAudit(cfg, { days } = {}) {
  const keep = Math.max(1, Number(days) || cfg.settings.auditRetentionDays || 180);
  const cutoff = now() - keep * 86400;
  let deleted = 0;
  let cursor;

  for (;;) {
    const page = await cfg.store.listPage(K.auditPrefix(), { cursor, limit: 1000 });
    for (const key of page.keys) {
      const ts = tsFromKey(key.name);
      // Newest first, so the first entry still inside the window means every
      // key before it is too; only the ones past the cutoff are removed.
      if (ts === null || ts >= cutoff) continue;
      await cfg.store.delete(key.name);
      deleted++;
      if (deleted >= PURGE_LIMIT) return { deleted, more: true };
    }
    cursor = page.cursor;
    if (page.done || !cursor) break;
  }
  return { deleted, more: false };
}

/** Recover the unix timestamp from an audit key, or null if it is malformed. */
export function tsFromKey(name) {
  const parts = String(name).split(':');
  if (parts.length < 2) return null;
  const inv = Number(parts[1]);
  if (!Number.isFinite(inv)) return null;
  return 9999999999 - inv;
}

export async function listAudit(cfg, { cursor, limit = 100 } = {}) {
  const page = await cfg.store.listPage(K.auditPrefix(), { cursor, limit });
  const records = await cfg.store.getMany(page.keys.map((k) => k.name));
  return {
    items: records.filter(Boolean),
    cursor: page.cursor,
    done: page.done,
  };
}
