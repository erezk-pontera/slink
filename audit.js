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
export async function listAudit(cfg, { cursor, limit = 100 } = {}) {
  const page = await cfg.store.listPage(K.auditPrefix(), { cursor, limit });
  const records = await cfg.store.getMany(page.keys.map((k) => k.name));
  return {
    items: records.filter(Boolean),
    cursor: page.cursor,
    done: page.done,
  };
}
