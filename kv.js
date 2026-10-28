/**
 * kv.js - the single KV namespace is the only datastore. This module owns the
 * key space, JSON (de)serialisation and prefix listing.
 *
 * Key space
 *   cfg                                global settings (admin editable)
 *   dom:<host>                         domain record
 *   usr:<emailNorm>                    user record
 *   uid:<userId>                       userId -> emailNorm pointer
 *   lnk:<host>:<pathLc>                link record
 *   own:<userId>:<host>:<pathLc>       owner index  (metadata = link summary)
 *   dir:<host>:<pathLc>                directory record
 *   grt:<host>:<dirPathLc>:<userId>    directory grant
 *   ugr:<userId>:<host>:<dirPathLc>    reverse grant index
 *   ses:<sidHash>                      session (TTL)
 *   uss:<userId>:<sidHash>             per-user session index, for sign-out-everywhere
 *   otp:<loginId>                      OTP challenge (TTL)
 *   cnt:<host>:<pathLc>                approximate click counter
 *   rl:<bucket>                        rate limit counter (TTL)
 *   aud:<invTs>:<rand>                 audit entry (TTL, newest first)
 *   pky:<credentialId>                 passkey, found by what the browser sends
 *   upk:<userId>:<id>                  an account's passkeys, for listing
 *
 * Links in a directory need no separate index: a link under `pub` has a path
 * beginning `pub/`, so listing prefix `lnk:<host>:pub/` finds them.
 *
 * Consistency note: KV is eventually consistent and reads are edge-cached.
 * Administrative reads pass cacheTtl 0 so an operator sees their own writes;
 * the hot redirect path accepts a short cache window in exchange for latency.
 */

const SEP = ':';

export const K = {
  settings: () => 'cfg',
  domain: (host) => 'dom:' + host,
  domainPrefix: () => 'dom:',
  user: (emailNorm) => 'usr:' + emailNorm,
  userPrefix: () => 'usr:',
  userId: (id) => 'uid:' + id,
  link: (host, pathLc) => 'lnk:' + host + SEP + pathLc,
  linkPrefix: (host, pathLc) => 'lnk:' + host + SEP + (pathLc || ''),
  owner: (userId, host, pathLc) => 'own:' + userId + SEP + host + SEP + pathLc,
  ownerPrefix: (userId) => 'own:' + userId + SEP,
  dir: (host, pathLc) => 'dir:' + host + SEP + pathLc,
  dirPrefix: (host, pathLc) => 'dir:' + host + SEP + (pathLc || ''),
  grant: (host, dirPathLc, userId) => 'grt:' + host + SEP + dirPathLc + SEP + userId,
  grantPrefix: (host, dirPathLc) => 'grt:' + host + SEP + dirPathLc + SEP,
  userGrant: (userId, host, dirPathLc) => 'ugr:' + userId + SEP + host + SEP + dirPathLc,
  userGrantPrefix: (userId) => 'ugr:' + userId + SEP,
  /** A passkey, keyed by its credential id so sign-in is one read. */
  passkey: (credentialId) => 'pky:' + credentialId,
  /** The reverse index, so an account's keys can be listed. */
  userPasskey: (userId, id) => 'upk:' + userId + SEP + id,
  userPasskeyPrefix: (userId) => 'upk:' + userId + SEP,
  session: (sidHash) => 'ses:' + sidHash,
  userSession: (userId, sidHash) => 'uss:' + userId + SEP + sidHash,
  userSessionPrefix: (userId) => 'uss:' + userId + SEP,
  otp: (loginId) => 'otp:' + loginId,
  rate: (bucket) => 'rl:' + bucket,
  clicks: (host, pathLc) => 'cnt:' + host + SEP + pathLc,
  audit: (invTs, rand) => 'aud:' + invTs + SEP + rand,
  auditPrefix: () => 'aud:',
};

/** Inverted timestamp so a lexicographic listing yields newest-first. */
export function invTs(unix) {
  return String(9999999999 - Math.floor(unix)).padStart(10, '0');
}

export class Store {
  constructor(kv) {
    if (!kv) throw new Error('KV binding missing');
    this.kv = kv;
  }

  /** Read JSON. `fresh` bypasses the edge cache for read-after-write views. */
  async get(key, { fresh = true } = {}) {
    const opts = { type: 'json' };
    if (!fresh) opts.cacheTtl = 60;
    return this.kv.get(key, opts);
  }

  /** Read JSON plus the key's metadata in one round trip. */
  async getWithMeta(key, { fresh = true } = {}) {
    const opts = { type: 'json' };
    if (!fresh) opts.cacheTtl = 60;
    const res = await this.kv.getWithMetadata(key, opts);
    return { value: res.value, metadata: res.metadata || null };
  }

  /**
   * Write JSON. `ttl` is seconds from now; `metadata` is surfaced by list()
   * so index listings do not need a read per entry (KV caps it at 1024 bytes).
   */
  async put(key, value, { ttl, metadata } = {}) {
    const opts = {};
    if (ttl && ttl > 60) opts.expirationTtl = Math.floor(ttl);
    else if (ttl) opts.expirationTtl = 60; // KV minimum
    if (metadata) opts.metadata = metadata;
    return this.kv.put(key, JSON.stringify(value), opts);
  }

  async delete(key) {
    return this.kv.delete(key);
  }

  /** One page of keys under a prefix. */
  async listPage(prefix, { cursor, limit = 200 } = {}) {
    const res = await this.kv.list({ prefix, limit: Math.min(1000, Math.max(1, limit)), cursor });
    return {
      keys: res.keys || [],
      cursor: res.list_complete ? null : res.cursor,
      done: !!res.list_complete,
    };
  }

  /**
   * Every key under a prefix, following cursors. `max` guards against an
   * unbounded scan; callers that may exceed it should paginate instead.
   */
  async listAll(prefix, { max = 2000 } = {}) {
    const out = [];
    let cursor;
    for (;;) {
      const page = await this.listPage(prefix, { cursor, limit: 1000 });
      out.push(...page.keys);
      if (page.done || out.length >= max || !page.cursor) break;
      cursor = page.cursor;
    }
    return out.slice(0, max);
  }

  /** Fetch many JSON records concurrently. */
  async getMany(keys, opts) {
    return Promise.all(keys.map((k) => this.get(k, opts)));
  }

  /**
   * Best-effort atomic-ish counter used for rate limiting. KV has no compare
   * and swap, so a burst spread across colos can overshoot; limits are set
   * well below the point where overshoot matters and Turnstile gates the
   * same endpoints.
   */
  async bump(bucket, windowSeconds) {
    const key = K.rate(bucket);
    const cur = (await this.get(key)) || { n: 0, reset: 0 };
    const nowSec = Math.floor(Date.now() / 1000);
    const rec =
      cur.reset > nowSec ? { n: cur.n + 1, reset: cur.reset } : { n: 1, reset: nowSec + windowSeconds };
    await this.put(key, rec, { ttl: Math.max(60, rec.reset - nowSec) });
    return rec;
  }

  async peek(bucket) {
    const rec = await this.get(K.rate(bucket));
    const nowSec = Math.floor(Date.now() / 1000);
    if (!rec || rec.reset <= nowSec) return { n: 0, reset: 0 };
    return rec;
  }

  async reset(bucket) {
    return this.delete(K.rate(bucket));
  }
}
