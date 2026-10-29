/**
 * pending.js - what this session changed a moment ago.
 *
 * Workers KV prefix listing is eventually consistent. A key written a
 * moment ago can be missing from the next listing for up to a minute, and
 * a key just deleted can still be in it, so a screen reached straight after
 * a change can show the state before it: a directory that is not there yet,
 * a passkey still listed after it was removed. Reading one key by name is
 * not subject to that delay.
 *
 * So each change this session makes is noted on the session record, and a
 * listing is reconciled against those few names: one that should be there
 * is added and read like any other record, one that should be gone is
 * dropped. Nothing else about the listing is touched.
 *
 * It corrects what a screen shows and never what it permits. A name noted
 * here only causes a read of that key; the record that comes back is the
 * authority, and a record that has really gone reads as null and vanishes
 * from the list anyway. The notes expire on their own, so the correction
 * lasts about as long as the inconsistency it covers.
 */

import { K } from './kv.js';
import { now } from './util.js';

/** How long a note is worth keeping: KV settles well inside this. */
export const PENDING_TTL = 120;

/**
 * Caps, so a long session cannot grow the record that every request on an
 * authenticated host has to read. A key longer than this is not one of the
 * listings reconciled here, so dropping it costs nothing.
 */
const MAX_PENDING = 24;
const MAX_KEY = 320;

/** The live notes on a session record, oldest first. */
function live(record) {
  if (!record || !Array.isArray(record.pending)) return [];
  const cutoff = now() - PENDING_TTL;
  return record.pending.filter((p) => p && typeof p.k === 'string' && p.t > cutoff);
}

/**
 * Note that this session wrote or deleted `key`, and persist it.
 *
 * Awaited rather than deferred: the redirect that follows is usually
 * served before a background write would land, and a note that arrives
 * after the screen it was meant to correct is no use.
 */
async function note(ctx, keys, deleted) {
  const session = ctx && ctx.session;
  if (!session || !session.record || !session.sidHash) return;
  const wanted = (Array.isArray(keys) ? keys : [keys]).filter(
    (k) => typeof k === 'string' && k && k.length <= MAX_KEY
  );
  if (!wanted.length) return;

  // Re-read rather than writing back the copy this request started with.
  // Writing a whole record to add a note to it would otherwise undo
  // anything else that touched the session meanwhile, and would put the
  // record back if the session had been signed out or revoked in between.
  // A session that is gone gets no note and nothing is written.
  const current = await ctx.cfg.store.get(K.session(session.sidHash));
  if (!current) return;

  // Every key in one read-modify-write. Two of these in parallel would
  // each start from the record as it was and the second would drop the
  // first's note, so a change that touches more than one key says so in a
  // single call rather than a call per key.
  const at = now();
  const kept = live(current).filter((p) => !wanted.includes(p.k));
  for (const k of wanted) kept.push({ k, d: deleted ? 1 : 0, t: at });
  current.pending = kept.slice(-MAX_PENDING);
  const ttl = Math.max(60, (current.expiresAt || 0) - now());
  await ctx.cfg.store.put(K.session(session.sidHash), current, { ttl });
  // Keep the in-memory copy in step, so a second note in the same request
  // does not start from a stale list.
  session.record.pending = current.pending;
}

/** Note one key, or several, this session has just written. */
export function noteWrite(ctx, keys) {
  return note(ctx, keys, false);
}

/** Note one key, or several, this session has just deleted. */
export function noteDelete(ctx, keys) {
  return note(ctx, keys, true);
}

/**
 * The notes under a key prefix, as a listing correction.
 * Returns `{ added, removed }`, both arrays of full key names.
 */
export function pendingUnder(ctx, prefix) {
  const notes = live(ctx && ctx.session && ctx.session.record).filter((p) => p.k.startsWith(prefix));
  if (!notes.length) return null;
  return {
    added: notes.filter((p) => !p.d).map((p) => p.k),
    removed: notes.filter((p) => p.d).map((p) => p.k),
  };
}

/**
 * Fold a correction into the key names a prefix listing returned. Order is
 * not preserved; every caller sorts the records afterwards.
 */
export function mergeNames(names, correction) {
  if (!correction) return names;
  const gone = new Set(correction.removed || []);
  const out = names.filter((name) => !gone.has(name));
  const have = new Set(out);
  for (const name of correction.added || []) {
    if (!have.has(name)) out.push(name);
  }
  return out;
}
