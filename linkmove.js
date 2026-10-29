/**
 * linkmove.js - putting a link on a different host, or on several at once.
 *
 * Both operations are the same question asked repeatedly: may this person
 * create this shortcut on that host, and is the shortcut free there. The
 * answer is gathered for every host before anything is written, so a run
 * that cannot finish does not leave half of it done.
 *
 * KV has no transaction, so "none are created" is kept by validating first
 * and, if a write still fails part way, removing what this run wrote. The
 * rollback is best effort by nature; validating first is what makes it
 * almost never needed.
 */

import { resolveDomain } from './domains.js';
import { getDirectory } from './directories.js';
import { deleteLink, getLink, newLink, putLink } from './links.js';
import { parsePath, RESERVED_PATHS } from './paths.js';
import { canCreate } from './permissions.js';

/** Reserved names apply on the administration host only. */
function reservedFor(cfg, host) {
  return host === cfg.hubHost ? RESERVED_PATHS : ['__slink'];
}

/**
 * Can `user` put a shortcut at `pathLc` on `host`? Returns
 * { ok, error } with the host named in the error, since this runs over
 * several hosts and "already in use" is useless without one.
 */
export async function checkTarget(cfg, { user, host, rawPath }) {
  if (!cfg.knownHosts.includes(host)) {
    return { ok: false, error: `${host} is not a domain here.` };
  }
  const domain = await resolveDomain(cfg, host);
  if (!domain || domain.enabled === false) {
    return { ok: false, error: `${host} is disabled.` };
  }

  let parsed;
  try {
    parsed = parsePath(rawPath, { reserved: reservedFor(cfg, host) });
  } catch (err) {
    return { ok: false, error: `${host}: ${err.message}` };
  }

  const permit = await canCreate(cfg, { user, domain, host, pathLc: parsed.pathLc });
  if (!permit.allowed) return { ok: false, error: `${host}: ${permit.reason}` };

  if (await getLink(cfg, host, parsed.pathLc)) {
    return { ok: false, error: `${host}/${parsed.path} is already in use.` };
  }
  if (await getDirectory(cfg, host, parsed.pathLc)) {
    return { ok: false, error: `${host}: a directory already uses that path.` };
  }
  return { ok: true, domain, parsed };
}

/** The fields that travel with a link when it is copied or moved. */
export function carryOver(link) {
  return {
    target: link.target,
    status: link.status,
    delay: link.delay,
    countdown: link.countdown,
    showTarget: link.showTarget,
    routing: link.routing,
    frame: link.frame,
    preview: link.preview,
    password: link.password,
    note: link.note,
    forwardQuery: link.forwardQuery,
    readonly: link.readonly,
    enabled: link.enabled,
    activeFrom: link.activeFrom,
    expiresAt: link.expiresAt,
    qrLogo: link.qrLogo,
  };
}

/**
 * Create the same shortcut in each of `places`, one { host, rawPath } per
 * domain.
 *
 * A path per domain rather than one for all of them, because the directory
 * is chosen per domain: the same shortcut can sit at the root of one and
 * inside `eng/` on another, and which directories exist - and which this
 * person may create in - is a question each domain answers for itself.
 *
 * Every place is checked before any is written. Returns { ok, created,
 * error }, where `created` is the list of hosts written on success.
 */
export async function createEverywhere(cfg, { user, places, fields }) {
  const wanted = [];
  for (const place of places || []) {
    if (!place || !place.host) continue;
    if (wanted.some((p) => p.host === place.host)) continue;
    wanted.push(place);
  }
  if (!wanted.length) return { ok: false, error: 'Choose at least one domain.' };

  const plan = [];
  for (const { host, rawPath } of wanted) {
    const check = await checkTarget(cfg, { user, host, rawPath });
    if (!check.ok) return { ok: false, error: check.error };
    plan.push(check);
  }

  const written = [];
  try {
    for (const { domain, parsed } of plan) {
      const link = newLink(domain.host, parsed, fields.target, user, {
        ...fields,
        status: fields.status || domain.defaultStatus || 302,
      });
      await putLink(cfg, link);
      written.push(link);
    }
  } catch (err) {
    // Undo whatever this run managed to write, so a partial failure leaves
    // the same state as a refused one.
    for (const link of written) {
      try {
        await deleteLink(cfg, link);
      } catch {
        /* nothing more can be done about this one */
      }
    }
    return { ok: false, error: 'Could not create them all, so none were kept: ' + (err && err.message) };
  }
  return { ok: true, created: written.map((l) => l.host), links: written };
}

/**
 * Move a link to another host, keeping everything about it.
 *
 * The new copy is written before the old one is removed: a crash between
 * the two leaves the link reachable at both addresses, which is recoverable,
 * where the other order would lose it.
 */
export async function moveLink(cfg, { user, link, toHost, rawPath }) {
  const path = rawPath || link.path;
  if (toHost === link.host) return { ok: false, error: 'That is the domain it is already on.' };

  const check = await checkTarget(cfg, { user, host: toHost, rawPath: path });
  if (!check.ok) return { ok: false, error: check.error };

  const moved = newLink(toHost, check.parsed, link.target, null, {
    ...carryOver(link),
    ownerId: link.ownerId,
    ownerEmail: link.ownerEmail,
    createdAt: link.createdAt,
    createdBy: link.createdBy,
  });
  await putLink(cfg, moved);
  await deleteLink(cfg, link);
  return { ok: true, link: moved, from: link.host + '/' + link.path };
}
