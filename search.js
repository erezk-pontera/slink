/**
 * search.js - finding links and directories across domains.
 *
 * Everything here answers from the KV indexes the rest of the app already
 * maintains, so a query costs listings rather than a read per record, and
 * only the rows that match are hydrated.
 *
 * Which listings get walked depends on who is asking, because that is also
 * what makes the result safe: an administrator with full reach walks the
 * host, while everyone else walks their own owner index and the directories
 * they hold a grant on. Nobody is ever shown rows that are then filtered
 * out, so the result cap cannot be eaten by records they may not see.
 */

import { listDirectories, listUserGrants } from './directories.js';
import { hasPassword } from './linkpass.js';
import { hydrate, listLinks, listOwnedLinks } from './links.js';
import { adminReachesAllDirectories, directoryAuthority } from './permissions.js';
import { isAdmin } from './users.js';

/** Keys one listing will walk before the query is called too broad. */
export const MAX_KEYS = 5000;

/**
 * Matches a query will rank before paging. A listing is cheap but a page of
 * hydrated records is not, so the whole match set is bounded here and then
 * served a page at a time.
 */
export const MAX_RESULTS = 2000;

/** Rows on one page of results. */
export const PAGE_SIZE = 50;

export const TYPES = ['all', 'links', 'directories'];

/**
 * Split a query into lowercase terms. Every term must appear somewhere in a
 * row for it to match, which makes "pub plan" narrow rather than widen.
 */
export function terms(query) {
  return String(query || '')
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean)
    .slice(0, 8);
}

export function matches(haystack, want) {
  if (!want.length) return true;
  const hay = String(haystack).toLowerCase();
  return want.every((t) => hay.includes(t));
}

/** The directory that governs a path, given this host's directories by path. */
export function owningDir(pathLc, dirsByPath) {
  const segments = String(pathLc || '').split('/');
  for (let i = segments.length - 1; i >= 1; i--) {
    const dir = dirsByPath.get(segments.slice(0, i).join('/'));
    if (dir) return dir;
  }
  return null;
}

/** Walk a link listing to the end, or to the point where it is too big. */
async function allLinks(cfg, host, opts = {}) {
  const items = [];
  let cursor;
  for (;;) {
    const page = await listLinks(cfg, host, { ...opts, cursor, limit: 1000 });
    items.push(...page.items);
    cursor = page.cursor;
    if (page.done || !cursor || items.length >= MAX_KEYS) break;
  }
  return { items, truncated: items.length >= MAX_KEYS };
}

async function allOwned(cfg, userId) {
  const items = [];
  let cursor;
  for (;;) {
    const page = await listOwnedLinks(cfg, userId, { cursor, limit: 1000 });
    items.push(...page.items);
    cursor = page.cursor;
    if (page.done || !cursor || items.length >= MAX_KEYS) break;
  }
  return { items, truncated: items.length >= MAX_KEYS };
}

function linkRow(host, pathLc, meta, dir) {
  const m = meta || {};
  return {
    kind: 'link',
    host,
    pathLc,
    path: m.p || pathLc,
    detail: m.t || '',
    readonly: m.ro === 1,
    enabled: m.en !== 0,
    dirPathLc: dir ? dir.pathLc : '',
    owner: '',
    mine: false,
  };
}

/**
 * Run a search across the given hosts.
 *
 * Returns rows already filtered to what `user` may see, newest listing state
 * hydrated onto the link rows so that owner and read-only state come from
 * the record rather than from the index metadata.
 */
export async function search(cfg, { user, hosts, query, type = 'all', offset = 0, limit = PAGE_SIZE }) {
  const want = terms(query);
  const admin = isAdmin(cfg, user);
  // Who administers which directory, read once for the whole page rather
  // than per row. A directory administrator stands to a link inside their
  // directory as its owner does, the destination of a protected one
  // included.
  const authority = await directoryAuthority(cfg, user, hosts);
  const reaches = adminReachesAllDirectories(cfg, user);
  const grants = await listUserGrants(cfg, user.id);
  const results = [];
  let truncated = false;

  for (const host of hosts) {
    const dirs = await listDirectories(cfg, host);
    const dirsByPath = new Map(dirs.map((d) => [d.pathLc, d]));
    const granted = new Map();
    for (const g of grants) if (g.host === host) granted.set(g.dirPathLc, g);

    if (type !== 'links') {
      for (const dir of dirs) {
        const grant = granted.get(dir.pathLc);
        const owns = !!(dir.ownerId && dir.ownerId === user.id);
        if (!(admin && reaches) && !owns && !grant) continue;
        if (!matches([dir.pathLc, dir.ownerEmail || '', dir.note || ''].join(' '), want)) continue;
        results.push({
          kind: 'dir',
          host,
          pathLc: dir.pathLc,
          path: dir.path || dir.pathLc,
          detail: dir.note || '',
          owner: dir.ownerEmail || '',
          readonly: !!dir.readonly,
          enabled: dir.enabled !== false,
          mine: owns,
          manage: (admin && reaches) || owns || !!(grant && grant.canManage),
        });
      }
    }

    if (type === 'directories') continue;

    // An administrator who reaches every directory can walk the host. One who
    // does not still owns everything outside a directory, so they walk it too
    // and drop what sits in a directory they hold no grant on.
    if (admin) {
      const page = await allLinks(cfg, host);
      if (page.truncated) truncated = true;
      for (const row of page.items) {
        const dir = owningDir(row.pathLc, dirsByPath);
        if (dir && !reaches && !granted.has(dir.pathLc)) continue;
        if (!matches([row.pathLc, (row.meta && row.meta.t) || ''].join(' '), want)) continue;
        results.push(linkRow(host, row.pathLc, row.meta, dir));
      }
      continue;
    }

    // Everyone else: the directories they hold a grant on, in full.
    const seen = new Set();
    for (const [dirPathLc] of granted) {
      const page = await allLinks(cfg, host, { dirPathLc });
      if (page.truncated) truncated = true;
      for (const row of page.items) {
        if (seen.has(row.pathLc)) continue;
        seen.add(row.pathLc);
        if (!matches([row.pathLc, (row.meta && row.meta.t) || ''].join(' '), want)) continue;
        results.push(linkRow(host, row.pathLc, row.meta, dirsByPath.get(dirPathLc) || null));
      }
    }
  }

  // Plus, for a non-administrator, everything they own anywhere.
  if (!admin && type !== 'directories') {
    const owned = await allOwned(cfg, user.id);
    if (owned.truncated) truncated = true;
    const want2 = want;
    for (const row of owned.items) {
      if (!hosts.includes(row.host)) continue;
      if (results.some((r) => r.kind === 'link' && r.host === row.host && r.pathLc === row.pathLc)) {
        continue;
      }
      if (!matches([row.pathLc, (row.meta && row.meta.t) || ''].join(' '), want2)) continue;
      results.push(linkRow(row.host, row.pathLc, row.meta, null));
    }
  }

  results.sort(
    (a, b) =>
      a.host.localeCompare(b.host) || a.kind.localeCompare(b.kind) || a.pathLc.localeCompare(b.pathLc)
  );
  if (results.length > MAX_RESULTS) {
    results.length = MAX_RESULTS;
    truncated = true;
  }

  // Only the page being shown is hydrated. Matching is done from listing
  // metadata, so a large match set costs listings rather than reads.
  const total = results.length;
  const from = Math.max(0, Math.min(offset, total));
  const page = results.slice(from, from + Math.max(1, limit));

  // Settle the link rows against their records, so ownership and read-only
  // state shown beside a checkbox are the ones a batch action will act on.
  const links = page.filter((r) => r.kind === 'link');
  if (links.length) {
    const byHost = new Map();
    for (const row of links) {
      if (!byHost.has(row.host)) byHost.set(row.host, []);
      byHost.get(row.host).push(row);
    }
    const found = new Map();
    for (const [host, rows] of byHost) {
      for (const rec of await hydrate(cfg, host, rows)) found.set(rec.host + ':' + rec.pathLc, rec);
    }
    for (const row of links) {
      const rec = found.get(row.host + ':' + row.pathLc);
      if (!rec) continue;
      row.owner = rec.ownerEmail || '';
      row.readonly = !!rec.readonly;
      row.enabled = rec.enabled !== false;
      // A password protects the destination as much as the link: showing
      // it in a listing would hand out what the prompt is there to withhold.
      // Whoever may edit the link already sees it on the edit screen.
      row.locked = hasPassword(rec);
      // `mine` is settled before it is read. It used to be assigned on the
      // line after the one that tests it, so it was always undefined there
      // and a person searching for their own protected link got a row with
      // the destination struck out of it.
      row.mine = !!(rec.ownerId && rec.ownerId === user.id);
      const held = admin || row.mine || authority.manages(row.host, row.pathLc);
      row.detail = row.locked && !held ? '' : rec.target || '';
    }
  }

  return {
    results: page,
    total,
    offset: from,
    limit: Math.max(1, limit),
    hasMore: from + page.length < total,
    truncated,
    terms: want,
  };
}
