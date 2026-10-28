/**
 * admin-search.js - the search page and the batch actions run from it.
 *
 * Search is open to everyone and shows only what the viewer may act on.
 * The batch bar is for administrators: it is the only place where one
 * submission changes many records, so each action re-checks every selected
 * row against the same permission helpers the single-record screens use,
 * and reports what it did and what it refused rather than failing whole.
 */

import { adminPage, ALL_HOSTS, back, denied, flashFrom, formToken, hostFilter, hostsFor, readForm } from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf } from './auth.js';
import {
  deleteGrant,
  directoryPathSet,
  getDirectory,
  getGrant,
  governingDirectory,
  newGrant,
  putDirectory,
  putGrant,
} from './directories.js';
import { resolveDomain } from './domains.js';
import { inviteAllowed } from './invites.js';
import { getLink, putLink } from './links.js';
import { normalizeEmail, ValidationError } from './paths.js';
import {
  canManageDirectory,
  canManageLink,
  canReceiveTransfer,
  canSetReadonly,
  canTransferDirectory,
  canTransferLink,
} from './permissions.js';
import { MAX_RESULTS, PAGE_SIZE, search, TYPES } from './search.js';
import { getUserByNorm, inviteUser, isAdmin } from './users.js';
import { esc } from './util.js';
import { alert, csrfField, field, hidden, pager, select, statusBadges } from './views.js';

/** The selection value for one row, and its inverse. */
function rowId(row) {
  return row.kind + ':' + row.host + ':' + row.pathLc;
}

export function parseRowId(value) {
  const raw = String(value || '');
  const first = raw.indexOf(':');
  const second = raw.indexOf(':', first + 1);
  if (first < 1 || second < 0) return null;
  const kind = raw.slice(0, first);
  if (kind !== 'link' && kind !== 'dir') return null;
  const host = raw.slice(first + 1, second);
  const pathLc = raw.slice(second + 1).toLowerCase();
  if (!host || !pathLc) return null;
  return { kind, host, pathLc };
}

export const BATCH_OPS = [
  { value: 'transfer', label: 'Change owner', needs: 'email' },
  { value: 'enable', label: 'Enable' },
  { value: 'disable', label: 'Disable' },
  { value: 'readonly', label: 'Make read-only' },
  { value: 'unreadonly', label: 'Clear read-only' },
  { value: 'grant', label: 'Add a directory administrator', needs: 'email', dirsOnly: true },
  { value: 'revoke', label: 'Remove a directory administrator', needs: 'email', dirsOnly: true },
];

/** The operations that turn a record on or off rather than marking it. */
const LIVENESS = ['enable', 'disable'];

/* --------------------------------------------------------------- the page */

function resultRows(rows, pickable) {
  return rows
    .map((row) => {
      const href =
        row.kind === 'link'
          ? '/admin/links/edit?host=' + encodeURIComponent(row.host) + '&path=' + encodeURIComponent(row.pathLc)
          : '/admin/directories/edit?host=' +
            encodeURIComponent(row.host) +
            '&path=' +
            encodeURIComponent(row.pathLc);
      return `<tr>
      <td${pickable ? '' : ' hidden'}>${
        pickable
          ? `<input type="checkbox" name="sel" value="${esc(rowId(row))}" data-slink-pick
        aria-label="Select ${esc(row.host)}/${esc(row.path)}">`
          : ''
      }</td>
      <td>${row.kind === 'dir' ? '<span class="badge">directory</span>' : ''}
        <a href="${href}">${esc(row.host)}/${esc(row.path)}</a>
        ${statusBadges(row) || ''}
        ${
          row.kind === 'link'
            ? `<button class="link" type="button" data-copy="https://${esc(row.host)}/${esc(row.path)}">Copy</button>`
            : ''
        }</td>
      <td class="trunc">${esc(row.detail || '')}</td>
      <td>${esc(row.owner || '—')}</td>
    </tr>`;
    })
    .join('');
}

function batchBar(token, offset) {
  return `<div class="card">
  <h2>Act on the selected rows</h2>
  <p class="hint">Ownership, enabling and read-only apply to links and directories alike. Directory administrators apply to selected directories only. A row you may not change is reported and skipped rather than failing the rest.</p>
  ${csrfField(token)}${hidden('from', String(offset))}
  <div class="row">
    ${select({
      name: 'op',
      label: 'Action',
      value: 'transfer',
      options: BATCH_OPS.map((o) => ({ value: o.value, label: o.label })),
    })}
    ${field({ name: 'email', label: 'Person', type: 'email', value: '', placeholder: 'colleague@example.com', note: 'Needed for an owner or directory-administrator change.' })}
  </div>
  <div class="actions">
    <button type="submit" class="secondary">Apply to selected</button>
    <button type="button" class="link" data-slink-pick-all>Select all</button>
    <button type="button" class="link" data-slink-pick-none>Clear</button>
  </div>
</div>`;
}

async function searchPage(ctx, { error, info } = {}) {
  const { cfg, url } = ctx;
  const query = String(url.searchParams.get('q') || '').slice(0, 200);
  const rawType = String(url.searchParams.get('type') || 'all');
  const type = TYPES.includes(rawType) ? rawType : 'all';
  const selected = hostFilter(ctx, url);
  const hosts = hostsFor(ctx, selected);
  const mayBatch = isAdmin(cfg, ctx.session.user);

  const offset = Math.max(0, Number(url.searchParams.get('from')) || 0);
  const found = await search(cfg, {
    user: ctx.session.user,
    hosts,
    query,
    type,
    offset,
    limit: PAGE_SIZE,
  });
  const batchToken = mayBatch ? await formToken(ctx, 'search.batch') : null;

  const typeOptions = [
    { value: 'all', label: 'Links and directories' },
    { value: 'links', label: 'Links only' },
    { value: 'directories', label: 'Directories only' },
  ];

  const head = `
${flashFrom(url)}${alert('error', error)}${alert('ok', info)}
<h1>Search</h1>
<p class="sub">Across everything you own, administer or may use.</p>

<div class="card">
  <form method="get" action="/admin/search" data-no-busy>
    <div class="row">
      ${field({ name: 'q', label: 'Find', value: query, placeholder: 'shortcut, destination, note or owner', attrs: 'autofocus spellcheck="false"' })}
      ${select({ name: 'type', label: 'Show', value: type, options: typeOptions })}
      ${select({
        name: 'host',
        label: 'Domain',
        value: selected || ALL_HOSTS,
        options: [{ value: ALL_HOSTS, label: 'All Domains' }].concat(
          cfg.knownHosts.map((h) => ({ value: h, label: h }))
        ),
      })}
    </div>
    <div class="actions"><button type="submit">Search</button></div>
  </form>
</div>

${
  found.truncated
    ? alert('error', `More than ${MAX_RESULTS} matches. Narrow the query or pick one domain.`)
    : ''
}`;

  const results = `
<div class="card">
  <h2>${
    found.total === 0
      ? 'No results'
      : found.total <= found.limit
        ? `${found.total} result${found.total === 1 ? '' : 's'}`
        : `${found.offset + 1}&ndash;${found.offset + found.results.length} of ${found.total}`
  }</h2>
  ${
    found.results.length
      ? `<div class="tablewrap"><table><thead><tr>
      <th${mayBatch ? '' : ' hidden'}></th><th>Item</th><th>Destination or note</th><th>Owner</th>
    </tr></thead><tbody>${resultRows(found.results, mayBatch)}</tbody></table></div>`
      : `<p class="hint">${query ? 'Nothing matched.' : 'Enter something to search for.'}</p>`
  }
  ${pageLinks(url, found)}
</div>`;

  // The checkboxes and the action bar are one form, so a batch works with
  // no JavaScript at all; the select-all buttons only make it quicker.
  const batched =
    mayBatch && found.results.length
      ? `<form method="post" action="/admin/search/batch" data-slink-batch>${results}${batchBar(batchToken, found.offset)}</form>`
      : results;

  const body = head + batched;

  return adminPage(ctx, { title: 'Search', nav: 'search', body });
}

/**
 * Previous and next, carrying the query, type and domain so paging does not
 * silently change what is being searched. A selection does not survive a
 * page change, which is deliberate: a batch should act on rows you can see.
 */
function pageLinks(url, found) {
  if (found.total <= found.limit) return '';
  const at = (from) => {
    const next = new URL(url.toString());
    next.searchParams.set('from', String(Math.max(0, from)));
    return next.pathname + next.search;
  };
  return pager(
    found.offset > 0 ? at(found.offset - found.limit) : '',
    found.hasMore ? at(found.offset + found.limit) : ''
  );
}

/* ------------------------------------------------------------ batch action */

/**
 * Apply one action to every selected row. Each row is re-checked, so a
 * selection that was stale or hand-edited changes nothing it should not.
 */
async function batchSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/search', 'csrf');
  const guard = await checkCsrf(ctx, 'search.batch', body);
  if (!guard.ok) return back('/admin/search', 'csrf');

  const { cfg, session } = ctx;
  if (!isAdmin(cfg, session.user)) return denied(ctx, 'Only an administrator may act in bulk.');

  const op = BATCH_OPS.find((o) => o.value === String(body.get('op') || ''));
  if (!op) return searchPage(ctx, { error: 'Choose an action.' });

  if (body.get('from')) ctx.url.searchParams.set('from', String(body.get('from')));
  const picked = body
    .getAll('sel')
    .map(parseRowId)
    .filter(Boolean)
    .slice(0, MAX_RESULTS);
  if (!picked.length) return searchPage(ctx, { error: 'Select at least one row first.' });

  // The address is parsed once here; the invite policy is checked per row,
  // because it can differ by host and by directory, and the account is only
  // created once a row has actually accepted it.
  let parsedPerson = null;
  if (op.needs === 'email') {
    try {
      parsedPerson = normalizeEmail(body.get('email'), cfg.emailOpts);
    } catch (err) {
      if (err instanceof ValidationError) return searchPage(ctx, { error: err.message });
      throw err;
    }
  }

  // One directory-path listing per host, shared by every row on it, rather
  // than one per row.
  const dirSets = new Map();
  const dirSetFor = async (host) => {
    if (!dirSets.has(host)) dirSets.set(host, await directoryPathSet(cfg, host));
    return dirSets.get(host);
  };

  const done = [];
  const skipped = [];
  for (const row of picked) {
    const label = row.host + '/' + row.pathLc;
    try {
      const outcome = await applyOne(ctx, op, row, parsedPerson, await dirSetFor(row.host));
      if (outcome.ok) done.push(label);
      else skipped.push(label + ' (' + outcome.reason + ')');
    } catch (err) {
      skipped.push(label + ' (' + (err && err.message ? err.message : 'failed') + ')');
    }
  }

  const summary =
    `${done.length} changed` + (skipped.length ? `, ${skipped.length} skipped: ` + skipped.join('; ') : '');
  return searchPage(ctx, skipped.length ? { error: summary } : { info: summary });
}

async function applyOne(ctx, op, row, parsedPerson, dirSet) {
  const { cfg, session } = ctx;
  const actor = session.user;

  /** Resolve the named person for this row, once its policy has accepted them. */
  const personFor = async (dir) => {
    const invite = inviteAllowed(cfg, {
      domain: await resolveDomain(cfg, row.host),
      dir,
      emailNorm: parsedPerson.emailNorm,
    });
    if (!invite.allowed) return { error: invite.reason };
    const invited = await inviteUser(cfg, {
      email: parsedPerson.email,
      emailNorm: parsedPerson.emailNorm,
      invitedBy: actor,
    });
    return { person: invited.user };
  };

  if (row.kind === 'link') {
    if (op.dirsOnly) return { ok: false, reason: 'directories only' };
    const link = await getLink(cfg, row.host, row.pathLc);
    if (!link) return { ok: false, reason: 'gone' };

    if (op.value === 'transfer') {
      const permit = await canTransferLink(cfg, { user: actor, link, host: row.host, dirSet });
      if (!permit.allowed) return { ok: false, reason: permit.reason };
      const got = await personFor(await governingDirectory(cfg, row.host, row.pathLc));
      if (got.error) return { ok: false, reason: got.error };
      const person = got.person;
      const fit = await canReceiveTransfer(cfg, {
        actor,
        recipient: person,
        host: row.host,
        pathLc: row.pathLc,
        dirSet,
      });
      if (!fit.allowed) return { ok: false, reason: fit.reason };
      const previousOwnerId = link.ownerId;
      const from = link.ownerEmail;
      link.ownerId = person.id;
      link.ownerEmail = person.emailNorm;
      await putLink(cfg, link, { previousOwnerId });
      ctx.waitUntil(
        audit(cfg, {
          event: EVENTS.linkTransferred,
          actor,
          host: row.host,
          ip: ctx.ip,
          object: row.pathLc,
          detail: { from, to: person.emailNorm, batch: true },
        })
      );
      return { ok: true };
    }

    const may = await canManageLink(cfg, { user: actor, link, host: row.host, dirSet });
    if (!may.allowed) return { ok: false, reason: may.reason };

    if (LIVENESS.includes(op.value)) {
      link.enabled = op.value === 'enable';
      await putLink(cfg, link);
      ctx.waitUntil(
        audit(cfg, {
          event: EVENTS.linkUpdated,
          actor,
          host: row.host,
          ip: ctx.ip,
          object: row.pathLc,
          detail: { enabled: link.enabled, batch: true },
        })
      );
      return { ok: true };
    }

    // Read-only is an administrator-only field on top of that right.
    if (!canSetReadonly(cfg, actor)) return { ok: false, reason: 'not permitted' };
    link.readonly = op.value === 'readonly';
    await putLink(cfg, link);
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.linkUpdated,
        actor,
        host: row.host,
        ip: ctx.ip,
        object: row.pathLc,
        detail: { readonly: link.readonly, batch: true },
      })
    );
    return { ok: true };
  }

  const dir = await getDirectory(cfg, row.host, row.pathLc);
  if (!dir) return { ok: false, reason: 'gone' };

  if (op.value === 'transfer') {
    const permit = canTransferDirectory(cfg, { user: actor, dir });
    if (!permit.allowed) return { ok: false, reason: permit.reason };
    const got = await personFor(dir);
    if (got.error) return { ok: false, reason: got.error };
    const person = got.person;
    const from = dir.ownerEmail;
    dir.ownerId = person.id;
    dir.ownerEmail = person.emailNorm;
    await putDirectory(cfg, dir);
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.dirTransferred,
        actor,
        host: row.host,
        ip: ctx.ip,
        object: row.pathLc,
        detail: { from, to: person.emailNorm, batch: true },
      })
    );
    return { ok: true };
  }

  if (op.value === 'grant' || op.value === 'revoke') {
    const may = await canManageDirectory(cfg, { user: actor, dir });
    if (!may.allowed) return { ok: false, reason: may.reason };
    if (op.value === 'grant') {
      const got = await personFor(dir);
      if (got.error) return { ok: false, reason: got.error };
      const person = got.person;
      const existing = await getGrant(cfg, row.host, row.pathLc, person.id);
      const grant = existing
        ? { ...existing, canCreate: true, canManage: true }
        : newGrant(row.host, row.pathLc, person, {
            canCreate: true,
            canManage: true,
            grantedBy: actor.emailNorm,
          });
      await putGrant(cfg, grant);
      ctx.waitUntil(
        audit(cfg, {
          event: EVENTS.grantAdded,
          actor,
          host: row.host,
          ip: ctx.ip,
          object: row.pathLc,
          detail: { to: person.emailNorm, canManage: true, batch: true },
        })
      );
      return { ok: true };
    }
    const person = await getUserByNorm(cfg, parsedPerson.emailNorm);
    if (!person) return { ok: false, reason: 'no such user' };
    const existing = await getGrant(cfg, row.host, row.pathLc, person.id);
    if (!existing) return { ok: false, reason: 'no grant to remove' };
    await deleteGrant(cfg, row.host, row.pathLc, person.id);
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.grantRemoved,
        actor,
        host: row.host,
        ip: ctx.ip,
        object: row.pathLc,
        detail: { from: person.emailNorm, batch: true },
      })
    );
    return { ok: true };
  }

  // An administrator is never refused by the read-only mark itself, so this
  // still clears a mark they set; what it does enforce is directory scope.
  const mayDir = await canManageDirectory(cfg, { user: actor, dir });
  if (!mayDir.allowed) return { ok: false, reason: mayDir.reason };

  if (LIVENESS.includes(op.value)) {
    dir.enabled = op.value === 'enable';
    await putDirectory(cfg, dir);
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.dirUpdated,
        actor,
        host: row.host,
        ip: ctx.ip,
        object: row.pathLc,
        detail: { enabled: dir.enabled, batch: true },
      })
    );
    return { ok: true };
  }

  if (!canSetReadonly(cfg, actor)) return { ok: false, reason: 'not permitted' };
  dir.readonly = op.value === 'readonly';
  await putDirectory(cfg, dir);
  ctx.waitUntil(
    audit(cfg, {
      event: EVENTS.dirUpdated,
      actor,
      host: row.host,
      ip: ctx.ip,
      object: row.pathLc,
      detail: { readonly: dir.readonly, batch: true },
    })
  );
  return { ok: true };
}

export async function adminSearch(ctx, path) {
  const method = ctx.request.method;
  if (path === '/admin/search') return searchPage(ctx);
  if (path === '/admin/search/batch' && method === 'POST') return batchSubmit(ctx);
  return back('/admin/search');
}
