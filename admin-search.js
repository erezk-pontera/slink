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
  getDirectory,
  getGrant,
  newGrant,
  putDirectory,
  putGrant,
} from './directories.js';
import { getLink, putLink } from './links.js';
import { normalizeEmail, ValidationError } from './paths.js';
import {
  canReceiveTransfer,
  canSetReadonly,
  canTransferDirectory,
  canTransferLink,
} from './permissions.js';
import { MAX_RESULTS, search, TYPES } from './search.js';
import { getUserByNorm, isAdmin } from './users.js';
import { esc } from './util.js';
import { alert, csrfField, field, hidden, select, statusBadges } from './views.js';

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
  { value: 'readonly', label: 'Make read-only' },
  { value: 'unreadonly', label: 'Clear read-only' },
  { value: 'grant', label: 'Add a directory administrator', needs: 'email', dirsOnly: true },
  { value: 'revoke', label: 'Remove a directory administrator', needs: 'email', dirsOnly: true },
];

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
        ${statusBadges(row) || ''}</td>
      <td class="trunc">${esc(row.detail || '')}</td>
      <td>${esc(row.owner || '—')}</td>
    </tr>`;
    })
    .join('');
}

function batchBar(token) {
  return `<div class="card">
  <h2>Act on the selected rows</h2>
  <p class="hint">Ownership and read-only apply to links and directories. Directory administrators apply to selected directories only. A row you may not change is reported and skipped rather than failing the rest.</p>
  ${csrfField(token)}
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

  const found = await search(cfg, { user: ctx.session.user, hosts, query, type });
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
    ? alert('error', `Showing the first ${MAX_RESULTS} matches. Narrow the query or pick one domain.`)
    : ''
}`;

  const results = `
<div class="card">
  <h2>${found.results.length} result${found.results.length === 1 ? '' : 's'}</h2>
  ${
    found.results.length
      ? `<div class="tablewrap"><table><thead><tr>
      <th${mayBatch ? '' : ' hidden'}></th><th>Item</th><th>Destination or note</th><th>Owner</th>
    </tr></thead><tbody>${resultRows(found.results, mayBatch)}</tbody></table></div>`
      : `<p class="hint">${query ? 'Nothing matched.' : 'Enter something to search for.'}</p>`
  }
</div>`;

  // The checkboxes and the action bar are one form, so a batch works with
  // no JavaScript at all; the select-all buttons only make it quicker.
  const batched =
    mayBatch && found.results.length
      ? `<form method="post" action="/admin/search/batch" data-slink-batch>${results}${batchBar(batchToken)}</form>`
      : results;

  const body = head + batched;

  return adminPage(ctx, { title: 'Search', nav: 'search', body });
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

  const picked = body
    .getAll('sel')
    .map(parseRowId)
    .filter(Boolean)
    .slice(0, MAX_RESULTS);
  if (!picked.length) return searchPage(ctx, { error: 'Select at least one row first.' });

  let person = null;
  if (op.needs === 'email') {
    try {
      const parsed = normalizeEmail(body.get('email'), cfg.emailOpts);
      person = await getUserByNorm(cfg, parsed.emailNorm);
    } catch (err) {
      if (err instanceof ValidationError) return searchPage(ctx, { error: err.message });
      throw err;
    }
    if (!person) {
      return searchPage(ctx, {
        error: 'No such user. They must sign in once before they can be given anything.',
      });
    }
  }

  const done = [];
  const skipped = [];
  for (const row of picked) {
    const label = row.host + '/' + row.pathLc;
    try {
      const outcome = await applyOne(ctx, op, row, person);
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

async function applyOne(ctx, op, row, person) {
  const { cfg, session } = ctx;
  const actor = session.user;

  if (row.kind === 'link') {
    if (op.dirsOnly) return { ok: false, reason: 'directories only' };
    const link = await getLink(cfg, row.host, row.pathLc);
    if (!link) return { ok: false, reason: 'gone' };

    if (op.value === 'transfer') {
      const permit = await canTransferLink(cfg, { user: actor, link, host: row.host });
      if (!permit.allowed) return { ok: false, reason: permit.reason };
      const fit = await canReceiveTransfer(cfg, {
        actor,
        recipient: person,
        host: row.host,
        pathLc: row.pathLc,
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
    // In bulk, a directory only changes hands if the person running the
    // batch owns it. Reassigning someone else's directory stays a deliberate
    // act on its own screen, where the consequences are in front of you.
    const owns = dir.ownerId && dir.ownerId === actor.id;
    if (!owns) return { ok: false, reason: 'not yours; use the directory screen' };
    const permit = canTransferDirectory(cfg, { user: actor, dir });
    if (!permit.allowed) return { ok: false, reason: permit.reason };
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
    if (op.value === 'grant') {
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
