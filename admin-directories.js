/**
 * admin-directories.js - directories and the grants that govern them.
 *
 * A directory restricts who may create beneath it. Two privileges exist:
 * "create" lets a user add links inside, and "manage" makes them a directory
 * administrator who can also edit and delete other users' links in there and
 * hand the privileges to others.
 */

import {
  adminPage,
  back,
  denied,
  flashFrom,
  formToken,
  hostFilter,
  hostsFor,
  policyForm,
  readForm,
  readPolicy,
} from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf } from './auth.js';
import {
  deleteDirectory,
  deleteGrant,
  getDirectory,
  getGrant,
  listDirectories,
  listGrants,
  newDirectory,
  newGrant,
  putDirectory,
  putGrant,
} from './directories.js';
import { resolveDomain } from './domains.js';
import {
  describePolicy,
  directoryMayOverride,
  EXEMPTIBLE,
  narrow,
  normalizeExempt,
  normalizePolicy,
} from './interstitial.js';
import { clientIp } from './geo.js';
import { getLink, listLinks } from './links.js';
import {
  normalizeEmail,
  parseDestination,
  parsePath,
  RESERVED_PATHS,
  ValidationError,
} from './paths.js';
import {
  canCreateDirectory,
  canManageDirectory,
  canSetReadonly,
  canTransferDirectory,
  mayCreateAnyDirectory,
  requireAdmin,
} from './permissions.js';
import { describeMissingPolicy, directoryMaySetMissing, resolveMissing } from './dirmissing.js';
import {
  describeInvitePolicy,
  directoryMayNarrowInvites,
  inviteAllowed,
  normalizeInviteDomains,
} from './invites.js';
import { getUserByNorm, inviteUser, isAdmin } from './users.js';
import { esc, fmtTime } from './util.js';
import { alert, checkbox, csrfField, field, hidden, textarea } from './views.js';

function dirHref(host, pathLc) {
  return `/admin/directories/edit?host=${encodeURIComponent(host)}&path=${encodeURIComponent(pathLc)}`;
}

/* ----------------------------------------------------------------- list */

async function listPage(ctx) {
  const { cfg, url } = ctx;
  const selected = hostFilter(ctx, url);
  const hosts = hostsFor(ctx, selected);

  // Gather across the chosen domains. A non-administrator sees only the
  // directories they hold a grant on.
  const rows = [];
  const creatable = [];
  for (const host of hosts) {
    const all = await listDirectories(cfg, host);
    let visible = all;
    if (!ctx.isAdmin) {
      const checked = await Promise.all(
        all.map(async (d) => ((await getGrant(cfg, host, d.pathLc, ctx.session.user.id)) ? d : null))
      );
      visible = checked.filter(Boolean);
    }
    for (const d of visible) rows.push({ host, dir: d });
    if (await mayCreateAnyDirectory(cfg, { user: ctx.session.user, host })) creatable.push(host);
  }

  const tableRows = rows
    .map(
      ({ host, dir }) => `<tr>
      <td><a href="${esc(dirHref(host, dir.pathLc))}">${esc(host)}/${esc(dir.path)}</a>
        ${dir.readonly ? '<span class="badge ro">read-only</span>' : ''}
        ${dir.open ? '<span class="badge">open</span>' : ''}
        ${dir.enabled === false ? '<span class="badge off">disabled</span>' : ''}</td>
      <td>${esc(dir.note || '\u2014')}</td>
      <td class="num">${esc(fmtTime(dir.createdAt))}</td>
    </tr>`
    )
    .join('');

  const token = await formToken(ctx, 'dir.create');
  const createHostOptions = creatable
    .map((h) => `<option value="${esc(h)}"${h === selected ? ' selected' : ''}>${esc(h)}</option>`)
    .join('');

  const body = `
${flashFrom(url)}
<h1>Directories</h1>
<p class="sub">A directory such as <code>ptra.cc/pub</code> restricts who may create links beneath it. Showing ${
    selected ? esc(selected) : 'every domain'
  }.</p>

<div class="card">
  ${
    rows.length
      ? `<div class="tablewrap"><table><thead><tr><th>Directory</th><th>Note</th><th>Created</th></tr></thead>
         <tbody>${tableRows}</tbody></table></div>`
      : '<div class="empty">No directories here.</div>'
  }
</div>

${
  creatable.length
    ? `<div class="card">
  <h2>Create a directory</h2>
  <p class="hint">${
    ctx.isAdmin
      ? 'As an administrator you may create one on any domain, at any depth.'
      : 'You may create one on the domains listed. To nest a directory inside another, you must administer that one.'
  }</p>
  <form method="post" action="/admin/directories/new">
    ${csrfField(token)}
    <div class="row">
      <div class="field">
        <label for="f_newhost">Domain</label>
        <select id="f_newhost" name="host">${createHostOptions}</select>
      </div>
      ${field({
        name: 'path',
        label: 'Path',
        required: true,
        placeholder: 'pub',
        attrs: 'data-slink-slug spellcheck="false"',
        note: 'Nested paths such as pub/eng are allowed where you administer the parent.',
      })}
    </div>
    ${textarea({ name: 'note', label: 'Note (optional)' })}
    ${checkbox({ name: 'open', label: 'Open', note: '(anyone who may create at the root may also create here)' })}
    ${
      ctx.isAdmin
        ? checkbox({ name: 'readonly', label: 'Read-only', note: '(only administrators may change anything inside)' })
        : ''
    }
    <div class="actions"><button type="submit">Create directory</button></div>
  </form>
</div>`
    : ''
}`;

  return adminPage(ctx, { title: 'Directories', nav: 'directories', body });
}

/* --------------------------------------------------------------- create */

async function createSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.create', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || ctx.host);
  if (!ctx.cfg.knownHosts.includes(host)) return back('/admin/directories', 'notfound');
  const domain = await resolveDomain(ctx.cfg, host);

  let parsed;
  try {
    parsed = parsePath(body.get('path'), {
      reserved: host === ctx.cfg.hubHost ? RESERVED_PATHS : ['__slink'],
    });
  } catch (err) {
    if (err instanceof ValidationError) return denied(ctx, err.message);
    throw err;
  }

  const permit = await canCreateDirectory(ctx.cfg, {
    user: ctx.session.user,
    domain,
    host,
    pathLc: parsed.pathLc,
  });
  if (!permit.allowed) return denied(ctx, permit.reason);

  if (await getDirectory(ctx.cfg, host, parsed.pathLc)) {
    return back(dirHref(host, parsed.pathLc), 'dir.created');
  }
  if (await getLink(ctx.cfg, host, parsed.pathLc)) {
    return denied(ctx, 'A link already uses that path.');
  }

  const dir = newDirectory(host, parsed.path, parsed.pathLc, {
    ownerId: ctx.session.user.id,
    ownerEmail: ctx.session.user.emailNorm,
    note: String(body.get('note') || '').slice(0, 500),
    open: body.get('open') === '1',
    readonly: canSetReadonly(ctx.cfg, ctx.session.user) && body.get('readonly') === '1',
  });
  await putDirectory(ctx.cfg, dir);

  // Whoever creates a directory administers it. Administrators already reach
  // every directory, so a grant for them would only be noise in the list.
  if (!isAdmin(ctx.cfg, ctx.session.user)) {
    await putGrant(
      ctx.cfg,
      newGrant(host, parsed.pathLc, ctx.session.user, {
        canCreate: true,
        canManage: true,
        grantedBy: ctx.session.user.emailNorm,
      })
    );
  }

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirCreated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: parsed.pathLc,
    })
  );
  return back(dirHref(host, parsed.pathLc), 'dir.created');
}

/* ----------------------------------------------------------------- edit */

async function editForm(ctx, { error } = {}) {
  const { cfg, url } = ctx;
  const host = url.searchParams.get('host') || ctx.host;
  const pathLc = String(url.searchParams.get('path') || '').toLowerCase();
  const dir = await getDirectory(cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = await canManageDirectory(cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const grants = await listGrants(cfg, host, pathLc);
  const contents = await listLinks(cfg, host, { dirPathLc: pathLc, limit: 100 });
  const settingsToken = await formToken(ctx, 'dir.update');
  const grantToken = await formToken(ctx, 'grant.save');
  const revokeToken = await formToken(ctx, 'grant.remove');
  const deleteToken = await formToken(ctx, 'dir.delete');
  const moveToken = await formToken(ctx, 'dir.transfer');
  const policyToken = await formToken(ctx, 'dir.policy');
  const exemptToken = await formToken(ctx, 'dir.exempt');
  const parentDomain = await resolveDomain(cfg, host);
  const domainPolicy = normalizePolicy(parentDomain && parentDomain.interstitial);
  const exempt = normalizeExempt(dir.interstitialExempt);
  const exemptions = EXEMPTIBLE.filter((k) => exempt[k]);
  const maySetMissing = directoryMaySetMissing(parentDomain, dir);
  const mayNarrowInvites = directoryMayNarrowInvites(parentDomain);
  const effectiveMissing = resolveMissing(parentDomain, dir);
  const mayOverride = directoryMayOverride(domainPolicy, dir);
  const dirPolicy = dir.interstitial
    ? narrow(domainPolicy, dir.interstitial, dir.interstitialExempt)
    : domainPolicy;
  const mayAdmin = isAdmin(cfg, ctx.session.user);

  const grantRows = grants
    .map(
      (g) => `<tr>
      <td>${esc(g.userEmail)}</td>
      <td>${g.canCreate ? 'create' : ''}${g.canManage ? (g.canCreate ? ', manage' : 'manage') : ''}</td>
      <td class="num">${esc(fmtTime(g.createdAt))}</td>
      <td class="tools">
        <form method="post" action="/admin/directories/grant">
          ${csrfField(grantToken)}${hidden('host', host)}${hidden('path', pathLc)}
          ${hidden('email', g.userEmail)}${hidden('canCreate', '1')}
          ${hidden('canManage', g.canManage ? '' : '1')}
          <button type="submit" class="link">${g.canManage ? 'Demote' : 'Make administrator'}</button>
        </form>
        <form method="post" action="/admin/directories/revoke" data-confirm="Remove access for ${esc(g.userEmail)}?">
          ${csrfField(revokeToken)}${hidden('host', host)}${hidden('path', pathLc)}${hidden('email', g.userEmail)}
          <button type="submit" class="link">Remove</button>
        </form>
      </td>
    </tr>`
    )
    .join('');

  const contentRows = contents.items
    .map((row) => {
      const meta = row.meta || {};
      return `<tr>
        <td><a href="/admin/links/edit?host=${encodeURIComponent(host)}&path=${encodeURIComponent(
        row.pathLc
      )}">${esc(host)}/${esc(meta.p || row.pathLc)}</a></td>
        <td><span class="target">${esc(meta.t || '')}</span></td>
      </tr>`;
    })
    .join('');

  const body = `
${flashFrom(url)}${alert('error', error)}
<h1>${esc(host)}/${esc(dir.path)}</h1>
<p class="sub">Directory &middot; created ${esc(fmtTime(dir.createdAt))}</p>

<div class="card">
  <h2>Access</h2>
  <p class="hint">"Create" lets a user add links here. "Manage" makes them a directory administrator: they can also edit and delete other people's links in this directory and change this list.</p>
  ${
    grants.length
      ? `<div class="tablewrap"><table><thead><tr><th>User</th><th>Privileges</th><th>Granted</th><th></th></tr></thead>
         <tbody>${grantRows}</tbody></table></div>`
      : '<div class="empty">Nobody has been granted access yet.</div>'
  }
  <form method="post" action="/admin/directories/grant">
    ${csrfField(grantToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({
      name: 'email',
      label: 'Grant access to',
      type: 'email',
      required: true,
      placeholder: 'colleague@example.com',
      note: 'The user must have signed in at least once.',
    })}
    ${checkbox({ name: 'canCreate', label: 'May create links in this directory', checked: true })}
    ${checkbox({ name: 'canManage', label: 'Directory administrator' })}
    <div class="actions"><button type="submit">Save access</button></div>
  </form>
</div>

<div class="card">
  <h2>Owner</h2>
  <p class="hint">Currently ${esc(dir.ownerEmail || '\u2014')}. The owner and any administrator can hand it over; a directory administrator who is not the owner cannot. The new owner is made a directory administrator here.</p>
  ${
    canTransferDirectory(cfg, { user: ctx.session.user, dir }).allowed
      ? `<form method="post" action="/admin/directories/transfer">
    ${csrfField(moveToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({ name: 'owner', label: 'New owner email', type: 'email', required: true, placeholder: 'colleague@example.com' })}
    <div class="actions"><button type="submit" class="secondary">Transfer</button></div>
  </form>`
      : '<p class="note">You cannot change the owner of this directory.</p>'
  }
</div>

${
  mayOverride
    ? `<div class="card">
  <h2>Countdown</h2>
  <p class="hint">${
    exemptions.length
      ? 'An administrator has exempted this directory from: ' + esc(exemptions.join(', ')) +
        '. Those settings may differ from the domain; the rest may only be made stricter.'
      : 'You may make this stricter than the domain, not looser. An administrator can grant an exemption if you need otherwise.'
  }</p>
  <form method="post" action="/admin/directories/policy">
    ${csrfField(policyToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${checkbox({ name: 'enabled', label: 'Use a policy for this directory', checked: !!dir.interstitial })}
    ${policyForm(ctx, dirPolicy, { prefix: 'it', inherited: domainPolicy })}
    <div class="actions"><button type="submit">Save countdown policy</button></div>
  </form>
</div>`
    : `<div class="card">
  <h2>Countdown</h2>
  <p class="hint">Set by the domain: ${esc(describePolicy(domainPolicy))} An administrator can let this directory set its own.</p>
</div>`
}

${
  mayAdmin
    ? `<div class="card">
  <h2>Exemptions</h2>
  <p class="hint">Administrators only. Each exemption lets this directory set that one thing against the domain policy; the others stay narrowing-only.</p>
  <form method="post" action="/admin/directories/exempt">
    ${csrfField(exemptToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${checkbox({ name: 'allowOverride', label: 'Let directory administrators set a policy here', checked: !!dir.allowInterstitialOverride })}
    ${checkbox({ name: 'ex_countdown', label: 'Exempt from the domain countdown lock', checked: !!exempt.countdown })}
    ${checkbox({ name: 'ex_destination', label: 'Exempt from the domain destination lock', checked: !!exempt.destination })}
    ${checkbox({ name: 'ex_minDelay', label: 'Exempt from the domain minimum delay', checked: !!exempt.minDelay })}
    ${checkbox({
      name: 'ex_missing',
      label: 'Let this directory set its own MISSING destination',
      checked: !!dir.missingExempt,
      note: '(domain policy: ' + describeMissingPolicy(parentDomain) + ')',
    })}
    <div class="actions"><button type="submit">Save exemptions</button></div>
  </form>
</div>`
    : ''
}

<div class="card">
  <h2>Settings</h2>
  <form method="post" action="/admin/directories/edit">
    ${csrfField(settingsToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${textarea({ name: 'note', label: 'Note', value: dir.note || '' })}
    ${
      maySetMissing
        ? field({
            name: 'missingUrl',
            label: 'MISSING destination',
            value: dir.missingUrl || '',
            placeholder: 'https://example.com/team',
            note:
              'Where to send someone who browses this directory, or a shortcut under it that does not exist. Leave empty to use the domain default' +
              (effectiveMissing.source === 'domain' ? ' (' + effectiveMissing.target + ').' : '.'),
          })
        : `<p class="note">MISSING destination: ${esc(
            effectiveMissing.target || 'the domain default'
          )}. ${esc(describeMissingPolicy(parentDomain))}</p>`
    }
    ${
      mayNarrowInvites
        ? field({
            name: 'inviteDomains',
            label: 'Who may be given access here (optional)',
            value: (normalizeInviteDomains(dir.inviteDomains) || []).join(', '),
            placeholder: 'pontera.com, partner.com',
            note:
              'Comma separated. Leave empty to use the domain list. You may only narrow it: ' +
              describeInvitePolicy(cfg, parentDomain),
          })
        : `<p class="note">Who may be given access here: ${esc(describeInvitePolicy(cfg, parentDomain))}</p>`
    }
    ${checkbox({ name: 'enabled', label: 'Enabled', checked: dir.enabled !== false })}
    ${checkbox({
      name: 'open',
      label: 'Open',
      checked: !!dir.open,
      note: '(anyone who may create at the root may also create here)',
    })}
    ${checkbox({
      name: 'readonly',
      label: 'Read-only',
      checked: !!dir.readonly,
      disabled: !mayAdmin,
      note: mayAdmin ? '(only administrators may change anything inside)' : '(administrators only)',
    })}
    <div class="actions"><button type="submit">Save settings</button></div>
  </form>
</div>

<div class="card">
  <h2>Links in this directory</h2>
  ${
    contents.items.length
      ? `<div class="tablewrap"><table><thead><tr><th>Short link</th><th>Destination</th></tr></thead>
         <tbody>${contentRows}</tbody></table></div>`
      : '<div class="empty">No links here yet.</div>'
  }
</div>

${
  mayAdmin
    ? `<div class="card">
  <h2>Delete</h2>
  <p class="hint">Removes the directory and every grant on it. Links inside are left in place and fall back to the domain's root policy.</p>
  <form method="post" action="/admin/directories/delete" data-confirm="Delete the directory ${esc(dir.path)}?">
    ${csrfField(deleteToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="actions"><button type="submit" class="danger">Delete directory</button></div>
  </form>
</div>`
    : ''
}`;

  return adminPage(ctx, { title: dir.path, nav: 'directories', body });
}

async function editSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.update', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = await canManageDirectory(ctx.cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  dir.note = String(body.get('note') || '').slice(0, 500);
  dir.enabled = body.get('enabled') === '1';
  dir.open = body.get('open') === '1';
  if (canSetReadonly(ctx.cfg, ctx.session.user)) dir.readonly = body.get('readonly') === '1';

  // A validation failure re-renders this directory's screen, which reads the
  // record it is editing from the query string.
  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  const parentDomain = await resolveDomain(ctx.cfg, host);
  // Narrowing is only offered where the host delegates it, and the module
  // discards anything the host's own list does not already cover.
  if (directoryMayNarrowInvites(parentDomain)) {
    dir.inviteDomains = normalizeInviteDomains(String(body.get('inviteDomains') || ''));
  }

  // The field only renders where the domain allows it, so a submission that
  // carries it anyway is ignored rather than trusted.
  if (directoryMaySetMissing(parentDomain, dir)) {
    const raw = String(body.get('missingUrl') || '').trim();
    if (!raw) {
      dir.missingUrl = '';
    } else {
      try {
        dir.missingUrl = parseDestination(raw, { blockedSchemes: ctx.cfg.settings.blockedSchemes }).target;
      } catch (err) {
        if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
        throw err;
      }
    }
  }
  await putDirectory(ctx.cfg, dir);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
    })
  );
  return back(dirHref(host, pathLc), 'dir.updated');
}

async function grantSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'grant.save', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = await canManageDirectory(ctx.cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  let parsedEmail;
  try {
    parsedEmail = normalizeEmail(body.get('email'), ctx.cfg.emailOpts);
  } catch (err) {
    if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
    throw err;
  }

  const invite = inviteAllowed(ctx.cfg, {
    domain: await resolveDomain(ctx.cfg, host),
    dir,
    emailNorm: parsedEmail.emailNorm,
  });
  if (!invite.allowed) return editForm(ctx, { error: invite.reason });

  const target = (
    await inviteUser(ctx.cfg, {
      email: parsedEmail.email,
      emailNorm: parsedEmail.emailNorm,
      invitedBy: ctx.session.user,
    })
  ).user;

  const canManage = body.get('canManage') === '1';
  const canCreate = body.get('canCreate') === '1' || canManage;
  if (!canCreate && !canManage) {
    return editForm(ctx, { error: 'Choose at least one privilege.' });
  }

  const existing = await getGrant(ctx.cfg, host, pathLc, target.id);
  const grant = existing
    ? { ...existing, canCreate, canManage }
    : newGrant(host, pathLc, target, { canCreate, canManage, grantedBy: ctx.session.user.emailNorm });
  await putGrant(ctx.cfg, grant);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.grantAdded,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { user: target.emailNorm, canCreate, canManage },
    })
  );
  return back(dirHref(host, pathLc), 'grant.saved');
}

async function revokeSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'grant.remove', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = await canManageDirectory(ctx.cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const parsed = normalizeEmail(body.get('email'), ctx.cfg.emailOpts);
  const target = await getUserByNorm(ctx.cfg, parsed.emailNorm);
  if (target) {
    await deleteGrant(ctx.cfg, host, pathLc, target.id);
    ctx.waitUntil(
      audit(ctx.cfg, {
        event: EVENTS.grantRemoved,
        actor: ctx.session.user,
        host,
        ip: clientIp(ctx.request),
        object: pathLc,
        detail: { user: target.emailNorm },
      })
    );
  }
  return back(dirHref(host, pathLc), 'grant.removed');
}

async function policySubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.policy', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = await canManageDirectory(ctx.cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const domain = await resolveDomain(ctx.cfg, host);
  const domainPolicy = normalizePolicy(domain && domain.interstitial);
  if (!directoryMayOverride(domainPolicy, dir)) {
    return denied(ctx, 'This directory may not set its own countdown policy.');
  }

  // Stored as submitted; narrowing and any exemption are applied when the
  // policy is resolved, so withdrawing an exemption takes effect at once.
  dir.interstitial = body.get('enabled') === '1' ? readPolicy(body, 'it', domainPolicy) : null;
  await putDirectory(ctx.cfg, dir);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { interstitial: dir.interstitial },
    })
  );
  return back(dirHref(host, pathLc), 'dir.updated');
}

async function exemptSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.exempt', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  // Exemptions are the escape hatch from domain policy, so they are an
  // administrator's call alone, never a directory administrator's.
  const gate = requireAdmin(ctx.cfg, ctx.session.user);
  if (!gate.allowed) return denied(ctx, gate.reason);

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  dir.allowInterstitialOverride = body.get('allowOverride') === '1';
  dir.missingExempt = body.get('ex_missing') === '1';
  dir.interstitialExempt = normalizeExempt({
    countdown: body.get('ex_countdown') === '1',
    destination: body.get('ex_destination') === '1',
    minDelay: body.get('ex_minDelay') === '1',
  });
  await putDirectory(ctx.cfg, dir);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { exempt: dir.interstitialExempt, allowOverride: dir.allowInterstitialOverride },
    })
  );
  return back(dirHref(host, pathLc), 'dir.updated');
}

async function transferSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.transfer', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  const permit = canTransferDirectory(ctx.cfg, { user: ctx.session.user, dir });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  let parsedOwner;
  try {
    parsedOwner = normalizeEmail(body.get('owner'), ctx.cfg.emailOpts);
  } catch (err) {
    if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
    throw err;
  }

  const invite = inviteAllowed(ctx.cfg, {
    domain: await resolveDomain(ctx.cfg, host),
    dir,
    emailNorm: parsedOwner.emailNorm,
  });
  if (!invite.allowed) return editForm(ctx, { error: invite.reason });

  const recipient = (
    await inviteUser(ctx.cfg, {
      email: parsedOwner.email,
      emailNorm: parsedOwner.emailNorm,
      invitedBy: ctx.session.user,
    })
  ).user;
  if (recipient.disabled) return editForm(ctx, { error: 'That account is disabled.' });

  const from = dir.ownerEmail || null;
  dir.ownerId = recipient.id;
  dir.ownerEmail = recipient.emailNorm;
  await putDirectory(ctx.cfg, dir);

  // The new owner must be able to run what they now own. Administrators
  // already reach every directory, so they need no grant row.
  if (!isAdmin(ctx.cfg, recipient)) {
    const existing = await getGrant(ctx.cfg, host, pathLc, recipient.id);
    await putGrant(
      ctx.cfg,
      existing
        ? { ...existing, canCreate: true, canManage: true }
        : newGrant(host, pathLc, recipient, {
            canCreate: true,
            canManage: true,
            grantedBy: ctx.session.user.emailNorm,
          })
    );
  }

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirTransferred,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { from, to: recipient.emailNorm },
    })
  );
  return back(dirHref(host, pathLc), 'dir.moved');
}

async function deleteSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/directories', 'csrf');
  const guard = await checkCsrf(ctx, 'dir.delete', body);
  if (!guard.ok) return back('/admin/directories', 'csrf');

  const gate = requireAdmin(ctx.cfg, ctx.session.user);
  if (!gate.allowed) return denied(ctx, gate.reason);

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const dir = await getDirectory(ctx.cfg, host, pathLc);
  if (!dir) return back('/admin/directories', 'notfound');

  await deleteDirectory(ctx.cfg, dir);
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.dirDeleted,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
    })
  );
  return back('/admin/directories?host=' + encodeURIComponent(host), 'dir.deleted');
}

/* --------------------------------------------------------------- router */

export async function adminDirectories(ctx, path) {
  const method = ctx.request.method;
  if (path === '/admin/directories') return listPage(ctx);
  if (path === '/admin/directories/new' && method === 'POST') return createSubmit(ctx);
  if (path === '/admin/directories/edit') return method === 'POST' ? editSubmit(ctx) : editForm(ctx);
  if (path === '/admin/directories/grant' && method === 'POST') return grantSubmit(ctx);
  if (path === '/admin/directories/revoke' && method === 'POST') return revokeSubmit(ctx);
  if (path === '/admin/directories/policy' && method === 'POST') return policySubmit(ctx);
  if (path === '/admin/directories/exempt' && method === 'POST') return exemptSubmit(ctx);
  if (path === '/admin/directories/transfer' && method === 'POST') return transferSubmit(ctx);
  if (path === '/admin/directories/delete' && method === 'POST') return deleteSubmit(ctx);
  return back('/admin/directories');
}
