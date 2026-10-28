/**
 * admin-links.js - creating, editing, transferring and deleting shortcuts.
 *
 * Ownership is enforced on every write: the creator may change their own
 * link, a directory administrator may change anything inside their directory,
 * an administrator may change anything, and a read-only link may be changed
 * by administrators alone.
 */

import { adminPage, back, denied, flashFrom, formToken, hostFilter, hostsFor, readForm } from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf } from './auth.js';
import { creatableDirectories, getDirectory, governingDirectory } from './directories.js';
import { policyFor, resolveLink, userExemption, MAX_DELAY } from './interstitial.js';
import {
  emptyPreview,
  normalizePreview,
  previewAllowed,
  previewBlockedReason,
  previewCard,
} from './preview.js';
import { ALL_SLOTS, normalizeRouting, SLOT_LABELS } from './targets.js';
import { resolveDomain } from './domains.js';
import { clientIp } from './geo.js';
import {
  clampDelay,
  clampStatus,
  deleteLink,
  getLink,
  hydrate,
  listLinks,
  listOwnedLinks,
  MAX_DELAY_SECONDS,
  newLink,
  putLink,
  readClicks,
} from './links.js';
import { parseDestination, parsePath, RESERVED_PATHS, ValidationError } from './paths.js';
import { canCreate, canManageLink, canReceiveTransfer, canSetReadonly } from './permissions.js';
import { getUserByNorm } from './users.js';
import { normalizeEmail } from './paths.js';
import { esc, fmtTime } from './util.js';
import { alert, checkbox, csrfField, field, hidden, select, statusBadges, textarea } from './views.js';

const STATUS_OPTIONS = [
  { value: 302, label: '302 - Found (temporary, default)' },
  { value: 301, label: '301 - Moved permanently' },
  { value: 307, label: '307 - Temporary redirect (keeps method)' },
  { value: 308, label: '308 - Permanent redirect (keeps method)' },
  { value: 303, label: '303 - See other' },
];

/**
 * The countdown fields a given person may change on a given link. A locked
 * setting is shown as settled rather than as a control that does nothing.
 */
function countdownControls(behaviour, link) {
  const parts = [];
  if (behaviour.countdownLocked) {
    parts.push(
      `<p class="note">Countdown is ${behaviour.show ? 'required' : 'disabled'} by policy for this location.</p>`
    );
  } else {
    parts.push(
      checkbox({
        name: 'countdown',
        label: 'Show a countdown before opening',
        checked: behaviour.show,
      })
    );
  }
  if (behaviour.show) {
    parts.push(
      field({
        name: 'delay',
        label: 'Delay (seconds)',
        type: 'number',
        value: link && link.delay ? link.delay : behaviour.delay,
        attrs: `min="${Math.max(1, behaviour.minDelay)}" max="${MAX_DELAY}"`,
        note: behaviour.minDelay > 0 ? `Policy requires at least ${behaviour.minDelay}s.` : '',
      })
    );
    if (behaviour.targetLocked) {
      parts.push(
        `<p class="note">The destination is ${behaviour.showTarget ? 'always shown' : 'never shown'} by policy.</p>`
      );
    } else {
      parts.push(
        checkbox({
          name: 'showTarget',
          label: 'Show the destination on the countdown page',
          checked: behaviour.showTarget,
        })
      );
    }
  }
  return parts.join('\n');
}


/**
 * Country rules are edited as one line each, `IL,US https://example.com/x`,
 * which keeps a five-slot form manageable and needs no JavaScript to add or
 * remove rows.
 */
function rulesToText(rules) {
  return (rules || []).map((r) => r.countries.join(',') + ' ' + r.url).join('\n');
}

function textToRules(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const gap = line.search(/\s/);
      if (gap < 0) return null;
      return {
        countries: line.slice(0, gap).split(',').map((c) => c.trim().toUpperCase()).filter(Boolean),
        url: line.slice(gap + 1).trim(),
      };
    })
    .filter((r) => r && r.url && r.countries.length);
}

/** The five destination slots, with their optional country rules. */
function routingFields(routing, { blockedSchemes } = {}) {
  const r = normalizeRouting(routing);
  const slot = (key) => {
    const isDefault = key === 'default';
    return `<fieldset class="grants">
      <legend class="note">${esc(SLOT_LABELS[key])}${isDefault ? '' : ' (optional)'}</legend>
      ${
        isDefault
          ? ''
          : field({
              name: 'url__' + key,
              label: 'Destination',
              value: r[key].url,
              placeholder: 'leave blank to use the main destination',
            })
      }
      ${textarea({
        name: 'rules__' + key,
        label: 'Country rules (optional)',
        value: rulesToText(r[key].rules),
        placeholder: 'IL,US https://example.com/local',
        note: 'One per line: comma-separated two-letter codes, a space, then the destination. The first match wins; anything else falls through.',
      })}
    </fieldset>`;
  };
  return ALL_SLOTS.map(slot).join('');
}

/** Read the five slots back out of a submitted form. */
function readRouting(body) {
  const out = {};
  for (const key of ALL_SLOTS) {
    out[key] = {
      url: String(body.get('url__' + key) || '').trim(),
      rules: textToRules(body.get('rules__' + key)),
    };
  }
  return out;
}

/**
 * Validate and canonicalise every URL in a routing table, so a device or
 * country branch cannot smuggle in a scheme the main destination forbids.
 */
function cleanRouting(raw, opts) {
  const r = normalizeRouting(raw);
  for (const key of ALL_SLOTS) {
    if (r[key].url) r[key].url = parseDestination(r[key].url, opts).target;
    r[key].rules = r[key].rules.map((rule) => ({
      countries: rule.countries,
      url: parseDestination(rule.url, opts).target,
    }));
  }
  return r;
}

function linkEditHref(host, pathLc) {
  return `/admin/links/edit?host=${encodeURIComponent(host)}&path=${encodeURIComponent(pathLc)}`;
}

/** Rows for a list of link records. */
function linkRows(records, { showOwner = false } = {}) {
  return records
    .map((link) => {
      const href = 'https://' + link.host + '/' + link.path;
      return `<tr>
      <td>
        <a href="${esc(href)}" rel="noreferrer">${esc(link.host)}/${esc(link.path)}</a>
        ${statusBadges(link)}
        <button class="link" type="button" data-copy="${esc(href)}">Copy</button>
      </td>
      <td><span class="target" title="${esc(link.target)}">${esc(link.target)}</span></td>
      ${showOwner ? `<td>${esc(link.ownerEmail || '—')}</td>` : ''}
      <td class="num">${esc(link.status)}${link.delay ? ` / ${esc(link.delay)}s` : ''}</td>
      <td><a href="${esc(linkEditHref(link.host, link.pathLc))}">Edit</a></td>
    </tr>`;
    })
    .join('');
}

/* ----------------------------------------------------------------- list */

async function listPage(ctx) {
  const { cfg, url } = ctx;
  const scope = url.searchParams.get('scope') === 'all' && ctx.isAdmin ? 'all' : 'mine';
  const selected = hostFilter(ctx, url);
  const dir = String(url.searchParams.get('dir') || '').trim().toLowerCase();

  let records = [];
  let truncated = false;

  if (scope === 'all') {
    // One listing per domain, because KV lists by key prefix and each host is
    // its own prefix. With a domain chosen this is a single pass.
    for (const host of hostsFor(ctx, selected)) {
      const page = await listLinks(cfg, host, { dirPathLc: dir, limit: 100 });
      records.push(...(await hydrate(cfg, host, page.items)));
      if (page.cursor) truncated = true;
    }
  } else {
    const page = await listOwnedLinks(cfg, ctx.session.user.id, { limit: 200 });
    const wanted = page.items.filter((row) => {
      if (selected && row.host !== selected) return false;
      if (dir && !row.pathLc.startsWith(dir + '/')) return false;
      return true;
    });
    records = await hydrate(cfg, null, wanted);
    if (page.cursor) truncated = true;
  }

  records.sort((a, b) => a.host.localeCompare(b.host) || a.pathLc.localeCompare(b.pathLc));

  const where = selected ? esc(selected) : 'every domain';
  const body = `
${flashFrom(url)}
<h1>Links</h1>
<p class="sub">${scope === 'all' ? 'Every link on ' : 'Links you created on '}${where}.</p>

<div class="card">
  <form method="get" action="/admin/links" class="row" data-no-busy>
    <div class="field">
      <label for="f_scope">Show</label>
      <select id="f_scope" name="scope">
        <option value="mine"${scope === 'mine' ? ' selected' : ''}>My links</option>
        ${ctx.isAdmin ? `<option value="all"${scope === 'all' ? ' selected' : ''}>All links</option>` : ''}
      </select>
    </div>
    <div class="field">
      <label for="f_dir">Directory</label>
      <input id="f_dir" name="dir" type="text" value="${esc(dir)}" placeholder="pub">
    </div>
    <div class="field"><label>&nbsp;</label><button type="submit" class="secondary">Apply</button></div>
  </form>
</div>

<div class="card">
  ${
    records.length
      ? `<div class="tablewrap"><table><thead><tr>
          <th>Short link</th><th>Destination</th>${scope === 'all' ? '<th>Owner</th>' : ''}
          <th>Code</th><th></th></tr></thead>
          <tbody>${linkRows(records, { showOwner: scope === 'all' })}</tbody></table></div>`
      : '<div class="empty">No links to show.</div>'
  }
  ${
    truncated
      ? '<p class="note">There are more than shown. Pick a single domain, or filter by directory, to narrow the list.</p>'
      : ''
  }
  <div class="actions"><a class="btn" href="/admin/links/new">Create a link</a></div>
</div>`;

  return adminPage(ctx, { title: 'Links', nav: 'links', body });
}

/* --------------------------------------------------------------- create */

async function newForm(ctx, { error, info, values = {} } = {}) {
  const { cfg } = ctx;
  const token = await formToken(ctx, 'link.create');
  const chosenHost = values.host || ctx.host;
  const dirs = ctx.isAdmin ? null : await creatableDirectories(cfg, chosenHost, ctx.session.user.id);

  const hostOptions = cfg.knownHosts
    .map((h) => `<option value="${esc(h)}"${h === chosenHost ? ' selected' : ''}>${esc(h)}</option>`)
    .join('');

  const parentDomain = await resolveDomain(cfg, chosenHost);
  const preview = normalizePreview(values.preview);
  const previewBlocked = previewBlockedReason(parentDomain);

  const body = `
${alert('error', error)}${alert('ok', info)}
<h1>Create a link</h1>
<p class="sub">Shortcuts use letters, digits, underscore and hyphen. They are case-insensitive, so <code>Deck</code> and <code>deck</code> are the same link.</p>

<div class="card">
  <form method="post" action="/admin/links/new">
    ${csrfField(token)}
    <div class="row">
      <div class="field">
        <label for="f_host">Domain</label>
        <select id="f_host" name="host">${hostOptions}</select>
      </div>
      ${field({
        name: 'path',
        label: 'Shortcut',
        value: values.path || '',
        required: true,
        placeholder: dirs && dirs.length ? dirs[0] + '/my-link' : 'my-link',
        attrs: 'data-slink-slug spellcheck="false"',
        note:
          dirs === null
            ? 'As an administrator you may create anywhere on any domain.'
            : dirs.length
              ? 'You may create at the root or inside: ' + dirs.join(', ')
              : 'You may create at the root of the selected domain.',
      })}
    </div>
    ${field({
      name: 'target',
      label: 'Destination',
      value: values.target || '',
      required: true,
      placeholder: 'example.com/page',
      note: 'Without a scheme this becomes https://. Other schemes such as mailto: or slack:// are kept as written.',
    })}
    <div class="row">
      ${select({ name: 'status', label: 'Redirect code', value: values.status || 302, options: STATUS_OPTIONS })}
      ${field({
        name: 'delay',
        label: 'Delay (seconds)',
        type: 'number',
        value: values.delay || 0,
        attrs: `min="0" max="${MAX_DELAY_SECONDS}"`,
        note: '0 redirects immediately; above 0 shows a countdown page first.',
      })}
    </div>
    <div class="row">
      ${field({ name: 'expires', label: 'Expires (optional)', type: 'text', value: values.expires || '', placeholder: 'YYYY-MM-DD', note: 'Leave blank for no expiry.' })}
      ${textarea({ name: 'note', label: 'Note (optional)', value: values.note || '' })}
    </div>
    ${checkbox({ name: 'forwardQuery', label: 'Append the incoming query string to the destination', checked: !!values.forwardQuery })}

    <h2>Where different visitors go</h2>
    <p class="hint">All optional. A device slot left blank falls through to the main destination.</p>
    ${routingFields(values.routing)}

    <h2>Preview card</h2>
    ${
      previewBlocked
        ? `<p class="note">${esc(previewBlocked)}</p>`
        : `<p class="hint">Shown when something like Slack or Twitter unfurls this link.</p>
    ${checkbox({ name: 'previewEnabled', label: 'Use a preview card for this link', checked: !!preview.enabled })}
    ${field({ name: 'previewTitle', label: 'Title', value: preview.title })}
    ${textarea({ name: 'previewDescription', label: 'Description', value: preview.description })}
    ${field({ name: 'previewImage', label: 'Image URL', value: preview.image, placeholder: 'https://example.com/card.png', note: 'Must be https.' })}`
    }
    ${
      canSetReadonly(ctx.cfg, ctx.session.user)
        ? checkbox({
            name: 'readonly',
            label: 'Read-only',
            checked: !!values.readonly,
            note: '(only administrators can change it afterwards)',
          })
        : ''
    }
    <div class="actions">
      <button type="submit">Create link</button>
      <a class="btn secondary" href="/admin/links">Cancel</a>
    </div>
  </form>
</div>`;

  return adminPage(ctx, { title: 'Create a link', nav: 'links', body });
}

/** Parse an optional YYYY-MM-DD expiry into a unix timestamp. */
function parseExpiry(raw) {
  const value = String(raw || '').trim();
  if (!value) return 0;
  const ts = Date.parse(value.length === 10 ? value + 'T23:59:59Z' : value);
  if (!Number.isFinite(ts)) throw new ValidationError('Expiry must be a date such as 2026-12-31.', 'expires');
  return Math.floor(ts / 1000);
}

function expiryInput(expiresAt) {
  if (!expiresAt) return '';
  return new Date(expiresAt * 1000).toISOString().slice(0, 10);
}

async function createSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.create', body);
  if (!guard.ok) return back('/admin/links/new', 'csrf');

  const host = String(body.get('host') || ctx.host);
  if (!ctx.cfg.knownHosts.includes(host)) return newForm(ctx, { error: 'Unknown domain.' });
  const domain = await resolveDomain(ctx.cfg, host);
  if (!domain) return newForm(ctx, { error: 'Unknown domain.' });

  const values = {
    host,
    path: body.get('path') || '',
    target: body.get('target') || '',
    status: body.get('status'),
    delay: body.get('delay'),
    expires: body.get('expires') || '',
    note: body.get('note') || '',
    forwardQuery: body.get('forwardQuery') === '1',
    readonly: body.get('readonly') === '1',
    routing: readRouting(body),
    preview: {
      enabled: body.get('previewEnabled') === '1',
      title: body.get('previewTitle'),
      description: body.get('previewDescription'),
      image: String(body.get('previewImage') || '').trim(),
    },
  };

  let parsed;
  let destination;
  let expiresAt;
  let routing;
  try {
    parsed = parsePath(values.path, { reserved: reservedFor(ctx, host) });
    destination = parseDestination(values.target, { blockedSchemes: ctx.cfg.settings.blockedSchemes });
    expiresAt = parseExpiry(values.expires);
    routing = cleanRouting(values.routing, { blockedSchemes: ctx.cfg.settings.blockedSchemes });
    if (values.preview.image && !/^https:\/\//i.test(values.preview.image)) {
      throw new ValidationError('The preview image must be an https URL.', 'previewImage');
    }
  } catch (err) {
    if (err instanceof ValidationError) return newForm(ctx, { error: err.message, values });
    throw err;
  }

  const permit = await canCreate(ctx.cfg, {
    user: ctx.session.user,
    domain,
    host,
    pathLc: parsed.pathLc,
  });
  if (!permit.allowed) {
    ctx.waitUntil(
      audit(ctx.cfg, {
        event: EVENTS.denied,
        actor: ctx.session.user,
        host,
        ip: clientIp(ctx.request),
        outcome: 'denied',
        object: parsed.pathLc,
        detail: { action: 'link.create', reason: permit.reason },
      })
    );
    return newForm(ctx, { error: permit.reason, values });
  }

  const existing = await getLink(ctx.cfg, host, parsed.pathLc);
  if (existing) return newForm(ctx, { error: 'That shortcut is already in use.', values });
  const clash = await getDirectory(ctx.cfg, host, parsed.pathLc);
  if (clash) return newForm(ctx, { error: 'A directory already uses that path.', values });

  const link = newLink(host, parsed, destination.target, ctx.session.user, {
    status: clampStatus(values.status, domain.defaultStatus || 302),
    delay: clampDelay(values.delay, domain.defaultDelay || 0),
    note: String(values.note).slice(0, 500),
    expiresAt,
    forwardQuery: values.forwardQuery,
    readonly: canSetReadonly(ctx.cfg, ctx.session.user) ? values.readonly : false,
    routing,
    preview: previewBlockedReason(domain) ? emptyPreview() : normalizePreview(values.preview),
  });
  await putLink(ctx.cfg, link);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkCreated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: parsed.pathLc,
      detail: { target: destination.target, status: link.status, delay: link.delay },
    })
  );
  return back(linkEditHref(host, parsed.pathLc), 'link.created');
}

/** Reserved names apply on the administration host only. */
function reservedFor(ctx, host) {
  return host === ctx.cfg.hubHost ? RESERVED_PATHS : ['__slink'];
}

/* ----------------------------------------------------------------- edit */

async function editForm(ctx, { error, info } = {}) {
  const { cfg, url } = ctx;
  const host = url.searchParams.get('host') || ctx.host;
  const pathLc = String(url.searchParams.get('path') || '').toLowerCase();
  const link = await getLink(cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const token = await formToken(ctx, 'link.update');
  const delToken = await formToken(ctx, 'link.delete');
  const moveToken = await formToken(ctx, 'link.transfer');
  const clicks = await readClicks(cfg, host, pathLc);
  const dir = await governingDirectory(cfg, host, pathLc);
  const policy = policyFor(await resolveDomain(cfg, host), dir);
  const behaviour = resolveLink(policy, link, userExemption(ctx.session.user, host));
  const parentDomain = await resolveDomain(cfg, host);
  const preview = normalizePreview(link.preview);
  const previewBlocked = previewBlockedReason(parentDomain);
  const dupToken = await formToken(ctx, 'link.duplicate');
  const shortUrl = 'https://' + host + '/' + link.path;
  const mayReadonly = canSetReadonly(cfg, ctx.session.user);

  const body = `
${flashFrom(url)}${alert('error', error)}${alert('ok', info)}
<h1>${esc(host)}/${esc(link.path)}</h1>
<p class="sub">${statusBadges(link) || 'Active'} &middot; created ${esc(fmtTime(link.createdAt))} &middot; ${esc(
    clicks
  )} hit${clicks === 1 ? '' : 's'}</p>

<div class="card">
  <h2>Settings</h2>
  <form method="post" action="/admin/links/edit">
    ${csrfField(token)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({
      name: 'newpath',
      label: 'Shortcut',
      value: link.path,
      required: true,
      attrs: 'data-slink-slug spellcheck="false"',
      note: 'Renaming changes the short link; the old one stops working.',
    })}
    ${field({ name: 'target', label: 'Destination', value: link.target, required: true, note: 'Used when nothing more specific matches.' })}
    ${select({ name: 'status', label: 'Redirect code', value: link.status, options: STATUS_OPTIONS })}
    ${countdownControls(behaviour, link)}
    <div class="row">
      ${field({ name: 'expires', label: 'Expires', type: 'text', value: expiryInput(link.expiresAt), placeholder: 'YYYY-MM-DD' })}
      ${textarea({ name: 'note', label: 'Note', value: link.note || '' })}
    </div>
    ${checkbox({ name: 'enabled', label: 'Enabled', checked: link.enabled !== false })}
    ${checkbox({ name: 'forwardQuery', label: 'Append the incoming query string to the destination', checked: !!link.forwardQuery })}

    <h2>Where different visitors go</h2>
    <p class="hint">All optional. A device slot left blank falls through to the main destination, so configuring only one is perfectly normal.</p>
    ${routingFields(link.routing)}

    <h2>Preview card</h2>
    ${
      previewBlocked
        ? `<p class="note">${esc(previewBlocked)}</p>`
        : `<p class="hint">Shown when something like Slack or Twitter unfurls this link. Leave it off and the unfurler reads the destination's own tags instead.</p>
    ${checkbox({ name: 'previewEnabled', label: 'Use a preview card for this link', checked: !!preview.enabled })}
    ${field({ name: 'previewTitle', label: 'Title', value: preview.title, placeholder: 'Required for a card to show' })}
    ${textarea({ name: 'previewDescription', label: 'Description', value: preview.description })}
    ${field({ name: 'previewImage', label: 'Image URL', value: preview.image, placeholder: 'https://example.com/card.png', note: 'Must be https. Saved and shown as entered; it is not copied or hosted here.' })}
    <p class="note">How it will look:</p>
    ${previewCard(host, link, preview)}`
    }
    ${checkbox({
      name: 'readonly',
      label: 'Read-only',
      checked: !!link.readonly,
      disabled: !mayReadonly,
      note: mayReadonly ? '(only administrators can change it afterwards)' : '(administrators only)',
    })}
    <div class="actions">
      <button type="submit">Save changes</button>
      <a class="btn secondary" href="/admin/links">Back</a>
      <button class="link" type="button" data-copy="${esc(shortUrl)}">Copy short link</button>
    </div>
  </form>
</div>

<div class="card">
  <h2>Owner</h2>
  <p class="hint">Currently ${esc(link.ownerEmail || 'unassigned')}. Transferring hands over the right to edit and delete it.</p>
  <form method="post" action="/admin/links/transfer">
    ${csrfField(moveToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({ name: 'owner', label: 'New owner email', type: 'email', value: '', required: true, placeholder: 'colleague@example.com' })}
    <div class="actions"><button type="submit" class="secondary">Transfer</button></div>
  </form>
</div>

<div class="card">
  <h2>Duplicate</h2>
  <p class="hint">Copies everything on this link except the shortcut, and opens a new one for you to name.</p>
  <form method="post" action="/admin/links/duplicate">
    ${csrfField(dupToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="actions"><button type="submit" class="secondary">Duplicate</button></div>
  </form>
</div>

<div class="card">
  <h2>Delete</h2>
  <p class="hint">This cannot be undone. The shortcut becomes available again.</p>
  <form method="post" action="/admin/links/delete" data-confirm="Delete ${esc(host)}/${esc(link.path)}?">
    ${csrfField(delToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="actions"><button type="submit" class="danger">Delete link</button></div>
  </form>
</div>`;

  // The editor renders the card's image, which is an arbitrary https URL.
  return adminPage(ctx, { title: link.path, nav: 'links', body, externalImages: true });
}

async function editSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.update', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const domain = await resolveDomain(ctx.cfg, host);
  let parsed;
  let destination;
  let expiresAt;
  try {
    parsed = parsePath(body.get('newpath') || link.path, { reserved: reservedFor(ctx, host) });
    destination = parseDestination(body.get('target'), {
      blockedSchemes: ctx.cfg.settings.blockedSchemes,
    });
    expiresAt = parseExpiry(body.get('expires'));
    cleanRouting(readRouting(body), { blockedSchemes: ctx.cfg.settings.blockedSchemes });
  } catch (err) {
    if (err instanceof ValidationError) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: err.message });
    }
    throw err;
  }

  const renamed = parsed.pathLc !== link.pathLc;
  if (renamed) {
    // A rename is a create at the new path, so it needs create permission there.
    const mayPlace = await canCreate(ctx.cfg, {
      user: ctx.session.user,
      domain,
      host,
      pathLc: parsed.pathLc,
    });
    if (!mayPlace.allowed) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: mayPlace.reason });
    }
    if (await getLink(ctx.cfg, host, parsed.pathLc)) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: 'That shortcut is already in use.' });
    }
  }

  const before = { target: link.target, status: link.status, delay: link.delay, path: link.path };
  const oldPathLc = link.pathLc;

  link.path = parsed.path;
  link.pathLc = parsed.pathLc;
  link.target = destination.target;
  link.status = clampStatus(body.get('status'), link.status);
  link.delay = clampDelay(body.get('delay'), link.delay);
  // Only record a choice where one is actually permitted, so a locked
  // setting cannot be smuggled in by hand-posting the form.
  const dir = await governingDirectory(ctx.cfg, host, pathLc);
  const policy = policyFor(domain, dir);
  const effective = resolveLink(policy, link, userExemption(ctx.session.user, host));
  link.countdown = effective.countdownLocked ? null : body.get('countdown') === '1';
  link.showTarget = effective.targetLocked ? null : body.get('showTarget') === '1';
  link.routing = cleanRouting(readRouting(body), {
    blockedSchemes: ctx.cfg.settings.blockedSchemes,
  });
  if (previewBlockedReason(domain)) {
    link.preview = emptyPreview();
  } else {
    const img = String(body.get('previewImage') || '').trim();
    if (img && !/^https:\/\//i.test(img)) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: 'The preview image must be an https URL.' });
    }
    link.preview = normalizePreview({
      enabled: body.get('previewEnabled') === '1',
      title: body.get('previewTitle'),
      description: body.get('previewDescription'),
      image: img,
    });
  }
  link.note = String(body.get('note') || '').slice(0, 500);
  link.expiresAt = expiresAt;
  link.enabled = body.get('enabled') === '1';
  link.forwardQuery = body.get('forwardQuery') === '1';
  if (canSetReadonly(ctx.cfg, ctx.session.user)) link.readonly = body.get('readonly') === '1';

  if (renamed) {
    await deleteLink(ctx.cfg, { ...link, pathLc: oldPathLc });
  }
  await putLink(ctx.cfg, link);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: link.pathLc,
      detail: { before, after: { target: link.target, status: link.status, delay: link.delay, path: link.path } },
    })
  );
  return back(linkEditHref(host, link.pathLc), 'link.updated');
}

async function deleteSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.delete', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  await deleteLink(ctx.cfg, link);
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkDeleted,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { target: link.target },
    })
  );
  return back('/admin/links', 'link.deleted');
}

async function transferSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.transfer', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  let recipient;
  try {
    const parsed = normalizeEmail(body.get('owner'), ctx.cfg.emailOpts);
    recipient = await getUserByNorm(ctx.cfg, parsed.emailNorm);
  } catch (err) {
    if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
    throw err;
  }
  if (!recipient) {
    return editForm(ctx, {
      error: 'No such user. They must sign in once before a link can be transferred to them.',
    });
  }

  const domain = await resolveDomain(ctx.cfg, host);
  const mayReceive = await canReceiveTransfer(ctx.cfg, {
    actor: ctx.session.user,
    recipient,
    domain,
    host,
    pathLc,
  });
  if (!mayReceive.allowed) {
    return editForm(ctx, { error: 'That user cannot hold a link here: ' + mayReceive.reason });
  }

  const previousOwnerId = link.ownerId;
  const previousOwnerEmail = link.ownerEmail;
  link.ownerId = recipient.id;
  link.ownerEmail = recipient.emailNorm;
  await putLink(ctx.cfg, link, { previousOwnerId });

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkTransferred,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { from: previousOwnerEmail, to: recipient.emailNorm },
    })
  );
  return back(linkEditHref(host, pathLc), 'link.moved');
}

async function duplicateSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.duplicate', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const source = await getLink(ctx.cfg, host, pathLc);
  if (!source) return back('/admin/links', 'notfound');

  // Duplicating reveals everything the link holds, so it needs the same
  // standing as editing it, not merely permission to create.
  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link: source, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  return newForm(ctx, {
    info: 'Copied from ' + host + '/' + source.path + '. Give it a shortcut to save it.',
    values: {
      host,
      path: '',
      target: source.target,
      status: source.status,
      delay: source.delay,
      countdown: source.countdown,
      showTarget: source.showTarget,
      note: source.note,
      forwardQuery: !!source.forwardQuery,
      readonly: !!source.readonly,
      routing: source.routing,
      preview: source.preview,
    },
  });
}

/* --------------------------------------------------------------- router */

export async function adminLinks(ctx, path) {
  const method = ctx.request.method;
  if (path === '/admin/links') return listPage(ctx);
  if (path === '/admin/links/new') return method === 'POST' ? createSubmit(ctx) : newForm(ctx);
  if (path === '/admin/links/edit') return method === 'POST' ? editSubmit(ctx) : editForm(ctx);
  if (path === '/admin/links/delete' && method === 'POST') return deleteSubmit(ctx);
  if (path === '/admin/links/transfer' && method === 'POST') return transferSubmit(ctx);
  if (path === '/admin/links/duplicate' && method === 'POST') return duplicateSubmit(ctx);
  return back('/admin/links');
}
