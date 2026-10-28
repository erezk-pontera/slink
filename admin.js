/**
 * admin.js - the administration router and the pieces its pages share.
 *
 * Every page requires a session. Every state change is a POST carrying a CSRF
 * token bound to that session and the specific form, and is refused unless
 * the Origin (or Referer) matches this host.
 */

import { adminDirectories } from './admin-directories.js';
import { adminDomains } from './admin-domains.js';
import { adminLinks } from './admin-links.js';
import { adminUsers } from './admin-users.js';
import { tokenFor } from './auth.js';
import { creatableDirectories } from './directories.js';
import { resolveDomain } from './domains.js';
import { listOwnedLinks } from './links.js';
import { mayCreateAnyDirectory, requireAdmin, rootCreateAllowed } from './permissions.js';
import { esc, fmtTime } from './util.js';
import { alert, html, layout, messagePage } from './views.js';

/** The query value meaning "every domain", which is the default everywhere. */
export const ALL_HOSTS = 'all';

/**
 * Read the domain filter from a URL. Returns '' for "every domain", which is
 * what the listings default to; a named host is kept only when the worker
 * actually serves it.
 */
export function hostFilter(ctx, url) {
  const raw = String(url.searchParams.get('host') || '').trim().toLowerCase();
  if (!raw || raw === ALL_HOSTS) return '';
  return ctx.cfg.knownHosts.includes(raw) ? raw : '';
}

/** The hosts a listing should cover, given the filter. */
export function hostsFor(ctx, selected) {
  return selected ? [selected] : ctx.cfg.knownHosts;
}

/** Fixed flash messages, referenced by code so a URL cannot inject prose. */
export const MESSAGES = {
  'link.created': ['ok', 'Link created.'],
  'link.updated': ['ok', 'Link updated.'],
  'link.deleted': ['ok', 'Link deleted.'],
  'link.moved': ['ok', 'Link transferred.'],
  'dir.created': ['ok', 'Directory created.'],
  'dir.updated': ['ok', 'Directory updated.'],
  'dir.deleted': ['ok', 'Directory deleted.'],
  'dir.moved': ['ok', 'Directory transferred.'],
  'grant.saved': ['ok', 'Access updated.'],
  'grant.removed': ['ok', 'Access removed.'],
  'domain.created': ['ok', 'Domain added.'],
  'domain.updated': ['ok', 'Domain updated.'],
  'domain.deleted': ['ok', 'Domain removed.'],
  'user.updated': ['ok', 'User updated.'],
  'user.deleted': ['ok', 'User removed.'],
  'settings.updated': ['ok', 'Settings saved.'],
  'sessions.revoked': ['ok', 'Sessions revoked.'],
  denied: ['error', 'You do not have permission to do that.'],
  csrf: ['error', 'That request could not be verified. Please try again.'],
  notfound: ['error', 'That item no longer exists.'],
};

export function flashFrom(url) {
  const code = url.searchParams.get('m');
  if (!code || !Object.prototype.hasOwnProperty.call(MESSAGES, code)) return '';
  const [kind, text] = MESSAGES[code];
  return alert(kind === 'ok' ? 'ok' : 'error', text);
}

/** Redirect within the admin area, optionally with a flash code. */
export function back(path, code, cookies = []) {
  const url = code ? path + (path.includes('?') ? '&' : '?') + 'm=' + encodeURIComponent(code) : path;
  const headers = new Headers({ Location: url });
  for (const cookie of cookies) if (cookie) headers.append('Set-Cookie', cookie);
  return new Response(null, { status: 303, headers });
}

/** The navigation bar, filtered to what this user may reach. */
export function adminNav(ctx, current) {
  const items = [
    { href: '/admin', label: 'Overview', key: 'overview' },
    { href: '/admin/links', label: 'Links', key: 'links' },
    { href: '/admin/directories', label: 'Directories', key: 'directories' },
  ];
  if (ctx.isAdmin) {
    items.push(
      { href: '/admin/domains', label: 'Domains', key: 'domains' },
      { href: '/admin/users', label: 'Users', key: 'users' },
      { href: '/admin/settings', label: 'Settings', key: 'settings' },
      { href: '/admin/audit', label: 'Audit', key: 'audit' }
    );
  }
  items.push({ href: '/logout', label: 'Sign out', key: 'logout' });
  return items.map((i) => ({ ...i, current: i.key === current }));
}

/** Pages where a domain filter means something, so the picker is shown. */
const FILTERABLE = ['/admin', '/admin/links', '/admin/directories'];

/**
 * The domain picker that sits beside the brand. It submits to the current
 * page, carrying the other filters along, so switching domain keeps the view
 * you were looking at. Pages that act on one specific record do not get it,
 * because changing the domain there would point at a different thing.
 */
function hostPicker(ctx) {
  const path = ctx.url.pathname.replace(/\/+$/, '') || '/admin';
  if (!FILTERABLE.includes(path)) return '';
  const selected = hostFilter(ctx, ctx.url);
  const carried = ['scope', 'dir']
    .map((k) => {
      const v = ctx.url.searchParams.get(k);
      return v ? `<input type="hidden" name="${esc(k)}" value="${esc(v)}">` : '';
    })
    .join('');
  const options = [`<option value="${ALL_HOSTS}"${selected ? '' : ' selected'}>All Domains</option>`]
    .concat(
      ctx.cfg.knownHosts.map(
        (h) => `<option value="${esc(h)}"${h === selected ? ' selected' : ''}>${esc(h)}</option>`
      )
    )
    .join('');
  return `<form class="hostpick" method="get" action="${esc(path)}" data-no-busy data-slink-autosubmit>
  ${carried}
  <label class="visually-hidden" for="f_hostpick">Domain</label>
  <select id="f_hostpick" name="host">${options}</select>
  <button type="submit" class="secondary nojs">Go</button>
</form>`;
}

/** Render an admin page inside the shared chrome. */
export function adminPage(ctx, { title, nav, body, status = 200 }) {
  return html(
    layout({
      title: title + ' - ' + ctx.cfg.appName,
      appName: ctx.cfg.appName,
      host: ctx.host,
      user: ctx.session.user,
      nav: adminNav(ctx, nav),
      headerExtra: hostPicker(ctx),
      body,
    }),
    { status }
  );
}

/** A refusal rendered inside the admin chrome. */
export function denied(ctx, reason) {
  return adminPage(ctx, {
    title: 'Not permitted',
    nav: '',
    status: 403,
    body:
      alert('error', reason || 'You do not have permission to do that.') +
      `<div class="card"><div class="actions"><a class="btn secondary" href="/admin">Back to overview</a></div></div>`,
  });
}

/** The largest form body any page here legitimately produces. */
const MAX_FORM_BYTES = 64 * 1024;

/**
 * Parse a form body, refusing anything that is not a urlencoded form or is
 * larger than any of these pages can produce. The declared length is checked
 * first so an oversized body is rejected before it is buffered.
 */
export async function readForm(request) {
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/x-www-form-urlencoded')) return null;
  const declared = Number.parseInt(request.headers.get('Content-Length') || '', 10);
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) return null;
  const text = await request.text();
  if (text.length > MAX_FORM_BYTES) return null;
  return new URLSearchParams(text);
}

/* ------------------------------------------------------------- overview */

async function overview(ctx) {
  const { cfg } = ctx;
  const selected = hostFilter(ctx, ctx.url);
  const owned = await listOwnedLinks(cfg, ctx.session.user.id, { limit: 200 });
  const rows = owned.items
    .filter((row) => !selected || row.host === selected)
    .slice(0, 10)
    .map((row) => {
      const meta = row.meta || {};
      const href = 'https://' + row.host + '/' + (meta.p || row.pathLc);
      return `<tr>
        <td><a href="${esc(href)}" rel="noreferrer">${esc(row.host)}/${esc(meta.p || row.pathLc)}</a></td>
        <td><span class="target">${esc(meta.t || '')}</span></td>
        <td class="num">${esc(meta.s || '')}</td>
        <td><a href="/admin/links/edit?host=${encodeURIComponent(row.host)}&path=${encodeURIComponent(
        row.pathLc
      )}">Edit</a></td>
      </tr>`;
    })
    .join('');

  // What this person may do, per domain. An administrator is never narrowed
  // by a grant, so say so rather than listing an empty set.
  const admin = ctx.isAdmin;
  const perHost = [];
  for (const host of hostsFor(ctx, selected)) {
    const domain = await resolveDomain(cfg, host);
    const dirs = admin ? null : await creatableDirectories(cfg, host, ctx.session.user.id);
    perHost.push({
      host,
      root: admin || (domain ? rootCreateAllowed(cfg, domain, ctx.session.user) : false),
      dirs,
      mayAddDir: await mayCreateAnyDirectory(cfg, { user: ctx.session.user, host }),
    });
  }

  const rightsRows = perHost
    .map(
      (h) => `<tr>
      <td>${esc(h.host)}</td>
      <td>${h.root ? 'Yes' : 'No'}</td>
      <td>${h.dirs === null ? 'All' : h.dirs.length ? esc(h.dirs.join(', ')) : '\u2014'}</td>
      <td>${h.mayAddDir ? 'Yes' : 'No'}</td>
    </tr>`
    )
    .join('');

  const body = `
${flashFrom(ctx.url)}
<h1>Overview</h1>
<p class="sub">Signed in as ${esc(ctx.session.user.email)}${
    admin ? ' with administrator rights on every domain' : ''
  }.</p>

<div class="card">
  <h2>Your most recent links</h2>
  ${
    rows
      ? `<div class="tablewrap"><table>
          <thead><tr><th>Short link</th><th>Destination</th><th>Code</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table></div>`
      : '<div class="empty">Nothing here yet.</div>'
  }
  <div class="actions">
    <a class="btn" href="/admin/links/new">Create a link</a>
    <a class="btn secondary" href="/admin/links">All your links</a>
  </div>
</div>

<div class="card">
  <h2>Where you can create</h2>
  <p class="hint">${
    admin
      ? 'You are an administrator, so nothing here is restricted.'
      : 'Ask an administrator if you need more.'
  }</p>
  <div class="tablewrap"><table>
    <thead><tr><th>Domain</th><th>Links at root</th><th>Directories you may use</th><th>May add directories</th></tr></thead>
    <tbody>${rightsRows}</tbody>
  </table></div>
  <dl class="kv">
    <dt>Account</dt><dd>${esc(ctx.session.user.emailNorm)}</dd>
    <dt>Last sign-in</dt><dd>${esc(fmtTime(ctx.session.user.lastLoginAt))}</dd>
  </dl>
</div>`;

  return adminPage(ctx, { title: 'Overview', nav: 'overview', body });
}

/* --------------------------------------------------------------- router */

/**
 * Dispatch an /admin request. The session is already resolved and guaranteed
 * present by the caller.
 */
export async function handleAdmin(ctx) {
  const path = ctx.url.pathname.replace(/\/+$/, '') || '/admin';

  if (path === '/admin') return overview(ctx);
  if (path.startsWith('/admin/links')) return adminLinks(ctx, path);
  if (path.startsWith('/admin/directories')) return adminDirectories(ctx, path);

  if (path.startsWith('/admin/domains')) {
    const gate = requireAdmin(ctx.cfg, ctx.session.user);
    if (!gate.allowed) return denied(ctx, gate.reason);
    return adminDomains(ctx, path);
  }
  if (
    path.startsWith('/admin/users') ||
    path.startsWith('/admin/settings') ||
    path.startsWith('/admin/audit')
  ) {
    const gate = requireAdmin(ctx.cfg, ctx.session.user);
    if (!gate.allowed) return denied(ctx, gate.reason);
    return adminUsers(ctx, path);
  }

  const page = messagePage({
    cfg: ctx.cfg,
    host: ctx.host,
    title: 'Not found',
    heading: 'Page not found',
    message: 'That administration page does not exist.',
    status: 404,
    actions: [{ href: '/admin', label: 'Back to overview' }],
  });
  return html(page.body, { status: 404 });
}

/** Shared helper: the CSRF token for a named form on the current page. */
export async function formToken(ctx, name) {
  return tokenFor(ctx, name);
}
