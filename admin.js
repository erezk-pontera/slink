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
import { listOwnedLinks } from './links.js';
import { requireAdmin } from './permissions.js';
import { esc, fmtTime } from './util.js';
import { alert, html, layout, messagePage } from './views.js';

/** Fixed flash messages, referenced by code so a URL cannot inject prose. */
export const MESSAGES = {
  'link.created': ['ok', 'Link created.'],
  'link.updated': ['ok', 'Link updated.'],
  'link.deleted': ['ok', 'Link deleted.'],
  'link.moved': ['ok', 'Link transferred.'],
  'dir.created': ['ok', 'Directory created.'],
  'dir.updated': ['ok', 'Directory updated.'],
  'dir.deleted': ['ok', 'Directory deleted.'],
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

/** Render an admin page inside the shared chrome. */
export function adminPage(ctx, { title, nav, body, status = 200 }) {
  return html(
    layout({
      title: title + ' - ' + ctx.cfg.appName,
      appName: ctx.cfg.appName,
      host: ctx.host,
      user: ctx.session.user,
      nav: adminNav(ctx, nav),
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
  const owned = await listOwnedLinks(cfg, ctx.session.user.id, { limit: 10 });
  const dirs = await creatableDirectories(cfg, ctx.host, ctx.session.user.id);

  const rows = owned.items
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

  const body = `
${flashFrom(ctx.url)}
<h1>Overview</h1>
<p class="sub">Signed in as ${esc(ctx.session.user.email)}${
    ctx.isAdmin ? ' with administrator rights' : ''
  }.</p>

<div class="card">
  <h2>Your most recent links</h2>
  <p class="hint">${owned.items.length ? '' : 'You have not created any links yet.'}</p>
  ${
    owned.items.length
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
  <p class="hint">On ${esc(ctx.host)}.</p>
  <dl class="kv">
    <dt>Root</dt><dd>${ctx.canCreateRoot ? 'Allowed' : 'Not allowed'}</dd>
    <dt>Directories</dt><dd>${dirs.length ? esc(dirs.join(', ')) : 'None granted'}</dd>
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
