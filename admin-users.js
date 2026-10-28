/**
 * admin-users.js - users, global settings and the audit log.
 *
 * All three are administrator-only; the caller gates on that before routing
 * here, and each handler re-checks so a direct POST cannot slip past.
 */

import { adminPage, back, denied, flashFrom, formToken, readForm } from './admin.js';
import { audit, EVENTS, listAudit } from './audit.js';
import { checkCsrf, destroyAllSessions } from './auth.js';
import { saveSettings } from './config.js';
import { listUserGrants } from './directories.js';
import { clientIp } from './geo.js';
import { PROVIDERS } from './mailer.js';
import { HARD_BLOCKED_SCHEMES, normalizeEmail, ValidationError } from './paths.js';
import { requireAdmin } from './permissions.js';
import { deleteUser, getUserByNorm, isRootAdmin, listUsers, putUser } from './users.js';
import { esc, fmtTime, intEnv, listEnv } from './util.js';
import { alert, checkbox, csrfField, field, hidden, select, textarea } from './views.js';

const ROOT_IMMUTABLE =
  'That account is a root administrator, set by the ADMIN variable. It always holds every ' +
  'permission and cannot be changed, disabled or deleted here. Edit ADMIN and redeploy instead.';

/* ----------------------------------------------------------------- users */

/**
 * Root administrators are configured in the ADMIN environment variable, hold
 * every permission unconditionally, and are not manageable from here at all:
 * they are left out of the list and every write that names one is refused.
 * Their authority comes from the deployment, so the UI must not suggest it
 * can be edited away.
 */
function isRootAccount(cfg, user) {
  return !!user && isRootAdmin(cfg, user.emailNorm);
}

async function usersPage(ctx, { error } = {}) {
  const { cfg, url } = ctx;
  const all = await listUsers(cfg);
  const users = all.filter((u) => !isRootAdmin(cfg, u.emailNorm));
  const hidden = all.length - users.length;

  const rows = users
    .map((u) => {
      return `<tr>
      <td>${esc(u.email)}
        ${u.isAdmin ? '<span class="badge ok">admin</span>' : ''}
        ${u.disabled ? '<span class="badge off">disabled</span>' : ''}
        ${u.emailNorm !== u.email ? `<div class="note">identity: ${esc(u.emailNorm)}</div>` : ''}
      </td>
      <td class="num">${esc(fmtTime(u.lastLoginAt))}</td>
      <td class="num">${esc(u.loginCount || 0)}</td>
      <td><a href="/admin/users/edit?u=${encodeURIComponent(u.emailNorm)}">Manage</a></td>
    </tr>`;
    })
    .join('');

  const body = `
${flashFrom(url)}${alert('error', error)}
<h1>Users</h1>
<p class="sub">Accounts are created the first time someone completes a sign-in.</p>
${
  hidden
    ? `<p class="sub">${hidden} root administrator${hidden === 1 ? ' is' : 's are'} not listed. They are set by the ADMIN variable, always hold every permission, and cannot be changed, disabled or deleted from here — edit ADMIN and redeploy instead.</p>`
    : ''
}

<div class="card">
  ${
    users.length
      ? `<div class="tablewrap"><table><thead><tr><th>User</th><th>Last sign-in</th><th>Sign-ins</th><th></th></tr></thead>
         <tbody>${rows}</tbody></table></div>`
      : '<div class="empty">No users yet.</div>'
  }
</div>`;

  return adminPage(ctx, { title: 'Users', nav: 'users', body });
}

async function userEditForm(ctx, { error } = {}) {
  const { cfg, url } = ctx;
  const emailNorm = String(url.searchParams.get('u') || '').toLowerCase();
  const user = await getUserByNorm(cfg, emailNorm);
  if (!user) return back('/admin/users', 'notfound');
  if (isRootAccount(cfg, user)) return denied(ctx, ROOT_IMMUTABLE);

  const root = false;
  const grants = await listUserGrants(cfg, user.id);
  const token = await formToken(ctx, 'user.update');
  const revokeToken = await formToken(ctx, 'user.revoke');
  const deleteToken = await formToken(ctx, 'user.delete');

  // Per-domain grants. An administrator already holds all of these, so the
  // boxes render ticked and disabled rather than implying a restriction.
  const isAdminAccount = root || !!user.isAdmin;
  const perDomainBoxes = cfg.knownHosts
    .map(
      (h) => `<fieldset class="grants">
        <legend class="note">${esc(h)}</legend>
        ${checkbox({
          name: 'root__' + h,
          label: 'May create links at the root',
          checked: isAdminAccount || !!(user.rootCreate && user.rootCreate[h]),
          disabled: isAdminAccount,
          note: isAdminAccount ? '(administrator)' : '',
        })}
        ${checkbox({
          name: 'dir__' + h,
          label: 'May create directories',
          checked: isAdminAccount || !!(user.dirCreate && user.dirCreate[h]),
          disabled: isAdminAccount,
          note: isAdminAccount ? '(administrator)' : '',
        })}
      </fieldset>`
    )
    .join('');

  const grantList = grants.length
    ? grants
        .map(
          (g) =>
            `<li>${esc(g.host)}/${esc(g.dirPathLc)} &mdash; ${g.canManage ? 'directory administrator' : 'create'}</li>`
        )
        .join('')
    : '<li>None</li>';

  const body = `
${flashFrom(url)}${alert('error', error)}
<h1>${esc(user.email)}</h1>
<p class="sub">Identity <code>${esc(user.emailNorm)}</code> &middot; joined ${esc(fmtTime(user.createdAt))}</p>

<div class="card">
  <h2>Privileges</h2>
  <form method="post" action="/admin/users/edit">
    ${csrfField(token)}${hidden('u', user.emailNorm)}
    ${checkbox({
      name: 'isAdmin',
      label: 'Administrator',
      checked: root || !!user.isAdmin,
      disabled: root,
      note: root ? '(set by the ADMIN variable)' : '(full control over everything)',
    })}
    ${checkbox({
      name: 'disabled',
      label: 'Disabled',
      checked: !!user.disabled,
      disabled: root,
      note: root ? '(root administrators cannot be disabled)' : '(blocks sign-in and revokes access)',
    })}
    ${perDomainBoxes}
    ${textarea({ name: 'note', label: 'Note', value: user.note || '' })}
    <div class="actions">
      <button type="submit">Save</button>
      <a class="btn secondary" href="/admin/users">Back</a>
    </div>
  </form>
</div>

<div class="card">
  <h2>Directory access</h2>
  <ul>${grantList}</ul>
  <p class="hint">Change these from the directory's own page.</p>
</div>

<div class="card">
  <h2>Sessions</h2>
  <p class="hint">Signs this user out of every host immediately.</p>
  <form method="post" action="/admin/users/revoke">
    ${csrfField(revokeToken)}${hidden('u', user.emailNorm)}
    <div class="actions"><button type="submit" class="secondary">Revoke all sessions</button></div>
  </form>
</div>

${
  root
    ? ''
    : `<div class="card">
  <h2>Delete</h2>
  <p class="hint">Removes the account. Links they own stay in place and keep pointing at the deleted owner, so reassign them first.</p>
  <form method="post" action="/admin/users/delete" data-confirm="Delete ${esc(user.email)}?">
    ${csrfField(deleteToken)}${hidden('u', user.emailNorm)}
    <div class="actions"><button type="submit" class="danger">Delete user</button></div>
  </form>
</div>`
}`;

  return adminPage(ctx, { title: user.email, nav: 'users', body });
}

async function userEditSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/users', 'csrf');
  const guard = await checkCsrf(ctx, 'user.update', body);
  if (!guard.ok) return back('/admin/users', 'csrf');

  const emailNorm = String(body.get('u') || '').toLowerCase();
  const user = await getUserByNorm(ctx.cfg, emailNorm);
  if (!user) return back('/admin/users', 'notfound');
  if (isRootAccount(ctx.cfg, user)) return denied(ctx, ROOT_IMMUTABLE);

  const root = false;
  if (!root) {
    user.isAdmin = body.get('isAdmin') === '1';
    user.disabled = body.get('disabled') === '1';
  }
  // An administrator's boxes render disabled, so a browser submits none of
  // them. Leaving the stored grants untouched keeps them intact if the
  // account is later demoted, rather than silently clearing them on save.
  if (!root && !user.isAdmin) {
    const rootCreate = {};
    const dirCreate = {};
    for (const host of ctx.cfg.knownHosts) {
      if (body.get('root__' + host) === '1') rootCreate[host] = true;
      if (body.get('dir__' + host) === '1') dirCreate[host] = true;
    }
    user.rootCreate = rootCreate;
    user.dirCreate = dirCreate;
  }
  user.note = String(body.get('note') || '').slice(0, 500);
  await putUser(ctx.cfg, user);

  // A disabled account must lose its live sessions at once.
  if (user.disabled) await destroyAllSessions(ctx.cfg, user.id);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.userUpdated,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: user.emailNorm,
      detail: {
        isAdmin: user.isAdmin,
        disabled: user.disabled,
        rootCreate: user.rootCreate,
        dirCreate: user.dirCreate,
      },
    })
  );
  return back('/admin/users/edit?u=' + encodeURIComponent(user.emailNorm), 'user.updated');
}

async function userRevokeSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/users', 'csrf');
  const guard = await checkCsrf(ctx, 'user.revoke', body);
  if (!guard.ok) return back('/admin/users', 'csrf');

  const emailNorm = String(body.get('u') || '').toLowerCase();
  const user = await getUserByNorm(ctx.cfg, emailNorm);
  if (!user) return back('/admin/users', 'notfound');
  if (isRootAccount(ctx.cfg, user)) return denied(ctx, ROOT_IMMUTABLE);
  const count = await destroyAllSessions(ctx.cfg, user.id);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.userUpdated,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: user.emailNorm,
      detail: { revokedSessions: count },
    })
  );
  return back('/admin/users/edit?u=' + encodeURIComponent(user.emailNorm), 'sessions.revoked');
}

async function userDeleteSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/users', 'csrf');
  const guard = await checkCsrf(ctx, 'user.delete', body);
  if (!guard.ok) return back('/admin/users', 'csrf');

  const emailNorm = String(body.get('u') || '').toLowerCase();
  const user = await getUserByNorm(ctx.cfg, emailNorm);
  if (!user) return back('/admin/users', 'notfound');
  if (isRootAccount(ctx.cfg, user)) return denied(ctx, ROOT_IMMUTABLE);

  await destroyAllSessions(ctx.cfg, user.id);
  await deleteUser(ctx.cfg, user);
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.userDeleted,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: user.emailNorm,
    })
  );
  return back('/admin/users', 'user.deleted');
}

/* -------------------------------------------------------------- settings */

async function settingsPage(ctx, { error } = {}) {
  const { cfg, url } = ctx;
  const s = cfg.settings;
  const token = await formToken(ctx, 'settings.update');
  const geo = s.geo || {};
  const limits = s.rateLimits || {};

  const body = `
${flashFrom(url)}${alert('error', error)}
<h1>Settings</h1>
<p class="sub">These override the matching environment variables. Secrets are not editable here.</p>

<div class="card">
  <form method="post" action="/admin/settings">
    ${csrfField(token)}

    <h2>Sign-in codes</h2>
    <div class="row">
      ${field({ name: 'otpLength', label: 'Code length', type: 'number', value: s.otpLength, attrs: 'min="4" max="10"' })}
      ${field({ name: 'otpTtlSeconds', label: 'Code lifetime (seconds)', type: 'number', value: s.otpTtlSeconds, attrs: 'min="30" max="3600"' })}
      ${field({ name: 'otpMaxAttempts', label: 'Attempts per code', type: 'number', value: s.otpMaxAttempts, attrs: 'min="1" max="20"' })}
      ${field({ name: 'otpResendSeconds', label: 'Resend cooldown (seconds)', type: 'number', value: s.otpResendSeconds, attrs: 'min="10" max="600"' })}
    </div>

    <h2>Sessions</h2>
    <div class="row">
      ${field({
        name: 'sessionTtlSeconds',
        label: 'Session lifetime (seconds)',
        type: 'number',
        value: s.sessionTtlSeconds,
        attrs: 'min="60"',
        note: '604800 is one week.',
      })}
      ${field({
        name: 'sessionIdleSeconds',
        label: 'Idle timeout (seconds)',
        type: 'number',
        value: s.sessionIdleSeconds || 0,
        attrs: 'min="0"',
        note: '0 disables the idle timeout.',
      })}
    </div>
    ${checkbox({ name: 'sessionPermanent', label: 'Keep sessions signed in indefinitely', checked: !!s.sessionPermanent, note: '(overrides the lifetime above)' })}
    ${checkbox({ name: 'bindSessionToUa', label: 'Invalidate a session if the browser user-agent changes', checked: !!s.bindSessionToUa })}
    ${checkbox({ name: 'bindSessionToIp', label: 'Invalidate a session if the client IP changes', checked: !!s.bindSessionToIp, note: '(breaks roaming between networks)' })}

    <h2>Identity</h2>
    ${checkbox({ name: 'ignoreEmailDot', label: 'Ignore dots in the local part of an address', checked: !!cfg.ignoreEmailDot, note: '(a.a@x.com is a.a@x.com and aa@x.com)' })}
    ${checkbox({ name: 'ignoreEmailPlus', label: 'Ignore +tag suffixes', checked: !!cfg.ignoreEmailPlus, note: '(aa+bb@cc.com becomes aa@cc.com)' })}

    <h2>Where sign-in is allowed</h2>
    ${checkbox({ name: 'geoBlockTor', label: 'Refuse sign-in from Tor exit nodes', checked: geo.blockTor !== false })}
    ${checkbox({ name: 'geoBlockUnknown', label: 'Refuse sign-in when the country is unknown', checked: geo.blockUnknown !== false })}
    <div class="row">
      ${select({
        name: 'geoMode',
        label: 'Country rule',
        value: geo.mode || 'off',
        options: [
          { value: 'off', label: 'No country rule' },
          { value: 'allow', label: 'Only the countries listed' },
          { value: 'block', label: 'Every country except those listed' },
        ],
      })}
      ${field({ name: 'geoCountries', label: 'Countries', value: (geo.countries || []).join(', '), placeholder: 'IL, US, GB', note: 'Two-letter codes, comma separated.' })}
      ${select({
        name: 'geoApplyTo',
        label: 'Apply to',
        value: geo.applyTo || 'login',
        options: [
          { value: 'login', label: 'Sign-in only' },
          { value: 'all', label: 'Every authenticated request' },
        ],
      })}
    </div>

    <h2>Limits</h2>
    <div class="row">
      ${field({ name: 'rlOtpIp', label: 'Codes per IP', type: 'number', value: limits.otpRequestPerIp, attrs: 'min="1"' })}
      ${field({ name: 'rlOtpEmail', label: 'Codes per address', type: 'number', value: limits.otpRequestPerEmail, attrs: 'min="1"' })}
      ${field({ name: 'rlOtpVerify', label: 'Verifications per sign-in', type: 'number', value: limits.otpVerifyPerLogin, attrs: 'min="1"' })}
      ${field({ name: 'rlWindow', label: 'Window (seconds)', type: 'number', value: limits.otpWindowSeconds, attrs: 'min="60"' })}
    </div>

    <h2>Links</h2>
    ${field({
      name: 'blockedSchemes',
      label: 'Additional blocked destination schemes',
      value: (s.blockedSchemes || []).join(', '),
      note: 'Always blocked regardless: ' + HARD_BLOCKED_SCHEMES.join(', ') + '.',
    })}
    ${checkbox({ name: 'countClicks', label: 'Count hits on each link', checked: s.countClicks !== false, note: '(approximate)' })}
    ${field({ name: 'auditRetentionDays', label: 'Audit retention (days)', type: 'number', value: s.auditRetentionDays, attrs: 'min="1" max="3650"' })}

    <h2>Mail</h2>
    <div class="row">
      ${field({
        name: 'mailFromName',
        label: 'Sender name',
        value: s.mail.fromName || '',
        placeholder: cfg.appName,
        note: 'Blank uses the application name.',
      })}
      ${field({ name: 'mailReplyTo', label: 'Reply-to (optional)', type: 'email', value: s.mail.replyTo || '' })}
    </div>
    ${field({ name: 'mailSubject', label: 'Subject template', value: s.mail.subject || '', note: 'Placeholders: {{app}}, {{code}}, {{host}}.' })}
    <p class="note">Provider <code>${esc(cfg.mailProvider)}</code> sending as <code>${esc(cfg.mailFrom)}</code>. Both are set by environment variables (MAIL_PROVIDER, MAIL_FROM); available providers: ${esc(PROVIDERS.join(', '))}.</p>

    <div class="actions"><button type="submit">Save settings</button></div>
  </form>
</div>`;

  return adminPage(ctx, { title: 'Settings', nav: 'settings', body });
}

async function settingsSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/settings', 'csrf');
  const guard = await checkCsrf(ctx, 'settings.update', body);
  if (!guard.ok) return back('/admin/settings', 'csrf');

  const num = (name, fallback, min, max) => intEnv(body.get(name), fallback, min, max);
  const s = ctx.cfg.settings;

  let replyTo = '';
  const rawReply = String(body.get('mailReplyTo') || '').trim();
  if (rawReply) {
    try {
      replyTo = normalizeEmail(rawReply, { ignoreDot: false, ignorePlus: false }).email;
    } catch (err) {
      if (err instanceof ValidationError) return settingsPage(ctx, { error: 'Reply-to: ' + err.message });
      throw err;
    }
  }

  const patch = {
    otpLength: num('otpLength', s.otpLength, 4, 10),
    otpTtlSeconds: num('otpTtlSeconds', s.otpTtlSeconds, 30, 3600),
    otpMaxAttempts: num('otpMaxAttempts', s.otpMaxAttempts, 1, 20),
    otpResendSeconds: num('otpResendSeconds', s.otpResendSeconds, 10, 600),
    sessionTtlSeconds: num('sessionTtlSeconds', s.sessionTtlSeconds, 60, 10 * 365 * 24 * 3600),
    sessionIdleSeconds: num('sessionIdleSeconds', 0, 0, 10 * 365 * 24 * 3600),
    sessionPermanent: body.get('sessionPermanent') === '1',
    bindSessionToUa: body.get('bindSessionToUa') === '1',
    bindSessionToIp: body.get('bindSessionToIp') === '1',
    ignoreEmailDot: body.get('ignoreEmailDot') === '1',
    ignoreEmailPlus: body.get('ignoreEmailPlus') === '1',
    countClicks: body.get('countClicks') === '1',
    auditRetentionDays: num('auditRetentionDays', s.auditRetentionDays, 1, 3650),
    blockedSchemes: listEnv(body.get('blockedSchemes')),
    geo: {
      blockTor: body.get('geoBlockTor') === '1',
      blockUnknown: body.get('geoBlockUnknown') === '1',
      mode: ['off', 'allow', 'block'].includes(String(body.get('geoMode'))) ? String(body.get('geoMode')) : 'off',
      countries: listEnv(body.get('geoCountries')).map((c) => c.toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c)),
      applyTo: body.get('geoApplyTo') === 'all' ? 'all' : 'login',
    },
    rateLimits: {
      ...s.rateLimits,
      otpRequestPerIp: num('rlOtpIp', s.rateLimits.otpRequestPerIp, 1, 1000),
      otpRequestPerEmail: num('rlOtpEmail', s.rateLimits.otpRequestPerEmail, 1, 1000),
      otpVerifyPerLogin: num('rlOtpVerify', s.rateLimits.otpVerifyPerLogin, 1, 100),
      otpWindowSeconds: num('rlWindow', s.rateLimits.otpWindowSeconds, 60, 86400),
    },
    mail: {
      ...s.mail,
      fromName: String(body.get('mailFromName') || '').slice(0, 80),
      replyTo,
      subject: String(body.get('mailSubject') || '').slice(0, 200),
    },
  };

  await saveSettings(ctx.cfg, patch);
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.settingsUpdated,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      detail: { geo: patch.geo, sessionPermanent: patch.sessionPermanent },
    })
  );
  return back('/admin/settings', 'settings.updated');
}

/* ----------------------------------------------------------------- audit */

async function auditPage(ctx) {
  const cursor = ctx.url.searchParams.get('c') || undefined;
  const page = await listAudit(ctx.cfg, { cursor, limit: 100 });

  const rows = page.items
    .map(
      (e) => `<tr>
      <td class="num">${esc(fmtTime(e.ts))}</td>
      <td>${esc(e.event)}${e.outcome && e.outcome !== 'ok' ? ` <span class="badge off">${esc(e.outcome)}</span>` : ''}</td>
      <td>${esc(e.actor || '—')}</td>
      <td>${esc(e.host || '—')}${e.object ? '/' + esc(e.object) : ''}</td>
      <td><span class="target" title="${esc(JSON.stringify(e.detail || {}))}">${esc(
        e.detail ? JSON.stringify(e.detail) : ''
      )}</span></td>
    </tr>`
    )
    .join('');

  const body = `
${flashFrom(ctx.url)}
<h1>Audit</h1>
<p class="sub">Newest first. Entries expire after ${esc(ctx.cfg.settings.auditRetentionDays)} days. Client IPs are stored only as a hash.</p>
<div class="card">
  ${
    page.items.length
      ? `<div class="tablewrap"><table><thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Object</th><th>Detail</th></tr></thead>
         <tbody>${rows}</tbody></table></div>`
      : '<div class="empty">Nothing recorded yet.</div>'
  }
  ${
    page.cursor
      ? `<div class="pager"><a class="btn secondary" href="/admin/audit?c=${encodeURIComponent(page.cursor)}">Next</a></div>`
      : ''
  }
</div>`;

  return adminPage(ctx, { title: 'Audit', nav: 'audit', body });
}

/* --------------------------------------------------------------- router */

export async function adminUsers(ctx, path) {
  const gate = requireAdmin(ctx.cfg, ctx.session.user);
  if (!gate.allowed) return denied(ctx, gate.reason);

  const method = ctx.request.method;
  if (path === '/admin/users') return usersPage(ctx);
  if (path === '/admin/users/edit') return method === 'POST' ? userEditSubmit(ctx) : userEditForm(ctx);
  if (path === '/admin/users/revoke' && method === 'POST') return userRevokeSubmit(ctx);
  if (path === '/admin/users/delete' && method === 'POST') return userDeleteSubmit(ctx);
  if (path === '/admin/settings') return method === 'POST' ? settingsSubmit(ctx) : settingsPage(ctx);
  if (path === '/admin/audit') return auditPage(ctx);
  return back('/admin');
}
