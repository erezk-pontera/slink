/**
 * views.js - server-rendered HTML.
 *
 * Every interpolated value goes through esc(). No inline <script> is ever
 * emitted; behaviour comes from the external asset and `data-` attributes.
 */

import { ASSET_PREFIX, ASSET_VERSION } from './assets.js';
import { harden } from './security.js';
import { turnstileScriptTag, turnstileWidget } from './turnstile.js';
import { esc, fmtTime } from './util.js';

const CSS_HREF = `${ASSET_PREFIX}/app.css?v=${ASSET_VERSION}`;
const JS_SRC = `${ASSET_PREFIX}/app.js?v=${ASSET_VERSION}`;
const ICON_HREF = `${ASSET_PREFIX}/logo.svg?v=${ASSET_VERSION}`;

/**
 * Where /admin lives as seen from `host`. Only the hub serves the admin area,
 * so a page rendered on a short-link host must link to it absolutely.
 */
export function adminUrl(cfg, host) {
  return host === cfg.hubHost ? '/admin' : 'https://' + cfg.hubHost + '/admin';
}

/** Wrap a body fragment in the page chrome. */
export function layout({
  title,
  appName = 'Shrink Link',
  body,
  user = null,
  nav = [],
  turnstile = false,
  narrow = false,
  host = '',
  footer = '',
  homeHref = '/admin',
  headerExtra = '',
}) {
  const navHtml = nav.length
    ? `<nav class="main">${nav
        .map(
          (item) =>
            `<a href="${esc(item.href)}"${item.current ? ' aria-current="page"' : ''}>${esc(
              item.label
            )}</a>`
        )
        .join('')}</nav>`
    : '';

  const whoHtml = user
    ? `<span class="who">${esc(user.email || user.emailNorm)}${
        user.isAdminEffective ? ' <span class="badge ok">admin</span>' : ''
      }</span>`
    : '';

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title>
<link rel="stylesheet" href="${esc(CSS_HREF)}">
<link rel="icon" type="image/svg+xml" href="${esc(ICON_HREF)}">
<link rel="apple-touch-icon" href="${esc(ICON_HREF)}">
${turnstile ? turnstileScriptTag() : ''}
</head><body>
<header class="top"><div class="wrap">
  <a class="brand" href="${esc(homeHref)}">${esc(appName)}</a>
  ${headerExtra || (host ? `<span class="hostname">${esc(host)}</span>` : '')}
  ${navHtml}${whoHtml}
</div></header>
<main class="wrap${narrow ? ' narrow' : ''}">${body}</main>
<footer class="foot">${footer ? `<div>${footer}</div>` : ''}<div>&copy; Pontera Solutions Inc. All rights reserved</div></footer>
<script src="${esc(JS_SRC)}" defer></script>
</body></html>`;
}

/** Build an HTML response with the hardened header set. */
export function html(bodyHtml, { status = 200, turnstile = false, headers } = {}) {
  const res = new Response(bodyHtml, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...(headers || {}) },
  });
  return harden(res, { turnstile });
}

export function alert(kind, message) {
  if (!message) return '';
  const cls = kind === 'error' ? 'err' : kind === 'ok' ? 'ok' : 'info';
  return `<div class="alert ${cls}" role="${kind === 'error' ? 'alert' : 'status'}">${esc(message)}</div>`;
}

export function csrfField(token) {
  return `<input type="hidden" name="_csrf" value="${esc(token)}">`;
}

export function hidden(name, value) {
  if (value === null || value === undefined) return '';
  return `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
}

/** A labelled input with an optional help note. */
export function field({
  name,
  label,
  value = '',
  type = 'text',
  note = '',
  placeholder = '',
  required = false,
  attrs = '',
  autocomplete,
}) {
  return `<div class="field">
  <label for="f_${esc(name)}">${esc(label)}</label>
  <input id="f_${esc(name)}" name="${esc(name)}" type="${esc(type)}" value="${esc(value)}"
    ${placeholder ? `placeholder="${esc(placeholder)}"` : ''}
    ${required ? 'required' : ''}
    ${autocomplete ? `autocomplete="${esc(autocomplete)}"` : ''} ${attrs}>
  ${note ? `<p class="note">${esc(note)}</p>` : ''}
</div>`;
}

export function textarea({ name, label, value = '', note = '', placeholder = '' }) {
  return `<div class="field">
  <label for="f_${esc(name)}">${esc(label)}</label>
  <textarea id="f_${esc(name)}" name="${esc(name)}" ${
    placeholder ? `placeholder="${esc(placeholder)}"` : ''
  }>${esc(value)}</textarea>
  ${note ? `<p class="note">${esc(note)}</p>` : ''}
</div>`;
}

export function select({ name, label, value, options, note = '' }) {
  const opts = options
    .map(
      (o) =>
        `<option value="${esc(o.value)}"${String(o.value) === String(value) ? ' selected' : ''}>${esc(
          o.label
        )}</option>`
    )
    .join('');
  return `<div class="field">
  <label for="f_${esc(name)}">${esc(label)}</label>
  <select id="f_${esc(name)}" name="${esc(name)}">${opts}</select>
  ${note ? `<p class="note">${esc(note)}</p>` : ''}
</div>`;
}

export function checkbox({ name, label, checked = false, note = '', disabled = false }) {
  return `<div class="check">
  <input id="f_${esc(name)}" name="${esc(name)}" type="checkbox" value="1"${checked ? ' checked' : ''}${
    disabled ? ' disabled' : ''
  }>
  <label for="f_${esc(name)}">${esc(label)}${note ? ` <span class="note">${esc(note)}</span>` : ''}</label>
</div>`;
}

/** Status pill for a link or directory row. */
export function statusBadges(rec) {
  const out = [];
  if (rec.enabled === false) out.push('<span class="badge off">disabled</span>');
  if (rec.readonly) out.push('<span class="badge ro">read-only</span>');
  if (rec.expiresAt && rec.expiresAt > 0) {
    out.push(`<span class="badge">expires ${esc(fmtTime(rec.expiresAt))}</span>`);
  }
  return out.join(' ');
}

export function pager(prevHref, nextHref) {
  const parts = [];
  if (prevHref) parts.push(`<a class="btn secondary" href="${esc(prevHref)}">Back</a>`);
  if (nextHref) parts.push(`<a class="btn secondary" href="${esc(nextHref)}">Next</a>`);
  return parts.length ? `<div class="pager">${parts.join('')}</div>` : '';
}

/* ---------------------------------------------------------------- sign-in */

export function loginPage({ cfg, host, error, info, csrf, next, email = '' }) {
  const body = `
${alert('error', error)}${alert('info', info)}
<div class="card">
  <h1>Sign in</h1>
  <p class="sub">We will email you a ${cfg.settings.otpLength}-digit code.</p>
  <form method="post" action="/admin" data-no-busy>
    ${csrfField(csrf)}${hidden('stage', 'email')}${hidden('next', next)}
    ${field({
      name: 'email',
      label: 'Work email',
      type: 'email',
      value: email,
      required: true,
      autocomplete: 'email',
      placeholder: 'you@example.com',
    })}
    ${turnstileWidget(cfg.turnstileSiteKey, 'login')}
    <div class="actions"><button type="submit">Send code</button></div>
  </form>
</div>`;
  return layout({
    title: 'Sign in - ' + cfg.appName,
    appName: cfg.appName,
    host,
    body,
    narrow: true,
    turnstile: true,
  });
}

export function verifyPage({ cfg, host, error, info, csrf, email, expiresIn }) {
  const len = cfg.settings.otpLength || 6;
  const body = `
${alert('error', error)}${alert('info', info)}
<div class="card">
  <h1>Enter your code</h1>
  <p class="sub">Sent to ${esc(email)}${
    expiresIn ? ` &middot; expires in ${Math.max(1, Math.round(expiresIn / 60))} min` : ''
  }</p>
  <form method="post" action="/admin" data-no-busy>
    ${csrfField(csrf)}${hidden('stage', 'code')}
    <div class="field">
      <label for="f_code">Verification code</label>
      <input id="f_code" class="otp" name="code" type="text" inputmode="numeric"
        autocomplete="one-time-code" maxlength="${len}" required data-slink-code
        pattern="[0-9]{${len}}" aria-label="${len} digit code">
    </div>
    ${turnstileWidget(cfg.turnstileSiteKey, 'otp')}
    <div class="actions"><button type="submit">Verify</button></div>
  </form>
</div>
<div class="card">
  <h2>Did not get it?</h2>
  <p class="hint">Check your spam folder, or request a new code.</p>
  <form method="post" action="/admin" class="actions tight">
    ${csrfField(csrf)}${hidden('stage', 'resend')}
    <button type="submit" class="secondary">Send a new code</button>
  </form>
  <form method="post" action="/admin" class="actions">
    ${csrfField(csrf)}${hidden('stage', 'restart')}
    <button type="submit" class="secondary">Use a different address</button>
  </form>
</div>`;
  return layout({
    title: 'Verify - ' + cfg.appName,
    appName: cfg.appName,
    host,
    body,
    narrow: true,
    turnstile: true,
  });
}

/* ------------------------------------------------------------- interstitial */

/** The delayed redirect page. Works without JavaScript via meta refresh. */
export function interstitialPage({ cfg, host, link, target, delay }) {
  const home = adminUrl(cfg, host);
  const body = `
<div class="card center">
  <p class="hint">You are being redirected</p>
  <p class="count"><span data-slink-count>${esc(delay)}</span></p>
  <p class="dest mono">${esc(target)}</p>
  <div class="actions" style="justify-content:center">
    <a class="btn" href="${esc(target)}" rel="noopener noreferrer nofollow">Go now</a>
  </div>
</div>
<div data-slink-redirect="${esc(target)}" data-slink-delay="${esc(delay)}" hidden></div>`;

  // The meta refresh is the no-script fallback; the counter above is cosmetic.
  const head = `<meta http-equiv="refresh" content="${esc(delay)};url=${esc(target)}">`;
  const page = layout({
    title: 'Redirecting - ' + cfg.appName,
    appName: cfg.appName,
    host,
    body,
    narrow: true,
    footer: esc(host + '/' + link.path),
    homeHref: home,
  });
  return page.replace('</head>', head + '</head>');
}

/* -------------------------------------------------------------- messages */

export function messagePage({ cfg, host, title, heading, message, status = 200, actions = [] }) {
  const body = `
<div class="card">
  <h1>${esc(heading)}</h1>
  <p class="sub">${esc(message)}</p>
  ${
    actions.length
      ? `<div class="actions">${actions
          .map((a) => `<a class="btn ${esc(a.kind || 'secondary')}" href="${esc(a.href)}">${esc(a.label)}</a>`)
          .join('')}</div>`
      : ''
  }
</div>`;
  return {
    body: layout({
      title: title + ' - ' + cfg.appName,
      appName: cfg.appName,
      host,
      body,
      narrow: true,
      homeHref: adminUrl(cfg, host),
    }),
    status,
  };
}

/** Landing page for a host root with no configured redirect. */
/**
 * The host root, when no redirect is configured anywhere. It deliberately
 * offers no way in: administration is reached by going to /admin on the hub,
 * and a short-link host should not advertise that a sign-in exists.
 */
export function landingPage({ cfg, host }) {
  const body = `
<div class="card">
  <h1>${esc(cfg.appName)}</h1>
  <p class="sub">Short links for ${esc(host)}.</p>
</div>`;
  return layout({
    title: cfg.appName,
    appName: cfg.appName,
    host,
    body,
    narrow: true,
    homeHref: '/',
  });
}
