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
  account = '',
  signOut = '',
  footerText = '',
}) {
  // Two groups, not one list: where you can go, and who you are. Signing
  // out and switching domain are things done to the account, so putting
  // them among the sections made them read as places.
  const navHtml = nav.length
    ? `<nav class="main" aria-label="Sections">${nav
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
  const acctHtml =
    account || whoHtml || signOut
      ? `<div class="acct">${account}${whoHtml}${
          signOut ? `<a class="signout" href="${esc(signOut)}">Sign out</a>` : ''
        }</div>`
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
  ${headerExtra || (!account && host ? `<span class="hostname">${esc(host)}</span>` : '')}
  ${navHtml}${acctHtml}
</div></header>
<main class="wrap${narrow ? ' narrow' : ''}">${body}</main>
<footer class="foot">${footer ? `<div>${footer}</div>` : ''}${
    // Set by FOOTER_TEXT. Escaped like any other configured string, and
    // the line is left out altogether when there is nothing to put in it.
    footerText ? `<div>${esc(footerText)}</div>` : ''
  }</footer>
<script src="${esc(JS_SRC)}" defer></script>
</body></html>`;
}

/** Build an HTML response with the hardened header set. */
export function html(bodyHtml, { status = 200, turnstile = false, store = false, externalImages = false, headers } = {}) {
  const res = new Response(bodyHtml, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...(headers || {}) },
  });
  return harden(res, { turnstile, store, externalImages });
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
  tooltip = '',
}) {
  return `<div class="field">
  <label for="f_${esc(name)}">${esc(label)}${tooltip ? hint(tooltip) : ''}</label>
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

export function select({ name, label, value, options, note = '', attrs = '', tooltip = '' }) {
  const opts = options
    .map(
      (o) =>
        `<option value="${esc(o.value)}"${String(o.value) === String(value) ? ' selected' : ''}${
          // A data attribute per option, for the few selects whose choices
          // belong to something else on the page.
          o.data ? ` data-${esc(o.data.name)}="${esc(o.data.value)}"` : ''
        }>${esc(o.label)}</option>`
    )
    .join('');
  return `<div class="field">
  <label for="f_${esc(name)}">${esc(label)}${tooltip ? hint(tooltip) : ''}</label>
  <select id="f_${esc(name)}" name="${esc(name)}" ${attrs}>${opts}</select>
  ${note ? `<p class="note">${esc(note)}</p>` : ''}
</div>`;
}

export function checkbox({ name, label, checked = false, note = '', disabled = false, tooltip = '' }) {
  return `<div class="check">
  <input id="f_${esc(name)}" name="${esc(name)}" type="checkbox" value="1"${checked ? ' checked' : ''}${
    disabled ? ' disabled' : ''
  }>
  <label for="f_${esc(name)}">${esc(label)}${note ? ` <span class="note">${esc(note)}</span>` : ''}</label>
  ${tooltip ? hint(tooltip) : ''}
</div>`;
}

/**
 * A hover-and-focus tooltip marker.
 *
 * `title` is what a mouse gets; `aria-label` and `tabindex` are what a
 * keyboard and a screen reader get, so the text is not mouse-only.
 */
export function hint(text) {
  return `<span class="tip" tabindex="0" role="note" title="${esc(text)}" aria-label="${esc(text)}">?</span>`;
}

/**
 * The small inline icons. Inline SVG rather than an icon font or a sprite:
 * no extra request, no flash of missing glyph, and `currentColor` means
 * they follow the theme without a second set for dark mode.
 */
const ICONS = {
  // A clipboard, not a second pair of sheets: copy and duplicate sit next
  // to each other in a row and two stacked-paper glyphs read as one icon.
  copy: '<path d="M7 4H5.5A1.5 1.5 0 0 0 4 5.5v11A1.5 1.5 0 0 0 5.5 18h9a1.5 1.5 0 0 0 1.5-1.5v-11A1.5 1.5 0 0 0 14.5 4H13"/><rect x="7" y="2.2" width="6" height="3.2" rx="1"/>',
  check: '<path d="M4 10.5 8 14.5 16 5.5"/>',
  // Two sheets and a plus, so it cannot be mistaken for copy-to-clipboard
  // sitting next to it in the same row.
  duplicate: '<path d="M4 13H3.5A1.5 1.5 0 0 1 2 11.5v-8A1.5 1.5 0 0 1 3.5 2h8A1.5 1.5 0 0 1 13 3.5V4"/><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M12 9.5v5M9.5 12h5"/>',
  external: '<path d="M8 4H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-3"/><path d="M12 3h5v5"/><path d="M9 11 17 3"/>',
};

export function icon(name, { cls = '' } = {}) {
  return `<svg class="ic${cls ? ' ' + esc(cls) : ''}" viewBox="0 0 20 20" width="16" height="16"
    fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"
    stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[name] || ''}</svg>`;
}

/**
 * Copy-to-clipboard as a button rather than a word.
 *
 * It carries both icons and the script swaps which one shows, so the
 * confirmation does not reflow the row. The accessible name says what is
 * being copied, since "Copy" on its own tells a screen reader nothing about
 * which row it belongs to.
 */
export function copyButton(value, { what = 'link', label = '' } = {}) {
  return `<button type="button" class="iconbtn${label ? ' haslabel' : ''}" data-copy="${esc(value)}"
  data-copied-label="Copied" title="Copy ${esc(what)}" aria-label="Copy ${esc(what)}"
  >${icon('copy', { cls: 'ic-idle' })}${icon('check', { cls: 'ic-done' })}${
    label ? `<span>${esc(label)}</span>` : ''
  }</button>`;
}

/** Status pill for a link or directory row. */
export function statusBadges(rec) {
  const out = [];
  if (rec.enabled === false) out.push('<span class="badge off">disabled</span>');
  if (rec.readonly) out.push('<span class="badge ro">read-only</span>');
  if (rec.activeFrom && rec.activeFrom > 0 && rec.activeFrom > Math.floor(Date.now() / 1000)) {
    out.push(`<span class="badge ro">starts ${esc(fmtTime(rec.activeFrom))}</span>`);
  }
  if (rec.expiresAt && rec.expiresAt > 0) {
    out.push(`<span class="badge">expires ${esc(fmtTime(rec.expiresAt))}</span>`);
  }
  return out.join(' ');
}

/**
 * A bar chart of daily hits as inline SVG. Inline markup, not script, so it
 * costs nothing in the content security policy and renders with JavaScript
 * off. Colours come from the theme tokens, so it follows light and dark.
 */
export function clickChart(series, { height = 56 } = {}) {
  if (!series || !series.length) return '';
  const peak = series.reduce((m, d) => Math.max(m, d.n), 0);
  if (!peak) {
    return '<p class="note">No hits recorded in this period.</p>';
  }
  const gap = 2;
  const barWidth = 6;
  const width = series.length * (barWidth + gap) - gap;
  const bars = series
    .map((d, i) => {
      const h = Math.max(1, Math.round((d.n / peak) * height));
      const x = i * (barWidth + gap);
      return `<rect x="${x}" y="${height - h}" width="${barWidth}" height="${h}" rx="1"><title>${esc(
        d.day
      )}: ${esc(d.n)}</title></rect>`;
    })
    .join('');
  return `<div class="chart">
  <svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img"
       preserveAspectRatio="none" aria-label="Daily hits, peak ${esc(peak)}">${bars}</svg>
  <p class="note">${esc(series[0].day)} to ${esc(series[series.length - 1].day)} &middot; peak ${esc(
    peak
  )} in a day</p>
</div>`;
}

export function pager(prevHref, nextHref) {
  const parts = [];
  if (prevHref) parts.push(`<a class="btn secondary" href="${esc(prevHref)}">Back</a>`);
  if (nextHref) parts.push(`<a class="btn secondary" href="${esc(nextHref)}">Next</a>`);
  return parts.length ? `<div class="pager">${parts.join('')}</div>` : '';
}

/* ---------------------------------------------------------------- sign-in */

export function loginPage({
  cfg,
  host,
  error,
  info,
  csrf,
  next,
  email = '',
  methods = { otp: true, oauth: false, passkey: false },
  ssoLabel = 'Single sign-on',
  passkeyCsrf = '',
}) {
  const ssoHref = '/__slink/oauth/start?r=' + encodeURIComponent(next || '/admin');
  const sso = methods.oauth
    ? `<div class="sso">
    <a class="btn" href="${esc(ssoHref)}">Continue with ${esc(ssoLabel)}</a>
  </div>`
    : '';

  // With the code switched off, single sign-on is the only way in and the
  // page should not present a form that cannot succeed.
  const rule = '<p class="divider"><span>or</span></p>';
  const divider = methods.oauth && methods.otp ? rule : '';

  // The whole passkey block stays hidden until the script has confirmed
  // this browser can use one, its own divider included, so a visitor
  // without JavaScript is never shown a stray rule above a control that
  // was never going to appear.
  const passkey =
    methods.passkey && passkeyCsrf
      ? `<div data-slink-passkey-login data-token="${esc(passkeyCsrf)}"
       data-next="${esc(next || '/admin')}" hidden>
    <div class="sso">
      <button type="button" class="btn secondary" data-slink-passkey-go>Sign in with a passkey</button>
    </div>
    <p class="hint" data-slink-passkey-msg role="status"></p>${methods.otp ? rule : ''}
  </div>`
      : '';
  const byEmail = methods.otp
    ? `<p class="sub">We will email you a ${cfg.settings.otpLength}-digit code.</p>
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
  </form>`
    : '';

  // Single sign-on alone, because the other two were switched off. They
  // are still open to administrators - that is the point of the exemption,
  // so an outage at the provider cannot lock out the people who would fix
  // it - but reaching them meant knowing to type `?otp=1`, which is a
  // password of a sort and a poor one. The route is named instead.
  //
  // Naming it tells nobody who the administrators are: everyone sees the
  // same link, is shown the same form, and gets the same answer back. Only
  // the code itself goes nowhere for somebody who is not one.
  const adminOnly =
    methods.oauth && !methods.otp && !methods.passkey
      ? `<p class="divider"><span>or</span></p>
  <p class="sub">Administrators keep the emailed code and passkeys for when
  ${esc(ssoLabel)} cannot be reached.
  <a href="${esc(
    '/admin?otp=1' + (next && next !== '/admin' ? '&next=' + encodeURIComponent(next) : '')
  )}">Other sign-in methods</a>.</p>`
      : '';

  const body = `
${alert('error', error)}${alert('info', info)}
<div class="card">
  <h1>Sign in</h1>
  ${sso}${passkey}${divider}${byEmail}${adminOnly}
  ${
    !methods.otp && !methods.oauth && !methods.passkey
      ? '<p class="sub">No sign-in method is available on this domain. An administrator needs to enable one.</p>'
      : ''
  }
</div>`;
  return layout({
    title: 'Sign in - ' + cfg.appName,
    appName: cfg.appName,
    footerText: cfg.footerText,
    host,
    body,
    narrow: true,
    turnstile: true,
  });
}

/**
 * The screen a visitor meets when a link is password-protected.
 *
 * Deliberately says as little as possible: no destination, no owner, no
 * shortcut beyond what is already in the address bar. A wrong answer and an
 * unknown link should look the same to someone probing.
 *
 * Autofill is turned off on the field. A link password is shared with a
 * group and typed once, not a credential a browser should remember, and a
 * saved one would hand the link to the next person at that machine.
 */
export function passwordPage({ cfg, host, path, error, csrf, next = '' }) {
  const body = `
${alert('error', error)}
<div class="card">
  <h1>This link is protected</h1>
  <p class="sub">Enter the password for <code>${esc(host)}/${esc(path)}</code>.</p>
  <form method="post" action="/${esc(path)}" data-no-busy autocomplete="off" data-slink-unlock>
    ${csrfField(csrf)}${hidden('slink-unlock', '1')}${next ? hidden('next', next) : ''}
    <div class="field">
      <label for="f_linkpw">Password</label>
      <input id="f_linkpw" name="password" type="password" required autofocus
        autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"
        data-lpignore="true" data-1p-ignore data-bwignore maxlength="128">
    </div>
    ${turnstileWidget(cfg.turnstileSiteKey, 'unlock')}
    <div class="actions"><button type="submit">Open the link</button></div>
  </form>
</div>`;
  return layout({
    title: 'Protected link - ' + cfg.appName,
    appName: cfg.appName,
    footerText: cfg.footerText,
    host,
    body,
    narrow: true,
    turnstile: true,
    homeHref: '/',
  });
}

/**
 * Deliver a destination inside a frame instead of redirecting to it.
 *
 * Whether this works at all is up to the destination: a site that sends
 * X-Frame-Options or a frame-ancestors policy will refuse, and there is
 * nothing this end can do about that. The page says so, visibly, because a
 * silent blank frame is the worst version of that failure.
 */
export function framePage({ cfg, host, link, url: target }) {
  const title = (link.preview && link.preview.title) || link.path;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<link rel="stylesheet" href="${ASSET_PREFIX}/app.css?v=${ASSET_VERSION}">
<link rel="icon" type="image/svg+xml" href="${ASSET_PREFIX}/logo.svg?v=${ASSET_VERSION}">
</head><body class="framed">
<iframe class="slink-frame" src="${esc(target)}" title="${esc(title)}"
  referrerpolicy="no-referrer" loading="eager"
  sandbox="allow-forms allow-popups allow-popups-to-escape-sandbox allow-same-origin allow-scripts"></iframe>
</body></html>`;
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
  <p class="hint">Check your spam folder, or ask for the same code again. It stays valid either way.</p>
  <form method="post" action="/admin" data-no-busy>
    ${csrfField(csrf)}${hidden('stage', 'resend')}
    ${turnstileWidget(cfg.turnstileSiteKey, 'resend')}
    <div class="actions tight"><button type="submit" class="secondary">Send it again</button></div>
  </form>
  <form method="post" action="/admin" class="actions">
    ${csrfField(csrf)}${hidden('stage', 'restart')}
    <button type="submit" class="secondary">Use a different address</button>
  </form>
</div>`;
  return layout({
    title: 'Verify - ' + cfg.appName,
    appName: cfg.appName,
    footerText: cfg.footerText,
    host,
    body,
    narrow: true,
    turnstile: true,
  });
}

/* ------------------------------------------------------------- interstitial */

/** The delayed redirect page. Works without JavaScript via meta refresh. */
export function interstitialPage({
  cfg,
  host,
  link,
  target,
  delay,
  showTarget = true,
  continueHref,
  returnHere = false,
}) {
  const home = adminUrl(cfg, host);
  // Where the page sends the visitor. With the destination hidden this is a
  // path on this host, so the real target appears nowhere in the markup.
  // A framed link comes back here too even when the destination is shown,
  // because leaving straight for it would skip the frame.
  const go = showTarget && !returnHere ? target : continueHref;

  const body = `
<div class="card center">
  <p class="hint">You are being redirected</p>
  <p class="count"><span data-slink-count>${esc(delay)}</span></p>
  ${
    showTarget
      ? `<p class="dest mono">${esc(target)}</p>`
      : '<p class="dest hint">The destination is not shown for this link.</p>'
  }
  <div class="actions" style="justify-content:center">
    <a class="btn" href="${esc(go)}" rel="noopener noreferrer nofollow">Go now</a>
  </div>
</div>
<div data-slink-redirect="${esc(go)}" data-slink-delay="${esc(delay)}" hidden></div>`;

  // The meta refresh is the no-script fallback; the counter above is cosmetic.
  const head = `<meta http-equiv="refresh" content="${esc(delay)};url=${esc(go)}">`;
  const page = layout({
    title: 'Redirecting - ' + cfg.appName,
    appName: cfg.appName,
    footerText: cfg.footerText,
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
      footerText: cfg.footerText,
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
    footerText: cfg.footerText,
    host,
    body,
    narrow: true,
    homeHref: '/',
  });
}
