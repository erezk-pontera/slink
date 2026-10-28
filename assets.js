/**
 * assets.js - the stylesheet and script served as same-origin static files.
 *
 * Keeping these out of the HTML is what lets the CSP forbid inline script
 * entirely. Page-specific values reach the script through `data-` attributes.
 */

import { LOGO_SVG } from './logo.js';

export const ASSET_PREFIX = '/__slink';

/** Bumped whenever the asset bodies change; used for immutable caching. */
export const ASSET_VERSION = '4';

export const CSS = `
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#15181d; --muted:#5c6470; --line:#e2e5ea;
  --accent:#2f6df6; --accent-ink:#ffffff; --danger:#c0392b; --ok:#1b7f4b; --warn:#9a6700;
  --radius:10px; --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0f1216; --panel:#171b21; --ink:#e8eaed; --muted:#9aa4b2; --line:#262c35;
    --accent:#5b8dff; --accent-ink:#0b0e12; --danger:#ff6b5e; --ok:#4ade80; --warn:#fbbf24;
    --shadow:0 1px 2px rgba(0,0,0,.4);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-text-size-adjust:100%}
a{color:var(--accent)}
code,kbd,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1040px;margin:0 auto;padding:16px}
.narrow{max-width:440px}
header.top{border-bottom:1px solid var(--line);background:var(--panel)}
header.top .wrap{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding-top:12px;padding-bottom:12px}
.brand{font-weight:650;letter-spacing:-.01em;text-decoration:none;color:var(--ink)}
.brand span{color:var(--muted);font-weight:400}
nav.main{display:flex;gap:4px;flex-wrap:wrap;margin-left:auto;align-items:center}
nav.main a{padding:6px 10px;border-radius:7px;text-decoration:none;color:var(--muted);font-size:14px}
nav.main a:hover{background:var(--bg);color:var(--ink)}
nav.main a[aria-current=page]{background:var(--bg);color:var(--ink);font-weight:550}
.who{font-size:13px;color:var(--muted);white-space:nowrap}
.hostname{font-size:13px;color:var(--muted)}
.hostpick{display:flex;gap:6px;align-items:center}
.hostpick select{width:auto;min-width:9.5rem;padding:5px 8px;font-size:13px;border-radius:7px}
.hostpick .nojs{padding:5px 10px;font-size:13px}
.js .hostpick .nojs{display:none}
.visually-hidden{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;
  clip:rect(0 0 0 0);white-space:nowrap;border:0}
.badge{display:inline-block;padding:1px 7px;border-radius:999px;border:1px solid var(--line);
  font-size:11.5px;color:var(--muted);vertical-align:middle}
.badge.ok{color:var(--ok);border-color:currentColor}
.badge.ro{color:var(--warn);border-color:currentColor}
.badge.off{color:var(--danger);border-color:currentColor}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:18px;margin:0 0 16px}
.card h2{margin:0 0 4px;font-size:16px;font-weight:600}
.card h2+.hint{margin-top:0}
.hint{color:var(--muted);font-size:13px;margin:0 0 14px}
h1{font-size:21px;font-weight:650;letter-spacing:-.01em;margin:0 0 4px}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 18px}
label{display:block;font-size:13px;font-weight:550;margin:0 0 5px}
input[type=text],input[type=email],input[type=url],input[type=number],input[type=password],select,textarea{
  width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
  color:var(--ink);font:inherit;font-size:14px}
textarea{min-height:68px;resize:vertical}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.field{margin:0 0 14px}
.field .note{font-size:12px;color:var(--muted);margin:5px 0 0}
.row{display:flex;gap:12px;flex-wrap:wrap}
.row>*{flex:1 1 180px;min-width:0}
.check{display:flex;align-items:flex-start;gap:8px;margin:0 0 9px;font-size:14px}
.check input{margin-top:3px;flex:none}
.check label{margin:0;font-weight:400}
button,.btn{display:inline-block;padding:9px 15px;border-radius:8px;border:1px solid var(--accent);
  background:var(--accent);color:var(--accent-ink);font:inherit;font-size:14px;font-weight:550;
  cursor:pointer;text-decoration:none;text-align:center}
button:hover,.btn:hover{filter:brightness(1.06)}
button.secondary,.btn.secondary{background:transparent;color:var(--ink);border-color:var(--line)}
button.danger,.btn.danger{background:transparent;color:var(--danger);border-color:var(--danger)}
button.link{background:none;border:none;color:var(--accent);padding:0;font-weight:400;
  text-decoration:underline;width:auto}
.actions{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-top:16px}
.actions.tight{margin-top:0}
.alert{padding:11px 13px;border-radius:8px;margin:0 0 16px;font-size:14px;border:1px solid}
.alert.err{background:color-mix(in srgb,var(--danger) 9%,transparent);border-color:var(--danger);color:var(--danger)}
.alert.ok{background:color-mix(in srgb,var(--ok) 10%,transparent);border-color:var(--ok);color:var(--ok)}
.alert.info{background:color-mix(in srgb,var(--accent) 9%,transparent);border-color:var(--accent);color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;margin:0 -4px}
.target{display:block;max-width:40ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:13px}
.empty{text-align:center;color:var(--muted);padding:28px 10px;font-size:14px}
.pager{display:flex;gap:9px;justify-content:flex-end;margin-top:14px}
.otp{font-size:27px;letter-spacing:.42em;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:12px}
.cf-turnstile{margin:0 0 14px;min-height:65px}
.center{text-align:center}
.count{font-size:38px;font-weight:650;font-variant-numeric:tabular-nums;margin:8px 0}
.dest{word-break:break-all;font-size:14px;margin:0 0 18px}
footer.foot{color:var(--muted);font-size:12px;text-align:center;padding:22px 16px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:5px 14px;font-size:13.5px;margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.grants{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:0 0 10px}
.grants legend{padding:0 6px}
.tools{display:flex;gap:7px;flex-wrap:wrap}
.tools form{display:inline}
@media (max-width:620px){
  .wrap{padding:12px}
  header.top .wrap{gap:8px}
  nav.main{width:100%;margin-left:0}
  .target{max-width:22ch}
}
`.trim();

export const JS = `
(function () {
  'use strict';

  // Lets CSS hide controls that only exist for the no-JavaScript path.
  document.documentElement.classList.add('js');

  // The domain picker in the header applies as soon as it changes.
  var picker = document.querySelector('[data-slink-autosubmit] select');
  if (picker) {
    picker.addEventListener('change', function () {
      var form = picker.form;
      if (form) form.submit();
    });
  }

  // Delayed-redirect interstitial. The destination is carried in a data
  // attribute; a <meta http-equiv="refresh"> in the page is the no-JS path.
  var hold = document.querySelector('[data-slink-redirect]');
  if (hold) {
    var dest = hold.getAttribute('data-slink-redirect');
    var left = parseInt(hold.getAttribute('data-slink-delay') || '0', 10);
    var out = hold.querySelector('[data-slink-count]');
    var tick = function () {
      if (out) out.textContent = String(left);
      if (left <= 0) { window.location.replace(dest); return; }
      left -= 1;
      window.setTimeout(tick, 1000);
    };
    tick();
  }

  // Destructive actions confirm before submitting.
  document.addEventListener('submit', function (ev) {
    var form = ev.target;
    if (!(form instanceof HTMLFormElement)) return;
    var msg = form.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) { ev.preventDefault(); return; }
    var btn = form.querySelector('button[type=submit],button:not([type])');
    if (btn && !form.hasAttribute('data-no-busy')) {
      window.setTimeout(function () { btn.disabled = true; }, 0);
    }
  });

  // Copy a short link to the clipboard.
  document.addEventListener('click', function (ev) {
    var el = ev.target.closest ? ev.target.closest('[data-copy]') : null;
    if (!el) return;
    ev.preventDefault();
    var value = el.getAttribute('data-copy');
    var done = function () {
      var old = el.textContent;
      el.textContent = 'Copied';
      window.setTimeout(function () { el.textContent = old; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () {});
    }
  });

  // Code entry: digits only, submit as soon as it is complete.
  var code = document.querySelector('[data-slink-code]');
  if (code) {
    code.focus();
    code.addEventListener('input', function () {
      var want = parseInt(code.getAttribute('maxlength') || '6', 10);
      code.value = code.value.replace(/[^0-9]/g, '').slice(0, want);
      if (code.value.length === want) {
        var form = code.form;
        // Only auto-submit once Turnstile has produced a token.
        var token = form && form.querySelector('[name="cf-turnstile-response"]');
        if (form && (!token || token.value)) form.requestSubmit();
      }
    });
  }

  // Suggest the shortcut path from the destination when the field is empty.
  var slug = document.querySelector('[data-slink-slug]');
  if (slug) {
    slug.addEventListener('input', function () {
      slug.setCustomValidity(
        /^[A-Za-z0-9_-]+(\\/[A-Za-z0-9_-]+)*$/.test(slug.value) || slug.value === ''
          ? ''
          : 'Use letters, digits, underscore and hyphen, with / between segments.'
      );
    });
  }
})();
`.trim();

/** Serve a static asset, or null when the path is not one. */
export function serveAsset(pathname) {
  if (pathname === ASSET_PREFIX + '/app.css') {
    return new Response(CSS, {
      headers: {
        'Content-Type': 'text/css; charset=utf-8',
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  }
  if (pathname === ASSET_PREFIX + '/app.js') {
    return new Response(JS, {
      headers: {
        'Content-Type': 'text/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  }
  if (pathname === ASSET_PREFIX + '/logo.svg') {
    return new Response(LOGO_SVG, {
      headers: {
        'Content-Type': 'image/svg+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=31536000, immutable',
        // An SVG is active content when a browser navigates straight to it,
        // so this one is served inert: no script, no network, no framing.
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }
  return null;
}
