/**
 * assets.js - the stylesheet and script served as same-origin static files.
 *
 * Keeping these out of the HTML is what lets the CSP forbid inline script
 * entirely. Page-specific values reach the script through `data-` attributes.
 */

import { HASH_PREFIX } from './linkpass.js';
import { LOGO_SVG } from './logo.js';
import { harden } from './security.js';

export const ASSET_PREFIX = '/__slink';

/** Bumped whenever the asset bodies change; used for immutable caching. */
export const ASSET_VERSION = '10';

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
/* The QR that follows the shortcut field. Fixed beside the form on a wide
   screen; above it on a narrow one, where there is no room to the side. */
.qrfloat{display:block;margin:0 0 16px;padding:12px;border:1px solid var(--line);
  border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);text-align:center}
/* An explicit display beats the browser's own [hidden] rule, so say it
   again here or the panel can never hide itself. */
.qrfloat[hidden],.qrfloat img[hidden]{display:none}
.qrfloat img{display:block;width:150px;height:150px;margin:0 auto;border-radius:6px}
.qrfloat .note{margin:8px 0 0;word-break:break-all}
@media (min-width:1180px){
  .qrfloat{position:fixed;top:96px;right:max(16px,calc(50vw - 520px - 182px));width:174px;margin:0;z-index:5}
}
.tip{display:inline-flex;align-items:center;justify-content:center;flex:none;
  width:16px;height:16px;margin-left:6px;border:1px solid var(--line);border-radius:50%;
  font-size:11px;line-height:1;color:var(--muted);cursor:help;user-select:none}
.tip:hover,.tip:focus{color:var(--ink);border-color:var(--muted);outline:none}
.visually-hidden{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;
  clip:rect(0 0 0 0);white-space:nowrap;border:0}
.badge{display:inline-block;padding:1px 7px;border-radius:999px;border:1px solid var(--line);
  font-size:11.5px;color:var(--muted);vertical-align:middle}
.badge.ok{color:var(--ok);border-color:currentColor}
.badge.ro{color:var(--warn);border-color:currentColor}
.badge.off{color:var(--danger);border-color:currentColor}
.impbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  margin:0 0 18px;padding:10px 14px;border:1px solid var(--warn);border-radius:8px;
  color:var(--warn);background:color-mix(in srgb,var(--warn) 10%,transparent)}
.impbar strong{color:inherit}
.impbar .btn{flex:none}
.chart{margin:8px 0 0}
.chart svg{display:block;overflow:visible}
.chart rect{fill:var(--accent,currentColor);opacity:.75}
.chart rect:hover{opacity:1}
.qrwrap{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
.qrwrap form{flex:1 1 260px;min-width:0}
img.qr{flex:none;width:220px;height:220px;border:1px solid var(--line);border-radius:8px;background:#fff}
details.group{border-top:1px solid var(--line);padding:10px 0 2px}
details.group:first-of-type{border-top:0}
details.group>summary{cursor:pointer;font-weight:600;padding:4px 0;list-style:revert}
details.group>summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
details.group[open]>summary{margin-bottom:6px}
.sso{margin:0 0 4px}
.sso .btn{display:block;text-align:center}
.divider{display:flex;align-items:center;gap:12px;color:var(--muted);margin:16px 0;font-size:.9em}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--line)}
.target-big{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:1.05em;margin:14px 0;padding:12px;border:1px solid var(--line);border-radius:8px;
  background:color-mix(in srgb,var(--line) 18%,transparent)}
body.framed{margin:0;padding:0;height:100vh;overflow:hidden;display:flex;flex-direction:column}
.slink-frame{flex:1 1 auto;width:100%;border:0;display:block}
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
button.small,.btn.small{padding:5px 10px;font-size:13px}
/* Icon buttons: square, quiet until pointed at, and large enough to hit on
   a touch screen even though the glyph inside is 16px. */
.iconbtn{display:inline-flex;align-items:center;justify-content:center;gap:6px;width:32px;height:32px;
  padding:0;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--muted)}
.iconbtn.haslabel{width:auto;padding:0 11px;font-size:13px}
.iconbtn:hover{color:var(--ink);border-color:var(--muted);filter:none}
.iconbtn:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.iconbtn .ic-done{display:none}
.iconbtn.copied{color:var(--ok);border-color:var(--ok)}
.iconbtn.copied .ic-idle{display:none}
.iconbtn.copied .ic-done{display:inline}
.iconbtn.copyfail{color:var(--danger);border-color:var(--danger)}
svg.ic{flex:none;vertical-align:-3px}
/* The marker on a link that opens in a new tab. */
.ic-out{opacity:.5;margin-left:4px}
a:hover .ic-out{opacity:1}
.rowtools{display:flex;gap:6px;align-items:center;justify-content:flex-end}
.rowtools form{margin:0;display:inline-flex}
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
footer.foot div+div{margin-top:4px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:5px 14px;font-size:13.5px;margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.grants{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:0 0 10px}
.grants legend{padding:0 6px}
.ogcard{border:1px solid var(--line);border-radius:10px;overflow:hidden;max-width:520px;background:var(--bg)}
.ogimg{aspect-ratio:1.91/1;background:var(--line);display:flex;align-items:center;justify-content:center}
.ogimg img{width:100%;height:100%;object-fit:cover;display:block}
.ogimg-none{color:var(--muted);font-size:13px}
.ogbody{padding:10px 12px}
.oghost{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.ogtitle{font-weight:600;margin:2px 0}
.ogdesc{font-size:13px;color:var(--muted)}
.tools{display:flex;gap:7px;flex-wrap:wrap}
.tools form{display:inline-flex;gap:6px;align-items:center}
.tools input[type=text]{width:auto;min-width:9rem;padding:5px 8px;font-size:13px}
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

  // A password carried in the fragment: \`#${HASH_PREFIX}secret\`.
  //
  // A fragment never reaches the server, so this is the only place it can
  // be read. It is cleared from the address bar before anything else
  // happens, so it does not survive into the next page, get carried to the
  // destination by the redirect, or sit in the history for the next person
  // at this machine.
  var unlock = document.querySelector('[data-slink-unlock]');
  if (unlock && location.hash) {
    var carried = '';
    var parts = location.hash.replace(/^#/, '').split('&');
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].indexOf('${HASH_PREFIX}') !== 0) continue;
      var raw = parts[i].slice(${HASH_PREFIX.length}).replace(/\\+/g, ' ');
      try { carried = decodeURIComponent(raw); } catch (e) { carried = raw; }
      break;
    }
    if (carried) {
      try {
        history.replaceState(null, '', location.pathname + location.search);
      } catch (e) {
        location.hash = '';
      }
      var pwField = unlock.querySelector('input[type="password"]');
      if (pwField) pwField.value = carried;

      // Wait for the challenge to produce a token, then submit exactly as
      // pressing the button would. If it never arrives, the form is simply
      // left filled in for the person to submit themselves.
      var waited = 0;
      var poll = setInterval(function () {
        var token = unlock.querySelector('[name="cf-turnstile-response"]');
        if (token && token.value) {
          clearInterval(poll);
          unlock.submit();
        } else if (++waited > 60) {
          clearInterval(poll);
        }
      }, 250);
    }
  }

  // The domain picker in the header applies as soon as it changes.
  var picker = document.querySelector('[data-slink-autosubmit] select');
  if (picker) {
    picker.addEventListener('change', function () {
      var form = picker.form;
      if (form) form.submit();
    });
  }

  // Domain and Directory describe one choice between them, so the second
  // is narrowed to the first. Every option is in the markup for a browser
  // without JavaScript, which is why this prunes rather than fetches; the
  // submit checks the pair whichever way it arrives.
  var dirPick = document.querySelector('select[data-slink-places]');
  var hostPick = document.getElementById('f_host');
  if (dirPick && hostPick) {
    var every = [];
    for (var p = 0; p < dirPick.options.length; p++) {
      var src = dirPick.options[p];
      every.push({ value: src.value, label: src.textContent, host: src.getAttribute('data-host') });
    }
    var narrow = function (keep) {
      var want = hostPick.value;
      while (dirPick.options.length) dirPick.remove(0);
      for (var q = 0; q < every.length; q++) {
        if (every[q].host !== want) continue;
        var made = new Option(every[q].label, every[q].value);
        made.setAttribute('data-host', every[q].host);
        dirPick.add(made);
      }
      if (keep) dirPick.value = keep;
      if (!dirPick.value && dirPick.options.length) dirPick.selectedIndex = 0;
    };
    hostPick.addEventListener('change', function () { narrow(dirPick.value); });
    narrow(dirPick.value);
  }

  // Bulk selection on the search page. Without JavaScript the checkboxes
  // still work one by one; these only save the clicking.
  var batch = document.querySelector('[data-slink-batch]');
  if (batch) {
    var setAll = function (on) {
      var boxes = batch.querySelectorAll('[data-slink-pick]');
      for (var i = 0; i < boxes.length; i++) boxes[i].checked = on;
    };
    var all = batch.querySelector('[data-slink-pick-all]');
    var none = batch.querySelector('[data-slink-pick-none]');
    if (all) all.addEventListener('click', function () { setAll(true); });
    if (none) none.addEventListener('click', function () { setAll(false); });
  }

  // Delayed-redirect interstitial. The destination is carried in a data
  // attribute; a <meta http-equiv="refresh"> in the page is the no-JS path.
  var hold = document.querySelector('[data-slink-redirect]');
  if (hold) {
    var dest = hold.getAttribute('data-slink-redirect');
    var left = parseInt(hold.getAttribute('data-slink-delay') || '0', 10);
    // The number the visitor watches is in the card; the element holding
    // the destination is an empty hidden one further down. Searching the
    // document rather than inside it is what makes the digits move.
    var out = document.querySelector('[data-slink-count]');
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
  //
  // The confirmation is a class rather than new text, so the button keeps
  // its size and a row does not jump. The accessible name changes with it,
  // because a colour swap alone says nothing to a screen reader, and a
  // failure says so instead of looking like success.
  document.addEventListener('click', function (ev) {
    var el = ev.target.closest ? ev.target.closest('[data-copy]') : null;
    if (!el) return;
    ev.preventDefault();
    var value = el.getAttribute('data-copy');
    var was = el.getAttribute('aria-label') || el.textContent;
    var settle = function (cls, say) {
      el.classList.add(cls);
      el.setAttribute('aria-label', say);
      window.setTimeout(function () {
        el.classList.remove(cls);
        el.setAttribute('aria-label', was);
      }, 1400);
    };
    var done = function () { settle('copied', el.getAttribute('data-copied-label') || 'Copied'); };
    var failed = function () { settle('copyfail', 'Could not copy. Select the link and copy it.'); };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, failed);
      return;
    }
    // No clipboard API: an insecure origin, or an older browser. The old
    // selection route still works in both.
    try {
      var pad = document.createElement('textarea');
      pad.value = value;
      pad.setAttribute('readonly', '');
      pad.style.position = 'fixed';
      pad.style.opacity = '0';
      document.body.appendChild(pad);
      pad.select();
      var ok = document.execCommand && document.execCommand('copy');
      document.body.removeChild(pad);
      if (ok) { done(); } else { failed(); }
    } catch (e) {
      failed();
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

  // ---------------------------------------------------------- passkeys
  //
  // Everything here is progressive: the buttons start hidden and are only
  // revealed once this browser is known to support WebAuthn, so a browser
  // that cannot do it never shows a control that would fail.

  var b64url = function (buffer) {
    var bytes = new Uint8Array(buffer);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return btoa(out).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  };

  var fromB64url = function (value) {
    var padded = String(value).replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  };

  var postJson = function (url, payload) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok || data.error) {
          throw new Error(data.error || 'That did not work. Please try again.');
        }
        return data;
      });
    });
  };

  var hasWebAuthn = function () {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
  };

  // Adding a passkey, on the account's own page.
  var add = document.querySelector('[data-slink-passkey-add]');
  if (add) {
    var addBtn = add.querySelector('[data-slink-passkey-go]');
    var addMsg = add.querySelector('[data-slink-passkey-msg]');
    var nameField = add.querySelector('[data-slink-passkey-name]');
    // Say so rather than leaving a field with no button beside it.
    if (!hasWebAuthn() && addMsg) {
      addMsg.textContent = 'This browser cannot use passkeys. The emailed code still works.';
    }
    if (addBtn && hasWebAuthn()) {
      addBtn.hidden = false;
      addBtn.addEventListener('click', function () {
        addBtn.disabled = true;
        if (addMsg) addMsg.textContent = 'Follow your device’s prompt…';
        var token = add.getAttribute('data-token');
        postJson('/admin/passkeys/register/begin', { _csrf: token })
          .then(function (opts) {
            return navigator.credentials.create({
              publicKey: {
                challenge: fromB64url(opts.challenge),
                rp: opts.rp,
                user: {
                  id: new TextEncoder().encode(opts.user.id),
                  name: opts.user.name,
                  displayName: opts.user.displayName
                },
                pubKeyCredParams: opts.algorithms.map(function (alg) {
                  return { type: 'public-key', alg: alg };
                }),
                timeout: opts.timeout,
                attestation: 'none',
                excludeCredentials: (opts.exclude || []).map(function (id) {
                  return { type: 'public-key', id: fromB64url(id) };
                }),
                authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
              }
            }).then(function (credential) {
              if (!credential) throw new Error('No passkey was created.');
              return postJson('/admin/passkeys/register/finish', {
                _csrf: token,
                token: opts.token,
                name: nameField ? nameField.value : '',
                attestationObject: b64url(credential.response.attestationObject),
                clientDataJSON: b64url(credential.response.clientDataJSON)
              });
            });
          })
          .then(function () {
            window.location.assign('/admin/passkeys?m=passkey.added');
          })
          .catch(function (err) {
            addBtn.disabled = false;
            if (addMsg) {
              addMsg.textContent =
                err && err.name === 'NotAllowedError'
                  ? 'That was cancelled, or it timed out.'
                  : (err && err.message) || 'That did not work.';
            }
          });
      });
    }
  }

  // Signing in with a passkey, on the sign-in page. The whole block is
  // revealed at once, so a browser that cannot do this shows nothing at
  // all rather than a dead control.
  var login = document.querySelector('[data-slink-passkey-login]');
  if (login && hasWebAuthn()) {
    var inBtn = login.querySelector('[data-slink-passkey-go]');
    var inMsg = login.querySelector('[data-slink-passkey-msg]');
    if (inBtn) {
      login.hidden = false;
      inBtn.addEventListener('click', function () {
        inBtn.disabled = true;
        if (inMsg) inMsg.textContent = 'Follow your device’s prompt…';
        var token = login.getAttribute('data-token');
        postJson('/__slink/passkey/login/begin', { _csrf: token })
          .then(function (opts) {
            return navigator.credentials.get({
              publicKey: {
                challenge: fromB64url(opts.challenge),
                rpId: opts.rpId,
                timeout: opts.timeout,
                userVerification: 'preferred'
              },
              mediation: 'optional'
            }).then(function (assertion) {
              if (!assertion) throw new Error('No passkey was offered.');
              return postJson('/__slink/passkey/login/finish', {
                _csrf: token,
                token: opts.token,
                next: login.getAttribute('data-next') || '/admin',
                id: assertion.id,
                authenticatorData: b64url(assertion.response.authenticatorData),
                clientDataJSON: b64url(assertion.response.clientDataJSON),
                signature: b64url(assertion.response.signature)
              });
            });
          })
          .then(function (done) {
            window.location.assign(done.next || '/admin');
          })
          .catch(function (err) {
            inBtn.disabled = false;
            if (inMsg) {
              inMsg.textContent =
                err && err.name === 'NotAllowedError'
                  ? 'That was cancelled, or no passkey was available.'
                  : (err && err.message) || 'That did not work.';
            }
          });
      });
    }
  }

  // The QR that follows the shortcut field.
  //
  // The code encodes the short URL, which is known from the form alone, so
  // this works on the create screen before the link exists. It is filled in
  // here rather than server-side because it has to track what is being
  // typed, and it stays hidden until there is a shortcut to encode.
  var qrBox = document.querySelector('[data-slink-qr]');
  if (qrBox) {
    var qrImg = qrBox.querySelector('img');
    var qrLabel = qrBox.querySelector('[data-slink-qr-label]');
    var pathField = document.querySelector(
      '[name="' + (qrBox.getAttribute('data-path-field') || 'path') + '"]'
    );
    var hostField = document.querySelector('select[name="host"]');
    var timer = null;

    var currentHost = function () {
      return (hostField && hostField.value) || qrBox.getAttribute('data-host') || '';
    };

    // The same shape the server accepts, so a half-typed path asks for
    // nothing rather than producing a request that can only be refused.
    var usable = function (value) {
      var v = String(value || '').replace(/^\\/+|\\/+$/g, '');
      return v !== '' && /^[A-Za-z0-9_-]+(\\/[A-Za-z0-9_-]+)*$/.test(v) ? v : '';
    };

    var paint = function () {
      var path = usable(pathField && pathField.value);
      var host = currentHost();
      if (!path || !host) {
        qrBox.hidden = true;
        return;
      }
      var logo = qrBox.getAttribute('data-logo');
      var src =
        qrBox.getAttribute('data-base') +
        '?host=' + encodeURIComponent(host) +
        '&path=' + encodeURIComponent(path) +
        '&size=300' +
        (logo ? '&logo=' + encodeURIComponent(logo) : '');
      if (qrImg) {
        qrImg.hidden = false;
        if (qrImg.getAttribute('src') !== src) qrImg.setAttribute('src', src);
      }
      if (qrLabel) qrLabel.textContent = host + '/' + path;
      qrBox.hidden = false;
    };

    var schedule = function () {
      window.clearTimeout(timer);
      timer = window.setTimeout(paint, 250);
    };

    if (pathField) {
      pathField.addEventListener('input', schedule);
      pathField.addEventListener('change', schedule);
    }
    if (hostField) hostField.addEventListener('change', schedule);
    paint();
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

/**
 * Serve a static asset, or null when the path is not one.
 *
 * These go through harden() like every other response. They are answered
 * before configuration is even loaded, so without it a browser whose very
 * first request here is for the stylesheet would get no HSTS, and the
 * script would be served without `nosniff`.
 *
 * `store: true` keeps each asset's own caching; the SVG's stricter policy
 * is re-applied after hardening because that one has to stay inert.
 */
const SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
const IMMUTABLE = 'public, max-age=31536000, immutable';

export function serveAsset(pathname) {
  if (pathname === ASSET_PREFIX + '/app.css') {
    return harden(
      new Response(CSS, {
        headers: { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': IMMUTABLE },
      }),
      { store: true }
    );
  }
  if (pathname === ASSET_PREFIX + '/app.js') {
    return harden(
      new Response(JS, {
        headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': IMMUTABLE },
      }),
      { store: true }
    );
  }
  if (pathname === ASSET_PREFIX + '/logo.svg') {
    const response = harden(
      new Response(LOGO_SVG, {
        headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': IMMUTABLE },
      }),
      { store: true }
    );
    // An SVG is active content when a browser navigates straight to it, so
    // this one keeps the inert policy rather than the ordinary page one.
    response.headers.set('Content-Security-Policy', SVG_CSP);
    return response;
  }
  return null;
}
