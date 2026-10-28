import assert from 'node:assert/strict';
import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const h = new Harness();

/* ------------------------------------------------------ infrastructure */
section('infrastructure');
{
  const css = await h.req('https://ptra.dev/__slink/app.css');
  ok('css served', css.status === 200 && (css.headers.get('Content-Type') || '').includes('text/css'));
  ok('css immutable', (css.headers.get('Cache-Control') || '').includes('immutable'));

  const health = await h.req('https://ptra.dev/health');
  const hj = await health.json();
  ok('health ok', health.status === 200 && hj.ok === true, JSON.stringify(hj));

  const robots = await h.req('https://ptra.cc/robots.txt');
  ok('robots disallows', (await robots.text()).includes('Disallow: /'));

  const unknown = await h.req('https://nope.example/');
  ok('unknown host 404', unknown.status === 404, String(unknown.status));

  const bad = await h.req('https://ptra.dev/admin', { method: 'DELETE' });
  ok('method not allowed', bad.status === 405, String(bad.status));
}

/* ------------------------------------------------------------- headers */
section('security headers');
{
  const r = await h.req('https://ptra.dev/admin');
  const csp = r.headers.get('Content-Security-Policy') || '';
  ok('CSP present', csp.includes("default-src 'none'"));
  ok('CSP no unsafe-inline script', !/script-src[^;]*unsafe-inline/.test(csp));
  ok('CSP allows turnstile', csp.includes('frame-src https://challenges.cloudflare.com'));
  ok('HSTS', (r.headers.get('Strict-Transport-Security') || '').includes('max-age=63072000'));
  ok('nosniff', r.headers.get('X-Content-Type-Options') === 'nosniff');
  ok('frame deny', r.headers.get('X-Frame-Options') === 'DENY');
  ok('no-store on login', (r.headers.get('Cache-Control') || '').includes('no-store'));
  ok('referrer policy on html', r.headers.get('Referrer-Policy') === 'same-origin');
}

/* -------------------------------------------------------- auth gating */
section('authentication gating');
{
  const gated = await h.req('https://ptra.dev/some-link');
  ok('ptra.dev link requires auth', gated.status === 303 && (gated.headers.get('Location') || '').startsWith('/admin?next='),
     gated.status + ' ' + gated.headers.get('Location'));

  const open = await h.req('https://ptra.cc/');
  ok('ptra.cc root redirects to MISSING', open.status === 302 && open.headers.get('Location') === 'https://fallback.example/home',
     open.status + ' ' + open.headers.get('Location'));

  const adminAnon = await h.req('https://ptra.dev/admin');
  ok('admin shows the sign-in form', adminAnon.status === 200);
  ok('sign-in form posts to /admin', (await adminAnon.text()).includes('action="/admin"'));
}

/* ------------------------------------------------------------- sign-in */
section('sign-in');
{
  const page = await h.req('https://ptra.dev/admin');
  const body = await page.text();
  const token = Harness.csrf(body);

  const noCsrf = await h.req('https://ptra.dev/admin', {
    form: { stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  ok('login without CSRF refused', noCsrf.status === 400, String(noCsrf.status));

  const crossOrigin = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
    headers: { Origin: 'https://evil.example' },
  });
  ok('cross-origin login refused', crossOrigin.status === 400, String(crossOrigin.status));

  const badTurnstile = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, email: 'root@pontera.com', 'cf-turnstile-response': 'BAD' },
  });
  ok('bad turnstile refused', badTurnstile.status === 400 && (await badTurnstile.text()).includes('Verification failed'));

  const wrongDomain = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'outsider@gmail.com', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  ok('disallowed email domain refused', (await wrongDomain.text()).includes('not permitted to sign in'));

  const tor = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
    country: 'T1',
  });
  ok('tor refused', (await tor.text()).includes('not available over this network'));

  const unknownCountry = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
    country: 'XX',
  });
  ok('unknown country refused', (await unknownCountry.text()).includes('not available from this location'));

  ok('no mail sent for refused attempts', h.mail.length === 0, String(h.mail.length));

  // Turnstile action must match the surface.
  const wrongAction = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('turnstile action mismatch refused', (await wrongAction.text()).includes('Verification failed'));

  // Turnstile hostname must be one of ours.
  const wrongHost = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', 'cf-turnstile-response': 't:login:evil.example' },
  });
  ok('turnstile hostname mismatch refused', (await wrongHost.text()).includes('Verification failed'));

  const begin = await h.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'root@pontera.com', next: '/admin', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  ok('login accepted', begin.status === 303 && begin.headers.get('Location') === '/admin');
  ok('code emailed', h.mail.length === 1 && /\b\d{6}\b/.test(h.mail[0].text));
  ok('mail from configured sender', h.mail[0].from.email === 'no-reply@ptra.dev');

  const vPage = await h.req('https://ptra.dev/admin');
  const vBody = await vPage.text();
  const vToken = Harness.csrf(vBody);
  ok('verify page shows address', vBody.includes('root@pontera.com'));

  const wrongCode = await h.req('https://ptra.dev/admin', {
    form: { _csrf: vToken, stage: 'code', code: '000000', 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('wrong code refused', (await wrongCode.text()).includes('not correct'));

  const code = h.lastCode();
  const done = await h.req('https://ptra.dev/admin', {
    form: { _csrf: vToken, stage: 'code', code, 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('correct code signs in', done.status === 303 && done.headers.get('Location') === '/admin',
     done.status + ' ' + done.headers.get('Location'));

  const replay = await h.req('https://ptra.dev/admin', {
    form: { _csrf: vToken, stage: 'code', code, 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  // The spent challenge is deleted and the CSRF binding has moved to the new
  // session, so a replay cannot mint a second session.
  ok('code cannot be replayed', replay.status !== 303 || replay.headers.get('Location') !== '/admin',
     replay.status + ' ' + replay.headers.get('Location'));
  const replaySetsNoSession = !(replay.headers.getSetCookie
    ? replay.headers.getSetCookie()
    : []).some((c) => c.startsWith('__Host-slink_sess=') && !c.includes('Max-Age=0'));
  ok('replay issues no session cookie', replaySetsNoSession);

  const admin = await h.req('https://ptra.dev/admin');
  const adminBody = await admin.text();
  ok('admin reachable after sign-in', admin.status === 200, String(admin.status));
  ok('admin shows the user', adminBody.includes('root@pontera.com'));
  ok('root admin sees Domains nav', adminBody.includes('/admin/domains'));
}

/* --------------------------------------------------------- link CRUD */
section('links');
let createdPath = null;
{
  const form = await h.req('https://ptra.dev/admin/links/new');
  const body = await form.text();
  const token = Harness.csrf(body);

  const noToken = await h.req('https://ptra.dev/admin/links/new', {
    form: { host: 'ptra.cc', path: 'nope', target: 'example.com' },
  });
  ok('create without CSRF refused', noToken.status === 303 && (noToken.headers.get('Location') || '').includes('m=csrf'));

  const created = await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'AAA', target: 'example.com/page', status: '302', delay: '0' },
  });
  ok('link created', created.status === 303 && (created.headers.get('Location') || '').includes('m=link.created'),
     created.status + ' ' + created.headers.get('Location'));
  createdPath = 'aaa';

  const dup = await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'aaa', target: 'example.com' },
  });
  ok('duplicate shortcut refused', (await dup.text()).includes('already in use'));

  const reserved = await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.dev', path: 'admin', target: 'example.com' },
  });
  ok('reserved path refused on hub', (await reserved.text()).includes('reserved'));

  const badChars = await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'has space', target: 'example.com' },
  });
  ok('invalid characters refused', (await badChars.text()).includes('letters, digits, underscore and hyphen'));

  const jsScheme = await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'evil', target: 'javascript:alert(1)' },
  });
  ok('javascript: destination refused', (await jsScheme.text()).includes('not allowed'));
}

/* ------------------------------------------------------- redirection */
section('redirects');
{
  const hit = await h.req('https://ptra.cc/aaa');
  ok('redirect works', hit.status === 302 && hit.headers.get('Location') === 'https://example.com/page',
     hit.status + ' ' + hit.headers.get('Location'));

  const upper = await h.req('https://ptra.cc/AAA');
  ok('lookup is case-insensitive', upper.status === 302);

  // www is canonicalised to the apex first, so a session on one is a session
  // on the other despite the __Host- cookie being bound to an exact hostname.
  const www = await h.req('https://www.ptra.cc/aaa');
  ok('www redirects to the apex', www.status === 301 && www.headers.get('Location') === 'https://ptra.cc/aaa',
     www.status + ' ' + www.headers.get('Location'));
  const wwwHub = await h.req('https://www.ptra.dev/admin');
  ok('www hub redirects to the apex', wwwHub.status === 301 && wwwHub.headers.get('Location') === 'https://ptra.dev/admin',
     wwwHub.status + ' ' + wwwHub.headers.get('Location'));

  const missing = await h.req('https://ptra.cc/does-not-exist');
  ok('unknown link goes to MISSING',
     missing.status === 302 && missing.headers.get('Location') === 'https://fallback.example/home',
     missing.status + ' ' + missing.headers.get('Location'));

  const redirCache = await h.req('https://ptra.cc/aaa');
  ok('302 is not cached', (redirCache.headers.get('Cache-Control') || '').includes('no-store'));
  // The destination must not learn which shortcut was followed.
  ok('redirect sends no referrer', redirCache.headers.get('Referrer-Policy') === 'no-referrer',
     String(redirCache.headers.get('Referrer-Policy')));
}

/* ------------------------------------------------- codes, delay, schemes */
section('redirect options');
{
  const form = await h.req('https://ptra.dev/admin/links/new');
  const token = Harness.csrf(await form.text());

  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'perm', target: 'example.com/p', status: '301', delay: '0' },
  });
  const perm = await h.req('https://ptra.cc/perm');
  ok('301 honoured', perm.status === 301, String(perm.status));
  ok('301 is cacheable', (perm.headers.get('Cache-Control') || '').includes('max-age=300'));

  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'slow', target: 'example.com/s', status: '302', delay: '5' },
  });
  const slow = await h.req('https://ptra.cc/slow');
  const slowBody = await slow.text();
  ok('delay renders interstitial', slow.status === 200 && slowBody.includes('data-slink-redirect="https://example.com/s"'));
  ok('interstitial has meta refresh', slowBody.includes('http-equiv="refresh" content="5;url=https://example.com/s"'));

  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'mail', target: 'mailto:help@example.com', status: '302' },
  });
  const mail = await h.req('https://ptra.cc/mail');
  ok('mailto scheme kept', mail.headers.get('Location') === 'mailto:help@example.com', String(mail.headers.get('Location')));

  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'app', target: 'slack://channel?id=7', status: '307' },
  });
  const app = await h.req('https://ptra.cc/app');
  ok('custom scheme kept with 307', app.status === 307 && app.headers.get('Location') === 'slack://channel?id=7');
}

console.log(`\ne2e: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
