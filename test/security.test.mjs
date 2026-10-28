import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const admin = new Harness();
await admin.signIn('root@pontera.com');

function peer(base) {
  const p = new Harness();
  p.env.KV = base.env.KV;
  p.env.EMAIL = base.env.EMAIL;
  p.mail = base.mail;
  return p;
}

/* ------------------------------------------------------ cookie hygiene */
section('cookies');
{
  const fresh = peer(admin);
  const page = await fresh.req('https://ptra.dev/login');
  const token = Harness.csrf(await page.text());
  await fresh.req('https://ptra.dev/login', {
    form: { _csrf: token, email: 'cook@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  const vPage = await fresh.req('https://ptra.dev/login/verify');
  const vToken = Harness.csrf(await vPage.text());
  const done = await fresh.req('https://ptra.dev/login/verify', {
    form: { _csrf: vToken, code: fresh.lastCode(), 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  const setCookies = done.headers.getSetCookie();
  const sess = setCookies.find((c) => c.startsWith('__Host-slink_sess='));
  ok('session cookie uses __Host- prefix', !!sess, setCookies.join(' | '));
  ok('session cookie is HttpOnly', /HttpOnly/i.test(sess || ''));
  ok('session cookie is Secure', /Secure/i.test(sess || ''));
  ok('session cookie is SameSite=Lax', /SameSite=Lax/i.test(sess || ''));
  ok('session cookie has no Domain attribute', !/Domain=/i.test(sess || ''));
  ok('login cookie cleared after use', setCookies.some((c) => c.startsWith('__Host-slink_login=') && /Max-Age=0/.test(c)));
}

/* ------------------------------------------------------- CSRF binding */
section('CSRF binding');
{
  const alice = peer(admin);
  await alice.signIn('csrfa@pontera.com');
  const bob = peer(admin);
  await bob.signIn('csrfb@pontera.com');

  // A token minted in Alice's session must not work in Bob's.
  const aliceToken = Harness.csrf(await (await alice.req('https://ptra.dev/admin/links/new')).text());
  const crossSession = await bob.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: aliceToken, host: 'ptra.cc', path: 'cross-session', target: 'example.com' },
  });
  ok('token is bound to the session',
     (crossSession.headers.get('Location') || '').includes('m=csrf'),
     crossSession.status + ' ' + crossSession.headers.get('Location'));
  ok('no link was created', (await admin.req('https://ptra.cc/cross-session')).status === 404);

  // A token minted for one form must not work on another.
  await alice.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: aliceToken, host: 'ptra.cc', path: 'alices-own', target: 'example.com/a', status: '302',
    },
  });
  const editUrl = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=alices-own';
  const editBody = await (await alice.req(editUrl)).text();
  const updateToken = Harness.csrfFor(editBody, '/admin/links/edit');
  const crossForm = await alice.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: updateToken, host: 'ptra.cc', path: 'alices-own' },
  });
  ok('token is bound to the form',
     (crossForm.headers.get('Location') || '').includes('m=csrf'),
     crossForm.status + ' ' + crossForm.headers.get('Location'));
  ok('link survived the cross-form attempt', (await admin.req('https://ptra.cc/alices-own')).status === 302);

  // Missing Origin on a cross-site post is refused.
  const noOrigin = await alice.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: Harness.csrfFor(editBody, '/admin/links/delete'), host: 'ptra.cc', path: 'alices-own' },
    headers: { Origin: null, Referer: 'https://evil.example/x' },
  });
  ok('foreign Referer refused', (noOrigin.headers.get('Location') || '').includes('m=csrf'));
}

/* ------------------------------------------------------- open redirect */
section('open redirect');
{
  const fresh = peer(admin);
  const page = await fresh.req('https://ptra.dev/login?next=https://evil.example/');
  const body = await page.text();
  ok('absolute next is discarded in the form', body.includes('name="next" value="/admin"'),
     (body.match(/name="next" value="[^"]*"/) || [''])[0]);

  const token = Harness.csrf(body);
  await fresh.req('https://ptra.dev/login', {
    form: { _csrf: token, email: 'openr@pontera.com', next: '//evil.example/x', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  const vBody = await (await fresh.req('https://ptra.dev/login/verify')).text();
  const done = await fresh.req('https://ptra.dev/login/verify', {
    form: { _csrf: Harness.csrf(vBody), code: fresh.lastCode(), 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('protocol-relative next is discarded', done.headers.get('Location') === '/admin',
     String(done.headers.get('Location')));
}

/* ------------------------------------------- host separation and limits */
section('host separation');
{
  // The admin area is served only by the hub; on a short-link host those
  // paths are ordinary shortcut lookups.
  const onShortHost = await admin.req('https://ptra.cc/admin');
  ok('short-link host does not serve /admin', onShortHost.status === 404, String(onShortHost.status));
  const loginOnShortHost = await admin.req('https://ptra.cc/login');
  ok('short-link host does not serve /login', loginOnShortHost.status === 404, String(loginOnShortHost.status));

  // A 404 page on a short-link host links to the hub, not to a local path.
  const notFound = await admin.req('https://ptra.cc/nothing-here');
  const nfBody = await notFound.text();
  ok('404 links to the hub admin', nfBody.includes('https://ptra.dev/admin'), 'no absolute admin link found');

  // Anonymous on ptra.cc, so the landing page offers sign-in - on the hub,
  // absolutely, because ptra.cc serves no /login of its own.
  const landing = await admin.req('https://ptra.cc/');
  const lb = await landing.text();
  ok('landing links to the hub', lb.includes('href="https://ptra.dev/login"'),
     (lb.match(/class="btn" href="[^"]*"/) || [''])[0]);
  ok('landing has no bare /login link', !lb.includes('href="/login"'));
}

section('request limits');
{
  const big = 'x'.repeat(70 * 1024);
  const r = await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: 'x', host: 'ptra.cc', path: 'big', target: big },
  });
  ok('oversized form refused', (r.headers.get('Location') || '').includes('m=csrf'), String(r.status));

  const wrongType = await admin.req('https://ptra.dev/admin/links/new', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  ok('non-form content type refused', (wrongType.headers.get('Location') || '').includes('m=csrf'));
}

/* --------------------------------------------------- output escaping */
section('output escaping');
{
  const token = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  await admin.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: token, host: 'ptra.cc', path: 'xss-note', target: 'example.com/x', status: '302',
      note: '</textarea><script>alert(1)</script>',
    },
  });
  const edit = await admin.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=xss-note');
  const body = await edit.text();
  ok('note is escaped', !body.includes('<script>alert(1)</script>'));
  ok('escaped form present', body.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));

  const target = 'https://example.com/?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E';
  await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'xss-dest', target, status: '302', delay: '3' },
  });
  const inter = await admin.req('https://ptra.cc/xss-dest');
  const ib = await inter.text();
  ok('interstitial destination is escaped', !ib.includes('<script>alert(1)</script>'));
  ok('interstitial still renders the link', ib.includes('data-slink-redirect='));
}

/* ---------------------------------------------------------- rate limit */
section('rate limiting');
{
  const spammer = peer(admin);
  const page = await spammer.req('https://ptra.dev/login');
  const token = Harness.csrf(await page.text());
  let blocked = false;
  for (let i = 0; i < 15; i++) {
    const r = await spammer.req('https://ptra.dev/login', {
      form: { _csrf: token, email: `flood${i}@pontera.com`, 'cf-turnstile-response': 't:login:ptra.dev' },
    });
    if (r.status !== 303 && (await r.text()).includes('Too many sign-in attempts')) { blocked = true; break; }
  }
  ok('per-IP code requests are throttled', blocked);
}

console.log(`\nsecurity: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
