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
  const page = await fresh.req('https://ptra.dev/admin');
  const token = Harness.csrf(await page.text());
  await fresh.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'cook@pontera.com', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  const vPage = await fresh.req('https://ptra.dev/admin');
  const vToken = Harness.csrf(await vPage.text());
  const done = await fresh.req('https://ptra.dev/admin', {
    form: { _csrf: vToken, stage: 'code', code: fresh.lastCode(), 'cf-turnstile-response': 't:otp:ptra.dev' },
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
  const absent = await admin.req('https://ptra.cc/cross-session');
  ok('no link was created', absent.headers.get('Location') === 'https://fallback.example/home',
     absent.status + ' ' + absent.headers.get('Location'));

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

  // A foreign Referer is refused even with no Origin header.
  const foreignRef = await alice.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: Harness.csrfFor(editBody, '/admin/links/delete'), host: 'ptra.cc', path: 'alices-own' },
    headers: { Origin: null, Referer: 'https://evil.example/x' },
  });
  ok('foreign Referer refused', (foreignRef.headers.get('Location') || '').includes('m=csrf'));
  ok('link survived the foreign-Referer attempt', (await admin.req('https://ptra.cc/alices-own')).status === 302);

  // An opaque origin (a sandboxed frame) sends the literal string "null".
  const opaque = await alice.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: Harness.csrfFor(editBody, '/admin/links/delete'), host: 'ptra.cc', path: 'alices-own' },
    headers: { Origin: 'null' },
  });
  ok('opaque origin refused', (opaque.headers.get('Location') || '').includes('m=csrf'));

  // Neither header: several browsers omit Origin on a same-origin form post,
  // and Referrer-Policy removes the Referer fallback. Refusing these locked
  // real people out of every form, so the signed cookie-bound token and
  // SameSite=Lax carry the defence instead.
  const bare = await alice.req('https://ptra.dev/admin/links/edit', {
    form: {
      _csrf: updateToken, host: 'ptra.cc', path: 'alices-own', newpath: 'alices-own',
      target: 'https://example.com/renamed', status: '302', delay: '0', enabled: '1',
    },
    headers: { Origin: null },
  });
  ok('no Origin and no Referer is accepted',
     (bare.headers.get('Location') || '').includes('m=link.updated'),
     bare.status + ' ' + bare.headers.get('Location'));
  const renamed = await admin.req('https://ptra.cc/alices-own');
  ok('that edit really applied', renamed.headers.get('Location') === 'https://example.com/renamed',
     String(renamed.headers.get('Location')));

  // A bare request still needs a valid token.
  const bareNoToken = await alice.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: 'forged', host: 'ptra.cc', path: 'alices-own' },
    headers: { Origin: null },
  });
  ok('a bare request still needs a valid token',
     (bareNoToken.headers.get('Location') || '').includes('m=csrf'));
}

/* ------------------------------------------------------- open redirect */
section('open redirect');
{
  const fresh = peer(admin);
  const page = await fresh.req('https://ptra.dev/admin?next=https://evil.example/');
  const body = await page.text();
  ok('absolute next is discarded in the form', body.includes('name="next" value="/admin"'),
     (body.match(/name="next" value="[^"]*"/) || [''])[0]);

  const token = Harness.csrf(body);
  await fresh.req('https://ptra.dev/admin', {
    form: { _csrf: token, stage: 'email', email: 'openr@pontera.com', next: '//evil.example/x', 'cf-turnstile-response': 't:login:ptra.dev' },
  });
  const vBody = await (await fresh.req('https://ptra.dev/admin')).text();
  const done = await fresh.req('https://ptra.dev/admin', {
    form: { _csrf: Harness.csrf(vBody), stage: 'code', code: fresh.lastCode(), 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('protocol-relative next is discarded', done.headers.get('Location') === '/admin',
     String(done.headers.get('Location')));
}

/* ------------------------------------------- host separation and limits */
section('host separation');
{
  // The admin area is served only by the hub; on a short-link host those
  // paths are ordinary shortcut lookups.
  // On a short-link host these are ordinary shortcut lookups, so they fall
  // through to the MISSING redirect rather than offering a way in.
  const onShortHost = await admin.req('https://ptra.cc/admin');
  ok('short-link host does not serve /admin',
     onShortHost.status === 302 && onShortHost.headers.get('Location') === 'https://fallback.example/home',
     onShortHost.status + ' ' + onShortHost.headers.get('Location'));
  const loginOnShortHost = await admin.req('https://ptra.cc/login');
  ok('short-link host does not serve /login', loginOnShortHost.status === 302);
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
  const page = await spammer.req('https://ptra.dev/admin');
  const token = Harness.csrf(await page.text());
  let blocked = false;
  for (let i = 0; i < 15; i++) {
    const r = await spammer.req('https://ptra.dev/admin', {
      form: {
        _csrf: token, stage: 'email', email: `flood${i}@pontera.com`,
        'cf-turnstile-response': 't:login:ptra.dev',
      },
    });
    if (r.status !== 303 && (await r.text()).includes('Too many sign-in attempts')) { blocked = true; break; }
  }
  ok('per-IP code requests are throttled', blocked);
}

console.log(`\nsecurity: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
