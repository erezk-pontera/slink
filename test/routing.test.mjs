import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const MISSING = 'https://fallback.example/home';
const h = new Harness();

/* ------------------------------------------------------- host roots */
section('host roots go to MISSING and offer no way in');
{
  // www is canonicalised first, so www roots take two hops to the same place.
  for (const host of ['ptra.cc', 'ptra.dev']) {
    const r = await h.req(`https://${host}/`);
    ok(`${host}/ redirects to MISSING`,
       r.status === 302 && r.headers.get('Location') === MISSING,
       r.status + ' ' + r.headers.get('Location'));
    ok(`${host}/ sends no body a visitor could click`, (await r.text()).length === 0);
  }
  for (const host of ['www.ptra.cc', 'www.ptra.dev']) {
    const first = await h.req(`https://${host}/`);
    ok(`${host}/ canonicalises to the apex`,
       first.status === 301 && first.headers.get('Location') === `https://${host.slice(4)}/`,
       first.status + ' ' + first.headers.get('Location'));
    const second = await h.req(first.headers.get('Location'));
    ok(`${host}/ then reaches MISSING`, second.headers.get('Location') === MISSING,
       String(second.headers.get('Location')));
  }
}

/* ------------------------------------------- unknown, disabled, expired */
section('nothing-to-show cases');
{
  await h.signIn('root@pontera.com');
  const token = Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());

  const unknown = await h.req('https://ptra.cc/never-created');
  ok('unknown shortcut goes to MISSING', unknown.headers.get('Location') === MISSING,
     String(unknown.headers.get('Location')));

  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'off', target: 'example.com/x', status: '302' },
  });
  const live = await h.req('https://ptra.cc/off');
  ok('link works while enabled', live.headers.get('Location') === 'https://example.com/x');

  const editBody = await (await h.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=off')).text();
  await h.req('https://ptra.dev/admin/links/edit', {
    form: {
      _csrf: Harness.csrfFor(editBody, '/admin/links/edit'), host: 'ptra.cc', path: 'off',
      newpath: 'off', target: 'https://example.com/x', status: '302', delay: '0',
    },
  });
  const disabled = await h.req('https://ptra.cc/off');
  ok('disabled link goes to MISSING', disabled.headers.get('Location') === MISSING,
     String(disabled.headers.get('Location')));

  // Expiry in the past is the same "nothing to show" case.
  await h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'past', target: 'example.com/y', status: '302',
            expires: '2020-01-01' },
  });
  const expired = await h.req('https://ptra.cc/past');
  ok('expired link goes to MISSING', expired.headers.get('Location') === MISSING,
     String(expired.headers.get('Location')));
}

/* ------------------------------------------------- per-domain override */
section('per-domain overrides beat MISSING');
{
  const body = await (await h.req('https://ptra.dev/admin/domains/edit?host=ptra.cc')).text();
  const saved = await h.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: Harness.csrfFor(body, '/admin/domains/edit'), host: 'ptra.cc',
      allowedAuthDomains: 'pontera.com', rootCreatePolicy: 'email_domain',
      allowedCreateDomains: 'pontera.com', defaultStatus: '302', defaultDelay: '0', enabled: '1',
      rootRedirect: 'https://root.example/', notFoundUrl: 'https://gone.example/',
    },
  });
  ok('overrides saved', saved.status === 303, String(saved.status));

  const root = await h.req('https://ptra.cc/');
  ok('root uses the per-domain value', root.headers.get('Location') === 'https://root.example/',
     String(root.headers.get('Location')));
  const gone = await h.req('https://ptra.cc/still-nothing');
  ok('unknown uses the per-domain value', gone.headers.get('Location') === 'https://gone.example/',
     String(gone.headers.get('Location')));
  const stillOff = await h.req('https://ptra.cc/off');
  ok('disabled uses the per-domain value', stillOff.headers.get('Location') === 'https://gone.example/',
     String(stillOff.headers.get('Location')));

  // ptra.dev, untouched, still falls back to MISSING.
  const hub = await h.req('https://ptra.dev/');
  ok('the other host still uses MISSING', hub.headers.get('Location') === MISSING,
     String(hub.headers.get('Location')));
}

/* ------------------------------------------------ where sign-in appears */
section('the sign-in form appears only at /admin on the hub');
{
  const anon = new Harness();
  anon.env.KV = h.env.KV;

  const adminPage = await anon.req('https://ptra.dev/admin');
  const adminBody = await adminPage.text();
  ok('/admin shows the form', adminPage.status === 200 && adminBody.includes('name="email"'));
  ok('the form posts to /admin', adminBody.includes('action="/admin"'));
  ok('the form carries the Turnstile widget', adminBody.includes('data-action="login"'));

  // The old paths are bookmarks that land on /admin, not a second form.
  for (const p of ['/login', '/login/verify', '/login/resend']) {
    const r = await anon.req('https://ptra.dev' + p);
    ok(`${p} redirects to /admin`, r.status === 303 && r.headers.get('Location') === '/admin',
       r.status + ' ' + r.headers.get('Location'));
    ok(`${p} renders no form`, (await r.text()).length === 0);
  }

  // Short-link hosts never render a form; those paths are ordinary lookups.
  for (const p of ['/', '/admin', '/login']) {
    const r = await anon.req('https://ptra.cc' + p);
    const b = await r.text();
    ok(`ptra.cc${p} shows no sign-in`, !b.includes('name="email"') && !b.includes('cf-turnstile'),
       'status ' + r.status);
  }

  // A gated short link on the hub points at /admin, not at a login page.
  const gated = await anon.req('https://ptra.dev/some-private-link');
  ok('gated hub link bounces to /admin',
     gated.status === 303 && (gated.headers.get('Location') || '').startsWith('/admin?next='),
     gated.status + ' ' + gated.headers.get('Location'));
}

console.log(`\nrouting: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
