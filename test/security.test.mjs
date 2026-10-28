import { Harness } from './harness.js';
import { normalizeUserCapabilities } from '../capabilities.js';
import { parseCookies } from '../security.js';
import { isSafeKey } from '../util.js';

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

const guest = peer(admin);

/* ----------------------------------------- input handling, end to end */
section('every form field is escaped on the way back out');
{
  // Escaping failed if and only if a payload comes back exactly as it was
  // sent. Looking for fragments like "onerror=" matches inert escaped text
  // and proves nothing either way.
  const PAYLOADS = [
    '"><img src=x onerror=alert(1)>',
    "'><script>alert(1)</script>",
    '</textarea><script>alert(1)</script>',
    '</title><script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    '" autofocus onfocus="alert(1)',
    '${7*7}',
  ];

  const nf = async () => Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  let raw = 0;
  let crashed = 0;
  for (const p of PAYLOADS) {
    const r = await admin.req('https://ptra.dev/admin/links/new', {
      form: {
        _csrf: await nf(), host: 'ptra.cc', path: p, target: p, status: '302', note: p,
        previewTitle: p, previewDescription: p, previewImage: p,
        rules__default: p, url__mobileAndroid: p, activeFrom: p, expires: p,
      },
    });
    if (r.status >= 500) crashed++;
    const body = await r.text();
    if (body.includes(p) && /[<>"']/.test(p)) raw++;
  }
  ok('no payload survives the link form unescaped', raw === 0, String(raw));
  ok('and none of them crashes it', crashed === 0, String(crashed));

  let searchRaw = 0;
  for (const p of PAYLOADS) {
    const r = await admin.req(
      'https://ptra.dev/admin/search?q=' + encodeURIComponent(p) +
      '&type=' + encodeURIComponent(p) + '&host=' + encodeURIComponent(p) +
      '&from=' + encodeURIComponent(p)
    );
    const body = await r.text();
    if (r.status >= 500 || (body.includes(p) && /[<>"']/.test(p))) searchRaw++;
  }
  ok('search echoes nothing unescaped', searchRaw === 0, String(searchRaw));
}

section('a destination cannot break out into a header');
{
  const nf = async () => Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  let injected = 0;
  const raws = [
    'https://example.com/a\r\nSet-Cookie: evil=1',
    'https://example.com/a\nSet-Cookie: evil=1',
  ];
  for (const [i, t] of raws.entries()) {
    const r = await admin.req('https://ptra.dev/admin/links/new', {
      form: { _csrf: await nf(), host: 'ptra.cc', path: 'crlf' + i, target: t, status: '302' },
    });
    ok(`a destination with a line break is refused (${i})`,
       !(r.headers.get('Location') || '').includes('link.created'));
  }

  // Percent-encoded breaks are legal URL characters and stay encoded.
  const r = await admin.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: await nf(), host: 'ptra.cc', path: 'crlfpc',
      target: 'https://example.com/a%0d%0aSet-Cookie:%20evil=1', status: '302',
    },
  });
  if ((r.headers.get('Location') || '').includes('link.created')) {
    const hit = await guest.req('https://ptra.cc/crlfpc');
    const loc = hit.headers.get('Location') || '';
    if (/[\r\n]/.test(loc) || (hit.headers.get('Set-Cookie') || '').includes('evil')) injected++;
  }
  ok('an encoded line break stays encoded in the Location', injected === 0);

  // No response anywhere carries a stray line break in a header.
  let strays = 0;
  for (const u of [
    'https://ptra.dev/admin', 'https://ptra.dev/admin/links', 'https://ptra.cc/',
    'https://ptra.cc/nope', 'https://ptra.dev/admin/search?q=x',
  ]) {
    const r = await admin.req(u);
    for (const [k, v] of r.headers) if (/[\r\n]/.test(k) || /[\r\n]/.test(v)) strays++;
  }
  ok('no response header carries a line break', strays === 0, String(strays));
}

section('a key from the wire cannot reach a prototype');
{
  ok('isSafeKey rejects the three', !isSafeKey('__proto__') && !isSafeKey('constructor') && !isSafeKey('prototype'));
  ok('and accepts ordinary ones', isSafeKey('session') && isSafeKey('a-b_c'));

  const jar = parseCookies({ headers: new Headers({ Cookie: '__proto__=x; constructor=y; ok=1' }) });
  ok('a dangerous cookie name is dropped', Object.keys(jar).join(',') === 'ok', Object.keys(jar).join(','));
  ok('the object prototype is untouched', Object.getPrototypeOf({}) === Object.prototype);
  ok('an ordinary cookie still parses', jar.ok === '1');

  const caps = normalizeUserCapabilities({ __proto__: { frame: true }, 'ptra.cc': { frame: true } });
  ok('a dangerous host key is dropped from capabilities',
     Object.keys(caps).join(',') === 'ptra.cc', Object.keys(caps).join(','));
  ok('nothing leaked onto Object.prototype', {}.frame === undefined);
}

section('a forged cookie signs nobody in');
{
  let signedIn = 0;
  for (const cookie of [
    '__Host-slink_sess=',
    '__Host-slink_sess=not-a-real-session',
    '__Host-slink_sess=' + 'x'.repeat(5000),
    "__Host-slink_sess=' OR 1=1--",
    '__Host-slink_sess=../../admin',
  ]) {
    const r = await admin.req('https://ptra.dev/admin', { headers: { Cookie: cookie }, cookies: false });
    if (r.status === 200 && (await r.text()).includes('class="who"')) signedIn++;
  }
  ok('no forged session cookie is accepted', signedIn === 0, String(signedIn));
}

console.log(`\nsecurity: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
