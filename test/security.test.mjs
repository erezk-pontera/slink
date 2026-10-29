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

section('every state-changing endpoint is guarded, without exception');
{
  // Enumerated rather than sampled: a new endpoint that forgets its guard
  // is exactly the kind of thing a spot check misses.
  const ENDPOINTS = [
    ['/admin/links/new', { host: 'ptra.cc', path: 'csrf-x', target: 'evil.example', status: '302' }],
    ['/admin/links/edit', { host: 'ptra.cc', path: 'csrf-x', newpath: 'csrf-x', target: 'evil.example', status: '302', enabled: '1' }],
    ['/admin/links/delete', { host: 'ptra.cc', path: 'csrf-x' }],
    ['/admin/links/transfer', { host: 'ptra.cc', path: 'csrf-x', owner: 'root@pontera.com' }],
    ['/admin/links/duplicate', { host: 'ptra.cc', path: 'csrf-x' }],
    ['/admin/links/password', { host: 'ptra.cc', path: 'csrf-x', password: 'x' }],
    ['/admin/links/move', { host: 'ptra.cc', path: 'csrf-x', toHost: 'ptra.dev', newpath: 'x' }],
    ['/admin/directories/new', { host: 'ptra.cc', path: 'csrfdir' }],
    ['/admin/directories/edit', { host: 'ptra.cc', path: 'csrfdir', enabled: '1' }],
    ['/admin/directories/delete', { host: 'ptra.cc', path: 'csrfdir' }],
    ['/admin/directories/grant', { host: 'ptra.cc', path: 'csrfdir', email: 'root@pontera.com', canCreate: '1' }],
    ['/admin/directories/revoke', { host: 'ptra.cc', path: 'csrfdir', userId: 'x' }],
    ['/admin/directories/transfer', { host: 'ptra.cc', path: 'csrfdir', owner: 'root@pontera.com' }],
    ['/admin/directories/policy', { host: 'ptra.cc', path: 'csrfdir' }],
    ['/admin/directories/exempt', { host: 'ptra.cc', path: 'csrfdir' }],
    ['/admin/directories/capabilities', { host: 'ptra.cc', path: 'csrfdir', cap_frame: 'deny' }],
    ['/admin/domains/new', { host: 'evil.example' }],
    ['/admin/domains/edit', { host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'open', enabled: '1' }],
    ['/admin/domains/delete', { host: 'ptra.cc' }],
    ['/admin/users/edit', { u: 'root@pontera.com', isAdmin: '1' }],
    ['/admin/users/revoke', { u: 'root@pontera.com' }],
    ['/admin/users/delete', { u: 'root@pontera.com' }],
    ['/admin/users/impersonate', { u: 'root@pontera.com' }],
    ['/admin/settings', { auditRetentionDays: '1' }],
    ['/admin/search/batch', { op: 'readonly', sel: 'link:ptra.cc:x' }],
    ['/admin/passkeys', { id: 'x', action: 'delete' }],
  ];

  let accepted = 0;
  for (const [path, form] of ENDPOINTS) {
    const r = await admin.req('https://ptra.dev' + path, { form: { _csrf: 'forged-token', ...form } });
    const loc = r.headers.get('Location') || '';
    if (!(r.status === 403 || r.status === 404 || loc.includes('csrf'))) {
      console.log('    accepted a forged token: ' + path);
      accepted++;
    }
  }
  ok(`all ${ENDPOINTS.length} POST endpoints refuse a forged token`, accepted === 0, String(accepted));

  let foreign = 0;
  for (const [path, form] of ENDPOINTS) {
    const tok = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
    const r = await admin.req('https://ptra.dev' + path, {
      form: { _csrf: tok, ...form },
      headers: { Origin: 'https://evil.example' },
    });
    const loc = r.headers.get('Location') || '';
    if (!(r.status === 403 || r.status === 404 || loc.includes('csrf'))) {
      console.log('    accepted a foreign Origin: ' + path);
      foreign++;
    }
  }
  ok('and all of them refuse a foreign Origin', foreign === 0, String(foreign));
}

section('a GET changes nothing');
{
  const tok = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'getsafe', target: 'example.com/gs', status: '302' },
  });
  for (const path of [
    '/admin/links/delete', '/admin/links/password', '/admin/links/move',
    '/admin/users/impersonate', '/admin/search/batch', '/admin/directories/delete',
  ]) {
    await admin.req(
      `https://ptra.dev${path}?host=ptra.cc&path=getsafe&u=root@pontera.com` +
      `&op=readonly&sel=link:ptra.cc:getsafe&password=x&toHost=ptra.dev`
    );
  }
  const still = await guest.req('https://ptra.cc/getsafe');
  ok('the link survives every state-changing path fetched as a GET',
     (still.headers.get('Location') || '').includes('example.com/gs'),
     still.headers.get('Location'));
}

section('what an identity provider says is not taken on trust');
{
  // The provider is a system setting. Post the whole settings form, as a
  // browser would, so nothing else on it is cleared.
  const page = await (await admin.req('https://ptra.dev/admin/settings')).text();
  const form = { _csrf: Harness.csrfFor(page, '/admin/settings') };
  for (const m of page.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>/g)) {
    if (m[1] === '_csrf') continue;
    if (/type="checkbox"/.test(m[0]) && !/\schecked/.test(m[0])) continue;
    form[m[1]] = m[2];
  }
  for (const m of page.matchAll(/<select[^>]*name="([^"]+)"[\s\S]*?<\/select>/g)) {
    const sel = m[0].match(/<option value="([^"]*)"[^>]*selected/);
    if (sel) form[m[1]] = sel[1];
  }
  await admin.req('https://ptra.dev/admin/settings', {
    form: {
      ...form,
      oauthEnabled: '1', oauthClientId: 'c',
      oauthAuthorizeUrl: 'https://idp.example/authorize',
      oauthTokenUrl: 'https://idp.example/token',
      oauthUserinfoUrl: 'https://idp.example/me',
    },
  });

  let signedIn = 0;
  for (const email of [
    '"><img src=x onerror=alert(1)>@pontera.com',
    'not-an-email',
    '',
    'a'.repeat(400) + '@pontera.com',
    'a\r\nb@pontera.com',
    '\u0430dmin@pontera.com',
    'a\u0000b@pontera.com',
  ]) {
    const h = peer(admin);
    h.idpEmail = email;
    const s = await h.req('https://ptra.dev/__slink/oauth/start');
    const st = new URL(s.headers.get('Location')).searchParams.get('state');
    const r = await h.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st);
    if (r.status === 303) signedIn++;
    else if ((await r.text()).includes('<img src=x')) signedIn++;
  }
  ok('no malformed or confusable address from a provider signs anyone in',
     signedIn === 0, String(signedIn));
}

section('credentials never live in a destination');
{
  const tok = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  const r = await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'creds', target: 'https://u:hunter2@ex.com/',
            status: '302' },
  });
  ok('a destination carrying a password is refused', r.status === 200);
  ok('and says why', (await r.text()).includes('cannot carry a password'));

  // Nothing was stored, so the shortcut falls through to the host's own
  // MISSING destination rather than to ex.com.
  const check = await admin.req('https://ptra.cc/creds');
  ok('so nothing was stored', !(check.headers.get('Location') || '').includes('ex.com'),
     check.status + ' ' + check.headers.get('Location'));
}

section('a destination that masks its host says so');
{
  const tok = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'masked',
            target: 'https://pontera.example@evil.example/x', status: '302' },
  });
  const page = await (await admin.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=masked')).text();
  ok('the editor warns', page.includes('is not where this goes'));
  ok('and names the real host', page.includes('the host is evil.example'));
  const warning = (page.match(/<div class="alert err"[^>]*>([^<]*)<\/div>/) || [])[1] || '';
  ok('the warning is escaped like everything else',
     warning.includes('&quot;pontera.example&quot;'), warning.slice(0, 60));
}

section('a key longer than the store allows is a miss, not an error');
{
  const { Store, MAX_KEY_BYTES } = await import('../kv.js');
  const store = new Store(admin.env.KV);

  // Characters and bytes are not the same thing, and KV counts bytes.
  const wide = '\u00e9'.repeat(300);
  for (const key of ['a'.repeat(MAX_KEY_BYTES + 1), 'a'.repeat(20000), wide]) {
    ok('a read answers nothing', (await store.get(key)) === null, String(key.length));
    const meta = await store.getWithMeta(key);
    ok('so does a read with metadata', meta.value === null && meta.metadata === null);
    ok('a listing under it is empty', (await store.listPage(key)).keys.length === 0);
    ok('and deleting it does nothing at all', (await store.delete(key)) === undefined);
    // A write is this code's own doing, so it says so rather than failing
    // quietly somewhere later.
    let threw = false;
    try {
      await store.put(key, { x: 1 });
    } catch {
      threw = true;
    }
    ok('while a write of one is refused out loud', threw);
  }
  // A key right at the limit is still a real key.
  const edge = 'k'.repeat(MAX_KEY_BYTES);
  await store.put(edge, { ok: true });
  ok('a key at the limit works', (await store.get(edge)).ok === true);

  // And the screens that build a key from a query value stay up.
  for (const path of [
    '/admin/links/edit?host=ptra.cc&path=' + 'a'.repeat(900),
    '/admin/links?dir=' + 'b'.repeat(900),
    '/admin/directories/edit?host=ptra.cc&path=' + 'c'.repeat(900),
    '/admin/users/edit?u=' + 'd'.repeat(900) + '%40pontera.com',
  ]) {
    const r = await admin.req('https://ptra.dev' + path);
    ok('no 5xx from ' + path.split('?')[0], r.status < 500, String(r.status));
  }
  const long = await admin.req('https://ptra.cc/' + 'e'.repeat(900));
  ok('nor from a very long shortcut in the URL', long.status < 500, String(long.status));
}

console.log(`\nsecurity: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
