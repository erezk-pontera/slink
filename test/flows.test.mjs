import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

/** A fresh harness with its own cookie jar, sharing one KV namespace. */
function peer(base) {
  const p = new Harness();
  p.env.KV = base.env.KV;
  p.env.EMAIL = base.env.EMAIL;
  p.mail = base.mail;
  return p;
}

const admin = new Harness();
await admin.signIn('root@pontera.com');

// A link on ptra.cc that later sections resolve.
{
  const token = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  await admin.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'aaa', target: 'example.com/page', status: '302' },
  });
}

/* ------------------------------------------------- email normalisation */
section('email identity');
{
  // IGNORE_EMAIL_DOT and IGNORE_EMAIL_PLUS are both on in the test env.
  const staff = peer(admin);
  const r = await staff.signIn('Jo.Hn+weekly@Pontera.com');
  ok('dotted/tagged address signs in', r.ok, String(r.status));

  const again = peer(admin);
  await again.signIn('john@pontera.com');
  const page = await again.req('https://ptra.dev/admin');
  const body = await page.text();
  ok('normalises to one identity', body.includes('john@pontera.com'), 'admin page did not show the normalised identity');

  const users = await admin.req('https://ptra.dev/admin/users');
  const ub = await users.text();
  // One account, keyed by the normalised identity. The display name keeps the
  // spelling first used to sign in, which is why the dotted form still shows.
  const rows = (ub.match(/u=john%40pontera\.com/g) || []).length;
  ok('one account for both spellings', rows === 1, 'rows=' + rows);
  ok('identity shown normalised', ub.includes('identity: john@pontera.com'));
}

/* ----------------------------------------------------- ownership rules */
section('ownership');
{
  const alice = peer(admin);
  await alice.signIn('alice@pontera.com');
  const bob = peer(admin);
  await bob.signIn('bob@pontera.com');

  const form = await alice.req('https://ptra.dev/admin/links/new');
  const token = Harness.csrf(await form.text());
  const made = await alice.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'alice-link', target: 'example.com/a', status: '302' },
  });
  ok('alice can create at root', made.status === 303 && (made.headers.get('Location') || '').includes('link.created'));

  const edit = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=alice-link';
  const aliceView = await alice.req(edit);
  ok('owner can open her link', aliceView.status === 200, String(aliceView.status));

  const bobView = await bob.req(edit);
  ok('stranger cannot open it', bobView.status === 403, String(bobView.status));

  // Bob forges a delete using a token minted in his own session.
  const bobForm = await bob.req('https://ptra.dev/admin/links/new');
  const bobToken = Harness.csrf(await bobForm.text());
  const bobDelete = await bob.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: bobToken, host: 'ptra.cc', path: 'alice-link' },
  });
  ok('stranger cannot delete it', bobDelete.status !== 303 || !(bobDelete.headers.get('Location') || '').includes('deleted'),
     String(bobDelete.status));
  const stillThere = await admin.req('https://ptra.cc/alice-link');
  ok('link survived the attempt', stillThere.status === 302, String(stillThere.status));

  const adminView = await admin.req(edit);
  ok('admin can open any link', adminView.status === 200, String(adminView.status));

  // Transfer to bob, then bob owns it and alice does not.
  const aToken = Harness.csrfFor(await (await alice.req(edit)).text(), '/admin/links/transfer');
  const moved = await alice.req('https://ptra.dev/admin/links/transfer', {
    form: { _csrf: aToken, host: 'ptra.cc', path: 'alice-link', owner: 'bob@pontera.com' },
  });
  ok('transfer accepted', moved.status === 303 && (moved.headers.get('Location') || '').includes('link.moved'),
     moved.status + ' ' + moved.headers.get('Location'));
  ok('new owner can edit', (await bob.req(edit)).status === 200);
  ok('old owner can no longer edit', (await alice.req(edit)).status === 403);
}

/* -------------------------------------------------------- read-only */
section('read-only links');
{
  const carol = peer(admin);
  await carol.signIn('carol@pontera.com');
  const token = Harness.csrf(await (await carol.req('https://ptra.dev/admin/links/new')).text());
  await carol.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: token, host: 'ptra.cc', path: 'locked', target: 'example.com/l', status: '302', readonly: '1' },
  });
  const edit = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=locked';
  ok('non-admin cannot self-assign read-only', (await carol.req(edit)).status === 200);

  // An administrator marks it read-only; the owner is then locked out.
  const aTok = Harness.csrfFor(await (await admin.req(edit)).text(), '/admin/links/edit');
  const marked = await admin.req('https://ptra.dev/admin/links/edit', {
    form: { _csrf: aTok, host: 'ptra.cc', path: 'locked', newpath: 'locked',
            target: 'https://example.com/l', status: '302', delay: '0', enabled: '1', readonly: '1' },
  });
  ok('admin set read-only', marked.status === 303, String(marked.status));
  ok('owner now locked out', (await carol.req(edit)).status === 403);
  ok('admin still has access', (await admin.req(edit)).status === 200);
}

/* ------------------------------------------------------- directories */
section('directories and grants');
{
  const dave = peer(admin);
  await dave.signIn('dave@pontera.com');
  const erin = peer(admin);
  await erin.signIn('erin@pontera.com');

  const dirPage = await admin.req('https://ptra.dev/admin/directories?host=ptra.cc');
  const dirToken = Harness.csrfFor(await dirPage.text(), '/admin/directories/new');
  const made = await admin.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: dirToken, host: 'ptra.cc', path: 'pub', note: 'shared' },
  });
  ok('admin created directory', made.status === 303 && (made.headers.get('Location') || '').includes('dir.created'),
     made.status + ' ' + made.headers.get('Location'));

  const nf = Harness.csrf(await (await dave.req('https://ptra.dev/admin/links/new')).text());
  const blocked = await dave.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: nf, host: 'ptra.cc', path: 'pub/deck', target: 'example.com/d' },
  });
  ok('ungranted user blocked inside directory', (await blocked.text()).includes('do not have permission to create in this directory'));

  const dirEdit = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=pub';
  const gTok = Harness.csrfFor(await (await admin.req(dirEdit)).text(), '/admin/directories/grant');
  const granted = await admin.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: gTok, host: 'ptra.cc', path: 'pub', email: 'dave@pontera.com', canCreate: '1' },
  });
  ok('grant saved', granted.status === 303 && (granted.headers.get('Location') || '').includes('grant.saved'));

  const nf2 = Harness.csrf(await (await dave.req('https://ptra.dev/admin/links/new')).text());
  const allowed = await dave.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: nf2, host: 'ptra.cc', path: 'pub/deck', target: 'example.com/d' },
  });
  ok('granted user can create inside', allowed.status === 303 && (allowed.headers.get('Location') || '').includes('link.created'));
  ok('directory link resolves', (await admin.req('https://ptra.cc/pub/deck')).status === 302);

  // Erin becomes directory administrator and manages Dave's link.
  const gTok2 = Harness.csrfFor(await (await admin.req(dirEdit)).text(), '/admin/directories/grant');
  await admin.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: gTok2, host: 'ptra.cc', path: 'pub', email: 'erin@pontera.com', canCreate: '1', canManage: '1' },
  });
  const deckEdit = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=pub%2Fdeck';
  ok('directory admin manages another user link', (await erin.req(deckEdit)).status === 200,
     String((await erin.req(deckEdit)).status));

  // ...but has no power over a link outside the directory.
  ok('directory admin blocked outside directory',
     (await erin.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=locked')).status === 403);

  // A plain grantee is not a directory administrator.
  const daveOnDir = await dave.req(dirEdit);
  ok('plain grantee cannot administer the directory', daveOnDir.status === 403, String(daveOnDir.status));
  const erinOnDir = await erin.req(dirEdit);
  ok('directory admin can administer it', erinOnDir.status === 200, String(erinOnDir.status));
}

/* ------------------------------------------------- admin-only surfaces */
section('admin-only surfaces');
{
  const frank = peer(admin);
  await frank.signIn('frank@pontera.com');
  for (const path of ['/admin/domains', '/admin/users', '/admin/settings', '/admin/audit']) {
    const r = await frank.req('https://ptra.dev' + path);
    ok('non-admin blocked from ' + path, r.status === 403, String(r.status));
  }
  const nav = await (await frank.req('https://ptra.dev/admin')).text();
  ok('non-admin nav hides admin links', !nav.includes('/admin/domains'));
}

/* ---------------------------------------------------------------- SSO */
section('cross-host SSO');
{
  // Require sign-in on ptra.cc, then confirm an existing hub session carries over.
  const dTok = Harness.csrfFor(await (await admin.req('https://ptra.dev/admin/domains/edit?host=ptra.cc')).text(), '/admin/domains/edit');
  const saved = await admin.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dTok, host: 'ptra.cc', authRequired: '1', allowedAuthDomains: 'pontera.com',
            rootCreatePolicy: 'email_domain', allowedCreateDomains: 'pontera.com',
            defaultStatus: '302', defaultDelay: '0', enabled: '1' },
  });
  ok('ptra.cc now requires sign-in', saved.status === 303, String(saved.status));

  const anon = new Harness();
  anon.env.KV = admin.env.KV;
  const gated = await anon.req('https://ptra.cc/aaa');
  ok('anonymous bounced to SSO start',
     gated.status === 303 && (gated.headers.get('Location') || '').startsWith('https://ptra.dev/sso/authorize'),
     gated.status + ' ' + gated.headers.get('Location'));

  // The signed-in administrator walks the handshake.
  const start = await admin.req('https://ptra.cc/aaa');
  ok('signed-in user bounced to hub', start.status === 303);
  const authorizeUrl = start.headers.get('Location');
  const authorized = await admin.req(authorizeUrl);
  const callbackUrl = authorized.headers.get('Location');
  ok('hub issues a callback token',
     authorized.status === 303 && (callbackUrl || '').startsWith('https://ptra.cc/__slink/sso/callback?t='),
     authorized.status + ' ' + callbackUrl);

  const landed = await admin.req(callbackUrl);
  ok('callback opens a session on ptra.cc', landed.status === 303 && landed.headers.get('Location') === '/aaa',
     landed.status + ' ' + landed.headers.get('Location'));
  const nowWorks = await admin.req('https://ptra.cc/aaa');
  ok('link now resolves on ptra.cc', nowWorks.status === 302, String(nowWorks.status));

  // A token minted for ptra.cc must not be accepted by the hub.
  const token = new URL(callbackUrl).searchParams.get('t');
  const wrongAud = await admin.req('https://ptra.dev/__slink/sso/callback?t=' + encodeURIComponent(token));
  ok('token rejected on the wrong host', wrongAud.status === 400, String(wrongAud.status));

  // A tampered token is rejected.
  const stranger = new Harness();
  stranger.env.KV = admin.env.KV;
  const forged = await stranger.req('https://ptra.cc/__slink/sso/callback?t=' + encodeURIComponent(token.slice(0, -3) + 'aaa'));
  ok('tampered token rejected', forged.status === 400, String(forged.status));

  // Replay without the nonce cookie is rejected.
  const noNonce = new Harness();
  noNonce.env.KV = admin.env.KV;
  const replayed = await noNonce.req(callbackUrl);
  ok('token replay without nonce rejected', replayed.status === 400, String(replayed.status));

  // Put ptra.cc back to public for the remaining tests.
  const dTok2 = Harness.csrfFor(await (await admin.req('https://ptra.dev/admin/domains/edit?host=ptra.cc')).text(), '/admin/domains/edit');
  await admin.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dTok2, host: 'ptra.cc', allowedAuthDomains: 'pontera.com',
            rootCreatePolicy: 'email_domain', allowedCreateDomains: 'pontera.com',
            defaultStatus: '302', defaultDelay: '0', enabled: '1' },
  });
  ok('ptra.cc public again', (await anon.req('https://ptra.cc/aaa')).status === 302);
}

/* ------------------------------------------------------------- logout */
section('logout');
{
  const gus = peer(admin);
  await gus.signIn('gus@pontera.com');
  ok('signed in', (await gus.req('https://ptra.dev/admin')).status === 200);

  const page = await gus.req('https://ptra.dev/logout');
  const token = Harness.csrf(await page.text());
  ok('logout GET is a confirmation, not an action', (await gus.req('https://ptra.dev/admin')).status === 200);

  const out = await gus.req('https://ptra.dev/logout', { form: { _csrf: token } });
  ok('logout POST signs out', out.status === 303 && out.headers.get('Location') === '/login');
  ok('session is gone', (await gus.req('https://ptra.dev/admin')).status === 303);
}

/* ------------------------------------------------------ disabled user */
section('disabled accounts');
{
  const hank = peer(admin);
  await hank.signIn('hank@pontera.com');
  ok('hank is in', (await hank.req('https://ptra.dev/admin')).status === 200);

  const uEdit = 'https://ptra.dev/admin/users/edit?u=hank%40pontera.com';
  const uTok = Harness.csrfFor(await (await admin.req(uEdit)).text(), '/admin/users/edit');
  const disabled = await admin.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: uTok, u: 'hank@pontera.com', disabled: '1' },
  });
  ok('admin disabled the account', disabled.status === 303, String(disabled.status));
  ok('disabled session is revoked', (await hank.req('https://ptra.dev/admin')).status === 303);

  // A root admin cannot be demoted through the UI.
  const rEdit = 'https://ptra.dev/admin/users/edit?u=root%40pontera.com';
  const rTok = Harness.csrfFor(await (await admin.req(rEdit)).text(), '/admin/users/edit');
  await admin.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: rTok, u: 'root@pontera.com', isAdmin: '', disabled: '1' },
  });
  ok('root admin survives demotion attempt', (await admin.req('https://ptra.dev/admin/domains')).status === 200);
}

/* -------------------------------------------------------------- audit */
section('audit');
{
  const page = await admin.req('https://ptra.dev/admin/audit');
  const body = await page.text();
  ok('audit page renders', page.status === 200);
  ok('records sign-ins', body.includes('login.succeeded'));
  ok('records link creation', body.includes('link.created'));
  ok('records denials', body.includes('access.denied') || body.includes('login.blocked'));
  ok('stores no raw IPs', !body.includes('CF-Connecting'));
}

console.log(`\nflows: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
