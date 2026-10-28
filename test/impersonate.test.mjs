/**
 * Impersonation is per tab, so the interesting assertions are all about one
 * cookie jar holding several views at once, and about impersonation never
 * being a way to reach further than the administrator already could.
 */
import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

function peer(base) {
  const p = new Harness();
  p.env.KV = base.env.KV;
  p.env.EMAIL = base.env.EMAIL;
  p.mail = base.mail;
  return p;
}

const admin = new Harness();
await admin.signIn('root@pontera.com');

// Two ordinary accounts to look at, plus a second administrator.
for (const who of ['pia@pontera.com', 'quinn@pontera.com', 'rhea@pontera.com']) {
  const h = peer(admin);
  await h.signIn(who);
}

const usersPage = await (await admin.req('https://ptra.dev/admin/users')).text();
const impToken = Harness.csrfFor(usersPage, '/admin/users/impersonate');

async function startAs(h, email) {
  const page = await (await h.req('https://ptra.dev/admin/users')).text();
  const token = Harness.csrfFor(page, '/admin/users/impersonate');
  const r = await h.req('https://ptra.dev/admin/users/impersonate', {
    form: { _csrf: token, u: email },
  });
  return { status: r.status, location: r.headers.get('Location') || '' };
}

/* ------------------------------------------------- 1. opening a view */
section('an administrator opens a view as someone else');
{
  ok('the people list offers it', usersPage.includes('/admin/users/impersonate'), 'no form');
  ok('it opens in its own tab', usersPage.includes('target="_blank"'));

  const started = await startAs(admin, 'pia@pontera.com');
  ok('starting redirects into the namespace', started.location.startsWith('/admin/as/'),
     started.status + ' ' + started.location);

  const page = await (await admin.req('https://ptra.dev' + started.location)).text();
  ok('the page is rendered as that person', page.includes('pia@pontera.com'));
  ok('a banner says whose view it is', page.includes('class="impbar"'));
  ok('the banner names the real account', page.includes('root@pontera.com'));
  ok('hub links stay inside the namespace',
     page.includes('href="' + started.location + '/links"'), 'nav not rewritten');
  ok('static assets are left alone', page.includes('href="/__slink/'));
  ok('ending the view leaves the session alone', page.includes('href="/admin"'));
  ok('sign out does not end the admin session', !page.includes('href="/logout"'));
}

/* ------------------------------- 2. several tabs, one cookie jar */
section('tabs are independent');
{
  const a = await startAs(admin, 'pia@pontera.com');
  const b = await startAs(admin, 'quinn@pontera.com');
  ok('two impersonations differ', a.location !== b.location);

  const asPia = await (await admin.req('https://ptra.dev' + a.location)).text();
  const asQuinn = await (await admin.req('https://ptra.dev' + b.location)).text();
  const asSelf = await (await admin.req('https://ptra.dev/admin')).text();

  ok('tab one is pia', asPia.includes('pia@pontera.com') && !asPia.includes('quinn@pontera.com'));
  ok('tab two is quinn', asQuinn.includes('quinn@pontera.com') && !asQuinn.includes('pia@pontera.com'));
  ok('tab three is still the administrator',
     asSelf.includes('root@pontera.com') && !asSelf.includes('class="impbar"'));
  ok('the administrator tab keeps admin navigation', asSelf.includes('href="/admin/users"'));

  // Reloading each one keeps giving the same identity: nothing is stored, so
  // there is no shared state for one tab to overwrite in another.
  const again = await (await admin.req('https://ptra.dev' + a.location)).text();
  ok('reloading a tab is stable', again.includes('pia@pontera.com'));
}

/* ----------------------------------------- 3. it grants nothing extra */
section('an impersonated view holds only that person\'s rights');
{
  const started = await startAs(admin, 'pia@pontera.com');
  const users = await admin.req('https://ptra.dev' + started.location + '/users');
  ok('administration pages are refused', users.status === 403, String(users.status));

  const page = await (await admin.req('https://ptra.dev' + started.location)).text();
  ok('no administration navigation is offered',
     !page.includes('href="' + started.location + '/users"'));
  ok('no domains tab either', !page.includes('href="' + started.location + '/domains"'));
}

/* ------------------------------------------------- 4. who may be viewed */
section('impersonation only ever reaches downwards');
{
  // Promote rhea so there are two administrators.
  const edit = 'https://ptra.dev/admin/users/edit?u=rhea%40pontera.com';
  const tok = Harness.csrfFor(await (await admin.req(edit)).text(), '/admin/users/edit');
  await admin.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: tok, u: 'rhea@pontera.com', isAdmin: '1', allDirectories: '1' },
  });

  const rootTry = await startAs(admin, 'root@pontera.com');
  ok('the root administrator is never listed',
     !usersPage.includes('root@pontera.com') || rootTry.status === 403, String(rootTry.status));

  // A non-root administrator may not borrow another administrator's reach.
  const rhea = peer(admin);
  await rhea.signIn('rhea@pontera.com');
  const sideways = await startAs(rhea, 'root@pontera.com');
  ok('an admin cannot impersonate the root admin', sideways.status === 403, String(sideways.status));

  // An ordinary account cannot impersonate at all.
  const pia = peer(admin);
  await pia.signIn('pia@pontera.com');
  const list = await pia.req('https://ptra.dev/admin/users');
  ok('an ordinary user cannot reach the people list', list.status === 403, String(list.status));
  const direct = await pia.req('https://ptra.dev/admin/users/impersonate', {
    form: { _csrf: impToken, u: 'quinn@pontera.com' },
  });
  ok('and cannot post the action directly', direct.status === 403, String(direct.status));
}

/* ------------------------------------------- 5. the URL is not a bearer */
section('an impersonation URL is bound to the session that made it');
{
  const started = await startAs(admin, 'pia@pontera.com');

  // Another administrator's browser holds a different session cookie.
  const rhea = peer(admin);
  await rhea.signIn('rhea@pontera.com');
  const stolen = await rhea.req('https://ptra.dev' + started.location);
  ok('the URL does nothing in another browser', stolen.status === 403, String(stolen.status));

  // And nothing at all without a session.
  const anon = peer(admin);
  const out = await anon.req('https://ptra.dev' + started.location);
  ok('an anonymous visitor is sent to sign in',
     out.status === 303 && (out.headers.get('Location') || '').startsWith('/admin?next='),
     out.status + ' ' + out.headers.get('Location'));

  const tampered = started.location.slice(0, -2) + 'xy';
  const bad = await admin.req('https://ptra.dev' + tampered);
  ok('a tampered token is refused', bad.status === 403, String(bad.status));
}

/* -------------------------------------------------- 6. ending the view */
section('ending impersonation');
{
  const started = await startAs(admin, 'pia@pontera.com');
  const self = await admin.req('https://ptra.dev/admin');
  ok('leaving the namespace is all it takes', self.status === 200, String(self.status));

  // Signing the administrator out ends every impersonation at once, because
  // the token is only ever honoured alongside that session's cookie.
  const logoutPage = await (await admin.req('https://ptra.dev/logout')).text();
  const logoutToken = Harness.csrf(logoutPage);
  await admin.req('https://ptra.dev/logout', { form: { _csrf: logoutToken } });
  const after = await admin.req('https://ptra.dev' + started.location);
  ok('signing out ends every impersonated tab',
     after.status === 303 && (after.headers.get('Location') || '').startsWith('/admin?next='),
     after.status + ' ' + after.headers.get('Location'));
}

/* ------------------------------------------------------- 7. audit trail */
section('the log credits the administrator, not the person viewed');
{
  const fresh = peer(admin);
  await fresh.signIn('root@pontera.com');
  await startAs(fresh, 'quinn@pontera.com');
  const log = await (await fresh.req('https://ptra.dev/admin/audit')).text();
  ok('starting a view is recorded', log.includes('user.impersonated'));
  ok('the record names the administrator', log.includes('root@pontera.com'));
  ok('and names who was viewed', log.includes('quinn@pontera.com'));
}

console.log(`\nimpersonation: ${passed} passed, ${failed} failed`);
admin.restore();
export default { passed, failed };
