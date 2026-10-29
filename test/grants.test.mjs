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

/* ------------------------------------- 1. admins are unrestricted */
section('administrators hold every permission by default');
{
  const token = Harness.csrf(await (await admin.req('https://ptra.dev/admin/links/new')).text());
  for (const host of ['ptra.cc', 'ptra.dev']) {
    const r = await admin.req('https://ptra.dev/admin/links/new', {
      form: { _csrf: token, host, path: 'admin-' + host.split('.')[1], target: 'example.com/a', status: '302' },
    });
    ok(`admin creates a link on ${host}`, (r.headers.get('Location') || '').includes('link.created'),
       r.status + ' ' + r.headers.get('Location'));
  }

  const dirToken = Harness.csrfFor(await (await admin.req('https://ptra.dev/admin/directories')).text(),
                                   '/admin/directories/new');
  for (const host of ['ptra.cc', 'ptra.dev']) {
    const r = await admin.req('https://ptra.dev/admin/directories/new', {
      form: { _csrf: dirToken, host, path: 'adm' },
    });
    ok(`admin creates a directory on ${host}`, (r.headers.get('Location') || '').includes('dir.created'),
       r.status + ' ' + r.headers.get('Location'));
  }

  // The UI must say so rather than showing an empty grant list.
  const over = await (await admin.req('https://ptra.dev/admin')).text();
  ok('overview states admin reach', over.includes('administrator rights on every domain'));
  ok('overview lists every domain', over.includes('ptra.cc') && over.includes('ptra.dev'));
  ok('directories column reads All', /<td>All<\/td>/.test(over));
  const newForm = await (await admin.req('https://ptra.dev/admin/links/new')).text();
  // The directory picker is the statement now: an administrator is offered
  // every root and every directory on every domain.
  ok('create form offers every domain root',
     newForm.includes('>ptra.cc/<') && newForm.includes('>ptra.dev/<'),
     (newForm.match(/<option[^>]*data-host[^>]*>[^<]*<\/option>/g) || []).join(' '));
}

/* --------------------------- 2. per user:domain directory creation */
section('directory creation is a per user and domain grant');
{
  const ivy = peer(admin);
  await ivy.signIn('ivy@pontera.com');

  const noForm = await (await ivy.req('https://ptra.dev/admin/directories')).text();
  ok('ungranted user sees no create form', !noForm.includes('Create a directory'));

  // The permission itself, checked directly: a CSRF token is bound to its own
  // session, so an ungranted user has no way to even submit the form.
  const { loadConfig } = await import('../config.js');
  const { canCreateDirectory } = await import('../permissions.js');
  const { getUserByNorm } = await import('../users.js');
  const { resolveDomain } = await import('../domains.js');
  const cfg = await loadConfig(admin.env);
  const ivyUser = await getUserByNorm(cfg, 'ivy@pontera.com');
  const cc = await resolveDomain(cfg, 'ptra.cc');
  const before = await canCreateDirectory(cfg, {
    user: ivyUser, domain: cc, host: 'ptra.cc', pathLc: 'ivydir',
  });
  ok('ungranted user is refused by the permission check', before.allowed === false, String(before.reason));

  // Grant it on ptra.cc only.
  const uEdit = 'https://ptra.dev/admin/users/edit?u=ivy%40pontera.com';
  const uTok = Harness.csrfFor(await (await admin.req(uEdit)).text(), '/admin/users/edit');
  const saved = await admin.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: uTok, u: 'ivy@pontera.com', 'dir__ptra.cc': '1', 'root__ptra.cc': '1' },
  });
  ok('grant saved', saved.status === 303, String(saved.status));

  const form = await (await ivy.req('https://ptra.dev/admin/directories')).text();
  ok('granted user now sees the form', form.includes('Create a directory'));
  ok('form offers only the granted domain',
     form.includes('value="ptra.cc"') && !/name="host">[^<]*<option value="ptra\.dev"/.test(form));

  const ownToken = Harness.csrfFor(form, '/admin/directories/new');
  const made = await ivy.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: ownToken, host: 'ptra.cc', path: 'ivydir' },
  });
  ok('granted user creates on ptra.cc', (made.headers.get('Location') || '').includes('dir.created'),
     made.status + ' ' + made.headers.get('Location'));

  const wrongHost = await ivy.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: ownToken, host: 'ptra.dev', path: 'ivydir2' },
  });
  ok('grant does not leak to the other domain', wrongHost.status === 403, String(wrongHost.status));

  // A directory administrator may nest, and may pass that on.
  const jack = peer(admin);
  await jack.signIn('jack@pontera.com');
  const dirEdit = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=ivydir';
  const gTok = Harness.csrfFor(await (await ivy.req(dirEdit)).text(), '/admin/directories/grant');
  const granted = await ivy.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: gTok, host: 'ptra.cc', path: 'ivydir', email: 'jack@pontera.com',
            canCreate: '1', canManage: '1' },
  });
  ok('directory admin appoints another', (granted.headers.get('Location') || '').includes('grant.saved'));

  const jackForm = await (await jack.req('https://ptra.dev/admin/directories')).text();
  const jackToken = Harness.csrfFor(jackForm, '/admin/directories/new');
  const nested = await jack.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: jackToken, host: 'ptra.cc', path: 'ivydir/sub' },
  });
  ok('appointed directory admin nests inside it',
     (nested.headers.get('Location') || '').includes('dir.created'),
     nested.status + ' ' + nested.headers.get('Location'));

  const outside = await jack.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: jackToken, host: 'ptra.cc', path: 'jack-root' },
  });
  ok('but not at the domain root', outside.status === 403, String(outside.status));
}

/* ------------------------------- 3. listings default to all domains */
section('listings cover every domain by default');
{
  const links = await (await admin.req('https://ptra.dev/admin/links?scope=all')).text();
  ok('links listing spans domains', links.includes('ptra.cc/') && links.includes('ptra.dev/'));
  ok('links listing says every domain', links.includes('Every link on every domain'));
  ok('links offers the domain picker in the header', links.includes('>All Domains</option>'));

  const filtered = await (await admin.req('https://ptra.dev/admin/links?scope=all&host=ptra.cc')).text();
  ok('filtering to one domain works', filtered.includes('ptra.cc/') && !filtered.includes('>ptra.dev/adm'),
     'ptra.dev rows leaked into a ptra.cc filter');
  ok('filter is reflected in the heading', filtered.includes('Every link on ptra.cc'));

  const dirs = await (await admin.req('https://ptra.dev/admin/directories')).text();
  ok('directories span domains', dirs.includes('ptra.cc/adm') && dirs.includes('ptra.dev/adm'));
  ok('directories say every domain', dirs.includes('Showing every domain'));

  const dirsOne = await (await admin.req('https://ptra.dev/admin/directories?host=ptra.dev')).text();
  ok('directories filter to one domain', dirsOne.includes('ptra.dev/adm') && !dirsOne.includes('ptra.cc/adm'));

  // A bogus host falls back to every domain rather than erroring.
  const bogus = await admin.req('https://ptra.dev/admin/links?scope=all&host=evil.example');
  ok('unknown host falls back to all', (await bogus.text()).includes('Every link on every domain'),
     String(bogus.status));
}

/* --------------------------- 4. naming and the header domain picker */
section('branding and the header domain picker');
{
  const page = await admin.req('https://ptra.dev/admin');
  const b = await page.text();
  ok('brand reads Shrink Link', /class="brand"[^>]*>Shrink Link</.test(b),
     (b.match(/class="brand"[^>]*>[^<]*/) || [''])[0]);
  ok('title reads Shrink Link', b.includes('<title>Overview - Shrink Link</title>'));
  ok('footer carries the configured line',
     b.includes('<div>\u00a9 Example Inc. All rights reserved</div>'),
     (b.match(/<footer[\s\S]*?<\/footer>/) || [''])[0]);
  ok('no "Slink" anywhere on the page', !b.includes('Slink'));

  // The line is configuration, not a constant: it changes with the
  // variable, is escaped like anything else, and goes away when unset.
  const other = new Harness({ FOOTER_TEXT: 'Acme & Co <Ltd>' });
  await other.signIn('root@pontera.com');
  const mine = await (await other.req('https://ptra.dev/admin')).text();
  ok('another installation gets its own line', mine.includes('<div>Acme &amp; Co &lt;Ltd&gt;</div>'),
     (mine.match(/<footer[\s\S]*?<\/footer>/) || [''])[0]);
  ok('and it is escaped, not injected', !mine.includes('<Ltd>'));
  other.restore();

  const bare = new Harness({ FOOTER_TEXT: '' });
  await bare.signIn('root@pontera.com');
  const none = await (await bare.req('https://ptra.dev/admin')).text();
  ok('with none set there is no line at all', /<footer class="foot"><\/footer>/.test(none),
     (none.match(/<footer[\s\S]*?<\/footer>/) || [''])[0]);
  bare.restore();

  // Every page the service serves, not only the admin area.
  const guest = new Harness({ FOOTER_TEXT: 'Acme & Co <Ltd>' });
  for (const [name, url] of [
    ['the sign-in page', 'https://ptra.dev/admin'],
    ['a short-link host root', 'https://ptra.cc/'],
  ]) {
    const r = await guest.req(url);
    const page = r.status === 200 ? await r.text() : '';
    if (page) {
      ok(name + ' carries it too', page.includes('<div>Acme &amp; Co &lt;Ltd&gt;</div>'),
         (page.match(/<footer[\s\S]*?<\/footer>/) || [''])[0]);
    }
  }
  guest.restore();

  const anon = new Harness();
  anon.env.KV = admin.env.KV;
  const signin = await (await anon.req('https://ptra.dev/admin')).text();
  ok('sign-in page reads Shrink Link', signin.includes('Shrink Link') && !signin.includes('Slink'));

  // The header picker replaces the static host label on filterable pages.
  const pick = (b.match(/<form class="hostpick"[\s\S]*?<\/form>/) || [''])[0];
  ok('header carries the picker', pick.includes('All Domains'));
  ok('All Domains is the default', /value="all" selected/.test(pick));
  ok('every domain is offered', pick.includes('>ptra.cc<') && pick.includes('>ptra.dev<'));
  ok('static host label is gone', !b.includes('class="hostname"'));

  for (const p of ['/admin/links', '/admin/directories']) {
    const t = await (await admin.req('https://ptra.dev' + p)).text();
    const f = (t.match(/<form class="hostpick"[\s\S]*?<\/form>/) || [''])[0];
    ok(`${p} has the picker posting to itself`, f.includes(`action="${p}"`), f.slice(0, 80));
  }

  // Pages acting on one record must not offer it.
  for (const p of ['/admin/users', '/admin/settings', '/admin/domains']) {
    const t = await (await admin.req('https://ptra.dev' + p)).text();
    ok(`${p} has no picker`, !t.includes('hostpick'));
  }

  // Choosing a domain keeps the other filters.
  const withFilters = await (await admin.req('https://ptra.dev/admin/links?scope=all&host=ptra.cc&dir=adm')).text();
  const ff = (withFilters.match(/<form class="hostpick"[\s\S]*?<\/form>/) || [''])[0];
  ok('picker carries scope and dir', ff.includes('name="scope"') && ff.includes('name="dir"'));
  ok('picker reflects the chosen domain', /value="ptra\.cc" selected/.test(ff));

  // And it still works with JavaScript off.
  ok('picker has a no-JS submit', ff.includes('<button type="submit"'));
}

console.log(`\ngrants: ${passed} passed, ${failed} failed`);
admin.restore();
if (failed) process.exit(1);
