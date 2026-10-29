/**
 * A directory may answer its own root, and unknown shortcuts under it, with
 * a MISSING destination of its own. The domain decides whether directories
 * may set one, and an administrator may exempt a single directory either way.
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

const root = new Harness();
await root.signIn('root@pontera.com');

const DIR = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=team';
const DOMAIN = 'https://ptra.dev/admin/domains/edit?host=ptra.cc';

async function mkDir(path) {
  const tok = Harness.csrfFor(
    await (await root.req('https://ptra.dev/admin/directories')).text(),
    '/admin/directories/new'
  );
  return root.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: tok, host: 'ptra.cc', path },
  });
}
async function setDirMissing(value) {
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/edit');
  return root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'team', missingUrl: value, enabled: '1' },
  });
}
async function setExempt(on) {
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/exempt');
  return root.req('https://ptra.dev/admin/directories/exempt', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'team', ...(on ? { ex_missing: '1' } : {}) },
  });
}
async function setDomainPolicy(mode, target = '') {
  const page = await (await root.req(DOMAIN)).text();
  const tok = Harness.csrfFor(page, '/admin/domains/edit');
  return root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: tok, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain',
      enabled: '1', dirMissingMode: mode, dirMissingTarget: target,
    },
  });
}

// An anonymous visitor, since ptra.cc needs no sign-in.
const guest = peer(root);
const hit = (path) => guest.req('https://ptra.cc/' + path);

await mkDir('team');

/* ------------------------------------------- 1. the directory's own value */
section('a directory answers its own root');
{
  const before = await hit('team');
  ok('without one it uses the domain default',
     (before.headers.get("Location") || "").includes("fallback.example"),
     before.status + ' ' + before.headers.get('Location'));

  await setDirMissing('https://example.com/team-home');
  const after = await hit('team');
  ok('the directory root uses its own',
     after.headers.get('Location') === 'https://example.com/team-home',
     after.status + ' ' + after.headers.get('Location'));

  const child = await hit('team/nothing-here');
  ok('an unknown shortcut under it does too',
     child.headers.get('Location') === 'https://example.com/team-home',
     child.headers.get('Location'));

  const elsewhere = await hit('not-in-a-directory');
  ok('a path outside the directory is unaffected',
     (elsewhere.headers.get('Location') || '').includes('fallback.example'),
     elsewhere.headers.get('Location'));
}

/* ------------------------------------- 2. a real link still wins outright */
section('a live shortcut is never replaced by the MISSING destination');
{
  const tok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
  await root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', dir: 'ptra.cc/team', path: 'deck', target: 'example.com/deck', status: '302' },
  });
  const r = await hit('team/deck');
  ok('the shortcut resolves normally',
     (r.headers.get('Location') || '').includes('example.com/deck'),
     r.headers.get('Location'));
}

/* ---------------------------------------------------- 3. the domain decides */
section('the domain can take the choice away');
{
  await setDomainPolicy('off');
  const r = await hit('team');
  ok('an off domain ignores the directory value',
     (r.headers.get('Location') || '').includes('fallback.example'), r.headers.get('Location'));
  const page = await (await root.req(DIR)).text();
  ok('and the field is not offered', !page.includes('name="missingUrl"'));
  ok('the screen explains why', page.includes('does not let directories set their own'));

  await setDomainPolicy('locked', 'https://example.com/all-teams');
  const locked = await hit('team');
  ok('a locked domain imposes its own',
     locked.headers.get('Location') === 'https://example.com/all-teams', locked.headers.get('Location'));

  await setDomainPolicy('optional');
  const back = await hit('team');
  ok('restoring the choice restores the directory value',
     back.headers.get('Location') === 'https://example.com/team-home', back.headers.get('Location'));
}

/* ------------------------------------------------ 4. the per-directory escape */
section('an administrator can exempt one directory');
{
  await setDomainPolicy('locked', 'https://example.com/all-teams');
  const before = await hit('team');
  ok('locked applies first', before.headers.get('Location') === 'https://example.com/all-teams');

  await setExempt(true);
  const after = await hit('team');
  ok('an exempt directory keeps its own',
     after.headers.get('Location') === 'https://example.com/team-home', after.headers.get('Location'));

  const page = await (await root.req(DIR)).text();
  ok('the field comes back for an exempt directory', page.includes('name="missingUrl"'));

  await setExempt(false);
  const off = await hit('team');
  ok('withdrawing the exemption restores the lock',
     off.headers.get('Location') === 'https://example.com/all-teams', off.headers.get('Location'));
}

/* ------------------------------------------- 5. only an admin may exempt */
section('the exemption is administrators only');
{
  const nina = peer(root);
  await nina.signIn('nina@pontera.com');
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/exempt');
  const r = await nina.req('https://ptra.dev/admin/directories/exempt', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'team', ex_missing: '1' },
  });
  ok('a non-administrator cannot grant it',
     r.status === 403 || (r.headers.get('Location') || '').includes('csrf'),
     r.status + ' ' + r.headers.get('Location'));

  // And the value itself is rejected where the domain says no.
  await setDomainPolicy('off');
  const dirPage = await (await root.req(DIR)).text();
  const editTok = Harness.csrfFor(dirPage, '/admin/directories/edit');
  await root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: editTok, host: 'ptra.cc', path: 'team', missingUrl: 'https://evil.example/x', enabled: '1' },
  });
  await setDomainPolicy('optional');
  const r2 = await hit('team');
  ok('a submission for a field that was not offered is ignored',
     r2.headers.get('Location') === 'https://example.com/team-home', r2.headers.get('Location'));
}

/* -------------------------------------------------- 6. the value is validated */
section('the destination is validated like any other');
{
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/edit');
  const r = await root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'team', missingUrl: 'javascript:alert(1)', enabled: '1' },
  });
  const text = await r.text();
  ok('a dangerous scheme is refused', text.includes('not allowed') || text.includes('blocked'),
     text.slice(0, 200));
  const still = await hit('team');
  ok('and nothing was stored', still.headers.get('Location') === 'https://example.com/team-home');
}

console.log(`\ndirectory MISSING: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
