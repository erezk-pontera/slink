/**
 * Search must never show a row the viewer could not already reach, and a
 * batch action must re-check every row rather than trusting the selection
 * that came back from the browser.
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
for (const who of ['uma@pontera.com', 'vic@pontera.com']) {
  const h = peer(root);
  await h.signIn(who);
}

async function mkDir(host, path) {
  const tok = Harness.csrfFor(
    await (await root.req('https://ptra.dev/admin/directories')).text(),
    '/admin/directories/new'
  );
  return root.req('https://ptra.dev/admin/directories/new', { form: { _csrf: tok, host, path } });
}
async function mkLink(h, host, path, target) {
  const tok = Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());
  return h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host, path, target, status: '302' },
  });
}
async function grant(host, dirPath, email, canManage) {
  const page = await (await root.req(
    `https://ptra.dev/admin/directories/edit?host=${host}&path=${encodeURIComponent(dirPath)}`
  )).text();
  const tok = Harness.csrfFor(page, '/admin/directories/grant');
  return root.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: tok, host, path: dirPath, email, canCreate: '1', ...(canManage ? { canManage: '1' } : {}) },
  });
}

await mkDir('ptra.cc', 'eng');
await mkDir('ptra.cc', 'ops');
await mkLink(root, 'ptra.cc', 'eng/runbook', 'example.com/runbook');
await mkLink(root, 'ptra.cc', 'ops/oncall', 'example.com/oncall');
await mkLink(root, 'ptra.cc', 'secret-root', 'example.com/secret');
await grant('ptra.cc', 'eng', 'uma@pontera.com', true);

const uma = peer(root);
await uma.signIn('uma@pontera.com');
await mkLink(uma, 'ptra.cc', 'uma-own', 'example.com/uma');
const vic = peer(root);
await vic.signIn('vic@pontera.com');

const S = (h, q, extra = '') => h.req(`https://ptra.dev/admin/search?q=${encodeURIComponent(q)}${extra}`);

/* ----------------------------------------------------- 1. what it finds */
section('search finds links and directories across domains');
{
  const page = await (await S(root, '')).text();
  ok('the search page is reachable', page.includes('<h1>Search</h1>'));
  ok('it is in the navigation', page.includes('href="/admin/search"'));

  const hit = await (await S(root, 'runbook')).text();
  ok('a shortcut matches', hit.includes('ptra.cc/eng/runbook'));
  ok('unrelated rows are left out', !hit.includes('ptra.cc/ops/oncall'));

  const byTarget = await (await S(root, 'example.com/oncall')).text();
  ok('a destination matches', byTarget.includes('ptra.cc/ops/oncall'));

  const dirs = await (await S(root, 'eng', '&type=directories')).text();
  ok('directories can be searched alone', dirs.includes('ptra.cc/eng'));
  ok('and links are then excluded', !dirs.includes('eng/runbook'));

  const scoped = await (await S(root, '', '&host=ptra.dev')).text();
  ok('a domain filter narrows the search', !scoped.includes('ptra.cc/eng/runbook'));
  const all = await (await S(root, '')).text();
  ok('all domains is the default', all.includes('ptra.cc/eng/runbook'));
}

/* ------------------------------------------------- 2. it shows no more */
section('search shows only what the viewer may reach');
{
  const mine = await (await S(uma, '')).text();
  ok('a granted directory is visible', mine.includes('ptra.cc/eng'));
  ok('and the links inside it', mine.includes('eng/runbook'));
  ok('their own link is visible', mine.includes('ptra.cc/uma-own'));
  ok('another directory is not', !mine.includes('ptra.cc/ops'));
  ok('someone else\'s root link is not', !mine.includes('secret-root'));
  ok('no batch bar for a non-administrator', !mine.includes('/admin/search/batch'));

  const nothing = await (await S(vic, '')).text();
  ok('a user with nothing sees nothing', nothing.includes('0 result'));
  ok('not even root-level links', !nothing.includes('secret-root'));
}

/* --------------------------------------------------- 3. batch ownership */
section('batch ownership change');
{
  const page = await (await S(root, 'eng')).text();
  ok('an administrator gets the batch bar', page.includes('/admin/search/batch'));
  ok('every action is offered', page.includes('Make read-only') && page.includes('Add a directory administrator'));
  const tok = Harness.csrfFor(page, '/admin/search/batch');

  const r = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok, op: 'transfer', email: 'vic@pontera.com', sel: 'link:ptra.cc:eng/runbook' },
  });
  const after = await r.text();
  ok('one link changed hands', after.includes('1 changed'), after.slice(0, 200));

  const check = await (await S(root, 'runbook')).text();
  ok('the new owner is shown', check.includes('vic@pontera.com'));
}

/* ------------------------------------------------------ 4. batch readonly */
section('batch read-only');
{
  const page = await (await S(root, '')).text();
  const tok = Harness.csrfFor(page, '/admin/search/batch');
  const r = await root.req('https://ptra.dev/admin/search/batch', {
    form: {
      _csrf: tok,
      op: 'readonly',
      sel: ['link:ptra.cc:eng/runbook', 'link:ptra.cc:ops/oncall', 'dir:ptra.cc:ops'],
    },
  });
  const after = await r.text();
  ok('all three were marked', after.includes('3 changed'), after.slice(0, 200));
  ok('the rows render as read-only', after.includes('read-only'));

  const tok2 = Harness.csrfFor(after, '/admin/search/batch');
  const back = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok2, op: 'unreadonly', sel: ['link:ptra.cc:eng/runbook', 'dir:ptra.cc:ops'] },
  });
  ok('and can be cleared again', (await back.text()).includes('2 changed'));
}

/* ------------------------------------------- 5. batch directory grants */
section('batch directory administrators');
{
  const page = await (await S(root, '', '&type=directories')).text();
  const tok = Harness.csrfFor(page, '/admin/search/batch');
  const added = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok, op: 'grant', email: 'vic@pontera.com', sel: ['dir:ptra.cc:eng', 'dir:ptra.cc:ops'] },
  });
  ok('two directories gained an administrator', (await added.text()).includes('2 changed'));

  const vicSees = await (await S(vic, '', '&type=directories')).text();
  ok('they can now see both', vicSees.includes('ptra.cc/eng') && vicSees.includes('ptra.cc/ops'));

  const page2 = await (await S(root, '', '&type=directories')).text();
  const tok2 = Harness.csrfFor(page2, '/admin/search/batch');
  const removed = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok2, op: 'revoke', email: 'vic@pontera.com', sel: ['dir:ptra.cc:eng', 'dir:ptra.cc:ops'] },
  });
  ok('and lose it again', (await removed.text()).includes('2 changed'));
  const gone = await (await S(vic, '', '&type=directories')).text();
  ok('the directories disappear from their view', !gone.includes('ptra.cc/ops'));
}

/* --------------------------------------------------- 6. the batch is checked */
section('a batch re-checks every row');
{
  const page = await (await S(root, '')).text();
  const tok = Harness.csrfFor(page, '/admin/search/batch');

  const missing = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok, op: 'readonly', sel: 'link:ptra.cc:no-such-link' },
  });
  ok('a row that is gone is skipped, not fatal', (await missing.text()).includes('0 changed'));

  const tok2 = Harness.csrfFor(await (await S(root, '')).text(), '/admin/search/batch');
  const wrongKind = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok2, op: 'grant', email: 'vic@pontera.com', sel: 'link:ptra.cc:secret-root' },
  });
  ok('a grant is refused on a link', (await wrongKind.text()).includes('directories only'));

  // A non-administrator is never handed a batch token, so a hand-made
  // request fails at CSRF; either way nothing may change.
  const umaPage = await (await S(uma, '')).text();
  ok('no batch token is minted for them', !Harness.csrfFor(umaPage, '/admin/search/batch'));
  const refused = await uma.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: 'forged', op: 'readonly', sel: 'link:ptra.cc:uma-own' },
  });
  ok('a hand-made batch is refused',
     refused.status === 403 || (refused.headers.get('Location') || '').includes('csrf'),
     refused.status + ' ' + refused.headers.get('Location'));
  const stillOpen = await (await S(uma, 'uma-own')).text();
  ok('and nothing was marked read-only', !stillOpen.includes('read-only'));

  // An administrator may move any directory in bulk, owned or not.
  const tok3 = Harness.csrfFor(await (await S(root, '', '&type=directories')).text(), '/admin/search/batch');
  const mine = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok3, op: 'transfer', email: 'vic@pontera.com', sel: 'dir:ptra.cc:eng' },
  });
  ok('a directory moves in bulk', (await mine.text()).includes('1 changed'));

  const tok4 = Harness.csrfFor(await (await S(root, '', '&type=directories')).text(), '/admin/search/batch');
  const notMine = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok4, op: 'transfer', email: 'uma@pontera.com', sel: 'dir:ptra.cc:eng' },
  });
  const text = await notMine.text();
  ok('one they do not own moves too', text.includes('1 changed'), text.slice(0, 220));

  // The single-directory screen is unrestricted for an administrator as well.
  const dirPage = await (await root.req(
    'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=eng'
  )).text();
  const oneTok = Harness.csrfFor(dirPage, '/admin/directories/transfer');
  const oneOff = await root.req('https://ptra.dev/admin/directories/transfer', {
    form: { _csrf: oneTok, host: 'ptra.cc', path: 'eng', owner: 'vic@pontera.com' },
  });
  ok('and so is the directory screen',
     oneOff.status !== 403 && !(oneOff.headers.get('Location') || '').includes('csrf'),
     oneOff.status + ' ' + oneOff.headers.get('Location'));
}

console.log(`\nsearch and batch: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
