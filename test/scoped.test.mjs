/**
 * An administrator may be scoped out of directories they hold no grant on.
 * That scoping covers what is inside a directory; it never takes away the
 * ownership changes an administrator can make on anything.
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

for (const who of ['sam@pontera.com', 'tess@pontera.com']) {
  const h = peer(root);
  await h.signIn(who);
}

async function setUser(form) {
  const edit = 'https://ptra.dev/admin/users/edit?u=' + encodeURIComponent(form.u);
  const tok = Harness.csrfFor(await (await root.req(edit)).text(), '/admin/users/edit');
  return root.req('https://ptra.dev/admin/users/edit', { form: { _csrf: tok, ...form } });
}

// A directory with a link inside it, both owned by tess.
const dirTok = Harness.csrfFor(
  await (await root.req('https://ptra.dev/admin/directories')).text(),
  '/admin/directories/new'
);
await root.req('https://ptra.dev/admin/directories/new', {
  form: { _csrf: dirTok, host: 'ptra.cc', path: 'team' },
});
const linkTok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
await root.req('https://ptra.dev/admin/links/new', {
  form: { _csrf: linkTok, host: 'ptra.cc', path: 'team/plan', target: 'example.com/plan', status: '302' },
});
const rootLinkTok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
await root.req('https://ptra.dev/admin/links/new', {
  form: { _csrf: rootLinkTok, host: 'ptra.cc', path: 'loose', target: 'example.com/loose', status: '302' },
});

// Sam is an administrator, at first with the default full reach.
await setUser({ u: 'sam@pontera.com', isAdmin: '1', allDirectories: '1' });
const sam = peer(root);
await sam.signIn('sam@pontera.com');

const EDIT = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=team%2Fplan';
const DIR = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=team';

/* ------------------------------------------- 1. the default is full reach */
section('administrators reach every directory by default');
{
  const page = await sam.req(EDIT);
  ok('an unscoped admin edits inside a directory', page.status === 200, String(page.status));
  const form = await (await root.req('https://ptra.dev/admin/users/edit?u=sam%40pontera.com')).text();
  ok('the box is offered and ticked', /name="allDirectories"[^>]*checked/.test(form), 'not ticked');
  ok('the box explains itself', form.includes('Reaches every directory'));
}

/* ------------------------------------------------------- 2. scoping it off */
section('scoping an administrator out of directories');
{
  await setUser({ u: 'sam@pontera.com', isAdmin: '1' });   // allDirectories absent => off
  const inside = await sam.req(EDIT);
  ok('managing inside a directory is refused', inside.status === 200 && !(await inside.clone().text()).includes('name="newpath"'),
     String(inside.status));

  const loose = await sam.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=loose');
  ok('a link outside any directory is untouched',
     (await loose.text()).includes('name="newpath"'), String(loose.status));

  const dirPage = await sam.req(DIR);
  ok('the directory itself is not theirs to manage', dirPage.status === 403, String(dirPage.status));
}

/* ------------------------------- 3. ownership stays an administrative act */
section('a scoped administrator may still change ownership of anything');
{
  const page = await (await sam.req(EDIT)).text();
  ok('the ownership card is still offered', page.includes('/admin/links/transfer'), 'no transfer form');
  ok('and it says why the rest is missing', page.includes('not scoped to this directory'));
  ok('but nothing else is editable', !page.includes('/admin/links/delete'));

  const tok = Harness.csrfFor(page, '/admin/links/transfer');
  const moved = await sam.req('https://ptra.dev/admin/links/transfer', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'team/plan', owner: 'tess@pontera.com' },
  });
  ok('the transfer goes through', (moved.headers.get('Location') || '').includes('link.moved'),
     moved.status + ' ' + moved.headers.get('Location'));

  const dirForm = await (await root.req(DIR)).text();
  const dirTransfer = Harness.csrfFor(dirForm, '/admin/directories/transfer');
  const dirMoved = await sam.req('https://ptra.dev/admin/directories/transfer', {
    form: { _csrf: dirTransfer, host: 'ptra.cc', path: 'team', owner: 'tess@pontera.com' },
  });
  ok('a directory transfer is refused only for a bad token, not for scope',
     dirMoved.status !== 403, String(dirMoved.status));
}

/* ------------------- 4. scoping removes reach, it does not demote */
section('a scoped administrator keeps full authority where they are granted');
{
  // Grant sam the ops directory, and mark it read-only: a read-only mark
  // exists to stop non-administrators, so it must not stop this one.
  await root.req('https://ptra.dev/admin/directories/new', {
    form: {
      _csrf: Harness.csrfFor(
        await (await root.req('https://ptra.dev/admin/directories')).text(),
        '/admin/directories/new'
      ),
      host: 'ptra.cc', path: 'ops',
    },
  });
  const opsEdit = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=ops';
  const grantTok = Harness.csrfFor(await (await root.req(opsEdit)).text(), '/admin/directories/grant');
  await root.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: grantTok, host: 'ptra.cc', path: 'ops', email: 'sam@pontera.com', canManage: '1' },
  });
  const roTok = Harness.csrfFor(await (await root.req(opsEdit)).text(), '/admin/directories/edit');
  await root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: roTok, host: 'ptra.cc', path: 'ops', enabled: '1', readonly: '1' },
  });

  const page = await sam.req(opsEdit);
  ok('a granted directory is reachable', page.status === 200, String(page.status));
  const text = await page.text();
  ok('and read-only does not stop an administrator there',
     text.includes('name="readonly"'), 'no admin-only control');

  // The host root is not a directory, so scoping never reaches it.
  const newDir = await sam.req('https://ptra.dev/admin/directories');
  ok('they may still create directories at the root',
     (await newDir.text()).includes('/admin/directories/new'), String(newDir.status));
  const made = await sam.req('https://ptra.dev/admin/directories/new', {
    form: {
      _csrf: Harness.csrfFor(
        await (await sam.req('https://ptra.dev/admin/directories')).text(),
        '/admin/directories/new'
      ),
      host: 'ptra.cc', path: 'sam-root-dir',
    },
  });
  ok('and the creation goes through',
     (made.headers.get('Location') || '').includes('dir.created'),
     made.status + ' ' + made.headers.get('Location'));

  // A directory they hold nothing on stays shut.
  const shut = await sam.req(DIR);
  ok('an ungranted directory is still refused', shut.status === 403, String(shut.status));
}

/* ------------------------------------------------- 5. the root admin is fixed */
section('a root administrator can never be scoped');
{
  const form = await (await root.req('https://ptra.dev/admin/users')).text();
  ok('the root account is not listed at all', !form.includes('root@pontera.com<'), 'listed');
  const still = await root.req(EDIT);
  ok('the root administrator still reaches everything',
     (await still.text()).includes('name="newpath"'), String(still.status));
}

console.log(`\nscoped admins: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
