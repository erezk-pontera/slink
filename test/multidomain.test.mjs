/**
 * A shortcut can be put on several domains in one go, and moved between
 * them afterwards. Both are the same question asked repeatedly — may this
 * person create this here, and is it free — so both check every domain
 * before writing to any.
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
const guest = peer(root);

const token = async () => Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
const create = async (form) =>
  root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: await token(), status: '302', ...form },
  });
const exists = async (host, path) =>
  (await root.req(`https://ptra.dev/admin/links/edit?host=${host}&path=${encodeURIComponent(path)}`))
    .status === 200;

/* ------------------------------------------------ 1. several at once */
section('one submission, several domains');
{
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  // The default domain is the one being browsed, so the other is offered.
  ok('the form offers the other domains', form.includes('name="also__ptra.cc"'), 'default host is ptra.dev');
  ok('and explains the all-or-nothing rule', form.includes('none are made'));

  const made = await create({
    host: 'ptra.cc', path: 'both-ways', target: 'example.com/b', 'also__ptra.dev': '1',
  });
  ok('the submission succeeds', (made.headers.get('Location') || '').includes('createdMany'),
     made.headers.get('Location'));
  ok('it exists on the first domain', await exists('ptra.cc', 'both-ways'));
  ok('and on the second', await exists('ptra.dev', 'both-ways'));

  const hit = await guest.req('https://ptra.cc/both-ways');
  ok('the first one resolves', (hit.headers.get('Location') || '').includes('example.com/b'),
     hit.headers.get('Location'));
}

/* ------------------------------------------------- 2. all or nothing */
section('a problem on one domain creates none');
{
  await create({ host: 'ptra.cc', path: 'taken', target: 'example.com/t' });

  const clash = await create({
    host: 'ptra.dev', path: 'taken', target: 'example.com/x', 'also__ptra.cc': '1',
  });
  const text = await clash.text();
  ok('the clash is named with its domain', text.includes('ptra.cc/taken is already in use'),
     text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('nothing was created on the free domain', !(await exists('ptra.dev', 'taken')));

  // The original is untouched.
  const hit = await guest.req('https://ptra.cc/taken');
  ok('the existing link is unharmed', (hit.headers.get('Location') || '').includes('example.com/t'),
     hit.headers.get('Location'));
}

/* ------------------------------------------- 3. permission is per domain */
section('each domain is checked on its own terms');
{
  const nora = peer(root);
  await nora.signIn('nora@pontera.com');
  // Make ptra.cc administrators-only, so an ordinary account cannot create.
  const dom = 'https://ptra.dev/admin/domains/edit?host=ptra.cc';
  const dt = Harness.csrfFor(await (await root.req(dom)).text(), '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dt, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'admins_only', enabled: '1' },
  });

  const tok = Harness.csrf(await (await nora.req('https://ptra.dev/admin/links/new')).text());
  const tried = await nora.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: tok, host: 'ptra.dev', path: 'nora-try', target: 'example.com/n',
      status: '302', 'also__ptra.cc': '1',
    },
  });
  const text = await tried.text();
  ok('the refusal names the domain that refused', text.includes('ptra.cc'),
     text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('and nothing was created anywhere', !(await exists('ptra.dev', 'nora-try')));

  const dt2 = Harness.csrfFor(await (await root.req(dom)).text(), '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dt2, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain', enabled: '1' },
  });
}

/* --------------------------------------- 3b. a directory per domain */
section('each domain chooses its own directory');
{
  // Two directories of the same name would prove nothing, so they differ:
  // the point is that the second domain is asked separately rather than
  // handed the first one's answer.
  const mk = async (host, path) => {
    const page = await (await root.req('https://ptra.dev/admin/directories')).text();
    return root.req('https://ptra.dev/admin/directories/new', {
      form: { _csrf: Harness.csrfFor(page, '/admin/directories/new'), host, path },
    });
  };
  await mk('ptra.dev', 'eng');
  await mk('ptra.cc', 'ops');

  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('the other domain brings its own directory picker',
     form.includes('name="alsodir__ptra.cc"'));
  ok('and the picker offers that domain\'s directories',
     form.includes('value="ptra.cc/ops"'), 'expected ptra.cc/ops among its options');
  ok('not the first domain\'s',
     !/<select[^>]*name="alsodir__ptra.cc"[\s\S]*?value="ptra.dev\/eng"[\s\S]*?<\/select>/.test(form));

  const made = await create({
    host: 'ptra.dev', dir: 'ptra.dev/eng', path: 'runbook', target: 'example.com/r',
    'also__ptra.cc': '1', 'alsodir__ptra.cc': 'ptra.cc/ops',
  });
  ok('the submission succeeds', (made.headers.get('Location') || '').includes('createdMany'),
     made.headers.get('Location'));
  ok('it lands in the chosen directory here', await exists('ptra.dev', 'eng/runbook'));
  ok('and in a different one there', await exists('ptra.cc', 'ops/runbook'));
  ok('not at the other domain\'s root', !(await exists('ptra.cc', 'runbook')));

  const hit = await guest.req('https://ptra.cc/ops/runbook');
  ok('the second one resolves', (hit.headers.get('Location') || '').includes('example.com/r'),
     hit.headers.get('Location'));

  // Only a browser without the script can post these out of step.
  const crossed = await create({
    host: 'ptra.dev', dir: 'ptra.dev/eng', path: 'crossed', target: 'example.com/c',
    'also__ptra.cc': '1', 'alsodir__ptra.cc': 'ptra.dev/eng',
  });
  const text = await crossed.text();
  ok('a directory on the wrong domain is refused',
     text.includes('chosen for ptra.cc') && text.includes('ptra.dev'),
     text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('and nothing was created anywhere', !(await exists('ptra.dev', 'eng/crossed')));

  // The permission check runs again at the destination, so a directory the
  // picker would not have offered is refused even when it is posted by hand.
  const gone = await create({
    host: 'ptra.dev', dir: 'ptra.dev/eng', path: 'nowhere', target: 'example.com/g',
    'also__ptra.cc': '1', 'alsodir__ptra.cc': 'ptra.cc/no-such-dir',
  });
  ok('a directory that does not exist there is refused',
     (await gone.text()).includes('no longer exists on ptra.cc'));
  ok('and that created nothing either', !(await exists('ptra.dev', 'eng/nowhere')));
}

/* --------------------------------------------------------- 4. moving */
section('moving a link between domains');
{
  await create({ host: 'ptra.cc', path: 'to-move', target: 'example.com/mv', note: 'carried' });
  const href = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=to-move';
  const page = await (await root.req(href)).text();
  ok('the move card is offered', page.includes('Move to another domain'));

  const tok = Harness.csrfFor(page, '/admin/links/move');
  const moved = await root.req('https://ptra.dev/admin/links/move', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'to-move', toHost: 'ptra.dev', newpath: 'arrived' },
  });
  ok('the move succeeds', (moved.headers.get('Location') || '').includes('link.moved2'),
     moved.headers.get('Location'));
  ok('the old address is gone', !(await exists('ptra.cc', 'to-move')));
  ok('the new address has it', await exists('ptra.dev', 'arrived'));

  const old = await guest.req('https://ptra.cc/to-move');
  ok('the old shortcut stops answering',
     (old.headers.get('Location') || '').includes('fallback.example'), old.headers.get('Location'));

  const now = await (await root.req('https://ptra.dev/admin/links/edit?host=ptra.dev&path=arrived')).text();
  ok('the note came with it', now.includes('carried'));
}

/* --------------------------------------------------- 5. a move is checked */
section('a move is refused where a create would be');
{
  await create({ host: 'ptra.cc', path: 'blocker', target: 'example.com/x' });
  await create({ host: 'ptra.dev', path: 'blocker', target: 'example.com/y' });

  const href = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=blocker';
  const tok = Harness.csrfFor(await (await root.req(href)).text(), '/admin/links/move');
  const r = await root.req('https://ptra.dev/admin/links/move', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'blocker', toHost: 'ptra.dev', newpath: 'blocker' },
  });
  ok('moving onto a taken shortcut is refused', (await r.text()).includes('already in use'));
  ok('and the link stays where it was', await exists('ptra.cc', 'blocker'));

  const tok2 = Harness.csrfFor(await (await root.req(href)).text(), '/admin/links/move');
  const same = await root.req('https://ptra.dev/admin/links/move', {
    form: { _csrf: tok2, host: 'ptra.cc', path: 'blocker', toHost: 'ptra.cc', newpath: 'blocker' },
  });
  ok('moving to the same domain is refused', (await same.text()).includes('already on'));

  const tok3 = Harness.csrfFor(await (await root.req(href)).text(), '/admin/links/move');
  const nowhere = await root.req('https://ptra.dev/admin/links/move', {
    form: { _csrf: tok3, host: 'ptra.cc', path: 'blocker', toHost: 'evil.example', newpath: 'blocker' },
  });
  ok('moving to an unknown domain is refused', (await nowhere.text()).includes('not a domain here'));
}

console.log(`\nmulti-domain: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
