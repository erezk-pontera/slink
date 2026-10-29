/**
 * What a screen shows straight after a change.
 *
 * Workers KV prefix listing is eventually consistent: a key written a
 * moment ago can be absent from the next listing, and one just deleted can
 * still be in it. The in-memory store the other suites use is immediate,
 * so it cannot show the problem at all. Here the listing is deliberately
 * made to lag, and the screens are checked against it.
 */
import { Harness } from './harness.js';
import { FakeKV } from './fakekv.js';
import { makeAuthenticator } from './authenticator.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

/**
 * A store whose `list` is frozen: it reports the keys as they were when
 * `freeze()` was called, which is what a lagging listing looks like.
 * `get`, `put` and `delete` stay immediate, as they are in KV.
 */
class LaggingKV extends FakeKV {
  constructor() {
    super();
    this.frozen = null;
  }
  freeze() {
    this.frozen = new Set(this.map.keys());
  }
  thaw() {
    this.frozen = null;
  }
  async list(opts) {
    const page = await super.list(opts);
    if (!this.frozen) return page;
    return { ...page, keys: page.keys.filter((k) => this.frozen.has(k.name)) };
  }
}

const kv = new LaggingKV();
const auth = await makeAuthenticator();
const root = new Harness();
root.env.KV = kv;
await root.signIn('root@pontera.com');

const dirTok = async () =>
  Harness.csrfFor(
    await (await root.req('https://ptra.dev/admin/directories')).text(),
    '/admin/directories/new'
  );
const newTok = async () =>
  Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());

/* ------------------------------------------------------- 1. directories */
section('a directory just created is on the list');
{
  kv.freeze();
  const made = await root.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: await dirTok(), host: 'ptra.cc', path: 'fresh', note: 'brand new' },
  });
  ok('it was created', (made.headers.get('Location') || '').includes('dir.created'),
     made.status + ' ' + made.headers.get('Location'));

  // The listing is still frozen, so without the correction this is empty.
  const list = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('and the list shows it at once', list.includes('ptra.cc/fresh'),
     (list.match(/<td><a[^>]*>[^<]*</g) || []).join(' '));
  ok('with its own details, not a placeholder', list.includes('brand new'));

  // And it can be used immediately, which needs the permission lookup to
  // see it too rather than treating the path as an ordinary root-level one.
  const made2 = await root.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: await newTok(), host: 'ptra.cc', dir: 'ptra.cc/fresh', path: 'doc',
      target: 'example.com/doc', status: '302',
    },
  });
  ok('a link can be created inside it right away',
     (made2.headers.get('Location') || '').includes('path=fresh%2Fdoc'),
     made2.status + ' ' + made2.headers.get('Location'));
  ok('and the create form offers it',
     (await (await root.req('https://ptra.dev/admin/links/new?host=ptra.cc')).text())
       .includes('>ptra.cc/fresh/<'));
}

section('a directory just deleted is off it');
{
  kv.thaw();
  await root.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: await dirTok(), host: 'ptra.cc', path: 'doomed' },
  });
  const before = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('it is there to begin with', before.includes('ptra.cc/doomed'));

  kv.freeze();
  const page = await (await root.req(
    'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=doomed'
  )).text();
  const gone = await root.req('https://ptra.dev/admin/directories/delete', {
    form: { _csrf: Harness.csrfFor(page, '/admin/directories/delete'), host: 'ptra.cc', path: 'doomed' },
  });
  ok('it was deleted', (gone.headers.get('Location') || '').includes('dir.deleted'),
     gone.status + ' ' + gone.headers.get('Location'));
  const after = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('and the list drops it at once', !after.includes('ptra.cc/doomed'));
  ok('while leaving the others alone', after.includes('ptra.cc/fresh'));
  kv.thaw();
}

/* ------------------------------------------------------------ 2. links */
section('a link just created is on the list');
{
  kv.freeze();
  const made = await root.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: await newTok(), host: 'ptra.cc', dir: 'ptra.cc/', path: 'quick',
      target: 'example.com/quick', status: '302',
    },
  });
  ok('it was created', (made.headers.get('Location') || '').includes('link.created'));
  const mine = await (await root.req('https://ptra.dev/admin/links')).text();
  ok('the list shows it at once', mine.includes('ptra.cc/quick'));
  const all = await (await root.req('https://ptra.dev/admin/links?scope=all&host=ptra.cc')).text();
  ok('and so does the every-link view', all.includes('ptra.cc/quick'));
  kv.thaw();
}

section('a link just deleted is off it');
{
  const page = await (await root.req(
    'https://ptra.dev/admin/links/edit?host=ptra.cc&path=quick'
  )).text();
  kv.freeze();
  const gone = await root.req('https://ptra.dev/admin/links/delete', {
    form: { _csrf: Harness.csrfFor(page, '/admin/links/delete'), host: 'ptra.cc', path: 'quick' },
  });
  ok('it was deleted', (gone.headers.get('Location') || '').includes('link.deleted'),
     gone.status + ' ' + gone.headers.get('Location'));
  const mine = await (await root.req('https://ptra.dev/admin/links')).text();
  ok('and the list drops it at once', !mine.includes('ptra.cc/quick'));
  kv.thaw();
}

/* --------------------------------------------------------- 3. passkeys */
section('a passkey just registered is on the list');
{
  const page = await (await root.req('https://ptra.dev/admin/passkeys')).text();
  const at = page.indexOf('data-slink-passkey-add');
  const csrf = page.slice(at).match(/data-token="([^"]+)"/)[1];

  kv.freeze();
  const begin = await root.req('https://ptra.dev/admin/passkeys/register/begin', { json: { _csrf: csrf } });
  const opts = await begin.json();
  const made = auth.register({ challenge: opts.challenge, origin: 'https://ptra.dev' });
  const finish = await root.req('https://ptra.dev/admin/passkeys/register/finish', {
    json: { _csrf: csrf, token: opts.token, name: 'A laptop that lags', ...made },
  });
  ok('it registered', finish.status === 200, JSON.stringify(await finish.json()));

  const after = await (await root.req('https://ptra.dev/admin/passkeys')).text();
  ok('the list shows it at once', after.includes('A laptop that lags'),
     (after.match(/<td>[^<]*<\/td>/g) || []).slice(0, 6).join(' '));
  kv.thaw();
}

/* ----------------------------------------------------- 4. what it is not */
section('the correction only covers what this session changed');
{
  // Another signed-in person has notes of their own and none of ours, so a
  // frozen listing is all they see. The correction is a display aid for the
  // person who made the change, not a shared cache.
  const other = new Harness();
  other.env.KV = kv;
  other.env.EMAIL = root.env.EMAIL;
  other.mail = root.mail;
  await other.signIn('watcher@pontera.com');

  kv.freeze();
  await root.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: await dirTok(), host: 'ptra.cc', path: 'unseen' },
  });
  const theirs = await (await other.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('another session still sees the listing as it is', !theirs.includes('ptra.cc/unseen'));
  const ours = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('while ours is corrected', ours.includes('ptra.cc/unseen'));

  // And a note cannot conjure a record: if the key is really gone, the
  // read behind the correction returns nothing and so does the screen.
  await kv.delete('dir:ptra.cc:unseen');
  const after = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('a note for a record that no longer exists shows nothing',
     !after.includes('ptra.cc/unseen'));
  kv.thaw();
}

console.log(`\nlisting lag: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
