/**
 * A password in front of a link, the capability that governs it, and the
 * `+` suffix that asks where a link goes instead of going there.
 */
import { Harness } from './harness.js';
import { capabilityAllowed } from '../capabilities.js';
import {
  HASH_PREFIX,
  hasPassword,
  passwordFromHash,
  passwordMatches,
  readPassword,
  setPassword,
  shareableUrl,
} from '../linkpass.js';
import { JS } from '../assets.js';

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
    form: { _csrf: await token(), host: 'ptra.cc', status: '302', ...form },
  });
const editHref = (h, p) => `https://ptra.dev/admin/links/edit?host=${h}&path=${encodeURIComponent(p)}`;
const setPw = async (path, password) => {
  const page = await (await root.req(editHref('ptra.cc', path))).text();
  const tok = Harness.csrfFor(page, '/admin/links/password');
  return root.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: tok, host: 'ptra.cc', path, password },
  });
};

/* -------------------------------------------------------- 1. storage */
section('the password is kept so it can be read back, not in the clear');
{
  const cfg = { authSecret: root.env.AUTH_SECRET };
  const link = {};
  ok('an empty link has none', !hasPassword(link));
  await setPassword(cfg, link, 'correct horse');
  ok('it is set', hasPassword(link));
  ok('the stored form is opaque', !String(link.password).includes('correct horse'));
  ok('it reads back', (await readPassword(cfg, link)) === 'correct horse');
  ok('it matches', await passwordMatches(cfg, link, 'correct horse'));
  ok('a near miss does not', !(await passwordMatches(cfg, link, 'correct hors')));
  ok('empty does not', !(await passwordMatches(cfg, link, '')));

  const whitespace = await setPassword(cfg, {}, '    ');
  ok('whitespace alone is refused', !whitespace.ok);
  const long = await setPassword(cfg, {}, 'x'.repeat(500));
  ok('an overlong one is refused', !long.ok);

  await setPassword(cfg, link, '');
  ok('clearing works', !hasPassword(link));
}

/* --------------------------------------------------------- 2. the gate */
section('the visitor is asked');
{
  await create({ path: 'vault', target: 'example.com/vault' });
  const open = await guest.req('https://ptra.cc/vault');
  ok('an open link just resolves', (open.headers.get('Location') || '').includes('example.com/vault'));

  await setPw('vault', 'open-sesame');
  const asked = await guest.req('https://ptra.cc/vault');
  const page = await asked.text();
  ok('a protected link asks', asked.status === 200 && page.includes('This link is protected'));
  ok('the destination is nowhere on the page', !page.includes('example.com/vault'));
  ok('autofill is off', page.includes('autocomplete="off"'));
  ok('password managers are asked to stay out', page.includes('data-1p-ignore'));
  ok('the field is a password field', /type="password"/.test(page));
  ok('turnstile guards it', page.includes('data-action="unlock"'));

  const wrong = await guest.req('https://ptra.cc/vault', {
    form: {
      _csrf: Harness.csrf(page), 'slink-unlock': '1', password: 'guess',
      'cf-turnstile-response': 't:unlock:ptra.cc',
    },
  });
  const wt = await wrong.text();
  ok('a wrong answer is refused', wt.includes('not right'));
  ok('and still leaks nothing', !wt.includes('example.com/vault'));

  const right = await guest.req('https://ptra.cc/vault', {
    form: {
      _csrf: Harness.csrf(wt), 'slink-unlock': '1', password: 'open-sesame',
      'cf-turnstile-response': 't:unlock:ptra.cc',
    },
  });
  ok('the right answer unlocks', right.status === 303, String(right.status));
  const after = await guest.req('https://ptra.cc/vault');
  ok('and the link resolves', (after.headers.get('Location') || '').includes('example.com/vault'));

  const other = peer(root);
  ok('another browser is still asked',
     (await (await other.req('https://ptra.cc/vault')).text()).includes('This link is protected'));
}

/* ----------------------------------------------- 3. unlocks are scoped */
section('one unlock does not open another link');
{
  await create({ path: 'vault2', target: 'example.com/two' });
  await setPw('vault2', 'different');
  const still = await guest.req('https://ptra.cc/vault2');
  ok('a second protected link is asked for separately',
     (await still.text()).includes('This link is protected'));

  // Changing the password closes everyone who had already answered.
  await setPw('vault', 'changed-now');
  const again = await guest.req('https://ptra.cc/vault');
  ok('changing the password asks again', (await again.text()).includes('This link is protected'));
}

/* ------------------------------------------------- 4. without turnstile */
section('the prompt cannot be brute-forced freely');
{
  const h = peer(root);
  const page = await (await h.req('https://ptra.cc/vault')).text();
  const bare = await h.req('https://ptra.cc/vault', {
    form: { _csrf: Harness.csrf(page), 'slink-unlock': '1', password: 'changed-now' },
  });
  ok('an answer with no token is refused', (await bare.text()).includes('Verification failed'));

  const noCsrf = await h.req('https://ptra.cc/vault', {
    form: { _csrf: 'forged', 'slink-unlock': '1', password: 'changed-now',
            'cf-turnstile-response': 't:unlock:ptra.cc' },
  });
  ok('an answer with a forged token is refused', (await noCsrf.text()).includes('could not be verified'));
}

/* ----------------------------------------------- 5. destinations are hidden */
section('a protected link hides its destination from onlookers');
{
  const nina = peer(root);
  await nina.signIn('nina@pontera.com');
  // Nina owns one protected link of her own and should see that one.
  const ntok = Harness.csrf(await (await nina.req('https://ptra.dev/admin/links/new')).text());
  await nina.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: ntok, host: 'ptra.cc', path: 'nina-own', target: 'example.com/nina', status: '302' },
  });

  const mine = await (await nina.req('https://ptra.dev/admin/links')).text();
  ok('her own link shows its destination', mine.includes('example.com/nina'));

  const search = await (await root.req('https://ptra.dev/admin/search?q=vault')).text();
  ok('an administrator still sees it', search.includes('example.com/vault'));
}

/* -------------------------------------------------- 6. the capability */
section('the capability governs who may set one');
{
  const cfg = { rootAdmins: [] };
  const u = { id: 'u', emailNorm: 'u@x.y' };
  ok('allowed by default', capabilityAllowed(cfg, 'password', { user: u, domain: { host: 'h' } }).allowed);
  ok('a domain can withhold it',
     !capabilityAllowed(cfg, 'password', { user: u, domain: { host: 'h', capabilities: { password: false } } }).allowed);

  // Withhold it on ptra.cc and check the screen says so.
  const dom = 'https://ptra.dev/admin/domains/edit?host=ptra.cc';
  const dt = Harness.csrfFor(await (await root.req(dom)).text(), '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dt, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain',
            enabled: '1', cap_password: 'deny' },
  });

  const nina = peer(root);
  await nina.signIn('nina@pontera.com');
  const page = await (await nina.req(editHref('ptra.cc', 'nina-own'))).text();
  ok('the form is withdrawn', !page.includes('action="/admin/links/password"'));
  ok('and the screen explains', page.includes('does not allow'));

  const forged = await nina.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: 'x', host: 'ptra.cc', path: 'nina-own', password: 'sneaky' },
  });
  ok('a hand-made submission is refused',
     forged.status === 403 || (forged.headers.get('Location') || '').includes('csrf'),
     String(forged.status));

  // An administrator may still use it, and may still clear one.
  const adminPage = await (await root.req(editHref('ptra.cc', 'vault'))).text();
  ok('an administrator keeps the form', adminPage.includes('action="/admin/links/password"'));

  const dt2 = Harness.csrfFor(await (await root.req(dom)).text(), '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: dt2, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain', enabled: '1' },
  });
}

/* ------------------------------------------- 8. one user, another's link */
section('a password does not widen who may touch a link');
{
  const al = peer(root);
  await al.signIn('al@pontera.com');
  const bo = peer(root);
  await bo.signIn('bo@pontera.com');
  const mk = async (h, path, target) => {
    const t = Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());
    return h.req('https://ptra.dev/admin/links/new', {
      form: { _csrf: t, host: 'ptra.cc', path, target, status: '302' },
    });
  };
  await mk(al, 'al-link', 'example.com/al');
  await mk(bo, 'bo-link', 'example.com/bo');

  // Bo takes a token from a form on his own page, so the refusal is about
  // the link rather than about the token.
  const actOnAls = async (action, form) => {
    const own = await (await bo.req(editHref('ptra.cc', 'bo-link'))).text();
    const tok = Harness.csrfFor(own, action) || Harness.csrf(own);
    const r = await bo.req('https://ptra.dev' + action, { form: { _csrf: tok, ...form } });
    const loc = r.headers.get('Location') || '';
    return r.status === 403 || loc.includes('csrf') || loc.includes('notfound');
  };

  ok('cannot set a password on it',
     await actOnAls('/admin/links/password', { host: 'ptra.cc', path: 'al-link', password: 'x' }));
  ok('cannot move it',
     await actOnAls('/admin/links/move', { host: 'ptra.cc', path: 'al-link', toHost: 'ptra.dev', newpath: 'stolen' }));
  ok('cannot transfer it',
     await actOnAls('/admin/links/transfer', { host: 'ptra.cc', path: 'al-link', owner: 'bo@pontera.com' }));
  ok('cannot delete it',
     await actOnAls('/admin/links/delete', { host: 'ptra.cc', path: 'al-link' }));

  const hit = await peer(root).req('https://ptra.cc/al-link');
  ok('the link is untouched', (hit.headers.get('Location') || '').includes('example.com/al'),
     hit.headers.get('Location'));

  // Once it has a password, the destination and the password itself are
  // visible to its owner and to administrators, and to nobody else.
  const pt = Harness.csrfFor(await (await al.req(editHref('ptra.cc', 'al-link'))).text(),
                             '/admin/links/password');
  await al.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: pt, host: 'ptra.cc', path: 'al-link', password: 'al-secret' },
  });

  ok('another user cannot open the edit screen',
     (await bo.req(editHref('ptra.cc', 'al-link'))).status === 403);
  const boList = await (await bo.req('https://ptra.dev/admin/links')).text();
  ok('their list shows neither the destination', !boList.includes('example.com/al'));
  ok('nor the password', !boList.includes('al-secret'));
  ok('the owner sees the password',
     (await (await al.req(editHref('ptra.cc', 'al-link'))).text()).includes('al-secret'));
  ok('an administrator sees it too',
     (await (await root.req(editHref('ptra.cc', 'al-link'))).text()).includes('al-secret'));

  // A per-user ruling withdraws the feature from one person only.
  const ue = 'https://ptra.dev/admin/users/edit?u=bo%40pontera.com';
  const ut = Harness.csrfFor(await (await root.req(ue)).text(), '/admin/users/edit');
  await root.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: ut, u: 'bo@pontera.com', 'cap__*__password': 'deny' },
  });
  const boEdit = await (await bo.req(editHref('ptra.cc', 'bo-link'))).text();
  ok('a blocked person loses the form', !boEdit.includes('action="/admin/links/password"'));
  ok('and is told why', boEdit.includes('blocked you'));
  const alEdit = await (await al.req(editHref('ptra.cc', 'al-link'))).text();
  ok('everyone else is unaffected', alEdit.includes('action="/admin/links/password"'));
}

/* ------------------------------- 9. the password carried in the fragment */
section('a password can travel in the link fragment');
{
  // The parsing itself. A fragment never reaches the server, so the page
  // does this; these are the cases the page has to get right.
  const p = (h) => passwordFromHash(h);
  ok('a plain fragment', p('#ptrap=secret') === 'secret');
  ok('without the hash', p('ptrap=secret') === 'secret');
  ok('percent-encoded', p('#ptrap=p%40ss%20word') === 'p@ss word');
  ok('plus means space', p('#ptrap=a+b') === 'a b');
  ok('among other parts', p('#x=1&ptrap=mine&y=2') === 'mine');
  ok('an unrelated fragment yields nothing', p('#other=1') === '');
  ok('empty yields nothing', p('') === '' && p('#') === '' && p(null) === '');
  ok('a stray percent is taken literally', p('#ptrap=100%') === '100%');
  ok('the share form round-trips',
     p('#' + shareableUrl('h', 'x', 'p@ss word').split('#')[1]) === 'p@ss word');

  // The page has to be able to find the form, and the script has to agree
  // with the module about the prefix.
  await create({ path: 'frag', target: 'example.com/frag' });
  await setPw('frag', 'frag-secret');
  const prompt = await (await guest.req('https://ptra.cc/frag')).text();
  ok('the prompt marks the form for the script', prompt.includes('data-slink-unlock'));
  ok('the script knows the same prefix', JS.includes(HASH_PREFIX));
  ok('the script clears the fragment first', JS.includes('history.replaceState'));
  ok('the script waits for the challenge', JS.includes('cf-turnstile-response'));
  ok('the script never puts it in a URL', !JS.includes('?' + HASH_PREFIX));

  // The editor explains how to share it.
  const edit = await (await root.req(editHref('ptra.cc', 'frag'))).text();
  ok('the editor shows the shareable link', edit.includes('#ptrap=frag-secret'));
  ok('with a copy button', edit.includes('Copy link with password'));
  ok('and says the fragment stays in the browser', edit.includes('never leaves the browser'));
  ok('and warns what sharing it means', edit.includes('has the password'));

  // The tip only appears once there is a password to share.
  await create({ path: 'nofrag', target: 'example.com/nofrag' });
  const open = await (await root.req(editHref('ptra.cc', 'nofrag'))).text();
  ok('an open link gets no tip', !open.includes('Copy link with password'));

  // The server never sees the fragment, so the same request without a
  // password still gets the prompt: the fragment is not a server-side key.
  const direct = await peer(root).req('https://ptra.cc/frag');
  ok('the server still asks when it is not told',
     (await direct.text()).includes('This link is protected'));
}

/* --------------------------------- 10. a password can be set at creation */
section('a password can be set as the link is made');
{
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('the create form offers it', form.includes('name="password"'));

  const made = await create({ path: 'born-locked', target: 'example.com/bl', password: 'from-the-start' });
  ok('the link is created', (made.headers.get('Location') || '').includes('link.created'),
     made.headers.get('Location'));
  const hit = await peer(root).req('https://ptra.cc/born-locked');
  ok('and is protected straight away', (await hit.text()).includes('This link is protected'));
  const edit = await (await root.req(editHref('ptra.cc', 'born-locked'))).text();
  ok('the editor shows the password', edit.includes('from-the-start'));
  ok('and the shareable link', edit.includes('#ptrap=from-the-start'));

  const bad = await create({ path: 'born-bad', target: 'example.com/bb', password: '   ' });
  ok('a whitespace password is refused', (await bad.text()).includes('only whitespace'));
}

/* --------------------------------- 11. how it sits with everything else */
section('a password sits in front of every other behaviour');
{
  await create({
    path: 'combo', target: 'example.com/desktop', status: '302',
    frame__default: '1', url__mobileIos: 'example.com/ios', frame__mobileIos: '1',
    rules__default: 'IL https://example.com/israel', password: 'combo-pw',
  });

  const asked = await guest.req('https://ptra.cc/combo');
  ok('it is asked before the frame is served',
     (await asked.text()).includes('This link is protected'), String(asked.status));

  const tok = Harness.csrf(await (await guest.req('https://ptra.cc/combo')).text());
  await guest.req('https://ptra.cc/combo', {
    form: { _csrf: tok, 'slink-unlock': '1', password: 'combo-pw',
            'cf-turnstile-response': 't:unlock:ptra.cc' },
  });

  const framed = await guest.req('https://ptra.cc/combo', { country: 'US' });
  ok('then the frame is served', framed.status === 200 && (await framed.text()).includes('<iframe'));
  const il = await guest.req('https://ptra.cc/combo', { country: 'IL' });
  ok('a country rule still applies under it', (await il.text()).includes('example.com/israel'));
  const ios = await guest.req('https://ptra.cc/combo', {
    country: 'US', headers: { 'Sec-CH-UA-Mobile': '?1', 'Sec-CH-UA-Platform': '"iOS"' },
  });
  ok('and the device slot picks its own destination', (await ios.text()).includes('example.com/ios'));

  // A link that is not servable never reaches the prompt: it has nothing to
  // protect, and prompting would say that a disabled link exists.
  const href = editHref('ptra.cc', 'combo');
  const et = Harness.csrfFor(await (await root.req(href)).text(), '/admin/links/edit');
  await root.req('https://ptra.dev/admin/links/edit', {
    form: { _csrf: et, host: 'ptra.cc', path: 'combo', newpath: 'combo',
            target: 'example.com/desktop', status: '302' },
  });
  const off = await peer(root).req('https://ptra.cc/combo');
  ok('a disabled link goes to MISSING rather than prompting',
     (off.headers.get('Location') || '').includes('fallback.example'),
     off.headers.get('Location'));
}

/* ------------------------------------------- 12. copies carry everything */
section('a copy of a link is a copy of all of it');
{
  await create({
    path: 'orig', target: 'example.com/o', status: '301', note: 'the note',
    frame__default: '1', password: 'orig-pw', activeFrom: '2026-06-01',
    expires: '2027-06-01', url__mobileIos: 'example.com/ios',
  });

  // Moving takes everything to the other domain.
  const mt = Harness.csrfFor(await (await root.req(editHref('ptra.cc', 'orig'))).text(),
                             '/admin/links/move');
  await root.req('https://ptra.dev/admin/links/move', {
    form: { _csrf: mt, host: 'ptra.cc', path: 'orig', toHost: 'ptra.dev', newpath: 'moved-orig' },
  });
  const moved = await (await root.req(editHref('ptra.dev', 'moved-orig'))).text();
  ok('a move carries the password', moved.includes('orig-pw'));
  ok('and the share tip follows to the new domain',
     moved.includes('https://ptra.dev/moved-orig#ptrap=orig-pw'));

  // Duplicating fills the create form with everything but the shortcut.
  const dt = Harness.csrfFor(await (await root.req(editHref('ptra.dev', 'moved-orig'))).text(),
                             '/admin/links/duplicate');
  const dup = await root.req('https://ptra.dev/admin/links/duplicate', {
    form: { _csrf: dt, host: 'ptra.dev', path: 'moved-orig' },
  });
  const form = await dup.text();
  ok('duplicate opens the create form', dup.status === 200 && form.includes('Copied from'));
  ok('with the shortcut cleared', /name="path"[^>]*value=""/.test(form));
  ok('the destination carried', form.includes('example.com/o'));
  ok('the device destination carried', form.includes('example.com/ios'));
  ok('the note carried', form.includes('the note'));
  ok('the frame flag carried', /name="frame__default"[^>]*checked/.test(form));
  ok('the schedule carried', form.includes('2026-06-01') && form.includes('2027-06-01'));
  ok('and the password carried', form.includes('orig-pw'));
}

console.log(`\nlink passwords: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
