/**
 * Showing a destination in a frame instead of sending the visitor to it,
 * per destination slot, governed by the capability framework.
 */
import { Harness } from './harness.js';
import { normalizeFrame, shouldFrame } from '../targets.js';
import { frameCsp } from '../security.js';

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
const setDomainCaps = async (extra) => {
  const url = 'https://ptra.dev/admin/domains/edit?host=ptra.cc';
  const tok = Harness.csrfFor(await (await root.req(url)).text(), '/admin/domains/edit');
  return root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: tok, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain', enabled: '1', ...extra },
  });
};

/* ---------------------------------------------------------- 1. the flags */
section('framing is stored per destination slot');
{
  ok('nothing framed by default', !shouldFrame({}, 'default'));
  ok('a flag reads back', shouldFrame({ frame: { default: true } }, 'default'));
  ok('one slot does not imply another', !shouldFrame({ frame: { default: true } }, 'mobileAndroid'));
  ok('unknown slots are dropped', !('nonsense' in normalizeFrame({ nonsense: true })));
  ok('non-booleans are dropped', !('default' in normalizeFrame({ default: 'yes' })));
}

/* ------------------------------------------------------- 2. the policy */
section('the content security policy names one origin');
{
  const csp = frameCsp('https://example.com/some/page?q=1');
  ok('the frame source is that origin', csp.includes('frame-src https://example.com'));
  ok('it does not open the web', !csp.includes('frame-src *') && !csp.includes("frame-src 'self' https:"));
  ok('everything else stays shut', csp.includes("default-src 'none'"));
  ok('it cannot itself be framed', csp.includes("frame-ancestors 'none'"));
  ok('a malformed target frames nothing', frameCsp('not a url').includes("frame-src 'none'"));
}

/* -------------------------------------------------------- 3. behaviour */
section('a framed link shows the page instead of leaving');
{
  await create({ path: 'plain', target: 'example.com/plain' });
  const normal = await guest.req('https://ptra.cc/plain');
  ok('an unframed link redirects', normal.status === 302,
     normal.status + ' ' + normal.headers.get('Location'));

  await create({ path: 'inframe', target: 'example.com/inframe', frame__default: '1' });
  const framed = await guest.req('https://ptra.cc/inframe');
  ok('a framed link answers with a page', framed.status === 200, String(framed.status));
  const body = await framed.text();
  ok('and the page holds an iframe', body.includes('<iframe'));
  ok('pointing at the destination', body.includes('example.com/inframe'));
  ok('the iframe is sandboxed', body.includes('sandbox='));
  ok('with no referrer', body.includes('referrerpolicy="no-referrer"'));
  ok('the policy allows just that origin',
     (framed.headers.get('Content-Security-Policy') || '').includes('frame-src https://example.com'));
  ok('it is not cached', (framed.headers.get('Cache-Control') || '').includes('no-store'));
  ok('a warning is visible', body.includes('does not allow being framed'));
  ok('with a direct way out', body.includes('Open it directly'));
}

/* ------------------------------------------------------ 4. the capability */
section('the domain decides whether framing may be used');
{
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('the create form offers it', form.includes('name="frame__default"'));
  ok('and warns about it', form.includes('refuse to be framed'));

  // The capability is resolved against the link's owner, so the withdrawal
  // has to be tested on a link an ordinary person owns. An administrator
  // may always use it, which is the point of the rule.
  const nina = peer(root);
  await nina.signIn('nina@pontera.com');
  const ntok = Harness.csrf(await (await nina.req('https://ptra.dev/admin/links/new')).text());
  await nina.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: ntok, host: 'ptra.cc', path: 'nina-frame', target: 'example.com/nf',
            status: '302', frame__default: '1' },
  });
  const before = await guest.req('https://ptra.cc/nina-frame');
  ok('her framed link frames while it is allowed', before.status === 200, String(before.status));

  await setDomainCaps({ cap_frame: 'deny' });

  // The stored flag stays; the capability is resolved on every request.
  const after = await guest.req('https://ptra.cc/nina-frame');
  ok('withdrawing the capability stops the framing', after.status === 302,
     after.status + ' ' + after.headers.get('Location'));
  ok('the link still works', (after.headers.get('Location') || '').includes('example.com/nf'));
  const adminLink = await guest.req('https://ptra.cc/inframe');
  ok('an administrator-owned link keeps framing', adminLink.status === 200, String(adminLink.status));

  // A hand-made submission cannot grant what the domain withheld.
  const tok2 = Harness.csrf(await (await nina.req('https://ptra.dev/admin/links/new')).text());
  await nina.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok2, host: 'ptra.cc', path: 'nina-two', target: 'example.com/n2',
            status: '302', frame__default: '1' },
  });
  const hit = await guest.req('https://ptra.cc/nina-two');
  ok('a submitted flag is ignored where the capability is withheld', hit.status === 302,
     String(hit.status));

  // An administrator is still offered it.
  const adminForm = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('an administrator keeps the option', adminForm.includes('name="frame__default"'));

  await setDomainCaps({ cap_frame: '' });
  const back = await guest.req('https://ptra.cc/nina-frame');
  ok('restoring the capability restores the framing', back.status === 200, String(back.status));
}

console.log(`\nframing: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
