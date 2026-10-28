/**
 * Handing something to someone else — a link transfer, a directory
 * transfer, a directory grant — is governed by which email domains a host
 * accepts. A directory may narrow that list where the host delegates it,
 * and may never widen it.
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

const DOMAIN = 'https://ptra.dev/admin/domains/edit?host=ptra.cc';
const DIR = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=crew';
const LINK = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=crew%2Fdoc';

async function setDomain(extra) {
  const tok = Harness.csrfFor(await (await root.req(DOMAIN)).text(), '/admin/domains/edit');
  return root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: tok, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain',
      enabled: '1', allowedAuthDomains: 'pontera.com', ...extra,
    },
  });
}
async function transferLink(owner) {
  const page = await (await root.req(LINK)).text();
  const tok = Harness.csrfFor(page, '/admin/links/transfer');
  const r = await root.req('https://ptra.dev/admin/links/transfer', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'crew/doc', owner },
  });
  return { status: r.status, location: r.headers.get('Location') || '', text: await r.text() };
}
async function grantDir(email) {
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/grant');
  const r = await root.req('https://ptra.dev/admin/directories/grant', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'crew', email, canCreate: '1' },
  });
  return { location: r.headers.get('Location') || '', text: await r.text() };
}
async function narrowDir(list) {
  const page = await (await root.req(DIR)).text();
  const tok = Harness.csrfFor(page, '/admin/directories/edit');
  return root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'crew', enabled: '1', inviteDomains: list },
  });
}

// Everyone needs an account before they can be handed anything, so the hub
// is widened far enough for all three to sign in. What may then be given to
// whom on ptra.cc is the separate question these tests are about.
{
  const hub = 'https://ptra.dev/admin/domains/edit?host=ptra.dev';
  const tok = Harness.csrfFor(await (await root.req(hub)).text(), '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: tok, host: 'ptra.dev', defaultStatus: '302', rootCreatePolicy: 'email_domain',
      enabled: '1', authRequired: '1',
      allowedAuthDomains: 'pontera.com, partner.com, other.com',
    },
  });
}
for (const who of ['ida@pontera.com', 'oleg@partner.com', 'zed@other.com']) {
  const h = peer(root);
  await h.signIn(who);
}

const dirTok = Harness.csrfFor(
  await (await root.req('https://ptra.dev/admin/directories')).text(),
  '/admin/directories/new'
);
await root.req('https://ptra.dev/admin/directories/new', {
  form: { _csrf: dirTok, host: 'ptra.cc', path: 'crew' },
});
const linkTok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
await root.req('https://ptra.dev/admin/links/new', {
  form: { _csrf: linkTok, host: 'ptra.cc', path: 'crew/doc', target: 'example.com/doc', status: '302' },
});

/* ------------------------------------------------------ 1. the default */
section('by default only the sign-in domains may be given anything');
{
  await setDomain({ inviteMode: 'off', inviteDomains: '' });
  const inside = await transferLink('ida@pontera.com');
  ok('an internal address is accepted', inside.location.includes('link.moved'),
     inside.status + ' ' + inside.location);

  const outside = await transferLink('oleg@partner.com');
  ok('an outside address is refused', outside.text.includes('cannot be given access here'),
     outside.location);
  ok('and the refusal names what is permitted', outside.text.includes('pontera.com'));
}

/* --------------------------------------------------- 2. widening the list */
section('a host may widen the list');
{
  await setDomain({ inviteMode: 'optional', inviteDomains: 'pontera.com, partner.com' });
  const partner = await transferLink('oleg@partner.com');
  ok('a listed partner is accepted', partner.location.includes('link.moved'), partner.location);

  const stranger = await transferLink('zed@other.com');
  ok('an unlisted domain is still refused', stranger.text.includes('cannot be given access here'));

  const granted = await grantDir('oleg@partner.com');
  ok('a directory grant follows the same list', granted.location.includes('grant'), granted.location);
  const refusedGrant = await grantDir('zed@other.com');
  ok('and refuses the same addresses', refusedGrant.text.includes('cannot be given access here'));
}

/* ------------------------------------------------- 3. a directory narrows */
section('a directory may narrow the list but never widen it');
{
  const page = await (await root.req(DIR)).text();
  ok('the narrowing field is offered', page.includes('name="inviteDomains"'));

  await narrowDir('pontera.com');
  const partner = await transferLink('oleg@partner.com');
  ok('a narrowed directory refuses the partner', partner.text.includes('cannot be given access here'),
     partner.location);
  const inside = await transferLink('ida@pontera.com');
  ok('and still accepts internal addresses', inside.location.includes('link.moved'), inside.location);

  // A directory cannot name a domain the host never allowed.
  await narrowDir('other.com');
  const stranger = await transferLink('zed@other.com');
  ok('a directory cannot widen the host list', stranger.text.includes('cannot be given access here'),
     stranger.location);
  await narrowDir('');
}

/* ------------------------------------------------------- 4. a locked host */
section('a locked host ignores directory narrowing');
{
  await setDomain({ inviteMode: 'locked', inviteDomains: 'pontera.com, partner.com' });
  const page = await (await root.req(DIR)).text();
  ok('the narrowing field is withdrawn', !page.includes('name="inviteDomains"'));
  ok('and the screen says why', page.includes('Who may be given access here'));

  const partner = await transferLink('oleg@partner.com');
  ok('the host list still applies', partner.location.includes('link.moved'), partner.location);
}

/* --------------------------------------------- 5. the bulk path agrees */
section('a batch cannot route around the policy');
{
  await setDomain({ inviteMode: 'off', inviteDomains: '' });
  const page = await (await root.req('https://ptra.dev/admin/search?q=crew')).text();
  const tok = Harness.csrfFor(page, '/admin/search/batch');

  const refused = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok, op: 'transfer', email: 'oleg@partner.com', sel: 'link:ptra.cc:crew/doc' },
  });
  const text = await refused.text();
  ok('a bulk transfer honours the policy',
     text.includes('0 changed') && text.includes('cannot be given access here'), text.slice(0, 220));

  const tok2 = Harness.csrfFor(await (await root.req('https://ptra.dev/admin/search?q=crew')).text(),
                               '/admin/search/batch');
  const granted = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok2, op: 'grant', email: 'oleg@partner.com', sel: 'dir:ptra.cc:crew' },
  });
  ok('so does a bulk directory grant',
     (await granted.text()).includes('cannot be given access here'));

  const tok3 = Harness.csrfFor(await (await root.req('https://ptra.dev/admin/search?q=crew')).text(),
                               '/admin/search/batch');
  const inside = await root.req('https://ptra.dev/admin/search/batch', {
    form: { _csrf: tok3, op: 'transfer', email: 'ida@pontera.com', sel: 'link:ptra.cc:crew/doc' },
  });
  ok('and an allowed address still goes through', (await inside.text()).includes('1 changed'));
}

console.log(`\ninvite domains: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
