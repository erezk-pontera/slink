/**
 * Showing a destination in a frame instead of sending the visitor to it,
 * per destination slot, governed by the capability framework.
 */
import { Harness } from './harness.js';
import { normalizeFrame, shouldFrame } from '../targets.js';
import { frameCsp } from '../security.js';
import { GO_PARAM } from '../interstitial.js';

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

/* ------------------------------------- 5. apex, www, and both domains */
section('the same link frames on every host it exists on');
{
  // The same shortcut on both domains, exactly as described: ptra.cc/aa and
  // ptra.dev/aa, each reachable on the apex and on www.
  await create({ path: 'aa', target: 'www.google.com', frame__default: '1' });
  const dtok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
  await root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: dtok, host: 'ptra.dev', path: 'aa', target: 'www.google.com',
            status: '302', frame__default: '1' },
  });

  // ptra.dev requires a session, so the visitor there is signed in.
  const member = peer(root);
  await member.signIn('frames@pontera.com');

  for (const [who, host] of [[guest, 'ptra.cc'], [member, 'ptra.dev']]) {
    let hit = await who.req('https://' + host + '/aa');
    ok(`${host}/aa answers with a page, not a redirect`, hit.status === 200,
       hit.status + ' ' + (hit.headers.get('Location') || ''));
    let body = await hit.text();

    // ptra.dev carries a countdown by default, so the frame is one step on;
    // either way the visitor never leaves for the destination.
    if (body.includes('data-slink-redirect')) {
      const href = (body.match(/data-slink-redirect="([^"]+)"/) || [])[1];
      ok(`${host}/aa holds the countdown here rather than leaving`, href === '/aa?' + GO_PARAM + '=1', href);
      hit = await who.req('https://' + host + href);
      body = await hit.text();
    }
    ok(`${host}/aa frames the destination`, body.includes('src="https://www.google.com/'));
    ok(`${host}/aa sends no Location`, !hit.headers.get('Location'));

    // www is one 301 to the apex, and the apex then frames: the address
    // ends up as the shortcut, never as the destination.
    const www = await who.req('https://www.' + host + '/aa');
    ok(`www.${host}/aa redirects to the apex shortcut`,
       www.status === 301 && www.headers.get('Location') === 'https://' + host + '/aa',
       www.status + ' ' + www.headers.get('Location'));
  }
}

section('the continue flag is not a way round a frame');
{
  // `?slink-go=1` is how a countdown page comes back to finish. It used to
  // turn a framed link into a plain redirect, handing out the destination
  // the frame exists to keep out of the address bar.
  const r = await guest.req('https://ptra.cc/aa?' + GO_PARAM + '=1');
  ok('the flag still frames', r.status === 200, r.status + ' ' + (r.headers.get('Location') || ''));
  ok('and leaks no Location', !r.headers.get('Location'));

  // Unknown query parameters are forwarded into the frame, not around it.
  const extra = await guest.req('https://ptra.cc/aa?utm=x');
  ok('an ordinary parameter frames too', extra.status === 200, String(extra.status));

  // A countdown in front of a framed link has to come back here as well.
  const dir = await (await root.req('https://ptra.dev/admin/domains/edit?host=ptra.cc')).text();
  const tok = Harness.csrfFor(dir, '/admin/domains/edit');
  await root.req('https://ptra.dev/admin/domains/edit', {
    form: { _csrf: tok, host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain',
            enabled: '1', it_countdown: 'required', it_delay: '3', it_destination: 'show' },
  });
  const held = await guest.req('https://ptra.cc/aa');
  const page = await held.text();
  ok('the countdown appears first', held.status === 200 && page.includes('data-slink-redirect'),
     String(held.status));
  ok('and it comes back here rather than leaving',
     page.includes('data-slink-redirect="/aa?' + GO_PARAM + '=1"'),
     (page.match(/data-slink-redirect="[^"]*"/) || [])[0]);
  ok('the meta refresh agrees', page.includes('url=/aa?' + GO_PARAM + '=1'));
  const after = await guest.req('https://ptra.cc/aa?' + GO_PARAM + '=1');
  ok('and continuing lands in the frame', after.status === 200, String(after.status));

  await root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: Harness.csrfFor(
        await (await root.req('https://ptra.dev/admin/domains/edit?host=ptra.cc')).text(),
        '/admin/domains/edit'
      ),
      host: 'ptra.cc', defaultStatus: '302', rootCreatePolicy: 'email_domain', enabled: '1',
      it_countdown: 'optional', it_delay: '0', it_destination: 'show',
    },
  });
}

section('the frame page carries the ordinary headers');
{
  const r = await guest.req('https://ptra.cc/aa');
  const h = (name) => r.headers.get(name) || '';
  ok('it cannot itself be framed', h('Content-Security-Policy').includes("frame-ancestors 'none'"));
  ok('nor by an old browser', h('X-Frame-Options') === 'DENY');
  ok('transport security is set', h('Strict-Transport-Security').includes('max-age='));
  ok('the type is not sniffed', h('X-Content-Type-Options') === 'nosniff');
  ok('no referrer leaves', h('Referrer-Policy') === 'no-referrer');
  ok('it is kept out of search', h('X-Robots-Tag').includes('noindex'));
  ok('and out of caches', h('Cache-Control').includes('no-store'));
  ok('the policy still names the one origin',
     h('Content-Security-Policy').includes('frame-src https://www.google.com'));
}

section('the editor shows a password and lets it change');
{
  const tok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
  await root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'shown', target: 'example.com/s', status: '302',
            password: 'first-secret' },
  });
  const edit = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=shown';
  const page = await (await root.req(edit)).text();
  ok('the current password is shown', page.includes('value="first-secret"'));
  ok('the button offers to change it', page.includes('Update password'));
  ok('and the shareable form is offered', page.includes('#ptrap=first-secret'));

  const ptok = Harness.csrfFor(page, '/admin/links/password');
  await root.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: ptok, host: 'ptra.cc', path: 'shown', password: 'second-secret' },
  });
  const changed = await (await root.req(edit)).text();
  ok('changing it works', changed.includes('value="second-secret"'));
  ok('and the old one is gone', !changed.includes('first-secret'));

  const ctok = Harness.csrfFor(changed, '/admin/links/password');
  await root.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: ctok, host: 'ptra.cc', path: 'shown', password: '' },
  });
  const cleared = await (await root.req(edit)).text();
  ok('clearing it works', cleared.includes('Set a password') && !cleared.includes('second-secret'));
}

console.log(`\nframing: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
