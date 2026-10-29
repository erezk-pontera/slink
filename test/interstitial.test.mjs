import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const h = new Harness();
await h.signIn('root@pontera.com');

async function newLink(form) {
  const token = Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());
  return h.req('https://ptra.dev/admin/links/new', { form: { _csrf: token, ...form } });
}
async function setDomainPolicy(host, policy) {
  const body = await (await h.req(`https://ptra.dev/admin/domains/edit?host=${host}`)).text();
  return h.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: Harness.csrfFor(body, '/admin/domains/edit'), host,
      allowedAuthDomains: 'pontera.com', rootCreatePolicy: 'email_domain',
      allowedCreateDomains: 'pontera.com', defaultStatus: '302', enabled: '1',
      ...(host === 'ptra.dev' ? { authRequired: '1' } : {}),
      it_countdown: 'optional', it_defaultDelay: '5', it_minDelay: '0',
      it_destination: 'optional', it_defaultShowTarget: '1',
      ...policy,
    },
  });
}

/* ------------------------------------------------- seeded defaults */
section('the countdown defaults on for ptra.dev and off for ptra.cc');
{
  await newLink({ host: 'ptra.cc', path: 'plain', target: 'example.com/a', status: '302' });
  const cc = await h.req('https://ptra.cc/plain');
  ok('ptra.cc goes straight through', cc.status === 302 && cc.headers.get('Location') === 'https://example.com/a',
     cc.status + ' ' + cc.headers.get('Location'));

  await newLink({ host: 'ptra.dev', path: 'gated', target: 'example.com/b', status: '302' });
  const dev = await h.req('https://ptra.dev/gated');
  const body = await dev.text();
  ok('ptra.dev shows a countdown', dev.status === 200 && body.includes('data-slink-redirect'),
     String(dev.status));
  ok('countdown uses the 5s default', body.includes('data-slink-delay="5"'),
     (body.match(/data-slink-delay="[^"]*"/) || [''])[0]);
  ok('destination is shown by default', body.includes('https://example.com/b'));

  // Asking for a delay is itself asking for a countdown, even where the
  // domain default is off.
  await newLink({ host: 'ptra.cc', path: 'slowcc', target: 'example.com/c', status: '302', countdown: '1', delay: '7' });
  const slow = await h.req('https://ptra.cc/slowcc');
  ok('an explicit countdown works on ptra.cc', (await slow.text()).includes('data-slink-delay="7"'),
     String(slow.status));
}

/* --------------------------------------------- offered up front */
section('the countdown is settled when the link is created');
{
  // Every countdown setting the editor offers is on the create form too,
  // rendered against the policy of the domain currently selected.
  const dev = await (await h.req('https://ptra.dev/admin/links/new')).text();
  ok('the countdown is offered', dev.includes('name="countdown"'));
  ok('so is the delay', dev.includes('name="delay"'));
  ok('and whether the destination shows', dev.includes('name="showTarget"'));
  ok('the box starts ticked where the domain default is on',
     /name="countdown"[^>]*checked/.test(dev), (dev.match(/<input[^>]*name="countdown"[^>]*>/) || [''])[0]);
  ok('the delay starts at the policy default', dev.includes('value="5"'));

  // `?host=` picks the domain the form is rendered against, so the controls
  // match the domain the link is about to be created on.
  const cc = await (await h.req('https://ptra.dev/admin/links/new?host=ptra.cc')).text();
  ok('another domain can be chosen up front', /value="ptra.cc" selected/.test(cc));
  ok('its countdown starts unticked', !/name="countdown"[^>]*checked/.test(cc));
  ok('and the delay is not asked for while it is off', !cc.includes('name="delay"'));

  // Unticking it at creation time is enough: no second save needed.
  await newLink({
    host: 'ptra.dev', path: 'straight', target: 'example.com/s', status: '302',
    countdownSet: '1', enabledSet: '1', enabled: '1',
  });
  const off = await h.req('https://ptra.dev/straight');
  ok('a link created with it off goes straight through', off.status === 302,
     String(off.status));

  // And the destination can be withheld from the countdown page at creation.
  await newLink({
    host: 'ptra.dev', path: 'quiet', target: 'example.com/q', status: '302',
    countdownSet: '1', countdown: '1', delay: '3', enabledSet: '1', enabled: '1',
  });
  const quiet = await (await h.req('https://ptra.dev/quiet')).text();
  ok('the countdown is kept', quiet.includes('data-slink-delay="3"'));
  ok('the destination is withheld as asked', !quiet.includes('https://example.com/q'));
}

/* ------------------------------------------------------- locking */
section('a locked domain policy cannot be undone by a link');
{
  await setDomainPolicy('ptra.cc', { it_countdown: 'required', it_defaultDelay: '4' });
  const forced = await h.req('https://ptra.cc/plain');
  ok('required forces a countdown onto an existing link', forced.status === 200,
     String(forced.status));
  ok('it uses the policy delay', (await forced.text()).includes('data-slink-delay="4"'));

  const edit = await (await h.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=plain')).text();
  ok('the editor shows it as settled, not as a control',
     edit.includes('Countdown is required by policy') && !edit.includes('name="countdown"'));

  // Hand-posting the locked field must not take effect.
  const tok = Harness.csrfFor(edit, '/admin/links/edit');
  await h.req('https://ptra.dev/admin/links/edit', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'plain', newpath: 'plain',
            target: 'https://example.com/a', status: '302', delay: '9',
            countdown: '', enabled: '1' },
  });
  const still = await h.req('https://ptra.cc/plain');
  ok('a forged opt-out is ignored', still.status === 200, String(still.status));

  await setDomainPolicy('ptra.cc', { it_countdown: 'off' });
  const offNow = await h.req('https://ptra.cc/slowcc');
  ok('off beats a link that asked for a countdown', offNow.status === 302,
     String(offNow.status));

  await setDomainPolicy('ptra.cc', { it_countdown: 'optional', it_defaultOn: '1', it_minDelay: '8' });
  const floored = await h.req('https://ptra.cc/slowcc');
  ok('a minimum delay raises a shorter one', (await floored.text()).includes('data-slink-delay="8"'),
     'expected the 8s floor to win over the link\'s 7s');
}

/* --------------------------------------------- hidden destination */
section('a hidden destination never reaches the page');
{
  await setDomainPolicy('ptra.cc', { it_countdown: 'required', it_defaultDelay: '3', it_destination: 'hide' });
  const page = await h.req('https://ptra.cc/plain');
  const body = await page.text();
  ok('the destination is absent from the markup', !body.includes('example.com'),
     'the target leaked into the countdown page');
  ok('it says so instead', body.includes('destination is not shown'));
  ok('the page points back at this host', body.includes('data-slink-redirect="/plain?slink-go=1"'),
     (body.match(/data-slink-redirect="[^"]*"/) || [''])[0]);
  ok('the meta refresh does too', body.includes('url=/plain?slink-go=1'));

  const go = await h.req('https://ptra.cc/plain?slink-go=1');
  ok('the continue flag performs the redirect',
     go.status === 302 && go.headers.get('Location') === 'https://example.com/a',
     go.status + ' ' + go.headers.get('Location'));

  // The flag is ours and must never be handed to the destination.
  await newLink({ host: 'ptra.dev', path: 'fwd', target: 'example.com/f', status: '302',
                  forwardQuery: '1', countdown: '' });
  const fwd = await h.req('https://ptra.dev/fwd?a=1&slink-go=1');
  ok('the continue flag is stripped from a forwarded query',
     fwd.headers.get('Location') === 'https://example.com/f?a=1',
     String(fwd.headers.get('Location')));
}

/* ------------------------------------------- directory narrowing */
section('a directory may tighten, and only tighten, without an exemption');
{
  await setDomainPolicy('ptra.cc', { it_countdown: 'optional', it_defaultOn: '', it_delegate: '1' });
  const dirToken = Harness.csrfFor(await (await h.req('https://ptra.dev/admin/directories')).text(),
                                   '/admin/directories/new');
  await h.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: dirToken, host: 'ptra.cc', path: 'safe' },
  });
  await newLink({ host: 'ptra.cc', path: 'safe/doc', target: 'example.com/d', status: '302' });
  const before = await h.req('https://ptra.cc/safe/doc');
  ok('inherits the domain default of off', before.status === 302, String(before.status));

  const dirEdit = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=safe';
  const pTok = Harness.csrfFor(await (await h.req(dirEdit)).text(), '/admin/directories/policy');
  await h.req('https://ptra.dev/admin/directories/policy', {
    form: { _csrf: pTok, host: 'ptra.cc', path: 'safe', enabled: '1',
            it_countdown: 'required', it_defaultDelay: '6', it_minDelay: '0',
            it_destination: 'optional', it_defaultShowTarget: '1' },
  });
  const after = await h.req('https://ptra.cc/safe/doc');
  ok('the directory can require a countdown', after.status === 200 && (await after.text()).includes('data-slink-delay="6"'),
     String(after.status));
  // A link with no delay of its own, outside the directory, to show the
  // directory policy really is scoped. ("plain" has an explicit 9s delay by
  // now, which is itself a request for a countdown, so it is not the test.)
  await newLink({ host: 'ptra.cc', path: 'bare', target: 'example.com/e', status: '302' });
  const outside = await h.req('https://ptra.cc/bare');
  ok('and it does not affect links outside it', outside.status === 302, String(outside.status));

  // Now lock the domain the other way and confirm the directory cannot undo it.
  await setDomainPolicy('ptra.cc', { it_countdown: 'off', it_delegate: '1' });
  const blocked = await h.req('https://ptra.cc/safe/doc');
  ok('a domain lock beats a directory policy', blocked.status === 302, String(blocked.status));
}

/* ------------------------------------------- directory exemption */
section('an exemption lets a directory break the domain policy');
{
  const dirEdit = 'https://ptra.dev/admin/directories/edit?host=ptra.cc&path=safe';
  const eTok = Harness.csrfFor(await (await h.req(dirEdit)).text(), '/admin/directories/exempt');
  await h.req('https://ptra.dev/admin/directories/exempt', {
    form: { _csrf: eTok, host: 'ptra.cc', path: 'safe', allowOverride: '1', ex_countdown: '1' },
  });
  const exempted = await h.req('https://ptra.cc/safe/doc');
  ok('the exempted directory overrides the domain lock', exempted.status === 200,
     String(exempted.status));

  // The exemption is per setting: destination stays under the domain.
  await setDomainPolicy('ptra.cc', { it_countdown: 'off', it_delegate: '1', it_destination: 'hide' });
  const stillHidden = await h.req('https://ptra.cc/safe/doc');
  ok('an unexempted setting still follows the domain',
     !(await stillHidden.text()).includes('example.com/d'));

  // Withdraw it and the directory snaps back.
  const eTok2 = Harness.csrfFor(await (await h.req(dirEdit)).text(), '/admin/directories/exempt');
  await h.req('https://ptra.dev/admin/directories/exempt', {
    form: { _csrf: eTok2, host: 'ptra.cc', path: 'safe', allowOverride: '1' },
  });
  const revoked = await h.req('https://ptra.cc/safe/doc');
  ok('withdrawing it restores the domain policy', revoked.status === 302, String(revoked.status));
}

/* ------------------------------------------------ user exemption */
section('a user exemption follows the links that person owns');
{
  await setDomainPolicy('ptra.cc', { it_countdown: 'required', it_defaultDelay: '3' });
  await newLink({ host: 'ptra.cc', path: 'mine', target: 'example.com/m', status: '302', countdown: '' });
  const under = await h.req('https://ptra.cc/mine');
  ok('the owner is under the policy to begin with', under.status === 200, String(under.status));

  const uEdit = 'https://ptra.dev/admin/users/edit?u=root%40pontera.com';
  const noEdit = await h.req(uEdit);
  ok('a root administrator is still not editable', noEdit.status === 403, String(noEdit.status));

  // Use a second person, since root administrators are unmanageable.
  const kim = new Harness();
  kim.env.KV = h.env.KV; kim.env.EMAIL = h.env.EMAIL; kim.mail = h.mail;
  await kim.signIn('kim@pontera.com');
  const kTok = Harness.csrf(await (await kim.req('https://ptra.dev/admin/links/new')).text());
  await kim.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: kTok, host: 'ptra.cc', path: 'kim', target: 'example.com/k', status: '302' },
  });
  const kimUnder = await h.req('https://ptra.cc/kim');
  ok('their link is under the policy too', kimUnder.status === 200, String(kimUnder.status));

  const kEdit = 'https://ptra.dev/admin/users/edit?u=kim%40pontera.com';
  const exTok = Harness.csrfFor(await (await h.req(kEdit)).text(), '/admin/users/edit');
  await h.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: exTok, u: 'kim@pontera.com', 'ex__ptra.cc__countdown': '1' },
  });

  // The link must now be editable by them, and the stored choice must hold.
  const kBody = await (await kim.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=kim')).text();
  ok('the exempted owner gets the control back', kBody.includes('name="countdown"'),
     'the countdown checkbox should be editable under an exemption');
  const kEditTok = Harness.csrfFor(kBody, '/admin/links/edit');
  await kim.req('https://ptra.dev/admin/links/edit', {
    form: { _csrf: kEditTok, host: 'ptra.cc', path: 'kim', newpath: 'kim',
            target: 'https://example.com/k', status: '302', delay: '0', enabled: '1',
            // What the form itself carries: the controls were on the page and
            // the box was left unticked. Without the marker the post would be
            // saying nothing about the countdown rather than turning it off.
            countdownSet: '1' },
  });
  const kimOut = await h.req('https://ptra.cc/kim');
  ok('their link now skips the countdown', kimOut.status === 302, String(kimOut.status));
  const othersStill = await h.req('https://ptra.cc/mine');
  ok('everyone else is unaffected', othersStill.status === 200, String(othersStill.status));

  // Withdrawing the exemption pulls the link straight back under the policy.
  const revTok = Harness.csrfFor(await (await h.req(kEdit)).text(), '/admin/users/edit');
  await h.req('https://ptra.dev/admin/users/edit', { form: { _csrf: revTok, u: 'kim@pontera.com' } });
  const backUnder = await h.req('https://ptra.cc/kim');
  ok('withdrawing it takes effect immediately', backUnder.status === 200, String(backUnder.status));
}

console.log(`\ninterstitial: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
