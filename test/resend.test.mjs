/**
 * Asking for the code again sends the same code.
 *
 * Issuing a fresh one would invalidate a code already in transit, which is
 * exactly the situation someone is in when they press the button. Keeping
 * the expiry fixed matters too: extending it on each press would let anyone
 * hold a challenge open indefinitely.
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

/** Let a resend past the minimum gap without waiting for the clock. */
function rewindGap(h) {
  for (const [k, rec] of h.env.KV.map) {
    if (!k.startsWith('otp:')) continue;
    const v = JSON.parse(rec.value);
    v.resentAt = 0;
    rec.value = JSON.stringify(v);
    h.env.KV.map.set(k, rec);
  }
}

const h = new Harness();
const start = async (email) => {
  const tok = Harness.csrf(await (await h.req('https://ptra.dev/admin')).text());
  return h.req('https://ptra.dev/admin', {
    form: {
      _csrf: tok, stage: 'email', email, next: '/admin',
      'cf-turnstile-response': 't:login:ptra.dev',
    },
  });
};
const resend = async (extra = {}) => {
  const page = await (await h.req('https://ptra.dev/admin')).text();
  const tok = Harness.csrfFor(page, '/admin');
  const r = await h.req('https://ptra.dev/admin', {
    form: { _csrf: tok, stage: 'resend', 'cf-turnstile-response': 't:resend:ptra.dev', ...extra },
  });
  return { status: r.status, text: await r.text() };
};

await start('resend@pontera.com');
const first = h.lastCode();

/* ------------------------------------------------------- 1. the page */
section('the resend is a challenge of its own');
{
  ok('a code was sent to begin with', !!first, String(first));
  const page = await (await h.req('https://ptra.dev/admin')).text();
  ok('the resend form carries its own widget', page.includes('data-action="resend"'));
  ok('the verify form keeps its own', page.includes('data-action="otp"'));
  ok('the wording does not promise a new code', !page.includes('request a new code'));

  const before = h.mail.length;
  const bare = await resend({ 'cf-turnstile-response': '' });
  ok('a resend without a token is refused', bare.text.includes('Verification failed'),
     bare.text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('and sends nothing', h.mail.length === before);

  const bad = await resend({ 'cf-turnstile-response': 'BAD' });
  ok('a rejected token is refused', bad.text.includes('Verification failed'));
  ok('still sends nothing', h.mail.length === before);
}

/* --------------------------------------------------- 2. the same code */
section('the same code comes back');
{
  const again = await resend();
  ok('the resend succeeds', again.text.includes('same code again'),
     again.text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('the code is unchanged', h.lastCode() === first, `${first} then ${h.lastCode()}`);
  ok('it says so plainly', again.text.includes('still the one to use'));

  // Pressing again immediately is held off, and still changes nothing.
  const tooSoon = await resend();
  ok('a second press inside the gap waits', tooSoon.text.includes('wait a moment'),
     tooSoon.text.match(/alert[^>]*>([^<]*)/)?.[1]);
  ok('the code is still unchanged', h.lastCode() === first);

  rewindGap(h);
  await resend();
  ok('and past the gap it is still the same code', h.lastCode() === first);
}

/* ------------------------------------------------- 3. validity is fixed */
section('a resend does not extend the challenge');
{
  const key = [...h.env.KV.map.keys()].find((k) => k.startsWith('otp:'));
  const before = JSON.parse(h.env.KV.map.get(key).value);
  rewindGap(h);
  await resend();
  const after = JSON.parse(h.env.KV.map.get(key).value);
  ok('the expiry is untouched', after.expiresAt === before.expiresAt,
     `${before.expiresAt} -> ${after.expiresAt}`);
  ok('attempts already spent are kept', after.attempts === before.attempts);
  ok('the resend is counted', after.resendCount > before.resendCount);
  ok('the stored code is never in the clear',
     !JSON.stringify(after).includes(String(first)));
}

/* ------------------------------------------------ 4. the code still works */
section('the original code still verifies');
{
  const page = await (await h.req('https://ptra.dev/admin')).text();
  const tok = Harness.csrfFor(page, '/admin');
  const done = await h.req('https://ptra.dev/admin', {
    form: { _csrf: tok, stage: 'code', code: first, 'cf-turnstile-response': 't:otp:ptra.dev' },
  });
  ok('signing in with the first code works', done.status === 303,
     done.status + ' ' + done.headers.get('Location'));
}

/* ---------------------------------------------------- 5. the resend cap */
section('a challenge cannot be resent forever');
{
  const g = new Harness();
  g.env.KV = h.env.KV;
  g.env.EMAIL = h.env.EMAIL;
  g.mail = h.mail;
  const tok = Harness.csrf(await (await g.req('https://ptra.dev/admin')).text());
  await g.req('https://ptra.dev/admin', {
    form: {
      _csrf: tok, stage: 'email', email: 'capped@pontera.com', next: '/admin',
      'cf-turnstile-response': 't:login:ptra.dev',
    },
  });

  let last = '';
  for (let i = 0; i < 7; i++) {
    rewindGap(g);
    const page = await (await g.req('https://ptra.dev/admin')).text();
    const t = Harness.csrfFor(page, '/admin');
    const r = await g.req('https://ptra.dev/admin', {
      form: { _csrf: t, stage: 'resend', 'cf-turnstile-response': 't:resend:ptra.dev' },
    });
    last = await r.text();
  }
  ok('the cap is reached', last.includes('sent several times already'),
     last.match(/alert[^>]*>([^<]*)/)?.[1]);
  g.restore();
}

console.log(`\nresend: ${passed} passed, ${failed} failed`);
h.restore();
export default { passed, failed };
