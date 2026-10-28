/**
 * Rotating AUTH_SECRET.
 *
 * Almost everything derived from the secret is short-lived — a CSRF token,
 * an unlock cookie, a login code — so a rotation costs at most a retry. A
 * link password is not: it is encrypted at rest and has to stay readable,
 * and before `AUTH_SECRET_PREVIOUS` existed a rotation left every
 * protected link behind a password nobody could read, type or clear.
 */
import { Harness } from './harness.js';
import { open, seal } from '../crypt.js';

const OLD = 'test-secret-value-that-is-long-enough-123456';
const NEW = 'a-brand-new-secret-value-long-enough-7890123';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const root = new Harness();
await root.signIn('root@pontera.com');
const t = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
await root.req('https://ptra.dev/admin/links/new', {
  form: { _csrf: t, host: 'ptra.cc', path: 'rot', target: 'example.com/r', status: '302',
          password: 'keepsake' },
});

/** A worker running against the same data with a different secret. */
const after = (overrides) => {
  const h = new Harness(overrides);
  h.env.KV = root.env.KV;
  h.env.EMAIL = root.env.EMAIL;
  h.mail = root.mail;
  return h;
};

/* --------------------------------------------------------- 1. the seal */
section('a sealed value and the secret it was sealed under');
{
  const sealed = await seal(OLD, 'p', 'hello');
  ok('it opens under its own secret', (await open(OLD, 'p', sealed)) === 'hello');
  ok('and not under another', (await open(NEW, 'p', sealed)) === '');
  ok('a fallback recovers it', (await open(NEW, 'p', sealed, { also: [OLD] })) === 'hello');
  ok('an empty fallback is skipped', (await open(NEW, 'p', sealed, { also: ['', OLD] })) === 'hello');
  ok('a wrong fallback still fails', (await open(NEW, 'p', sealed, { also: ['nope'] })) === '');
  ok('the purpose is still bound in',
     (await open(OLD, 'other', sealed, { also: [OLD] })) === '');
  ok('rubbish is refused rather than thrown',
     (await open(OLD, 'p', 'not.a.sealed.value', { also: [NEW] })) === '');
}

/* ------------------------------------------- 2. rotated, nothing recorded */
section('rotated with no previous secret recorded');
{
  const admin = after({ AUTH_SECRET: NEW });
  await admin.signIn('root@pontera.com');
  const edit = await (await admin.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=rot')).text();
  ok('the editor says the password cannot be read',
     edit.includes('cannot be decrypted with the current AUTH_SECRET'));
  ok('it does not pass for having no password', !edit.includes('leave blank for no password'));
  ok('the shareable form is withheld', !edit.includes('#ptrap='));
  ok('and removing it is offered explicitly', edit.includes('name="confirmClear"'));

  const tok = Harness.csrfFor(edit, '/admin/links/password');
  const blank = await admin.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'rot', password: '' },
  });
  ok('saving the empty field is refused rather than unprotecting the link',
     (await blank.text()).includes('refused rather than silently removing'), String(blank.status));

  const visitor = after({ AUTH_SECRET: NEW });
  const still = await visitor.req('https://ptra.cc/rot');
  ok('the visitor is still asked, never let through',
     still.status === 200 && (await still.text()).includes('f_linkpw'));
}

/* ------------------------------------------ 3. rotated, previous recorded */
section('rotated with the previous secret recorded');
{
  const admin = after({ AUTH_SECRET: NEW, AUTH_SECRET_PREVIOUS: OLD });
  await admin.signIn('root@pontera.com');
  const edit = await (await admin.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=rot')).text();
  ok('the password is readable again', edit.includes('value="keepsake"'));
  ok('and nothing is flagged', !edit.includes('cannot be decrypted'));
  ok('the shareable form is back', edit.includes('#ptrap=keepsake'));

  const visitor = after({ AUTH_SECRET: NEW, AUTH_SECRET_PREVIOUS: OLD });
  const prompt = await (await visitor.req('https://ptra.cc/rot')).text();
  const opened = await visitor.req('https://ptra.cc/rot', {
    form: { _csrf: Harness.csrf(prompt), 'slink-unlock': '1', password: 'keepsake',
            'cf-turnstile-response': 't:unlock:ptra.cc' },
  });
  ok('a visitor can still open it', opened.status === 303, String(opened.status));

  // Saving migrates it, so the fallback can be dropped afterwards.
  const tok = Harness.csrfFor(edit, '/admin/links/password');
  await admin.req('https://ptra.dev/admin/links/password', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'rot', password: 'keepsake' },
  });
  const onlyNew = after({ AUTH_SECRET: NEW });
  await onlyNew.signIn('root@pontera.com');
  const again = await (await onlyNew.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=rot')).text();
  ok('saving re-seals it under the new secret alone', again.includes('value="keepsake"'));
}

/* --------------------------------------------------- 4. everything else */
section('what a rotation does not break');
{
  const before = after({});
  await before.signIn('survivor@pontera.com');
  const rotated = after({ AUTH_SECRET: NEW });
  rotated.jar = before.jar;
  const page = await rotated.req('https://ptra.dev/admin');
  ok('a live session survives, because a session id is stored, not signed',
     page.status === 200, String(page.status));

  // A CSRF token is bound to the secret, so one minted before the rotation
  // must be refused after it rather than quietly accepted. The derived key
  // used to be cached by purpose alone, which meant a long-lived isolate
  // went on honouring old-secret tokens after a rotation - the one thing a
  // rotation exists to stop.
  const stale = Harness.csrf(await (await before.req('https://ptra.dev/admin/links/new')).text());
  const used = await rotated.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: stale, host: 'ptra.cc', path: 'rot-stale', target: 'example.com/s', status: '302' },
  });
  const where = used.headers.get('Location') || '';
  ok('a token minted under the old secret is refused',
     where.includes('m=csrf'), used.status + ' ' + where);
  const made = await rotated.req('https://ptra.cc/rot-stale');
  ok('and the link it carried was not created',
     !(made.headers.get('Location') || '').includes('example.com/s'),
     made.headers.get('Location'));

  // A token minted after the rotation works, so the refusal is the secret
  // changing rather than the form breaking.
  const fresh = Harness.csrf(await (await rotated.req('https://ptra.dev/admin/links/new')).text());
  const good = await rotated.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: fresh, host: 'ptra.cc', path: 'rot-fresh', target: 'example.com/g', status: '302' },
  });
  ok('a token minted after it is accepted',
     (good.headers.get('Location') || '').includes('m=link.created'),
     good.status + ' ' + good.headers.get('Location'));
}

console.log(`\nsecret rotation: ${passed} passed, ${failed} failed`);
root.restore();
process.exit(failed ? 1 : 0);
