/**
 * Passkeys, driven end to end through the real endpoints against a
 * simulated authenticator that produces genuine signatures.
 *
 * Two halves. The first is that the ordinary flow works: enrol a key, sign
 * out, sign back in with it. The second, and the longer one, is everything
 * that must not work - a replayed challenge, a key enrolled on somebody
 * else's account, a disabled account, a host that does not offer them, and
 * every endpoint without its CSRF token or from a foreign origin.
 */
import { Harness } from './harness.js';
import { b64u, makeAuthenticator } from './authenticator.js';
import { decode } from '../cbor.js';
import { coseToKey, derToRaw, fromB64Url, parseAuthData, verifyAssertion, verifyRegistration } from '../webauthn.js';
import { MAX_PASSKEYS, passkeysEnabled } from '../passkeys.js';

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

const HUB = 'https://ptra.dev';
const ORIGIN = HUB;

/** The token a page carries for the passkey controls. */
function dataToken(body, marker) {
  const at = body.indexOf(marker);
  if (at < 0) return null;
  const m = body.slice(at).match(/data-token="([^"]+)"/);
  return m ? m[1] : null;
}

/** Enrol a key on whoever `agent` is signed in as. Returns the response. */
async function enrol(agent, auth, { name = 'Test key' } = {}) {
  const page = await (await agent.req(HUB + '/admin/passkeys')).text();
  const csrf = dataToken(page, 'data-slink-passkey-add');
  const begin = await agent.req(HUB + '/admin/passkeys/register/begin', { json: { _csrf: csrf } });
  const opts = await begin.json();
  if (!opts.challenge) return { begin, opts };
  const made = auth.register({ challenge: opts.challenge, origin: ORIGIN });
  const finish = await agent.req(HUB + '/admin/passkeys/register/finish', {
    json: { _csrf: csrf, token: opts.token, name, ...made },
  });
  return { begin, opts, finish, csrf, body: await finish.json() };
}

/** Sign in with a key on a fresh browser. Returns the finishing response. */
async function signInWith(agent, auth, { next, mutate, from = '/admin' } = {}) {
  const page = await (await agent.req(HUB + from)).text();
  const csrf = dataToken(page, 'data-slink-passkey-login');
  const begin = await agent.req(HUB + '/__slink/passkey/login/begin', { json: { _csrf: csrf } });
  const opts = await begin.json();
  if (!opts.challenge) return { begin, opts };
  const assertion = await auth.assert({ challenge: opts.challenge, origin: ORIGIN });
  const payload = { _csrf: csrf, token: opts.token, next, ...assertion };
  if (mutate) await mutate(payload, opts);
  const finish = await agent.req(HUB + '/__slink/passkey/login/finish', { json: payload });
  return { begin, opts, finish, csrf, body: await finish.json().catch(() => ({})) };
}

const root = new Harness();
await root.signIn('root@pontera.com');

/* ------------------------------------------------- 1. the library itself */
section('the verification layer');
{
  for (const alg of [-7, -257]) {
    const label = alg === -7 ? 'ES256' : 'RS256';
    const auth = await makeAuthenticator({ alg });
    const challenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const made = auth.register({ challenge, origin: ORIGIN });
    const cred = await verifyRegistration({
      attestationObject: fromB64Url(made.attestationObject),
      clientDataJSON: fromB64Url(made.clientDataJSON),
      challenge,
      origin: ORIGIN,
      rpId: 'ptra.dev',
    });
    ok(`${label}: registration verifies`, cred.credentialId === auth.id);
    ok(`${label}: the algorithm is recorded`, cred.alg === alg, String(cred.alg));

    const c2 = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const a = await auth.assert({ challenge: c2, origin: ORIGIN });
    const args = {
      credential: cred,
      authenticatorData: fromB64Url(a.authenticatorData),
      clientDataJSON: fromB64Url(a.clientDataJSON),
      signature: fromB64Url(a.signature),
      challenge: c2,
      origin: ORIGIN,
      rpId: 'ptra.dev',
    };
    const res = await verifyAssertion(args);
    ok(`${label}: a genuine assertion verifies`, res.ok);
    ok(`${label}: the counter advances`, res.signCount > cred.signCount);

    const refuses = async (label2, mutate) => {
      const c = b64u(crypto.getRandomValues(new Uint8Array(32)));
      const base = await auth.assert({ challenge: c, origin: ORIGIN });
      const probe = {
        credential: cred,
        authenticatorData: fromB64Url(base.authenticatorData),
        clientDataJSON: fromB64Url(base.clientDataJSON),
        signature: fromB64Url(base.signature),
        challenge: c,
        origin: ORIGIN,
        rpId: 'ptra.dev',
      };
      await mutate(probe);
      let threw = false;
      try {
        await verifyAssertion(probe);
      } catch {
        threw = true;
      }
      ok(`${label}: ${label2}`, threw);
    };
    await refuses('a replayed challenge is refused', (p) => {
      p.challenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
    });
    await refuses('a foreign origin is refused', (p) => { p.origin = 'https://evil.example'; });
    await refuses("another site's rpId is refused", (p) => { p.rpId = 'evil.example'; });
    await refuses('a tampered signature is refused', (p) => {
      p.signature = new Uint8Array(p.signature);
      p.signature[p.signature.length - 1] ^= 1;
    });
    await refuses('tampered authenticator data is refused', (p) => {
      p.authenticatorData = new Uint8Array(p.authenticatorData);
      p.authenticatorData[33] ^= 0x02;
    });
    await refuses('no user-present flag is refused', (p) => {
      p.authenticatorData = new Uint8Array(p.authenticatorData);
      p.authenticatorData[32] &= ~0x01;
    });
    await refuses('a create assertion is not a get', async (p) => {
      const wrong = await auth.assert({ challenge: p.challenge, origin: ORIGIN, type: 'webauthn.create' });
      p.authenticatorData = fromB64Url(wrong.authenticatorData);
      p.clientDataJSON = fromB64Url(wrong.clientDataJSON);
      p.signature = fromB64Url(wrong.signature);
    });

    // A genuinely different key of the same kind, not a tweaked copy.
    const other = await makeAuthenticator({ alg });
    const oc = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const otherMade = other.register({ challenge: oc, origin: ORIGIN });
    const otherCred = await verifyRegistration({
      attestationObject: fromB64Url(otherMade.attestationObject),
      clientDataJSON: fromB64Url(otherMade.clientDataJSON),
      challenge: oc,
      origin: ORIGIN,
      rpId: 'ptra.dev',
    });
    await refuses('another key cannot sign for this one', (p) => { p.credential = otherCred; });

    // Presence only, with and without verification demanded.
    const c3 = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const presence = await auth.assert({ challenge: c3, origin: ORIGIN, flags: 0x01 });
    const presenceArgs = {
      credential: cred,
      authenticatorData: fromB64Url(presence.authenticatorData),
      clientDataJSON: fromB64Url(presence.clientDataJSON),
      signature: fromB64Url(presence.signature),
      challenge: c3,
      origin: ORIGIN,
      rpId: 'ptra.dev',
    };
    let refusedUv = false;
    try {
      await verifyAssertion({ ...presenceArgs, requireUserVerification: true });
    } catch {
      refusedUv = true;
    }
    ok(`${label}: presence alone is refused where verification is demanded`, refusedUv);
    ok(`${label}: presence alone is accepted where it is not`, (await verifyAssertion(presenceArgs)).ok);
  }

  // A counter that goes backwards is reported, not fatal.
  const auth = await makeAuthenticator({ alg: -7 });
  const c = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const made = auth.register({ challenge: c, origin: ORIGIN });
  const cred = await verifyRegistration({
    attestationObject: fromB64Url(made.attestationObject),
    clientDataJSON: fromB64Url(made.clientDataJSON),
    challenge: c,
    origin: ORIGIN,
    rpId: 'ptra.dev',
  });
  const c2 = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const stale = await auth.assert({ challenge: c2, origin: ORIGIN, count: 1 });
  const res = await verifyAssertion({
    credential: { ...cred, signCount: 9 },
    authenticatorData: fromB64Url(stale.authenticatorData),
    clientDataJSON: fromB64Url(stale.clientDataJSON),
    signature: fromB64Url(stale.signature),
    challenge: c2,
    origin: ORIGIN,
    rpId: 'ptra.dev',
  });
  ok('a stale counter still verifies', res.ok);
  ok('but it is flagged as a possible clone', res.cloneWarning === true);
}

/* --------------------------------------------------- 2. the parsers */
section('what the parsers refuse');
{
  const refuses = (name, fn) => {
    let threw = false;
    try {
      fn();
    } catch {
      threw = true;
    }
    ok(name, threw);
  };
  refuses('authenticator data shorter than its header', () => parseAuthData(new Uint8Array(20)));
  refuses('a truncated credential id', () => {
    const b = new Uint8Array(60);
    b[32] = 0x41;
    b[53] = 0x03;
    b[54] = 0xff;
    parseAuthData(b);
  });
  refuses('a COSE key that is not a map', () => coseToKey(new Uint8Array([0x01])));
  refuses('a DER signature that is not a sequence', () => derToRaw(new Uint8Array(10)));
  refuses('a field that is not base64url', () => fromB64Url('not base64!'));
  refuses('a field that is far too large', () => fromB64Url('A'.repeat(70000)));
  refuses('indefinite-length CBOR', () => decode(new Uint8Array([0x5f, 0xff])));
  refuses('a CBOR float', () => decode(new Uint8Array([0xfb, 0, 0, 0, 0, 0, 0, 0, 0])));
  ok('trailing bytes after the CBOR item are refused', (() => {
    try {
      decode(new Uint8Array([0x01, 0x02]));
      return false;
    } catch {
      return true;
    }
  })());
}

/* ------------------------------------------------- 3. the ordinary flow */
section('enrolling and using a passkey');
let mainAuth;
{
  const page = await (await root.req(HUB + '/admin/passkeys')).text();
  ok('the page offers to add one', page.includes('data-slink-passkey-add'));
  ok('and says none are held yet', page.includes('not added a passkey yet'));
  ok('the add control starts hidden', /data-slink-passkey-go hidden/.test(page));

  mainAuth = await makeAuthenticator();
  const r = await enrol(root, mainAuth, { name: 'Work laptop' });
  ok('registration succeeds', r.finish.status === 200 && r.body.ok === true, JSON.stringify(r.body));

  const listed = await (await root.req(HUB + '/admin/passkeys')).text();
  ok('the key is listed by name', listed.includes('value="Work laptop"'));
  ok('with the algorithm shown', listed.includes('EC P-256'));
  ok('and a way to remove it', listed.includes('name="action" value="delete"'));

  const log = await (await root.req(HUB + '/admin/audit')).text();
  ok('adding one is recorded', log.includes('passkey.added'));
}

section('signing in with it');
{
  const browser = peer(root);
  const login = await (await browser.req(HUB + '/admin')).text();
  ok('the sign-in page offers a passkey', login.includes('data-slink-passkey-login'));
  // Hidden until the script says this browser can use one, divider and all,
  // so no-JavaScript sees no stray rule above a control that never appears.
  ok('the whole block starts hidden', /data-slink-passkey-login[^>]*hidden/.test(login));
  ok('and the divider is inside it',
     login.indexOf('class="divider"') > login.indexOf('data-slink-passkey-login') &&
     login.indexOf('class="divider"') < login.indexOf('</div>', login.indexOf('data-slink-passkey-msg')));
  ok('the emailed code is still offered', login.includes('name="email"'));

  const r = await signInWith(browser, mainAuth, { next: '/admin/links' });
  ok('the assertion is accepted', r.finish.status === 200 && r.body.ok === true, JSON.stringify(r.body));
  ok('it says where to go next', r.body.next === '/admin/links');
  ok('a session cookie is set', (r.finish.headers.get('Set-Cookie') || '').includes('__Host-slink_sess='));

  const after = await browser.req(HUB + '/admin');
  ok('the session works', after.status === 200);
  ok('and belongs to the right account', (await after.text()).includes('root@pontera.com'));

  const log = await (await root.req(HUB + '/admin/audit')).text();
  ok('the sign-in is recorded as a passkey', log.includes('passkey'));
}

section('what a sign-in refuses');
{
  // A challenge is single use: the same assertion replayed does not work.
  const browser = peer(root);
  const first = await signInWith(browser, mainAuth);
  ok('a fresh sign-in works', first.body.ok === true);

  const replay = peer(root);
  const page = await (await replay.req(HUB + '/admin')).text();
  const csrf = dataToken(page, 'data-slink-passkey-login');
  const begin = await replay.req(HUB + '/__slink/passkey/login/begin', { json: { _csrf: csrf } });
  const opts = await begin.json();
  const assertion = await mainAuth.assert({ challenge: opts.challenge, origin: ORIGIN });
  const once = await replay.req(HUB + '/__slink/passkey/login/finish', {
    json: { _csrf: csrf, token: opts.token, ...assertion },
  });
  ok('the first use of a challenge works', once.status === 200);

  const twice = peer(root);
  await twice.req(HUB + '/admin');
  const again = await twice.req(HUB + '/__slink/passkey/login/finish', {
    json: { _csrf: csrf, token: opts.token, ...assertion },
  });
  // The token is bound to the browser that asked for it, so another
  // browser cannot use it even with the whole assertion in hand.
  ok('the same challenge in another browser is refused', again.status !== 200, String(again.status));

  const unknown = peer(root);
  const r = await signInWith(unknown, mainAuth, {
    mutate: (p) => { p.id = b64u(crypto.getRandomValues(new Uint8Array(32))); },
  });
  ok('an unknown credential is refused', r.finish.status === 400);
  ok('and says nothing about why', r.body.error === 'That passkey could not be used to sign in here.');

  const forged = peer(root);
  const r2 = await signInWith(forged, mainAuth, {
    mutate: (p) => { p.signature = b64u(crypto.getRandomValues(new Uint8Array(70))); },
  });
  ok('a forged signature is refused', r2.finish.status === 400);
  ok('with exactly the same message', r2.body.error === 'That passkey could not be used to sign in here.');

  const stale = peer(root);
  const r3 = await signInWith(stale, mainAuth, {
    mutate: (p) => { p.token = 'not.a.token'; },
  });
  ok('a forged challenge token is refused', r3.finish.status === 400);
}

/* --------------------------------------------- 4. one key, one account */
section('a credential belongs to one account');
{
  const other = peer(root);
  await other.signIn('second@pontera.com');
  const r = await enrol(other, mainAuth, { name: 'Stolen' });
  ok('re-enrolling somebody else’s key is refused', r.finish.status === 409, String(r.finish.status));
  ok('and does not say whose it is', r.body.error === 'That passkey is already registered.');

  const mine = await enrol(root, mainAuth, { name: 'Again' });
  ok('re-enrolling your own is refused too', mine.finish.status === 409);
  ok('and does say it is yours', mine.body.error === 'That passkey is already on this account.');

  // A challenge minted for one account cannot be spent by another.
  const page = await (await root.req(HUB + '/admin/passkeys')).text();
  const rootCsrf = dataToken(page, 'data-slink-passkey-add');
  const begin = await root.req(HUB + '/admin/passkeys/register/begin', { json: { _csrf: rootCsrf } });
  const opts = await begin.json();

  const otherPage = await (await other.req(HUB + '/admin/passkeys')).text();
  const otherCsrf = dataToken(otherPage, 'data-slink-passkey-add');
  const fresh = await makeAuthenticator();
  const made = fresh.register({ challenge: opts.challenge, origin: ORIGIN });
  const stolen = await other.req(HUB + '/admin/passkeys/register/finish', {
    json: { _csrf: otherCsrf, token: opts.token, name: 'Carried over', ...made },
  });
  ok('a challenge cannot be carried to another account', stolen.status === 400, String(stolen.status));
}

/* ----------------------------------------------------- 5. the account */
section('a passkey is personal');
{
  const other = peer(root);
  await other.signIn('third@pontera.com');
  const theirs = await makeAuthenticator();
  await enrol(other, theirs, { name: 'Their phone' });

  const theirPage = await (await other.req(HUB + '/admin/passkeys')).text();
  const id = (theirPage.match(/name="id" value="([^"]+)"/) || [])[1];
  ok('their key has an id on their page', !!id);

  // An administrator is not an exception: the keys are not an admin surface.
  const rootPage = await (await root.req(HUB + '/admin/passkeys')).text();
  ok('an administrator does not see it', !rootPage.includes('Their phone'));

  const token = Harness.csrfFor(rootPage, '/admin/passkeys');
  const attempt = await root.req(HUB + '/admin/passkeys', {
    form: { _csrf: token, id, action: 'delete' },
  });
  ok('and cannot delete it', (attempt.headers.get('Location') || '').includes('m=notfound'));
  const still = await (await other.req(HUB + '/admin/passkeys')).text();
  ok('it is still there', still.includes('Their phone'));

  // Renaming and removing your own works.
  const ownToken = Harness.csrfFor(still, '/admin/passkeys');
  await other.req(HUB + '/admin/passkeys', {
    form: { _csrf: ownToken, id, action: 'rename', name: 'Their new phone' },
  });
  const renamed = await (await other.req(HUB + '/admin/passkeys')).text();
  ok('renaming works', renamed.includes('Their new phone'));

  const delToken = Harness.csrfFor(renamed, '/admin/passkeys');
  await other.req(HUB + '/admin/passkeys', { form: { _csrf: delToken, id, action: 'delete' } });
  const gone = await (await other.req(HUB + '/admin/passkeys')).text();
  ok('removing works', !gone.includes('Their new phone'));

  const dead = peer(root);
  const r = await signInWith(dead, theirs);
  ok('and the removed key no longer signs in', r.finish.status === 400);
}

/* ------------------------------------------------- 6. account state */
section('the account still decides');
{
  const person = peer(root);
  await person.signIn('fourth@pontera.com');
  const auth = await makeAuthenticator();
  await enrol(person, auth, { name: 'Fourth key' });

  // Disable the account and the key stops working.
  const edit = HUB + '/admin/users/edit?u=' + encodeURIComponent('fourth@pontera.com');
  const tok = Harness.csrfFor(await (await root.req(edit)).text(), '/admin/users/edit');
  await root.req(HUB + '/admin/users/edit', {
    form: { _csrf: tok, u: 'fourth@pontera.com', disabled: '1' },
  });

  const blocked = peer(root);
  const r = await signInWith(blocked, auth);
  ok('a disabled account cannot sign in with one', r.finish.status === 400, String(r.finish.status));
  ok('and is told no more than anyone else', r.body.error === 'That passkey could not be used to sign in here.');

  const tok2 = Harness.csrfFor(await (await root.req(edit)).text(), '/admin/users/edit');
  await root.req(HUB + '/admin/users/edit', { form: { _csrf: tok2, u: 'fourth@pontera.com' } });
  const back = peer(root);
  ok('re-enabling restores it', (await signInWith(back, auth)).body.ok === true);

  // Deleting the account takes the credential with it.
  const delTok = Harness.csrfFor(await (await root.req(edit)).text(), '/admin/users/delete');
  const removed = await root.req(HUB + '/admin/users/delete', {
    form: { _csrf: delTok, u: 'fourth@pontera.com' },
  });
  ok('the account is deleted', (removed.headers.get('Location') || '').includes('m=user.deleted'),
     removed.status + ' ' + removed.headers.get('Location'));
  const orphan = peer(root);
  const after = await signInWith(orphan, auth);
  ok('a deleted account leaves no usable key', after.finish.status === 400, String(after.finish.status));

  // And the credential is really gone, not merely unreachable: the same
  // address signing up again must not inherit the old device.
  const reborn = peer(root);
  await reborn.signIn('fourth@pontera.com');
  const inherited = peer(root);
  const tried = await signInWith(inherited, auth);
  ok('nor does the address used again inherit it', tried.finish.status === 400, String(tried.finish.status));
}

/* ------------------------------------------------------ 7. the policy */
section('a host may switch them off');
{
  // The provider is a system setting; the per-host switch is not.
  const cfg = {
    hubHost: 'ptra.dev',
    oauthSecret: 'secret',
    settings: {
      oauth: {
        enabled: true,
        clientId: 'c',
        authorizeUrl: 'https://idp.example/a',
        tokenUrl: 'https://idp.example/t',
        userinfoUrl: 'https://idp.example/u',
      },
    },
  };
  const noProvider = { hubHost: 'ptra.dev', oauthSecret: 'secret', settings: {} };
  ok('on by default', passkeysEnabled(cfg, {}) === true);
  ok('a host may turn them off', passkeysEnabled(cfg, { disabledMethods: ['passkey'] }) === false);
  ok('an administrator keeps them',
     passkeysEnabled(cfg, { disabledMethods: ['passkey'] }, { isAdmin: true }) === true);
  ok('turning them off needs a working provider',
     passkeysEnabled(noProvider, { disabledMethods: ['passkey'] }) === true);

  // And through the real screens: the provider in settings, the switch on
  // the domain.
  const setProvider = async (extra) => {
    const page = await (await root.req(HUB + '/admin/settings')).text();
    const form = { _csrf: Harness.csrfFor(page, '/admin/settings') };
    for (const m of page.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>/g)) {
      if (m[1] === '_csrf') continue;
      if (/type="checkbox"/.test(m[0]) && !/\schecked/.test(m[0])) continue;
      form[m[1]] = m[2];
    }
    for (const m of page.matchAll(/<select[^>]*name="([^"]+)"[\s\S]*?<\/select>/g)) {
      const sel = m[0].match(/<option value="([^"]*)"[^>]*selected/);
      if (sel) form[m[1]] = sel[1];
    }
    return root.req(HUB + '/admin/settings', { form: { ...form, ...extra } });
  };
  const setDomain = async (extra) => {
    const url = HUB + '/admin/domains/edit?host=ptra.dev';
    const tok = Harness.csrfFor(await (await root.req(url)).text(), '/admin/domains/edit');
    return root.req(HUB + '/admin/domains/edit', {
      form: {
        _csrf: tok, host: 'ptra.dev', defaultStatus: '302', rootCreatePolicy: 'email_domain',
        enabled: '1', authRequired: '1', allowedAuthDomains: 'pontera.com', ...extra,
      },
    });
  };
  await setProvider({
    oauthEnabled: '1', oauthLabel: 'Example SSO', oauthClientId: 'client-123',
    oauthAuthorizeUrl: 'https://idp.example/authorize',
    oauthTokenUrl: 'https://idp.example/token',
    oauthUserinfoUrl: 'https://idp.example/me',
  });
  await setDomain({ disable_passkey: '1' });

  const guest = peer(root);
  const page = await (await guest.req(HUB + '/admin')).text();
  ok('the button is gone from the page', !page.includes('data-slink-passkey-login'));
  ok('but an administrator can still reach it',
     (await (await peer(root).req(HUB + '/admin?otp=1')).text()).includes('data-slink-passkey-login'));

  // An ordinary person's key is refused at the finish, where there is an
  // account to apply the policy to. The challenge itself is still handed
  // out, because it says nothing about anyone and the request carries no
  // identity yet.
  const person = peer(root);
  await person.signIn('policy@pontera.com');
  const theirs = await makeAuthenticator();
  await enrol(person, theirs, { name: 'Ordinary' });
  const refused = peer(root);
  const r = await signInWith(refused, theirs, { from: '/admin?otp=1' });
  ok('an ordinary account cannot use one while they are off', r.finish.status === 400,
     String(r.finish.status));

  // An administrator can, which is the whole point of the exemption.
  const adminAuth = await makeAuthenticator();
  await enrol(root, adminAuth, { name: 'Admin key' });
  const adminBrowser = peer(root);
  const allowed = await signInWith(adminBrowser, adminAuth, { from: '/admin?otp=1' });
  ok('an administrator still can', allowed.body.ok === true, JSON.stringify(allowed.body));

  await setDomain({});
  const back = await (await peer(root).req(HUB + '/admin')).text();
  ok('turning it back on restores the button', back.includes('data-slink-passkey-login'));
  await setProvider({ oauthEnabled: '' });
}

section('signing in cannot be aimed somewhere else');
{
  const auth = await makeAuthenticator();
  const person = peer(root);
  await person.signIn('aimed@pontera.com');
  await enrol(person, auth, { name: 'Aimed' });

  for (const [next, want] of [
    ['https://evil.example/', '/admin'],
    ['//evil.example/', '/admin'],
    ['/admin\r\nX: 1', '/admin'],
    ['/admin/links', '/admin/links'],
    ['not-a-path', '/admin'],
  ]) {
    const browser = peer(root);
    const r = await signInWith(browser, auth, { next });
    ok(`next ${JSON.stringify(next)} lands on ${want}`, r.body.next === want, String(r.body.next));
  }
}

/* ---------------------------------------------------- 8. the endpoints */
section('every endpoint is guarded');
{
  const ENDPOINTS = [
    ['/admin/passkeys/register/begin', true],
    ['/admin/passkeys/register/finish', true],
    ['/__slink/passkey/login/begin', false],
    ['/__slink/passkey/login/finish', false],
  ];
  for (const [path, needsSession] of ENDPOINTS) {
    const agent = needsSession ? root : peer(root);
    if (!needsSession) await agent.req(HUB + '/admin');

    const forged = await agent.req(HUB + path, { json: { _csrf: 'forged' } });
    ok(`${path} refuses a forged token`, forged.status === 403, String(forged.status));

    const foreign = await agent.req(HUB + path, {
      json: { _csrf: 'forged' },
      headers: { Origin: 'https://evil.example' },
    });
    ok(`${path} refuses a foreign origin`, foreign.status === 403, String(foreign.status));

    const get = await agent.req(HUB + path);
    ok(`${path} is not a GET`, get.status === 404 || get.status === 405, String(get.status));

    const form = await agent.req(HUB + path, { form: { _csrf: 'forged' } });
    ok(`${path} refuses a form body`, form.status >= 400, String(form.status));
  }

  // A body that is not an object, and one that is far too big.
  const huge = await root.req(HUB + '/admin/passkeys/register/begin', {
    json: { _csrf: 'x', pad: 'A'.repeat(40000) },
  });
  ok('an oversized body is refused', huge.status === 400, String(huge.status));

  // Signed out, the register endpoints are not reachable at all.
  const guest = peer(root);
  const out = await guest.req(HUB + '/admin/passkeys/register/begin', { json: { _csrf: 'x' } });
  ok('registration needs a session', out.status === 303 || out.status === 403, String(out.status));

  // Signed in, the login endpoints refuse.
  const already = await root.req(HUB + '/__slink/passkey/login/begin', { json: { _csrf: 'x' } });
  ok('signing in again is refused while signed in', already.status === 400, String(already.status));
}

section('they live on the hub alone');
{
  const guest = peer(root);
  for (const path of ['/__slink/passkey/login/begin', '/__slink/passkey/login/finish']) {
    const r = await guest.req('https://ptra.cc' + path, { json: { _csrf: 'x' } });
    ok(`${path} is not served on a short-link host`, r.status === 404, String(r.status));
  }
  const page = await (await guest.req('https://ptra.cc/admin')).text();
  ok('and no button is offered there', !page.includes('data-slink-passkey-login'));
}

/* ------------------------------------------------- 9. impersonation */
section('impersonation stops at the door');
{
  const target = peer(root);
  await target.signIn('fifth@pontera.com');

  const users = await (await root.req(HUB + '/admin/users')).text();
  const tok = Harness.csrfFor(users, '/admin/users/impersonate');
  const start = await root.req(HUB + '/admin/users/impersonate', {
    form: { _csrf: tok, u: 'fifth@pontera.com' },
  });
  const where = start.headers.get('Location') || '';
  ok('impersonation starts', where.startsWith('/admin/as/'), where.slice(0, 20));

  const prefix = where.replace(/\/?$/, '');
  const view = await (await root.req(HUB + prefix)).text();
  ok('the view has no passkeys tab', !view.includes('>Passkeys<'));

  const page = await root.req(HUB + prefix + '/passkeys');
  ok('and the page itself refuses', page.status === 403, String(page.status));

  const begin = await root.req(HUB + prefix + '/passkeys/register/begin', { json: { _csrf: 'x' } });
  ok('registering from an impersonated view is refused', begin.status === 403, String(begin.status));
}

/* ------------------------------------------- 9b. awkward credentials */
section('an awkward credential is still handled');
{
  const person = peer(root);
  await person.signIn('seventh@pontera.com');

  // The specification allows a credential id of up to 1023 bytes, which is
  // 1366 characters of base64url - far past the 512-byte limit on a KV key.
  const long = await makeAuthenticator({ idBytes: 1023 });
  const r = await enrol(person, long, { name: 'Long id' });
  ok('a 1023-byte credential id registers', r.finish.status === 200, JSON.stringify(r.body));
  ok('and it is listed', (await (await person.req(HUB + '/admin/passkeys')).text()).includes('Long id'));
  const back = peer(root);
  ok('and it signs in', (await signInWith(back, long)).body.ok === true);

  // One byte past the specification is refused by the parser, not stored.
  const tooLong = await makeAuthenticator({ idBytes: 1024 });
  const over = await enrol(person, tooLong, { name: 'Too long' });
  ok('a longer one is refused', over.finish.status === 400, String(over.finish.status));

  // A name is never trusted into the page.
  const nasty = await makeAuthenticator();
  const payload = '"><img src=x onerror=alert(1)>';
  await enrol(person, nasty, { name: payload });
  const page = await (await person.req(HUB + '/admin/passkeys')).text();
  ok('a name with markup comes back escaped', !page.includes(payload));
  ok('and the escaped form is there', page.includes('&quot;&gt;&lt;img'));
  ok('no attribute was broken out of', !/<img src=x onerror/.test(page));

  // Control characters never reach an attribute.
  const control = await makeAuthenticator();
  await enrol(person, control, { name: 'a\u0000b\nc' });
  const page2 = await (await person.req(HUB + '/admin/passkeys')).text();
  ok('control characters are stripped', !/value="[^"]*[\u0000-\u001f]/.test(page2));

  // An empty name falls back rather than rendering nothing.
  const blank = await makeAuthenticator();
  await enrol(person, blank, { name: '   ' });
  ok('a blank name gets a default',
     (await (await person.req(HUB + '/admin/passkeys')).text()).includes('value="Passkey"'));
}

/* ------------------------------------------------------- 10. the cap */
section('an account cannot hold unlimited keys');
{
  const person = peer(root);
  await person.signIn('sixth@pontera.com');
  let last = null;
  for (let i = 0; i < MAX_PASSKEYS; i++) {
    last = await enrol(person, await makeAuthenticator(), { name: 'Key ' + i });
  }
  ok('the cap is reachable', last && last.finish.status === 200, last && JSON.stringify(last.body));
  const over = await enrol(person, await makeAuthenticator(), { name: 'One too many' });
  ok('and one more is refused', over.begin.status === 400, String(over.begin.status));
  const page = await (await person.req(HUB + '/admin/passkeys')).text();
  ok('the page says so', page.includes('maximum of ' + MAX_PASSKEYS));
}

console.log(`\npasskeys: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
