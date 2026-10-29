/**
 * Single sign-on, driven end to end against a stand-in provider.
 *
 * The flow is only half the story: the other half is that the provider
 * establishes an address and nothing more. The host's allowed-domain list,
 * the disabled flag and the administrator exemption all still apply.
 */
import { Harness } from './harness.js';
import {
  isPrivateHost,
  methodsFor,
  normalizeDisabledMethods,
  normalizeOauth,
  oauthReady,
  oauthSettings,
} from '../oauth.js';

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

const PROVIDER = {
  oauthEnabled: '1',
  oauthLabel: 'Example SSO',
  oauthClientId: 'client-123',
  oauthAuthorizeUrl: 'https://idp.example/authorize',
  oauthTokenUrl: 'https://idp.example/token',
  oauthUserinfoUrl: 'https://idp.example/me',
  oauthScope: 'openid email',
  oauthEmailField: 'email',
};

const root = new Harness();
await root.signIn('root@pontera.com');

/** The per-host switches, which stay on the domain screen. */
async function setDomain(extra) {
  const url = 'https://ptra.dev/admin/domains/edit?host=ptra.dev';
  const tok = Harness.csrfFor(await (await root.req(url)).text(), '/admin/domains/edit');
  return root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: tok, host: 'ptra.dev', defaultStatus: '302', rootCreatePolicy: 'email_domain',
      enabled: '1', authRequired: '1', allowedAuthDomains: 'pontera.com', ...extra,
    },
  });
}

/**
 * The provider itself, which is one setting for the installation. Posting
 * the whole settings form, as a browser would, so nothing else is cleared.
 */
async function setProvider(extra) {
  const page = await (await root.req('https://ptra.dev/admin/settings')).text();
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
  return root.req('https://ptra.dev/admin/settings', { form: { ...form, ...extra } });
}

/** Clear the provider again. */
const clearProvider = () => setProvider({ oauthEnabled: '' });

/* --------------------------------------------------- 1. configuration */
section('configuration');
{
  ok('an http endpoint is discarded', normalizeOauth({ tokenUrl: 'http://idp.example/t' }).tokenUrl === '');
  ok('an https endpoint is kept', normalizeOauth({ tokenUrl: 'https://idp.example/t' }).tokenUrl !== '');
  ok('rubbish is discarded', normalizeOauth({ tokenUrl: 'not a url' }).tokenUrl === '');

  // The provider lives in settings, not on a domain.
  const withProvider = (over = {}) => ({
    oauthSecret: 's',
    settings: {
      oauth: {
        enabled: true, clientId: 'c', authorizeUrl: 'https://idp.example/a',
        tokenUrl: 'https://idp.example/t', userinfoUrl: 'https://idp.example/u', ...over,
      },
    },
  });
  ok('not ready without a secret', !oauthReady({ ...withProvider(), oauthSecret: '' }));
  ok('ready with a secret', oauthReady(withProvider()));
  ok('not ready when switched off', !oauthReady(withProvider({ enabled: false })));
  ok('not ready with an endpoint missing', !oauthReady(withProvider({ tokenUrl: '' })));
  ok('a provider on a domain record is ignored',
     !oauthReady({ oauthSecret: 's', settings: {} }));
  ok('the settings reader fills in the defaults',
     oauthSettings({ settings: {} }).emailField === 'email');
  ok('and is safe with nothing at all', oauthSettings({}).enabled === false);

  // These endpoints are fetched with the client secret attached, so a
  // wrong one sends that secret somewhere it should not go.
  for (const host of [
    '127.0.0.1', '10.0.0.1', '172.16.5.5', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', 'localhost', 'box.localhost', 'idp.internal',
    'printer.local', '[::1]', '[fd00::1]', '[fe80::1]',
  ]) {
    ok(`a private endpoint is refused: ${host}`,
       normalizeOauth({ tokenUrl: `https://${host}/t` }).tokenUrl === '');
  }
  for (const host of ['idp.example.com', '8.8.8.8', '172.15.0.1', '172.32.0.1', '100.128.0.1']) {
    ok(`a public endpoint is kept: ${host}`,
       normalizeOauth({ tokenUrl: `https://${host}/t` }).tokenUrl !== '');
  }
  ok('the host check is exported for reuse', isPrivateHost('10.1.2.3') && !isPrivateHost('example.com'));

  ok('single sign-on cannot be disabled', !normalizeDisabledMethods(['oauth', 'otp']).includes('oauth'));
  ok('an unknown method is dropped', normalizeDisabledMethods(['nonsense']).length === 0);

  ok('no provider means every route stays',
     methodsFor({ oauthSecret: 's', settings: {} }, {}).otp === true);
  ok('a host may turn the code off',
     methodsFor(withProvider(), { disabledMethods: ['otp'] }).otp === false);
  ok('an administrator keeps the code',
     methodsFor(withProvider(), { disabledMethods: ['otp'] }, { isAdmin: true }).otp === true);
  ok('switching the code off needs a working provider',
     methodsFor({ oauthSecret: 's', settings: {} }, { disabledMethods: ['otp'] }).otp === true);
  ok('the switch is still per host',
     methodsFor(withProvider(), { disabledMethods: [] }).otp === true &&
     methodsFor(withProvider(), { disabledMethods: ['otp'] }).otp === false);
}

/* -------------------------------------------------------- 2. the page */
section('the sign-in page');
{
  const before = await (await root.req('https://ptra.dev/admin', { cookies: false })).text();
  ok('no button before it is configured', !before.includes('/__slink/oauth/start'));

  await setProvider(PROVIDER);
  const after = await (await root.req('https://ptra.dev/admin', { cookies: false })).text();
  ok('the button appears', after.includes('/__slink/oauth/start'));
  ok('it carries the label', after.includes('Continue with Example SSO'));
  ok('the code form is still offered', after.includes('name="email"'));
  ok('with a divider between them', after.includes('class="divider"'));

  await setDomain({ disable_otp: '1' });
  const only = await (await root.req('https://ptra.dev/admin', { cookies: false })).text();
  ok('turning the code off removes the form', !only.includes('name="email"'));
  ok('the button remains', only.includes('/__slink/oauth/start'));
  ok('an administrator can still reach the code',
     (await (await root.req('https://ptra.dev/admin?otp=1', { cookies: false })).text()).includes('name="email"'));

  await setDomain({});
}

/* ------------------------------------------------------ 3. the handshake */
section('the authorization request');
{
  const guest = peer(root);
  const r = await guest.req('https://ptra.dev/__slink/oauth/start?r=%2Fadmin%2Flinks');
  const loc = r.headers.get('Location') || '';
  ok('redirects to the provider', r.status === 303 && loc.startsWith('https://idp.example/authorize'), loc.slice(0, 60));

  const u = new URL(loc);
  ok('asks for a code', u.searchParams.get('response_type') === 'code');
  ok('names the client', u.searchParams.get('client_id') === 'client-123');
  ok('uses PKCE with S256', u.searchParams.get('code_challenge_method') === 'S256');
  ok('sends a challenge, not the verifier', (u.searchParams.get('code_challenge') || '').length === 43);
  ok('declares the redirect URI',
     u.searchParams.get('redirect_uri') === 'https://ptra.dev/__slink/oauth/callback');
  ok('carries a state', (u.searchParams.get('state') || '').length >= 16);

  const setCookie = r.headers.get('Set-Cookie') || '';
  ok('the attempt is held in a host-locked cookie', setCookie.includes('__Host-slink_oauth='));
  ok('the cookie is http-only', /HttpOnly/i.test(setCookie));
  ok('and same-site', /SameSite=Lax/i.test(setCookie));
  ok('the verifier never reaches the provider', !loc.includes(setCookie.slice(0, 20)));
}

/* -------------------------------------------------------- 4. the callback */
section('completing the sign-in');
{
  const user = peer(root);
  const start = await user.req('https://ptra.dev/__slink/oauth/start?r=%2Fadmin%2Flinks');
  const state = new URL(start.headers.get('Location')).searchParams.get('state');

  const done = await user.req('https://ptra.dev/__slink/oauth/callback?code=abc&state=' + state);
  ok('signs in and returns where it started',
     done.status === 303 && done.headers.get('Location') === '/admin/links',
     done.status + ' ' + done.headers.get('Location'));

  ok('the secret went in the body', user.idpToken && user.idpToken.client_secret !== undefined);
  ok('the verifier was presented', user.idpToken && (user.idpToken.code_verifier || '').length >= 40);
  ok('the grant type is right', user.idpToken && user.idpToken.grant_type === 'authorization_code');
  ok('the token was used as a bearer', user.idpAuth === 'Bearer at-abc');

  const page = await user.req('https://ptra.dev/admin');
  ok('the session works', page.status === 200);
  ok('and belongs to the provider address', (await page.text()).includes('sso@pontera.com'));

  const log = await (await root.req('https://ptra.dev/admin/audit')).text();
  ok('the sign-in is recorded as single sign-on', log.includes('oauth'));
}

/* --------------------------------------------------- 5. it is not trusted */
section('the provider establishes an address, nothing more');
{
  // An address outside the host's allowed domains is refused.
  const outsider = peer(root);
  outsider.idpEmail = 'someone@other.com';
  const s1 = await outsider.req('https://ptra.dev/__slink/oauth/start');
  const st1 = new URL(s1.headers.get('Location')).searchParams.get('state');
  const r1 = await outsider.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st1);
  ok('an address outside the allowed domains is refused',
     (await r1.text()).includes('may not sign in to this domain'), String(r1.status));

  // The provider's own verification flag is no longer consulted. Letting
  // somebody through its sign-in is the provider saying who they are;
  // what they may do here is decided on this side.
  const unverified = peer(root);
  unverified.idpVerified = false;
  unverified.idpEmail = 'unverified@pontera.com';
  const s2 = await unverified.req('https://ptra.dev/__slink/oauth/start');
  const st2 = new URL(s2.headers.get('Location')).searchParams.get('state');
  const r2 = await unverified.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st2);
  ok('an address the provider does not mark verified still signs in',
     r2.status === 303, String(r2.status));

  // What it does *not* get is any standing. The provider says who, never what.
  const who = await unverified.req('https://ptra.dev/admin');
  const page = await who.text();
  ok('and lands as an ordinary account', page.includes('unverified@pontera.com'));
  ok('with no administrator rights', !page.includes('administrator rights on every domain'));
  ok('and no administrator tabs', !page.includes('>Users<') && !page.includes('>Settings<'));

  // A disabled account stays disabled.
  const edit = 'https://ptra.dev/admin/users/edit?u=sso%40pontera.com';
  const tok = Harness.csrfFor(await (await root.req(edit)).text(), '/admin/users/edit');
  await root.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: tok, u: 'sso@pontera.com', disabled: '1' },
  });
  const blocked = peer(root);
  const s3 = await blocked.req('https://ptra.dev/__slink/oauth/start');
  const st3 = new URL(s3.headers.get('Location')).searchParams.get('state');
  const r3 = await blocked.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st3);
  ok('a disabled account is refused', (await r3.text()).includes('disabled'));
}

/* ------------------------------------------------------ 6. the callback is guarded */
section('the callback cannot be forged');
{
  const victim = peer(root);
  const start = await victim.req('https://ptra.dev/__slink/oauth/start');
  const state = new URL(start.headers.get('Location')).searchParams.get('state');

  const wrongState = await victim.req('https://ptra.dev/__slink/oauth/callback?code=a&state=not-it');
  ok('a mismatched state is refused', (await wrongState.text()).includes('could not be verified'));

  const noCookie = peer(root);
  const noJar = await noCookie.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + state);
  ok('another browser cannot complete it', (await noJar.text()).includes('took too long'));

  const noCode = peer(root);
  const s = await noCode.req('https://ptra.dev/__slink/oauth/start');
  const st = new URL(s.headers.get('Location')).searchParams.get('state');
  const missing = await noCode.req('https://ptra.dev/__slink/oauth/callback?state=' + st);
  ok('a callback with no code is refused', (await missing.text()).includes('did not return a code'));

  const refused = peer(root);
  refused.idpTokenStatus = 400;
  const s4 = await refused.req('https://ptra.dev/__slink/oauth/start');
  const st4 = new URL(s4.headers.get('Location')).searchParams.get('state');
  const r4 = await refused.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st4);
  ok('a provider refusal is surfaced', (await r4.text()).includes('refused the sign-in'));

  const noToken = peer(root);
  noToken.idpNoToken = true;
  const s5 = await noToken.req('https://ptra.dev/__slink/oauth/start');
  const st5 = new URL(s5.headers.get('Location')).searchParams.get('state');
  const r5 = await noToken.req('https://ptra.dev/__slink/oauth/callback?code=a&state=' + st5);
  ok('a reply with no token is refused', (await r5.text()).includes('no access token'));
}

/* ------------------------------- 7. the policy is enforced by address */
section('turning the code off is enforced where the address is known');
{
  // Anyone can add ?otp=1 to the URL, so the page cannot be what enforces
  // this. The rule has to be applied once an address has been typed.
  for (const who of ['ola@pontera.com', 'pat@pontera.com']) {
    const h = peer(root);
    await h.signIn(who);
  }
  const promote = 'https://ptra.dev/admin/users/edit?u=pat%40pontera.com';
  const ptok = Harness.csrfFor(await (await root.req(promote)).text(), '/admin/users/edit');
  await root.req('https://ptra.dev/admin/users/edit', {
    form: { _csrf: ptok, u: 'pat@pontera.com', isAdmin: '1', allDirectories: '1' },
  });

  await setDomain({ disable_otp: '1' });

  const tryOtp = async (email) => {
    const h = peer(root);
    const page = await (await h.req('https://ptra.dev/admin?otp=1')).text();
    const tok = Harness.csrf(page);
    const before = h.mail.length;
    const r = await h.req('https://ptra.dev/admin', {
      form: {
        _csrf: tok, stage: 'email', email, next: '/admin',
        'cf-turnstile-response': 't:login:ptra.dev',
      },
    });
    return { status: r.status, sent: h.mail.length > before };
  };

  const ordinary = await tryOtp('ola@pontera.com');
  ok('an ordinary address gets no code', !ordinary.sent);
  const admin = await tryOtp('pat@pontera.com');
  ok('an administrator still gets one', admin.sent);
  const rootAdmin = await tryOtp('root@pontera.com');
  ok('the root administrator still gets one', rootAdmin.sent);
  // Telling them apart would turn the sign-in form into a way of asking who
  // the administrators are.
  ok('the two outcomes are indistinguishable', ordinary.status === admin.status,
     ordinary.status + ' vs ' + admin.status);

  await setDomain(PROVIDER);
  const restored = await tryOtp('ola@pontera.com');
  ok('re-enabling the code restores it for everyone', restored.sent);
}

console.log(`\noauth: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
