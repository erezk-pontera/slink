/**
 * admin-passkeys.js - the passkey screens and the four endpoints behind them.
 *
 * Registration and sign-in are each two steps: ask for a challenge, then
 * hand back what the authenticator produced. The challenge travels as a
 * signed token rather than a stored record, so an abandoned attempt costs
 * nothing and expires by itself.
 *
 * These four speak JSON rather than form posts, because the browser has to
 * return structured data from `navigator.credentials`. They are guarded
 * exactly as a form is: the CSRF token the page was rendered with travels in
 * the JSON body under the same name, and the Origin is checked.
 */

import { adminPage, back, denied, flashFrom, readForm } from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf, safeNext, createSession, tokenFor, mayAuthenticate } from './auth.js';
import { clientIp, geoCheck, geoMessage } from './geo.js';
import {
  CHALLENGE_TTL_SECONDS,
  cleanName,
  deletePasskey,
  getPasskey,
  listPasskeys,
  MAX_NAME,
  MAX_PASSKEYS,
  mintChallenge,
  newPasskey,
  openChallenge,
  passkeysEnabled,
  putPasskey,
  rpId,
} from './passkeys.js';
import * as rl from './ratelimit.js';
import { harden } from './security.js';
import { getUserByNorm, isAdmin, putUser } from './users.js';
import { esc, fmtTime, now } from './util.js';
import { alert, csrfField, hidden } from './views.js';
import { ALGORITHMS, fromB64Url, RS256, verifyAssertion, verifyRegistration } from './webauthn.js';

/** The largest JSON body any of these endpoints legitimately produces. */
const MAX_BODY = 32 * 1024;

/**
 * Sign-in attempts one address can make from one network before it has to
 * wait. A passkey assertion is cheap to refuse but a credential id is a
 * guessable-looking string, so the attempt rate is capped rather than left
 * open. Held here rather than in settings: it needs no tuning and an
 * administrator cannot lock themselves out by getting it wrong.
 */
const LOGIN_ATTEMPTS_PER_IP = 30;
const LOGIN_WINDOW_SECONDS = 900;

function json(data, status = 200, cookies = []) {
  const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
  for (const cookie of cookies) if (cookie) headers.append('Set-Cookie', cookie);
  // Through harden() like every other response, so a JSON reply carries the
  // same headers a page does rather than its own shorter list.
  return harden(new Response(JSON.stringify(data), { status, headers }));
}

/** Read a JSON object body, refusing anything oversized or malformed. */
async function readJson(request) {
  const type = request.headers.get('Content-Type') || '';
  if (!type.includes('application/json')) return null;
  const declared = Number.parseInt(request.headers.get('Content-Length') || '', 10);
  if (Number.isFinite(declared) && declared > MAX_BODY) return null;
  let text;
  try {
    text = await request.text();
  } catch {
    return null;
  }
  if (text.length > MAX_BODY) return null;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value;
}

/** A string field from a JSON body, or '' when it is anything else. */
function str(body, name) {
  const value = body[name];
  return typeof value === 'string' ? value : '';
}

/**
 * The same guard a form gets. `checkCsrf` reads the token through `get`, so
 * one implementation covers both a form body and a JSON one.
 */
function guardJson(ctx, form, body) {
  return checkCsrf(ctx, form, { get: (name) => str(body, name) });
}

/* --------------------------------------------------------- registration */

/** Step one: hand the browser a challenge to register against. */
export async function registerBegin(ctx) {
  const { cfg, session } = ctx;
  // An administrator viewing the hub as somebody else is not that person.
  // Enrolling a key there would attach a device the account holder has
  // never seen, so impersonation stops at this door.
  if (ctx.impersonator) return json({ error: 'Not available while impersonating.' }, 403);

  const body = await readJson(ctx.request);
  if (!body) return json({ error: 'That request could not be read.' }, 400);
  const guard = await guardJson(ctx, 'passkey.register', body);
  if (!guard.ok) return json({ error: 'That request could not be verified.' }, 403);

  const existing = await listPasskeys(cfg, session.user.id);
  if (existing.length >= MAX_PASSKEYS) {
    return json({ error: 'This account already holds as many passkeys as it can.' }, 400);
  }

  const { challenge, token } = await mintChallenge(cfg, { kind: 'create', userId: session.user.id });
  return json({
    challenge,
    token,
    timeout: CHALLENGE_TTL_SECONDS * 1000,
    rp: { id: rpId(cfg), name: cfg.appName },
    user: {
      // The handle is the account id rather than the address: it is stored
      // on the authenticator, and an address can change.
      id: session.user.id,
      name: session.user.emailNorm,
      displayName: session.user.email || session.user.emailNorm,
    },
    algorithms: ALGORITHMS,
    // So the browser does not offer to enrol a key this account already has.
    exclude: existing.map((key) => key.credentialId),
  });
}

/** Step two: check what came back, and keep the credential. */
export async function registerFinish(ctx) {
  const { cfg, session } = ctx;
  if (ctx.impersonator) return json({ error: 'Not available while impersonating.' }, 403);

  const body = await readJson(ctx.request);
  if (!body) return json({ error: 'That request could not be read.' }, 400);
  const guard = await guardJson(ctx, 'passkey.register', body);
  if (!guard.ok) return json({ error: 'That request could not be verified.' }, 403);

  const challenge = await openChallenge(cfg, str(body, 'token'), {
    kind: 'create',
    userId: session.user.id,
  });
  if (!challenge) return json({ error: 'That took too long. Please try again.' }, 400);

  let credential;
  try {
    credential = await verifyRegistration({
      attestationObject: fromB64Url(str(body, 'attestationObject')),
      clientDataJSON: fromB64Url(str(body, 'clientDataJSON')),
      challenge,
      origin: ctx.origin,
      rpId: rpId(cfg),
    });
  } catch (err) {
    return json({ error: 'That key could not be registered: ' + (err && err.message) }, 400);
  }

  // A credential belongs to one account. Were a re-registration allowed to
  // overwrite, enrolling a key would be a way to move it between accounts.
  const already = await getPasskey(cfg, credential.credentialId);
  if (already) {
    return json(
      {
        error:
          already.userId === session.user.id
            ? 'That passkey is already on this account.'
            : 'That passkey is already registered.',
      },
      409
    );
  }

  // Re-read rather than trusting the count from step one: two tabs could
  // each have been handed a challenge while the account was one short.
  if ((await listPasskeys(cfg, session.user.id)).length >= MAX_PASSKEYS) {
    return json({ error: 'This account already holds as many passkeys as it can.' }, 400);
  }

  const key = newPasskey(session.user, { ...credential, name: str(body, 'name') });
  await putPasskey(cfg, key);

  ctx.waitUntil(
    audit(cfg, {
      event: EVENTS.passkeyAdded,
      actor: session.user,
      host: ctx.host,
      ip: ctx.ip,
      detail: { name: key.name, alg: key.alg },
    })
  );
  return json({ ok: true, id: key.id, name: key.name });
}

/* -------------------------------------------------------------- sign-in */

/**
 * Step one of signing in.
 *
 * No address is asked for and none is revealed: the response is the same
 * whoever is asking, and a discoverable credential means the browser
 * already knows which keys it holds for this site.
 */
export async function loginBegin(ctx) {
  const { cfg } = ctx;
  if (ctx.session) return json({ error: 'Already signed in.' }, 400);

  const body = await readJson(ctx.request);
  if (!body) return json({ error: 'That request could not be read.' }, 400);
  const guard = await guardJson(ctx, 'passkey.login', body);
  if (!guard.ok) return json({ error: 'That request could not be verified.' }, 403);

  // No policy check here, deliberately. A challenge is 32 random bytes and
  // says nothing about anyone, while the account doing the signing in is
  // not known until the assertion comes back - that is what a discoverable
  // credential means. Refusing here would also take the passkey away from
  // an administrator on a host that has switched them off, and an
  // administrator keeps every method. The policy is applied at the finish,
  // where there is an account to apply it to.
  const { challenge, token } = await mintChallenge(cfg, { kind: 'get' });
  return json({ challenge, token, timeout: CHALLENGE_TTL_SECONDS * 1000, rpId: rpId(cfg) });
}

/** Step two: check the assertion and open a session. */
export async function loginFinish(ctx) {
  const { cfg, domain, host, request } = ctx;
  const ip = clientIp(request);
  if (ctx.session) return json({ error: 'Already signed in.' }, 400);

  const body = await readJson(request);
  if (!body) return json({ error: 'That request could not be read.' }, 400);
  const guard = await guardJson(ctx, 'passkey.login', body);
  if (!guard.ok) return json({ error: 'That request could not be verified.' }, 403);

  const gate = geoCheck(cfg, request, 'login');
  if (!gate.allowed) return json({ error: geoMessage(gate.reason) }, 403);

  const limited = await rl.consume(
    cfg,
    'passkey-login',
    ip || 'unknown',
    LOGIN_ATTEMPTS_PER_IP,
    LOGIN_WINDOW_SECONDS
  );
  if (!limited.allowed) return json({ error: 'Too many attempts. Try again later.' }, 429);

  const challenge = await openChallenge(cfg, str(body, 'token'), { kind: 'get' });
  if (!challenge) return json({ error: 'That took too long. Please try again.' }, 400);

  // Deliberately one message for every refusal below. Whether a credential
  // exists, whose it is, and whether that account may sign in here are all
  // things a caller holding a guess should not learn.
  const refuse = () => json({ error: 'That passkey could not be used to sign in here.' }, 400);
  const miss = (reason, detail = {}) => {
    ctx.waitUntil(
      audit(cfg, {
        event: EVENTS.loginFailed,
        host,
        ip,
        outcome: reason,
        detail: { via: 'passkey', ...detail },
      })
    );
    return refuse();
  };

  const stored = await getPasskey(cfg, str(body, 'id'));
  if (!stored) return miss('unknown');

  const user = await getUserByNorm(cfg, stored.userEmail);
  if (!user || user.disabled) return miss('disabled', { email: stored.userEmail });
  const admin = isAdmin(cfg, user);
  if (!passkeysEnabled(cfg, domain, { isAdmin: admin })) return miss('method-off');
  if (!mayAuthenticate(cfg, domain, user.emailNorm)) return miss('domain', { email: user.emailNorm });

  let result;
  try {
    result = await verifyAssertion({
      credential: stored,
      authenticatorData: fromB64Url(str(body, 'authenticatorData')),
      clientDataJSON: fromB64Url(str(body, 'clientDataJSON')),
      signature: fromB64Url(str(body, 'signature')),
      challenge,
      origin: ctx.origin,
      rpId: rpId(cfg),
    });
  } catch {
    return miss('signature', { email: user.emailNorm });
  }

  stored.signCount = result.signCount;
  stored.lastUsedAt = now();
  stored.useCount = (stored.useCount || 0) + 1;
  if (result.cloneWarning) stored.cloneWarning = true;
  await putPasskey(cfg, stored);

  user.lastLoginAt = now();
  user.loginCount = (user.loginCount || 0) + 1;
  await putUser(cfg, user);

  const session = await createSession(cfg, { user, host, request });
  await rl.clear(cfg, 'passkey-login', ip || 'unknown');
  ctx.waitUntil(
    audit(cfg, {
      event: EVENTS.loginSucceeded,
      actor: user,
      host,
      ip,
      detail: {
        via: 'passkey',
        name: stored.name,
        cloneWarning: result.cloneWarning || undefined,
      },
    })
  );

  return json({ ok: true, next: safeNext(str(body, 'next'), '/admin') }, 200, [session.cookie]);
}

/* ------------------------------------------------------------- managing */

/**
 * The management screen.
 *
 * A passkey is personal: it is listed, named and removed by the account
 * that holds it and by nobody else, an administrator included. Someone
 * locked out is helped by disabling the account or by the emailed code,
 * not by reaching into their keys.
 */
export async function passkeysPage(ctx, { error, info } = {}) {
  // Which devices somebody holds is theirs to know. An impersonated view
  // is not them, so it sees nothing here rather than a list it could act on.
  if (ctx.impersonator) {
    return denied(ctx, 'Passkeys belong to the account holder and are not visible from here.');
  }
  const keys = await listPasskeys(ctx.cfg, ctx.session.user.id);
  const token = await tokenFor(ctx, 'passkey.manage');
  const register = await tokenFor(ctx, 'passkey.register');

  const rows = keys
    .map(
      (key) => `<tr>
      <td class="tools">
        <form method="post" action="/admin/passkeys">
          ${csrfField(token)}${hidden('id', key.id)}${hidden('action', 'rename')}
          <label class="visually-hidden" for="f_pk_${esc(key.id)}">Name</label>
          <input id="f_pk_${esc(key.id)}" type="text" name="name" value="${esc(key.name)}"
                 maxlength="${MAX_NAME}" spellcheck="false" required>
          <button type="submit" class="link">Rename</button>
        </form>
      </td>
      <td>${key.alg === RS256 ? 'RSA' : 'EC P-256'}${
        key.cloneWarning
          ? ' <span class="badge off" title="The counter on this key went backwards, which can mean it has been copied. Remove it if that was not expected.">check this one</span>'
          : ''
      }</td>
      <td>${esc(fmtTime(key.createdAt))}</td>
      <td>${key.lastUsedAt ? esc(fmtTime(key.lastUsedAt)) : '—'}</td>
      <td class="num">${key.useCount || 0}</td>
      <td class="tools">
        <form method="post" action="/admin/passkeys"
              data-confirm="Remove ${esc(key.name)}? You will not be able to sign in with it again.">
          ${csrfField(token)}${hidden('id', key.id)}${hidden('action', 'delete')}
          <button type="submit" class="link">Remove</button>
        </form>
      </td>
    </tr>`
    )
    .join('');

  const full = keys.length >= MAX_PASSKEYS;
  const body = `
${flashFrom(ctx.url)}${alert('error', error)}${alert('ok', info)}
<h1>Passkeys</h1>
<p class="sub">Sign in with the fingerprint reader, face unlock or security key this
device already has, instead of waiting for a code.</p>

<div class="card">
  <h2>Your passkeys</h2>
  ${
    rows
      ? `<div class="tablewrap"><table>
          <thead><tr><th>Name</th><th>Type</th><th>Added</th><th>Last used</th>
            <th class="num">Uses</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table></div>`
      : '<div class="empty">You have not added a passkey yet.</div>'
  }
</div>

<div class="card" data-slink-passkey-add data-token="${esc(register)}">
  <h2>Add a passkey</h2>
  ${
    full
      ? `<p class="hint">This account holds the maximum of ${MAX_PASSKEYS}. Remove one to add another.</p>`
      : `<noscript><p class="hint">Adding a passkey needs JavaScript. The emailed code works without it.</p></noscript>
  <div class="field">
    <label for="f_pk_new">Name this key</label>
    <input id="f_pk_new" type="text" data-slink-passkey-name value="This device"
           maxlength="${MAX_NAME}" spellcheck="false">
    <p class="hint">Only you see this. Something like &ldquo;work laptop&rdquo; makes it easy to
    tell which one to remove later.</p>
  </div>
  <div class="actions">
    <button type="button" data-slink-passkey-go hidden>Add a passkey</button>
  </div>
  <p class="hint" data-slink-passkey-msg role="status"></p>`
  }
</div>

<div class="card">
  <h2>Good to know</h2>
  <ul class="hint">
    <li>A passkey never replaces the emailed code. If you lose the device, ask for a code as usual.</li>
    <li>The key itself never leaves your device; this service only stores its public half.</li>
    <li>Passkeys belong to you alone. Nobody else, administrators included, can see, rename or remove them.</li>
  </ul>
</div>`;

  return adminPage(ctx, { title: 'Passkeys', nav: 'passkeys', body, status: error ? 400 : 200 });
}

/** Rename or remove one of your own passkeys. */
async function manageSubmit(ctx) {
  if (ctx.impersonator) return back('/admin/passkeys', 'denied');

  const body = await readForm(ctx.request);
  if (!body) return back('/admin/passkeys', 'csrf');
  const guard = await checkCsrf(ctx, 'passkey.manage', body);
  if (!guard.ok) return back('/admin/passkeys', 'csrf');

  const id = String(body.get('id') || '');
  const mine = await listPasskeys(ctx.cfg, ctx.session.user.id);
  const key = mine.find((candidate) => candidate.id === id);
  if (!key) return back('/admin/passkeys', 'notfound');

  if (body.get('action') === 'delete') {
    await deletePasskey(ctx.cfg, key);
    ctx.waitUntil(
      audit(ctx.cfg, {
        event: EVENTS.passkeyRemoved,
        actor: ctx.session.user,
        host: ctx.host,
        ip: ctx.ip,
        detail: { name: key.name },
      })
    );
    return back('/admin/passkeys', 'passkey.removed');
  }

  const raw = String(body.get('name') || '').trim();
  if (!raw) return back('/admin/passkeys', 'passkey.noname');
  key.name = cleanName(raw);
  await putPasskey(ctx.cfg, key);
  return back('/admin/passkeys', 'passkey.renamed');
}

/** Dispatch everything under /admin/passkeys. */
export async function adminPasskeys(ctx, path) {
  const post = ctx.request.method === 'POST';
  if (path === '/admin/passkeys/register/begin') {
    return post ? registerBegin(ctx) : json({ error: 'Use POST.' }, 405);
  }
  if (path === '/admin/passkeys/register/finish') {
    return post ? registerFinish(ctx) : json({ error: 'Use POST.' }, 405);
  }
  if (path !== '/admin/passkeys') return null;
  return post ? manageSubmit(ctx) : passkeysPage(ctx);
}
