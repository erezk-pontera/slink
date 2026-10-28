/**
 * index.js - the Worker entry point and top-level router.
 *
 * Request shape:
 *   1. static assets and /health, which need no configuration
 *   2. configuration load, with a fail-closed check on secrets
 *   3. host resolution (apex and www are one host)
 *   4. session resolution, then the per-host authentication gate
 *   5. either an administration page (hub host only) or a shortcut lookup
 *
 * Every HTML response leaves through views.html(), which applies the security
 * headers, so there is no path that returns an unhardened page.
 */

import { handleAdmin, readForm } from './admin.js';
import {
  beginLogin,
  checkCsrf,
  completeLogin,
  COOKIE,
  csrfCookie,
  readSession,
  resendLogin,
  safeNext,
  signOut,
  ssoAuthorize,
  ssoCallback,
  ssoStart,
  tokenFor,
} from './auth.js';
import { serveAsset } from './assets.js';
import { loadConfig, saveSettings } from './config.js';
import { ensureBootstrapDomains, resolveDomain } from './domains.js';
import { clientIp, geoCheck, geoMessage } from './geo.js';
import { canonicalHost } from './paths.js';
import { rootCreateAllowed } from './permissions.js';
import { getChallenge } from './otp.js';
import { handleRedirect } from './redirect.js';
import { clearCookie, harden, parseCookies } from './security.js';
import { isAdmin } from './users.js';
import { randomId } from './util.js';
import { html, loginPage, messagePage, verifyPage } from './views.js';

const ALLOWED_METHODS = ['GET', 'HEAD', 'POST'];

/** Attach cookies to a response without discarding ones already set. */
function withCookies(response, cookies) {
  const list = (cookies || []).filter(Boolean);
  if (list.length === 0) return response;
  const out = new Response(response.body, response);
  for (const cookie of list) out.headers.append('Set-Cookie', cookie);
  return out;
}

/** A 303 redirect carrying cookies. */
function seeOther(location, cookies = []) {
  const headers = new Headers({ Location: location });
  for (const cookie of (cookies || []).filter(Boolean)) headers.append('Set-Cookie', cookie);
  return harden(new Response(null, { status: 303, headers }));
}

function textResponse(body, status = 200, type = 'text/plain; charset=utf-8') {
  return harden(new Response(body, { status, headers: { 'Content-Type': type } }));
}

/* ------------------------------------------------------------- sign-in UI */

async function loginGet(ctx) {
  if (ctx.session) return seeOther(safeNext(ctx.url.searchParams.get('next'), '/admin'));
  const csrf = await tokenFor(ctx, 'login.begin');
  const page = loginPage({
    cfg: ctx.cfg,
    host: ctx.host,
    csrf,
    next: safeNext(ctx.url.searchParams.get('next'), '/admin'),
    error: ctx.flashError,
    info: ctx.flashInfo,
  });
  return withCookies(html(page, { turnstile: true }), [csrfCookie(ctx)]);
}

async function loginPost(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return loginGet({ ...ctx, flashError: 'Could not read that form. Please try again.' });

  const guard = await checkCsrf(ctx, 'login.begin', body);
  if (!guard.ok) {
    return withCookies(
      html(
        loginPage({
          cfg: ctx.cfg,
          host: ctx.host,
          csrf: await tokenFor(ctx, 'login.begin'),
          next: safeNext(body.get('next'), '/admin'),
          error: 'That request could not be verified. Please try again.',
        }),
        { turnstile: true, status: 400 }
      ),
      [csrfCookie(ctx)]
    );
  }

  const result = await beginLogin(ctx, body);
  if (!result.ok) {
    return withCookies(
      html(
        loginPage({
          cfg: ctx.cfg,
          host: ctx.host,
          csrf: await tokenFor(ctx, 'login.begin'),
          next: safeNext(body.get('next'), '/admin'),
          error: result.error,
          email: String(body.get('email') || ''),
        }),
        { turnstile: true, status: 400 }
      ),
      [csrfCookie(ctx)]
    );
  }
  return seeOther('/login/verify', result.cookies);
}

async function verifyGet(ctx, { error, info } = {}) {
  const cookies = parseCookies(ctx.request);
  const loginId = cookies[COOKIE.login];
  if (!loginId) return seeOther('/login');

  const challenge = await getChallenge(ctx.cfg, loginId);
  if (!challenge) return seeOther('/login');

  const csrf = await tokenFor(ctx, 'login.verify');
  const page = verifyPage({
    cfg: ctx.cfg,
    host: ctx.host,
    csrf,
    email: challenge.email,
    expiresIn: Math.max(0, challenge.expiresAt - Math.floor(Date.now() / 1000)),
    error,
    info,
  });
  return withCookies(html(page, { turnstile: true }), [csrfCookie(ctx)]);
}

async function verifyPost(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return verifyGet(ctx, { error: 'Could not read that form. Please try again.' });

  const guard = await checkCsrf(ctx, 'login.verify', body);
  if (!guard.ok) return verifyGet(ctx, { error: 'That request could not be verified. Please try again.' });

  const result = await completeLogin(ctx, body);
  if (!result.ok) {
    if (result.restart) {
      return withCookies(
        html(
          loginPage({
            cfg: ctx.cfg,
            host: ctx.host,
            csrf: await tokenFor(ctx, 'login.begin'),
            next: '/admin',
            error: result.error,
          }),
          { turnstile: true, status: 400 }
        ),
        [clearCookie(COOKIE.login), csrfCookie(ctx)]
      );
    }
    return verifyGet(ctx, { error: result.error });
  }
  return seeOther(result.next, result.cookies);
}

async function resendPost(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return verifyGet(ctx, { error: 'Could not read that form. Please try again.' });
  const guard = await checkCsrf(ctx, 'login.verify', body);
  if (!guard.ok) return verifyGet(ctx, { error: 'That request could not be verified. Please try again.' });

  const result = await resendLogin(ctx);
  if (!result.ok) {
    if (result.restart) return seeOther('/login');
    return verifyGet(ctx, { error: result.error });
  }
  return verifyGet(ctx, { info: result.info });
}

/**
 * Sign-out is a POST so a third-party page cannot force it. The GET shows a
 * one-button confirmation.
 */
async function logoutGet(ctx) {
  if (!ctx.session) return seeOther('/login');
  const csrf = await tokenFor(ctx, 'logout');
  const page = messagePage({
    cfg: ctx.cfg,
    host: ctx.host,
    title: 'Sign out',
    heading: 'Sign out',
    message: 'This signs you out of every domain served by this worker.',
  });
  const form = `
<div class="card">
  <form method="post" action="/logout">
    <input type="hidden" name="_csrf" value="${csrf}">
    <div class="actions">
      <button type="submit">Sign out</button>
      <a class="btn secondary" href="/admin">Stay signed in</a>
    </div>
  </form>
</div>`;
  return html(page.body.replace('</main>', form + '</main>'));
}

async function logoutPost(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return seeOther('/logout');
  const guard = await checkCsrf(ctx, 'logout', body);
  if (!guard.ok) return seeOther('/logout');
  const result = await signOut(ctx, { everywhere: true });
  return seeOther('/login', result.cookies);
}

/* ------------------------------------------------------------------- SSO */

async function ssoAuthorizeGet(ctx) {
  const targetHost = canonicalHost(ctx.url.searchParams.get('h'));
  const returnPath = safeNext(ctx.url.searchParams.get('r'), '/');
  const nonce = ctx.url.searchParams.get('n') || '';

  if (!ctx.session) {
    const next = '/sso/authorize' + ctx.url.search;
    return seeOther('/login?next=' + encodeURIComponent(next));
  }
  const result = await ssoAuthorize(ctx, { targetHost, returnPath, nonce });
  if (!result.ok) {
    const page = messagePage({
      cfg: ctx.cfg,
      host: ctx.host,
      title: 'Sign-in',
      heading: 'Cannot continue',
      message: 'That sign-in request is not valid for this service.',
      status: 400,
      actions: [{ href: '/admin', label: 'Back to admin' }],
    });
    return html(page.body, { status: 400 });
  }
  return seeOther(result.location);
}

async function ssoCallbackGet(ctx) {
  const result = await ssoCallback(ctx, ctx.url.searchParams.get('t'));
  if (!result.ok) {
    const page = messagePage({
      cfg: ctx.cfg,
      host: ctx.host,
      title: 'Sign-in',
      heading: 'Sign-in failed',
      message: result.error,
      status: 400,
    });
    return withCookies(html(page.body, { status: 400 }), [clearCookie(COOKIE.sso)]);
  }
  return seeOther(result.next, result.cookies);
}

/* ---------------------------------------------------------------- router */

async function route(request, env, exec) {
  const url = new URL(request.url);

  // Static assets first: no configuration, no session, cacheable.
  const asset = serveAsset(url.pathname);
  if (asset) return asset;

  if (url.pathname === '/robots.txt') {
    return textResponse('User-agent: *\nDisallow: /\n');
  }

  if (!ALLOWED_METHODS.includes(request.method)) {
    return textResponse('Method not allowed', 405);
  }

  const cfg = await loadConfig(env);

  if (url.pathname === '/health') {
    // Unauthenticated, so it reports only a count. The names of the missing
    // settings go to the Worker log, where `wrangler tail` can read them.
    const problems = cfg.problems();
    if (problems.length) console.error('configuration incomplete:', problems.join(' '));
    return harden(
      new Response(JSON.stringify({ ok: problems.length === 0, problems: problems.length }), {
        status: problems.length === 0 ? 200 : 503,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      })
    );
  }

  // Fail closed on a misconfigured deployment rather than serving something
  // half-secured. The names of the missing settings are safe to show; their
  // values are never read here.
  const problems = cfg.problems();
  if (problems.length) {
    // The detail names which settings are absent, which is exactly what an
    // attacker probing a half-deployed service would like to know, so it goes
    // to the log rather than the page.
    console.error('configuration incomplete:', problems.join(' '));
    const page = messagePage({
      cfg,
      host: url.hostname,
      title: 'Unavailable',
      heading: 'This service is not available',
      message: 'It has not finished being set up. Please try again later.',
      status: 503,
    });
    return html(page.body, { status: 503 });
  }

  const host = canonicalHost(url.hostname);

  // Seed the configured hosts once, then remember it in settings.
  if (!cfg.settings.bootstrapAt) {
    const created = await ensureBootstrapDomains(cfg);
    await saveSettings(cfg, { bootstrapAt: Math.floor(Date.now() / 1000), bootstrapHosts: created });
  }

  const domain = await resolveDomain(cfg, host);
  if (!domain) {
    return textResponse('Unknown host', 404);
  }
  if (domain.enabled === false) {
    const page = messagePage({
      cfg,
      host,
      title: 'Unavailable',
      heading: 'This domain is disabled',
      message: 'An administrator has turned this domain off.',
      status: 503,
    });
    return html(page.body, { status: 503 });
  }

  const cookies = parseCookies(request);
  const existingNonce = cookies[COOKIE.csrf];
  const ctx = {
    cfg,
    env,
    request,
    url,
    host,
    domain,
    origin: url.origin,
    ip: clientIp(request),
    csrfNonce: existingNonce || randomId(18),
    csrfNonceIsNew: !existingNonce,
    waitUntil: (p) => exec.waitUntil(p),
    session: null,
    isAdmin: false,
    canCreateRoot: false,
  };

  ctx.session = await readSession(cfg, request, host);
  if (ctx.session) {
    if (ctx.session.touched) exec.waitUntil(ctx.session.touched);
    ctx.isAdmin = isAdmin(cfg, ctx.session.user);
    ctx.canCreateRoot = ctx.isAdmin || rootCreateAllowed(cfg, domain, ctx.session.user);
  }

  const path = url.pathname.replace(/\/+$/, '') || '/';
  const isHub = host === cfg.hubHost;

  // The SSO handshake endpoints live on every host.
  if (path === '/__slink/sso/callback') return ssoCallbackGet(ctx);
  if (path === '/__slink/sso/start') {
    if (ctx.session) return seeOther(safeNext(url.searchParams.get('r'), '/'));
    const start = ssoStart(ctx, url.searchParams.get('r') || '/');
    return seeOther(start.location, [start.cookie]);
  }

  if (isHub) {
    if (path === '/login') {
      return request.method === 'POST' ? loginPost(ctx) : loginGet(ctx);
    }
    if (path === '/login/verify') {
      return request.method === 'POST' ? verifyPost(ctx) : verifyGet(ctx);
    }
    if (path === '/login/resend' && request.method === 'POST') return resendPost(ctx);
    if (path === '/logout') {
      return request.method === 'POST' ? logoutPost(ctx) : logoutGet(ctx);
    }
    if (path === '/sso/authorize') return ssoAuthorizeGet(ctx);

    if (path === '/admin' || path.startsWith('/admin/')) {
      if (!ctx.session) {
        return seeOther('/login?next=' + encodeURIComponent(url.pathname + url.search));
      }
      const gate = geoCheck(cfg, request, 'access');
      if (!gate.allowed) {
        const page = messagePage({
          cfg,
          host,
          title: 'Unavailable',
          heading: 'Not available here',
          message: geoMessage(gate.reason),
          status: 403,
        });
        return html(page.body, { status: 403 });
      }
      const response = await handleAdmin(ctx);
      return withCookies(response, [csrfCookie(ctx)]);
    }
  }

  // Hosts that require authentication gate every shortcut behind a session.
  if (domain.authRequired && !ctx.session) {
    const want = url.pathname + url.search;
    if (isHub) return seeOther('/login?next=' + encodeURIComponent(want));
    const start = ssoStart(ctx, want);
    return seeOther(start.location, [start.cookie]);
  }

  if (domain.authRequired && ctx.session) {
    const gate = geoCheck(cfg, request, 'access');
    if (!gate.allowed) {
      const page = messagePage({
        cfg,
        host,
        title: 'Unavailable',
        heading: 'Not available here',
        message: geoMessage(gate.reason),
        status: 403,
      });
      return html(page.body, { status: 403 });
    }
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return textResponse('Method not allowed', 405);
  }

  return handleRedirect(ctx);
}

export default {
  async fetch(request, env, exec) {
    try {
      const response = await route(request, env, exec);
      if (request.method === 'HEAD') {
        return new Response(null, { status: response.status, headers: response.headers });
      }
      return response;
    } catch (err) {
      // Nothing from the exception reaches the client; the detail goes to the
      // Worker log where an operator can see it.
      console.error('unhandled', err && err.stack ? err.stack : String(err));
      return harden(
        new Response('Something went wrong.', {
          status: 500,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        })
      );
    }
  },
};
