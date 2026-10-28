/**
 * turnstile.js - integration with the pre-existing Turnstile widget.
 *
 * The widget and its sitekey/secret already exist; nothing here creates or
 * rotates a widget. The sitekey is read from `turnstile-sitekey` and the
 * secret from `turnstile-secret` (SCREAMING_SNAKE aliases are also accepted).
 * The secret is only ever sent to siteverify in a POST body - it is never
 * logged, echoed into HTML, or placed in a URL.
 *
 * Verification requires all three of: success === true, the action matching
 * the form that was submitted, and a hostname on this deployment's allow
 * list. Tokens are single use, so a failed submission must re-render or reset
 * the widget to obtain a fresh one.
 */

import { audit, EVENTS } from './audit.js';
import { consume } from './ratelimit.js';

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
const TIMEOUT_MS = 10000;

/** Field name the widget writes into the form. */
export const RESPONSE_FIELD = 'cf-turnstile-response';

/** The script tag; `defer`+`async` per Cloudflare's guidance. */
export function turnstileScriptTag() {
  return `<script src="${SCRIPT_URL}" async defer></script>`;
}

/**
 * The widget container. Implicit (class-based) rendering keeps the page free
 * of inline script, which is what lets the CSP forbid inline script entirely.
 */
export function turnstileWidget(siteKey, action) {
  return (
    `<div class="cf-turnstile" data-sitekey="${siteKey}" data-action="${action}" ` +
    `data-theme="auto" data-size="flexible" data-retry="auto"></div>`
  );
}

/**
 * Hostnames siteverify may legitimately report. Production never includes
 * localhost or 127.0.0.1.
 */
export function expectedHostnames(cfg) {
  const hosts = new Set();
  for (const host of cfg.knownHosts) {
    hosts.add(host);
    hosts.add('www.' + host);
  }
  hosts.add(cfg.hubHost);
  hosts.add('www.' + cfg.hubHost);
  if (cfg.settings.allowLocalhostTurnstile === true) {
    hosts.add('localhost');
    hosts.add('127.0.0.1');
  }
  return hosts;
}

/**
 * Verify a token. Returns { ok, reason, hostname, action }. Any failure is
 * reported to the caller as a generic refusal; the detail is for the audit
 * log, not for the end user.
 */
export async function verifyTurnstile(cfg, { token, remoteIp, expectedAction }) {
  if (!cfg.turnstileSecret) return { ok: false, reason: 'secret-not-configured' };
  if (!token || typeof token !== 'string' || token.length > 4096) {
    return { ok: false, reason: 'missing-token' };
  }

  const body = new URLSearchParams();
  body.set('secret', cfg.turnstileSecret);
  body.set('response', token);
  if (remoteIp) body.set('remoteip', remoteIp);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(SITEVERIFY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal,
    });
  } catch {
    return { ok: false, reason: 'siteverify-unreachable' };
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) return { ok: false, reason: 'siteverify-http-' + res.status };

  let data;
  try {
    data = await res.json();
  } catch {
    return { ok: false, reason: 'siteverify-bad-json' };
  }

  if (data.success !== true) {
    const codes = Array.isArray(data['error-codes']) ? data['error-codes'].join(',') : 'unknown';
    return { ok: false, reason: 'rejected:' + codes };
  }

  if (expectedAction && data.action !== expectedAction) {
    return { ok: false, reason: 'action-mismatch', action: data.action };
  }

  const allowed = expectedHostnames(cfg);
  if (!data.hostname || !allowed.has(String(data.hostname).toLowerCase())) {
    return { ok: false, reason: 'hostname-not-allowed', hostname: data.hostname };
  }

  return { ok: true, reason: null, hostname: data.hostname, action: data.action };
}

/**
 * Verify the token on a submitted form, applying a per-IP throttle first so a
 * flood of bogus tokens cannot be used to hammer siteverify. Returns
 * { ok, error } with a message safe to show the visitor.
 */
export async function turnstileVerifyOrFail(ctx, body, action) {
  const { cfg } = ctx;
  const ip = ctx.ip || '';
  const limits = cfg.settings.rateLimits || {};
  const guard = await consume(
    cfg,
    'turnstile',
    ip || 'none',
    (limits.otpRequestPerIp || 10) * 4,
    limits.otpWindowSeconds || 900
  );
  if (!guard.allowed) return { ok: false, error: 'Too many attempts. Try again later.' };

  const result = await verifyTurnstile(cfg, {
    token: body.get(RESPONSE_FIELD),
    remoteIp: ip,
    expectedAction: action,
  });
  if (result.ok) return { ok: true };

  // Also to the Worker log. A misconfigured secret rejects every sign-in, and
  // the audit log can only be read by someone who managed to sign in, so the
  // reason has to reach an operator through `wrangler tail` as well.
  // `invalid-input-secret` means the secret is wrong; `invalid-input-response`
  // means the token was.
  console.warn('turnstile rejected:', result.reason, 'action=' + action, 'host=' + ctx.host);
  ctx.waitUntil(
    audit(cfg, {
      event: EVENTS.loginBlocked,
      host: ctx.host,
      ip,
      outcome: 'turnstile',
      detail: { reason: result.reason, action },
    })
  );
  return { ok: false, error: 'Verification failed. Please try again.' };
}
