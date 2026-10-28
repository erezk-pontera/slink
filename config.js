/**
 * config.js - resolves runtime configuration.
 *
 * Environment variables supply the defaults and the secrets. Everything an
 * administrator is allowed to change at runtime lives in the `cfg` KV record
 * and overrides the environment value. Secrets are never overridable.
 */

import { K, Store } from './kv.js';
import { parseDestination } from './paths.js';
import { boolEnv, intEnv, listEnv, now } from './util.js';

/** Read an env value under either the hyphenated or the SCREAMING_SNAKE name. */
export function envVar(env, ...names) {
  for (const name of names) {
    const v = env[name];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

export const DEFAULTS = {
  otpTtlSeconds: 600,
  otpLength: 6,
  otpMaxAttempts: 5,
  otpResendSeconds: 45,
  sessionTtlSeconds: 7 * 24 * 3600,
  sessionIdleSeconds: 0,
  sessionPermanent: false,
  auditRetentionDays: 180,
  interstitialDefaultDelay: 0,
  defaultStatus: 302,
  blockedSchemes: [],
  geo: {
    blockTor: true,
    blockUnknown: true,
    mode: 'off', // 'off' | 'allow' | 'block'
    countries: [],
    applyTo: 'login', // 'login' | 'all'
  },
  rateLimits: {
    otpRequestPerIp: 10,
    otpRequestPerEmail: 5,
    otpVerifyPerLogin: 8,
    otpWindowSeconds: 900,
  },
  mail: {
    // Blank falls back to the application name, so renaming the app renames
    // the sender too unless an administrator sets something else.
    fromName: '',
    replyTo: '',
    subject: 'Your {{app}} sign-in code: {{code}}',
  },
};

/** Permanent sessions still carry an absolute expiry; ten years is the cap. */
export const PERMANENT_TTL = 10 * 365 * 24 * 3600;

function mergeSettings(base, override) {
  const out = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (value === undefined) continue;
    if (value && typeof value === 'object' && !Array.isArray(value) && typeof base[key] === 'object') {
      out[key] = { ...base[key], ...value };
    } else {
      out[key] = value;
    }
  }
  return out;
}

/**
 * The resolved per-request context: bindings, secrets, settings and the
 * derived identity rules.
 */
export class Config {
  constructor(env, settings) {
    this.env = env;
    this.store = new Store(env.KV);
    this.settings = settings;

    this.authSecret = envVar(env, 'AUTH_SECRET', 'auth-secret');
    this.turnstileSiteKey = envVar(env, 'turnstile-sitekey', 'TURNSTILE_SITEKEY', 'TURNSTILE_SITE_KEY');
    this.turnstileSecret = envVar(env, 'turnstile-secret', 'TURNSTILE_SECRET');

    this.hubHost = String(envVar(env, 'HUB_HOST') || 'ptra.dev').toLowerCase().replace(/^www\./, '');
    this.appName = String(envVar(env, 'APP_NAME') || 'Shrink Link');
    this.knownHosts = listEnv(envVar(env, 'DOMAINS'), ['ptra.cc', 'ptra.dev']);

    this.rootAdmins = listEnv(envVar(env, 'ADMIN'));
    this.defaultAllowedDomains = listEnv(envVar(env, 'DEFAULT_ALLOWED_DOMAINS'));

    this.ignoreEmailDot = boolEnv(envVar(env, 'IGNORE_EMAIL_DOT'), false);
    this.ignoreEmailPlus = boolEnv(envVar(env, 'IGNORE_EMAIL_PLUS'), false);
    if (settings.ignoreEmailDot !== undefined) this.ignoreEmailDot = !!settings.ignoreEmailDot;
    if (settings.ignoreEmailPlus !== undefined) this.ignoreEmailPlus = !!settings.ignoreEmailPlus;

    this.mailFrom = envVar(env, 'MAIL_FROM') || 'no-reply@' + this.hubHost;
    this.mailProvider = String(envVar(env, 'MAIL_PROVIDER') || 'cloudflare').toLowerCase();
    this.emailBinding = env.EMAIL || null;

    this.debugMail = boolEnv(envVar(env, 'DEBUG_MAIL'), false);

    // Where a visitor goes when there is nothing to show them: a host root, an
    // unknown shortcut, or one that is disabled or expired. A domain may
    // override it per host in /admin/domains. Parsed through the destination
    // rules so a careless value cannot become a javascript: redirect.
    this.missingUrl = '';
    const missing = envVar(env, 'MISSING');
    if (missing) {
      try {
        this.missingUrl = parseDestination(missing, {
          blockedSchemes: settings.blockedSchemes,
        }).target;
      } catch {
        console.error('MISSING is not a usable destination; ignoring it.');
      }
    }
  }

  /** Options for normalizeEmail, honouring IGNORE_EMAIL_DOT / IGNORE_EMAIL_PLUS. */
  get emailOpts() {
    return { ignoreDot: this.ignoreEmailDot, ignorePlus: this.ignoreEmailPlus };
  }

  /** Session lifetime in seconds, honouring the "permanent" switch. */
  get sessionTtl() {
    return this.settings.sessionPermanent
      ? PERMANENT_TTL
      : Math.max(60, this.settings.sessionTtlSeconds);
  }

  /** Configuration problems that must fail closed rather than degrade. */
  problems() {
    const out = [];
    if (!this.env.KV) out.push('KV binding "KV" is not configured.');
    if (!this.authSecret || String(this.authSecret).length < 32) {
      out.push('AUTH_SECRET is missing or shorter than 32 characters.');
    }
    if (!this.turnstileSiteKey) out.push('turnstile-sitekey is not configured.');
    if (!this.turnstileSecret) out.push('turnstile-secret is not configured.');
    if (this.rootAdmins.length === 0) out.push('ADMIN is not configured.');
    return out;
  }
}

/** Load settings from KV and build the request configuration. */
export async function loadConfig(env) {
  const store = new Store(env.KV);
  let stored = null;
  try {
    stored = await store.get(K.settings());
  } catch {
    stored = null;
  }
  const envDefaults = {
    otpTtlSeconds: intEnv(envVar(env, 'OTP_TTL_SECONDS'), DEFAULTS.otpTtlSeconds, 30, 3600),
    otpLength: intEnv(envVar(env, 'OTP_LENGTH'), DEFAULTS.otpLength, 4, 10),
    otpMaxAttempts: intEnv(envVar(env, 'OTP_MAX_ATTEMPTS'), DEFAULTS.otpMaxAttempts, 1, 20),
    sessionTtlSeconds: intEnv(
      envVar(env, 'SESSION_TTL_SECONDS'),
      DEFAULTS.sessionTtlSeconds,
      60,
      PERMANENT_TTL
    ),
    sessionPermanent: boolEnv(envVar(env, 'SESSION_PERMANENT'), DEFAULTS.sessionPermanent),
  };
  const settings = mergeSettings(mergeSettings(DEFAULTS, envDefaults), stored || {});
  return new Config(env, settings);
}

/** Persist admin-edited settings. */
export async function saveSettings(cfg, patch) {
  const next = mergeSettings(cfg.settings, patch);
  next.updatedAt = now();
  await cfg.store.put(K.settings(), next);
  cfg.settings = next;
  return next;
}
