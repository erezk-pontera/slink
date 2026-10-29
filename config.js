/**
 * config.js - resolves runtime configuration.
 *
 * Environment variables supply the defaults and the secrets. Everything an
 * administrator is allowed to change at runtime lives in the `cfg` KV record
 * and overrides the environment value. Secrets are never overridable.
 */

import { K, Store } from './kv.js';
import { canonicalHost, DEFAULT_BLOCKED_SCHEMES, parseDestination } from './paths.js';
import { boolEnv, intEnv, isSafeKey, listEnv, now } from './util.js';

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
  /**
   * Destination schemes this installation refuses. Editable, and starts at
   * the dangerous set; see DEFAULT_BLOCKED_SCHEMES in paths.js for what
   * taking one off the list reopens.
   */
  blockedSchemes: [...DEFAULT_BLOCKED_SCHEMES],
  /**
   * Whether the list above has been chosen under the current rules.
   *
   * These five used to be refused by paths.js whatever the list said, so a
   * record saved before that changed can carry an empty list while meaning
   * "the five, and nothing else". Taking that literally would quietly unblock
   * them on an installation already running, so until the settings screen is
   * saved once they are added back; see loadConfig.
   */
  blockedSchemesSet: false,
  /**
   * Sign-in routes switched off for the whole installation, from
   * oauth.js METHODS. Single sign-on itself can never be one of them.
   */
  disabledMethods: [],
  /**
   * Whether the list above has been chosen here rather than per domain.
   *
   * These switches used to live on each domain's own screen. Until this
   * screen is saved once, methodsFor still reads the domain record it was
   * given, which on the hub - the only host that signs anybody in - is the
   * setting that was already governing the installation. Nothing changes
   * at the moment of deploy; saving the screen is what moves it.
   */
  disabledMethodsSet: false,
  /** The identity provider, one for the whole installation. See oauth.js. */
  oauth: {
    enabled: false,
    label: 'Single sign-on',
    clientId: '',
    authorizeUrl: '',
    tokenUrl: '',
    userinfoUrl: '',
    scope: 'openid email profile',
    emailField: 'email',
  },
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
    if (!isSafeKey(key)) continue;
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
    /**
     * The secret this deployment used before the current one, if it has
     * just been rotated. Optional, and only ever used to *read*: a link
     * password sealed under the old secret stays readable, and is re-sealed
     * under the new one the next time it is saved. Without it, rotating
     * AUTH_SECRET leaves every protected link stuck behind a password
     * nobody can read or type.
     */
    this.authSecretPrevious = envVar(env, 'AUTH_SECRET_PREVIOUS', 'auth-secret-previous') || '';
    this.turnstileSiteKey = envVar(env, 'turnstile-sitekey', 'TURNSTILE_SITEKEY', 'TURNSTILE_SITE_KEY');
    this.turnstileSecret = envVar(env, 'turnstile-secret', 'TURNSTILE_SECRET');
    this.oauthSecret = envVar(env, 'oauth-secret', 'OAUTH_SECRET');

    /**
     * The domain this installation is managed from: the one carrying /admin,
     * /login and /logout, the one passkeys are bound to, and the one the
     * other hosts hand sign-in to. There is no default. Guessing one would
     * mean an installation that deploys cleanly and then offers its
     * administration on a domain nobody named; problems() refuses instead.
     */
    this.hubHost = canonicalHost(envVar(env, 'HUB_HOST'));
    this.appName = String(envVar(env, 'APP_NAME') || 'Shrink Link');
    /**
     * The line at the bottom of every page: a copyright notice, a company
     * name, whatever this installation needs. Plain text, escaped like
     * anything else, and left out entirely when it is not set.
     */
    this.footerText = String(envVar(env, 'FOOTER_TEXT') || '');
    /**
     * The hosts this worker answers for, put through the same canonical
     * form an incoming Host header is: lowercased, any port dropped, a
     * leading `www.` removed.
     *
     * The two are compared directly on every request, so an entry carrying
     * either would have matched nothing at all - an installation that
     * deploys cleanly, passes its checks and serves nobody. Duplicates
     * collapse on the way through, since `ptra.dev` and `www.ptra.dev` are
     * one host here and always were.
     */
    this.knownHosts = [
      ...new Set(
        listEnv(envVar(env, 'DOMAINS'), ['ptra.cc', 'ptra.dev'])
          .map(canonicalHost)
          .filter(Boolean)
      ),
    ];

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
    // oauth-secret is only needed where a host actually offers single
    // sign-on, so its absence is reported by the domain screen rather than
    // held against the whole installation here.
    if (this.rootAdmins.length === 0) out.push('ADMIN is not configured.');
    // A management domain that is not served is the same as none at all: the
    // worker answers for DOMAINS only, so /admin would be on a host that
    // never reaches this code. A typo here is otherwise silent, and silent
    // means an installation with no way in.
    if (!this.hubHost) {
      out.push('HUB_HOST is not configured.');
    } else if (!this.knownHosts.includes(this.hubHost)) {
      out.push('HUB_HOST is not one of DOMAINS.');
    }
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

  // A settings record written before the hard block became an editable list
  // says nothing about these five, because back then the list did not govern
  // them. Reading its silence as consent would unblock `javascript:` on an
  // installation that never asked for it, so they are put back until the
  // screen is saved once under the current rules.
  if (!settings.blockedSchemesSet) {
    const have = new Set((settings.blockedSchemes || []).map((s) => String(s).toLowerCase()));
    settings.blockedSchemes = [
      ...DEFAULT_BLOCKED_SCHEMES.filter((s) => !have.has(s)),
      ...(settings.blockedSchemes || []),
    ];
  }

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
