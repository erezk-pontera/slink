/**
 * In-memory stand-in for a Workers KV namespace, good enough for the
 * behaviours this project relies on: JSON values, per-key metadata, prefix
 * listing in lexicographic order, cursors and TTL expiry.
 */
export class FakeKV {
  constructor() {
    this.map = new Map();
  }

  _live(key) {
    const rec = this.map.get(key);
    if (!rec) return null;
    if (rec.expires && rec.expires <= Date.now() / 1000) {
      this.map.delete(key);
      return null;
    }
    return rec;
  }

  async get(key, opts) {
    const rec = this._live(key);
    if (!rec) return null;
    const type = typeof opts === 'string' ? opts : opts && opts.type;
    return type === 'json' ? JSON.parse(rec.value) : rec.value;
  }

  async getWithMetadata(key, opts) {
    const rec = this._live(key);
    if (!rec) return { value: null, metadata: null };
    const type = typeof opts === 'string' ? opts : opts && opts.type;
    return {
      value: type === 'json' ? JSON.parse(rec.value) : rec.value,
      metadata: rec.metadata || null,
    };
  }

  async put(key, value, opts = {}) {
    const meta = opts.metadata || null;
    if (meta && JSON.stringify(meta).length > 1024) {
      throw new Error('KV metadata exceeds 1024 bytes: ' + key);
    }
    if (key.length > 512) throw new Error('KV key exceeds 512 bytes: ' + key);
    this.map.set(key, {
      value: String(value),
      metadata: meta,
      expires: opts.expirationTtl ? Date.now() / 1000 + opts.expirationTtl : 0,
    });
  }

  async delete(key) {
    this.map.delete(key);
  }

  async list({ prefix = '', limit = 1000, cursor } = {}) {
    const all = [...this.map.keys()].filter((k) => k.startsWith(prefix) && this._live(k)).sort();
    const start = cursor ? all.indexOf(cursor) + 1 : 0;
    const slice = all.slice(start, start + limit);
    const last = slice[slice.length - 1];
    const complete = start + slice.length >= all.length;
    return {
      keys: slice.map((name) => ({ name, metadata: this.map.get(name).metadata })),
      list_complete: complete,
      cursor: complete ? undefined : last,
    };
  }

  dump(prefix = '') {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
  }
}

export function makeEnv(overrides = {}) {
  return {
    KV: new FakeKV(),
    AUTH_SECRET: 'test-secret-value-that-is-long-enough-123456',
    'turnstile-sitekey': '1x00000000000000000000AA',
    'turnstile-secret': '1x0000000000000000000000000000000AA',
    'oauth-secret': 'test-oauth-client-secret',
    ADMIN: 'root@pontera.com',
    DEFAULT_ALLOWED_DOMAINS: 'pontera.com',
    // Mirrors wrangler.toml: dots and +tags are stripped for identity.
    IGNORE_EMAIL_DOT: 'true',
    IGNORE_EMAIL_PLUS: 'true',
    HUB_HOST: 'ptra.dev',
    DOMAINS: 'ptra.cc,ptra.dev',
    MAIL_FROM: 'no-reply@ptra.dev',
    MISSING: 'https://fallback.example/home',
    ...overrides,
  };
}
