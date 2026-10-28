/**
 * Drives the real Worker entry point against an in-memory KV, a stubbed
 * Turnstile siteverify and a capturing EMAIL binding, with a cookie jar so a
 * browser session can be followed across requests.
 */
import worker from '../index.js';
import { makeEnv } from './fakekv.js';

export class Harness {
  constructor(envOverrides = {}, { ip } = {}) {
    this.env = makeEnv(envOverrides);
    // A distinct client IP per harness, so per-IP rate limits behave as they
    // would for separate people rather than throttling the whole suite.
    Harness.ipSeq = (Harness.ipSeq || 0) + 1;
    this.ip = ip || '203.0.113.' + (Harness.ipSeq % 250);
    this.mail = [];
    this.env.EMAIL = {
      send: async (msg) => {
        this.mail.push(msg);
        return { messageId: 'mid-' + this.mail.length };
      },
    };
    this.jar = new Map();
    this.turnstileOk = true;
    this.turnstileAction = null; // null = echo whatever was asked for
    this.turnstileHostname = null;
    this.pending = [];
    this.installFetchStub();
  }

  installFetchStub() {
    const real = globalThis.fetch;
    this.realFetch = real;
    globalThis.fetch = async (input, init) => {
      const url = String(input && input.url ? input.url : input);
      if (url.includes('challenges.cloudflare.com/turnstile/v0/siteverify')) {
        const body = new URLSearchParams(init.body ? String(init.body) : '');
        const token = body.get('response');
        // A token of 'BAD' always fails, mirroring a rejected challenge.
        const ok = this.turnstileOk && token && token !== 'BAD';
        return new Response(
          JSON.stringify({
            success: ok,
            action: this.turnstileAction || (token || '').split(':')[1] || 'login',
            hostname: this.turnstileHostname || (token || '').split(':')[2] || 'ptra.dev',
            'error-codes': ok ? [] : ['invalid-input-response'],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      throw new Error('unexpected outbound fetch to ' + url);
    };
  }

  restore() {
    globalThis.fetch = this.realFetch;
  }

  cookieHeader(host) {
    const jar = this.jar.get(host);
    if (!jar || jar.size === 0) return undefined;
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  absorbCookies(host, response) {
    const raw = response.headers.getSetCookie
      ? response.headers.getSetCookie()
      : [response.headers.get('Set-Cookie')].filter(Boolean);
    if (!raw.length) return;
    if (!this.jar.has(host)) this.jar.set(host, new Map());
    const jar = this.jar.get(host);
    for (const line of raw) {
      const [pair, ...attrs] = line.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).trim();
      const value = decodeURIComponent(pair.slice(idx + 1).trim());
      const maxAge = attrs.find((a) => a.trim().toLowerCase().startsWith('max-age='));
      if (maxAge && Number(maxAge.split('=')[1]) === 0) jar.delete(name);
      else jar.set(name, value);
    }
  }

  /** Issue a request through the worker. `form` sends a urlencoded POST. */
  async req(url, { method = 'GET', form, country = 'IL', headers = {}, cookies = true } = {}) {
    const target = new URL(url);
    const host = target.hostname;
    const init = { method, headers: { ...headers } };

    if (form) {
      init.method = 'POST';
      const body = new URLSearchParams(form);
      init.body = body.toString();
      init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      if (!('Origin' in init.headers) && init.headers.Origin !== null) {
        init.headers.Origin = target.origin;
      }
    }
    if (init.headers.Origin === null) delete init.headers.Origin;

    if (cookies) {
      const cookie = this.cookieHeader(host);
      if (cookie) init.headers.Cookie = cookie;
    }
    if (!('CF-Connecting-IP' in init.headers)) init.headers['CF-Connecting-IP'] = this.ip;

    const request = new Request(target.toString(), init);
    Object.defineProperty(request, 'cf', {
      value: { country, colo: 'TLV', asn: 1234 },
      configurable: true,
    });

    const exec = { waitUntil: (p) => this.pending.push(Promise.resolve(p).catch(() => {})) };
    const response = await worker.fetch(request, this.env, exec);
    this.absorbCookies(host, response);
    await Promise.all(this.pending.splice(0));
    return response;
  }

  /** The first CSRF token on the page. */
  static csrf(body) {
    const m = body.match(/name="_csrf" value="([^"]+)"/);
    return m ? m[1] : null;
  }

  /**
   * The CSRF token belonging to the form that posts to `action`. Pages carry
   * several forms and each token is bound to its own form name, so picking
   * the first one only works by accident.
   */
  static csrfFor(body, action) {
    const idx = body.indexOf('action="' + action + '"');
    if (idx < 0) return null;
    const m = body.slice(idx).match(/name="_csrf" value="([^"]+)"/);
    return m ? m[1] : null;
  }

  lastCode() {
    const last = this.mail[this.mail.length - 1];
    if (!last) return null;
    const m = String(last.text).match(/\b(\d{4,10})\b/);
    return m ? m[1] : null;
  }

  /** Complete a full sign-in on the hub and leave the session in the jar. */
  async signIn(email, { host = 'ptra.dev' } = {}) {
    const page = await this.req(`https://${host}/login`);
    const body = await page.text();
    const token = Harness.csrf(body);
    const begin = await this.req(`https://${host}/login`, {
      form: { _csrf: token, email, next: '/admin', 'cf-turnstile-response': `t:login:${host}` },
    });
    if (begin.status !== 303) {
      return { ok: false, status: begin.status, body: await begin.text() };
    }
    const verifyPage = await this.req(`https://${host}/login/verify`);
    const verifyBody = await verifyPage.text();
    const vToken = Harness.csrf(verifyBody);
    const code = this.lastCode();
    const done = await this.req(`https://${host}/login/verify`, {
      form: { _csrf: vToken, code, 'cf-turnstile-response': `t:otp:${host}` },
    });
    return { ok: done.status === 303, status: done.status, location: done.headers.get('Location'), code };
  }
}
