/**
 * redirect.js - resolving a shortcut and sending the visitor on.
 *
 * Lookup is case-insensitive (A === a) because the stored key is the
 * lowercased path. A link may redirect immediately with a configurable status
 * code, or hold the visitor on an interstitial for a configured number of
 * seconds first.
 */

import { bumpClicks, getLink, isExpired, isServable } from './links.js';
import { adminUrl, interstitialPage, landingPage, messagePage } from './views.js';
import { harden } from './security.js';
import { html } from './views.js';

/** Decode a URL path into the lowercase lookup key, or null when unusable. */
export function lookupKey(pathname) {
  let raw = String(pathname || '');
  raw = raw.replace(/^\/+/, '').replace(/\/+$/, '');
  if (!raw) return '';
  let decoded;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  if (decoded.includes('\u0000') || /[\r\n]/.test(decoded)) return null;
  if (decoded.length > 255) return null;
  return decoded.toLowerCase();
}

/**
 * Merge the incoming query string into the destination when the link opts in.
 * Parameters already on the destination win, so a link's own settings are not
 * overridden by a visitor-supplied value.
 */
export function applyQuery(target, incoming) {
  if (!incoming || incoming === '?') return target;
  let url;
  try {
    url = new URL(target);
  } catch {
    return target; // opaque scheme such as mailto: - nothing to merge into
  }
  const extra = new URLSearchParams(incoming.startsWith('?') ? incoming.slice(1) : incoming);
  for (const [key, value] of extra) {
    if (!url.searchParams.has(key)) url.searchParams.append(key, value);
  }
  return url.toString();
}

/** Build the final redirect response. */
export function redirectResponse(target, status) {
  const res = new Response(null, {
    status,
    headers: {
      Location: target,
      // Permanent redirects are cacheable; temporary ones must not be, so a
      // changed destination takes effect at once.
      'Cache-Control':
        status === 301 || status === 308 ? 'public, max-age=300' : 'no-store, max-age=0',
      'Referrer-Policy': 'no-referrer',
    },
  });
  return harden(res, { store: status === 301 || status === 308 });
}

/** Serve the host root. */
export async function handleRoot(ctx) {
  const { cfg, domain, host } = ctx;
  if (domain.rootRedirect) {
    return redirectResponse(domain.rootRedirect, domain.defaultStatus || 302);
  }
  return html(landingPage({ cfg, host, signedIn: !!ctx.session }));
}

/** Resolve and serve a shortcut. */
export async function handleRedirect(ctx) {
  const { cfg, domain, host, url } = ctx;

  const key = lookupKey(url.pathname);
  if (key === null) return notFound(ctx);
  if (key === '') return handleRoot(ctx);

  // The hot path tolerates a short edge cache; admin views read fresh.
  const link = await getLink(cfg, host, key, { fresh: false });
  if (!link) return notFound(ctx);

  if (!isServable(link)) {
    return gone(ctx, isExpired(link) ? 'This link has expired.' : 'This link is disabled.');
  }

  const target = link.forwardQuery ? applyQuery(link.target, url.search) : link.target;
  const status = link.status || domain.defaultStatus || 302;
  const delay = Number.isFinite(link.delay) ? link.delay : domain.defaultDelay || 0;

  if (cfg.settings.countClicks !== false) {
    ctx.waitUntil(bumpClicks(cfg, host, key));
  }

  if (delay > 0) {
    return html(interstitialPage({ cfg, host, link, target, delay }));
  }
  return redirectResponse(target, status);
}

function notFound(ctx) {
  const { cfg, domain, host } = ctx;
  if (domain.notFoundUrl) return redirectResponse(domain.notFoundUrl, 302);
  const page = messagePage({
    cfg,
    host,
    title: 'Not found',
    heading: 'Link not found',
    message: 'That shortcut does not exist on this domain.',
    status: 404,
    actions: ctx.session ? [{ href: adminUrl(cfg, host), label: 'Open admin' }] : [],
  });
  return html(page.body, { status: 404 });
}

function gone(ctx, message) {
  const { cfg, host } = ctx;
  const page = messagePage({
    cfg,
    host,
    title: 'Unavailable',
    heading: 'Link unavailable',
    message,
    status: 410,
  });
  return html(page.body, { status: 410 });
}
