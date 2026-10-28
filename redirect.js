/**
 * redirect.js - resolving a shortcut and sending the visitor on.
 *
 * Lookup is case-insensitive (A === a) because the stored key is the
 * lowercased path. A link may redirect immediately with a configurable status
 * code, or hold the visitor on an interstitial for a configured number of
 * seconds first.
 */

import { getDirectory, governingDirectory } from './directories.js';
import { resolveMissing } from './dirmissing.js';
import { GO_PARAM, needsExemption, policyFor, resolveLink, userExemption } from './interstitial.js';
import { bumpClicks, getLink, isExpired, isPending, isServable } from './links.js';
import { isCrawler, previewAllowed, previewPage } from './preview.js';
import { deviceClass, resolveTarget } from './targets.js';
import { getUserById } from './users.js';
import { harden } from './security.js';
import { adminUrl, html, interstitialPage, landingPage, messagePage } from './views.js';

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

/** Drop our own continue flag so it is never forwarded to a destination. */
export function stripGoParam(search) {
  if (!search) return '';
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  params.delete(GO_PARAM);
  const out = params.toString();
  return out ? '?' + out : '';
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
  // A destination must not learn which shortcut sent the visitor.
  return harden(res, { store: status === 301 || status === 308, referrerPolicy: 'no-referrer' });
}

/**
 * Where to send someone when there is nothing to show: the per-domain
 * override if the administrator set one, otherwise the global MISSING URL.
 */
export function fallbackFor(ctx, kind, dir = null) {
  const { cfg, domain } = ctx;
  // A directory's own MISSING is the most specific answer there is, so it
  // comes before the domain's and before the global one.
  if (dir) {
    const own = resolveMissing(domain, dir).target;
    if (own) return own;
  }
  const perDomain = kind === 'root' ? domain.rootRedirect : domain.notFoundUrl;
  return perDomain || cfg.missingUrl || '';
}

/**
 * The directory a missing path belongs to: the path itself when it names a
 * directory root, otherwise the directory that governs it. Only consulted on
 * the miss path, so an ordinary redirect pays nothing for it.
 */
async function missingDirectory(cfg, host, pathLc) {
  if (!pathLc) return null;
  const self = await getDirectory(cfg, host, pathLc);
  if (self) return self;
  return governingDirectory(cfg, host, pathLc);
}

/**
 * Serve the host root. This runs before the sign-in gate: a root is a public
 * signpost, so it redirects rather than asking anyone to authenticate.
 */
export async function handleRoot(ctx) {
  const { cfg, host } = ctx;
  const target = fallbackFor(ctx, 'root');
  if (target) return redirectResponse(target, 302);
  return html(landingPage({ cfg, host }));
}

/** Resolve and serve a shortcut. */
export async function handleRedirect(ctx) {
  const { cfg, domain, host, url } = ctx;

  const key = lookupKey(url.pathname);
  if (key === null) return notFound(ctx);
  if (key === '') return handleRoot(ctx);

  // The hot path tolerates a short edge cache; admin views read fresh.
  const link = await getLink(cfg, host, key, { fresh: false });
  if (!link) return notFound(ctx, await missingDirectory(cfg, host, key));

  if (!isServable(link)) {
    return gone(
      ctx,
      isExpired(link)
        ? 'This link has expired.'
        : isPending(link)
          ? 'This link is not active yet.'
          : 'This link is disabled.',
      await missingDirectory(cfg, host, key)
    );
  }


  // The countdown is governed by the domain, narrowed by any directory that
  // owns the path, and finally by the link itself where that is permitted.
  const dir = await governingDirectory(cfg, host, key);
  const policy = policyFor(domain, dir);

  // The owner's exemptions are only consulted when the stored link actually
  // depends on one, so an ordinary redirect costs no extra reads. Resolving
  // against the owner rather than a snapshot means withdrawing an exemption
  // takes effect immediately.
  let exempt;
  if (needsExemption(policy, link) && link.ownerId) {
    const owner = await getUserById(cfg, link.ownerId);
    if (owner && !owner.disabled) exempt = userExemption(owner, host);
  }
  const behaviour = resolveLink(policy, link, exempt);

  const incoming = stripGoParam(url.search);
  // Which destination this particular visitor gets: their device first, then
  // any country rule inside that slot, falling back to the default.
  const chosen = resolveTarget(link, {
    device: deviceClass(ctx.request),
    country: (ctx.request.cf && ctx.request.cf.country) || '',
  }).url;
  const target = link.forwardQuery ? applyQuery(chosen, incoming) : chosen;
  const status = link.status || domain.defaultStatus || 302;
  const skip = url.searchParams.get(GO_PARAM) === '1';

  // Count the arrival, not the continue, so a hidden-destination link that
  // comes back through us a second time is not counted twice.
  if (cfg.settings.countClicks !== false && !skip) {
    ctx.waitUntil(bumpClicks(cfg, host, key));
  }

  // A crawler that would unfurl this link is served the card instead of a
  // redirect, and never a countdown page.
  if (previewAllowed(domain, link) && isCrawler(ctx.request)) {
    return html(previewPage(cfg, { host, link, url: target }), { store: true });
  }

  if (behaviour.show && !skip) {
    // When the destination is hidden it must not appear in the page at all,
    // so the page points back at us and we answer with the real redirect.
    const continueHref =
      '/' + link.path + (incoming ? incoming + '&' : '?') + GO_PARAM + '=1';
    return html(
      interstitialPage({
        cfg,
        host,
        link,
        target,
        delay: behaviour.delay,
        showTarget: behaviour.showTarget,
        continueHref,
      })
    );
  }
  return redirectResponse(target, status);
}

function notFound(ctx, dir = null) {
  const { cfg, host } = ctx;
  const target = fallbackFor(ctx, 'missing', dir);
  if (target) return redirectResponse(target, 302);
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

function gone(ctx, message, dir = null) {
  const { cfg, host } = ctx;
  // A disabled or expired shortcut is "nothing to show" too, so it lands in
  // the same place as an unknown one rather than on a dead end.
  const target = fallbackFor(ctx, 'missing', dir);
  if (target) return redirectResponse(target, 302);
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
