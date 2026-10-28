/**
 * preview.js - link unfurling cards.
 *
 * When something like Slack or Twitter fetches a short link it follows the
 * redirect and reads the destination's own tags, which is usually what you
 * want. A link can instead carry its own card, and then a crawler is served
 * that card rather than a redirect.
 *
 * Only public domains get cards. On a domain that requires sign-in, a
 * crawler cannot authenticate and would be bounced anyway, and emitting a
 * title and description for an internal link would publish exactly what the
 * sign-in requirement exists to protect.
 */

import { esc } from './util.js';

/**
 * User agents that unfurl links. This list decides who sees a card instead
 * of a redirect, so it errs towards well-known crawlers: anything unmatched
 * simply gets the normal redirect, which is the safe default.
 */
const CRAWLER_RE = new RegExp(
  [
    'twitterbot',
    'facebookexternalhit',
    'facebot',
    'slackbot',
    'slack-imgproxy',
    'discordbot',
    'linkedinbot',
    'whatsapp',
    'telegrambot',
    'skypeuripreview',
    'applebot',
    'googlebot',
    'bingbot',
    'redditbot',
    'pinterest',
    'vkshare',
    'embedly',
    'iframely',
    'mastodon',
    'bluesky',
    'bsky',
    'opengraph',
    'preview',
    'unfurl',
  ].join('|'),
  'i'
);

export function isCrawler(request) {
  const ua = request.headers.get('User-Agent') || '';
  if (!ua) return false;
  return CRAWLER_RE.test(ua);
}

/** An empty card. */
export function emptyPreview() {
  return { enabled: false, title: '', description: '', image: '' };
}

export function normalizePreview(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    enabled: !!p.enabled,
    title: String(p.title || '').slice(0, 120),
    description: String(p.description || '').slice(0, 300),
    image: String(p.image || '').slice(0, 1024),
  };
}

/**
 * May this link show a card? Public domain, switched on, and carrying at
 * least a title - a card with nothing in it is worse than none, because the
 * crawler would stop at an empty page instead of reading the destination.
 */
export function previewAllowed(domain, link) {
  if (!domain || domain.authRequired) return false;
  const p = normalizePreview(link && link.preview);
  return p.enabled && !!p.title;
}

/** Why a card cannot be shown, for the editor. */
export function previewBlockedReason(domain) {
  if (domain && domain.authRequired) {
    return 'This domain requires sign-in, so its links never show a preview card. A crawler cannot sign in, and publishing a title for an internal link would defeat the point.';
  }
  return '';
}

/**
 * The card itself. A crawler reads the meta tags; a person who somehow lands
 * here gets a plain page with a link, and no automatic redirect, so that a
 * crawler is never bounced on to the destination.
 */
export function previewPage(cfg, { host, link, url }) {
  const p = normalizePreview(link.preview);
  const canonical = 'https://' + host + '/' + link.path;
  const image = /^https:\/\//i.test(p.image) ? p.image : '';

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.title)}</title>
<link rel="canonical" href="${esc(canonical)}">
<meta name="description" content="${esc(p.description)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="${esc(cfg.appName)}">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:title" content="${esc(p.title)}">
<meta property="og:description" content="${esc(p.description)}">
${image ? `<meta property="og:image" content="${esc(image)}">` : ''}
<meta name="twitter:card" content="${image ? 'summary_large_image' : 'summary'}">
<meta name="twitter:title" content="${esc(p.title)}">
<meta name="twitter:description" content="${esc(p.description)}">
${image ? `<meta name="twitter:image" content="${esc(image)}">` : ''}
</head><body>
<h1>${esc(p.title)}</h1>
${p.description ? `<p>${esc(p.description)}</p>` : ''}
<p><a href="${esc(url)}" rel="nofollow noreferrer">Continue</a></p>
</body></html>`;
}

/** How the card will look, rendered into the editor. */
export function previewCard(host, link, preview) {
  const p = normalizePreview(preview);
  const image = /^https:\/\//i.test(p.image) ? p.image : '';
  return `<div class="ogcard">
  ${
    image
      ? `<div class="ogimg"><img src="${esc(image)}" alt="" loading="lazy"></div>`
      : '<div class="ogimg ogimg-none">No image</div>'
  }
  <div class="ogbody">
    <div class="oghost">${esc(host)}</div>
    <div class="ogtitle">${esc(p.title || 'Untitled')}</div>
    <div class="ogdesc">${esc(p.description || 'No description.')}</div>
  </div>
</div>`;
}
