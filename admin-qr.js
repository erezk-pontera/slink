/**
 * admin-qr.js - QR codes for short links.
 *
 * The code is generated on the fly and served as SVG, so it scales to any
 * size without a second request and needs no storage. Everything about it is
 * in the query string, which makes a particular code a shareable URL.
 *
 * A centre logo is damage the error correction has to absorb, so asking for
 * one raises the correction level and, on a small symbol, the version too.
 * The limits in LOGO_MIN_VERSION were measured by decoding rendered output,
 * not taken from the nominal recovery rates, which are per codeword rather
 * than per area and are optimistic about concentrated damage.
 */

import { back, denied } from './admin.js';
import { LOGO_SVG } from './logo.js';
import { parsePath } from './paths.js';
import { harden } from './security.js';
import { ECC_LEVELS, toSvg } from './qr.js';

export const QR_SIZES = [128, 256, 512, 1024, 2048];
export const DEFAULT_SIZE = 512;

/** Side of the symbol a logo may cover, and what that costs. */
export const LOGO_SCALES = [0.15, 0.2, 0.25];
export const DEFAULT_LOGO_SCALE = 0.2;

/** A logo always forces at least this much error correction. */
export const LOGO_MIN_LEVEL = 'H';

/**
 * The smallest version that still decodes with a logo of a given side.
 *
 * Measured, not derived: rendered output was decoded across every level and
 * a range of versions, twice over, once by rasterising the matrix directly
 * and once by rendering the real SVG in a browser. Both agreed that at level
 * H a logo covering a quarter of the side decodes from version 1, and three
 * tenths from version 5. The floors below sit a few versions above that,
 * because a decoder reading clean synthetic pixels has an easier time than a
 * camera pointed at a printed sticker.
 */
export function minVersionForLogo(scale) {
  if (scale > 0.22) return 7;
  if (scale > 0.17) return 5;
  return 3;
}

/** The brand mark with its document wrapper removed, ready to nest. */
export function logoFragment() {
  return LOGO_SVG.replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '');
}

function clampSize(raw) {
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return DEFAULT_SIZE;
  return Math.max(64, Math.min(2048, n));
}

/** Read the options a request is asking for, each clamped to something sane. */
export function qrOptions(params) {
  const rawLevel = String(params.get('ecc') || '').toUpperCase();
  const wantLogo = params.get('logo') === '1';
  const rawScale = Number.parseFloat(params.get('logoscale'));
  const logoScale = Number.isFinite(rawScale)
    ? Math.max(0.1, Math.min(0.25, rawScale))
    : DEFAULT_LOGO_SCALE;

  // An explicit level is honoured unless a logo needs more than it offers.
  let level = ECC_LEVELS.includes(rawLevel) ? rawLevel : 'M';
  if (wantLogo && ECC_LEVELS.indexOf(level) < ECC_LEVELS.indexOf(LOGO_MIN_LEVEL)) {
    level = LOGO_MIN_LEVEL;
  }

  return {
    size: clampSize(params.get('size')),
    margin: Math.max(0, Math.min(8, Number.parseInt(params.get('margin'), 10) || 4)),
    level,
    logo: wantLogo ? logoFragment() : null,
    logoScale,
    minVersion: wantLogo ? minVersionForLogo(logoScale) : 1,
  };
}

/**
 * Serve the QR code for a short link.
 *
 * The content encoded is the short link itself, which the caller supplies,
 * so this reveals nothing it was not already given. It is still behind the
 * hub's sign-in gate, and refuses a host the installation does not serve.
 */
export async function qrSvg(ctx) {
  const params = ctx.url.searchParams;
  const host = String(params.get('host') || '').toLowerCase();
  if (!ctx.cfg.knownHosts.includes(host)) return back('/admin/links', 'notfound');

  let parsed;
  try {
    parsed = parsePath(params.get('path'), { allowReserved: true });
  } catch {
    return back('/admin/links', 'notfound');
  }

  const target = 'https://' + host + '/' + parsed.path;
  const opts = qrOptions(params);
  let svg;
  try {
    svg = toSvg(target, { ...opts, label: target });
  } catch (err) {
    return denied(ctx, err && err.message ? err.message : 'That will not fit in a QR code.');
  }

  const response = harden(
    new Response(svg, {
      headers: {
        'Content-Type': 'image/svg+xml; charset=utf-8',
        'Content-Disposition': `inline; filename="${parsed.pathLc.replace(/\//g, '-')}.svg"`,
        // The code is a pure function of the query string, so it caches well,
        // but it is private to the signed-in viewer.
        'Cache-Control': 'private, max-age=3600',
      },
    }),
    { store: true }
  );
  // An SVG is active content when a browser navigates straight to it, so
  // this one keeps the inert policy rather than the ordinary page one.
  response.headers.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
  return response;
}
