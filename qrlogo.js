/**
 * qrlogo.js - the image a QR code can carry in its centre.
 *
 * Only raster formats are accepted, and only after sniffing the bytes
 * rather than trusting the declared type or the file name. The reason is
 * narrow and important: the code is an SVG, and the image is inlined into
 * it. An uploaded SVG is a document, not a picture - it can carry script,
 * styles and remote references - so letting one in would mean serving
 * attacker-chosen markup from this origin. A PNG cannot do that.
 *
 * The result is stored on the link record as a data URI, which keeps the
 * code a pure function of the link and needs no second fetch when it is
 * rendered.
 */

import { b64urlEncode } from './util.js';

/**
 * The largest image accepted. A centre mark is a few hundred pixels
 * square; anything beyond this is a photograph that would be unreadable at
 * that size anyway, and every byte of it is carried in the link record and
 * in every rendering of the code.
 */
export const MAX_LOGO_BYTES = 128 * 1024;

/**
 * Formats, by their leading bytes. SVG is deliberately absent: see above.
 * A sniffed type is also what gets written into the data URI, so a file
 * renamed to .png cannot smuggle a different type through.
 */
const SIGNATURES = [
  { type: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
  { type: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] },
  { type: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] },
];

function startsWith(bytes, signature) {
  if (bytes.length < signature.length) return false;
  for (let i = 0; i < signature.length; i++) if (bytes[i] !== signature[i]) return false;
  return true;
}

/** RIFF....WEBP, which needs two checks rather than one prefix. */
function isWebp(bytes) {
  if (bytes.length < 12) return false;
  const tag = (at, text) => {
    for (let i = 0; i < text.length; i++) if (bytes[at + i] !== text.charCodeAt(i)) return false;
    return true;
  };
  return tag(0, 'RIFF') && tag(8, 'WEBP');
}

/** The media type these bytes actually are, or '' for anything else. */
export function sniffImage(bytes) {
  if (!(bytes instanceof Uint8Array)) return '';
  for (const sig of SIGNATURES) if (startsWith(bytes, sig.bytes)) return sig.type;
  if (isWebp(bytes)) return 'image/webp';
  return '';
}

/**
 * Standard base64, which a data URI wants, from the url-safe encoder.
 * The padding the url-safe form strips has to go back on.
 */
function toBase64(bytes) {
  const body = b64urlEncode(bytes).replace(/-/g, '+').replace(/_/g, '/');
  return body + '='.repeat((4 - (body.length % 4)) % 4);
}

/**
 * Validate uploaded bytes and turn them into what the record stores.
 * Returns { ok, logo } or { ok: false, error }.
 */
export function makeLogo(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    return { ok: false, error: 'No image was uploaded.' };
  }
  if (bytes.length > MAX_LOGO_BYTES) {
    return {
      ok: false,
      error: `That image is ${Math.ceil(bytes.length / 1024)} KB. The limit is ${MAX_LOGO_BYTES / 1024} KB.`,
    };
  }
  const type = sniffImage(bytes);
  if (!type) {
    return {
      ok: false,
      error: 'That is not a PNG, JPEG, GIF or WebP. An SVG is a document rather than a picture and is not accepted.',
    };
  }
  return { ok: true, logo: { type, data: toBase64(bytes), bytes: bytes.length } };
}

/** Is there a usable uploaded image on this record? */
export function hasLogo(link) {
  const l = link && link.qrLogo;
  return !!(l && typeof l === 'object' && typeof l.data === 'string' && l.data && l.type);
}

/** The data URI for a stored image, or '' when there is none. */
export function logoDataUri(link) {
  if (!hasLogo(link)) return '';
  const { type, data } = link.qrLogo;
  // Re-checked on the way out as well as on the way in: a record could have
  // been written by an older version, or edited by hand.
  if (!/^image\/(png|jpeg|gif|webp)$/.test(type)) return '';
  if (!/^[A-Za-z0-9+/]+=*$/.test(data)) return '';
  return 'data:' + type + ';base64,' + data;
}

/**
 * The uploaded image as a fragment for the 512-unit box qr.js nests a logo
 * into. `preserveAspectRatio` keeps a non-square image from stretching.
 */
export function logoImageFragment(link) {
  const uri = logoDataUri(link);
  if (!uri) return '';
  return `<image href="${uri}" x="0" y="0" width="512" height="512" preserveAspectRatio="xMidYMid meet"/>`;
}
