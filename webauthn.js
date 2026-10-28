/**
 * webauthn.js - verifying what an authenticator sends back.
 *
 * Registration uses attestation `none`: the attestation statement is not
 * checked, which is the right default for a relying party that does not
 * care which make of key someone owns. The authenticator data inside it is
 * still parsed and checked, because that is where the credential and its
 * public key come from.
 *
 * Only ES256 and RS256 are accepted. They cover every passkey in practice,
 * and both are verifiable with WebCrypto alone.
 */

import { decode } from './cbor.js';
import { b64urlDecode, b64urlEncode, te } from './util.js';

export class WebAuthnError extends Error {}

/** COSE algorithm identifiers, in the order they are offered. */
export const ES256 = -7;
export const RS256 = -257;
export const ALGORITHMS = [ES256, RS256];

/** Authenticator data flags. */
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;

function fail(message) {
  throw new WebAuthnError(message);
}

/** Compare two byte arrays without leaking where they differ. */
function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Parse authenticator data.
 *
 * Layout: 32 bytes of RP ID hash, one flag byte, a four-byte counter, and
 * — only when the attested-data flag is set — the credential and its key.
 */
export function parseAuthData(bytes) {
  if (!bytes || bytes.length < 37) fail('authenticator data is too short');
  const rpIdHash = bytes.subarray(0, 32);
  const flags = bytes[32];
  const signCount = (bytes[33] << 24) >>> 0 | (bytes[34] << 16) | (bytes[35] << 8) | bytes[36];

  const out = {
    rpIdHash,
    flags,
    signCount: signCount >>> 0,
    userPresent: (flags & FLAG_USER_PRESENT) !== 0,
    userVerified: (flags & FLAG_USER_VERIFIED) !== 0,
    credentialId: null,
    coseKey: null,
  };

  if ((flags & FLAG_ATTESTED_DATA) === 0) return out;
  if (bytes.length < 55) fail('attested credential data is truncated');
  const idLength = (bytes[53] << 8) | bytes[54];
  if (idLength === 0 || idLength > 1023) fail('credential id length is implausible');
  if (bytes.length < 55 + idLength) fail('credential id is truncated');

  out.credentialId = new Uint8Array(bytes.subarray(55, 55 + idLength));
  // Whatever follows is the COSE key; CBOR tells us where it ends, and
  // anything after that would be extensions we do not read.
  out.coseKey = new Uint8Array(bytes.subarray(55 + idLength));
  return out;
}

/**
 * Turn a COSE public key into a JWK and the WebCrypto parameters that go
 * with it. Refuses anything that is not one of the two accepted algorithms.
 */
export function coseToKey(coseBytes) {
  let map;
  try {
    map = decode(coseBytes);
  } catch (err) {
    fail('the public key is not readable: ' + err.message);
  }
  if (!(map instanceof Map)) fail('the public key is not a CBOR map');

  const kty = map.get(1);
  const alg = map.get(3);

  if (kty === 2) {
    if (alg !== ES256) fail('unsupported elliptic-curve algorithm');
    if (map.get(-1) !== 1) fail('only the P-256 curve is accepted');
    const x = map.get(-2);
    const y = map.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) fail('malformed EC public key');
    if (x.length !== 32 || y.length !== 32) fail('EC coordinates are the wrong size');
    return {
      alg: ES256,
      jwk: { kty: 'EC', crv: 'P-256', x: b64urlEncode(x), y: b64urlEncode(y), ext: true },
      importParams: { name: 'ECDSA', namedCurve: 'P-256' },
      verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
    };
  }

  if (kty === 3) {
    if (alg !== RS256) fail('unsupported RSA algorithm');
    const n = map.get(-1);
    const e = map.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) fail('malformed RSA public key');
    if (n.length < 256) fail('the RSA key is too small');
    return {
      alg: RS256,
      jwk: { kty: 'RSA', n: b64urlEncode(n), e: b64urlEncode(e), ext: true },
      importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
    };
  }

  fail('unsupported key type');
}

/**
 * ECDSA signatures arrive DER-encoded; WebCrypto wants the raw r‖s pair.
 * Each value is left-padded or stripped to exactly 32 bytes.
 */
export function derToRaw(der) {
  if (!der || der.length < 8 || der[0] !== 0x30) fail('malformed ECDSA signature');
  let at = 2;
  // A long-form length means the sequence is longer than anything here.
  if (der[1] & 0x80) fail('malformed ECDSA signature');
  const readInt = () => {
    if (der[at] !== 0x02) fail('malformed ECDSA signature');
    const len = der[at + 1];
    at += 2;
    if (len === 0 || at + len > der.length) fail('malformed ECDSA signature');
    let value = der.subarray(at, at + len);
    at += len;
    // Strip the leading zero a positive DER integer carries, then pad.
    while (value.length > 32 && value[0] === 0) value = value.subarray(1);
    if (value.length > 32) fail('ECDSA signature component is too large');
    const out = new Uint8Array(32);
    out.set(value, 32 - value.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

/** Read and check the clientDataJSON the browser produced. */
export async function checkClientData(bytes, { type, challenge, origin }) {
  let data;
  try {
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    fail('client data is not readable');
  }
  if (data.type !== type) fail('client data is for the wrong ceremony');
  // The challenge is compared as text, both sides base64url, so an
  // authenticator that re-encodes it differently cannot slip through.
  if (typeof data.challenge !== 'string' || data.challenge !== challenge) {
    fail('the challenge does not match');
  }
  if (data.origin !== origin) fail('the origin does not match');
  // Keep it: a cross-origin ceremony is not something this ever asks for.
  if (data.crossOrigin === true) fail('a cross-origin ceremony is not accepted');
  return data;
}

/**
 * Finish a registration. Returns the credential to store.
 *
 * `requireUserVerification` is off by default: a passkey on a laptop may be
 * presence-only, and refusing it would turn a working key away.
 */
export async function verifyRegistration({
  attestationObject,
  clientDataJSON,
  challenge,
  origin,
  rpId,
  requireUserVerification = false,
}) {
  await checkClientData(clientDataJSON, { type: 'webauthn.create', challenge, origin });

  let attestation;
  try {
    attestation = decode(attestationObject);
  } catch (err) {
    fail('the attestation object is not readable: ' + err.message);
  }
  if (!(attestation instanceof Map)) fail('the attestation object is not a CBOR map');
  const authDataBytes = attestation.get('authData');
  if (!(authDataBytes instanceof Uint8Array)) fail('the attestation has no authenticator data');

  const auth = parseAuthData(authDataBytes);
  if (!sameBytes(auth.rpIdHash, await sha256(te.encode(rpId)))) fail('this key is for another site');
  if (!auth.userPresent) fail('the authenticator did not report the user was present');
  if (requireUserVerification && !auth.userVerified) fail('this key did not verify the user');
  if (!auth.credentialId || !auth.coseKey) fail('the attestation carries no credential');

  const key = coseToKey(auth.coseKey);
  // Imported here as well as at sign-in, so a key WebCrypto cannot use is
  // refused while registering rather than at the moment someone needs it.
  await crypto.subtle.importKey('jwk', key.jwk, key.importParams, false, ['verify']);

  return {
    credentialId: b64urlEncode(auth.credentialId),
    publicKey: key.jwk,
    alg: key.alg,
    signCount: auth.signCount,
    userVerified: auth.userVerified,
  };
}

/**
 * Check an assertion against a stored credential.
 *
 * Returns { ok, signCount, userVerified, cloneWarning }. A counter that
 * fails to advance is reported rather than fatal: plenty of authenticators
 * keep no counter at all and send zero every time, so refusing on it would
 * lock out working keys, while a counter that goes backwards on a key that
 * does keep one is worth recording.
 */
export async function verifyAssertion({
  credential,
  authenticatorData,
  clientDataJSON,
  signature,
  challenge,
  origin,
  rpId,
  requireUserVerification = false,
}) {
  await checkClientData(clientDataJSON, { type: 'webauthn.get', challenge, origin });

  const auth = parseAuthData(authenticatorData);
  if (!sameBytes(auth.rpIdHash, await sha256(te.encode(rpId)))) fail('this key is for another site');
  if (!auth.userPresent) fail('the authenticator did not report the user was present');
  if (requireUserVerification && !auth.userVerified) fail('this key did not verify the user');

  const jwk = credential.publicKey;
  const params =
    credential.alg === RS256
      ? { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' } }
      : { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' } };

  let key;
  try {
    key = await crypto.subtle.importKey('jwk', jwk, params.import, false, ['verify']);
  } catch {
    fail('the stored key cannot be used');
  }

  const signed = new Uint8Array(authenticatorData.length + 32);
  signed.set(authenticatorData, 0);
  signed.set(await sha256(clientDataJSON), authenticatorData.length);

  const sig = credential.alg === RS256 ? signature : derToRaw(signature);
  const ok = await crypto.subtle.verify(params.verify, key, sig, signed);
  if (!ok) fail('the signature did not verify');

  const stored = Number(credential.signCount) || 0;
  const cloneWarning = stored > 0 && auth.signCount > 0 && auth.signCount <= stored;
  return {
    ok: true,
    signCount: auth.signCount,
    userVerified: auth.userVerified,
    cloneWarning,
  };
}

/** Decode a base64url field a browser sent, refusing anything oversized. */
export function fromB64Url(value, { max = 64 * 1024 } = {}) {
  if (typeof value !== 'string' || !value) fail('a required field is missing');
  if (value.length > max) fail('a field is too large');
  if (!/^[A-Za-z0-9_-]+=*$/.test(value)) fail('a field is not base64url');
  try {
    return b64urlDecode(value);
  } catch {
    fail('a field is not base64url');
  }
}
