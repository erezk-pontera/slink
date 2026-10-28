/**
 * A simulated authenticator, built on Node's own crypto.
 *
 * It produces genuine signatures over genuine authenticator data, so the
 * verification layer is exercised for real rather than against fixtures.
 * It can also be asked to misbehave - a stale counter, a missing presence
 * flag, the wrong ceremony type - which is how the refusals are tested.
 */
import { webcrypto, createHash } from 'node:crypto';

const te = new TextEncoder();
export const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const sha = (bytes) => new Uint8Array(createHash('sha256').update(Buffer.from(bytes)).digest());

export function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/* A CBOR encoder, only as much of one as an authenticator needs. */
function head(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
  return new Uint8Array([(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);
}

export function cbor(value) {
  if (value instanceof Uint8Array) return cat(head(2, value.length), value);
  if (typeof value === 'string') {
    const bytes = te.encode(value);
    return cat(head(3, bytes.length), bytes);
  }
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (Array.isArray(value)) return cat(head(4, value.length), ...value.map(cbor));
  if (value instanceof Map) {
    const parts = [];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return cat(head(5, value.size), ...parts);
  }
  throw new Error('cannot encode ' + typeof value);
}

/** A raw r‖s pair as the DER a real authenticator actually sends. */
function rawToDer(raw) {
  const trim = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    return v[0] & 0x80 ? cat(new Uint8Array([0]), v) : v;
  };
  const r = trim(raw.subarray(0, 32));
  const s = trim(raw.subarray(32));
  const body = cat(new Uint8Array([2, r.length]), r, new Uint8Array([2, s.length]), s);
  return cat(new Uint8Array([0x30, body.length]), body);
}

export async function makeAuthenticator({ alg = -7, rpId = 'ptra.dev', idBytes = 32 } = {}) {
  const pair =
    alg === -7
      ? await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      : await webcrypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          },
          true,
          ['sign', 'verify']
        );
  const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const credentialId = new Uint8Array(idBytes);
  // getRandomValues takes at most 65536 bytes, and a credential id is far
  // smaller than that, but fill it in chunks so the cap is never the issue.
  for (let at = 0; at < idBytes; at += 1024) {
    webcrypto.getRandomValues(credentialId.subarray(at, Math.min(at + 1024, idBytes)));
  }
  const cose =
    alg === -7
      ? new Map([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, Buffer.from(jwk.x, 'base64url')],
          [-3, Buffer.from(jwk.y, 'base64url')],
        ])
      : new Map([
          [1, 3],
          [3, -257],
          [-1, Buffer.from(jwk.n, 'base64url')],
          [-2, Buffer.from(jwk.e, 'base64url')],
        ]);

  let counter = 0;
  const authData = (withCred, flags, atCount) => {
    const n = atCount === undefined ? ++counter : atCount;
    const base = cat(
      sha(te.encode(rpId)),
      new Uint8Array([flags]),
      new Uint8Array([(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255])
    );
    if (!withCred) return base;
    return cat(
      base,
      new Uint8Array(16),
      new Uint8Array([credentialId.length >> 8, credentialId.length & 255]),
      credentialId,
      cbor(cose)
    );
  };

  return {
    alg,
    rpId,
    credentialId,
    id: b64u(credentialId),

    /** The two fields a registration posts back, base64url as the browser sends them. */
    register({ challenge, origin, flags = 0x45 }) {
      const clientDataJSON = te.encode(
        JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false })
      );
      const attestationObject = cbor(
        new Map([
          ['fmt', 'none'],
          ['attStmt', new Map()],
          ['authData', authData(true, flags)],
        ])
      );
      return { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) };
    },

    /** The four fields an assertion posts back, likewise base64url. */
    async assert({ challenge, origin, flags = 0x05, type = 'webauthn.get', count } = {}) {
      const clientDataJSON = te.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
      const ad = authData(false, flags, count);
      const signed = cat(ad, sha(clientDataJSON));
      const params = alg === -7 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' };
      let signature = new Uint8Array(await webcrypto.subtle.sign(params, pair.privateKey, signed));
      if (alg === -7) signature = rawToDer(signature);
      return {
        id: b64u(credentialId),
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(ad),
        signature: b64u(signature),
      };
    },
  };
}
