/**
 * cbor.js - just enough CBOR to read what an authenticator sends.
 *
 * WebAuthn encodes the attestation object and the COSE public key inside it
 * as CBOR (RFC 8949). Only the subset those structures use is implemented:
 * unsigned and negative integers, byte strings, text strings, arrays, maps,
 * and the three simple values. Indefinite-length items, tags, floats and
 * big numbers are refused rather than guessed at — an authenticator does
 * not send them here, and quietly mis-reading one would be worse than
 * failing.
 */

export class CborError extends Error {}

/**
 * Decode one CBOR item. Returns { value, end } so a caller can tell whether
 * trailing bytes were left over.
 */
export function decodeFirst(bytes) {
  if (!bytes) throw new CborError('no CBOR to decode');
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (view.length === 0) throw new CborError('no CBOR to decode');
  const out = read(view, 0, 0);
  return { value: out.value, end: out.at };
}

/** Decode exactly one item, refusing anything left over. */
export function decode(bytes) {
  const { value, end } = decodeFirst(bytes);
  const len = (bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).length;
  if (end !== len) throw new CborError('trailing bytes after the CBOR item');
  return value;
}

/** Nesting deep enough for anything real, shallow enough to stop a bomb. */
const MAX_DEPTH = 16;

function need(bytes, at, count) {
  if (at + count > bytes.length) throw new CborError('truncated CBOR');
}

/** Read the argument that follows a major type's initial byte. */
function readArg(bytes, at, info) {
  if (info < 24) return { value: info, at };
  if (info === 24) {
    need(bytes, at, 1);
    return { value: bytes[at], at: at + 1 };
  }
  if (info === 25) {
    need(bytes, at, 2);
    return { value: (bytes[at] << 8) | bytes[at + 1], at: at + 2 };
  }
  if (info === 26) {
    need(bytes, at, 4);
    const v = ((bytes[at] << 24) >>> 0) + (bytes[at + 1] << 16) + (bytes[at + 2] << 8) + bytes[at + 3];
    return { value: v, at: at + 4 };
  }
  if (info === 27) {
    need(bytes, at, 8);
    // Read as a BigInt and refuse anything a Number cannot hold exactly,
    // rather than silently losing precision on a length.
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[at + i]);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('CBOR integer too large');
    return { value: Number(v), at: at + 8 };
  }
  throw new CborError('unsupported CBOR argument ' + info);
}

function read(bytes, at, depth) {
  if (depth > MAX_DEPTH) throw new CborError('CBOR nested too deeply');
  need(bytes, at, 1);
  const initial = bytes[at];
  const major = initial >> 5;
  const info = initial & 0x1f;
  if (info === 31) throw new CborError('indefinite-length CBOR is not supported');
  // Major 7 carries simple values and floats in the same slot. Only the
  // three simple values are wanted, so reject the rest before reading an
  // argument, which would otherwise report a float as a bad integer.
  if (major === 7 && info > 22) throw new CborError('unsupported CBOR simple value ' + info);
  const arg = readArg(bytes, at + 1, info);
  let cursor = arg.at;

  switch (major) {
    case 0:
      return { value: arg.value, at: cursor };
    case 1:
      return { value: -1 - arg.value, at: cursor };
    case 2: {
      need(bytes, cursor, arg.value);
      const slice = bytes.subarray(cursor, cursor + arg.value);
      return { value: new Uint8Array(slice), at: cursor + arg.value };
    }
    case 3: {
      need(bytes, cursor, arg.value);
      const slice = bytes.subarray(cursor, cursor + arg.value);
      return { value: new TextDecoder().decode(slice), at: cursor + arg.value };
    }
    case 4: {
      const items = [];
      for (let i = 0; i < arg.value; i++) {
        const item = read(bytes, cursor, depth + 1);
        items.push(item.value);
        cursor = item.at;
      }
      return { value: items, at: cursor };
    }
    case 5: {
      // A Map, not an object: COSE keys are negative integers, and an
      // object would turn them into strings and lose the distinction
      // between -1 and "-1".
      const map = new Map();
      for (let i = 0; i < arg.value; i++) {
        const k = read(bytes, cursor, depth + 1);
        const v = read(bytes, k.at, depth + 1);
        if (map.has(k.value)) throw new CborError('duplicate key in a CBOR map');
        map.set(k.value, v.value);
        cursor = v.at;
      }
      return { value: map, at: cursor };
    }
    case 7:
      if (info === 20) return { value: false, at: cursor };
      if (info === 21) return { value: true, at: cursor };
      if (info === 22) return { value: null, at: cursor };
      throw new CborError('unsupported CBOR simple value ' + info);
    default:
      throw new CborError('unsupported CBOR major type ' + major);
  }
}
