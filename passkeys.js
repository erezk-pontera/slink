/**
 * passkeys.js - registering and signing in with a passkey.
 *
 * A passkey never replaces the emailed code outright: the code is always
 * there to fall back to, so losing a device is an inconvenience rather than
 * a lockout. Where a host has switched the code off, an administrator still
 * keeps it, which is the same rule single sign-on follows.
 *
 * The relying-party id is the hub host. A credential is therefore usable on
 * the hub, and the other hosts reach it through the existing handshake,
 * rather than every host holding its own set of keys.
 */

import { K } from './kv.js';
import { methodsFor } from './oauth.js';
import { signToken, verifyToken } from './security.js';
import { b64urlEncode, now, randomId } from './util.js';

/** How long a registration or sign-in challenge stays good for. */
export const CHALLENGE_TTL_SECONDS = 300;

/** Passkeys one account may hold. */
export const MAX_PASSKEYS = 20;

export const MAX_NAME = 60;

export const CHALLENGE_PURPOSE = 'passkey-challenge';

/** The relying-party id every credential here is bound to. */
export function rpId(cfg) {
  return cfg.hubHost;
}

/** A fresh challenge, signed rather than stored: it is single use by expiry. */
export async function mintChallenge(cfg, { kind, userId = null }) {
  const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const iat = Math.floor(Date.now() / 1000);
  const token = await signToken(cfg.authSecret, CHALLENGE_PURPOSE, {
    c: challenge,
    k: kind,
    u: userId,
    iat,
    exp: iat + CHALLENGE_TTL_SECONDS,
  });
  return { challenge, token };
}

/** Recover a challenge from its token, or null when it is not usable. */
export async function openChallenge(cfg, token, { kind, userId = null }) {
  const payload = await verifyToken(cfg.authSecret, CHALLENGE_PURPOSE, token, {
    maxAgeSeconds: CHALLENGE_TTL_SECONDS,
  });
  if (!payload || payload.k !== kind) return null;
  // A registration challenge is tied to the account that asked for it, so
  // one cannot be carried across to another session.
  if (userId !== null && payload.u !== userId) return null;
  return payload.c;
}

/* ------------------------------------------------------------- storage */

export function newPasskey(user, { credentialId, publicKey, alg, signCount, name }) {
  const ts = now();
  return {
    id: randomId(10),
    userId: user.id,
    userEmail: user.emailNorm,
    credentialId,
    publicKey,
    alg,
    signCount: signCount || 0,
    name: String(name || '').slice(0, MAX_NAME) || 'Passkey',
    createdAt: ts,
    lastUsedAt: 0,
    useCount: 0,
    /** Set when a counter went backwards: worth a look, not a block. */
    cloneWarning: false,
  };
}

export async function putPasskey(cfg, key) {
  await cfg.store.put(K.passkey(key.credentialId), key);
  await cfg.store.put(K.userPasskey(key.userId, key.id), key.credentialId);
  return key;
}

export async function getPasskey(cfg, credentialId) {
  if (!credentialId || typeof credentialId !== 'string' || credentialId.length > 1400) return null;
  return cfg.store.get(K.passkey(credentialId));
}

export async function listPasskeys(cfg, userId) {
  const prefix = K.userPasskeyPrefix(userId);
  const keys = await cfg.store.listAll(prefix, { max: MAX_PASSKEYS * 2 });
  const ids = await cfg.store.getMany(keys.map((k) => k.name));
  const records = await cfg.store.getMany(
    ids.filter(Boolean).map((credentialId) => K.passkey(credentialId))
  );
  return records.filter(Boolean).sort((a, b) => a.createdAt - b.createdAt);
}

export async function deletePasskey(cfg, key) {
  await cfg.store.delete(K.passkey(key.credentialId));
  await cfg.store.delete(K.userPasskey(key.userId, key.id));
}

/** Remove every passkey an account holds, when the account goes. */
export async function deleteAllPasskeys(cfg, userId) {
  for (const key of await listPasskeys(cfg, userId)) await deletePasskey(cfg, key);
}

/* -------------------------------------------------------------- policy */

/**
 * Is a passkey usable for signing in here?
 *
 * A host may switch passkeys off the same way it may switch off the emailed
 * code, and on the same condition: only where single sign-on is configured,
 * so a host can never be left with no way in. An administrator keeps every
 * method regardless, so a policy mistake cannot lock out the people who
 * would undo it.
 */
export function passkeysEnabled(cfg, domain, { isAdmin = false } = {}) {
  return methodsFor(cfg, domain, { isAdmin }).passkey;
}
