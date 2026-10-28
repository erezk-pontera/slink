/**
 * users.js - user records, keyed by normalised email.
 *
 * The normalised address is the identity: with IGNORE_EMAIL_DOT and
 * IGNORE_EMAIL_PLUS enabled, `a.a+tag@cc.com` and `aa@cc.com` are one account.
 */

import { K } from './kv.js';
import { normalizeEmail, tryNormalizeEmail } from './paths.js';
import { now, randomId } from './util.js';

export function newUser(email, emailNorm, overrides = {}) {
  const ts = now();
  return {
    id: randomId(12),
    email,
    emailNorm,
    isAdmin: false,
    disabled: false,
    /** Administrators only: false scopes them to directories they are
     *  granted on. Never applies to a root administrator. */
    allDirectories: true,
    note: '',
    /** Per-host explicit permission to create links at the root. */
    rootCreate: {},
    /** Per-host explicit permission to create directories at the root. */
    dirCreate: {},
    /** Countdown-policy exemptions, keyed by host or '*' for every host. */
    interstitialExempt: {},
    /** Per-host capability rulings an administrator recorded against this
     *  person, keyed by host or '*'. See capabilities.js. */
    capabilities: {},
    createdAt: ts,
    updatedAt: ts,
    lastLoginAt: 0,
    loginCount: 0,
    /** Created by an invite rather than by signing in. The account holds
     *  whatever it was given but has never authenticated. */
    invitedBy: null,
    ...overrides,
  };
}

export async function getUserByNorm(cfg, emailNorm) {
  if (!emailNorm) return null;
  return cfg.store.get(K.user(emailNorm));
}

export async function getUserById(cfg, userId) {
  if (!userId) return null;
  const emailNorm = await cfg.store.get(K.userId(userId));
  if (!emailNorm) return null;
  return getUserByNorm(cfg, emailNorm);
}

export async function putUser(cfg, user) {
  user.updatedAt = now();
  await cfg.store.put(K.user(user.emailNorm), user, {
    metadata: { id: user.id, isAdmin: !!user.isAdmin, disabled: !!user.disabled },
  });
  await cfg.store.put(K.userId(user.id), user.emailNorm);
  return user;
}

/**
 * The account for an invited address, created if it does not exist yet.
 *
 * Without this an invite can only ever name someone who has already signed
 * in, which makes an invite-domain list that reaches beyond the sign-in
 * domains silently inert. Creating the account grants nothing on its own:
 * the person still has to authenticate, and `mayAuthenticate` decides that
 * separately. It only lets a link or a grant be put in their name first.
 */
export async function inviteUser(cfg, { email, emailNorm, invitedBy }) {
  const existing = await getUserByNorm(cfg, emailNorm);
  if (existing) return { user: existing, created: false };
  const user = newUser(email || emailNorm, emailNorm, {
    invitedBy: invitedBy ? invitedBy.emailNorm || invitedBy.email || null : null,
  });
  await putUser(cfg, user);
  return { user, created: true };
}

export async function deleteUser(cfg, user) {
  await cfg.store.delete(K.user(user.emailNorm));
  await cfg.store.delete(K.userId(user.id));
}

export async function listUsers(cfg, { max = 2000 } = {}) {
  const keys = await cfg.store.listAll(K.userPrefix(), { max });
  const records = await cfg.store.getMany(keys.map((k) => k.name));
  return records.filter(Boolean).sort((a, b) => a.emailNorm.localeCompare(b.emailNorm));
}

/** Find an existing account or create one on first successful sign-in. */
export async function findOrCreateUser(cfg, rawEmail) {
  const { email, emailNorm } = normalizeEmail(rawEmail, cfg.emailOpts);
  const existing = await getUserByNorm(cfg, emailNorm);
  if (existing) return { user: existing, created: false };
  const user = newUser(email, emailNorm);
  await putUser(cfg, user);
  return { user, created: true };
}

/**
 * Is this address a root administrator? Root admins come from the ADMIN
 * environment variable, cannot be demoted through the UI, and are compared
 * after the same normalisation as every other address.
 */
export function isRootAdmin(cfg, emailNorm) {
  if (!emailNorm) return false;
  for (const raw of cfg.rootAdmins) {
    const parsed = tryNormalizeEmail(raw, cfg.emailOpts);
    if (parsed && parsed.emailNorm === emailNorm) return true;
  }
  return false;
}

/** Root admins are implicitly admins; the stored flag grants the rest. */
export function isAdmin(cfg, user) {
  if (!user) return false;
  return isRootAdmin(cfg, user.emailNorm) || !!user.isAdmin;
}
