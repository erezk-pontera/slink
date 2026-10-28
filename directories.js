/**
 * directories.js - directories (for example ptra.cc/pub) and the per-user
 * grants that control them.
 *
 * A directory owns every path beneath it. Two privileges exist:
 *   canCreate - may create links inside the directory
 *   canManage - directory administrator: may edit, delete and transfer every
 *               link inside the directory regardless of owner, and may add or
 *               remove other users' grants.
 */

import { K } from './kv.js';
import { now } from './util.js';

export function newDirectory(host, path, pathLc, overrides = {}) {
  const ts = now();
  return {
    host,
    path,
    pathLc,
    ownerId: null,
    ownerEmail: null,
    /** Open directories inherit the host's root create policy. */
    open: false,
    /** Read-only directories can only be changed by administrators. */
    readonly: false,
    enabled: true,
    note: '',
    /** Narrows the host's invite domains for this directory. null leaves
     *  the host's list alone; only meaningful where the host delegates.
     *  See invites.js. */
    inviteDomains: null,
    /** Where to send someone who browses this directory's root, or a
     *  shortcut under it that does not exist. Empty uses the domain's
     *  MISSING destination. See dirmissing.js. */
    missingUrl: '',
    /** Set by a Shrink Link administrator only: lets this directory set its
     *  own MISSING even where the domain says otherwise. */
    missingExempt: false,
    /** Countdown override, used only when the domain delegates or an
     *  administrator enabled it on this directory. See interstitial.js. */
    interstitial: null,
    allowInterstitialOverride: false,
    /** Per-setting escape hatches from the domain policy, granted by a
     *  Shrink Link administrator only. See interstitial.js. */
    interstitialExempt: { countdown: false, destination: false, minDelay: false },
    createdAt: ts,
    updatedAt: ts,
    ...overrides,
  };
}

export function newGrant(host, dirPathLc, user, overrides = {}) {
  return {
    host,
    dirPathLc,
    userId: user.id,
    userEmail: user.emailNorm,
    canCreate: true,
    canManage: false,
    grantedBy: null,
    createdAt: now(),
    ...overrides,
  };
}

export async function getDirectory(cfg, host, pathLc) {
  if (!pathLc) return null;
  return cfg.store.get(K.dir(host, pathLc));
}

export async function putDirectory(cfg, dir) {
  dir.updatedAt = now();
  await cfg.store.put(K.dir(dir.host, dir.pathLc), dir, {
    metadata: { path: dir.path, readonly: !!dir.readonly, open: !!dir.open },
  });
  return dir;
}

export async function deleteDirectory(cfg, dir) {
  // Remove every grant on the directory alongside the record itself.
  const grantKeys = await cfg.store.listAll(K.grantPrefix(dir.host, dir.pathLc), { max: 1000 });
  for (const key of grantKeys) {
    const grant = await cfg.store.get(key.name);
    if (grant) await cfg.store.delete(K.userGrant(grant.userId, dir.host, dir.pathLc));
    await cfg.store.delete(key.name);
  }
  await cfg.store.delete(K.dir(dir.host, dir.pathLc));
}

export async function listDirectories(cfg, host, { max = 1000 } = {}) {
  const keys = await cfg.store.listAll(K.dirPrefix(host, ''), { max });
  const records = await cfg.store.getMany(keys.map((k) => k.name));
  return records.filter(Boolean).sort((a, b) => a.pathLc.localeCompare(b.pathLc));
}

/** The set of directory paths on a host, for parent resolution. */
export async function directoryPathSet(cfg, host) {
  const keys = await cfg.store.listAll(K.dirPrefix(host, ''), { max: 2000 });
  const prefix = K.dirPrefix(host, '');
  return new Set(keys.map((k) => k.name.slice(prefix.length)));
}

/* ------------------------------------------------------------------- grants */

export async function getGrant(cfg, host, dirPathLc, userId) {
  if (!userId || !dirPathLc) return null;
  return cfg.store.get(K.grant(host, dirPathLc, userId));
}

export async function putGrant(cfg, grant) {
  await cfg.store.put(K.grant(grant.host, grant.dirPathLc, grant.userId), grant, {
    metadata: {
      email: grant.userEmail,
      canCreate: !!grant.canCreate,
      canManage: !!grant.canManage,
    },
  });
  await cfg.store.put(K.userGrant(grant.userId, grant.host, grant.dirPathLc), {
    host: grant.host,
    dirPathLc: grant.dirPathLc,
    canCreate: !!grant.canCreate,
    canManage: !!grant.canManage,
  });
  return grant;
}

export async function deleteGrant(cfg, host, dirPathLc, userId) {
  await cfg.store.delete(K.grant(host, dirPathLc, userId));
  await cfg.store.delete(K.userGrant(userId, host, dirPathLc));
}

export async function listGrants(cfg, host, dirPathLc) {
  const keys = await cfg.store.listAll(K.grantPrefix(host, dirPathLc), { max: 1000 });
  const records = await cfg.store.getMany(keys.map((k) => k.name));
  return records.filter(Boolean).sort((a, b) => a.userEmail.localeCompare(b.userEmail));
}

/** Every directory grant held by a user, across hosts. */
export async function listUserGrants(cfg, userId) {
  const prefix = K.userGrantPrefix(userId);
  const keys = await cfg.store.listAll(prefix, { max: 1000 });
  const records = await cfg.store.getMany(keys.map((k) => k.name));
  return records.filter(Boolean);
}

/** Directories on `host` in which the user may create. */
export async function creatableDirectories(cfg, host, userId) {
  const grants = await listUserGrants(cfg, userId);
  return grants
    .filter((g) => g.host === host && (g.canCreate || g.canManage))
    .map((g) => g.dirPathLc)
    .sort();
}

/**
 * The directory that governs `pathLc`, found by probing its ancestors from
 * the longest down. A root-level path costs no reads and a path one level
 * deep costs one, which is why the redirect path uses this rather than
 * listing every directory on the host.
 */
export async function governingDirectory(cfg, host, pathLc) {
  const segments = String(pathLc || '').split('/');
  for (let i = segments.length - 1; i >= 1; i--) {
    const candidate = segments.slice(0, i).join('/');
    const dir = await cfg.store.get(K.dir(host, candidate), { fresh: false });
    if (dir) return dir;
  }
  return null;
}
