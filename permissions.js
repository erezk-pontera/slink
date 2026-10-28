/**
 * permissions.js - the single place every authorisation decision is made.
 *
 * Rules implemented here:
 *   - Only the user who created a link may modify, delete or transfer it.
 *   - Administrators are never restricted.
 *   - Creating at a host root requires permission (by email domain, by
 *     explicit grant, or open), configured per host.
 *   - A directory restricts creation inside it to users granted canCreate.
 *   - A directory administrator (canManage) controls everything inside the
 *     directory, including other users' links and the directory's own grants.
 *   - Read-only links and directories are administrator-only, which overrides
 *     ownership and directory administration alike.
 */

import { getDirectory, getGrant, directoryPathSet, listUserGrants } from './directories.js';
import { createDomainsFor } from './domains.js';
import { domainAllowed, parentDirectory } from './paths.js';
import { isAdmin, isRootAdmin } from './users.js';

/**
 * Administrators reach every directory by default. An administrator may turn
 * that off for themselves or for another administrator, which scopes them to
 * the directories they hold a grant on while leaving the rest of their
 * powers intact. A root administrator's access is never removable.
 */
export function adminReachesAllDirectories(cfg, user) {
  if (!user) return false;
  if (isRootAdmin(cfg, user.emailNorm)) return true;
  if (!isAdmin(cfg, user)) return false;
  return user.allDirectories !== false;
}

export const DENY = {
  anonymous: 'You must sign in.',
  disabled: 'This account is disabled.',
  domainDisabled: 'This domain is disabled.',
  domainReadonly: 'This domain is read-only; only administrators may change it.',
  dirDisabled: 'This directory is disabled.',
  dirReadonly: 'This directory is read-only; only administrators may change it.',
  dirNoGrant: 'You do not have permission to create in this directory.',
  dirNoCreate: 'You do not have permission to create directories on this domain.',
  rootNoPermission: 'You do not have permission to create at the root of this domain.',
  linkReadonly: 'This link is read-only; only administrators may change it.',
  notOwner: 'Only the link owner, a directory administrator or an administrator may change this.',
  notDirAdmin: 'Only a directory administrator or an administrator may change this.',
  adminOnly: 'Only administrators may do this.',
};

function allow(extra = {}) {
  return { allowed: true, reason: null, ...extra };
}

function deny(reason, extra = {}) {
  return { allowed: false, reason, ...extra };
}

/** The email domain used for allow-list checks. */
export function emailDomainOf(user) {
  if (!user || !user.emailNorm) return '';
  return user.emailNorm.slice(user.emailNorm.lastIndexOf('@') + 1);
}

/**
 * Resolve the directory that governs `pathLc`, if any. Returns
 * { dir, grant } with nulls when the path sits at the host root.
 */
export async function resolveGovernor(cfg, host, pathLc, user, { dirSet } = {}) {
  const known = dirSet || (await directoryPathSet(cfg, host));
  const parentLc = parentDirectory(pathLc, known);
  if (!parentLc) return { dir: null, grant: null, parentLc: null };
  const dir = await getDirectory(cfg, host, parentLc);
  if (!dir) return { dir: null, grant: null, parentLc: null };
  const grant = user ? await getGrant(cfg, host, parentLc, user.id) : null;
  return { dir, grant, parentLc };
}

/**
 * Does an administrator act with administrator authority at this spot?
 *
 * Scoping only withdraws the blanket reach into directories. Outside any
 * directory, and inside one they hold a grant on, a scoped administrator is
 * an administrator like any other; inside one they do not, they are shut out
 * rather than demoted to an ordinary user.
 */
export function adminActsHere(cfg, user, dir, grant) {
  if (!dir) return true;
  if (adminReachesAllDirectories(cfg, user)) return true;
  return !!grant;
}

/** Does the user satisfy the host's root-level create policy? */
export function rootCreateAllowed(cfg, domain, user) {
  const policy = (domain && domain.rootCreatePolicy) || 'email_domain';
  if (policy === 'admins_only') return false;
  if (policy === 'open') return true;
  const explicit = !!(user && user.rootCreate && user.rootCreate[domain.host]);
  if (policy === 'explicit') return explicit;
  // 'email_domain': the configured allow list, or an explicit per-user grant.
  return explicit || domainAllowed(emailDomainOf(user), createDomainsFor(cfg, domain));
}

/**
 * May `user` create a link at `pathLc` on `host`?
 * Returns { allowed, reason, dir, grant }.
 */
export async function canCreate(cfg, { user, domain, host, pathLc, dirSet }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  const admin = isAdmin(cfg, user);

  if (domain && domain.enabled === false && !admin) return deny(DENY.domainDisabled);

  const { dir, grant } = await resolveGovernor(cfg, host, pathLc, user, { dirSet });
  if (admin && adminActsHere(cfg, user, dir, grant)) return allow({ dir, grant, asAdmin: true });

  if (domain && domain.readonly) return deny(DENY.domainReadonly, { dir, grant });

  if (dir) {
    if (dir.enabled === false) return deny(DENY.dirDisabled, { dir, grant });
    if (dir.readonly) return deny(DENY.dirReadonly, { dir, grant });
    if (grant && (grant.canCreate || grant.canManage)) return allow({ dir, grant });
    if (!dir.open) return deny(DENY.dirNoGrant, { dir, grant });
    // Open directories fall through to the host's root policy.
  }

  if (rootCreateAllowed(cfg, domain, user)) return allow({ dir, grant });
  return deny(DENY.rootNoPermission, { dir, grant });
}

/**
 * May `user` modify, delete or transfer `link`?
 * Ownership, directory administration and the read-only flag are all applied.
 */
export async function canManageLink(cfg, { user, link, host, dirSet }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  const admin = isAdmin(cfg, user);
  const { dir, grant } = await resolveGovernor(cfg, host || link.host, link.pathLc, user, { dirSet });
  if (admin && adminActsHere(cfg, user, dir, grant)) return allow({ asAdmin: true, dir });

  if (link.readonly) return deny(DENY.linkReadonly);
  if (link.ownerId && link.ownerId === user.id) return allow({ asOwner: true });
  if (dir && !dir.readonly && grant && grant.canManage) return allow({ asDirAdmin: true, dir, grant });

  return deny(DENY.notOwner);
}

/** May `user` change a directory's grants or its settings? */
export async function canManageDirectory(cfg, { user, dir }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  const admin = isAdmin(cfg, user);
  if (admin && adminReachesAllDirectories(cfg, user)) return allow({ asAdmin: true });
  if (!dir) return deny(admin ? DENY.notDirAdmin : DENY.notDirAdmin);
  const grant = await getGrant(cfg, dir.host, dir.pathLc, user.id);
  // A scoped administrator keeps administrator authority inside the
  // directories they were granted; what scoping removed is the blanket
  // reach into the ones they were not.
  if (admin && grant) return allow({ asAdmin: true, grant });
  if (dir.readonly) return deny(DENY.dirReadonly);
  if (grant && grant.canManage) return allow({ asDirAdmin: true, grant });
  return deny(DENY.notDirAdmin);
}

/**
 * May `user` create a directory at `pathLc`?
 *
 *   - An administrator may create one anywhere.
 *   - A directory administrator may create nested directories inside the
 *     directory they administer, and may grant that same right to others by
 *     making them a directory administrator there.
 *   - Anyone else needs an explicit per-host grant, which permits directories
 *     at that host's root.
 */
export async function canCreateDirectory(cfg, { user, domain, host, pathLc, dirSet }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  const admin = isAdmin(cfg, user);
  if (admin && adminReachesAllDirectories(cfg, user)) return allow({ asAdmin: true });

  const { dir, grant } = await resolveGovernor(cfg, host, pathLc, user, { dirSet });
  // A scoped administrator is still an administrator at the host root, which
  // is not a directory, and inside any directory they were granted.
  if (admin && (!dir || (grant && grant.canManage))) return allow({ asAdmin: true, dir });
  if (domain && domain.readonly) return deny(DENY.domainReadonly);

  if (dir) {
    // Inside a directory, only its administrator may nest another.
    if (dir.readonly) return deny(DENY.dirReadonly);
    if (grant && grant.canManage) return allow({ asDirAdmin: true, dir });
    return deny(DENY.notDirAdmin);
  }

  if (user.dirCreate && user.dirCreate[host]) return allow({ byGrant: true });
  return deny(DENY.dirNoCreate);
}

/**
 * Could `user` create a directory somewhere on `host`? Used to decide whether
 * to offer the form at all, not to authorise a particular path.
 */
export async function mayCreateAnyDirectory(cfg, { user, host }) {
  if (!user || user.disabled) return false;
  if (isAdmin(cfg, user)) return true;
  if (user.dirCreate && user.dirCreate[host]) return true;
  const grants = await listUserGrants(cfg, user.id);
  return grants.some((g) => g.host === host && g.canManage);
}

/**
 * May `user` hand this directory to a different owner? The owner may, and an
 * administrator may. A directory administrator who is not the owner may run
 * everything inside the directory but may not take the directory itself.
 * Read-only puts it in administrators' hands alone.
 */
export function canTransferDirectory(cfg, { user, dir }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  // Reassigning ownership is an administrative act in its own right, so it
  // stays available to every administrator regardless of read-only marks or
  // whether their directory access has been scoped.
  if (isAdmin(cfg, user)) return allow({ asAdmin: true });
  if (!dir) return deny(DENY.notDirAdmin);
  if (dir.readonly) return deny(DENY.dirReadonly);
  if (dir.ownerId && dir.ownerId === user.id) return allow({ asOwner: true });
  return deny('Only the directory owner or an administrator may change its owner.');
}

/**
 * Fields only an administrator may set. Read-only is deliberately here: it is
 * the flag that protects a link from its own owner, so a directory
 * administrator must not be able to clear it.
 */
export function canSetReadonly(cfg, user) {
  return isAdmin(cfg, user);
}

/** Administrator-only surfaces: domains, users, global settings, audit. */
export function requireAdmin(cfg, user) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  return isAdmin(cfg, user) ? allow({ asAdmin: true }) : deny(DENY.adminOnly);
}

/**
 * May `user` hand this link to someone else? Administrators always may, for
 * the same reason as directories: ownership is an administrative matter, not
 * a content one. Everyone else needs the ordinary management right.
 */
export async function canTransferLink(cfg, args) {
  const { user } = args;
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  if (isAdmin(cfg, user)) return allow({ asAdmin: true });
  return canManageLink(cfg, args);
}

/**
 * A transfer must leave the link with an owner who could have created it
 * there. Administrators may override, so that a link can be parked on a user
 * whose permissions were later narrowed.
 */
export async function canReceiveTransfer(cfg, { actor, recipient, domain, host, pathLc, dirSet }) {
  if (!recipient) return deny('Recipient not found.');
  if (recipient.disabled) return deny('That account is disabled.');
  if (isAdmin(cfg, actor)) return allow({ asAdmin: true });
  return canCreate(cfg, { user: recipient, domain, host, pathLc, dirSet });
}
