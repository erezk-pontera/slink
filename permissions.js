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

import { getDirectory, getGrant, directoryPathSet } from './directories.js';
import { createDomainsFor } from './domains.js';
import { domainAllowed, parentDirectory } from './paths.js';
import { isAdmin } from './users.js';

export const DENY = {
  anonymous: 'You must sign in.',
  disabled: 'This account is disabled.',
  domainDisabled: 'This domain is disabled.',
  domainReadonly: 'This domain is read-only; only administrators may change it.',
  dirDisabled: 'This directory is disabled.',
  dirReadonly: 'This directory is read-only; only administrators may change it.',
  dirNoGrant: 'You do not have permission to create in this directory.',
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
  if (admin) return allow({ dir, grant, asAdmin: true });

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
  if (admin) return allow({ asAdmin: true });

  if (link.readonly) return deny(DENY.linkReadonly);
  if (link.ownerId && link.ownerId === user.id) return allow({ asOwner: true });

  const { dir, grant } = await resolveGovernor(cfg, host || link.host, link.pathLc, user, { dirSet });
  if (dir && !dir.readonly && grant && grant.canManage) return allow({ asDirAdmin: true, dir, grant });

  return deny(DENY.notOwner);
}

/** May `user` change a directory's grants or its settings? */
export async function canManageDirectory(cfg, { user, dir }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  if (isAdmin(cfg, user)) return allow({ asAdmin: true });
  if (!dir) return deny(DENY.notDirAdmin);
  if (dir.readonly) return deny(DENY.dirReadonly);
  const grant = await getGrant(cfg, dir.host, dir.pathLc, user.id);
  if (grant && grant.canManage) return allow({ asDirAdmin: true, grant });
  return deny(DENY.notDirAdmin);
}

/**
 * May `user` create a directory at `pathLc`? Administrators may create
 * anywhere; a directory administrator may create nested directories inside
 * the directory they administer.
 */
export async function canCreateDirectory(cfg, { user, domain, host, pathLc, dirSet }) {
  if (!user) return deny(DENY.anonymous);
  if (user.disabled) return deny(DENY.disabled);
  if (isAdmin(cfg, user)) return allow({ asAdmin: true });
  if (domain && domain.readonly) return deny(DENY.domainReadonly);
  const { dir, grant } = await resolveGovernor(cfg, host, pathLc, user, { dirSet });
  if (dir && !dir.readonly && grant && grant.canManage) return allow({ asDirAdmin: true, dir });
  return deny(DENY.adminOnly);
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
