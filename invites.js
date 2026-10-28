/**
 * invites.js - which email domains may be handed something.
 *
 * Three places name a person who is not you: transferring a link,
 * transferring a directory, and granting someone access to a directory.
 * This module decides whether that person's address is acceptable.
 *
 * The baseline is always "someone who could sign in to this host anyway",
 * because handing a link to an address that can never authenticate only
 * strands it. A host may widen or pin that:
 *
 *   off      the baseline alone; nothing below may widen it
 *   optional the configured list applies, and a directory may narrow it
 *   locked   the configured list applies and a directory may not change it
 */

import { authDomainsFor } from './domains.js';
import { domainAllowed } from './paths.js';

export const INVITE_MODES = ['off', 'optional', 'locked'];

export function defaultInvitePolicy(overrides = {}) {
  return { mode: 'off', domains: [], ...overrides };
}

export function normalizeInvitePolicy(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    mode: INVITE_MODES.includes(p.mode) ? p.mode : 'off',
    domains: Array.isArray(p.domains)
      ? p.domains.map((d) => String(d).trim().toLowerCase()).filter(Boolean)
      : [],
  };
}

/** Normalise a directory's narrowed list. */
/**
 * A directory's narrowed list, from either a stored array or the comma or
 * whitespace separated text a form submits. An empty list is null, meaning
 * "no narrowing", which is not the same as "nobody".
 */
export function normalizeInviteDomains(raw) {
  const parts = Array.isArray(raw)
    ? raw
    : typeof raw === 'string'
      ? raw.split(/[\s,;]+/)
      : null;
  if (!parts) return null;
  const out = [];
  for (const part of parts) {
    const value = String(part).trim().toLowerCase().replace(/^@/, '');
    if (value && !out.includes(value)) out.push(value);
  }
  return out.length ? out : null;
}

/**
 * The allow-list in force for a host, and optionally a directory within it.
 * A directory may only ever remove entries, never add them.
 */
export function inviteDomainsFor(cfg, domain, dir) {
  const policy = normalizeInvitePolicy(domain && domain.invitePolicy);
  const baseline = authDomainsFor(cfg, domain) || [];

  if (policy.mode === 'off') return baseline;
  const base = policy.domains.length ? policy.domains : baseline;
  if (policy.mode === 'locked') return base;

  const narrowed = normalizeInviteDomains(dir && dir.inviteDomains);
  if (!narrowed) return base;
  // Keep only the entries the host already permits.
  const kept = narrowed.filter((entry) => domainAllowed(entry.replace(/^\*\./, ''), base));
  return kept.length ? kept : base;
}

/** May a directory set its own narrowed list? */
export function directoryMayNarrowInvites(domain) {
  return normalizeInvitePolicy(domain && domain.invitePolicy).mode === 'optional';
}

/**
 * Check one address. Returns { allowed, reason, domains } so a caller can
 * tell the person what the list actually is rather than just refusing.
 */
export function inviteAllowed(cfg, { domain, dir, emailNorm }) {
  const domains = inviteDomainsFor(cfg, domain, dir);
  const at = String(emailNorm || '').lastIndexOf('@');
  const emailDomain = at > -1 ? emailNorm.slice(at + 1) : '';
  if (!emailDomain) return { allowed: false, reason: 'That is not a valid address.', domains };
  if (domainAllowed(emailDomain, domains)) return { allowed: true, reason: null, domains };
  return {
    allowed: false,
    reason:
      'Addresses at ' +
      emailDomain +
      ' cannot be given access here. Permitted: ' +
      (domains.length ? domains.join(', ') : 'none'),
    domains,
  };
}

/** A sentence for the admin screens. */
export function describeInvitePolicy(cfg, domain) {
  const policy = normalizeInvitePolicy(domain && domain.invitePolicy);
  const effective = inviteDomainsFor(cfg, domain, null);
  const list = effective.length ? effective.join(', ') : 'none';
  if (policy.mode === 'off') return `Anyone who may sign in here: ${list}.`;
  if (policy.mode === 'locked') return `${list}, and directories may not change it.`;
  return `${list}, and a directory may narrow it.`;
}
