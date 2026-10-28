/**
 * dirmissing.js - a directory's own MISSING destination.
 *
 * Browsing `ptra.cc/eng` with no shortcut after it, or a shortcut under it
 * that does not exist, falls through to the domain's MISSING destination. A
 * directory can carry its own instead, so a team's directory can land on the
 * team's page rather than the company default.
 *
 * The shape is the one used for the countdown policy: a domain-level mode,
 * narrowed by the directory, with a per-directory escape hatch that only a
 * Shrink Link administrator can grant.
 */

export const MISSING_MODES = ['off', 'optional', 'locked'];

/** The domain-level default: each directory decides for itself. */
export function defaultMissingPolicy(overrides = {}) {
  return { mode: 'optional', target: '', ...overrides };
}

export function normalizeMissingPolicy(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  return {
    mode: MISSING_MODES.includes(p.mode) ? p.mode : 'optional',
    target: typeof p.target === 'string' ? p.target : '',
  };
}

/**
 * May this directory's own MISSING be edited here? An administrator may
 * exempt one directory from a domain that says otherwise, which is what
 * `dir.missingExempt` records.
 */
export function directoryMaySetMissing(domain, dir) {
  if (dir && dir.missingExempt) return true;
  return normalizeMissingPolicy(domain && domain.dirMissingPolicy).mode === 'optional';
}

/**
 * The MISSING destination that applies inside `dir`, or '' when the domain's
 * own should be used. `source` says which setting won, for the admin screens.
 */
export function resolveMissing(domain, dir) {
  const policy = normalizeMissingPolicy(domain && domain.dirMissingPolicy);
  const own = dir && typeof dir.missingUrl === 'string' ? dir.missingUrl.trim() : '';
  const exempt = !!(dir && dir.missingExempt);

  // A locked domain wins over every directory that has not been exempted.
  if (policy.mode === 'locked' && !exempt) {
    return policy.target ? { target: policy.target, source: 'domain' } : { target: '', source: '' };
  }
  if (own && (exempt || policy.mode !== 'off')) return { target: own, source: 'dir' };
  if (policy.mode !== 'off' && policy.target) return { target: policy.target, source: 'domain' };
  return { target: '', source: '' };
}

/** A sentence for the directory screen explaining where it stands. */
export function describeMissingPolicy(domain) {
  const policy = normalizeMissingPolicy(domain && domain.dirMissingPolicy);
  if (policy.mode === 'off') {
    return 'This domain does not let directories set their own MISSING destination. An administrator can exempt a directory.';
  }
  if (policy.mode === 'locked') {
    return policy.target
      ? 'This domain sends every directory to ' + policy.target + '. An administrator can exempt a directory.'
      : 'This domain locks directory MISSING destinations to its own, which is not set.';
  }
  return 'Each directory may set its own MISSING destination.';
}
