/**
 * domains.js - the set of hosts the worker serves and their per-host policy.
 *
 * Apex and www are the same host: callers pass an already-canonicalised host.
 */

import { K } from './kv.js';
import { now } from './util.js';

export const ROOT_CREATE_POLICIES = ['email_domain', 'explicit', 'open', 'admins_only'];
export const REDIRECT_STATUSES = [301, 302, 303, 307, 308];

export function newDomain(host, overrides = {}) {
  const ts = now();
  return {
    host,
    enabled: true,
    authRequired: false,
    /** Email domains permitted to authenticate on this host. */
    allowedAuthDomains: [],
    /** Email domains permitted to create links at this host's root. */
    allowedCreateDomains: [],
    rootCreatePolicy: 'email_domain',
    defaultStatus: 302,
    defaultDelay: 0,
    /** Where `/` goes; null renders the default landing page. */
    rootRedirect: null,
    /** Where an unknown shortcut goes; null renders a 404 page. */
    notFoundUrl: null,
    /** Read-only hosts can only be modified by administrators. */
    readonly: false,
    note: '',
    createdAt: ts,
    updatedAt: ts,
    ...overrides,
  };
}

export async function getDomain(cfg, host) {
  if (!host) return null;
  return cfg.store.get(K.domain(host), { fresh: false });
}

/** Fresh read for administrative views that must reflect a just-made change. */
export async function getDomainFresh(cfg, host) {
  if (!host) return null;
  return cfg.store.get(K.domain(host));
}

export async function putDomain(cfg, domain) {
  domain.updatedAt = now();
  await cfg.store.put(K.domain(domain.host), domain, {
    metadata: { enabled: !!domain.enabled, authRequired: !!domain.authRequired },
  });
  return domain;
}

export async function deleteDomain(cfg, host) {
  await cfg.store.delete(K.domain(host));
}

export async function listDomains(cfg) {
  const keys = await cfg.store.listAll(K.domainPrefix(), { max: 500 });
  const records = await cfg.store.getMany(keys.map((k) => k.name));
  return records.filter(Boolean).sort((a, b) => a.host.localeCompare(b.host));
}

/**
 * Create the configured hosts on first run so a fresh deployment is usable
 * without a manual seeding step. Existing records are never overwritten.
 */
export async function ensureBootstrapDomains(cfg) {
  const created = [];
  for (const host of cfg.knownHosts) {
    const existing = await cfg.store.get(K.domain(host));
    if (existing) continue;
    const isHub = host === cfg.hubHost;
    const domain = newDomain(host, {
      authRequired: isHub,
      allowedAuthDomains: [...cfg.defaultAllowedDomains],
      allowedCreateDomains: [...cfg.defaultAllowedDomains],
      note: isHub ? 'Administration host (created automatically).' : 'Created automatically.',
    });
    await putDomain(cfg, domain);
    created.push(host);
  }
  return created;
}

/**
 * Resolve the policy for a host, falling back to an implicit record for a
 * configured-but-unseeded host so the worker never serves an unknown policy.
 */
export async function resolveDomain(cfg, host) {
  const found = await getDomain(cfg, host);
  if (found) return found;
  if (cfg.knownHosts.includes(host)) {
    return newDomain(host, {
      authRequired: host === cfg.hubHost,
      allowedAuthDomains: [...cfg.defaultAllowedDomains],
      allowedCreateDomains: [...cfg.defaultAllowedDomains],
    });
  }
  return null;
}

/** Email domains allowed to authenticate here; falls back to the global list. */
export function authDomainsFor(cfg, domain) {
  const list = domain && domain.allowedAuthDomains && domain.allowedAuthDomains.length
    ? domain.allowedAuthDomains
    : cfg.defaultAllowedDomains;
  return list || [];
}

/** Email domains allowed to create at this host's root. */
export function createDomainsFor(cfg, domain) {
  const list = domain && domain.allowedCreateDomains && domain.allowedCreateDomains.length
    ? domain.allowedCreateDomains
    : cfg.defaultAllowedDomains;
  return list || [];
}
