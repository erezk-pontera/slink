/**
 * impersonate.js - administrators viewing the hub as another person.
 *
 * The hard requirement is that impersonation is per tab: one tab stays the
 * administrator's own session while others view the hub as different people.
 * Cookies cannot do that, because every tab of a browser sends the same ones.
 * So the impersonated identity lives in the URL instead: an impersonated page
 * sits under `/admin/as/<token>/…`, and the token is a signed statement that
 * this administrator asked to view the hub as that user.
 *
 * Nothing is stored. The administrator's own session cookie still authorises
 * the request, so closing the tab ends the impersonation, signing out ends
 * every impersonation at once, and a token lifted from a URL is useless to
 * anyone whose cookie does not match the session it was minted against.
 */

import { isAdmin, isRootAdmin } from './users.js';
import { signToken, verifyToken } from './security.js';
import { getUserById } from './users.js';
import { esc } from './util.js';

export const IMP_PURPOSE = 'impersonate';
export const IMP_BASE = '/admin/as/';

/** How long an impersonation URL stays usable before it has to be reopened. */
export const IMP_TTL_SECONDS = 3600;

/**
 * A link the rewriter must leave alone so it can point back out of the
 * impersonated namespace. It cannot collide with page content, because every
 * value interpolated into markup goes through `esc`.
 */
export const EXIT_HREF = '#__slink_exit__';

export const IMP_DENY = {
  notAdmin: 'Only an administrator may view the hub as someone else.',
  nested: 'You are already viewing the hub as someone else.',
  self: 'You are already signed in as that person.',
  missing: 'That person does not have an account yet.',
  disabled: 'That account is disabled.',
  root: 'A root administrator cannot be impersonated.',
  admin: 'Only a root administrator may impersonate another administrator.',
  expired: 'That impersonation has expired. Start it again from the people list.',
};

/**
 * May `actor` view the hub as `target`? Impersonation must never be a way to
 * gain something, so it only ever reaches down: a root administrator is off
 * limits to everyone, and an ordinary administrator cannot borrow another
 * administrator's reach.
 */
export function canImpersonate(cfg, { actor, target, impersonating = false }) {
  if (!actor || !isAdmin(cfg, actor)) return { allowed: false, reason: IMP_DENY.notAdmin };
  if (impersonating) return { allowed: false, reason: IMP_DENY.nested };
  if (!target) return { allowed: false, reason: IMP_DENY.missing };
  if (target.disabled) return { allowed: false, reason: IMP_DENY.disabled };
  if (target.id === actor.id) return { allowed: false, reason: IMP_DENY.self };
  if (isRootAdmin(cfg, target.emailNorm)) return { allowed: false, reason: IMP_DENY.root };
  if (isAdmin(cfg, target) && !isRootAdmin(cfg, actor.emailNorm)) {
    return { allowed: false, reason: IMP_DENY.admin };
  }
  return { allowed: true };
}

/**
 * Mint the URL that opens an impersonated view. The token names the session
 * it was issued against, so it only works from the browser that asked for it.
 */
export async function mintImpersonation(cfg, { session, target }) {
  const iat = Math.floor(Date.now() / 1000);
  const token = await signToken(cfg.authSecret, IMP_PURPOSE, {
    u: target.id,
    s: session.sidHash,
    iat,
    exp: iat + IMP_TTL_SECONDS,
  });
  return IMP_BASE + encodeURIComponent(token);
}

/**
 * Split `/admin/as/<token>/rest` into its parts. Returns null for any path
 * that is not an impersonated one, including a bare `/admin/as`.
 */
export function splitImpersonation(path) {
  if (!path.startsWith(IMP_BASE)) return null;
  const rest = path.slice(IMP_BASE.length);
  if (!rest) return null;
  const slash = rest.indexOf('/');
  const raw = slash === -1 ? rest : rest.slice(0, slash);
  if (!raw) return null;
  let token;
  try {
    token = decodeURIComponent(raw);
  } catch {
    return null;
  }
  const tail = slash === -1 ? '' : rest.slice(slash);
  return { token, prefix: IMP_BASE + raw, path: '/admin' + tail };
}

/**
 * Resolve an impersonation token against the live session. Both the signature
 * and the session binding have to hold, so a URL shared with someone else
 * resolves to nothing in their browser.
 */
export async function openImpersonation(cfg, { token, session }) {
  const payload = await verifyToken(cfg.authSecret, IMP_PURPOSE, token, {
    maxAgeSeconds: IMP_TTL_SECONDS,
  });
  if (!payload || payload.s !== session.sidHash) return null;
  const target = await getUserById(cfg, payload.u);
  const permit = canImpersonate(cfg, { actor: session.user, target });
  if (!permit.allowed) return null;
  return target;
}

/**
 * Keep an impersonated page inside its own namespace. Every hub link and form
 * in our markup is an absolute path, and every interpolated value is escaped,
 * so rewriting the `/admin` and `/logout` ones covers the page exactly.
 */
export function withPrefix(markup, prefix) {
  return markup
    .replace(/(href|action)="\/admin(?=["/?])/g, (_m, attr) => attr + '="' + prefix)
    .replace(new RegExp('href="' + EXIT_HREF + '"', 'g'), 'href="/admin"');
}

/** Strip the sentinel from a page that is not being impersonated. */
export function withoutPrefix(markup) {
  return markup.replace(new RegExp('href="' + EXIT_HREF + '"', 'g'), 'href="/admin"');
}

/** The standing reminder that what you are looking at is not your own view. */
export function impersonationNotice(ctx) {
  if (!ctx.impersonator) return '';
  const who = ctx.session.user.emailNorm || ctx.session.user.email || 'this person';
  const by = ctx.impersonator.emailNorm || ctx.impersonator.email || 'an administrator';
  return `<div class="impbar" role="status">
  <span>Viewing as <strong>${esc(who)}</strong> &mdash; signed in as ${esc(by)}. This tab only.</span>
  <a class="btn secondary" href="${EXIT_HREF}">End</a>
</div>`;
}

