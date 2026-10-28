/**
 * admin-domains.js - the hosts the worker serves.
 *
 * An administrator can add a domain, require authentication on it, choose
 * which email domains may authenticate there and which may create links at
 * its root, set the default redirect behaviour, and mark the whole domain
 * read-only.
 *
 * A host added here is only reachable once a Worker route exists for it in
 * Cloudflare; the page says so rather than pretending otherwise.
 */

import { adminPage, back, denied, flashFrom, formToken, policyForm, readForm, readPolicy } from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf } from './auth.js';
import {
  deleteDomain,
  getDomainFresh,
  listDomains,
  newDomain,
  putDomain,
  REDIRECT_STATUSES,
  ROOT_CREATE_POLICIES,
} from './domains.js';
import { clientIp } from './geo.js';
import { describePolicy, normalizePolicy } from './interstitial.js';
import { clampStatus } from './links.js';
import { MISSING_MODES, normalizeMissingPolicy } from './dirmissing.js';
import { INVITE_MODES, normalizeInvitePolicy } from './invites.js';
import {
  METHODS,
  normalizeDisabledMethods,
  normalizeOauth,
  oauthReady,
} from './oauth.js';
import { canonicalHost, parseDestination, ValidationError } from './paths.js';
import { requireAdmin } from './permissions.js';
import { esc, listEnv } from './util.js';
import { alert, checkbox, csrfField, field, hidden, select, textarea } from './views.js';

const POLICY_LABELS = {
  email_domain: 'Email domain allow list (or an explicit per-user grant)',
  explicit: 'Explicit per-user grant only',
  open: 'Anyone who can sign in',
  admins_only: 'Administrators only',
};

const STATUS_OPTIONS = REDIRECT_STATUSES.map((s) => ({ value: s, label: String(s) }));

function domainHref(host) {
  return '/admin/domains/edit?host=' + encodeURIComponent(host);
}

/** Parse a comma or newline separated list of email domains. */
function parseDomainList(raw) {
  return listEnv(String(raw || '').replace(/\n/g, ','));
}

async function listPage(ctx) {
  const { url } = ctx;
  const domains = await listDomains(ctx.cfg);
  const token = await formToken(ctx, 'domain.create');

  const rows = domains
    .map(
      (d) => `<tr>
      <td><a href="${esc(domainHref(d.host))}">${esc(d.host)}</a>
        ${d.host === ctx.cfg.hubHost ? '<span class="badge">admin host</span>' : ''}
        ${d.enabled === false ? '<span class="badge off">disabled</span>' : ''}
        ${d.readonly ? '<span class="badge ro">read-only</span>' : ''}</td>
      <td>${d.authRequired ? 'Required' : 'Public'}</td>
      <td>${esc((d.allowedAuthDomains || []).join(', ') || '—')}</td>
      <td>${esc(POLICY_LABELS[d.rootCreatePolicy] || d.rootCreatePolicy)}</td>
      <td><span class="target">${esc(describePolicy(normalizePolicy(d.interstitial)))}</span></td>
    </tr>`
    )
    .join('');

  const configured = ctx.cfg.knownHosts.join(', ');

  const body = `
${flashFrom(url)}
<h1>Domains</h1>
<p class="sub">Hosts this worker serves. Apex and <code>www.</code> are treated as the same host.</p>

<div class="card">
  ${
    domains.length
      ? `<div class="tablewrap"><table><thead><tr>
         <th>Host</th><th>Sign-in</th><th>May sign in</th><th>Root creation</th><th>Countdown</th>
         </tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="empty">No domains configured.</div>'
  }
</div>

<div class="card">
  <h2>Add a domain</h2>
  <p class="hint">The DOMAINS variable currently lists: <code>${esc(configured)}</code>. A new host also needs a Worker route in Cloudflare and that variable updated before traffic reaches it.</p>
  <form method="post" action="/admin/domains/new">
    ${csrfField(token)}
    ${field({ name: 'host', label: 'Host', required: true, placeholder: 'links.example.com', note: 'Without www. and without a scheme.' })}
    ${checkbox({ name: 'authRequired', label: 'Require sign-in to follow links on this host' })}
    ${field({ name: 'allowedAuthDomains', label: 'Email domains allowed to sign in', placeholder: 'example.com, *.example.com', note: 'Comma separated. Leave blank to use DEFAULT_ALLOWED_DOMAINS.' })}
    <div class="actions"><button type="submit">Add domain</button></div>
  </form>
</div>`;

  return adminPage(ctx, { title: 'Domains', nav: 'domains', body });
}

async function createSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/domains', 'csrf');
  const guard = await checkCsrf(ctx, 'domain.create', body);
  if (!guard.ok) return back('/admin/domains', 'csrf');

  const host = canonicalHost(body.get('host'));
  if (!host || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
    return denied(ctx, 'That is not a valid host name.');
  }
  if (await getDomainFresh(ctx.cfg, host)) return back(domainHref(host), 'domain.updated');

  const domain = newDomain(host, {
    authRequired: body.get('authRequired') === '1',
    allowedAuthDomains: parseDomainList(body.get('allowedAuthDomains')),
    allowedCreateDomains: parseDomainList(body.get('allowedAuthDomains')),
  });
  await putDomain(ctx.cfg, domain);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.domainCreated,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: host,
    })
  );
  return back(domainHref(host), 'domain.created');
}

async function editForm(ctx, { error } = {}) {
  const { url } = ctx;
  const host = canonicalHost(url.searchParams.get('host'));
  const domain = await getDomainFresh(ctx.cfg, host);
  if (!domain) return back('/admin/domains', 'notfound');

  const token = await formToken(ctx, 'domain.update');
  const deleteToken = await formToken(ctx, 'domain.delete');
  const isHub = host === ctx.cfg.hubHost;
  const routed = ctx.cfg.knownHosts.includes(host);
  const policy = normalizePolicy(domain.interstitial);
  const missingPolicy = normalizeMissingPolicy(domain.dirMissingPolicy);
  const invitePolicy = normalizeInvitePolicy(domain.invitePolicy);
  const oauth = normalizeOauth(domain.oauth);
  const disabledMethods = normalizeDisabledMethods(domain.disabledMethods);

  const body = `
${flashFrom(url)}${alert('error', error)}
<h1>${esc(host)}</h1>
<p class="sub">${isHub ? 'This is the administration host.' : 'Short-link host.'}</p>

${routed ? '' : alert('error', 'This host is not in the DOMAINS variable, so the worker will not serve it yet.')}

<div class="card">
  <h2>Settings</h2>
  <form method="post" action="/admin/domains/edit">
    ${csrfField(token)}${hidden('host', host)}
    ${checkbox({
      name: 'authRequired',
      label: 'Require sign-in to follow links on this host',
      checked: !!domain.authRequired,
      disabled: isHub,
      note: isHub ? '(always on for the administration host)' : '',
    })}
    ${field({
      name: 'allowedAuthDomains',
      label: 'Email domains allowed to sign in',
      value: (domain.allowedAuthDomains || []).join(', '),
      placeholder: 'example.com, *.example.com',
      note: 'Comma separated. Blank falls back to DEFAULT_ALLOWED_DOMAINS.',
    })}
    ${select({
      name: 'rootCreatePolicy',
      label: 'Who may create links at the root',
      value: domain.rootCreatePolicy,
      options: ROOT_CREATE_POLICIES.map((p) => ({ value: p, label: POLICY_LABELS[p] })),
    })}
    ${field({
      name: 'allowedCreateDomains',
      label: 'Email domains allowed to create at the root',
      value: (domain.allowedCreateDomains || []).join(', '),
      note: 'Used by the email domain policy. Blank falls back to DEFAULT_ALLOWED_DOMAINS.',
    })}
    ${select({ name: 'defaultStatus', label: 'Default redirect code', value: domain.defaultStatus, options: STATUS_OPTIONS })}

    <h2>Countdown</h2>
    <p class="hint">Applies to every link on this host unless a directory narrows it, or is granted an exemption.</p>
    ${policyForm(ctx, policy, { prefix: 'it', showDelegate: true })}
    ${field({
      name: 'rootRedirect',
      label: 'Where / goes (optional)',
      value: domain.rootRedirect || '',
      placeholder: 'https://example.com',
      note: ctx.cfg.missingUrl
        ? 'Blank falls back to MISSING: ' + ctx.cfg.missingUrl
        : 'Blank shows a small landing page, because MISSING is not set.',
    })}
    ${field({
      name: 'notFoundUrl',
      label: 'Where unknown, disabled and expired shortcuts go (optional)',
      value: domain.notFoundUrl || '',
      placeholder: 'https://example.com/404',
      note: ctx.cfg.missingUrl
        ? 'Blank falls back to MISSING: ' + ctx.cfg.missingUrl
        : 'Blank shows a not-found page, because MISSING is not set.',
    })}
    <h2>Single sign-on</h2>
    <p class="hint">Authorization Code with PKCE. The provider establishes an address and nothing more: the allowed sign-in domains above still decide who may actually sign in, and an address the provider does not mark verified is refused.</p>
    ${checkbox({ name: 'oauthEnabled', label: 'Offer single sign-on on this domain', checked: !!oauth.enabled })}
    ${field({ name: 'oauthLabel', label: 'Button label', value: oauth.label, placeholder: 'Okta' })}
    ${field({ name: 'oauthClientId', label: 'Client ID', value: oauth.clientId })}
    ${field({ name: 'oauthAuthorizeUrl', label: 'Authorization endpoint', value: oauth.authorizeUrl, placeholder: 'https://idp.example.com/authorize', note: 'HTTPS only. Anything else is discarded.' })}
    ${field({ name: 'oauthTokenUrl', label: 'Token endpoint', value: oauth.tokenUrl, placeholder: 'https://idp.example.com/oauth/token' })}
    ${field({ name: 'oauthUserinfoUrl', label: 'Userinfo endpoint', value: oauth.userinfoUrl, placeholder: 'https://idp.example.com/userinfo' })}
    ${field({ name: 'oauthScope', label: 'Scope', value: oauth.scope })}
    <div class="row">
      ${field({ name: 'oauthEmailField', label: 'Email field', value: oauth.emailField })}
      ${field({ name: 'oauthVerifiedField', label: 'Verified field', value: oauth.verifiedField })}
    </div>
    ${checkbox({
      name: 'oauthAllowUnverified',
      label: 'Accept an address the provider has not verified',
      checked: !!oauth.allowUnverified,
      note: '(not recommended: an unverified address is a claim, not a fact)',
    })}
    <p class="note">Redirect URI to register with the provider: <code>https://${esc(
      domain.host
    )}/__slink/oauth/callback</code>. The client secret is the <code>oauth-secret</code> environment variable, never stored here.${
      oauth.enabled && !oauthReady(ctx.cfg, domain)
        ? ' <strong>Not usable yet: an endpoint, the client ID or the secret is missing.</strong>'
        : ''
    }</p>

    <h3>Other sign-in methods</h3>
    <p class="hint">Only available once single sign-on works. An administrator always keeps every route, so an outage at the provider cannot lock out the people who would fix it.</p>
    ${checkbox({
      name: 'disable_otp',
      label: 'Turn off the emailed code',
      checked: disabledMethods.includes('otp'),
    })}
    ${checkbox({
      name: 'disable_passkey',
      label: 'Turn off passkeys',
      checked: disabledMethods.includes('passkey'),
    })}

    <h2>Who may be given access</h2>
    <p class="hint">Applies when a link or directory changes hands, and when someone is granted access to a directory. The baseline is always whoever could sign in to this host anyway.</p>
    ${select({
      name: 'inviteMode',
      label: 'Beyond the sign-in domains',
      value: invitePolicy.mode,
      options: [
        { value: 'off', label: 'Nobody else' },
        { value: 'optional', label: 'The list below, and a directory may narrow it' },
        { value: 'locked', label: 'The list below, fixed for every directory' },
      ],
    })}
    ${field({
      name: 'inviteDomains',
      label: 'Email domains that may be given access',
      value: invitePolicy.domains.join(', '),
      placeholder: 'pontera.com, partner.com',
      note: 'Comma separated. Ignored when the choice above is "Nobody else".',
    })}

    <h2>Directory MISSING destinations</h2>
    <p class="hint">A directory can answer its own root, and unknown shortcuts under it, with a destination of its own. This decides whether directories may set one.</p>
    ${select({
      name: 'dirMissingMode',
      label: 'Directories may set their own',
      value: missingPolicy.mode,
      options: [
        { value: 'optional', label: 'Yes, each directory decides' },
        { value: 'locked', label: 'No, use the destination below for all of them' },
        { value: 'off', label: 'No, they all use this domain MISSING' },
      ],
      note: 'An administrator can still exempt one directory on its own screen.',
    })}
    ${field({
      name: 'dirMissingTarget',
      label: 'Destination for directories that set none (optional)',
      value: missingPolicy.target || '',
      placeholder: 'https://example.com/teams',
      note: 'Used when a directory has nothing of its own, and for every directory when the choice above is locked.',
    })}
    ${textarea({ name: 'note', label: 'Note', value: domain.note || '' })}
    ${checkbox({ name: 'enabled', label: 'Enabled', checked: domain.enabled !== false })}
    ${checkbox({ name: 'readonly', label: 'Read-only', checked: !!domain.readonly, note: '(only administrators may create or change anything on this host)' })}
    <div class="actions">
      <button type="submit">Save</button>
      <a class="btn secondary" href="/admin/domains">Back</a>
    </div>
  </form>
</div>

${
  isHub
    ? ''
    : `<div class="card">
  <h2>Remove</h2>
  <p class="hint">Removes the policy record. Links already created on this host stay in storage and return if the domain is added again.</p>
  <form method="post" action="/admin/domains/delete" data-confirm="Remove the domain ${esc(host)}?">
    ${csrfField(deleteToken)}${hidden('host', host)}
    <div class="actions"><button type="submit" class="danger">Remove domain</button></div>
  </form>
</div>`
}`;

  return adminPage(ctx, { title: host, nav: 'domains', body });
}

async function editSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/domains', 'csrf');
  const guard = await checkCsrf(ctx, 'domain.update', body);
  if (!guard.ok) return back('/admin/domains', 'csrf');

  const host = canonicalHost(body.get('host'));
  const domain = await getDomainFresh(ctx.cfg, host);
  if (!domain) return back('/admin/domains', 'notfound');

  const isHub = host === ctx.cfg.hubHost;
  ctx.url.searchParams.set('host', host);

  let rootRedirect = null;
  let notFoundUrl = null;
  let dirMissingTarget = null;
  try {
    const rr = String(body.get('rootRedirect') || '').trim();
    const nf = String(body.get('notFoundUrl') || '').trim();
    if (rr) rootRedirect = parseDestination(rr, { blockedSchemes: ctx.cfg.settings.blockedSchemes }).target;
    if (nf) notFoundUrl = parseDestination(nf, { blockedSchemes: ctx.cfg.settings.blockedSchemes }).target;
    const dm = String(body.get('dirMissingTarget') || '').trim();
    if (dm) dirMissingTarget = parseDestination(dm, { blockedSchemes: ctx.cfg.settings.blockedSchemes }).target;
  } catch (err) {
    if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
    throw err;
  }

  const policy = String(body.get('rootCreatePolicy') || 'email_domain');
  domain.authRequired = isHub ? true : body.get('authRequired') === '1';
  domain.allowedAuthDomains = parseDomainList(body.get('allowedAuthDomains'));
  domain.allowedCreateDomains = parseDomainList(body.get('allowedCreateDomains'));
  domain.rootCreatePolicy = ROOT_CREATE_POLICIES.includes(policy) ? policy : 'email_domain';
  domain.defaultStatus = clampStatus(body.get('defaultStatus'), 302);
  domain.interstitial = readPolicy(body, 'it');
  domain.rootRedirect = rootRedirect;
  domain.notFoundUrl = notFoundUrl;
  domain.oauth = normalizeOauth({
    enabled: body.get('oauthEnabled') === '1',
    label: body.get('oauthLabel'),
    clientId: body.get('oauthClientId'),
    authorizeUrl: body.get('oauthAuthorizeUrl'),
    tokenUrl: body.get('oauthTokenUrl'),
    userinfoUrl: body.get('oauthUserinfoUrl'),
    scope: body.get('oauthScope'),
    emailField: body.get('oauthEmailField'),
    verifiedField: body.get('oauthVerifiedField'),
    allowUnverified: body.get('oauthAllowUnverified') === '1',
  });
  domain.disabledMethods = normalizeDisabledMethods(
    METHODS.filter((m) => body.get('disable_' + m) === '1')
  );

  const inviteMode = String(body.get('inviteMode') || 'off');
  domain.invitePolicy = normalizeInvitePolicy({
    mode: INVITE_MODES.includes(inviteMode) ? inviteMode : 'off',
    domains: parseDomainList(body.get('inviteDomains')),
  });
  const dirMissingMode = String(body.get('dirMissingMode') || 'optional');
  domain.dirMissingPolicy = normalizeMissingPolicy({
    mode: MISSING_MODES.includes(dirMissingMode) ? dirMissingMode : 'optional',
    target: dirMissingTarget || '',
  });
  domain.note = String(body.get('note') || '').slice(0, 500);
  domain.enabled = body.get('enabled') === '1';
  domain.readonly = body.get('readonly') === '1';
  await putDomain(ctx.cfg, domain);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.domainUpdated,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: host,
      detail: { authRequired: domain.authRequired, policy: domain.rootCreatePolicy },
    })
  );
  return back(domainHref(host), 'domain.updated');
}

async function deleteSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/domains', 'csrf');
  const guard = await checkCsrf(ctx, 'domain.delete', body);
  if (!guard.ok) return back('/admin/domains', 'csrf');

  const host = canonicalHost(body.get('host'));
  if (host === ctx.cfg.hubHost) return denied(ctx, 'The administration host cannot be removed.');
  await deleteDomain(ctx.cfg, host);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.domainDeleted,
      actor: ctx.session.user,
      host: ctx.host,
      ip: clientIp(ctx.request),
      object: host,
    })
  );
  return back('/admin/domains', 'domain.deleted');
}

export async function adminDomains(ctx, path) {
  const gate = requireAdmin(ctx.cfg, ctx.session.user);
  if (!gate.allowed) return denied(ctx, gate.reason);

  const method = ctx.request.method;
  if (path === '/admin/domains') return listPage(ctx);
  if (path === '/admin/domains/new' && method === 'POST') return createSubmit(ctx);
  if (path === '/admin/domains/edit') return method === 'POST' ? editSubmit(ctx) : editForm(ctx);
  if (path === '/admin/domains/delete' && method === 'POST') return deleteSubmit(ctx);
  return back('/admin/domains');
}
