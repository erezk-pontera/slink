/**
 * admin-links.js - creating, editing, transferring and deleting shortcuts.
 *
 * Ownership is enforced on every write: the creator may change their own
 * link, a directory administrator may change anything inside their directory,
 * an administrator may change anything, and a read-only link may be changed
 * by administrators alone.
 */

import {
  adminPage,
  back,
  denied,
  flashFrom,
  formToken,
  hostFilter,
  hostsFor,
  readForm,
  readFormWithFiles,
} from './admin.js';
import { audit, EVENTS } from './audit.js';
import { checkCsrf } from './auth.js';
import { getDirectory, governingDirectory, listDirectories } from './directories.js';
import { K } from './kv.js';
import { noteDelete, noteWrite, pendingUnder } from './pending.js';
import { policyFor, resolveLink, userExemption, MAX_DELAY } from './interstitial.js';
import {
  emptyPreview,
  normalizePreview,
  previewAllowed,
  previewBlockedReason,
  previewCard,
} from './preview.js';
import { ALL_SLOTS, allDestinations, normalizeFrame, normalizeRouting, SLOT_LABELS } from './targets.js';
import { resolveDomain } from './domains.js';
import { capabilityAllowed, describeCapability } from './capabilities.js';
import { createEverywhere, moveLink } from './linkmove.js';
import {
  hasPassword,
  MAX_PASSWORD,
  readPassword,
  setPassword,
  shareableUrl,
} from './linkpass.js';
import {
  DEFAULT_LOGO_SCALE,
  DEFAULT_SIZE,
  LOGO_SCALES,
  QR_SIZES,
  qrSvg,
} from './admin-qr.js';
import { inviteAllowed } from './invites.js';
import { hasLogo, makeLogo, MAX_LOGO_BYTES } from './qrlogo.js';
import { clientIp } from './geo.js';
import {
  clampDelay,
  clampStatus,
  deleteLink,
  getLink,
  hydrate,
  listLinks,
  listOwnedLinks,
  newLink,
  putLink,
  readClickHistory,
} from './links.js';
import {
  destinationUserinfo,
  joinPath,
  MAX_PATH,
  parseDestination,
  parsePath,
  parseSegment,
  RESERVED_PATHS,
  splitPath,
  ValidationError,
} from './paths.js';
import {
  canCreate,
  creatableLocations,
  canManageLink,
  canReceiveTransfer,
  canSetReadonly,
  canTransferLink,
} from './permissions.js';
import { getUserByNorm, inviteUser } from './users.js';
import { normalizeEmail } from './paths.js';
import { esc, fmtTime } from './util.js';
import {
  alert,
  checkbox,
  clickChart,
  copyButton,
  csrfField,
  field,
  hidden,
  icon,
  select,
  statusBadges,
  textarea,
} from './views.js';

const STATUS_OPTIONS = [
  { value: 302, label: '302 - Found (temporary, default)' },
  { value: 301, label: '301 - Moved permanently' },
  { value: 307, label: '307 - Temporary redirect (keeps method)' },
  { value: 308, label: '308 - Permanent redirect (keeps method)' },
  { value: 303, label: '303 - See other' },
];

/**
 * The countdown fields a given person may change on a given link. A locked
 * setting is shown as settled rather than as a control that does nothing.
 */
function countdownControls(behaviour, link) {
  // Says the form carried these controls at all. An unticked checkbox
  // submits nothing, so without it a request that simply omits the field
  // could not be told apart from one asking for no countdown.
  const parts = [hidden('countdownSet', '1')];
  if (behaviour.countdownLocked) {
    parts.push(
      `<p class="note">Countdown is ${behaviour.show ? 'required' : 'disabled'} by policy for this location.</p>`
    );
  } else {
    parts.push(
      checkbox({
        name: 'countdown',
        label: 'Show a countdown before opening',
        checked: behaviour.show,
      })
    );
  }
  if (behaviour.show) {
    parts.push(
      field({
        name: 'delay',
        label: 'Delay (seconds)',
        type: 'number',
        value: link && link.delay ? link.delay : behaviour.delay,
        attrs: `min="${Math.max(1, behaviour.minDelay)}" max="${MAX_DELAY}"`,
        note: behaviour.minDelay > 0 ? `Policy requires at least ${behaviour.minDelay}s.` : '',
      })
    );
    if (behaviour.targetLocked) {
      parts.push(
        `<p class="note">The destination is ${behaviour.showTarget ? 'always shown' : 'never shown'} by policy.</p>`
      );
    } else {
      parts.push(
        checkbox({
          name: 'showTarget',
          label: 'Show the destination on the countdown page',
          checked: behaviour.showTarget,
        })
      );
    }
  }
  return parts.join('\n');
}

/**
 * The countdown choice a submitted form actually made.
 *
 * A ticked box is an unambiguous yes. An unticked one submits nothing, so
 * the marker above is what distinguishes "no, thank you" from a request
 * that never carried the control: the latter leaves the choice unset, and
 * the policy and the link's own delay go on deciding.
 */
function readChoice(body, name) {
  if (body.get(name) === '1') return true;
  return body.get('countdownSet') ? false : null;
}


/**
 * The QR that follows the shortcut field.
 *
 * Rendered on both the create and the edit screen and filled in by the
 * script as the shortcut is typed, which is why it carries the endpoint
 * rather than a finished `src`: on the create screen there is no link yet,
 * and the code encodes the short URL, which is known from the form alone.
 * It starts hidden and stays hidden without JavaScript, where it could
 * never update.
 */
function qrFloat({ host, path = '', pathField = 'path', logo = '' }) {
  return `<aside class="qrfloat" hidden
  data-slink-qr
  data-base="/admin/links/qr"
  data-path-field="${esc(pathField)}"
  data-host="${esc(host)}"
  data-logo="${esc(logo)}">
  <img class="qr" alt="QR code for the short link" width="150" height="150"${
    path ? '' : ' hidden'
  }>
  <p class="note" data-slink-qr-label></p>
</aside>`;
}

/**
 * Said beside each framing checkbox rather than on the visitor's page.
 * Many sites refuse to be framed and there is nothing this end can do, so
 * the person who sets it is the one who needs to know.
 */
const FRAME_HINT =
  'Keeps the visitor on this domain with the destination shown inside the page. ' +
  'Many sites refuse to be framed (X-Frame-Options, or a frame-ancestors policy) ' +
  'and show nothing at all. Test this destination before sharing the link.';

/**
 * The five destination slots.
 *
 * Four of them are device overrides that almost every link leaves empty,
 * and spelled out in full they were the longest thing on both forms. They
 * fold into one disclosure, opened already when the link actually uses
 * one, so nothing is hidden from a link that has it set.
 */
function routingFields(routing, { frame, mayFrame = false } = {}) {
  const r = normalizeRouting(routing);
  const frames = normalizeFrame(frame);
  const slot = (key) => {
    const isDefault = key === 'default';
    // The main destination's framing choice belongs with the destination
    // itself, not inside a box labelled as one slot among five.
    if (isDefault) {
      return mayFrame
        ? checkbox({
            name: 'frame__default',
            label: 'Show in a frame instead of sending the visitor there',
            checked: frames.default === true,
            tooltip: FRAME_HINT,
          })
        : '';
    }
    return `<fieldset class="grants">
      <legend class="note">${esc(SLOT_LABELS[key])}</legend>
      ${field({
        name: 'url__' + key,
        label: 'Destination',
        value: r[key].url,
        placeholder: 'leave blank to use the main destination',
      })}
      ${
        mayFrame
          ? checkbox({
              name: 'frame__' + key,
              label: 'Show in a frame instead of sending the visitor there',
              checked: frames[key] === true,
              tooltip: FRAME_HINT,
            })
          : ''
      }
    </fieldset>`;
  };
  const devices = ALL_SLOTS.filter((key) => key !== 'default');
  const used = devices.filter((key) => r[key].url || frames[key] === true).length;
  return `${slot('default')}
<details class="group"${used ? ' open' : ''}>
  <summary>Per-device destinations${
    used ? ` <span class="badge">${used} set</span>` : ' <span class="note">(none set)</span>'
  }</summary>
  <p class="hint">A slot left blank falls through to the destination above, so most links need none of these.</p>
  ${devices.map(slot).join('')}
</details>`;
}

/** Read the per-slot frame flags back out of a submitted form. */
function readFrame(body) {
  const out = {};
  for (const key of ALL_SLOTS) if (body.get('frame__' + key) === '1') out[key] = true;
  return out;
}

/** Read the five slots back out of a submitted form. */
function readRouting(body) {
  const out = {};
  for (const key of ALL_SLOTS) out[key] = { url: String(body.get('url__' + key) || '').trim() };
  return out;
}

/**
 * Validate and canonicalise every URL in a routing table, so a device
 * branch cannot smuggle in a scheme the main destination forbids.
 */
function cleanRouting(raw, opts) {
  const r = normalizeRouting(raw);
  for (const key of ALL_SLOTS) {
    if (r[key].url) r[key].url = parseDestination(r[key].url, opts).target;
  }
  return r;
}

/**
 * A place a link can live: the root of a domain, or a directory on it.
 * `ptra.cc/pub` names the directory `pub`; `ptra.cc/` names the root. One
 * value rather than two fields, so a directory can never be paired with the
 * wrong domain by accident.
 */
function placeValue(host, pathLc) {
  return host + '/' + pathLc;
}

function parsePlace(raw) {
  // Bounded before anything is built from it: the directory part becomes
  // part of a KV key, and a key past the store's limit is an error rather
  // than a miss. MAX_PATH is the longest a real directory can be.
  const value = String(raw || '').slice(0, MAX_PATH + 300);
  const at = value.indexOf('/');
  if (at < 0) return { host: value, dirPathLc: '' };
  return { host: value.slice(0, at), dirPathLc: value.slice(at + 1, at + 1 + MAX_PATH).toLowerCase() };
}

/**
 * Every place this person may put a link, across every domain.
 *
 * The create form offers the lot and carries each option's domain on the
 * option itself, so the script can narrow the list to the domain currently
 * chosen while a browser without JavaScript still sees every choice written
 * out in full. The submit checks the pair either way.
 */
async function creatablePlaces(ctx) {
  const { cfg } = ctx;
  return Promise.all(
    cfg.knownHosts.map(async (host) => ({
      host,
      locations: await creatableLocations(cfg, {
        user: ctx.session.user,
        domain: await resolveDomain(cfg, host),
        host,
        ...dirCorrection(ctx, host),
      }),
    }))
  );
}

/**
 * A directory created moments ago may not be in the next prefix listing.
 * Passing this alongside lets the permission code find it, so creating a
 * directory and then a link inside it works on the first try rather than
 * after the listing settles.
 */
function dirCorrection(ctx, host) {
  return {
    pending: pendingUnder(ctx, K.dirPrefix(host, '')),
    grantPending: pendingUnder(ctx, K.userGrantPrefix(ctx.session.user.id)),
  };
}

function placeOptions(perHost) {
  const out = [];
  for (const { host, locations } of perHost) {
    for (const loc of locations) {
      out.push({
        value: placeValue(host, loc.pathLc),
        label: loc.pathLc ? `${host}/${loc.path}/` : `${host}/`,
        data: { name: 'host', value: host },
      });
    }
  }
  return out;
}

/**
 * Note a link this session just wrote or removed, under both the keys the
 * two listings read: the links on a domain, and the links this person owns.
 */
function noteLink(ctx, link, { gone = false } = {}) {
  const mark = gone ? noteDelete : noteWrite;
  return mark(ctx, [
    K.link(link.host, link.pathLc),
    link.ownerId ? K.owner(link.ownerId, link.host, link.pathLc) : '',
  ]);
}

function linkEditHref(host, pathLc) {
  return `/admin/links/edit?host=${encodeURIComponent(host)}&path=${encodeURIComponent(pathLc)}`;
}

/** Rows for a list of link records. */
function linkRows(records, { showOwner = false, maySee = () => true, dupToken = '' } = {}) {
  return records
    .map((link) => {
      const href = 'https://' + link.host + '/' + link.path;
      const name = link.host + '/' + link.path;
      return `<tr>
      <td>
        <a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(name)}${icon('external', {
          cls: 'ic-out',
        })}</a>
        ${statusBadges(link)}
      </td>
      <td>${
        hasPassword(link) && !maySee(link)
          ? '<span class="badge ro">password</span>'
          : `<span class="target" title="${esc(link.target)}">${esc(link.target)}</span>`
      }</td>
      ${showOwner ? `<td>${esc(link.ownerEmail || '—')}</td>` : ''}
      <td class="num">${esc(link.status)}${link.delay ? ` / ${esc(link.delay)}s` : ''}</td>
      <td><div class="rowtools">
        ${copyButton(href, { what: name })}
        ${
          dupToken
            ? `<form method="post" action="/admin/links/duplicate" data-no-busy>
          ${csrfField(dupToken)}${hidden('host', link.host)}${hidden('path', link.pathLc)}
          <button type="submit" class="iconbtn" title="Duplicate ${esc(name)}"
            aria-label="Duplicate ${esc(name)}">${icon('duplicate')}</button>
        </form>`
            : ''
        }
        <a class="btn secondary small" href="${esc(linkEditHref(link.host, link.pathLc))}">Edit</a>
      </div></td>
    </tr>`;
    })
    .join('');
}

/* ----------------------------------------------------------------- list */

async function listPage(ctx) {
  const { cfg, url } = ctx;
  const scope = url.searchParams.get('scope') === 'all' && ctx.isAdmin ? 'all' : 'mine';
  const selected = hostFilter(ctx, url);
  const dir = String(url.searchParams.get('dir') || '').trim().toLowerCase();

  let records = [];
  let truncated = false;

  if (scope === 'all') {
    // One listing per domain, because KV lists by key prefix and each host is
    // its own prefix. With a domain chosen this is a single pass.
    for (const host of hostsFor(ctx, selected)) {
      const page = await listLinks(cfg, host, {
        dirPathLc: dir,
        limit: 100,
        pending: pendingUnder(ctx, K.linkPrefix(host, dir ? dir + '/' : '')),
      });
      records.push(...(await hydrate(cfg, host, page.items)));
      if (page.cursor) truncated = true;
    }
  } else {
    const page = await listOwnedLinks(cfg, ctx.session.user.id, {
      limit: 200,
      pending: pendingUnder(ctx, K.ownerPrefix(ctx.session.user.id)),
    });
    const wanted = page.items.filter((row) => {
      if (selected && row.host !== selected) return false;
      if (dir && !row.pathLc.startsWith(dir + '/')) return false;
      return true;
    });
    records = await hydrate(cfg, null, wanted);
    if (page.cursor) truncated = true;
  }

  records.sort((a, b) => a.host.localeCompare(b.host) || a.pathLc.localeCompare(b.pathLc));

  // Duplicating from the list posts the link back to the create screen
  // pre-filled; the submit there re-checks that this person may manage the
  // original, so one token for the page is enough.
  const dupToken = await formToken(ctx, 'link.duplicate');

  // The directories the filter can offer, de-duped by path because the same
  // name can exist on more than one domain.
  //
  // An administrator sees every one. Anybody else sees only the directories
  // they may already create in, which is what the directories screen shows
  // them: a filter naming a directory somebody holds no grant on would hand
  // out the name the other screen withholds.
  const seen = new Map();
  for (const host of hostsFor(ctx, selected)) {
    const list = ctx.isAdmin
      ? await listDirectories(cfg, host, { pending: pendingUnder(ctx, K.dirPrefix(host, '')) })
      : (
          await creatableLocations(cfg, {
            user: ctx.session.user,
            domain: await resolveDomain(cfg, host),
            host,
            ...dirCorrection(ctx, host),
          })
        )
          .filter((place) => place.dir)
          .map((place) => place.dir);
    for (const d of list) seen.set(d.pathLc, d);
  }
  const known = [...seen.values()].sort((a, b) => a.pathLc.localeCompare(b.pathLc));

  const where = selected ? esc(selected) : 'every domain';
  const body = `
${flashFrom(url)}
<h1>Links</h1>
<p class="sub">${scope === 'all' ? 'Every link on ' : 'Links you created on '}${where}.</p>

<div class="card">
  <form method="get" action="/admin/links" class="row" data-no-busy>
    <div class="field">
      <label for="f_scope">Show</label>
      <select id="f_scope" name="scope">
        <option value="mine"${scope === 'mine' ? ' selected' : ''}>My links</option>
        ${ctx.isAdmin ? `<option value="all"${scope === 'all' ? ' selected' : ''}>All links</option>` : ''}
      </select>
    </div>
    ${select({
      name: 'dir',
      label: 'Directory',
      value: dir,
      options: [{ value: '', label: 'Anywhere' }].concat(
        known.map((d) => ({ value: d.pathLc, label: d.path + '/' }))
      ),
    })}
    <div class="actions tight filterdo"><button type="submit" class="secondary">Apply</button></div>
  </form>
</div>

<div class="card">
  ${
    records.length
      ? `<div class="tablewrap"><table class="cards-sm"><thead><tr>
          <th>Short link</th><th>Destination</th>${scope === 'all' ? '<th>Owner</th>' : ''}
          <th>Code</th><th></th></tr></thead>
          <tbody>${linkRows(records, {
            dupToken,
            showOwner: scope === 'all',
            // The listing is already scoped to what this person may see at
            // all; this is only about the destination of a protected link.
            maySee: (link) =>
              ctx.isAdmin || (link.ownerId && link.ownerId === ctx.session.user.id),
          })}</tbody></table></div>`
      : '<div class="empty">No links to show.</div>'
  }
  ${
    truncated
      ? '<p class="note">There are more than shown. Pick a single domain, or filter by directory, to narrow the list.</p>'
      : ''
  }
  <div class="actions"><a class="btn" href="/admin/links/new">Create a link</a></div>
</div>`;

  return adminPage(ctx, { title: 'Links', nav: 'links', body });
}

/* --------------------------------------------------------------- create */

async function newForm(ctx, { error, info, values = {} } = {}) {
  const { cfg } = ctx;
  const token = await formToken(ctx, 'link.create');
  // A submitted host wins; failing that, `?host=` lets the links list link
  // straight to "create on this domain", and the current host is the last
  // resort. Which domain is chosen decides the policy the rest of the form
  // is rendered against, so it has to be settled first.
  const fromQuery = hostFilter(ctx, ctx.url);
  const chosenHost = values.host || fromQuery || ctx.host;
  // Where this person may put a link, on every domain. The pair of pickers
  // below is the only way to choose a directory, so this list is also what
  // the submit measures the choice against.
  const perHost = await creatablePlaces(ctx);
  const places = placeOptions(perHost);
  const here = places.filter((o) => o.data.value === chosenHost);
  const chosenPlace =
    values.dir && places.some((o) => o.value === values.dir)
      ? values.dir
      : here.length
        ? here[0].value
        : places.length
          ? places[0].value
          : placeValue(chosenHost, '');

  const hostOptions = cfg.knownHosts
    .map((h) => `<option value="${esc(h)}"${h === chosenHost ? ' selected' : ''}>${esc(h)}</option>`)
    .join('');

  const parentDomain = await resolveDomain(cfg, chosenHost);
  const preview = normalizePreview(values.preview);
  const chosenDomain = await resolveDomain(cfg, chosenHost);
  const mayFrame = capabilityAllowed(cfg, 'frame', {
    user: ctx.session.user,
    domain: chosenDomain,
  }).allowed;
  const mayPassword = capabilityAllowed(cfg, 'password', {
    user: ctx.session.user,
    domain: chosenDomain,
  }).allowed;
  // Said rather than hidden: the host is a picker on this form, so a card
  // that is useless on the host currently selected may be exactly right on
  // the one about to be chosen. The submit drops it where it does not apply.
  const previewBlocked = previewBlockedReason(parentDomain);
  // Creating in somebody else's name is the same power as transferring one
  // afterwards, and before the link exists only an administrator holds it.
  const mayTransfer = ctx.isAdmin;
  // What the form is holding, shaped like a link so the countdown controls
  // the editor uses can read it here too. Nothing is chosen on a first
  // render, so the policy's own defaults show; after a rejected submit the
  // booleans are back and the person's choice survives.
  const pending = {
    countdown: typeof values.countdown === 'boolean' ? values.countdown : null,
    showTarget: typeof values.showTarget === 'boolean' ? values.showTarget : null,
    delay: clampDelay(values.delay, 0),
  };
  // The shortcut is still being typed, so no directory is known: this is the
  // domain's policy. A directory that narrows it is applied again when the
  // form is submitted, which is where the path is finally settled.
  const behaviour = resolveLink(
    policyFor(chosenDomain, null),
    pending,
    userExemption(ctx.session.user, chosenHost)
  );

  const body = `
${alert('error', error)}${alert('ok', info)}
<h1>Create a link</h1>
<p class="sub">Shortcuts use letters, digits, underscore and hyphen. They are case-insensitive, so <code>Deck</code> and <code>deck</code> are the same link.</p>

${qrFloat({ host: chosenHost })}
<div class="card">
  <form method="post" action="/admin/links/new" enctype="multipart/form-data">
    ${csrfField(token)}
    <h2>Where it lives</h2>
    <div class="row">
      <div class="field">
        <label for="f_host">Domain</label>
        <select id="f_host" name="host">${hostOptions}</select>
      </div>
      ${select({
        name: 'dir',
        label: 'Directory',
        value: chosenPlace,
        options: places,
        attrs: 'data-slink-places',
        note: places.length
          ? 'Where the link lives. A domain on its own means its root.'
          : 'You cannot create links on any domain yet.',
      })}
      ${field({
        name: 'path',
        label: 'Shortcut',
        value: values.path || '',
        required: true,
        placeholder: 'my-link',
        attrs: 'data-slink-slug spellcheck="false" maxlength="64"',
        note: 'Letters, digits, underscore and hyphen. No "/" \u2014 the directory above decides that.',
      })}
    </div>
    ${textarea({
      name: 'note',
      label: 'Note (optional)',
      value: values.note || '',
      note: 'For whoever looks at this link later. Visitors never see it.',
    })}
    ${
      cfg.knownHosts.length > 1
        ? `<details class="group"${(values.also || []).length ? ' open' : ''}>
      <summary>Also create it on another domain${
        (values.also || []).length ? ` <span class="badge">${(values.also || []).length} ticked</span>` : ''
      }</summary>
      <p class="hint">The same shortcut, in the same directory, on each domain ticked. If it cannot be made on one of them, none are made.</p>
      ${cfg.knownHosts
        .filter((h) => h !== chosenHost)
        .map((h) =>
          checkbox({
            name: 'also__' + h,
            label: h,
            checked: (values.also || []).includes(h),
          })
        )
        .join('')}
    </details>`
        : ''
    }

    <h2>Where it goes</h2>
    ${field({
      name: 'target',
      label: 'Destination',
      value: values.target || '',
      required: true,
      placeholder: 'example.com/page',
      note: 'Without a scheme this becomes https://. Other schemes such as mailto: or slack:// are kept as written.',
    })}
    ${select({ name: 'status', label: 'Redirect code', value: values.status || 302, options: STATUS_OPTIONS })}
    ${checkbox({ name: 'forwardQuery', label: 'Append the incoming query string to the destination', checked: !!values.forwardQuery })}
    ${routingFields(values.routing, { frame: values.frame, mayFrame })}

    <h2>How it opens</h2>
    ${countdownControls(behaviour, pending)}

    <h2>When it works</h2>
    <div class="row">
      ${field({
        name: 'activeFrom',
        label: 'Starts (UTC, optional)',
        type: 'datetime-local',
        value: values.activeFrom || '',
        tooltip: UTC_HINT,
        note: 'Before this the link is not live.',
      })}
      ${field({
        name: 'expires',
        label: 'Expires (UTC, optional)',
        type: 'datetime-local',
        value: values.expires || '',
        tooltip: UTC_HINT,
        note: 'After this it stops resolving.',
      })}
    </div>
    ${hidden('enabledSet', '1')}${checkbox({
      name: 'enabled',
      label: 'Enabled',
      checked: values.enabled !== false,
      tooltip: 'A disabled link resolves to the domain\u2019s MISSING destination, the same as one that does not exist. Useful for preparing a link before it is announced.',
    })}

    <h2>Who may use it</h2>
    ${
      canSetReadonly(ctx.cfg, ctx.session.user)
        ? checkbox({
            name: 'readonly',
            label: 'Read-only',
            checked: !!values.readonly,
            note: '(only administrators can change it afterwards)',
          })
        : ''
    }
    ${
      mayTransfer
        ? field({
            name: 'owner',
            label: 'Owner (optional)',
            type: 'email',
            value: values.owner || '',
            placeholder: ctx.session.user.email,
            tooltip:
              'Create the link in somebody else\u2019s name. Leave blank to own it yourself. ' +
              'The same invite rules apply as when a link changes hands later.',
          })
        : ''
    }
    ${
      mayPassword
        ? field({
            name: 'password',
            label: 'Password (optional)',
            value: values.password || '',
            placeholder: 'leave blank for an open link',
            attrs: 'autocomplete="off" spellcheck="false" maxlength="' + MAX_PASSWORD + '"',
            note: 'A visitor types this before the link resolves. You can share it inside the link afterwards; the edit screen shows how.',
          })
        : ''
    }

    <h2>Preview card</h2>
    <p class="hint">Shown when something like Slack or Twitter unfurls this link. Leave it off and the unfurler reads the destination's own tags instead.</p>
    ${
      // Blocked on the domain currently chosen, but the domain is a picker
      // on this form, so the fields are folded away with the reason rather
      // than removed: the next domain in the list may well allow them.
      previewBlocked ? `<details class="group"><summary>Not used on ${esc(chosenHost)}</summary>
    <p class="hint">${esc(previewBlocked)}</p>` : ''
    }
    ${checkbox({ name: 'previewEnabled', label: 'Use a preview card for this link', checked: !!preview.enabled })}
    ${field({ name: 'previewTitle', label: 'Title', value: preview.title, placeholder: 'Required for a card to show' })}
    ${textarea({ name: 'previewDescription', label: 'Description', value: preview.description })}
    ${field({ name: 'previewImage', label: 'Image URL', value: preview.image, placeholder: 'https://example.com/card.png', note: 'Must be https.' })}
    ${previewBlocked ? '</details>' : ''}

    <h2>QR code</h2>
    <p class="hint">The code appears beside this form as soon as there is a shortcut, and encodes the short link rather than the destination, so it keeps working if the destination changes. Its size and durability are chosen on the edit screen afterwards.</p>
    <div class="field">
      <label for="f_qrimage">Centre image (optional)</label>
      <input id="f_qrimage" name="image" type="file" accept="image/png,image/jpeg,image/gif,image/webp">
      <p class="note">PNG, JPEG, GIF or WebP, up to ${MAX_LOGO_BYTES / 1024}&nbsp;KB. An SVG is a document rather than a picture, so it is not accepted.</p>
    </div>

    <div class="actions">
      <button type="submit">Create link</button>
      <a class="btn secondary" href="/admin/links">Cancel</a>
    </div>
  </form>
</div>`;

  return adminPage(ctx, { title: 'Create a link', nav: 'links', body });
}

/** Parse an optional YYYY-MM-DD expiry into a unix timestamp. */
/**
 * A schedule field, read as UTC.
 *
 * `datetime-local` gives `YYYY-MM-DDTHH:MM`, which a browser renders in the
 * viewer's own zone but submits without one. Appending `Z` is what makes
 * the value mean UTC rather than wherever the person happens to be: the
 * label and the tooltip both say so, because a link that goes live at
 * "09:00" has to mean the same instant to everybody who edits it.
 *
 * A bare date is still accepted, so a link stored before the time was
 * added, or typed by hand, keeps working: a start runs from the beginning
 * of that day and an expiry to the end of it.
 */
function parseMoment(raw, { field: fieldName, endOfDay }) {
  const value = String(raw || '').trim();
  if (!value) return 0;
  const label = fieldName === 'expires' ? 'Expiry' : 'Start';
  if (!/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?$/.test(value)) {
    throw new ValidationError(
      label + ' must be a UTC date and time, such as 2026-12-31 18:30.',
      fieldName
    );
  }
  const [datePart, timePart] = value.split(/[T ]/);
  const time = timePart ? (timePart.length === 5 ? timePart + ':00' : timePart) : endOfDay ? '23:59:59' : '00:00:00';
  const ts = Date.parse(datePart + 'T' + time + 'Z');
  if (!Number.isFinite(ts)) {
    throw new ValidationError(label + ' is not a real date and time.', fieldName);
  }
  return Math.floor(ts / 1000);
}

function parseExpiry(raw) {
  return parseMoment(raw, { field: 'expires', endOfDay: true });
}

function parseActiveFrom(raw) {
  return parseMoment(raw, { field: 'activeFrom', endOfDay: false });
}

/** A link cannot stop being live before it starts. */
function checkWindow(activeFrom, expiresAt) {
  if (activeFrom && expiresAt && activeFrom >= expiresAt) {
    throw new ValidationError('The start date must come before the expiry date.', 'activeFrom');
  }
}

/** The stored instant as the `YYYY-MM-DDTHH:MM` a datetime-local wants, in UTC. */
function expiryInput(at) {
  if (!at) return '';
  return new Date(at * 1000).toISOString().slice(0, 16);
}

const UTC_HINT =
  'Entered and shown in UTC, not your local time, so the link means the same ' +
  'instant to everyone who edits it. Leave blank for none.';

async function createSubmit(ctx) {
  const body = await readFormWithFiles(ctx.request, { maxBytes: MAX_LOGO_BYTES + 64 * 1024 });
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.create', body);
  if (!guard.ok) return back('/admin/links/new', 'csrf');

  const host = String(body.get('host') || ctx.host);
  if (!ctx.cfg.knownHosts.includes(host)) return newForm(ctx, { error: 'Unknown domain.' });
  const domain = await resolveDomain(ctx.cfg, host);
  if (!domain) return newForm(ctx, { error: 'Unknown domain.' });

  const values = {
    host,
    dir: String(body.get('dir') || ''),
    path: body.get('path') || '',
    target: body.get('target') || '',
    status: body.get('status'),
    delay: body.get('delay'),
    countdown: readChoice(body, 'countdown'),
    showTarget: readChoice(body, 'showTarget'),
    activeFrom: body.get('activeFrom') || '',
    expires: body.get('expires') || '',
    note: body.get('note') || '',
    forwardQuery: body.get('forwardQuery') === '1',
    // An unticked checkbox submits nothing, so a hidden marker says whether
    // the form carried the control at all. Without it, any caller posting a
    // form without the field would silently create a disabled link.
    enabled: body.get('enabledSet') ? body.get('enabled') === '1' : true,
    owner: String(body.get('owner') || '').trim(),
    readonly: body.get('readonly') === '1',
    routing: readRouting(body),
    frame: readFrame(body),
    also: ctx.cfg.knownHosts.filter((h) => body.get('also__' + h) === '1'),
    password: String(body.get('password') || ''),
    preview: {
      enabled: body.get('previewEnabled') === '1',
      title: body.get('previewTitle'),
      description: body.get('previewDescription'),
      image: String(body.get('previewImage') || '').trim(),
    },
  };

  // The directory comes from a picker. An empty value is a post that never
  // carried one, which means the root of the chosen domain; a value naming
  // another domain is the two pickers out of step, which only a browser
  // without JavaScript can manage and which is said plainly rather than
  // guessed at.
  const place = values.dir ? parsePlace(values.dir) : { host, dirPathLc: '' };
  if (place.host !== host) {
    return newForm(ctx, {
      error: `That directory is on ${place.host}. Pick one on ${host}, or change the domain.`,
      values,
    });
  }
  if (place.dirPathLc && !(await getDirectory(ctx.cfg, host, place.dirPathLc))) {
    return newForm(ctx, { error: 'That directory no longer exists.', values });
  }

  let parsed;
  let destination;
  let expiresAt;
  let activeFrom;
  let routing;
  try {
    parsed = parsePath(joinPath(place.dirPathLc, parseSegment(values.path)), {
      reserved: reservedFor(ctx, host),
    });
    destination = parseDestination(values.target, { blockedSchemes: ctx.cfg.settings.blockedSchemes });
    expiresAt = parseExpiry(values.expires);
    activeFrom = parseActiveFrom(values.activeFrom);
    checkWindow(activeFrom, expiresAt);
    routing = cleanRouting(values.routing, { blockedSchemes: ctx.cfg.settings.blockedSchemes });
    if (values.preview.image && !/^https:\/\//i.test(values.preview.image)) {
      throw new ValidationError('The preview image must be an https URL.', 'previewImage');
    }
  } catch (err) {
    if (err instanceof ValidationError) return newForm(ctx, { error: err.message, values });
    throw err;
  }

  const permit = await canCreate(ctx.cfg, {
    user: ctx.session.user,
    domain,
    host,
    pathLc: parsed.pathLc,
    pending: pendingUnder(ctx, K.dirPrefix(host, '')),
  });
  if (!permit.allowed) {
    ctx.waitUntil(
      audit(ctx.cfg, {
        event: EVENTS.denied,
        actor: ctx.session.user,
        host,
        ip: clientIp(ctx.request),
        outcome: 'denied',
        object: parsed.pathLc,
        detail: { action: 'link.create', reason: permit.reason },
      })
    );
    return newForm(ctx, { error: permit.reason, values });
  }

  const existing = await getLink(ctx.cfg, host, parsed.pathLc);
  if (existing) return newForm(ctx, { error: 'That shortcut is already in use.', values });
  const clash = await getDirectory(ctx.cfg, host, parsed.pathLc);
  if (clash) return newForm(ctx, { error: 'A directory already uses that path.', values });

  // Creating the link in somebody else's name, which goes through exactly
  // the checks a later transfer would: only an administrator may do it, the
  // invite policy decides whether that address may be given anything here,
  // and the recipient must be someone who could have created it themselves.
  let owner = ctx.session.user;
  if (values.owner) {
    if (!ctx.isAdmin) return newForm(ctx, { error: 'Only an administrator can set the owner.', values });
    let recipientEmail;
    try {
      recipientEmail = normalizeEmail(values.owner, ctx.cfg.emailOpts);
    } catch (err) {
      return newForm(ctx, { error: err.message, values });
    }
    const invite = await inviteAllowed(ctx.cfg, {
      host,
      domain,
      pathLc: parsed.pathLc,
      emailNorm: recipientEmail.emailNorm,
    });
    if (!invite.allowed) return newForm(ctx, { error: invite.reason, values });
    const invited = await inviteUser(ctx.cfg, {
      email: recipientEmail.email,
      emailNorm: recipientEmail.emailNorm,
      invitedBy: ctx.session.user,
    });
    const receive = await canReceiveTransfer(ctx.cfg, {
      actor: ctx.session.user,
      recipient: invited.user,
      domain,
      host,
      pathLc: parsed.pathLc,
    });
    if (!receive.allowed) return newForm(ctx, { error: receive.reason, values });
    owner = invited.user;
  }

  // Only record a choice the policy actually leaves open, so a locked
  // setting cannot be smuggled in by hand-posting the form. The shortcut is
  // parsed by now, so the governing directory is known and this is exactly
  // the check the editor makes on a save.
  const delay = clampDelay(values.delay, domain.defaultDelay || 0);
  const effective = resolveLink(
    policyFor(domain, await governingDirectory(ctx.cfg, host, parsed.pathLc)),
    { countdown: values.countdown, showTarget: values.showTarget, delay },
    userExemption(ctx.session.user, host)
  );

  const fields = {
    status: clampStatus(values.status, domain.defaultStatus || 302),
    delay,
    countdown: effective.countdownLocked ? null : values.countdown,
    showTarget: effective.targetLocked ? null : values.showTarget,
    note: String(values.note).slice(0, 500),
    activeFrom,
    expiresAt,
    forwardQuery: values.forwardQuery,
    enabled: values.enabled,
    readonly: canSetReadonly(ctx.cfg, ctx.session.user) ? values.readonly : false,
    routing,
    // Framing is only stored where the person creating the link may use it,
    // so a submitted flag cannot grant what the host withheld.
    frame: capabilityAllowed(ctx.cfg, 'frame', { user: ctx.session.user, domain }).allowed
      ? normalizeFrame(values.frame)
      : {},
    preview: previewBlockedReason(domain) ? emptyPreview() : normalizePreview(values.preview),
  };

  // An uploaded centre image, through exactly the checks the edit screen
  // applies: the bytes are sniffed, not the name or the declared type.
  const upload = body.get('image');
  if (upload && typeof upload !== 'string' && typeof upload.arrayBuffer === 'function' && upload.size > 0) {
    if (upload.size > MAX_LOGO_BYTES) {
      return newForm(ctx, {
        error: `That image is ${Math.ceil(upload.size / 1024)} KB. The limit is ${MAX_LOGO_BYTES / 1024} KB.`,
        values,
      });
    }
    const made = makeLogo(new Uint8Array(await upload.arrayBuffer()));
    if (!made.ok) return newForm(ctx, { error: made.error, values });
    fields.qrLogo = made.logo;
  }

  // Same reasoning as framing: a submitted password only lands where the
  // person creating the link may actually use one.
  if (values.password) {
    if (!capabilityAllowed(ctx.cfg, 'password', { user: ctx.session.user, domain }).allowed) {
      return newForm(ctx, { error: 'You cannot put a password on a link here.', values });
    }
    const holder = {};
    const sealed = await setPassword(ctx.cfg, holder, values.password);
    if (!sealed.ok) return newForm(ctx, { error: sealed.error, values });
    fields.password = holder.password;
  }

  // One submission can put the same shortcut on several domains. Every one
  // is checked before any is written, so a run that cannot finish writes
  // nothing at all.
  if (values.also && values.also.length) {
    const result = await createEverywhere(ctx.cfg, {
      user: owner,
      hosts: [host, ...values.also],
      rawPath: parsed.path,
      fields: { ...fields, target: destination.target },
    });
    if (!result.ok) return newForm(ctx, { error: result.error, values });
    for (const made of result.links) await noteLink(ctx, made);
    ctx.waitUntil(
      Promise.all(
        result.links.map((made) =>
          audit(ctx.cfg, {
            event: EVENTS.linkCreated,
            actor: ctx.session.user,
            host: made.host,
            ip: clientIp(ctx.request),
            object: made.pathLc,
            detail: { target: made.target, acrossDomains: result.created },
          })
        )
      )
    );
    return back(linkEditHref(host, parsed.pathLc), 'link.createdMany');
  }

  const link = newLink(host, parsed, destination.target, owner, fields);
  await putLink(ctx.cfg, link);
  await noteLink(ctx, link);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkCreated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: parsed.pathLc,
      detail: { target: destination.target, status: link.status, delay: link.delay },
    })
  );
  return back(linkEditHref(host, parsed.pathLc), 'link.created');
}

/** Reserved names apply on the administration host only. */
function reservedFor(ctx, host) {
  return host === ctx.cfg.hubHost ? RESERVED_PATHS : ['__slink'];
}

/* ------------------------------------------------------------------- qr */

/** The QR card on the edit screen: a live preview and the download link. */
function qrCard(host, link, url, { uploadToken, appName }) {
  const base =
    '/admin/links/qr?host=' + encodeURIComponent(host) + '&path=' + encodeURIComponent(link.pathLc);
  const uploaded = hasLogo(link);
  const rawLogo = url.searchParams.get('qrlogo') || (uploaded ? 'custom' : '');
  const current = {
    size: url.searchParams.get('qrsize') || String(DEFAULT_SIZE),
    ecc: url.searchParams.get('qrecc') || 'M',
    logo: rawLogo === '1' || (rawLogo === 'custom' && uploaded) ? rawLogo : '',
    scale: url.searchParams.get('qrscale') || String(DEFAULT_LOGO_SCALE),
  };
  const logoQuery = current.logo
    ? '&logo=' + encodeURIComponent(current.logo) + '&logoscale=' + encodeURIComponent(current.scale)
    : '';
  const src = base + '&size=512&ecc=' + encodeURIComponent(current.ecc) + logoQuery;
  const download =
    base + '&size=' + encodeURIComponent(current.size) + '&ecc=' + encodeURIComponent(current.ecc) + logoQuery;

  return `<div class="card">
  <h2>QR code</h2>
  <p class="hint">Encodes the short link itself, so it keeps working if the destination changes. Higher durability survives more damage and is what makes a centre logo safe.</p>
  <div class="qrwrap">
    <img class="qr" src="${esc(src)}" width="220" height="220" alt="QR code for ${esc(host)}/${esc(link.path)}">
    <form method="get" action="/admin/links/edit" data-no-busy>
      ${hidden('host', host)}${hidden('path', link.pathLc)}
      ${select({
        name: 'qrecc',
        label: 'Durability',
        value: current.ecc,
        options: [
          { value: 'L', label: 'Low (7%)' },
          { value: 'M', label: 'Medium (15%)' },
          { value: 'Q', label: 'Quartile (25%)' },
          { value: 'H', label: 'High (30%)' },
        ],
        note: 'Asking for a logo raises this to High on its own.',
      })}
      ${select({
        name: 'qrsize',
        label: 'Download size',
        value: current.size,
        options: QR_SIZES.map((n) => ({ value: String(n), label: n + ' px' })),
      })}
      ${select({
        name: 'qrlogo',
        label: 'Centre image',
        value: current.logo,
        options: [
          { value: '', label: 'None' },
          { value: '1', label: 'The ' + appName + ' mark' },
          ...(uploaded ? [{ value: 'custom', label: 'The image you uploaded' }] : []),
        ],
        note: uploaded ? '' : 'Upload one below to use your own.',
      })}
      ${select({
        name: 'qrscale',
        label: 'Image size',
        value: current.scale,
        options: LOGO_SCALES.map((n) => ({ value: String(n), label: Math.round(n * 100) + '% of the code' })),
      })}
      <div class="actions">
        <button type="submit" class="secondary">Update preview</button>
        <a class="btn secondary" href="${esc(download)}" download>Download SVG</a>
      </div>
    </form>
  </div>

  <h3>Your own centre image</h3>
  <p class="hint">PNG, JPEG, GIF or WebP, up to ${MAX_LOGO_BYTES / 1024}&nbsp;KB. An SVG is a document rather than a picture, so it is not accepted. A square image with a clear margin reads best; whatever it covers has to be reconstructed from the error correction, which is why choosing one raises durability to High.</p>
  <form method="post" action="/admin/links/qrlogo" enctype="multipart/form-data">
    ${csrfField(uploadToken)}${hidden('host', host)}${hidden('path', link.pathLc)}
    <div class="field">
      <label for="f_qrimage">Image file</label>
      <input id="f_qrimage" name="image" type="file" accept="image/png,image/jpeg,image/gif,image/webp">
    </div>
    <div class="actions">
      <button type="submit" class="secondary">Upload</button>
    </div>
  </form>
  ${
    uploaded
      ? `<form method="post" action="/admin/links/qrlogo" data-confirm="Remove the uploaded centre image?">
    ${csrfField(uploadToken)}${hidden('host', host)}${hidden('path', link.pathLc)}${hidden('remove', '1')}
    <p class="note">Using an uploaded ${esc(link.qrLogo.type.replace('image/', '').toUpperCase())} of ${Math.ceil(
          (link.qrLogo.bytes || 0) / 1024
        )}&nbsp;KB.</p>
    <div class="actions"><button type="submit" class="link">Remove it</button></div>
  </form>`
      : ''
  }
</div>`;
}

/** The host a destination actually resolves to, for the masking warning. */
function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/* ----------------------------------------------------------------- edit */

async function editForm(ctx, { error, info } = {}) {
  const { cfg, url } = ctx;
  const host = url.searchParams.get('host') || ctx.host;
  const pathLc = String(url.searchParams.get('path') || '').toLowerCase();
  const link = await getLink(cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) {
    // An administrator scoped out of this directory still owns the question
    // of who the link belongs to, so give them the one card they may use
    // rather than a flat refusal.
    const move = await canTransferLink(cfg, { user: ctx.session.user, link, host });
    if (move.allowed) return ownershipOnlyPage(ctx, { host, pathLc, link, error, info });
    return denied(ctx, permit.reason);
  }

  const token = await formToken(ctx, 'link.update');
  const delToken = await formToken(ctx, 'link.delete');
  const moveToken = await formToken(ctx, 'link.transfer');
  const history = await readClickHistory(cfg, host, pathLc, { days: 30 });
  const clicks = history.total;
  const dir = await governingDirectory(cfg, host, pathLc);
  const policy = policyFor(await resolveDomain(cfg, host), dir);
  const behaviour = resolveLink(policy, link, userExemption(ctx.session.user, host));
  const parentDomain = await resolveDomain(cfg, host);
  const preview = normalizePreview(link.preview);
  const mayFrame = capabilityAllowed(cfg, 'frame', {
    user: ctx.session.user,
    domain: parentDomain,
    dir,
  }).allowed;
  const mayPassword = capabilityAllowed(cfg, 'password', {
    user: ctx.session.user,
    domain: parentDomain,
    dir,
  }).allowed;
  const currentPassword = await readPassword(cfg, link);
  // A password that is set but will not decrypt means AUTH_SECRET was
  // rotated without AUTH_SECRET_PREVIOUS. Showing an empty field there
  // would invite a save that silently unprotects the link.
  const passwordLost = hasPassword(link) && !currentPassword;
  const previewBlocked = previewBlockedReason(parentDomain);
  const dupToken = await formToken(ctx, 'link.duplicate');
  const passwordToken = await formToken(ctx, 'link.password');
  const moveHostToken = await formToken(ctx, 'link.move');
  const qrLogoToken = await formToken(ctx, 'link.qrlogo');
  const shortUrl = 'https://' + host + '/' + link.path;
  const mayReadonly = canSetReadonly(cfg, ctx.session.user);

  // Where this link sits, and everywhere on this domain it could be moved
  // to. Its own directory is always offered even where this person could
  // not create there, so editing a link never forces it out of the place
  // somebody else put it.
  const at = splitPath(link.pathLc);
  const places = placeOptions([
    {
      host,
      locations: await creatableLocations(cfg, {
        user: ctx.session.user,
        domain: parentDomain,
        host,
        ...dirCorrection(ctx, host),
      }),
    },
  ]);
  if (!places.some((o) => o.value === placeValue(host, at.dirPathLc))) {
    places.unshift({
      value: placeValue(host, at.dirPathLc),
      label: at.dirPathLc ? `${host}/${at.dirPathLc}/` : `${host}/`,
      data: { name: 'host', value: host },
    });
  }

  // A destination whose authority carries a username reads as one host and
  // goes to another. It is sometimes meant, so it is said out loud rather
  // than refused.
  const masked = allDestinations(link)
    .map((url) => ({ url, user: destinationUserinfo(url) }))
    .filter((d) => d.user);
  const maskWarning = masked.length
    ? alert(
        'error',
        'Check the destination: ' +
          masked
            .map((d) => `"${d.user}" before the @ is not where this goes; the host is ` + hostOf(d.url))
            .join('; ') +
          '.'
      )
    : '';

  const body = `
${flashFrom(url)}${alert('error', error)}${alert('ok', info)}${maskWarning}
${qrFloat({
    host,
    path: link.path,
    pathField: 'newpath',
    logo: hasLogo(link) ? 'custom' : '',
  })}
<h1>${esc(host)}/${esc(link.path)}</h1>
<p class="sub">${statusBadges(link) || 'Active'} &middot; created ${esc(fmtTime(link.createdAt))} &middot;
<span title="Simultaneous arrivals can overwrite one another, so this is a floor rather than an exact count.">${esc(
    clicks
  )} hit${clicks === 1 ? '' : 's'} or more</span></p>

<div class="card">
  <h2>Where it lives</h2>
  <form method="post" action="/admin/links/edit">
    ${csrfField(token)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="row">
      ${select({
        name: 'dir',
        label: 'Directory',
        value: placeValue(host, at.dirPathLc),
        options: places,
        note: 'Moving it between directories needs permission to create in the new one.',
      })}
      ${field({
        name: 'newpath',
        label: 'Shortcut',
        value: at.segment,
        required: true,
        attrs: 'data-slink-slug spellcheck="false" maxlength="64"',
        note: 'Renaming or moving changes the short link; the old one stops working.',
      })}
    </div>
    ${textarea({
      name: 'note',
      label: 'Note',
      value: link.note || '',
      note: 'For whoever looks at this link later. Visitors never see it.',
    })}

    <h2>Where it goes</h2>
    ${field({ name: 'target', label: 'Destination', value: link.target, required: true, note: 'Used when nothing more specific matches.' })}
    ${select({ name: 'status', label: 'Redirect code', value: link.status, options: STATUS_OPTIONS })}
    ${checkbox({ name: 'forwardQuery', label: 'Append the incoming query string to the destination', checked: !!link.forwardQuery })}
    ${routingFields(link.routing, { frame: link.frame, mayFrame })}

    <h2>How it opens</h2>
    ${countdownControls(behaviour, link)}

    <h2>When it works</h2>
    <div class="row">
      ${field({
        name: 'activeFrom',
        label: 'Starts (UTC)',
        type: 'datetime-local',
        value: expiryInput(link.activeFrom),
        tooltip: UTC_HINT,
        note: 'Before this the link is not live.',
      })}
      ${field({
        name: 'expires',
        label: 'Expires (UTC)',
        type: 'datetime-local',
        value: expiryInput(link.expiresAt),
        tooltip: UTC_HINT,
        note: 'After this it stops resolving.',
      })}
    </div>
    ${checkbox({ name: 'enabled', label: 'Enabled', checked: link.enabled !== false })}

    <h2>Preview card</h2>
    ${
      previewBlocked
        ? `<p class="note">${esc(previewBlocked)}</p>`
        : `<p class="hint">Shown when something like Slack or Twitter unfurls this link. Leave it off and the unfurler reads the destination's own tags instead.</p>
    ${checkbox({ name: 'previewEnabled', label: 'Use a preview card for this link', checked: !!preview.enabled })}
    ${field({ name: 'previewTitle', label: 'Title', value: preview.title, placeholder: 'Required for a card to show' })}
    ${textarea({ name: 'previewDescription', label: 'Description', value: preview.description })}
    ${field({ name: 'previewImage', label: 'Image URL', value: preview.image, placeholder: 'https://example.com/card.png', note: 'Must be https. Saved and shown as entered; it is not copied or hosted here.' })}
    <p class="note">How it will look:</p>
    ${previewCard(host, link, preview)}`
    }
    ${checkbox({
      name: 'readonly',
      label: 'Read-only',
      checked: !!link.readonly,
      disabled: !mayReadonly,
      note: mayReadonly ? '(only administrators can change it afterwards)' : '(administrators only)',
    })}
    <div class="actions">
      <button type="submit">Save changes</button>
      <a class="btn secondary" href="/admin/links">Back</a>
      ${copyButton(shortUrl, { what: 'the short link', label: 'Copy short link' })}
    </div>
  </form>
</div>

<div class="card">
  <h2>Password</h2>
  ${
    mayPassword
      ? `${
          passwordLost
            ? alert(
                'error',
                'This link has a password, but it cannot be decrypted with the current AUTH_SECRET. ' +
                  'That happens when the secret is rotated: set AUTH_SECRET_PREVIOUS to the old value to ' +
                  'recover it, or set a new password here. Until one or the other, nobody can open this link.'
              )
            : ''
        }<p class="hint">A visitor has to type this before the link resolves, on any domain. It is stored encrypted and shown here because you have to be able to tell people what it is. Changing it closes every browser that had already answered.</p>
  <form method="post" action="/admin/links/password" autocomplete="off">
    ${csrfField(passwordToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({
      name: 'password',
      label: 'Password',
      value: currentPassword,
      placeholder: passwordLost
        ? 'type a new password to replace the unreadable one'
        : hasPassword(link)
          ? ''
          : 'leave blank for no password',
      attrs: 'autocomplete="off" spellcheck="false" maxlength="' + MAX_PASSWORD + '"',
      note: passwordLost
        ? 'Saving a new one replaces it. To remove it instead, tick the box below.'
        : hasPassword(link)
          ? 'Clear the field and save to remove the password.'
          : 'Setting one also hides this link\'s destinations from anyone who cannot edit it.',
    })}
    ${
      passwordLost
        ? checkbox({
            name: 'confirmClear',
            label: 'Yes, remove the password I cannot read',
            checked: false,
          })
        : ''
    }
    <div class="actions"><button type="submit" class="secondary">${
      hasPassword(link) ? 'Update password' : 'Set a password'
    }</button></div>
  </form>`
      : `<p class="hint">${esc(
          describeCapability(cfg, 'password', { user: ctx.session.user, domain: parentDomain, dir })
        )}${hasPassword(link) ? ' This link already has one, which still applies.' : ''}</p>`
  }
  ${
    hasPassword(link) && !passwordLost
      ? `<h3>Sharing it without the prompt</h3>
  <p class="hint">Adding the password to the end of the link opens it straight away. The part after <code>#</code> never leaves the browser, so it stays out of our logs and out of the referrer sent to the destination, and this page clears it from the address bar as soon as it has used it. Anyone holding this form of the link has the password, so share it exactly as carefully.</p>
  <p class="target-big">${esc(shareableUrl(host, link.path, currentPassword))}</p>
  <div class="actions">
    ${copyButton(shareableUrl(host, link.path, currentPassword), {
      what: 'the link with its password',
      label: 'Copy link with password',
    })}
  </div>`
      : ''
  }
</div>

${qrCard(host, link, url, { uploadToken: qrLogoToken, appName: cfg.appName })}

<div class="card">
  <h2>Hits</h2>
  ${
    history.lastAt
      ? `<p class="hint">${esc(clicks)} or more, last one ${esc(fmtTime(history.lastAt))}.</p>
  ${clickChart(history.series)}
  <p class="note">Counted approximately: arrivals at the same moment can overwrite one another. Counting can be turned off in Settings.</p>`
      : '<p class="hint">Nobody has followed this link yet.</p>'
  }
</div>

<div class="card">
  <h2>Ownership and copies</h2>
  <h3>Owner</h3>
  <p class="hint">Currently ${esc(link.ownerEmail || 'unassigned')}. Transferring hands over the right to edit and delete it.</p>
  <form method="post" action="/admin/links/transfer">
    ${csrfField(moveToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({ name: 'owner', label: 'New owner email', type: 'email', value: '', required: true, placeholder: 'colleague@example.com' })}
    <div class="actions"><button type="submit" class="secondary">Transfer</button></div>
  </form>
${
  cfg.knownHosts.length > 1
    ? `  <h3>Move to another domain</h3>
  <p class="hint">Keeps everything about the link, including its password and destinations, and stops answering on ${esc(
    host
  )}. You need to be allowed to create it on the domain you move it to.</p>
  <form method="post" action="/admin/links/move" data-confirm="Move ${esc(host)}/${esc(
    link.path
  )} to another domain?">
    ${csrfField(moveHostToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="row">
      ${select({
        name: 'toHost',
        label: 'Domain',
        value: cfg.knownHosts.find((h) => h !== host) || '',
        options: cfg.knownHosts.filter((h) => h !== host).map((h) => ({ value: h, label: h })),
      })}
      ${field({
        name: 'newpath',
        label: 'Shortcut there',
        value: link.path,
        required: true,
        attrs: 'data-slink-slug spellcheck="false"',
      })}
    </div>
    <div class="actions"><button type="submit" class="secondary">Move</button></div>
  </form>`
    : ''
}
  <h3>Duplicate</h3>
  <p class="hint">Copies everything on this link except the shortcut, and opens a new one for you to name.</p>
  <form method="post" action="/admin/links/duplicate">
    ${csrfField(dupToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="actions"><button type="submit" class="secondary">Duplicate</button></div>
  </form>
</div>

<div class="card">
  <h2>Delete</h2>
  <p class="hint">This cannot be undone. The shortcut becomes available again.</p>
  <form method="post" action="/admin/links/delete" data-confirm="Delete ${esc(host)}/${esc(link.path)}?">
    ${csrfField(delToken)}${hidden('host', host)}${hidden('path', pathLc)}
    <div class="actions"><button type="submit" class="danger">Delete link</button></div>
  </form>
</div>`;

  // The editor renders the card's image, which is an arbitrary https URL.
  return adminPage(ctx, { title: link.path, nav: 'links', body, externalImages: true });
}

/**
 * The edit screen reduced to its Owner card, for an administrator who may
 * reassign this link but is not scoped to manage what is inside it.
 */
async function ownershipOnlyPage(ctx, { host, pathLc, link, error, info }) {
  const moveToken = await formToken(ctx, 'link.transfer');
  const body = `
${flashFrom(ctx.url)}${alert('error', error)}${alert('ok', info)}
<h1>${esc(host)}/${esc(link.path)}</h1>
<p class="sub">You are not scoped to this directory, so only ownership is yours to change here.</p>

<div class="card">
  <h2>Owner</h2>
  <p class="hint">Currently ${esc(link.ownerEmail || 'unassigned')}. Transferring hands over the right to edit and delete it.</p>
  <form method="post" action="/admin/links/transfer">
    ${csrfField(moveToken)}${hidden('host', host)}${hidden('path', pathLc)}
    ${field({ name: 'owner', label: 'New owner email', type: 'email', value: '', required: true, placeholder: 'colleague@example.com' })}
    <div class="actions"><button type="submit" class="secondary">Transfer</button></div>
  </form>
</div>

<div class="actions"><a class="btn secondary" href="/admin/links">Back</a></div>`;
  return adminPage(ctx, { title: link.path, nav: 'links', body });
}

/** Move a link to a different domain. */
async function moveSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.move', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  const toHost = String(body.get('toHost') || '').toLowerCase();
  const result = await moveLink(ctx.cfg, {
    user: ctx.session.user,
    link,
    toHost,
    rawPath: body.get('newpath') || link.path,
  });
  if (!result.ok) return editForm(ctx, { error: result.error });

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkUpdated,
      actor: ctx.session.user,
      host: toHost,
      ip: clientIp(ctx.request),
      object: result.link.pathLc,
      detail: { movedFrom: result.from },
    })
  );
  return back(linkEditHref(toHost, result.link.pathLc), 'link.moved2');
}

/**
 * Accept the uploaded centre image, or remove the stored one.
 *
 * This is the only multipart endpoint here, so it reads the body itself
 * rather than through readForm, which deliberately refuses anything that
 * is not a urlencoded form. The declared length is checked before the body
 * is buffered, and the bytes are sniffed afterwards: see qrlogo.js for why
 * the format matters rather than the file name.
 */
async function qrLogoSubmit(ctx) {
  // A little headroom over the image limit for the multipart envelope.
  const body = await readFormWithFiles(ctx.request, { maxBytes: MAX_LOGO_BYTES + 16 * 1024 });
  if (!body) return back('/admin/links', 'qr.toobig');

  const guard = await checkCsrf(ctx, 'link.qrlogo', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  if (body.get('remove')) {
    link.qrLogo = null;
    await putLink(ctx.cfg, link);
    return back(linkEditHref(host, pathLc), 'qr.removed');
  }

  const file = body.get('image');
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    return editForm(ctx, { error: 'Choose an image file to upload.' });
  }
  if (file.size > MAX_LOGO_BYTES) {
    return editForm(ctx, {
      error: `That image is ${Math.ceil(file.size / 1024)} KB. The limit is ${MAX_LOGO_BYTES / 1024} KB.`,
    });
  }
  const made = makeLogo(new Uint8Array(await file.arrayBuffer()));
  if (!made.ok) return editForm(ctx, { error: made.error });

  link.qrLogo = made.logo;
  await putLink(ctx.cfg, link);
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { qrLogo: made.logo.type, bytes: made.logo.bytes },
    })
  );
  return back(linkEditHref(host, pathLc), 'qr.uploaded');
}

/** Set, change or clear a link's password. */
async function passwordSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.password', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  const dir = await governingDirectory(ctx.cfg, host, pathLc);
  const may = capabilityAllowed(ctx.cfg, 'password', {
    user: ctx.session.user,
    domain: await resolveDomain(ctx.cfg, host),
    dir,
  });
  // Clearing a password is always allowed, even where setting one is not:
  // a capability withdrawn later must not strand a link behind a prompt.
  const raw = String(body.get('password') || '');
  if (raw && !may.allowed) return denied(ctx, may.reason || 'Not permitted here.');

  // Where the stored password cannot be read, the field rendered empty.
  // Treating that as "clear it" would unprotect the link by accident, so
  // removing it has to be said out loud.
  if (!raw && hasPassword(link) && !(await readPassword(ctx.cfg, link)) && !body.get('confirmClear')) {
    return editForm(ctx, {
      error:
        'That password cannot be read with the current AUTH_SECRET, so saving an empty field was ' +
        'refused rather than silently removing it. Type a new password, or tick the box to remove it.',
    });
  }

  const result = await setPassword(ctx.cfg, link, raw);
  if (!result.ok) return editForm(ctx, { error: result.error });
  await putLink(ctx.cfg, link);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      // Never the password itself, only whether there is now one.
      detail: { password: result.cleared ? 'cleared' : 'set' },
    })
  );
  return back(linkEditHref(host, pathLc), result.cleared ? 'link.unlocked' : 'link.locked');
}

async function editSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.update', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  const domain = await resolveDomain(ctx.cfg, host);

  // The directory is a picker on this screen too. A post without one keeps
  // the link where it is, so a caller that only means to change the
  // destination cannot move it by omission.
  const at = splitPath(link.pathLc);
  const place = body.get('dir') ? parsePlace(String(body.get('dir'))) : { host, dirPathLc: at.dirPathLc };
  const bad = (message) => {
    ctx.url.searchParams.set('host', host);
    ctx.url.searchParams.set('path', pathLc);
    return editForm(ctx, { error: message });
  };
  if (place.host !== host) {
    return bad(`That directory is on ${place.host}. Use "Move to another domain" to change domain.`);
  }
  if (place.dirPathLc && place.dirPathLc !== at.dirPathLc &&
      !(await getDirectory(ctx.cfg, host, place.dirPathLc))) {
    return bad('That directory no longer exists.');
  }

  let parsed;
  let destination;
  let expiresAt;
  let activeFrom;
  try {
    parsed = parsePath(
      joinPath(place.dirPathLc, parseSegment(body.get('newpath') || at.segment)),
      { reserved: reservedFor(ctx, host) }
    );
    destination = parseDestination(body.get('target'), {
      blockedSchemes: ctx.cfg.settings.blockedSchemes,
    });
    expiresAt = parseExpiry(body.get('expires'));
    activeFrom = parseActiveFrom(body.get('activeFrom'));
    checkWindow(activeFrom, expiresAt);
    cleanRouting(readRouting(body), { blockedSchemes: ctx.cfg.settings.blockedSchemes });
  } catch (err) {
    if (err instanceof ValidationError) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: err.message });
    }
    throw err;
  }

  const renamed = parsed.pathLc !== link.pathLc;
  if (renamed) {
    // A rename is a create at the new path, so it needs create permission there.
    const mayPlace = await canCreate(ctx.cfg, {
      user: ctx.session.user,
      domain,
      host,
      pathLc: parsed.pathLc,
      pending: pendingUnder(ctx, K.dirPrefix(host, '')),
    });
    if (!mayPlace.allowed) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: mayPlace.reason });
    }
    if (await getLink(ctx.cfg, host, parsed.pathLc)) {
      return bad('That shortcut is already in use.');
    }
    // Create refuses to put a link where a directory already is; a rename
    // has to refuse it too, or the directory and the link would both claim
    // the same path.
    if (await getDirectory(ctx.cfg, host, parsed.pathLc)) {
      return bad('A directory already uses that path.');
    }
  }

  const before = { target: link.target, status: link.status, delay: link.delay, path: link.path };
  const oldPathLc = link.pathLc;

  link.path = parsed.path;
  link.pathLc = parsed.pathLc;
  link.target = destination.target;
  link.status = clampStatus(body.get('status'), link.status);
  link.delay = clampDelay(body.get('delay'), link.delay);
  // Only record a choice where one is actually permitted, so a locked
  // setting cannot be smuggled in by hand-posting the form.
  const dir = await governingDirectory(ctx.cfg, host, pathLc);
  const policy = policyFor(domain, dir);
  const effective = resolveLink(policy, link, userExemption(ctx.session.user, host));
  link.countdown = effective.countdownLocked ? null : readChoice(body, 'countdown');
  link.showTarget = effective.targetLocked ? null : readChoice(body, 'showTarget');
  link.routing = cleanRouting(readRouting(body), {
    blockedSchemes: ctx.cfg.settings.blockedSchemes,
  });
  if (previewBlockedReason(domain)) {
    link.preview = emptyPreview();
  } else {
    const img = String(body.get('previewImage') || '').trim();
    if (img && !/^https:\/\//i.test(img)) {
      ctx.url.searchParams.set('host', host);
      ctx.url.searchParams.set('path', pathLc);
      return editForm(ctx, { error: 'The preview image must be an https URL.' });
    }
    link.preview = normalizePreview({
      enabled: body.get('previewEnabled') === '1',
      title: body.get('previewTitle'),
      description: body.get('previewDescription'),
      image: img,
    });
  }
  link.note = String(body.get('note') || '').slice(0, 500);
  // Same reasoning as on create: a flag only lands if the capability holds.
  link.frame = capabilityAllowed(ctx.cfg, 'frame', {
    user: ctx.session.user,
    domain,
    dir: await governingDirectory(ctx.cfg, host, pathLc),
  }).allowed
    ? normalizeFrame(readFrame(body))
    : link.frame || {};
  link.activeFrom = activeFrom;
  link.expiresAt = expiresAt;
  link.enabled = body.get('enabled') === '1';
  link.forwardQuery = body.get('forwardQuery') === '1';
  if (canSetReadonly(ctx.cfg, ctx.session.user)) link.readonly = body.get('readonly') === '1';

  if (renamed) {
    await deleteLink(ctx.cfg, { ...link, pathLc: oldPathLc });
    await noteLink(ctx, { ...link, pathLc: oldPathLc }, { gone: true });
  }
  await putLink(ctx.cfg, link);
  if (renamed) await noteLink(ctx, link);

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkUpdated,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: link.pathLc,
      detail: { before, after: { target: link.target, status: link.status, delay: link.delay, path: link.path } },
    })
  );
  return back(linkEditHref(host, link.pathLc), 'link.updated');
}

async function deleteSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.delete', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  await deleteLink(ctx.cfg, link);
  await noteLink(ctx, link, { gone: true });
  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkDeleted,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { target: link.target },
    })
  );
  return back('/admin/links', 'link.deleted');
}

async function transferSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.transfer', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const link = await getLink(ctx.cfg, host, pathLc);
  if (!link) return back('/admin/links', 'notfound');

  const permit = await canTransferLink(ctx.cfg, { user: ctx.session.user, link, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  ctx.url.searchParams.set('host', host);
  ctx.url.searchParams.set('path', pathLc);

  let parsedEmail;
  try {
    parsedEmail = normalizeEmail(body.get('owner'), ctx.cfg.emailOpts);
  } catch (err) {
    if (err instanceof ValidationError) return editForm(ctx, { error: err.message });
    throw err;
  }

  // Whose addresses may be handed something on this host, narrowed by the
  // directory that owns the path. Checked before the account is created, so
  // a refused address leaves nothing behind.
  const invite = inviteAllowed(ctx.cfg, {
    domain: await resolveDomain(ctx.cfg, host),
    dir: await governingDirectory(ctx.cfg, host, pathLc),
    emailNorm: parsedEmail.emailNorm,
  });
  if (!invite.allowed) return editForm(ctx, { error: invite.reason });

  const invited = await inviteUser(ctx.cfg, {
    email: parsedEmail.email,
    emailNorm: parsedEmail.emailNorm,
    invitedBy: ctx.session.user,
  });
  const recipient = invited.user;
  if (!recipient) {
    return editForm(ctx, {
      error: 'No such user. They must sign in once before a link can be transferred to them.',
    });
  }

  const domain = await resolveDomain(ctx.cfg, host);
  const mayReceive = await canReceiveTransfer(ctx.cfg, {
    actor: ctx.session.user,
    recipient,
    domain,
    host,
    pathLc,
  });
  if (!mayReceive.allowed) {
    return editForm(ctx, { error: 'That user cannot hold a link here: ' + mayReceive.reason });
  }

  const previousOwnerId = link.ownerId;
  const previousOwnerEmail = link.ownerEmail;
  link.ownerId = recipient.id;
  link.ownerEmail = recipient.emailNorm;
  await putLink(ctx.cfg, link, { previousOwnerId });

  ctx.waitUntil(
    audit(ctx.cfg, {
      event: EVENTS.linkTransferred,
      actor: ctx.session.user,
      host,
      ip: clientIp(ctx.request),
      object: pathLc,
      detail: { from: previousOwnerEmail, to: recipient.emailNorm },
    })
  );
  return back(linkEditHref(host, pathLc), 'link.moved');
}

async function duplicateSubmit(ctx) {
  const body = await readForm(ctx.request);
  if (!body) return back('/admin/links', 'csrf');
  const guard = await checkCsrf(ctx, 'link.duplicate', body);
  if (!guard.ok) return back('/admin/links', 'csrf');

  const host = String(body.get('host') || '');
  const pathLc = String(body.get('path') || '').toLowerCase();
  const source = await getLink(ctx.cfg, host, pathLc);
  if (!source) return back('/admin/links', 'notfound');

  // Duplicating reveals everything the link holds, so it needs the same
  // standing as editing it, not merely permission to create.
  const permit = await canManageLink(ctx.cfg, { user: ctx.session.user, link: source, host });
  if (!permit.allowed) return denied(ctx, permit.reason);

  return newForm(ctx, {
    info: 'Copied from ' + host + '/' + source.path + '. Give it a shortcut to save it.',
    values: {
      host,
      // The copy starts in the same directory as the original. If this
      // person cannot create there the form falls back to somewhere they
      // can, rather than offering a place the submit would refuse.
      dir: placeValue(host, splitPath(source.pathLc).dirPathLc),
      path: '',
      target: source.target,
      status: source.status,
      delay: source.delay,
      countdown: source.countdown,
      showTarget: source.showTarget,
      note: source.note,
      forwardQuery: !!source.forwardQuery,
      readonly: !!source.readonly,
      routing: source.routing,
      frame: source.frame,
      preview: source.preview,
      activeFrom: expiryInput(source.activeFrom),
      expires: expiryInput(source.expiresAt),
      // A duplicate is a copy of the link, password included. The create
      // screen shows it, and whoever is duplicating already had to be
      // allowed to manage the original to get here.
      password: await readPassword(ctx.cfg, source),
    },
  });
}

/* --------------------------------------------------------------- router */

export async function adminLinks(ctx, path) {
  const method = ctx.request.method;
  if (path === '/admin/links') return listPage(ctx);
  if (path === '/admin/links/new') return method === 'POST' ? createSubmit(ctx) : newForm(ctx);
  if (path === '/admin/links/edit') return method === 'POST' ? editSubmit(ctx) : editForm(ctx);
  if (path === '/admin/links/delete' && method === 'POST') return deleteSubmit(ctx);
  if (path === '/admin/links/transfer' && method === 'POST') return transferSubmit(ctx);
  if (path === '/admin/links/duplicate' && method === 'POST') return duplicateSubmit(ctx);
  if (path === '/admin/links/qr') return qrSvg(ctx);
  if (path === '/admin/links/password' && method === 'POST') return passwordSubmit(ctx);
  if (path === '/admin/links/qrlogo' && method === 'POST') return qrLogoSubmit(ctx);
  if (path === '/admin/links/move' && method === 'POST') return moveSubmit(ctx);
  return back('/admin/links');
}
