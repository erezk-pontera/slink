/**
 * interstitial.js - policy for the countdown page shown before a redirect.
 *
 * The policy is set at three levels and resolved in order: domain, then
 * directory, then the individual link. A level may only ever *narrow* what
 * the level above allows, so an administrator who locks a setting on a
 * domain cannot have it loosened underneath them.
 *
 * Each switch is three-state, which is what makes locking possible:
 *
 *   countdown   'off'      never shown, and nothing below may turn it on
 *               'optional' shown or not per link, defaulting to defaultOn
 *               'required' always shown, and nothing below may turn it off
 *
 *   destination 'hide'     never displayed, and nothing below may show it
 *               'optional' per link, defaulting to defaultShowTarget
 *               'show'     always displayed, and nothing below may hide it
 *
 * `minDelay` is a floor that a lower level may raise but never lower.
 *
 * Narrowing is the rule, and exemptions are the exception. A directory
 * administrator may always make their directory stricter than the domain.
 * To let them go the other way - to set something the domain policy forbids -
 * a Shrink Link administrator grants that directory an exemption on the
 * specific setting. Each exemption is per directory and per setting, so
 * opening one does not open the rest.
 *
 * A user may be exempted too, either globally or on named domains, which
 * lets that person set link options the policy would otherwise lock. A link
 * is served according to its *owner's* exemptions, so withdrawing someone's
 * exemption immediately pulls their links back under the policy rather than
 * leaving a permanent hole behind.
 */

export const COUNTDOWN_MODES = ['off', 'optional', 'required'];
export const TARGET_MODES = ['hide', 'optional', 'show'];
export const MAX_DELAY = 60;

/** The query flag that skips a countdown the visitor has already seen. */
export const GO_PARAM = 'slink-go';

/**
 * The shipped default: a countdown is offered and shown unless a link opts
 * out, the destination is visible, and nothing is locked.
 */
export function defaultPolicy(overrides = {}) {
  return {
    countdown: 'optional',
    defaultOn: true,
    defaultDelay: 5,
    minDelay: 0,
    destination: 'optional',
    defaultShowTarget: true,
    /** May directory administrators set their own policy inside a directory? */
    delegate: false,
    ...overrides,
  };
}

function clampDelay(value, fallback, min = 0) {
  const n = Number.parseInt(value, 10);
  const base = Number.isFinite(n) && n >= 0 ? n : fallback;
  return Math.min(MAX_DELAY, Math.max(min, base));
}

/** Normalise a stored or submitted policy, filling anything absent. */
export function normalizePolicy(raw, base = defaultPolicy()) {
  const p = raw && typeof raw === 'object' ? raw : {};
  const minDelay = clampDelay(p.minDelay, base.minDelay);
  return {
    countdown: COUNTDOWN_MODES.includes(p.countdown) ? p.countdown : base.countdown,
    defaultOn: p.defaultOn === undefined ? base.defaultOn : !!p.defaultOn,
    defaultDelay: clampDelay(p.defaultDelay, base.defaultDelay, minDelay),
    minDelay,
    destination: TARGET_MODES.includes(p.destination) ? p.destination : base.destination,
    defaultShowTarget:
      p.defaultShowTarget === undefined ? base.defaultShowTarget : !!p.defaultShowTarget,
    delegate: p.delegate === undefined ? base.delegate : !!p.delegate,
  };
}

/**
 * Apply a lower level's policy on top of a higher one. Locks survive, floors
 * only rise, and anything the lower level leaves unset is inherited.
 */
export function narrow(base, override, rawExempt) {
  if (!override) return base;
  const exempt = normalizeExempt(rawExempt);
  const locked = (base.countdown === 'off' || base.countdown === 'required') && !exempt.countdown;
  const targetLocked =
    (base.destination === 'hide' || base.destination === 'show') && !exempt.destination;
  // An exempted directory may set any floor, including a lower one.
  const minDelay = exempt.minDelay
    ? clampDelay(override.minDelay, base.minDelay)
    : Math.max(base.minDelay, clampDelay(override.minDelay, base.minDelay));
  return {
    countdown: locked
      ? base.countdown
      : COUNTDOWN_MODES.includes(override.countdown)
        ? override.countdown
        : base.countdown,
    defaultOn: override.defaultOn === undefined ? base.defaultOn : !!override.defaultOn,
    defaultDelay: clampDelay(override.defaultDelay, base.defaultDelay, minDelay),
    minDelay,
    destination: targetLocked
      ? base.destination
      : TARGET_MODES.includes(override.destination)
        ? override.destination
        : base.destination,
    defaultShowTarget:
      override.defaultShowTarget === undefined
        ? base.defaultShowTarget
        : !!override.defaultShowTarget,
    // Delegation is the domain's call; a directory cannot widen its own reach.
    delegate: base.delegate,
  };
}

/** The settings a directory may be exempted from, one flag each. */
export const EXEMPTIBLE = ['countdown', 'destination', 'minDelay'];

/** Normalise a directory's exemption flags. */
export function normalizeExempt(raw) {
  const e = raw && typeof raw === 'object' ? raw : {};
  const out = {};
  for (const key of EXEMPTIBLE) out[key] = !!e[key];
  return out;
}

export function hasAnyExemption(exempt) {
  return EXEMPTIBLE.some((k) => exempt && exempt[k]);
}

/** The wildcard key meaning "on every domain". */
export const ANY_HOST = '*';

/**
 * A user's effective exemptions on one host: the global grant, plus anything
 * granted for that host specifically.
 */
export function userExemption(user, host) {
  const table = (user && user.interstitialExempt) || {};
  const global = normalizeExempt(table[ANY_HOST]);
  const perHost = normalizeExempt(table[host]);
  const out = {};
  for (const key of EXEMPTIBLE) out[key] = global[key] || perHost[key];
  return out;
}

/** Merge two exemption sets; either granting a setting opens it. */
export function mergeExempt(a, b) {
  const x = normalizeExempt(a);
  const y = normalizeExempt(b);
  const out = {};
  for (const key of EXEMPTIBLE) out[key] = x[key] || y[key];
  return out;
}

/**
 * May a directory administrator set a policy inside this directory? Either
 * the domain delegates generally, an administrator enabled this directory
 * specifically, or an administrator granted it an exemption, which is itself
 * a decision that this directory may differ.
 */
export function directoryMayOverride(domainPolicy, dir) {
  if (!dir) return false;
  return !!(
    domainPolicy.delegate ||
    dir.allowInterstitialOverride ||
    hasAnyExemption(normalizeExempt(dir.interstitialExempt))
  );
}

/**
 * The policy that governs a path, after the domain and any owning directory
 * have both had their say.
 */
export function policyFor(domain, dir) {
  const base = normalizePolicy(domain && domain.interstitial, defaultPolicy());
  if (dir && dir.interstitial && directoryMayOverride(base, dir)) {
    return narrow(base, dir.interstitial, dir.interstitialExempt);
  }
  return base;
}

/**
 * What a particular link actually does. Returns the resolved behaviour plus
 * which parts the link is not allowed to change, so the editor can show them
 * as fixed rather than pretending they are editable.
 */
export function resolveLink(policy, link, rawExempt) {
  const exempt = normalizeExempt(rawExempt);
  const countdownLocked = policy.countdown !== 'optional' && !exempt.countdown;
  const targetLocked = policy.destination !== 'optional' && !exempt.destination;
  const minDelay = exempt.minDelay ? 0 : policy.minDelay;

  let show;
  if (countdownLocked) {
    show = policy.countdown === 'required';
  } else if (link && link.countdown !== undefined && link.countdown !== null) {
    show = !!link.countdown;
  } else if (link && Number.isFinite(link.delay) && link.delay > 0) {
    // Setting a delay is itself a request for a countdown.
    show = true;
  } else {
    show = policy.defaultOn;
  }

  let delay = 0;
  if (show) {
    const chosen =
      link && Number.isFinite(link.delay) && link.delay > 0 ? link.delay : policy.defaultDelay;
    // A countdown of zero is not a countdown; one second is the floor.
    delay = Math.max(1, minDelay, Math.min(MAX_DELAY, chosen));
  }

  let showTarget;
  if (targetLocked) {
    showTarget = policy.destination === 'show';
  } else if (link && link.showTarget !== undefined && link.showTarget !== null) {
    showTarget = !!link.showTarget;
  } else {
    showTarget = policy.defaultShowTarget;
  }

  return { show, delay, showTarget, countdownLocked, targetLocked, minDelay };
}

/**
 * Does this link rely on an exemption to behave as stored? Used on the
 * redirect path to decide whether the owner's grants need loading at all,
 * which keeps the common case at zero extra reads.
 */
export function needsExemption(policy, link) {
  if (!link) return false;
  if (policy.countdown !== 'optional') {
    const forced = policy.countdown === 'required';
    if (link.countdown !== undefined && link.countdown !== null && !!link.countdown !== forced) {
      return true;
    }
  }
  if (policy.destination !== 'optional') {
    const forced = policy.destination === 'show';
    if (link.showTarget !== undefined && link.showTarget !== null && !!link.showTarget !== forced) {
      return true;
    }
  }
  if (policy.minDelay > 0 && Number.isFinite(link.delay) && link.delay > 0 && link.delay < policy.minDelay) {
    return true;
  }
  return false;
}

/** A short sentence describing a policy, for the admin screens. */
export function describePolicy(policy) {
  const parts = [];
  if (policy.countdown === 'off') parts.push('Countdown off, and links cannot turn it on');
  else if (policy.countdown === 'required') parts.push('Countdown always shown');
  else parts.push(`Countdown optional, ${policy.defaultOn ? 'on' : 'off'} by default`);

  if (policy.countdown !== 'off') {
    parts.push(`${policy.defaultDelay}s by default`);
    if (policy.minDelay > 0) parts.push(`never under ${policy.minDelay}s`);
    if (policy.destination === 'show') parts.push('destination always shown');
    else if (policy.destination === 'hide') parts.push('destination never shown');
    else parts.push(`destination ${policy.defaultShowTarget ? 'shown' : 'hidden'} by default`);
  }
  return parts.join(', ') + '.';
}
