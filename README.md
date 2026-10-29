# slink

A short-link service for **ptra.cc** and **ptra.dev**, running as a single
Cloudflare Worker backed by one KV namespace.

- `ptra.cc/aaa` — public short links, redirecting immediately or after a
  countdown, with a redirect code you choose.
- `ptra.dev/bbb` — the same, but every link requires a verified sign-in.
- `ptra.dev/admin` — manage links, directories, domains, users and settings,
  and the one place a sign-in form is ever shown.

The admin area spans every domain by default. A picker beside the name in the
header switches between **All Domains** and a single host, and carries the
other filters with it; pages that act on one record do not show it, because
changing the domain there would point at something else.

Apex and `www.` are the same host everywhere. A request to `www.` is
redirected to the apex before anything else runs, so `www.ptra.dev/bbb` and
`ptra.dev/bbb` are one link and one session. (Cookies here are `__Host-`
prefixed, which binds them to an exact hostname; redirecting is what makes
the two hosts genuinely interchangeable without weakening that.)

A host root, an unknown shortcut, and one that is disabled or expired all
lead to the same place: the `MISSING` URL, overridable per host. None of them
shows a sign-in button — administration is reached by going to `/admin` on
the hub and nowhere else.

---

## How it fits together

| File | Responsibility |
| --- | --- |
| `index.js` | Worker entry point and top-level router |
| `logo.js` | The brand mark as a string, mirroring `logo.svg` |
| `config.js` | Environment variables, admin-editable settings, fail-closed checks |
| `kv.js` | The KV key space, JSON access, prefix listing, counters |
| `paths.js` | Shortcut, destination and email validation and normalisation |
| `security.js` | HMAC key derivation, tokens, cookies, CSRF, response headers |
| `auth.js` | Sessions, the sign-in flow, cross-host SSO, sign-out |
| `otp.js` | Generating, hashing and verifying the one-time code |
| `mailer.js` | Delivering the code (Cloudflare Email Sending, plus alternatives) |
| `turnstile.js` | Widget markup and siteverify |
| `geo.js` | Tor and country policy |
| `ratelimit.js` | KV-backed throttles |
| `permissions.js` | Every authorisation decision |
| `users.js`, `domains.js`, `directories.js`, `links.js` | Records and their indexes |
| `redirect.js` | Shortcut resolution, redirects, the delay interstitial |
| `admin.js` + `admin-links.js`, `admin-directories.js`, `admin-domains.js`, `admin-users.js` | The admin area |
| `views.js`, `assets.js` | HTML, CSS, the favicon and the one client-side script |
| `audit.js` | Append-only activity log |

Everything is plain ES modules with no runtime dependencies.

---

## Storage

One KV namespace holds the lot. Keys are laid out so that a prefix listing
answers every query the admin area needs, and so index entries carry a
summary in their KV metadata — listing a user's links costs one `list` call,
not one read per row.

```
cfg                              global settings (admin editable)
dom:<host>                       domain policy
usr:<emailNorm>                  user, keyed by normalised address
uid:<userId>                     userId -> emailNorm
lnk:<host>:<pathLc>              link
own:<userId>:<host>:<pathLc>     owner index   (metadata: link summary)
dir:<host>:<pathLc>              directory
grt:<host>:<dirPathLc>:<userId>  directory grant
ugr:<userId>:<host>:<dirPathLc>  reverse grant index
ses:<sidHash>                    session (TTL)
uss:<userId>:<sidHash>           per-user session index, for sign-out-everywhere
otp:<loginId>                    sign-in challenge (TTL)
rl:<bucket>                      rate-limit counter (TTL)
cnt:<host>:<pathLc>              approximate hit counter
aud:<invertedTs>:<rand>          audit entry (TTL, newest first)
```

Links inside a directory need no index of their own: a link under `pub` has a
path beginning `pub/`, so listing the `lnk:<host>:pub/` prefix finds them.

**Consistency.** KV is eventually consistent and reads are edge-cached.
Administrative reads bypass the cache so an operator always sees their own
writes; the redirect hot path accepts a short cache window in exchange for
latency. A change to a link can take up to a minute to be visible from a
distant location.

**Hit counts are approximate.** KV permits roughly one write per second per
key, so concurrent hits on a popular link undercount. Treat the figure as a
usage signal, not analytics. It can be switched off in settings.

---

## Permissions

| Who | What they can do |
| --- | --- |
| Root administrator (`ADMIN` env var) | Everything, on every domain, unconditionally. Not listed in `/admin/users` and not editable, disablable or deletable from anywhere in the UI — change `ADMIN` and redeploy instead. |
| Administrator (flag set by an admin) | Everything, on every domain. No grant narrows an administrator, and the UI says so rather than showing an empty grant list. |
| Directory administrator (`manage` grant) | Everything inside their directory, including other people's links, plus granting and revoking access to it. |
| Granted user (`create` grant) | Create links inside that directory; edit and delete only their own. |
| Signed-in user | Create at a host root if the host's policy allows; edit and delete only their own links. |

Rules that override the table:

- **Only the creator may modify, delete or transfer a link.** Administrators
  and the relevant directory administrator are the exceptions.
- **Read-only beats ownership.** A link or directory marked read-only can only
  be changed by an administrator — not by its owner, not by a directory
  administrator. Only administrators can set or clear the flag.
- **A transfer must land somewhere legal.** The recipient must be able to
  create at that path, unless an administrator performs the transfer.
- **Renaming is a create.** Moving a link to a new path requires create
  permission at the new path.

**Creating directories** is a separate, per-user and per-domain grant
(`/admin/users` → *May create directories* for each domain). Administrators
always have it. A directory administrator may nest directories inside the
directory they administer, and may pass that on by making someone else a
directory administrator there. Whoever creates a directory becomes its
administrator automatically.

**Ownership** can be handed over for both links and directories. A link's
owner, the administrator of the directory holding it, or any administrator
may transfer it; the recipient must be able to create at that path unless an
administrator does the transfer. A directory's owner or any administrator may
transfer it, and the new owner is made a directory administrator so they can
run what they now own. Read-only puts either case in administrators' hands
alone.

Root-level creation on a host is governed by its `rootCreatePolicy`:
`email_domain` (the default — the host's allow list, falling back to
`DEFAULT_ALLOWED_DOMAINS`, or an explicit per-user grant), `explicit`,
`open`, or `admins_only`.

---

## Sign-in

The form lives at `/admin` on the hub and nowhere else. `/login`,
`/login/verify` and `/login/resend` remain as bookmarks that redirect there.
Both stages post back to `/admin`, distinguished by a hidden `stage` field, so
there is no second URL where a form appears.

1. `/admin` takes an email address, behind Turnstile.
2. The address is normalised and checked against the host's allowed sign-in
   domains. Tor exits and unlocatable clients are refused.
3. A six-digit code is emailed. It is never stored: KV holds an HMAC of the
   code bound to a per-challenge salt and to the login id in the browser's
   cookie, so a code only works in the browser that asked for it.
4. `/admin` then takes the code, also behind Turnstile. Attempts are counted
   on the challenge itself, and the challenge is deleted once spent.
5. A session is created. Accounts are created on first successful sign-in, so
   the sign-in form reveals nothing about who already has an account.

`/logout` asks for confirmation and then signs the user out of **every** host,
by revoking every session they hold.

**Across hosts.** Only `ptra.dev` serves `/admin`. Another host
that requires sign-in bounces the visitor through a signed, nonce-bound,
two-minute handshake on the hub, so one sign-in covers every host. The token
names the host it was minted for and is useless anywhere else.

Session lifetime is `SESSION_TTL_SECONDS`, or effectively permanent with
`SESSION_PERMANENT=true`. An optional idle timeout, and optional binding to
the user-agent or client IP, are in `/admin/settings`.

### Passkeys

A signed-in account can enrol a passkey at `/admin/passkeys` and sign in with
it afterwards, skipping the emailed code. WebAuthn is implemented here with no
dependencies: a small CBOR decoder (`cbor.js`), the verification layer
(`webauthn.js`), and storage and policy (`passkeys.js`).

- **Relying party.** The id is the hub host, so one credential covers every
  host; the others reach the hub through the handshake above. The endpoints
  are served on the hub alone.
- **Algorithms.** ES256 and RS256, both verified with WebCrypto. Attestation
  is `none`: which make of key somebody owns is not this service's business,
  but the authenticator data inside it is parsed and checked in full.
- **Challenges** are signed tokens rather than stored records, good for five
  minutes, bound to the browser that asked and - for registration - to the
  account that asked. Nothing is written for an abandoned attempt.
- **A credential belongs to one account.** Re-registering an existing one is
  refused rather than moving it, and deleting an account deletes its keys.
- **A passkey is personal.** Only the account holding one can list, rename or
  remove it; an administrator cannot, and an impersonated view sees none of
  it. Someone locked out is helped with the emailed code.
- **Clone detection.** A sign counter that fails to advance is recorded on the
  credential and flagged on the page rather than refused, because plenty of
  authenticators keep no counter at all.
- **Never the only way in.** The emailed code always remains, and an
  administrator keeps every method whatever a domain's policy says.
- **Progressive.** The buttons stay hidden until the script has confirmed the
  browser supports WebAuthn, so nothing is offered that cannot work.

`Permissions-Policy` allows `publickey-credentials-create` and
`publickey-credentials-get` to `self` and nothing else, which is what lets the
hub's own pages use WebAuthn while still refusing to delegate it to an
embedded cross-origin page.

### Single sign-on

OAuth 2.0 Authorization Code with PKCE (S256). **One provider for the whole
installation**, configured in `/admin/settings` — not per domain. Signing in
happens on the hub and every other host arrives through the handshake above,
so a provider enabled on one domain and not another was a distinction
without a difference. What *is* per domain is whether that host also offers
the emailed code and passkeys, which stays on the domain screen.

The client secret is the `oauth-secret` environment variable and is sent only
in a token-exchange request body, never in a URL. Endpoints must be HTTPS and
are refused if they resolve to a private address, because they are fetched
with that secret attached. The redirect URI is
`https://<host>/__slink/oauth/callback`, registered once per host.

**The provider says who, never what.** Letting somebody through its sign-in
establishes an address and nothing else: they become an ordinary account
here. No role, group or privilege is read from the provider, and the
provider's own "verified" flag is not consulted either — whether that
address may sign in is decided on this side by the host's allowed sign-in
domains, and what it may do is decided by its own record. Making somebody an
administrator is done in `/admin/users` and nowhere else.

---

## Turnstile

The widget already exists; nothing here creates or rotates one. The sitekey is
a plain var, the secret is a Worker secret, and the secret is only ever sent
to siteverify in a POST body.

A token is accepted only when `success` is true **and** the returned `action`
matches the form that was submitted (`login` or `otp`) **and** the returned
`hostname` is one of this deployment's hosts. Production never allow-lists
`localhost`. Tokens are single use; every failure re-renders the page, which
mounts a fresh widget.

### Content Security Policy

`script-src` is `'self' https://challenges.cloudflare.com` with no
`'unsafe-inline'` and no nonce, because the app emits **no inline script at
all** — the stylesheet and the single script are same-origin files, and
page-specific values reach the client through `data-` attributes.

`style-src` does include `'unsafe-inline'`, because Turnstile styles the
container it injects. Every value this app writes into HTML is escaped, so
nothing user-supplied can reach a style attribute; script execution, the risk
that matters, stays locked down.

---

## Configuration

Set in `wrangler.toml` under `[vars]`:

| Variable | Meaning |
| --- | --- |
| `DOMAINS` | Hosts the worker serves, comma separated |
| `HUB_HOST` | The host carrying `/admin`, `/login` and `/logout` |
| `APP_NAME` | Name shown in the UI and in emails (default `Shrink Link`) |
| `ADMIN` | Root administrator addresses, comma separated |
| `DEFAULT_ALLOWED_DOMAINS` | Default email domains for signing in and for creating at a host root |
| `MISSING` | Where a host root, an unknown shortcut, or a disabled or expired one goes, unless a domain overrides it |
| `IGNORE_EMAIL_DOT` | `true` strips every `.` from the local part |
| `IGNORE_EMAIL_PLUS` | `true` drops everything from `+` up to `@` |
| `turnstile-sitekey` | The existing widget's sitekey (public) |
| `MAIL_PROVIDER` | `cloudflare` (default), `resend`, `sendgrid`, `postmark`, `mailgun`, `log` |
| `MAIL_FROM` | Sender address, on an onboarded Email Sending domain |
| `OTP_TTL_SECONDS`, `OTP_LENGTH`, `OTP_MAX_ATTEMPTS` | Code defaults |
| `SESSION_TTL_SECONDS`, `SESSION_PERMANENT` | Session defaults |

Secrets, set with `wrangler secret put` (never in the config file):

| Secret | Meaning |
| --- | --- |
| `AUTH_SECRET` | Master key for sessions, CSRF, SSO and OTP hashes. At least 32 characters. |
| `turnstile-secret` | The existing widget's secret |

With both `IGNORE_EMAIL_DOT` and `IGNORE_EMAIL_PLUS` on, `A.A+weekly@CC.com`
and `aa@cc.com` are the same account. The address first used to sign in is
kept for display; the normalised form is the identity.

Everything an administrator may change at runtime lives in `/admin/settings`
and overrides the matching variable. Secrets are never editable there.

---

## Deploying

```sh
npm install

# 1. Secrets. Each reads from standard input, so the value never appears in
#    your shell history or in a process list.
wrangler secret put AUTH_SECRET          # e.g. openssl rand -base64 48
wrangler secret put turnstile-secret     # the existing widget's secret

# 2. Put the widget's sitekey into wrangler.toml under [vars], and check that
#    ADMIN and DEFAULT_ALLOWED_DOMAINS are right.

# 3. Deploy.
wrangler deploy
```

The KV binding in `wrangler.toml` already points at the existing namespaces
(`slink` for production, `slink-dev` for preview). The four routes cover apex
and `www` on both zones.

On the first request the worker seeds a policy record for each host in
`DOMAINS`: the hub requires sign-in, the others do not. Adjust them in
`/admin/domains`.

Check it came up with `curl https://ptra.dev/health` — it reports only whether
configuration is complete; the names of anything missing go to the log, so use
`wrangler tail` while setting up.

### Where visitors end up when there is nothing to show

Three cases share one destination:

| Request | Goes to |
| --- | --- |
| A host root (`ptra.cc/`, `ptra.dev/`, and their `www.` forms) | the domain's **Where / goes**, else `MISSING` |
| An unknown shortcut | the domain's **Where unknown … go**, else `MISSING` |
| A shortcut that is disabled or expired | the same as unknown |

`MISSING` is an environment variable in `wrangler.toml`. Each domain can
override both cases in `/admin/domains`, and the override wins. If neither is
set, a small page is rendered instead — carrying no sign-in button, because a
short-link host should not advertise that an administration area exists.

The root is answered **before** the sign-in gate. That is deliberate: it means
`ptra.dev/` redirects like any other host rather than demanding a sign-in from
a passer-by. Everything below the root on an authenticated host still requires
a session.

`MISSING` runs through the same destination rules as any link, so a value with
a dangerous scheme is refused at startup and logged rather than served.

### Wrangler versus the dashboard

`keep_vars = true` is set in `wrangler.toml`. This is what each kind of
change survives a `wrangler deploy`:

| Changed in the dashboard | What a deploy does to it |
| --- | --- |
| A var that exists **only** in the dashboard | **Kept**, because of `keep_vars = true` |
| A var also declared in `[vars]` | **Overwritten** from `wrangler.toml`, every deploy |
| A secret (`AUTH_SECRET`, `turnstile-secret`) | **Kept** always, even with `keep_vars` off |
| A route | **Replaced** from `wrangler.toml` |
| A KV or `send_email` binding | **Replaced** from `wrangler.toml` |

The mechanism, from Wrangler's own source: `keep_vars = true` makes it send
`keep_bindings = ["plain_text", "json"]` with the upload, so the API inherits
those binding types from the previous version instead of dropping them.
Wrangler separately hard-codes `keepSecrets: true` on every deploy — its own
comment reads "Never delete secret bindings when deploying. Inherit unchanged
secrets from the previous Worker Version, including secrets absent from
config." Nothing else is covered, which is why routes and the KV and
`send_email` bindings are still replaced wholesale.

**The part that catches people out:** `keep_vars = true` does not hand the
variables below to the dashboard. Everything listed in `[vars]` is uploaded on
every deploy and overwrites whatever the dashboard holds. Deleting a key from
`[vars]` is the only thing that hands it over — after which the dashboard is
its home and `wrangler.toml` no longer mentions it.

So, concretely: editing `ADMIN` in the dashboard still looks like it works and
is still reverted on the next deploy, because `ADMIN` is declared below. If
you want it dashboard-managed, remove it from `wrangler.toml` and set it in
the dashboard — but note that a deploy to a Worker where it has never been
set will then serve 503 until it is, by design, since the service fails
closed without a root administrator.

In practice none of this should come up often. Everything an operator changes
while running the service lives in the KV `cfg` record and is edited at
`/admin/settings`, which no deploy touches. The variables in `wrangler.toml`
are deployment-time bootstrap: which hosts exist, who the root
administrators are, the Turnstile sitekey, the mail sender. Administrators
promoted through `/admin/users` are stored in KV and survive deploys, so use
that for everyone except the bootstrap administrator in `ADMIN`.

Wrangler 4 prints a diff of local-versus-remote settings before overwriting
and offers to copy the remote values into your config; accept that rather
than dismissing it. `wrangler deploy --strict` refuses to upload when the
remote has drifted.

### Email

`MAIL_PROVIDER=cloudflare` uses the `send_email` binding. Sending to arbitrary
recipients requires the sending domain to be onboarded in Cloudflare Email
Service (and a Workers Paid plan); before that, only verified destination
addresses on the account can be reached. Email Sending is enabled for
`ptra.dev`, which is why `MAIL_FROM` defaults to `no-reply@ptra.dev`.

If delivery is refused, the error in the log distinguishes an un-onboarded
sending domain from an unverified recipient. Switching to another provider is
a `MAIL_PROVIDER` change plus that provider's API key — no code change.

### Adding a domain later

Adding a host in `/admin/domains` records its policy. It will not receive
traffic until you also add it to `DOMAINS` in `wrangler.toml`, add a Worker
route for it, and redeploy. The admin page says so when a configured domain
has no route.

---

## Shortcuts and destinations

Shortcuts use `A-Za-z0-9`, `_` and `-`, in `/`-separated segments. They are
case-insensitive: `Deck` and `deck` are the same link. Leading and trailing
slashes are ignored, so `ptra.cc/aaa/` works.

Destinations default to `https://`. An explicit scheme is kept as written,
whether hierarchical (`slack://channel?id=7`) or opaque (`mailto:x@y.com`).
A destination is stored exactly as typed - scheme, host, path, query and
fragment all keep their case, because it belongs to somebody else's service
and no part of it is ours to normalise. What is still applied is the
encoding a `Location` header needs: a space becomes `%20`, a non-ASCII host
is punycoded, a default port is dropped and `..` segments are resolved.
`javascript:`, `data:`, `vbscript:`, `blob:` and `file:` are always refused
whatever case they are typed in; more can be blocked in settings.

**The incoming query string** is dropped unless the link opts in with
*Append the incoming query string to the destination*. With it on, a
visitor's parameters are merged into the destination and the destination's
own win: a link pointing at `https://www.google.com/?a=b` sends
`?qqqq=dddd` on as `?a=b&qqqq=dddd`, while `?a=c` is discarded because the
link already says what `a` is. Two names are ours and are never forwarded:
`slink-go`, the continue flag, and `ptrap`, which is what a link password
travels under in the fragment — a fragment never reaches us, so `?ptrap=`
is always a mistyped `#`, and passing it on would put the password in the
destination's logs.

**A fragment** is never sent to a server at all. The browser keeps it and
re-attaches it after a redirect, so `ptra.cc/aa#section-3` lands on the
destination with `#section-3` still on the end, provided the destination
carries no fragment of its own. An interstitial page in the way — the
countdown, or the password prompt — ends that: its own navigation starts
fresh and the fragment stops there. That is also why `#ptrap=` is safe: the
page consumes it, clears it from the address bar, and nothing of it reaches
the destination.

Redirect codes are 301, 302 (default), 303, 307 and 308. 301 and 308
responses are cacheable for five minutes; the rest are `no-store`, so a
changed destination takes effect at once.

## Where a visitor ends up

A link always has one mandatory destination, and may carry four more: Android
phone, iPhone, Android tablet and iPad.

Resolution is deliberately simple:

1. Pick the slot for the visitor's device. A slot left blank is skipped, so
   configuring only "Android phone" is normal and everything else falls
   through.
2. Otherwise the default slot.

Destinations used to be able to branch on the visitor's country as well.
That is gone. The sign-in geography gate is a separate thing and stays.

Device class comes from `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform` where the
browser sends them, which Chromium does by default and which beats reading
the user-agent; Safari sends neither, so the user-agent is the fallback. One
honest limitation: an iPad on iPadOS 13 or later presents itself as a Mac, so
it is seen as a desktop unless the visitor asked for the mobile site.

Every URL in the table goes through the same validation as the main
destination, so a device branch cannot smuggle in a scheme the main one
forbids.

**Duplicating** a link copies everything except the shortcut and opens the
create form. It needs the same standing as editing the original, since the
copy reveals everything the original holds.

**Framing.** Any slot, the default included, can be marked to show its
destination inside a frame instead of redirecting to it. The address bar
then stays on the short link - `ptra.cc/aa` keeps reading `ptra.cc/aa`
while the destination fills the page - on the apex and on `www` alike, and
on every domain the shortcut exists on. The capability is resolved against
the link's *owner*, not the visitor, because the visitor is usually not
signed in and it is the owner's decision to make; an administrator's link
therefore keeps framing when a domain withdraws the capability from
everyone else. The countdown, where a domain has one, still runs first and
then comes back here rather than leaving for the destination, and the
continue flag cannot be used to turn a framed link into a plain redirect.
The frame is sandboxed, carries no referrer, and the page's
`frame-src` names the destination's origin and nothing else. A destination
that refuses to be framed simply shows nothing: the visitor's page carries
no banner, because the warning belongs beside the checkbox that turns
framing on, where the person who can act on it will see it. Treat the
feature as a convenience rather than a guarantee, and test each destination.

**A destination cannot carry a password.** `https://user:secret@host/` is
refused: it would be stored in the clear, shown on the edit screen, written
into the audit log and encoded into the QR code. A bare username is kept,
because it is occasionally meant, but the editor says plainly that
`https://trusted.example@evil.example/` goes to the second host.

## Preview cards

When something like Slack or Twitter unfurls a short link it follows the
redirect and reads the destination's own tags. A link can instead carry its
own card — title, description and an https image — and then a crawler is
served that card rather than a redirect, while people still get the redirect.
The editor shows how the card will look.

**Only public domains get cards.** On a domain that requires sign-in a
crawler cannot authenticate and is bounced anyway, and emitting a title and
description for an internal link would publish exactly what the sign-in
requirement exists to protect. The editor says so rather than offering fields
that would be ignored, and nothing is stored.

A card needs a title. Without one the crawler is better served by the
destination's own tags, so no card is emitted.

## The countdown

Before opening a link, visitors can be held on a countdown page. Whether that
happens is decided by a policy resolved in three steps — domain, then any
directory owning the path, then the link itself.

Each switch is three-state, which is what makes locking possible:

| Setting | Values |
| --- | --- |
| Countdown | never shown · each link decides · always shown |
| Destination on that page | never shown · each link decides · always shown |
| Minimum delay | a floor a lower level may raise but not lower |

Plus a default delay, and defaults for the two "each link decides" cases.
Anything not locked is editable by whoever may edit the link.

**Narrowing is the rule.** A directory administrator may always make their
directory stricter than the domain. **Exemptions are the exception**: to let
a directory go the other way, a Shrink Link administrator grants it an
exemption on one named setting. Opening one does not open the others. The
same applies to people — a user can be exempted globally or on named
domains, which lets them set link options the policy would otherwise lock.

A link is served according to its **owner's** exemptions, not a snapshot
taken when it was saved, so withdrawing someone's exemption pulls their links
back under the policy at once rather than leaving a permanent hole. The
owner's grants are only loaded when the stored link actually depends on one,
so an ordinary redirect costs no extra reads.

Out of the box the countdown is available everywhere and defaults to **on for
`ptra.dev`** and **off for `ptra.cc`**: a public short link should go
straight through, while the authenticated host shows where it is sending you.
Setting a delay on a link is itself a request for a countdown, so a link can
opt in even where the default is off.

When the destination is hidden, it is genuinely absent from the page: the
countdown points back at this host with a `slink-go` flag and the worker
answers with the real redirect, so the target appears nowhere in the markup.
That flag is stripped before any query string is forwarded on.

The page works without JavaScript via a meta refresh.

---

## Security

- **Transport and headers.** HSTS, a strict CSP, `nosniff`, `no-referrer`,
  `X-Frame-Options: DENY`, COOP, CORP, a closed `Permissions-Policy`, and
  `no-store` on everything except permanent redirects and static assets.
- **CSRF.** Every state change is a POST whose token is an HMAC bound to both
  the session (or an HttpOnly cookie, before sign-in) and the specific form,
  compared in constant time. An attacker can neither read the input nor
  compute the token, and `SameSite=Lax` keeps cookies off a cross-site POST
  entirely. On top of that, an `Origin` or `Referer` header that is present
  must match. A header that is *absent* is not treated as an attack: several
  browsers omit `Origin` on a same-origin form post, and privacy extensions
  and proxies strip both, so refusing on absence locked real people out of
  every form. HTML pages send `Referrer-Policy: same-origin` so that fallback
  is actually available; redirect responses send `no-referrer`, so a
  destination never learns which shortcut was followed. A token from another session, or for another form,
  is refused.
- **Cookies.** `__Host-` prefixed, so Secure, `Path=/` and no `Domain`;
  HttpOnly and SameSite=Lax.
- **Sessions.** Server-side records keyed by the hash of a random id. The
  cookie carries only the id, so a dump of KV yields nothing replayable.
  Disabling an account revokes its sessions immediately.
- **Secrets.** Every signed value derives a purpose-scoped sub-key from
  `AUTH_SECRET`, so a token minted for one purpose cannot be replayed as
  another.
- **Fail closed.** A missing `AUTH_SECRET`, Turnstile key or `ADMIN` serves
  503 rather than a half-secured site.
- **Privacy.** Client IPs are stored only as truncated hashes, in sessions, in
  challenges and in the audit log.
- **Audit.** Sign-ins, refusals, and every change to a link, directory,
  domain, user or setting are recorded, newest first, expiring on the
  configured retention period.

### Known limits

- KV has no compare-and-swap, so the rate-limit counters can overshoot under a
  burst spread across locations. They are a throttle, not a guarantee; the
  real brute-force defences are Turnstile on both sign-in surfaces, the
  per-challenge attempt counter, and the short code lifetime.
- The sign-in code appears in the email subject by default, so it is visible
  in a notification preview. Change the subject template in settings if that
  is not wanted.
- Deleting a user leaves their links in place, still pointing at the deleted
  owner. Reassign them first; the UI says so. Their passkeys do go with the
  account, so an address reused later inherits no device.
- **Click counts are a floor, not a count.** Counting is a read-modify-write
  on one KV key with no compare-and-set, so simultaneous arrivals overwrite
  one another; twenty at once were measured to record one. The edit screen
  says "or more". Counting every hit needs a primitive that can increment —
  a Durable Object, or Analytics Engine — which is a deployment change
  rather than a code one, and nothing else depends on the figure.
- The same lack of compare-and-set means the twenty-passkey cap per account
  can be passed by registering from two tabs at the same instant. It is a
  sanity bound on how much one account can store, not a security boundary.
- There is no CI in this repository. `npm test` is the gate and it is run by
  hand; the only automatic check on a pull request is the Cloudflare build.

### Rotating AUTH_SECRET

Set `AUTH_SECRET_PREVIOUS` to the old value **before** changing
`AUTH_SECRET`, and keep it until every protected link has been saved once.

Nearly everything derived from the secret is short-lived — a CSRF token, an
unlock cookie, a login code, an SSO or impersonation token — so a rotation
costs those a retry and nothing more. Sessions are unaffected: a session id
is stored, not signed. The exception is a **link password**, which is
encrypted at rest and has to stay readable; without the previous secret the
link is stranded behind a password nobody can read, type or clear. With it,
the password still opens, and saving the link re-seals it under the new
secret, after which the fallback can be dropped.

If a rotation has already happened without it, the link editor says so
plainly rather than showing an empty field, and refuses to clear a password
it cannot read unless you confirm.

---

## Development

```sh
npm run check   # syntax-check every module as an ES module
npm test        # 1,138 checks across 25 suites
wrangler dev    # local run; see the note below
```

Tests run on plain Node against an in-memory KV, a stubbed siteverify and a
capturing mail binding, driving the real `fetch` handler — no account or
network needed.

`logo.svg` is the artwork; `logo.js` mirrors its bytes so the Worker can
serve it and Node can run the tests from one module graph. After editing the
SVG, regenerate `logo.js` — `npm test` fails if the two drift apart. The icon
is served from `/__slink/logo.svg` with a `sandbox` CSP and `nosniff`,
because an SVG is active content when a browser navigates straight to it.

Under `wrangler dev` the client country may be absent, which the default
policy treats as unlocatable and refuses. Either use `wrangler dev --remote`
or turn off "Refuse sign-in when the country is unknown" in settings while
developing.
