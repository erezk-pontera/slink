# slink

A short-link service for **ptra.cc** and **ptra.dev**, running as a single
Cloudflare Worker backed by one KV namespace.

- `ptra.cc/aaa` — public short links, redirecting immediately or after a
  countdown, with a redirect code you choose.
- `ptra.dev/bbb` — the same, but every link requires a verified sign-in.
- `ptra.dev/admin` — manage links, directories, domains, users and settings.

Apex and `www.` are the same host everywhere: `www.ptra.dev/bbb` and
`ptra.dev/bbb` are one link.

---

## How it fits together

| File | Responsibility |
| --- | --- |
| `index.js` | Worker entry point and top-level router |
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
| `views.js`, `assets.js` | HTML, CSS and the one client-side script |
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
| Root administrator (`ADMIN` env var) | Everything. Cannot be demoted or deleted from the UI. |
| Administrator (flag set by an admin) | Everything. |
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

Root-level creation on a host is governed by its `rootCreatePolicy`:
`email_domain` (the default — the host's allow list, falling back to
`DEFAULT_ALLOWED_DOMAINS`, or an explicit per-user grant), `explicit`,
`open`, or `admins_only`.

---

## Sign-in

1. `/login` takes an email address, behind Turnstile.
2. The address is normalised and checked against the host's allowed sign-in
   domains. Tor exits and unlocatable clients are refused.
3. A six-digit code is emailed. It is never stored: KV holds an HMAC of the
   code bound to a per-challenge salt and to the login id in the browser's
   cookie, so a code only works in the browser that asked for it.
4. `/login/verify` takes the code, also behind Turnstile. Attempts are counted
   on the challenge itself, and the challenge is deleted once spent.
5. A session is created. Accounts are created on first successful sign-in, so
   the sign-in form reveals nothing about who already has an account.

`/logout` asks for confirmation and then signs the user out of **every** host,
by revoking every session they hold.

**Across hosts.** Only `ptra.dev` serves `/login` and `/admin`. Another host
that requires sign-in bounces the visitor through a signed, nonce-bound,
two-minute handshake on the hub, so one sign-in covers every host. The token
names the host it was minted for and is useless anywhere else.

Session lifetime is `SESSION_TTL_SECONDS`, or effectively permanent with
`SESSION_PERMANENT=true`. An optional idle timeout, and optional binding to
the user-agent or client IP, are in `/admin/settings`.

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
| `APP_NAME` | Name shown in the UI and in emails |
| `ADMIN` | Root administrator addresses, comma separated |
| `DEFAULT_ALLOWED_DOMAINS` | Default email domains for signing in and for creating at a host root |
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
`javascript:`, `data:`, `vbscript:`, `blob:` and `file:` are always refused;
more can be blocked in settings.

Redirect codes are 301, 302 (default), 303, 307 and 308. A delay above zero
shows a countdown page first, which works without JavaScript via a meta
refresh. 301 and 308 responses are cacheable for five minutes; the rest are
`no-store`, so a changed destination takes effect at once.

---

## Security

- **Transport and headers.** HSTS, a strict CSP, `nosniff`, `no-referrer`,
  `X-Frame-Options: DENY`, COOP, CORP, a closed `Permissions-Policy`, and
  `no-store` on everything except permanent redirects and static assets.
- **CSRF.** Every state change is a POST whose token is bound to both the
  session and the specific form, checked in constant time, alongside a strict
  `Origin`/`Referer` check. A token from another session, or for another form,
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
  owner. Reassign them first; the UI says so.

---

## Development

```sh
npm run check   # syntax-check every module as an ES module
npm test        # 188 checks across five suites
wrangler dev    # local run; see the note below
```

Tests run on plain Node against an in-memory KV, a stubbed siteverify and a
capturing mail binding, driving the real `fetch` handler — no account or
network needed.

Under `wrangler dev` the client country may be absent, which the default
policy treats as unlocatable and refuses. Either use `wrangler dev --remote`
or turn off "Refuse sign-in when the country is unknown" in settings while
developing.
