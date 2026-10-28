/**
 * mailer.js - delivery of the sign-in code.
 *
 * The default driver is the Cloudflare Email Sending binding (`send_email` in
 * wrangler.toml, exposed as env.EMAIL). Sending to arbitrary recipients
 * requires the sending domain to be onboarded in Email Service; before that,
 * only verified destination addresses on the account can be reached.
 *
 * Other drivers exist so the deployment is not locked to one provider; pick
 * one with MAIL_PROVIDER. The 'log' driver writes to the Worker log and is
 * for local development only - it must never be selected in production.
 */

import { esc } from './util.js';

/** The display name on outgoing mail; blank means "use the app name". */
function senderName(cfg) {
  return cfg.settings.mail.fromName || cfg.appName;
}

export class MailError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'MailError';
    this.cause = cause || null;
  }
}

/** Plain-text and HTML bodies for the sign-in code. */
export function renderOtpEmail(cfg, { code, host, ttlSeconds, ip, country }) {
  const minutes = Math.max(1, Math.round((ttlSeconds || 600) / 60));
  const app = cfg.appName;
  const where = [country ? 'country ' + country : null, ip ? 'IP ' + ip : null]
    .filter(Boolean)
    .join(', ');

  const text = [
    `${app} sign-in code: ${code}`,
    '',
    `Enter this code to sign in to ${host}.`,
    `It expires in ${minutes} minute${minutes === 1 ? '' : 's'} and can be used once.`,
    where ? `Requested from ${where}.` : '',
    '',
    'If you did not request this, you can ignore this email. Nobody can sign in',
    'with this code unless they also control this mailbox.',
  ]
    .filter((line) => line !== '')
    .join('\n');

  const html = [
    '<!doctype html><html><body style="margin:0;padding:24px;background:#f5f6f8;',
    'font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#15181d">',
    '<table role="presentation" cellpadding="0" cellspacing="0" style="max-width:480px;margin:0 auto;',
    'background:#ffffff;border-radius:12px;border:1px solid #e3e6ea"><tr><td style="padding:28px">',
    `<p style="margin:0 0 6px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#6b7280">${esc(app)}</p>`,
    `<h1 style="margin:0 0 18px;font-size:19px;font-weight:600">Your sign-in code</h1>`,
    `<p style="margin:0 0 18px;font-size:14px;line-height:1.55">Enter this code to sign in to <strong>${esc(host)}</strong>.</p>`,
    `<p style="margin:0 0 18px;font-size:34px;font-weight:700;letter-spacing:.22em;`,
    `font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">${esc(code)}</p>`,
    `<p style="margin:0 0 18px;font-size:13px;color:#4b5563;line-height:1.55">`,
    `It expires in ${minutes} minute${minutes === 1 ? '' : 's'} and can be used once.`,
    where ? ` Requested from ${esc(where)}.` : '',
    '</p>',
    '<hr style="border:0;border-top:1px solid #e3e6ea;margin:20px 0">',
    `<p style="margin:0;font-size:12px;color:#6b7280;line-height:1.55">If you did not request this, `,
    'you can ignore this email. Nobody can sign in with this code unless they also control this mailbox.</p>',
    '</td></tr></table></body></html>',
  ].join('');

  const subject = String(cfg.settings.mail.subject || 'Your {{app}} sign-in code: {{code}}')
    .split('{{app}}')
    .join(app)
    .split('{{code}}')
    .join(code)
    .split('{{host}}')
    .join(host);

  return { subject, text, html };
}

/* ------------------------------------------------------------------ drivers */

async function sendViaCloudflare(cfg, message) {
  if (!cfg.emailBinding || typeof cfg.emailBinding.send !== 'function') {
    throw new MailError(
      'The EMAIL binding is not configured. Add a [[send_email]] binding named EMAIL in wrangler.toml.'
    );
  }
  try {
    const result = await cfg.emailBinding.send({
      to: message.to,
      from: { email: cfg.mailFrom, name: senderName(cfg) },
      subject: message.subject,
      text: message.text,
      html: message.html,
      ...(cfg.settings.mail.replyTo ? { replyTo: cfg.settings.mail.replyTo } : {}),
    });
    return { ok: true, id: (result && result.messageId) || null, provider: 'cloudflare' };
  } catch (err) {
    throw new MailError(describeCloudflareError(err), err);
  }
}

/**
 * Turn the binding's errors into something an operator can act on. The two
 * that matter in practice are an un-onboarded sending domain and a recipient
 * that is not a verified destination address.
 */
function describeCloudflareError(err) {
  const raw = String((err && err.message) || err || 'unknown error');
  if (/verified|destination/i.test(raw)) {
    return (
      'Email Service refused the recipient. Until the sending domain is onboarded, ' +
      'only verified destination addresses on the account can be reached. (' + raw + ')'
    );
  }
  if (/not allowed|sender/i.test(raw)) {
    return 'Email Service refused the sender address. MAIL_FROM must be on an onboarded sending domain. (' + raw + ')';
  }
  return 'Email Service rejected the message: ' + raw;
}

async function postJson(url, headers, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new MailError(`Mail provider returned ${res.status}: ${detail.slice(0, 300)}`);
  }
  return res.json().catch(() => ({}));
}

async function sendViaResend(cfg, message) {
  const key = cfg.env.RESEND_API_KEY;
  if (!key) throw new MailError('RESEND_API_KEY is not configured.');
  const data = await postJson('https://api.resend.com/emails', { Authorization: 'Bearer ' + key }, {
    from: `${senderName(cfg)} <${cfg.mailFrom}>`,
    to: [message.to],
    subject: message.subject,
    text: message.text,
    html: message.html,
  });
  return { ok: true, id: data.id || null, provider: 'resend' };
}

async function sendViaSendgrid(cfg, message) {
  const key = cfg.env.SENDGRID_API_KEY;
  if (!key) throw new MailError('SENDGRID_API_KEY is not configured.');
  await postJson('https://api.sendgrid.com/v3/mail/send', { Authorization: 'Bearer ' + key }, {
    personalizations: [{ to: [{ email: message.to }] }],
    from: { email: cfg.mailFrom, name: senderName(cfg) },
    subject: message.subject,
    content: [
      { type: 'text/plain', value: message.text },
      { type: 'text/html', value: message.html },
    ],
  });
  return { ok: true, id: null, provider: 'sendgrid' };
}

async function sendViaPostmark(cfg, message) {
  const key = cfg.env.POSTMARK_TOKEN;
  if (!key) throw new MailError('POSTMARK_TOKEN is not configured.');
  const data = await postJson('https://api.postmarkapp.com/email', { 'X-Postmark-Server-Token': key }, {
    From: `${senderName(cfg)} <${cfg.mailFrom}>`,
    To: message.to,
    Subject: message.subject,
    TextBody: message.text,
    HtmlBody: message.html,
    MessageStream: cfg.env.POSTMARK_STREAM || 'outbound',
  });
  return { ok: true, id: data.MessageID || null, provider: 'postmark' };
}

async function sendViaMailgun(cfg, message) {
  const key = cfg.env.MAILGUN_API_KEY;
  const domain = cfg.env.MAILGUN_DOMAIN;
  if (!key || !domain) throw new MailError('MAILGUN_API_KEY and MAILGUN_DOMAIN are required.');
  const body = new URLSearchParams();
  body.set('from', `${senderName(cfg)} <${cfg.mailFrom}>`);
  body.set('to', message.to);
  body.set('subject', message.subject);
  body.set('text', message.text);
  body.set('html', message.html);
  const res = await fetch(`https://api.mailgun.net/v3/${domain}/messages`, {
    method: 'POST',
    headers: { Authorization: 'Basic ' + btoa('api:' + key) },
    body,
  });
  if (!res.ok) throw new MailError(`Mailgun returned ${res.status}`);
  return { ok: true, id: null, provider: 'mailgun' };
}

/**
 * Development only. Guarded so it cannot be selected unless DEBUG_MAIL is
 * explicitly on, which keeps a misconfigured production deploy from silently
 * printing codes instead of sending them.
 */
async function sendViaLog(cfg, message) {
  if (!cfg.debugMail) {
    throw new MailError("MAIL_PROVIDER=log requires DEBUG_MAIL=true and is for local development only.");
  }
  console.log('[mail:log]', JSON.stringify({ to: message.to, subject: message.subject }));
  console.log('[mail:log] body:\n' + message.text);
  return { ok: true, id: 'log', provider: 'log' };
}

const DRIVERS = {
  cloudflare: sendViaCloudflare,
  resend: sendViaResend,
  sendgrid: sendViaSendgrid,
  postmark: sendViaPostmark,
  mailgun: sendViaMailgun,
  log: sendViaLog,
};

export const PROVIDERS = Object.keys(DRIVERS);

/** Send one message through the configured provider. */
export async function sendMail(cfg, { to, subject, text, html }) {
  const driver = DRIVERS[cfg.mailProvider];
  if (!driver) {
    throw new MailError(
      `Unknown MAIL_PROVIDER "${cfg.mailProvider}". Expected one of: ${PROVIDERS.join(', ')}.`
    );
  }
  return driver(cfg, { to, subject, text, html });
}

/** Compose and send the sign-in code. */
export async function sendOtpEmail(cfg, { to, code, host, ip, country }) {
  const message = renderOtpEmail(cfg, {
    code,
    host,
    ttlSeconds: cfg.settings.otpTtlSeconds,
    ip,
    country,
  });
  return sendMail(cfg, { to, ...message });
}
