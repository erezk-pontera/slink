import { makeEnv } from './fakekv.js';
import { loadConfig } from '../config.js';
import * as otp from '../otp.js';
import { normalizeEmail, parseDestination, parsePath } from '../paths.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}

const cfg = await loadConfig(makeEnv());

/* ---------------------------------------------------------------- OTP */
const ch = await otp.createChallenge(cfg, {
  email: 'a@pontera.com', emailNorm: 'a@pontera.com', host: 'ptra.dev', next: '/admin',
  ip: '1.2.3.4', geo: { country: 'IL' },
});
ok('code has configured length', ch.code.length === cfg.settings.otpLength);
ok('code is numeric', /^[0-9]+$/.test(ch.code));

const stored = JSON.stringify(await cfg.store.get('otp:' + ch.loginId));
ok('plaintext code is not stored', !stored.includes(ch.code));
ok('raw IP is not stored', !stored.includes('1.2.3.4'));

ok('wrong code mismatches', (await otp.verifyChallenge(cfg, ch.loginId, '000000')).status === 'mismatch');
ok('correct code verifies', (await otp.verifyChallenge(cfg, ch.loginId, ch.code)).status === 'ok');
ok('code cannot be reused', (await otp.verifyChallenge(cfg, ch.loginId, ch.code)).status === 'consumed');

const ch2 = await otp.createChallenge(cfg, { email: 'b@p.com', emailNorm: 'b@p.com', host: 'ptra.dev' });
let last;
for (let i = 0; i < cfg.settings.otpMaxAttempts + 1; i++) {
  last = await otp.verifyChallenge(cfg, ch2.loginId, '111111');
}
ok('lockout after max attempts', last.status === 'locked');
ok('correct code rejected once locked', (await otp.verifyChallenge(cfg, ch2.loginId, ch2.code)).status === 'locked');

const ch3 = await otp.createChallenge(cfg, { email: 'c@p.com', emailNorm: 'c@p.com', host: 'ptra.dev' });
ok("another challenge's code does not work", (await otp.verifyChallenge(cfg, ch3.loginId, ch.code)).status !== 'ok');
ok('unknown challenge', (await otp.verifyChallenge(cfg, 'nope', '123456')).status === 'unknown');

const expired = await otp.createChallenge(cfg, { email: 'd@p.com', emailNorm: 'd@p.com', host: 'ptra.dev' });
const rec = await otp.getChallenge(cfg, expired.loginId);
rec.expiresAt = Math.floor(Date.now() / 1000) - 1;
await otp.putChallenge(cfg, expired.loginId, rec);
ok('expired challenge rejected', (await otp.verifyChallenge(cfg, expired.loginId, expired.code)).status === 'expired');

/* ------------------------------------------------------------ identity */
const dotPlus = { ignoreDot: true, ignorePlus: true };
ok('dot and plus stripped', normalizeEmail('A.A+bb@CC.com', dotPlus).emailNorm === 'aa@cc.com');
ok('plus only', normalizeEmail('a.a+bb@cc.com', { ignorePlus: true }).emailNorm === 'a.a@cc.com');
ok('dot only', normalizeEmail('a.a+bb@cc.com', { ignoreDot: true }).emailNorm === 'aa+bb@cc.com');
ok('neither', normalizeEmail('a.a+bb@cc.com').emailNorm === 'a.a+bb@cc.com');
ok('domain dots survive', normalizeEmail('x@a.b.co.uk', dotPlus).emailNorm === 'x@a.b.co.uk');

/* ------------------------------------------------------------- parsing */
const bad = ['a b', 'a//b', '', 'a!b', 'unic\u00f6de', '../etc', 'a'.repeat(300), 'a/../b', 'a%2Fb'];
const accepted = bad.filter((v) => { try { parsePath(v); return true; } catch { return false; } });
ok('invalid shortcuts all rejected', accepted.length === 0, 'accepted: ' + JSON.stringify(accepted));
// Surrounding slashes are tolerated so ptra.cc/aaa/ reaches the same link.
ok('trailing slash normalised away', parsePath('a/').pathLc === 'a');
ok('leading slash normalised away', parsePath('/a/b').pathLc === 'a/b');
ok('valid shortcut lowercases', parsePath('Pub/Deck_1-x').pathLc === 'pub/deck_1-x');
// The displayed form is the stored form, so a shortcut is never shown in a
// case that differs from the one the redirect matches on.
ok('the displayed shortcut is lowercase too', parsePath('Pub/Deck_1-X').path === 'pub/deck_1-x');
ok('shortcut segments agree', parsePath('MiXeD').path === parsePath('MiXeD').pathLc);

// A shortcut is ours and is lowercased; a destination is somebody else's
// and is stored exactly as typed, every part of it.
ok('destination scheme keeps its case',
   parseDestination('HTTPS://Example.COM/a').target === 'HTTPS://Example.COM/a');
ok('destination host keeps its case',
   parseDestination('Example.COM/a').target === 'https://Example.COM/a');
ok('destination path, query and fragment keep theirs',
   parseDestination('https://example.com/MyPage?Token=AbC#Frag').target ===
     'https://example.com/MyPage?Token=AbC#Frag');
ok('a mixed-case host survives with everything else',
   parseDestination('HtTp://Ex.Com/A/b?C=D&e=F#G').target === 'HtTp://Ex.Com/A/b?C=D&e=F#G');
ok('an opaque scheme keeps its case too',
   parseDestination('MAILTO:Someone@Example.com').target === 'MAILTO:Someone@Example.com');
// The scheme is still compared in lowercase, so a policy cannot be dodged
// by typing it differently.
ok('the reported scheme is lowercase', parseDestination('HTTPS://Example.COM/a').scheme === 'https');
ok('a blocked scheme is still blocked in any case',
   (() => { try { parseDestination('JaVaScRiPt:alert(1)'); return false; } catch { return true; } })());
// What the parser must still do, because a Location header needs it.
ok('a space is still encoded', parseDestination('https://Ex.com/a b').target === 'https://Ex.com/a%20b');
ok('a non-ASCII host is still punycoded',
   parseDestination('https://\u4f8b\u3048.\u30c6\u30b9\u30c8/x').target.includes('xn--'));
ok('a default port is still dropped', parseDestination('https://Ex.com:443/x').target === 'https://Ex.com/x');
ok('dot segments are still resolved', parseDestination('https://Ex.com/a/../b').target === 'https://Ex.com/b');
// A password in the authority would be stored in the clear, logged and put
// into the QR code, so it is refused rather than kept.
ok('a password in a destination is refused',
   (() => { try { parseDestination('https://u:p@ex.com/'); return false; } catch { return true; } })());
ok('a username alone is kept but reported',
   parseDestination('https://trusted.example@evil.example/').userinfo === 'trusted.example');
ok('an ordinary destination reports none', parseDestination('https://ex.com/').userinfo === '');

const dangerous = ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>', 'vbscript:x', 'file:///etc/passwd'];
ok('dangerous schemes all rejected',
   dangerous.every((v) => { try { parseDestination(v); return false; } catch { return true; } }));
ok('bare host gets https', parseDestination('example.com').target === 'https://example.com/');
ok('scheme-relative gets https', parseDestination('//example.com/a').target === 'https://example.com/a');
ok('explicit scheme kept', parseDestination('ts3server://host?port=1').target === 'ts3server://host?port=1');
ok('opaque scheme kept', parseDestination('mailto:a@b.com').target === 'mailto:a@b.com');
ok('extra blocked scheme honoured',
   (() => { try { parseDestination('ftp://x/y', { blockedSchemes: ['ftp'] }); return false; } catch { return true; } })());

/* ------------------------------------------- an address is an identity */
// These addresses key directory grants, link ownership and the
// administrator list, so two that look alike but are not the same account
// is a correctness problem before it is a cosmetic one.
ok('an ordinary address is accepted', normalizeEmail('first.last@pontera.com', {}).emailNorm === 'first.last@pontera.com');
ok('a plus tag is accepted', normalizeEmail('a+tag@pontera.com', {}).emailNorm === 'a+tag@pontera.com');
ok('an apostrophe is accepted', normalizeEmail("o'brien@pontera.com", {}).emailNorm === "o'brien@pontera.com");
ok('the RFC specials are accepted',
   normalizeEmail("user!#$%&*+-/=?^_`{|}~@pontera.com", {}).emailNorm.startsWith('user!'));
ok('case is folded', normalizeEmail('A.B@Pontera.COM', {}).emailNorm === 'a.b@pontera.com');

const refused = (value) => {
  try { normalizeEmail(value, {}); return false; } catch { return true; }
};
// Cyrillic a, indistinguishable from the Latin one in most typefaces.
ok('a homoglyph local part is refused', refused('\u0430dmin@pontera.com'));
ok('a homoglyph domain is refused', refused('admin@ponter\u0430.com'));
ok('a null byte is refused', refused('a\u0000b@pontera.com'));
ok('a zero-width joiner is refused', refused('a\u200db@pontera.com'));
ok('a right-to-left override is refused', refused('a\u202eb@pontera.com'));
ok('an overlong address is refused', refused('x'.repeat(300) + '@pontera.com'));
ok('a space is refused', refused('a b@pontera.com'));
ok('angle brackets are refused', refused('a<b>@pontera.com'));
ok('a bare domain is refused', refused('a@b'));
ok('a doubled dot in the domain is refused', refused('a@pontera..com'));

console.log(`\notp/paths: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
