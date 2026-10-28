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

// Scheme and host are case-insensitive and get normalised; a path, query or
// fragment is case-sensitive and must survive exactly as typed.
ok('destination scheme lowercases', parseDestination('HTTPS://Example.COM/a').target.startsWith('https://'));
ok('destination host lowercases', parseDestination('HTTPS://Example.COM/a').target.includes('example.com'));
ok('destination path keeps its case',
   parseDestination('https://example.com/MyPage?Token=AbC#Frag').target === 'https://example.com/MyPage?Token=AbC#Frag');
ok('opaque scheme lowercases', parseDestination('MAILTO:Someone@Example.com').target.startsWith('mailto:'));
ok('opaque body keeps its case',
   parseDestination('MAILTO:Someone@Example.com').target === 'mailto:Someone@Example.com');

const dangerous = ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>', 'vbscript:x', 'file:///etc/passwd'];
ok('dangerous schemes all rejected',
   dangerous.every((v) => { try { parseDestination(v); return false; } catch { return true; } }));
ok('bare host gets https', parseDestination('example.com').target === 'https://example.com/');
ok('scheme-relative gets https', parseDestination('//example.com/a').target === 'https://example.com/a');
ok('explicit scheme kept', parseDestination('ts3server://host?port=1').target === 'ts3server://host?port=1');
ok('opaque scheme kept', parseDestination('mailto:a@b.com').target === 'mailto:a@b.com');
ok('extra blocked scheme honoured',
   (() => { try { parseDestination('ftp://x/y', { blockedSchemes: ['ftp'] }); return false; } catch { return true; } })());

console.log(`\notp/paths: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
