/** Runs every suite in sequence and reports a single verdict. */
import { spawnSync } from 'node:child_process';

const suites = [
  'test/permissions.test.mjs',
  'test/otp.test.mjs',
  'test/e2e.test.mjs',
  'test/flows.test.mjs',
  'test/security.test.mjs',
  'test/assets.test.mjs',
  'test/routing.test.mjs',
  'test/grants.test.mjs',
  'test/interstitial.test.mjs',
  'test/variants.test.mjs',
  'test/impersonate.test.mjs',
  'test/scoped.test.mjs',
  'test/search.test.mjs',
  'test/dirmissing.test.mjs',
  'test/invites.test.mjs',
  'test/qr.test.mjs',
  'test/oauth.test.mjs',
  'test/schedule.test.mjs',
];

let bad = 0;
for (const suite of suites) {
  const r = spawnSync(process.execPath, [suite], { stdio: 'inherit' });
  if (r.status !== 0) bad++;
}
console.log(bad ? `\n${bad} suite(s) failed` : '\nall suites passed');
process.exit(bad ? 1 : 0);
