import fs from 'node:fs';
import { Harness } from './harness.js';
import { serveAsset, ASSET_VERSION } from '../assets.js';
import { LOGO_SVG } from '../logo.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}

// logo.svg is the artwork; logo.js mirrors it so the Worker can serve it and
// Node can run the tests. This check is what keeps the two from drifting.
const onDisk = fs.readFileSync(new URL('../logo.svg', import.meta.url), 'utf8');
ok('logo.js matches logo.svg', LOGO_SVG.trim() === onDisk.trim(),
   `js=${LOGO_SVG.length} svg=${onDisk.length} - regenerate logo.js from logo.svg`);
ok('logo carries no script', !/<script|javascript:|onload=/i.test(LOGO_SVG));

const direct = serveAsset('/__slink/logo.svg');
ok('logo route exists', !!direct && direct.status === 200);
ok('logo served as svg', (direct.headers.get('Content-Type') || '').startsWith('image/svg+xml'));
ok('logo is immutable', (direct.headers.get('Cache-Control') || '').includes('immutable'));
ok('logo is served inert', (direct.headers.get('Content-Security-Policy') || '').includes("default-src 'none'"));
ok('logo is sandboxed', (direct.headers.get('Content-Security-Policy') || '').includes('sandbox'));
ok('logo has nosniff', direct.headers.get('X-Content-Type-Options') === 'nosniff');

const h = new Harness();

const served = await h.req('https://ptra.dev/__slink/logo.svg');
ok('logo reachable through the worker', served.status === 200);
const bytes = await served.text();
ok('logo bytes are the artwork', bytes.trim() === onDisk.trim());
ok('logo keeps the brand colour', bytes.includes('#FF651A'));

// The favicon must be referenced on pages a signed-out visitor sees, and on
// the admin pages, without needing a session for the icon itself.
const login = await h.req('https://ptra.dev/login');
const loginBody = await login.text();
ok('login page links the favicon',
   loginBody.includes(`<link rel="icon" type="image/svg+xml" href="/__slink/logo.svg?v=${ASSET_VERSION}">`),
   (loginBody.match(/<link rel="icon"[^>]*>/) || [''])[0]);
ok('apple-touch-icon present', loginBody.includes('rel="apple-touch-icon"'));
ok('emoji data-URI favicon is gone', !loginBody.includes('data:image/svg+xml,%3Csvg'));

await h.signIn('root@pontera.com');
const admin = await h.req('https://ptra.dev/admin');
ok('admin page links the favicon', (await admin.text()).includes('/__slink/logo.svg'));

const landing = await h.req('https://ptra.cc/');
ok('short-link host links the favicon', (await landing.text()).includes('/__slink/logo.svg'));

// The icon is same-origin, which img-src 'self' already permits.
const csp = login.headers.get('Content-Security-Policy') || '';
ok('CSP permits a same-origin icon', /img-src [^;]*'self'/.test(csp), csp);

console.log(`\nassets: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
