import fs from 'node:fs';
import { Harness } from './harness.js';
import { CSS, JS, serveAsset, ASSET_VERSION } from '../assets.js';
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
const login = await h.req('https://ptra.dev/admin');
const loginBody = await login.text();
ok('login page links the favicon',
   loginBody.includes(`<link rel="icon" type="image/svg+xml" href="/__slink/logo.svg?v=${ASSET_VERSION}">`),
   (loginBody.match(/<link rel="icon"[^>]*>/) || [''])[0]);
ok('apple-touch-icon present', loginBody.includes('rel="apple-touch-icon"'));
ok('emoji data-URI favicon is gone', !loginBody.includes('data:image/svg+xml,%3Csvg'));

await h.signIn('root@pontera.com');
const admin = await h.req('https://ptra.dev/admin');
ok('admin page links the favicon', (await admin.text()).includes('/__slink/logo.svg'));

// A short-link host root redirects, so check the favicon on a page it does
// render: the signed-out admin screen on the hub.
ok('hub pages link the favicon', loginBody.includes('/__slink/logo.svg'));

// The icon is same-origin, which img-src 'self' already permits.
const csp = login.headers.get('Content-Security-Policy') || '';
ok('CSP permits a same-origin icon', /img-src [^;]*'self'/.test(csp), csp);


// The floating QR can actually hide itself.
{
  // An explicit display beats the browser's own [hidden] rule, so the
  // stylesheet has to repeat it or the panel is stuck on screen.
  ok('the panel has a display of its own', /\.qrfloat\{[^}]*display:block/.test(CSS));
  ok('and a rule that lets it hide', /\.qrfloat\[hidden\][^{]*\{display:none\}/.test(CSS));
  ok('the image inside can hide too', /\.qrfloat img\[hidden\]|img\[hidden\]\{display:none\}/.test(CSS));
  ok('the script hides and shows it', JS.includes('qrBox.hidden = true') && JS.includes('qrBox.hidden = false'));
  ok('and debounces rather than firing per keystroke', JS.includes('window.clearTimeout(timer)'));
}

// The countdown digits.
{
  // The number the visitor watches is in the card; the element carrying the
  // destination is an empty hidden one further down the page. A lookup
  // scoped to the latter finds nothing and the digits sit still, which is
  // exactly the bug this guards.
  ok('the script looks for the counter in the document',
     JS.includes("document.querySelector('[data-slink-count]')"),
     (JS.match(/querySelector\('\[data-slink-count\]'\)/g) || []).join(' '));
  ok('and nowhere narrower', !/hold\.querySelector\('\[data-slink-count\]'\)/.test(JS));
  ok('it decrements', JS.includes('left -= 1'));
}

console.log(`\nassets: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
