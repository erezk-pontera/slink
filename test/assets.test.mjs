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

// One link, so the listings below have a row to render.
{
  const form = await (await h.req('https://ptra.dev/admin/links/new')).text();
  await h.req('https://ptra.dev/admin/links/new', {
    form: {
      _csrf: Harness.csrf(form),
      host: 'ptra.cc',
      dir: 'ptra.cc/',
      path: 'chrome',
      target: 'example.com/chrome',
      status: '302',
    },
  });
}

// The chrome: where you can go, and who you are, are two groups.
{
  const page = await (await h.req('https://ptra.dev/admin')).text();
  const navBlock = (page.match(/<nav class="main"[\s\S]*?<\/nav>/) || [''])[0];
  ok('the sections are a nav', navBlock.includes('href="/admin/links"'), navBlock.slice(0, 80));
  ok('signing out is not one of them', !navBlock.includes('Sign out'), navBlock);
  ok('it is with the account instead', /<div class="acct">[\s\S]*?class="signout"/.test(page),
     (page.match(/<div class="acct">[\s\S]*?<\/div>/) || [''])[0].slice(0, 160));
  ok('the nav says what it is', navBlock.includes('aria-label="Sections"'));

  // A phone cannot show a link row as a table row, so it is told to stack.
  ok('link listings can stack on a narrow screen', page.includes('<table class="cards-sm"'));
  ok('and the stylesheet knows how', CSS.includes('.cards-sm thead{display:none}'));

  // Sections inside one card are separated rather than run together.
  ok('a second heading in a card draws a rule', /\.card h2~h2[^{]*\{[^}]*border-top/.test(CSS));

  // The floating QR only pins itself where there is room beside the column.
  ok('the QR floats rather than taking a band', /\.qrfloat\{[^}]*float:right/.test(CSS));

  // Checked as arithmetic rather than as a number somebody has to remember:
  // the panel hangs off the edge of the window exactly when the breakpoint
  // is narrower than the column, the panel and the gap between them need.
  const pin = CSS.match(/@media \(min-width:(\d+)px\)\{\s*\.qrfloat\{position:fixed[^}]*\}/);
  ok('it pins on a wide screen', !!pin, 'no pinned rule found at all');
  const wrapMax = Number((CSS.match(/\.wrap\{max-width:(\d+)px/) || [])[1]);
  const panel = Number((CSS.match(/\.qrfloat\{[^}]*width:(\d+)px/) || [])[1]);
  const offset = Number((pin && pin[0].match(/left:calc\(50% \+ (\d+)px\)/) || [])[1]);
  ok('the panel clears the content column', offset >= wrapMax / 2,
     `offset ${offset} against half a column of ${wrapMax / 2}`);
  ok('and the breakpoint is wide enough to hold both',
     Number(pin && pin[1]) >= 2 * (offset + panel),
     `breakpoint ${pin && pin[1]} needs ${2 * (offset + panel)}`);

  // Measured from the centre, not the edge: vw counts the scrollbar and the
  // media query does not, so the pair of them cannot be mixed.
  ok('it is offset from the centre rather than the viewport edge',
     !!pin && !/vw/.test(pin[0]), pin && pin[0]);

  // Both codes carry class="qr", at two sizes. An unscoped `img.qr` ties
  // with `.qrfloat img` on specificity, so source order decides, and the
  // big one drew inside the small panel and hung out over the page. Each
  // rule names the container it belongs to, so neither can reach the other.
  const big = CSS.match(/([^{}]*)img\.qr\{[^}]*width:220px/);
  ok('the 220 code is scoped to its own card', !!big && /\.qrwrap\s*$/.test(big[1]),
     big ? `selector was "${big[1].trim()}img.qr"` : 'no 220px rule found');
  const panelImg = CSS.match(/\.qrfloat img\{[^}]*width:(\d+)px/);
  ok('and the panel code is smaller than the panel', !!panelImg && !!panel &&
     Number(panelImg[1]) <= panel, `${panelImg && panelImg[1]} inside ${panel}`);
}

// Copy and duplicate must not read as the same glyph.
{
  const list = await (await h.req('https://ptra.dev/admin/links')).text();
  const copyIcon = (list.match(/class="ic ic-idle"[\s\S]*?<\/svg>/) || [''])[0];
  ok('copy is drawn', copyIcon.length > 0);
  ok('and is not the duplicate glyph', !copyIcon.includes('M12 9.5v5'), copyIcon.slice(0, 120));
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
