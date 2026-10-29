/**
 * The QR that follows the shortcut field, and the image it can carry.
 *
 * The format check is the security-relevant half: the code is an SVG and
 * the image is inlined into it, so an uploaded SVG would mean serving
 * attacker-chosen markup from this origin. Bytes are sniffed, never the
 * name or the declared type.
 */
import { Harness } from './harness.js';
import worker from '../index.js';
import { hasLogo, logoDataUri, makeLogo, MAX_LOGO_BYTES, sniffImage } from '../qrlogo.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

/** Join strings and byte arrays, without spreading anything large. */
const bytes = (...parts) => {
  const chunks = parts.map((p) =>
    typeof p === 'string' ? Uint8Array.from([...p].map((c) => c.charCodeAt(0))) : Uint8Array.from(p)
  );
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
};
const PNG = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [1, 2, 3, 4]);
const JPEG = bytes([0xff, 0xd8, 0xff], [1, 2, 3]);
const GIF = bytes('GIF89a', [1, 2]);
const WEBP = bytes('RIFF', [0, 0, 0, 0], 'WEBP', [1, 2]);

const root = new Harness();
await root.signIn('root@pontera.com');
const HUB = 'https://ptra.dev';
const page = async (p) => (await root.req(HUB + p)).text();

/* ------------------------------------------------- 1. the format check */
section('only a raster image is accepted');
{
  ok('a PNG is recognised', sniffImage(PNG) === 'image/png');
  ok('a JPEG is recognised', sniffImage(JPEG) === 'image/jpeg');
  ok('a GIF is recognised', sniffImage(GIF) === 'image/gif');
  ok('a WebP is recognised', sniffImage(WEBP) === 'image/webp');

  // The one that matters. An SVG is a document: it can carry script and
  // remote references, and it would be inlined into our own SVG.
  for (const svg of ['<svg xmlns="x">', '<?xml version="1.0"?><svg>', '  <svg>']) {
    ok('an SVG is refused: ' + JSON.stringify(svg.slice(0, 16)), sniffImage(bytes(svg)) === '');
  }
  ok('and so is anything else', sniffImage(bytes('MZ\u0090')) === '' && sniffImage(bytes('%PDF-1.4')) === '');
  ok('a non-array is refused', sniffImage('not bytes') === '');

  ok('an empty upload is refused', makeLogo(new Uint8Array(0)).ok === false);
  ok('an oversized one is refused and says the size',
     /\d+ KB\. The limit is/.test(makeLogo(bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], new Uint8Array(MAX_LOGO_BYTES))).error));
  ok('one at the limit is accepted',
     makeLogo(bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], new Uint8Array(MAX_LOGO_BYTES - 8))).ok);

  // The sniffed type is what gets stored, so a renamed file cannot lie.
  const made = makeLogo(JPEG);
  ok('the stored type comes from the bytes', made.logo.type === 'image/jpeg');
  ok('the data URI carries that type', logoDataUri({ qrLogo: made.logo }).startsWith('data:image/jpeg;base64,'));

  // Read back defensively as well as written carefully.
  ok('a hand-edited type is refused on the way out',
     logoDataUri({ qrLogo: { type: 'image/svg+xml', data: 'PHN2Zz4=' } }) === '');
  ok('so is hand-edited data', logoDataUri({ qrLogo: { type: 'image/png', data: '<not base64>' } }) === '');
  ok('and nothing at all is simply nothing', logoDataUri({}) === '' && hasLogo({}) === false);
}

/* ------------------------------------------------------ 2. the upload */
const upload = async (path, { file, name = 'logo.png', type = 'image/png', remove = false } = {}) => {
  const editHref = '/admin/links/edit?host=ptra.cc&path=' + encodeURIComponent(path);
  const form = new FormData();
  form.set('_csrf', Harness.csrfFor(await page(editHref), '/admin/links/qrlogo'));
  form.set('host', 'ptra.cc');
  form.set('path', path);
  if (remove) form.set('remove', '1');
  if (file) form.set('image', new Blob([file], { type }), name);

  const built = new Request(HUB + '/admin/links/qrlogo', { method: 'POST', body: form });
  const headers = new Headers(built.headers);
  headers.set('Origin', HUB);
  headers.set('CF-Connecting-IP', root.ip);
  const cookie = root.cookieHeader('ptra.dev');
  if (cookie) headers.set('Cookie', cookie);
  const req = new Request(built.url, { method: 'POST', headers, body: await built.arrayBuffer() });
  Object.defineProperty(req, 'cf', { value: { country: 'IL' }, configurable: true });
  const pending = [];
  const res = await worker.fetch(req, root.env, { waitUntil: (p) => pending.push(p) });
  await Promise.allSettled(pending);
  return res;
};

const make = async (path) => {
  const tok = Harness.csrf(await page('/admin/links/new'));
  return root.req(HUB + '/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path, target: 'example.com/' + path, status: '302' },
  });
};

section('uploading a centre image');
{
  await make('qrl');
  const before = await page('/admin/links/edit?host=ptra.cc&path=qrl');
  ok('the upload form is offered', before.includes('name="image"') && before.includes('type="file"'));
  ok('it is a multipart form', before.includes('enctype="multipart/form-data"'));
  ok('the centre choice offers the built-in mark', before.includes('>The Shrink Link mark<'));
  ok('but not a custom one yet', !before.includes('The image you uploaded'));

  const good = await upload('qrl', { file: PNG });
  ok('a PNG uploads', (good.headers.get('Location') || '').includes('m=qr.uploaded'),
     good.status + ' ' + good.headers.get('Location'));

  const after = await page('/admin/links/edit?host=ptra.cc&path=qrl');
  ok('the custom choice appears', after.includes('The image you uploaded'));
  ok('and the page says what is stored', /Using an uploaded PNG/.test(after));

  const code = await root.req(HUB + '/admin/links/qr?host=ptra.cc&path=qrl&logo=custom');
  const svg = await code.text();
  ok('the code inlines it', svg.includes('<image href="data:image/png;base64,'));
  ok('it is placed in the centre box', svg.includes('preserveAspectRatio="xMidYMid meet"'));
  ok('and the code is still an SVG', code.headers.get('Content-Type').includes('image/svg+xml'));
  ok('served inert', (code.headers.get('Content-Security-Policy') || '').includes('sandbox'));

  const removed = await upload('qrl', { remove: true });
  ok('it can be removed', (removed.headers.get('Location') || '').includes('m=qr.removed'));
  const gone = await page('/admin/links/edit?host=ptra.cc&path=qrl');
  ok('and the choice goes with it', !gone.includes('The image you uploaded'));
  const plain = await (await root.req(HUB + '/admin/links/qr?host=ptra.cc&path=qrl&logo=custom')).text();
  ok('asking for it afterwards falls back rather than breaking', !plain.includes('<image href='));
}

section('what the upload refuses');
{
  await make('qrl2');
  // An SVG renamed and relabelled as a PNG. The bytes decide.
  const nasty = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script></svg>';
  const r = await upload('qrl2', { file: bytes(nasty), name: 'logo.png', type: 'image/png' });
  const body = await r.text();
  ok('an SVG renamed .png is refused', body.includes('not a PNG, JPEG, GIF or WebP'));
  ok('and its markup is never echoed back', !body.includes('<script>alert(2)</script>'));
  ok('nor its attribute', !body.includes('onload="alert(1)"'));
  const unchanged = await page('/admin/links/edit?host=ptra.cc&path=qrl2');
  ok('nothing was stored', !unchanged.includes('The image you uploaded'));

  const empty = await upload('qrl2', {});
  ok('no file at all is refused', (await empty.text()).includes('Choose an image file'));

  // The guard before the body is buffered.
  const huge = await upload('qrl2', { file: bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], new Uint8Array(MAX_LOGO_BYTES + 1)) });
  ok('an oversized upload is turned away', !(huge.headers.get('Location') || '').includes('m=qr.uploaded'),
     huge.status + ' ' + huge.headers.get('Location'));

  // Somebody who cannot manage the link cannot change its image.
  const other = new Harness();
  other.env.KV = root.env.KV;
  other.env.EMAIL = root.env.EMAIL;
  other.mail = root.mail;
  await other.signIn('qrstranger@pontera.com');
  const forged = await other.req(HUB + '/admin/links/qrlogo', {
    form: { _csrf: 'forged', host: 'ptra.cc', path: 'qrl2' },
  });
  ok('a forged token is refused', (forged.headers.get('Location') || '').includes('m=csrf'));
}

/* ------------------------------------------------ 3. creating with one */
section('a centre image can be set when the link is created');
{
  const tok = Harness.csrf(await page('/admin/links/new'));
  const form = new FormData();
  form.set('_csrf', tok);
  form.set('host', 'ptra.cc');
  form.set('path', 'qrl3');
  form.set('target', 'example.com/three');
  form.set('status', '302');
  form.set('image', new Blob([JPEG], { type: 'image/jpeg' }), 'mark.jpg');

  const built = new Request(HUB + '/admin/links/new', { method: 'POST', body: form });
  const headers = new Headers(built.headers);
  headers.set('Origin', HUB);
  headers.set('CF-Connecting-IP', root.ip);
  headers.set('Cookie', root.cookieHeader('ptra.dev'));
  const req = new Request(built.url, { method: 'POST', headers, body: await built.arrayBuffer() });
  Object.defineProperty(req, 'cf', { value: { country: 'IL' }, configurable: true });
  const pending = [];
  const res = await worker.fetch(req, root.env, { waitUntil: (p) => pending.push(p) });
  await Promise.allSettled(pending);

  ok('the link is created', (res.headers.get('Location') || '').includes('m=link.created'),
     res.status + ' ' + res.headers.get('Location'));
  const edit = await page('/admin/links/edit?host=ptra.cc&path=qrl3');
  ok('and it already has the image', edit.includes('The image you uploaded'));
  ok('stored as the type the bytes say', /Using an uploaded JPEG/.test(edit));
}

/* --------------------------------------------- 4. the floating preview */
section('the code follows the shortcut field');
{
  const create = await page('/admin/links/new');
  ok('the create screen carries the panel', create.includes('data-slink-qr'));
  ok('it starts hidden', /<aside class="qrfloat" hidden/.test(create));
  ok('it names the endpoint rather than a finished src',
     create.includes('data-base="/admin/links/qr"') && !/qrfloat[\s\S]{0,400}?<img[^>]*src=/.test(create));
  ok('and the field it follows', create.includes('data-path-field="path"'));

  const edit = await page('/admin/links/edit?host=ptra.cc&path=qrl3');
  ok('the edit screen carries it too', edit.includes('data-slink-qr'));
  ok('following the rename field there', edit.includes('data-path-field="newpath"'));
  ok('and asking for the uploaded image', edit.includes('data-logo="custom"'));

  // The endpoint it points at works for a shortcut that does not exist yet,
  // which is what lets the panel fill in while someone is still typing.
  const ahead = await root.req(HUB + '/admin/links/qr?host=ptra.cc&path=not-created-yet&size=300');
  ok('a code is served for an unsaved shortcut', ahead.status === 200,
     String(ahead.status));
  ok('and it encodes the short link', (await ahead.text()).includes('ptra.cc/not-created-yet'));

  const unknownHost = await root.req(HUB + '/admin/links/qr?host=evil.example&path=x');
  ok('an unknown host is refused', (unknownHost.headers.get('Location') || '').includes('m=notfound'));
}

console.log(`\nqr centre image: ${passed} passed, ${failed} failed`);
root.restore();
process.exit(failed ? 1 : 0);
