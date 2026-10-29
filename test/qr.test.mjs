/**
 * The encoder is checked three ways: a published Reed-Solomon vector, the
 * structural invariants the specification fixes, and the properties of the
 * BCH format code. During development every version was also compared
 * module-for-module against an independent encoder and decoded from rendered
 * output; that needs packages the Worker does not carry, so what remains
 * here is everything checkable with no dependencies.
 */
import { Harness } from './harness.js';
import { ECC_LEVELS, encode, levelForLogo, reedSolomon, toSvg } from '../qr.js';
import { minVersionForLogo, qrOptions } from '../admin-qr.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

/* ------------------------------------------------ 1. error correction */
section('Reed-Solomon');
{
  // The worked example from the specification: version 1-Q, "HELLO WORLD".
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
  const want = [196, 35, 39, 119, 235, 215, 231, 226, 93, 23];
  ok('matches the published vector', JSON.stringify(reedSolomon(data, 10)) === JSON.stringify(want));

  // The remainder of an all-zero message is zero, for any length.
  ok('zero message gives zero parity', reedSolomon([0, 0, 0, 0], 10).every((b) => b === 0));
  ok('parity length follows the request', reedSolomon([1, 2, 3], 17).length === 17);
}

/* -------------------------------------------------- 2. the symbol itself */
section('symbol structure');
{
  for (const [version, size] of [[1, 21], [2, 25], [7, 45], [40, 177]]) {
    const q = encode('https://ptra.cc/a', { level: 'L', minVersion: version });
    ok(`version ${version} is ${size} modules`, q.size === size && q.version === version,
       `${q.version}/${q.size}`);
  }

  const q = encode('https://ptra.cc/abc', { level: 'M' });
  const m = q.modules;
  const n = q.size;
  ok('every module is 0 or 1', m.every((row) => row.every((v) => v === 0 || v === 1)));
  ok('rows are square', m.length === n && m.every((row) => row.length === n));

  // Finder patterns: a 7x7 ring with a 3x3 core, in three corners.
  const finderAt = (r, c) =>
    m[r][c] === 1 && m[r + 6][c] === 1 && m[r][c + 6] === 1 && m[r + 6][c + 6] === 1 &&
    m[r + 1][c + 1] === 0 && m[r + 3][c + 3] === 1 && m[r + 2][c + 2] === 1;
  ok('finder top-left', finderAt(0, 0));
  ok('finder top-right', finderAt(0, n - 7));
  ok('finder bottom-left', finderAt(n - 7, 0));
  // The fourth corner carries an alignment pattern instead: a 5x5 with a
  // dark centre, a light ring and a dark border. Version 2 has exactly one,
  // centred at (18,18); the other three candidates fall under the finders.
  const alignAt = (r, c) =>
    m[r][c] === 1 &&
    [[-1,0],[1,0],[0,-1],[0,1],[-1,-1],[1,1],[-1,1],[1,-1]].every(([dr, dc]) => m[r + dr][c + dc] === 0) &&
    [[-2,-2],[-2,2],[2,-2],[2,2],[0,-2],[0,2],[-2,0],[2,0]].every(([dr, dc]) => m[r + dr][c + dc] === 1);
  ok('alignment pattern bottom-right', alignAt(18, 18));

  // Separators: the light ring around each finder.
  ok('separator under the top-left finder', m[7].slice(0, 8).every((v) => v === 0));
  ok('separator beside the top-left finder', [0,1,2,3,4,5,6,7].every((r) => m[r][7] === 0));

  // Timing patterns alternate, starting and ending dark.
  let timingOk = true;
  for (let i = 8; i < n - 8; i++) {
    if (m[6][i] !== (i % 2 === 0 ? 1 : 0)) timingOk = false;
    if (m[i][6] !== (i % 2 === 0 ? 1 : 0)) timingOk = false;
  }
  ok('timing patterns alternate', timingOk);
  ok('the dark module is dark', m[n - 8][8] === 1);
}

/* ------------------------------------------------- 3. the format code */
section('format information');
{
  // BCH(15,5) has a minimum Hamming distance of 7, so any two of the 32
  // format strings differ in at least 7 places. That is the property the
  // code exists for, and it catches an error in the generator polynomial
  // or the masking constant that a single hardcoded value would not.
  const bits = [];
  for (const level of ECC_LEVELS) {
    for (let mask = 0; mask < 8; mask++) {
      // Read the written cells back out of a symbol rather than reaching
      // into a private function.
      const q = encode('x', { level, minVersion: 1 });
      if (q.mask !== mask) continue;
      let v = 0;
      for (let i = 0; i < 6; i++) v |= q.modules[i][8] << i;
      v |= q.modules[7][8] << 6;
      v |= q.modules[8][8] << 7;
      for (let i = 8; i < 15; i++) v |= q.modules[q.size - 15 + i][8] << i;
      bits.push({ level, mask, v });
    }
  }
  ok('a format string was recovered for each symbol', bits.length >= 4, String(bits.length));

  // Both copies of the format agree with each other.
  let copiesAgree = true;
  for (const level of ECC_LEVELS) {
    const q = encode('x', { level, minVersion: 1 });
    for (let i = 0; i < 8; i++) {
      const a = i < 6 ? q.modules[i][8] : i < 8 ? q.modules[i + 1][8] : 0;
      const b = q.modules[8][q.size - 1 - i];
      if (i < 8 && a !== b) copiesAgree = false;
    }
  }
  ok('the two copies of the format agree', copiesAgree);

  const distinct = new Set(bits.map((b) => b.v));
  ok('each level produces a different format string', distinct.size === bits.length);

  const popcount = (x) => { let n = 0; while (x) { n += x & 1; x >>>= 1; } return n; };
  let minDistance = 99;
  for (let i = 0; i < bits.length; i++) {
    for (let j = i + 1; j < bits.length; j++) {
      minDistance = Math.min(minDistance, popcount(bits[i].v ^ bits[j].v));
    }
  }
  ok('format strings are at least 7 bits apart', bits.length < 2 || minDistance >= 7, String(minDistance));
}

/* --------------------------------------------------------- 4. encoding */
section('payloads');
{
  ok('utf-8 is carried', !!encode('https://ptra.cc/café-日本', { level: 'M' }));
  // 1000 bytes needs 1003 codewords, which first fits at version 22 level L.
  ok('a long payload picks the version that fits',
     encode('x'.repeat(1000), { level: 'L' }).version === 22,
     String(encode('x'.repeat(1000), { level: 'L' }).version));
  ok('a short payload picks version 1', encode('hi', { level: 'L' }).version === 1);

  let threw = false;
  try { encode('x'.repeat(5000), { level: 'H' }); } catch { threw = true; }
  ok('too much data is refused, not truncated', threw);

  // More correction means a bigger symbol for the same payload.
  const text = 'https://ptra.cc/some/medium/length/path';
  ok('H needs at least as many modules as L',
     encode(text, { level: 'H' }).size >= encode(text, { level: 'L' }).size);
}

/* -------------------------------------------------------------- 5. SVG */
section('SVG output');
{
  const svg = toSvg('https://ptra.cc/abc', { size: 256 });
  ok('is a standalone document', svg.startsWith('<svg') && svg.includes('xmlns='));
  ok('honours the requested size', svg.includes('width="256"') && svg.includes('height="256"'));
  ok('carries no script', !/<script/i.test(svg));
  ok('references nothing remote', !/https?:\/\//.test(svg.replace(/xmlns="[^"]*"/g, '').replace(/aria-label="[^"]*"/g, '')));
  ok('has a quiet zone', svg.includes('viewBox="0 0 33 33'), svg.match(/viewBox="[^"]*"/)?.[0]);

  const withLogo = toSvg('https://ptra.cc/abc', { size: 256, logo: '<rect width="512" height="512"/>' });
  ok('a logo is nested and scaled', withLogo.includes('<g transform="translate('));
  ok('a logo sits on a plate', (withLogo.match(/<rect/g) || []).length >= 2);

  ok('a bigger logo asks for more correction', ECC_LEVELS.indexOf(levelForLogo(0.2)) >= ECC_LEVELS.indexOf(levelForLogo(0.05)));
  ok('a larger logo needs a larger symbol', minVersionForLogo(0.25) > minVersionForLogo(0.15));
}

/* ----------------------------------------------------------- 6. options */
section('request options');
{
  const of = (q) => qrOptions(new URLSearchParams(q));
  ok('size is clamped low', of('size=1').size === 64);
  ok('size is clamped high', of('size=99999').size === 2048);
  ok('a bad size falls back', of('size=abc').size === 512);
  ok('margin is clamped', of('margin=99').margin === 8 && of('margin=-3').margin === 0);
  ok('an unknown level falls back to M', of('ecc=Z').level === 'M');
  ok('a known level is kept', of('ecc=Q').level === 'Q');
  ok('a logo raises a weak level', of('logo=1&ecc=L').level === 'H');
  ok('a logo raises the version floor', of('logo=1').minVersion >= 3);
  ok('no logo means no floor', of('').minVersion === 1);
  ok('logo scale is clamped', of('logo=1&logoscale=0.9').logoScale === 0.25);
}

/* ------------------------------------------------------- 7. the endpoint */
section('the endpoint');
{
  const root = new Harness();
  await root.signIn('root@pontera.com');
  const tok = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
  await root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'qr-test', target: 'example.com/q', status: '302' },
  });

  const r = await root.req('https://ptra.dev/admin/links/qr?host=ptra.cc&path=qr-test&size=256');
  ok('serves an SVG', r.status === 200 && (r.headers.get('Content-Type') || '').includes('image/svg+xml'));
  ok('is sandboxed', (r.headers.get('Content-Security-Policy') || '').includes('sandbox'));
  ok('is not sniffable', r.headers.get('X-Content-Type-Options') === 'nosniff');
  ok('is private to the viewer', (r.headers.get('Cache-Control') || '').includes('private'));

  const body = await r.text();
  const encoded = (body.match(/aria-label="([^"]*)"/) || [])[1];
  ok('encodes the short link', encoded === 'https://ptra.cc/qr-test', String(encoded));

  const unknown = await root.req('https://ptra.dev/admin/links/qr?host=evil.example&path=x');
  ok('an unknown host is refused', unknown.status === 303, String(unknown.status));

  const badPath = await root.req('https://ptra.dev/admin/links/qr?host=ptra.cc&path=' + encodeURIComponent('a b/../c'));
  ok('an invalid shortcut is refused', badPath.status === 303, String(badPath.status));

  const anon = new Harness();
  anon.env.KV = root.env.KV;
  const out = await anon.req('https://ptra.dev/admin/links/qr?host=ptra.cc&path=qr-test');
  ok('an anonymous visitor is sent to sign in',
     out.status === 303 && (out.headers.get('Location') || '').startsWith('/admin?next='));

  const page = await (await root.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=qr-test')).text();
  ok('the edit page offers the card', page.includes('<h2>QR code</h2>'));
  ok('with a preview', /<img class="qr"/.test(page));
  ok('and a download', page.includes('Download SVG'));
  root.restore();
}

console.log(`\nqr: ${passed} passed, ${failed} failed`);
export default { passed, failed };
