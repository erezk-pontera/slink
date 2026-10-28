/**
 * Every admin page is rendered and checked for structure.
 *
 * `check.sh` only parses the modules; it cannot see a template that
 * references a helper nobody imported. That exact mistake has already
 * happened once, and it takes a whole screen down while every other test
 * still passes, so the screens are now rendered here as a matter of course.
 */
import { Harness } from './harness.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

function peer(base) {
  const p = new Harness();
  p.env.KV = base.env.KV;
  p.env.EMAIL = base.env.EMAIL;
  p.mail = base.mail;
  return p;
}

const root = new Harness();
await root.signIn('root@pontera.com');

// Something of each kind to render against.
const dt = Harness.csrfFor(
  await (await root.req('https://ptra.dev/admin/directories')).text(),
  '/admin/directories/new'
);
await root.req('https://ptra.dev/admin/directories/new', {
  form: { _csrf: dt, host: 'ptra.cc', path: 'rend' },
});
const lt = Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
await root.req('https://ptra.dev/admin/links/new', {
  form: { _csrf: lt, host: 'ptra.cc', path: 'rend/one', target: 'example.com/one', status: '302' },
});
const member = peer(root);
await member.signIn('rend@pontera.com');

const PAGES = [
  ['overview', '/admin'],
  ['links', '/admin/links'],
  ['link new', '/admin/links/new'],
  ['link edit', '/admin/links/edit?host=ptra.cc&path=rend%2Fone'],
  ['directories', '/admin/directories'],
  ['directory edit', '/admin/directories/edit?host=ptra.cc&path=rend'],
  ['search', '/admin/search?q=rend'],
  ['search dirs', '/admin/search?q=&type=directories'],
  ['passkeys', '/admin/passkeys'],
  ['domains', '/admin/domains'],
  ['domain edit', '/admin/domains/edit?host=ptra.cc'],
  ['hub domain edit', '/admin/domains/edit?host=ptra.dev'],
  ['users', '/admin/users'],
  ['user edit', '/admin/users/edit?u=rend%40pontera.com'],
  ['settings', '/admin/settings'],
  ['audit', '/admin/audit'],
];

section('every admin page renders');
for (const [name, path] of PAGES) {
  const r = await root.req('https://ptra.dev' + path);
  const body = await r.text();
  const broken =
    r.status >= 500 ||
    /is not defined|is not a function|undefined is not|\[object Object\]|NaN/.test(body);
  ok(`${name} renders`, r.status === 200 && !broken, r.status + (broken ? ' (broken markup)' : ''));

  if (r.status !== 200) continue;
  const count = (re) => (body.match(re) || []).length;
  ok(`${name} markup is balanced`,
     count(/<div\b/g) === count(/<\/div>/g) &&
     count(/<form\b/g) === count(/<\/form>/g) &&
     count(/<table\b/g) === count(/<\/table>/g) &&
     count(/<details\b/g) === count(/<\/details>/g),
     `div ${count(/<div\b/g)}/${count(/<\/div>/g)} form ${count(/<form\b/g)}/${count(/<\/form>/g)}`);

  // No form may nest inside another, and every one needs its token.
  let depth = 0;
  let maxDepth = 0;
  for (const m of body.matchAll(/<form\b|<\/form>/g)) {
    if (m[0] === '</form>') depth--;
    else { depth++; maxDepth = Math.max(maxDepth, depth); }
  }
  ok(`${name} has no nested forms`, maxDepth <= 1, 'depth ' + maxDepth);

  const posts = (body.match(/<form[^>]*method="post"/gi) || []).length;
  const tokens = count(/name="_csrf"/g);
  ok(`${name} gives every POST form a token`, tokens >= posts, `${tokens} tokens, ${posts} posts`);

  ok(`${name} carries no inline script`, !/<script(?![^>]*\bsrc=)/i.test(body));
  ok(`${name} leaves no unrendered template`, !body.includes('${'));
}

section('the visitor-facing pages render too');
{
  const guest = peer(root);
  for (const [name, url] of [
    ['host root', 'https://ptra.cc/'],
    ['unknown shortcut', 'https://ptra.cc/no-such-thing'],
    ['sign in', 'https://ptra.dev/admin'],
  ]) {
    const r = await guest.req(url);
    const body = r.status === 200 ? await r.text() : '';
    ok(`${name} answers`, r.status < 500, String(r.status));
    if (body) ok(`${name} leaves no unrendered template`, !body.includes('${'));
  }
}

console.log(`\nrender: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
