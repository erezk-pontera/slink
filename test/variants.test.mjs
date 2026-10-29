import { Harness } from './harness.js';
import { normalizeRouting, resolveTarget } from '../targets.js';

let passed = 0;
let failed = 0;
function ok(name, cond, extra = '') {
  if (cond) { passed++; return; }
  failed++;
  console.log('  FAIL: ' + name + (extra ? ' -- ' + extra : ''));
}
function section(n) { console.log('\n' + n); }

const UA = {
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
  ipad: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
  android: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile Safari/537.36',
  androidTablet: 'Mozilla/5.0 (Linux; Android 14; SM-X200) AppleWebKit/537.36 Safari/537.36',
  desktop: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
  twitterbot: 'Twitterbot/1.0',
};

const h = new Harness();
await h.signIn('root@pontera.com');

async function create(form) {
  const token = Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());
  return h.req('https://ptra.dev/admin/links/new', { form: { _csrf: token, ...form } });
}
const where = (r) => r.headers.get('Location');

/* ------------------------------------------------- device slots */
section('a link can send each device somewhere different');
{
  const made = await create({
    host: 'ptra.cc', path: 'app', target: 'https://web.example/', status: '302',
    url__mobileAndroid: 'https://play.example/app',
    url__mobileIos: 'https://apps.example/app',
    url__tabletIos: 'https://apps.example/ipad',
  });
  ok('created with device slots', (made.headers.get('Location') || '').includes('link.created'),
     made.status + ' ' + made.headers.get('Location'));

  const hit = (ua) => h.req('https://ptra.cc/app', { headers: { 'User-Agent': ua } });
  ok('desktop gets the main destination', where(await hit(UA.desktop)) === 'https://web.example/');
  ok('Android phone gets Play', where(await hit(UA.android)) === 'https://play.example/app');
  ok('iPhone gets the App Store', where(await hit(UA.iphone)) === 'https://apps.example/app');
  ok('iPad gets its own link', where(await hit(UA.ipad)) === 'https://apps.example/ipad');
  // Left blank, so it must fall through rather than 404 or break.
  ok('Android tablet falls through to the main destination',
     where(await hit(UA.androidTablet)) === 'https://web.example/',
     String(where(await hit(UA.androidTablet))));

  // Client hints win over the user-agent string.
  const byHint = await h.req('https://ptra.cc/app', {
    headers: { 'User-Agent': UA.desktop, 'Sec-CH-UA-Platform': '"Android"', 'Sec-CH-UA-Mobile': '?1' },
  });
  ok('client hints are preferred', where(byHint) === 'https://play.example/app', String(where(byHint)));
}

/* -------------------------------- destinations no longer branch on country */
section('a destination is chosen by device alone');
{
  await create({
    host: 'ptra.cc', path: 'geo', target: 'https://global.example/', status: '302',
    url__mobileAndroid: 'https://play.example/geo',
  });
  const hit = (ua, country) => h.req('https://ptra.cc/geo', { headers: { 'User-Agent': ua }, country });

  ok('desktop gets the default', where(await hit(UA.desktop, 'FR')) === 'https://global.example/');
  ok('and gets the same thing from anywhere else',
     where(await hit(UA.desktop, 'IL')) === 'https://global.example/',
     String(where(await hit(UA.desktop, 'IL'))));
  ok('Android gets its slot', where(await hit(UA.android, 'FR')) === 'https://play.example/geo');
  ok('from anywhere', where(await hit(UA.android, 'IL')) === 'https://play.example/geo');
  ok('an unset slot falls through to the default',
     where(await hit(UA.iphone, 'IL')) === 'https://global.example/');

  // The form no longer offers them, and a submitted rule is ignored rather
  // than stored.
  const form = await (await h.req('https://ptra.dev/admin/links/new')).text();
  ok('the create form offers no country rules', !form.includes('rules__default'));
  ok('nor any mention of them', !/country rule/i.test(form));
  await create({
    host: 'ptra.cc', path: 'nogeo', target: 'https://global.example/', status: '302',
    rules__default: 'IL https://il.example/',
  });
  ok('a hand-made country rule is ignored',
     where(await h.req('https://ptra.cc/nogeo', { headers: { 'User-Agent': UA.desktop }, country: 'IL' })) ===
       'https://global.example/');

  // A record stored before they were removed resolves by device alone.
  const stale = {
    routing: {
      default: { url: 'https://global.example/', rules: [{ countries: ['IL'], url: 'https://old.example/' }] },
      mobileAndroid: { url: 'https://play.example/geo', rules: [] },
    },
    target: 'https://global.example/',
  };
  ok('an old record ignores the rules it still carries',
     resolveTarget(stale, { device: 'desktop' }).url === 'https://global.example/');
  ok('and still honours its device slots',
     resolveTarget(stale, { device: 'mobileAndroid' }).url === 'https://play.example/geo');
  ok('normalising drops the stored rules', !('rules' in normalizeRouting(stale.routing).default));

  // Every branch is still validated.
  const bad = await create({
    host: 'ptra.cc', path: 'evilvariant', target: 'https://ok.example/', status: '302',
    url__mobileIos: 'javascript:alert(1)',
  });
  ok('a dangerous scheme in a device slot is refused', (await bad.text()).includes('not allowed'));
}

/* --------------------------------------------------- previews */
section('preview cards, on public domains only');
{
  await create({
    host: 'ptra.cc', path: 'card', target: 'https://dest.example/', status: '302',
    previewEnabled: '1', previewTitle: 'Quarterly deck',
    previewDescription: 'The numbers', previewImage: 'https://img.example/c.png',
  });

  const bot = await h.req('https://ptra.cc/card', { headers: { 'User-Agent': UA.twitterbot } });
  const card = await bot.text();
  ok('a crawler gets the card', bot.status === 200 && card.includes('og:title'), String(bot.status));
  ok('the title is in the card', card.includes('content="Quarterly deck"'));
  ok('the image makes it a large card', card.includes('summary_large_image'));
  // The href itself, not a URL looked for anywhere in the markup: the
  // question is where the canonical points, which is an equality.
  const canonical = (card.match(/<link rel="canonical" href="([^"]*)"/) || [])[1];
  ok('the canonical points at the short link', canonical === 'https://ptra.cc/card', String(canonical));

  const person = await h.req('https://ptra.cc/card', { headers: { 'User-Agent': UA.desktop } });
  ok('a person still gets the redirect',
     person.status === 302 && where(person) === 'https://dest.example/',
     person.status + ' ' + where(person));

  // ptra.dev requires sign-in, so it must never emit a card.
  await create({
    host: 'ptra.dev', path: 'secretcard', target: 'https://internal.example/', status: '302',
    previewEnabled: '1', previewTitle: 'Internal roadmap',
  });
  const edit = await (await h.req('https://ptra.dev/admin/links/edit?host=ptra.dev&path=secretcard')).text();
  ok('the editor explains why there is no card', edit.includes('requires sign-in, so its links never show a preview card'));
  ok('nothing was stored for it', !edit.includes('Internal roadmap'),
     'a title was persisted on a sign-in-only domain');

  const anon = new Harness();
  anon.env.KV = h.env.KV;
  const gated = await anon.req('https://ptra.dev/secretcard', { headers: { 'User-Agent': UA.twitterbot } });
  ok('a crawler on the gated domain is bounced, not unfurled',
     gated.status === 303 && (where(gated) || '').startsWith('/admin?next='),
     gated.status + ' ' + where(gated));

  const nonHttps = await create({
    host: 'ptra.cc', path: 'badimg', target: 'https://ok.example/', status: '302',
    previewEnabled: '1', previewTitle: 't', previewImage: 'http://img.example/x.png',
  });
  ok('a non-https card image is refused', (await nonHttps.text()).includes('must be an https URL'));
}

/* -------------------------------------------------- duplicate */
section('duplicating a link');
{
  const editUrl = 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=geo';
  const body = await (await h.req(editUrl)).text();
  ok('the editor offers it', body.includes('action="/admin/links/duplicate"'));

  const dup = await h.req('https://ptra.dev/admin/links/duplicate', {
    form: { _csrf: Harness.csrfFor(body, '/admin/links/duplicate'), host: 'ptra.cc', path: 'geo' },
  });
  const form = await dup.text();
  ok('it lands on the create form', dup.status === 200 && form.includes('action="/admin/links/new"'),
     String(dup.status));
  ok('it says where the copy came from', form.includes('Copied from ptra.cc/geo'));
  ok('the shortcut is cleared', /name="path" type="text" value=""/.test(form),
     (form.match(/name="path"[^>]*/) || [''])[0]);
  ok('the destination came across', form.includes('value="https://global.example/"'));
  ok('the device slot came across', form.includes('value="https://play.example/geo"'));

  // The original is untouched.
  const original = await h.req('https://ptra.cc/geo', {
    headers: { 'User-Agent': UA.desktop }, country: 'FR',
  });
  ok('the original still works', where(original) === 'https://global.example/', String(where(original)));

  // Someone who may not manage the source may not copy it. They cannot even
  // obtain a token, because the form only renders on a link they can manage,
  // so check the refusal over HTTP and the rule itself directly.
  const stranger = new Harness();
  stranger.env.KV = h.env.KV; stranger.env.EMAIL = h.env.EMAIL; stranger.mail = h.mail;
  await stranger.signIn('nosy@pontera.com');
  const sEdit = await stranger.req(editUrl);
  ok('a stranger cannot open the source at all', sEdit.status === 403, String(sEdit.status));

  const sTok = Harness.csrf(await (await stranger.req('https://ptra.dev/admin/links/new')).text());
  const refused = await stranger.req('https://ptra.dev/admin/links/duplicate', {
    form: { _csrf: sTok, host: 'ptra.cc', path: 'geo' },
  });
  const refusedBody = await refused.text();
  ok('a stranger is refused the copy',
     refused.status !== 200 || !refusedBody.includes('action="/admin/links/new"'),
     refused.status + ' ' + (where(refused) || ''));

  const { loadConfig } = await import('../config.js');
  const { canManageLink } = await import('../permissions.js');
  const { getUserByNorm } = await import('../users.js');
  const { getLink } = await import('../links.js');
  const cfg = await loadConfig(h.env);
  const verdict = await canManageLink(cfg, {
    user: await getUserByNorm(cfg, 'nosy@pontera.com'),
    link: await getLink(cfg, 'ptra.cc', 'geo'),
    host: 'ptra.cc',
  });
  ok('and the rule itself refuses them', verdict.allowed === false, String(verdict.reason));
}

console.log(`\nvariants: ${passed} passed, ${failed} failed`);
h.restore();
if (failed) process.exit(1);
