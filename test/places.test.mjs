/**
 * Where a link lives.
 *
 * A shortcut is one segment and never carries a '/': the directory is a
 * separate control, offering exactly the places the person may create in.
 * These check the two halves agree - that the form offers nothing the
 * submit would refuse, and refuses nothing the form offered.
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

const newToken = async (h = root) =>
  Harness.csrf(await (await h.req('https://ptra.dev/admin/links/new')).text());
const create = async (h, form) =>
  h.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: await newToken(h), status: '302', ...form },
  });
const mkDir = async (host, path, extra = {}) => {
  const tok = Harness.csrfFor(
    await (await root.req('https://ptra.dev/admin/directories')).text(),
    '/admin/directories/new'
  );
  return root.req('https://ptra.dev/admin/directories/new', {
    form: { _csrf: tok, host, path, ...extra },
  });
};
async function setDomainPolicy(host, policy) {
  const page = await (await root.req(`https://ptra.dev/admin/domains/edit?host=${host}`)).text();
  return root.req('https://ptra.dev/admin/domains/edit', {
    form: {
      _csrf: Harness.csrfFor(page, '/admin/domains/edit'),
      host,
      allowedAuthDomains: 'pontera.com',
      rootCreatePolicy: 'email_domain',
      allowedCreateDomains: 'pontera.com',
      defaultStatus: '302',
      enabled: '1',
      ...(host === 'ptra.dev' ? { authRequired: '1' } : {}),
      it_countdown: 'optional',
      it_defaultDelay: '5',
      it_minDelay: '0',
      it_destination: 'optional',
      it_defaultShowTarget: '1',
      ...policy,
    },
  });
}
const dirEdit = (host, path) =>
  `https://ptra.dev/admin/directories/edit?host=${host}&path=${encodeURIComponent(path)}`;
const linkEdit = (host, path) =>
  `https://ptra.dev/admin/links/edit?host=${host}&path=${encodeURIComponent(path)}`;

await mkDir('ptra.cc', 'eng');
await mkDir('ptra.cc', 'ops');
await mkDir('ptra.cc', 'anyone', { createAccess: 'signed_in' });

/* ------------------------------------------------- 1. the shortcut field */
section('a shortcut is one segment');
{
  const refused = await create(root, {
    host: 'ptra.cc', dir: 'ptra.cc/', path: 'eng/deck', target: 'example.com/d',
  });
  const body = await refused.text();
  ok('a shortcut containing "/" is refused', body.includes('cannot contain'), body.slice(0, 120));
  ok('and says where the directory is chosen', body.includes('Pick the directory from the list'));

  const made = await create(root, {
    host: 'ptra.cc', dir: 'ptra.cc/eng', path: 'Deck', target: 'example.com/d',
  });
  ok('the picker puts it in the directory',
     (made.headers.get('Location') || '').includes('path=eng%2Fdeck'),
     made.headers.get('Location'));
  ok('and it resolves there', (await root.req('https://ptra.cc/eng/deck')).status === 302);

  // The create form no longer invites a path at all.
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('the form says so', form.includes('No &quot;/&quot;') || form.includes('No "/"'), '');
  ok('and caps the field at one segment', /name="path"[^>]*maxlength="64"/.test(form));
}

/* --------------------------------------------------- 2. the picker lists */
section('the picker offers every place and only those places');
{
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  const options = (form.match(/<option value="[^"]*" ?[^>]*data-host[^>]*>[^<]*<\/option>/g) || []).join('\n');
  ok('the root of each domain is offered',
     options.includes('>ptra.cc/<') && options.includes('>ptra.dev/<'), options);
  ok('so is each directory', options.includes('>ptra.cc/eng/<') && options.includes('>ptra.cc/ops/<'));
  ok('each option carries its domain', /data-host="ptra\.cc"/.test(options) && /data-host="ptra\.dev"/.test(options));

}

/* ------------------------------------------------- 3. a mismatched pair */
section('the pair has to agree');
{
  const crossed = await create(root, {
    host: 'ptra.dev', dir: 'ptra.cc/eng', path: 'crossed', target: 'example.com/x',
  });
  const body = await crossed.text();
  ok('a directory on another domain is refused', body.includes('That directory is on ptra.cc'), body.slice(0, 200));

  const gone = await create(root, {
    host: 'ptra.cc', dir: 'ptra.cc/nosuch', path: 'ghost', target: 'example.com/x',
  });
  ok('and so is one that does not exist', (await gone.text()).includes('no longer exists'));

  // No directory at all still means the root, so a scripted post that
  // predates the picker keeps working.
  const plain = await create(root, { host: 'ptra.cc', path: 'plainroot', target: 'example.com/p' });
  ok('a post with no directory lands at the root',
     (plain.headers.get('Location') || '').includes('path=plainroot'), plain.headers.get('Location'));
}

/* ----------------------------------------------------------- 4. moving */
section('a link can be moved between directories');
{
  const href = linkEdit('ptra.cc', 'eng/deck');
  const page = await (await root.req(href)).text();
  ok('the editor shows the directory it is in', /name="dir"[\s\S]*?value="ptra\.cc\/eng" selected/.test(page),
     (page.match(/<option value="ptra.cc\/[^"]*"[^>]*>/g) || []).join(' '));
  ok('and the shortcut alone in its own field', /name="newpath"[^>]*value="deck"/.test(page),
     (page.match(/name="newpath"[^>]*value="[^"]*"/) || [''])[0]);

  const tok = Harness.csrfFor(page, '/admin/links/edit');
  const moved = await root.req('https://ptra.dev/admin/links/edit', {
    form: {
      _csrf: tok, host: 'ptra.cc', path: 'eng/deck', dir: 'ptra.cc/ops', newpath: 'deck',
      target: 'https://example.com/d', status: '302', enabled: '1', countdownSet: '1',
    },
  });
  ok('the move is accepted', (moved.headers.get('Location') || '').includes('path=ops%2Fdeck'),
     moved.status + ' ' + moved.headers.get('Location'));
  ok('it answers at the new address', (await root.req('https://ptra.cc/ops/deck')).status === 302);
  ok('and no longer at the old one',
     !((await root.req('https://ptra.cc/eng/deck')).headers.get('Location') || '').includes('example.com/d'));

  // Moving needs create permission where it is going.
  const guest = peer(root);
  await guest.signIn('mover@pontera.com');
  const own = await create(guest, { host: 'ptra.cc', dir: 'ptra.cc/', path: 'movermine', target: 'example.com/m' });
  ok('the mover has a link of their own', (own.headers.get('Location') || '').includes('link.created'));
  const mine = linkEdit('ptra.cc', 'movermine');
  const minePage = await (await guest.req(mine)).text();
  ok('they are not offered a directory they cannot create in', !minePage.includes('>ptra.cc/eng/<'));
  const mineTok = Harness.csrfFor(minePage, '/admin/links/edit');
  const refused = await guest.req('https://ptra.dev/admin/links/edit', {
    form: {
      _csrf: mineTok, host: 'ptra.cc', path: 'movermine', dir: 'ptra.cc/eng', newpath: 'movermine',
      target: 'https://example.com/m', status: '302', enabled: '1', countdownSet: '1',
    },
  });
  ok('and posting one anyway is refused',
     (await refused.text()).includes('do not have permission to create in this directory'));
  ok('the link stayed where it was',
     ((await root.req('https://ptra.cc/movermine')).headers.get('Location') || '').includes('example.com/m'));
}

/* ------------------------------------- 5. a link already holding a slash */
section('a link stored before the rule still edits');
{
  // Written straight into the store, the way one created under the old
  // free-form field would be: a path two deep with no directory record.
  const legacy = { ...(await root.env.KV.get('lnk:ptra.cc:plainroot', { type: 'json' })) };
  legacy.path = 'old/thing';
  legacy.pathLc = 'old/thing';
  await root.env.KV.put('lnk:ptra.cc:old/thing', JSON.stringify(legacy));

  const page = await (await root.req(linkEdit('ptra.cc', 'old/thing'))).text();
  ok('the editor opens it', page.includes('name="newpath"'));
  ok('its own place is offered even with no directory record',
     /value="ptra\.cc\/old" selected/.test(page),
     (page.match(/<option value="ptra.cc\/[^"]*"[^>]*>/g) || []).join(' '));
  ok('with the shortcut split out', /name="newpath"[^>]*value="thing"/.test(page));
}

/* ------------------------------------------- 6. the list row affordances */
section('a row opens, copies and duplicates');
{
  const list = await (await root.req('https://ptra.dev/admin/links')).text();
  ok('the short link opens in a new tab',
     /<a href="https:\/\/ptra\.cc\/[^"]*" target="_blank" rel="noopener noreferrer"/.test(list),
     (list.match(/<a href="https:\/\/ptra\.cc[^>]*>/) || [''])[0]);
  ok('copy is a button, not a word', list.includes('class="iconbtn"') && !/>Copy<\/button>/.test(list));
  ok('and it carries the address to copy', /data-copy="https:\/\/ptra\.cc\//.test(list));
  ok('duplicate is offered', list.includes('action="/admin/links/duplicate"'));
  ok('the icons are labelled for a screen reader', /aria-label="Duplicate ptra\.cc\//.test(list));

  // The directory filter is a list of the directories that exist.
  ok('the filter offers directories', /name="dir"[\s\S]*?<option value="eng">eng\/<\/option>/.test(list),
     (list.match(/<select id="f_dir"[\s\S]*?<\/select>/) || [''])[0].slice(0, 200));

  const dupTok = Harness.csrfFor(list, '/admin/links/duplicate');
  const dup = await root.req('https://ptra.dev/admin/links/duplicate', {
    form: { _csrf: dupTok, host: 'ptra.cc', path: 'ops/deck' },
  });
  const dupBody = await dup.text();
  ok('duplicating from the list opens the create form', dupBody.includes('<h1>Create a link</h1>'));
  ok('it starts in the same directory', /value="ptra\.cc\/ops" selected/.test(dupBody),
     (dupBody.match(/<option value="ptra.cc\/[^"]*"[^>]*>/g) || []).join(' '));
  ok('with the shortcut cleared', /name="path"[^>]*value=""/.test(dupBody));
}

/* ------------------------------------------- 7. the directory setting UI */
section('who may create in a directory');
{
  const page = await (await root.req(dirEdit('ptra.cc', 'anyone'))).text();
  ok('the setting is a choice of three', (page.match(/name="createAccess"[\s\S]*?<\/select>/) || [''])[0]
     .match(/<option/g).length === 3);
  ok('and shows what this one is set to', /value="signed_in" selected/.test(page));

  const list = await (await root.req('https://ptra.dev/admin/directories?host=ptra.cc')).text();
  ok('the list badges it', list.includes('>anyone</span>'), '');
}

/* ----------------------------- 8. a directory open to anyone signed in */
section('a directory can take anyone who can sign in');
{
  // With the root shut, an ordinary account has nowhere to create unless a
  // directory says otherwise. That is the case the setting exists for.
  await setDomainPolicy('ptra.cc', { rootCreatePolicy: 'explicit' });

  const guest = peer(root);
  await guest.signIn('nobody@pontera.com');
  const theirs = await (await guest.req('https://ptra.dev/admin/links/new?host=ptra.cc')).text();
  ok('they are not offered the domain root', !/>ptra\.cc\/</.test(theirs),
     (theirs.match(/<option value="ptra.cc[^"]*"[^>]*>[^<]*</g) || []).join(' '));
  ok('but are offered the directory open to anyone signed in', theirs.includes('>ptra.cc/anyone/<'));
  ok('and not the ones that are not', !theirs.includes('>ptra.cc/eng/<'));
  ok('with it chosen for them, since it is the only one',
     /value="ptra\.cc\/anyone" selected/.test(theirs),
     (theirs.match(/<option value="ptra.cc[^"]*"[^>]*>/g) || []).join(' '));

  const got = await create(guest, {
    host: 'ptra.cc', dir: 'ptra.cc/anyone', path: 'mine', target: 'example.com/v',
  });
  ok('and may create there', (got.headers.get('Location') || '').includes('link.created'),
     got.status + ' ' + got.headers.get('Location'));
  const shut = await create(guest, {
    host: 'ptra.cc', dir: 'ptra.cc/eng', path: 'sneak', target: 'example.com/v',
  });
  ok('while a directory they were not offered is still refused',
     (await shut.text()).includes('do not have permission to create in this directory'));
  const atRoot = await create(guest, {
    host: 'ptra.cc', dir: 'ptra.cc/', path: 'sneakroot', target: 'example.com/v',
  });
  ok('and so is the root they were not offered',
     (await atRoot.text()).includes('do not have permission to create at the root'));

  // Withdrawing the setting shuts the door again.
  const page = await (await root.req(dirEdit('ptra.cc', 'anyone'))).text();
  const tok = Harness.csrfFor(page, '/admin/directories/edit');
  await root.req('https://ptra.dev/admin/directories/edit', {
    form: { _csrf: tok, host: 'ptra.cc', path: 'anyone', createAccess: 'granted', enabled: '1' },
  });
  const after = await create(guest, {
    host: 'ptra.cc', dir: 'ptra.cc/anyone', path: 'after', target: 'example.com/a',
  });
  ok('withdrawing it shuts the door again',
     (await after.text()).includes('do not have permission to create in this directory'));
  const gone = await (await guest.req('https://ptra.dev/admin/links/new?host=ptra.cc')).text();
  ok('and the form stops offering it', !gone.includes('>ptra.cc/anyone/<'));
}

console.log(`\nplaces: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
