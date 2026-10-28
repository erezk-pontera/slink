import assert from 'node:assert/strict';
import { makeEnv } from './fakekv.js';
import { loadConfig } from '../config.js';
import { ensureBootstrapDomains, getDomain, putDomain } from '../domains.js';
import { newUser, putUser } from '../users.js';
import { newDirectory, putDirectory, newGrant, putGrant } from '../directories.js';
import { canCreate, canManageLink, canManageDirectory, canSetReadonly } from '../permissions.js';
import { newLink } from '../links.js';

let pass = 0;
const checks = [];
function check(name, actual, expected) {
  checks.push({ name, actual, expected });
  assert.deepEqual(actual, expected, `${name}: got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`);
  pass++;
}

const cfg = await loadConfig(makeEnv());
await ensureBootstrapDomains(cfg);
const cc = await getDomain(cfg, 'ptra.cc');

// Users
const root = newUser('root@pontera.com', 'root@pontera.com');
const admin = newUser('admin@pontera.com', 'admin@pontera.com', { isAdmin: true });
const staff = newUser('staff@pontera.com', 'staff@pontera.com');
const other = newUser('someone@pontera.com', 'someone@pontera.com');
const outsider = newUser('x@gmail.com', 'x@gmail.com');
const disabled = newUser('off@pontera.com', 'off@pontera.com', { disabled: true });
for (const u of [root, admin, staff, other, outsider, disabled]) await putUser(cfg, u);

// ---- root-level creation on ptra.cc (DEFAULT_ALLOWED_DOMAINS = pontera.com)
check('staff may create at root', (await canCreate(cfg, { user: staff, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, true);
check('outsider may not create at root', (await canCreate(cfg, { user: outsider, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, false);
check('anonymous may not create', (await canCreate(cfg, { user: null, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, false);
check('disabled may not create', (await canCreate(cfg, { user: disabled, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, false);
check('root admin may create', (await canCreate(cfg, { user: root, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, true);

// outsider with an explicit per-host grant
outsider.rootCreate = { 'ptra.cc': true };
await putUser(cfg, outsider);
check('outsider with explicit grant may create', (await canCreate(cfg, { user: outsider, domain: cc, host: 'ptra.cc', pathLc: 'aaa' })).allowed, true);

// admins_only policy
const ccLocked = { ...cc, rootCreatePolicy: 'admins_only' };
check('admins_only blocks staff', (await canCreate(cfg, { user: staff, domain: ccLocked, host: 'ptra.cc', pathLc: 'aaa' })).allowed, false);
check('admins_only allows admin', (await canCreate(cfg, { user: admin, domain: ccLocked, host: 'ptra.cc', pathLc: 'aaa' })).allowed, true);

// readonly domain
const ccRo = { ...cc, readonly: true };
check('readonly domain blocks staff', (await canCreate(cfg, { user: staff, domain: ccRo, host: 'ptra.cc', pathLc: 'aaa' })).allowed, false);
check('readonly domain allows admin', (await canCreate(cfg, { user: admin, domain: ccRo, host: 'ptra.cc', pathLc: 'aaa' })).allowed, true);

// ---- directory /pub restricted to `staff`
const pub = newDirectory('ptra.cc', 'pub', 'pub', { ownerId: admin.id });
await putDirectory(cfg, pub);
await putGrant(cfg, newGrant('ptra.cc', 'pub', staff, { canCreate: true, canManage: false }));

check('granted user may create in dir', (await canCreate(cfg, { user: staff, domain: cc, host: 'ptra.cc', pathLc: 'pub/x' })).allowed, true);
check('ungranted user blocked in dir despite root rights', (await canCreate(cfg, { user: other, domain: cc, host: 'ptra.cc', pathLc: 'pub/x' })).allowed, false);
check('admin may create in dir', (await canCreate(cfg, { user: admin, domain: cc, host: 'ptra.cc', pathLc: 'pub/x' })).allowed, true);
check('other may still create at root', (await canCreate(cfg, { user: other, domain: cc, host: 'ptra.cc', pathLc: 'zzz' })).allowed, true);

// open directory falls through to root policy
const openDir = newDirectory('ptra.cc', 'open', 'open', { open: true });
await putDirectory(cfg, openDir);
check('open dir allows root-eligible user', (await canCreate(cfg, { user: other, domain: cc, host: 'ptra.cc', pathLc: 'open/x' })).allowed, true);

// nested directory resolution picks the longest parent
const eng = newDirectory('ptra.cc', 'pub/eng', 'pub/eng');
await putDirectory(cfg, eng);
await putGrant(cfg, newGrant('ptra.cc', 'pub/eng', other, { canCreate: true }));
check('nested dir grant applies', (await canCreate(cfg, { user: other, domain: cc, host: 'ptra.cc', pathLc: 'pub/eng/x' })).allowed, true);
check('parent grant does not leak into child', (await canCreate(cfg, { user: staff, domain: cc, host: 'ptra.cc', pathLc: 'pub/eng/x' })).allowed, false);

// ---- link management
const staffLink = newLink('ptra.cc', { path: 'Mine', pathLc: 'mine' }, 'https://e.com', staff);
check('owner may manage own link', (await canManageLink(cfg, { user: staff, link: staffLink, host: 'ptra.cc' })).allowed, true);
check('stranger may not manage link', (await canManageLink(cfg, { user: other, link: staffLink, host: 'ptra.cc' })).allowed, false);
check('admin may manage any link', (await canManageLink(cfg, { user: admin, link: staffLink, host: 'ptra.cc' })).allowed, true);

staffLink.readonly = true;
check('readonly blocks the owner', (await canManageLink(cfg, { user: staff, link: staffLink, host: 'ptra.cc' })).allowed, false);
check('readonly still allows admin', (await canManageLink(cfg, { user: admin, link: staffLink, host: 'ptra.cc' })).allowed, true);

// directory admin controls other users' links inside the directory
await putGrant(cfg, newGrant('ptra.cc', 'pub', other, { canCreate: true, canManage: true }));
const inPub = newLink('ptra.cc', { path: 'pub/deck', pathLc: 'pub/deck' }, 'https://e.com', staff);
check('dir admin manages another user link in dir', (await canManageLink(cfg, { user: other, link: inPub, host: 'ptra.cc' })).allowed, true);
const outsidePub = newLink('ptra.cc', { path: 'loose', pathLc: 'loose' }, 'https://e.com', staff);
check('dir admin has no power outside the dir', (await canManageLink(cfg, { user: other, link: outsidePub, host: 'ptra.cc' })).allowed, false);
inPub.readonly = true;
check('readonly beats dir admin', (await canManageLink(cfg, { user: other, link: inPub, host: 'ptra.cc' })).allowed, false);

// directory administration
check('dir admin may manage dir grants', (await canManageDirectory(cfg, { user: other, dir: pub })).allowed, true);
check('plain grantee may not manage dir', (await canManageDirectory(cfg, { user: staff, dir: pub })).allowed, false);
check('only admins may set readonly', [canSetReadonly(cfg, admin), canSetReadonly(cfg, other)], [true, false]);

console.log(`permissions: ${pass}/${checks.length} checks passed`);
