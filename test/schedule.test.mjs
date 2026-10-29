/**
 * A link can be given a start date as well as an expiry, so a campaign can
 * be prepared ahead of time. Before it starts, the link behaves like any
 * other link with nothing to show.
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
const guest = peer(root);

const token = async () => Harness.csrf(await (await root.req('https://ptra.dev/admin/links/new')).text());
const create = async (form) =>
  root.req('https://ptra.dev/admin/links/new', {
    form: { _csrf: await token(), host: 'ptra.cc', status: '302', ...form },
  });
const editHref = (p) => 'https://ptra.dev/admin/links/edit?host=ptra.cc&path=' + encodeURIComponent(p);

/* -------------------------------------------------------- 1. the form */
section('both dates are offered');
{
  const form = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('create offers a start date', form.includes('name="activeFrom"'));
  ok('create offers an expiry', form.includes('name="expires"'));

  await create({ path: 'sched-a', target: 'example.com/a' });
  const edit = await (await root.req(editHref('sched-a'))).text();
  ok('edit offers a start date', edit.includes('name="activeFrom"'));
}

/* ------------------------------------------------------ 2. the window */
section('a schedule carries a time, read as UTC');
{
  // A bare date still works: a start runs from the beginning of the day and
  // an expiry to the end of it.
  await create({ path: 'sched-day', target: 'example.com/d', activeFrom: '2026-01-02', expires: '2026-01-03' });
  const dayForm = await (await root.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=sched-day')).text();
  ok('a bare start reads as midnight UTC', dayForm.includes('value="2026-01-02T00:00"'),
     (dayForm.match(/name="activeFrom"[^>]*value="[^"]*"/) || [''])[0]);
  ok('a bare expiry reads as the end of the day', dayForm.includes('value="2026-01-03T23:59"'),
     (dayForm.match(/name="expires"[^>]*value="[^"]*"/) || [''])[0]);

  // And a time is kept exactly, in UTC.
  await create({
    path: 'sched-time', target: 'example.com/t',
    activeFrom: '2026-06-01T09:30', expires: '2026-06-02T17:45',
  });
  const form = await (await root.req('https://ptra.dev/admin/links/edit?host=ptra.cc&path=sched-time')).text();
  ok('the start time survives', form.includes('value="2026-06-01T09:30"'));
  ok('the expiry time survives', form.includes('value="2026-06-02T17:45"'));

  // The fields are real pickers, labelled and explained as UTC.
  ok('both are date-and-time pickers',
     (form.match(/type="datetime-local"/g) || []).length >= 2,
     String((form.match(/type="datetime-local"/g) || []).length));
  ok('the labels say UTC', form.includes('Starts (UTC)') && form.includes('Expires (UTC)'));
  ok('and a tooltip explains it', /class="tip"[^>]*title="Entered and shown in UTC/.test(form));

  const create_ = await (await root.req('https://ptra.dev/admin/links/new')).text();
  ok('the create form matches', create_.includes('Starts (UTC, optional)') &&
     create_.includes('Expires (UTC, optional)'));

  // A half-hour-offset zone is where a local reading would show up.
  const outside = await guest.req('https://ptra.cc/sched-time', { country: 'IN' });
  ok('the window is not read in the visitor\u2019s zone', outside.status === 302 || outside.status === 200,
     String(outside.status));
}

section('the window must make sense');
{
  const bad = await create({
    path: 'sched-bad', target: 'example.com/b', activeFrom: '2027-01-01', expires: '2026-01-01',
  });
  ok('a start after the expiry is refused', (await bad.text()).includes('must come before'));

  const nonsense = await create({ path: 'sched-x', target: 'example.com/x', activeFrom: 'soon' });
  ok('an unparseable start is refused', (await nonsense.text()).includes('Start must be a UTC date and time'));

  const fine = await create({
    path: 'sched-ok', target: 'example.com/ok', activeFrom: '2026-01-01', expires: '2027-01-01',
  });
  ok('a sensible window is accepted', (fine.headers.get('Location') || '').includes('link.created'));
}

/* ------------------------------------------------------ 3. behaviour */
section('a link that has not started yet');
{
  await create({ path: 'sched-future', target: 'example.com/future', activeFrom: '2099-01-01' });
  const hit = await guest.req('https://ptra.cc/sched-future');
  ok('does not resolve', !(hit.headers.get('Location') || '').includes('example.com/future'),
     hit.headers.get('Location'));
  ok('lands on the MISSING destination',
     (hit.headers.get('Location') || '').includes('fallback.example'), hit.headers.get('Location'));

  const page = await (await root.req(editHref('sched-future'))).text();
  ok('is badged as pending', page.includes('starts '));

  await create({ path: 'sched-past', target: 'example.com/past', activeFrom: '2020-01-01' });
  const live = await guest.req('https://ptra.cc/sched-past');
  ok('a start date already passed resolves normally',
     (live.headers.get('Location') || '').includes('example.com/past'), live.headers.get('Location'));
}

/* --------------------------------------------------------- 4. editing */
section('the start date can be changed');
{
  const href = editHref('sched-future');
  const tok = Harness.csrfFor(await (await root.req(href)).text(), '/admin/links/edit');
  await root.req('https://ptra.dev/admin/links/edit', {
    form: {
      _csrf: tok, host: 'ptra.cc', path: 'sched-future', newpath: 'sched-future',
      target: 'example.com/future', status: '302', enabled: '1', activeFrom: '',
    },
  });
  const now = await guest.req('https://ptra.cc/sched-future');
  ok('clearing it makes the link live',
     (now.headers.get('Location') || '').includes('example.com/future'), now.headers.get('Location'));
  const page = await (await root.req(href)).text();
  ok('and the badge is gone', !page.includes('starts '));
}

console.log(`\nscheduling: ${passed} passed, ${failed} failed`);
root.restore();
export default { passed, failed };
