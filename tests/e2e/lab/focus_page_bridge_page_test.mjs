// Offline: the device-general page script against the reviewed one it replaces (base b058df27), both driven through the
// SAME fake Playwright, which also runs every function the page evaluates in the browser against a stub cockpit.spawn.
// The R8 and page-emqx configs (no `device`) must give byte-identical records, actions and device spawns; a device's own
// config (focus_page_bridge.py) checks that device's hostname and reads the import request for its own apps.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pageExpectations, DEFAULT_DEVICE } from './focus_acceptance_ui_protocol.mjs';

const HERE = dirname(new URL(import.meta.url).pathname);
const REPO = join(HERE, '..', '..', '..');
const BASE = 'b058df278d661cc6195cd40936ff6494036c63a1';
// The reviewed files of the base, by digest: the comparison runs against exactly these.
const OLD = {
  'tests/e2e/lab/focus_acceptance_ui_page.mjs': '15eb21e600dc0e1bba95e9b94a1ac3a97dcc79cffdcb06809000a4024c6ead8b',
  'tests/e2e/lab/focus_acceptance_ui_protocol.mjs': 'e13e1ff6e48833e9033201a4d62a06f6d82ed07352cfea32c83b9ecff61e57c8',
  'tests/e2e/lab/focus_acceptance_ui_cookies.mjs': '81b59407c7a7f0bc783c9ecc53c221cca76f393ccdcc6ffcbd501f7dd85baeb4',
  'tests/e2e/lab/focus_acceptance_ui_cookie_source.json': '23464fdf1c938adc6aa81b7d768f006f1fc47b8523755280f02c0e14ba20f43d',
  'snippets/focus-acceptance/r8-cookie-scan-rendered.py': '50b7639d16a14dbe309f5d440f4cdee9ef9a8c665b7244bf14b9675c86445f12',
};
const sha = data => createHash('sha256').update(data).digest('hex');
const HA = 'ha-' + 'f'.repeat(20);
const S = 'files.skipped:' + 'a'.repeat(16);
const K = n => `emqx.device-psk:${String(n).repeat(16)}`;
const OD = n => `opendesign.unknown-entries:${String(n).repeat(16)}`;
const EMQX = { apps: ['emqx'], importable: ['emqx'], blocked: [], result_rows: [['emqx', 'imported']], exact: true,
  select_stage: 'select-emqx', texts: { upload: 'UI uploaded original real fixture through actual page',
    select: 'UI selects only EMQX', view: 'UI check shows EMQX importable',
    result: 'UI result shows EMQX imported as the only row',
    intent: 'UI one click sends one real acknowledged import intent for EMQX only',
    lines: 'UI lists every confirmation line of the EMQX check',
    keys: 'UI import carries every listed confirmation key exactly once' } };
// focus_page_bridge.page_settings(['open-design'], ['open-design'], []) (the Python test parses it with this protocol).
const OPEN_DESIGN = { apps: ['open-design'], importable: ['open-design'], blocked: [],
  result_rows: [['open-design', 'imported']], exact: true, select_stage: 'select-apps',
  texts: { upload: 'UI uploaded the real fixture through the actual page', select: 'UI selects exactly open-design',
    view: 'UI check shows open-design importable', result: 'UI result shows open-design imported',
    intent: 'UI one click sends one real acknowledged import intent for open-design only',
    lines: 'UI lists every confirmation line of the check',
    keys: 'UI import carries every listed confirmation key exactly once' } };

// A Playwright stand-in: Cockpit's login, the HA wizard's DOM answers, the WebSocket frames the page observes, and every
// function the page evaluates in the frame really runs, against a cockpit.spawn that records what it was asked.
const FAKE = String.raw`
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const scenario = JSON.parse(process.env.FAKE_PLAYWRIGHT_SCENARIO);
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const SESSION = 'fake-session-' + 'x'.repeat(24);
const digest = text => createHash('sha256').update(text, 'utf8').digest('hex');
const log = { actions: [], counts: [], unknown: [], spawns: [] };
const checked = new Set(scenario.initially_checked);
const responseHandlers = [], ws = {};
let jar = [], view = 'list', ticked = false;
const respond = (url, headers) => { for (const handler of responseHandlers) handler({ url: () => url,
  request: () => ({ method: () => 'GET' }), status: () => 200, headerValues: async () => headers }); };
const open = (channel, command) => '\n' + JSON.stringify({ command: 'open', channel, spawn: [HELPER, command] });
function spawn(argv, options) {
  const record = { argv: argv.map(a => (a.length > 60 ? 'sha256:' + digest(a) : a)), options };
  log.spawns.push(record);
  let input = null;
  const answer = () => {
    if (argv[0] === 'id') return '0\n';
    if (argv[0] === 'hostname') return scenario.hostname + '\n';
    if (argv[0] === 'python3' && argv[4].includes('cockpit-ws'))
      return JSON.stringify({ package_version: '362-1~bpo24.04.1', binary_sha256: 'a'.repeat(64) });
    const request = JSON.parse(input), values = {};
    for (const value of request.values) values[digest(value)] = { hits: 0 };
    record.scan_values = request.values.length;
    return JSON.stringify({ values, scanned: 12, archive_index_sidecars_scanned: 3, actual_archive_index_sidecars_expected: 3,
      regular_json_roots_scanned: 2, all_values_hits: 0 });
  };
  return { input(text) { input = text; record.input_bytes = text.length; },
    then(resolve, reject) { try { resolve(answer()); } catch (error) { reject(error); } } };
}
function count(selector) {
  let m;
  const app = id => scenario.check.apps.find(row => row.app_id === id);
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-importable="no"\] \.ha-issue-stop$/)))
    return view === 'confirm' && app(m[1])?.importable === false && app(m[1]).issues.some(i => i.level === 'stop') ? 1 : 0;
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-importable="yes"\]$/)))
    return view === 'confirm' && app(m[1])?.importable === true ? 1 : 0;
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-status="([a-z-]+)"\]$/)))
    return view === 'result' ? scenario.rows.filter(([id, status]) => id === m[1] && status === m[2]).length : 0;
  if (selector === '#ha-confirm-list .ha-issue-confirm') return view === 'confirm' ? scenario.lines_shown : 0;
  if (selector === '#view li.ha-group-row') return view === 'result' ? scenario.rows.length : 0;
  if (selector === '#ha-ack') return view === 'confirm' ? 1 : 0;
  if (selector === '#ha-key') return view === 'key' ? 1 : 0;
  log.unknown.push(selector);
  return 0;
}
function locator(selector) {
  const app = selector.match(/^#ha-app-([a-z0-9-]+)$/);
  return {
    async fill() { log.actions.push(['fill', selector]); },
    async click() {
      log.actions.push(['click', selector]);
      if (selector === '#login-button') {
        jar = [{ name: 'cockpit', value: SESSION, domain: '127.0.0.1', path: '/' }];
        respond(scenario.base + '/cockpit/login', ['cockpit=' + SESSION + '; Path=/; HttpOnly; Secure']);
      } else if (selector === '[data-focus="ha-apps-next"]') view = 'key';
      else if (selector === '[data-focus="ha-key-next"]') {
        ws.framesent({ payload: open('c1', 'ha-check-start') });
        ws.framesent({ payload: open('c2', 'job-status') });
        ws.framereceived({ payload: 'c2\n' + JSON.stringify({ job: { type: 'verify', params: { ha_backup_id: scenario.ha_id },
          result: { ha_check: scenario.check } } }) });
        view = 'confirm';
      } else if (selector === '[data-focus="ha-import"]') {
        ws.framesent({ payload: open('c3', 'ha-import-start') });
        ws.framesent({ payload: 'c3\n' + JSON.stringify(scenario.request) });
        view = 'result';
      }
    },
    async waitFor() {},
    async setInputFiles() { log.actions.push(['setInputFiles', selector]); },
    async evaluateAll(fn) { return fn([...checked].map(id => ({ id: 'ha-app-' + id }))); },
    async check() { log.actions.push(['check', selector]); if (app) checked.add(app[1]); if (selector === '#ha-ack') ticked = true; },
    async uncheck() { log.actions.push(['uncheck', selector]); if (app) checked.delete(app[1]); },
    async count() { const n = count(selector); log.counts.push([selector, n]); return n; },
    async isChecked() { return selector === '#ha-ack' && ticked; },
    async isDisabled() { return selector === '[data-focus="ha-import"]' && !ticked; },
    async isEnabled() { return selector !== '[data-focus="ha-import"]' || ticked; },
    async screenshot({ path }) { writeFileSync(path, 'fake image'); },
    async textContent() { return 'Administrative access'; },
    async elementHandle() { return { contentFrame: async () => frame }; },
  };
}
const frame = { locator, async waitForFunction() {},
  async evaluate(fn, arg) {
    globalThis.window = { cockpit: { spawn } };
    try { return await fn(arg); } finally { delete globalThis.window; }
  } };
const page = { setDefaultTimeout() {}, locator, async waitForURL() {}, getByRole: role => locator('role:' + role),
  on(event, handler) { if (event === 'websocket') handler({ on: (name, callback) => { ws[name] = callback; } }); },
  async goto(url) { log.actions.push(['goto', url.replace(scenario.base, '<base>')]); if (url === scenario.base) respond(url + '/', []); } };
export const chromium = { async launch() { return {
  async newContext() { return { on(event, handler) { if (event === 'response') responseHandlers.push(handler); },
    async newPage() { return page; }, async cookies() { return jar.map(cookie => ({ ...cookie })); } }; },
  async close() { writeFileSync(process.env.FAKE_PLAYWRIGHT_LOG, JSON.stringify({ ...log, checked: [...checked] })); } }; } };
`;

let oldTree;
function baseTree() {
  if (oldTree !== undefined) return oldTree;
  const root = mkdtempSync(join(tmpdir(), 'focus-page-base-'));
  for (const [path, digest] of Object.entries(OLD)) {
    const shown = spawnSync('git', ['-C', REPO, 'show', `${BASE}:${path}`], { maxBuffer: 16 << 20 });
    if (shown.status !== 0) { rmSync(root, { recursive: true }); oldTree = null; return oldTree; }
    assert.equal(sha(shown.stdout), digest, `base file ${path} is the reviewed one`);
    mkdirSync(join(root, dirname(path)), { recursive: true });
    writeFileSync(join(root, path), shown.stdout);
  }
  oldTree = root;
  process.on('exit', () => rmSync(root, { recursive: true, force: true }));
  return oldTree;
}

function drive(pagePath, settings, scenario) {
  const folder = mkdtempSync(join(tmpdir(), 'focus-page-bridge-drive-'));
  try {
    const evidence = join(folder, 'evidence'); mkdirSync(evidence, { mode: 0o700 });
    writeFileSync(join(folder, 'fake-playwright.mjs'), FAKE);
    writeFileSync(join(folder, 'fixture.tar'), 'fixture');
    const base = 'https://127.0.0.1:9';
    // Fixed paths in the config would differ per run; the records must not depend on them, so both pages get the same.
    const config = { base, ha_id: HA, fixture: join(folder, 'fixture.tar'), password: 'fake-cockpit-password',
      key: 'FAKE-HA-KEY', evidence, result: join(evidence, 'browser.json'), playwright: join(folder, 'fake-playwright.mjs'),
      chromium: join(folder, 'no-chromium'), since: 1, ...settings };
    const proc = spawnSync(process.execPath, [pagePath, '--run'], { input: JSON.stringify(config), timeout: 60000,
      env: { ...process.env, FAKE_PLAYWRIGHT_LOG: join(folder, 'log.json'),
        FAKE_PLAYWRIGHT_SCENARIO: JSON.stringify({ base, ha_id: HA, initially_checked: ['hermes'], hostname: 'woowbk-dev-d',
          ...scenario }) } });
    const read = name => readFileSync(join(evidence, name));
    let cookies = Buffer.from('absent');   // a page stopped before its authenticated frame writes no cookie record
    try { cookies = read('cookie-observations.json'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    return { status: proc.status, stdout: proc.stdout.toString(), browser: read('browser.json'), cookies,
      log: JSON.parse(readFileSync(join(folder, 'log.json'), 'utf8')), result: JSON.parse(read('browser.json')) };
  } finally { rmSync(folder, { recursive: true }); }
}

const R8 = { lines_shown: 0, rows: [['hermes', 'imported'], ['omnigent', 'imported'], ['emqx', 'excluded']],
  check: { schema: 2, shared: [], apps: [
    { app_id: 'emqx', importable: false, issues: [{ level: 'stop', message: 'corrupt member' }] },
    { app_id: 'omnigent', importable: true, issues: [{ level: 'notice', message: 'paused tasks' }] },
    { app_id: 'hermes', importable: true, issues: [] }] },
  request: { ha_backup_id: HA, apps: ['omnigent', 'hermes'], test_mode: false, then_restore: true, confirm: true,
    overwrite: true, request_id: 'ha-import-1', key: 'FAKE-HA-KEY' } };
const EMQX_RUN = { lines_shown: 3, rows: [['emqx', 'imported']],
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'emqx', importable: true, issues: [{ level: 'confirm', key: K(1), message: 'psk' },
      { level: 'confirm', key: K(2), message: 'routing' }, { level: 'notice', message: 'hot backup' }] }] },
  request: { ha_backup_id: HA, apps: ['emqx'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-2', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], emqx: [K(1), K(2)] } } };
const OD_RUN = { lines_shown: 2, rows: [['open-design', 'imported']], initially_checked: ['open-design'], hostname: 'woowbk-dev-e',
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'open-design', importable: true, issues: [{ level: 'confirm', key: OD(4), message: 'unknown entries' },
      { level: 'auto', message: 'links copied' }, { level: 'notice', message: 'project folders' }] }] },
  request: { ha_backup_id: HA, apps: ['open-design'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-3', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], 'open-design': [OD(4)] } } };
const byName = result => Object.fromEntries(result.checks.map(item => [item.check, item.ok]));
const BRIDGE = 'UI real administrative Cockpit bridge reaches this device';

test('the R8 and page-emqx configs give byte-identical records, actions and spawns to the reviewed page', t => {
  const tree = baseTree();
  if (!tree) return t.skip(`base commit ${BASE} is not in this checkout`);
  const cases = [['R8', {}, R8], ['page-emqx', EMQX, EMQX_RUN],
    ['page-emqx substituted key', EMQX, { ...EMQX_RUN, request: { ...EMQX_RUN.request, acknowledged: { _shared: [S], emqx: [K(1), K(3)] } } }],
    ['page-emqx blocked', EMQX, { ...EMQX_RUN, check: { ...EMQX_RUN.check, apps: [{ app_id: 'emqx', importable: false,
      issues: [{ level: 'stop', message: 'hot database did not load' }] }] } }],
    ['R8 on another host', {}, { ...R8, hostname: 'woowbk-dev-e' }],
    ['R8 with an unknown extra app in the request', {}, { ...R8, request: { ...R8.request, apps: ['omnigent', 'hermes', 'x-app'] } }]];
  for (const [name, settings, scenario] of cases) {
    const before = drive(join(tree, 'tests/e2e/lab/focus_acceptance_ui_page.mjs'), settings, scenario);
    const after = drive(join(HERE, 'focus_acceptance_ui_page.mjs'), settings, scenario);
    assert.equal(after.status, before.status, name);
    assert.equal(after.stdout, before.stdout, name);
    assert.equal(sha(after.browser), sha(before.browser), `${name}: browser.json bytes`);
    assert.equal(sha(after.cookies), sha(before.cookies), `${name}: cookie-observations.json bytes`);
    assert.deepEqual(after.log, before.log, `${name}: actions, DOM reads and cockpit.spawn calls`);
  }
  // The comparison is meaningful: the good cases complete, the device spawns ran, the bad ones stop where they should.
  const good = drive(join(HERE, 'focus_acceptance_ui_page.mjs'), EMQX, EMQX_RUN);
  assert.equal(good.status, 0);
  assert.deepEqual(good.log.spawns.slice(0, 3).map(s => s.argv[0]), ['id', 'hostname', 'python3']);
  assert.equal(good.log.spawns.length, 4);   // the capability probe's three, then the issued-value scan
  const other = drive(join(HERE, 'focus_acceptance_ui_page.mjs'), {}, { ...R8, hostname: 'woowbk-dev-e' });
  assert.equal(byName(other.result)[BRIDGE], false);
  assert.equal(other.log.actions.some(([kind]) => kind === 'setInputFiles'), false);
});

test('a device config checks THAT device\'s hostname with the same three spawns, and imports its own app', () => {
  const page = join(HERE, 'focus_acceptance_ui_page.mjs');
  const run = drive(page, { device: 'woowbk-dev-e', ...OPEN_DESIGN }, OD_RUN);
  assert.ok(run.result.checks.every(item => item.ok), JSON.stringify(run.result.checks));
  assert.equal(run.status, 0);
  assert.deepEqual(run.result.wire.import_apps, ['open-design']);
  assert.deepEqual(run.result.confirmations, { expected_keys: { _shared: [S], 'open-design': [OD(4)] },
    sent_keys: { _shared: [S], 'open-design': [OD(4)] }, lines_expected: 2, lines_shown: 2, check_importable: ['open-design'] });
  assert.deepEqual(run.log.checked, ['open-design']);
  const r8 = drive(page, {}, R8);
  assert.deepEqual(run.log.spawns.slice(0, 3), r8.log.spawns.slice(0, 3));   // id -u, hostname, the same native program
  assert.equal(JSON.stringify(run.result).includes('FAKE-HA-KEY'), false);
  assert.equal(JSON.stringify(run.result).includes('fake-cockpit-password'), false);
  // dev-e's config on dev-d's Cockpit (or a plain dev-d config on dev-e's): stopped before anything is uploaded.
  for (const [settings, hostname] of [[{ device: 'woowbk-dev-e', ...OPEN_DESIGN }, 'woowbk-dev-d'], [OPEN_DESIGN, 'woowbk-dev-e']]) {
    const wrong = drive(page, settings, { ...OD_RUN, hostname });
    assert.equal(byName(wrong.result)[BRIDGE], false, JSON.stringify(settings.device));
    assert.equal(wrong.status, 1);
    assert.equal(wrong.log.actions.some(([kind]) => kind === 'setInputFiles'), false);
  }
});

test('the import request is read for the selected app: an extra app or a substituted key fails the page', () => {
  const page = join(HERE, 'focus_acceptance_ui_page.mjs');
  const extra = drive(page, { device: 'woowbk-dev-e', ...OPEN_DESIGN },
    { ...OD_RUN, request: { ...OD_RUN.request, apps: ['open-design', 'emqx'] } });
  assert.equal(byName(extra.result)[OPEN_DESIGN.texts.intent], false);
  assert.deepEqual(extra.result.wire.import_apps, ['emqx', 'open-design']);
  assert.equal(extra.status, 1);
  const swapped = drive(page, { device: 'woowbk-dev-e', ...OPEN_DESIGN },
    { ...OD_RUN, request: { ...OD_RUN.request, acknowledged: { _shared: [S], 'open-design': [OD(5)] } } });
  assert.equal(byName(swapped.result)[OPEN_DESIGN.texts.intent], true);   // the same number of keys
  assert.equal(byName(swapped.result)[OPEN_DESIGN.texts.keys], false);
  assert.equal(swapped.status, 1);
});

test('the page expectations carry the device: dev-d by default, any lab device by name, nothing else', () => {
  assert.equal(DEFAULT_DEVICE, 'woowbk-dev-d');
  assert.equal(pageExpectations({}).device, 'woowbk-dev-d');
  assert.equal(pageExpectations({ ...EMQX }).device, 'woowbk-dev-d');
  assert.equal(pageExpectations({ device: 'woowbk-dev-e', ...OPEN_DESIGN }).device, 'woowbk-dev-e');
  assert.equal(pageExpectations({ device: 'woowbk-dev-c' }).select_stage, 'select-three-apps');   // a device alone is no selection
  for (const device of ['dev-e', 'woowbk-dev-E', 'woowbk-dev-ee', 'woowbk-dev-', 5, null, 'woowbk-dev-e\n'])
    assert.throws(() => pageExpectations({ device, ...OPEN_DESIGN }), /invalid page expectations/, JSON.stringify(device));
});
