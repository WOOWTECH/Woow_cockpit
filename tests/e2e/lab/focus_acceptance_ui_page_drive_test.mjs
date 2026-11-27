// Offline: the real page script driven through a fake Playwright module (no browser, no relay, no device). It proves the
// script selects and judges exactly what its config says: the R8 config keeps the old flow and check names, the page-emqx
// config selects only EMQX and compares the check's confirmation lines and keys with the one request exactly.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PAGE = new URL('./focus_acceptance_ui_page.mjs', import.meta.url).pathname;
const HA = 'ha-' + 'f'.repeat(20);
const S = 'files.skipped:' + 'a'.repeat(16);
const K = n => `emqx.device-psk:${String(n).repeat(16)}`;
const EMQX = { apps: ['emqx'], importable: ['emqx'], blocked: [], result_rows: [['emqx', 'imported']], exact: true,
  select_stage: 'select-emqx', texts: { upload: 'UI uploaded original real fixture through actual page',
    select: 'UI selects only EMQX', view: 'UI check shows EMQX importable',
    result: 'UI result shows EMQX imported as the only row',
    intent: 'UI one click sends one real acknowledged import intent for EMQX only',
    lines: 'UI lists every confirmation line of the EMQX check',
    keys: 'UI import carries every listed confirmation key exactly once' } };
const R8_NAMES = ['UI real administrative Cockpit bridge reaches this device', 'UI uploaded derived real fixture through actual page',
  'UI selects exactly the three reviewed apps', 'UI actual check confirmation keys observed including valid zero',
  'UI corrupt EMQX blocked and both other apps importable', 'UI has exactly one acknowledgement and import waits for it',
  'UI check did not start an import or separate restore', 'UI real key field removed before screenshot',
  'UI one acknowledgement enables import', 'UI result imports both apps and retains excluded EMQX row',
  'UI one click sends one real acknowledged import intent for only importable apps', 'UI no page script errors during this page flow',
  'UI cookie observation completed without gaps',
  'UI every issued credential absent from records journal and private evidence; proved public markers counted separately'];
const EMQX_NAMES = ['UI real administrative Cockpit bridge reaches this device', EMQX.texts.upload, EMQX.texts.select,
  'UI actual check confirmation keys observed including valid zero', EMQX.texts.view, EMQX.texts.lines,
  'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
  'UI real key field removed before screenshot', 'UI one acknowledgement enables import', EMQX.texts.result, EMQX.texts.intent,
  EMQX.texts.keys, 'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
  'UI every issued credential absent from records journal and private evidence; proved public markers counted separately'];

// A Playwright stand-in: the Cockpit login, the HA wizard's DOM answers and the WebSocket frames the page observes.
const FAKE = String.raw`
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const scenario = JSON.parse(process.env.FAKE_PLAYWRIGHT_SCENARIO);
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const SESSION = 'fake-session-' + 'x'.repeat(24);
const log = { actions: [], counts: [], unknown: [] };
const checked = new Set(scenario.initially_checked);
const responseHandlers = [], ws = {};
let jar = [], view = 'list', ticked = false;
const respond = (url, headers) => { for (const handler of responseHandlers) handler({ url: () => url,
  request: () => ({ method: () => 'GET' }), status: () => 200, headerValues: async () => headers }); };
const open = (channel, command) => '\n' + JSON.stringify({ command: 'open', channel, spawn: [HELPER, command] });
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
    if (typeof arg === 'string') return { root: true, native: { package_version: '362-1~bpo24.04.1', binary_sha256: 'a'.repeat(64) } };
    const values = {};
    for (const value of arg.values) values[createHash('sha256').update(value, 'utf8').digest('hex')] = { hits: 0 };
    return { values, scanned: 12, archive_index_sidecars_scanned: 3, actual_archive_index_sidecars_expected: 3,
      regular_json_roots_scanned: 2, all_values_hits: 0 };
  } };
const page = { setDefaultTimeout() {}, locator, async waitForURL() {}, getByRole: role => locator('role:' + role),
  on(event, handler) { if (event === 'websocket') handler({ on: (name, callback) => { ws[name] = callback; } }); },
  async goto(url) { log.actions.push(['goto', url.replace(scenario.base, '<base>')]); if (url === scenario.base) respond(url + '/', []); } };
export const chromium = { async launch() { return {
  async newContext() { return { on(event, handler) { if (event === 'response') responseHandlers.push(handler); },
    async newPage() { return page; }, async cookies() { return jar.map(cookie => ({ ...cookie })); } }; },
  async close() { writeFileSync(process.env.FAKE_PLAYWRIGHT_LOG, JSON.stringify({ ...log, checked: [...checked] })); } }; } };
`;

function drive(settings, scenario) {
  const folder = mkdtempSync(join(tmpdir(), 'focus-page-drive-'));
  try {
    const evidence = join(folder, 'evidence'); mkdirSync(evidence, { mode: 0o700 });
    writeFileSync(join(folder, 'fake-playwright.mjs'), FAKE);
    writeFileSync(join(folder, 'fixture.tar'), 'fixture');
    const base = 'https://127.0.0.1:9';
    const config = { base, ha_id: HA, fixture: join(folder, 'fixture.tar'), password: 'fake-cockpit-password',
      key: 'FAKE-HA-KEY', evidence, result: join(evidence, 'browser.json'), playwright: join(folder, 'fake-playwright.mjs'),
      chromium: join(folder, 'no-chromium'), since: 1, cookie_scan: 'unused', ...settings };
    const proc = spawnSync(process.execPath, [PAGE, '--run'], { input: JSON.stringify(config), timeout: 60000,
      env: { ...process.env, FAKE_PLAYWRIGHT_LOG: join(folder, 'log.json'),
        FAKE_PLAYWRIGHT_SCENARIO: JSON.stringify({ base, ha_id: HA, initially_checked: ['hermes'], ...scenario }) } });
    return { status: proc.status, result: JSON.parse(readFileSync(config.result, 'utf8')),
      log: JSON.parse(readFileSync(join(folder, 'log.json'), 'utf8')) };
  } finally { rmSync(folder, { recursive: true }); }
}

const R8_SCENARIO = { lines_shown: 0, rows: [['hermes', 'imported'], ['omnigent', 'imported'], ['emqx', 'excluded']],
  check: { schema: 2, shared: [], apps: [
    { app_id: 'emqx', importable: false, issues: [{ level: 'stop', message: 'corrupt member' }] },
    { app_id: 'omnigent', importable: true, issues: [{ level: 'notice', message: 'paused tasks' }] },
    { app_id: 'hermes', importable: true, issues: [] }] },
  request: { ha_backup_id: HA, apps: ['omnigent', 'hermes'], test_mode: false, then_restore: true, confirm: true,
    overwrite: true, request_id: 'ha-import-1', key: 'FAKE-HA-KEY' } };
const EMQX_SCENARIO = { lines_shown: 3, rows: [['emqx', 'imported']],
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'emqx', importable: true, issues: [{ level: 'confirm', key: K(1), message: 'psk' },
      { level: 'confirm', key: K(2), message: 'routing' }, { level: 'notice', message: 'hot backup' }] }] },
  request: { ha_backup_id: HA, apps: ['emqx'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-2', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], emqx: [K(1), K(2)] } } };
const names = result => result.checks.map(item => item.check);
const selections = log => log.actions.filter(([kind, selector]) => ['check', 'uncheck'].includes(kind) && selector.startsWith('#ha-app-'));

test('R8 config: the same three selections, expectations and check names as before; no confirmation record', () => {
  const { status, result, log } = drive({}, R8_SCENARIO);
  assert.deepEqual(names(result), R8_NAMES);
  assert.ok(result.checks.every(item => item.ok), JSON.stringify(result.checks));
  assert.equal(status, 0);
  assert.deepEqual(selections(log), [['uncheck', '#ha-app-hermes'], ['check', '#ha-app-emqx'], ['check', '#ha-app-omnigent'],
    ['check', '#ha-app-hermes']]);
  assert.equal(Object.hasOwn(result, 'confirmations'), false);
  assert.equal(result.stage, 'issued-value-scan');
  assert.deepEqual(result.wire.import_apps, ['hermes', 'omnigent']);
  assert.ok(!log.counts.some(([selector]) => selector.includes('ha-confirm-list') || selector.includes('ha-group-row')));
  assert.deepEqual(log.unknown, []);
});

test('page-emqx config: only EMQX selected, importable, every listed line shown and every key sent once', () => {
  const { status, result, log } = drive(EMQX, EMQX_SCENARIO);
  assert.deepEqual(names(result), EMQX_NAMES);
  assert.ok(result.checks.every(item => item.ok), JSON.stringify(result.checks));
  assert.equal(status, 0);
  assert.deepEqual(selections(log), [['uncheck', '#ha-app-hermes'], ['check', '#ha-app-emqx']]);
  assert.deepEqual(log.checked, ['emqx']);
  assert.deepEqual(result.confirmations, { expected_keys: { _shared: [S], emqx: [K(1), K(2)] },
    sent_keys: { _shared: [S], emqx: [K(1), K(2)] }, lines_expected: 3, lines_shown: 3, check_importable: ['emqx'] });
  assert.equal(result.wire.expected_acknowledged_keys, 3);
  assert.equal(result.wire.acknowledged_keys, 3);
  assert.equal(JSON.stringify(result).includes('FAKE-HA-KEY'), false);   // the HA key never reaches the record
  assert.deepEqual(log.unknown, []);
});

test('page-emqx refuses a substituted key the count check alone would accept', () => {
  const request = { ...EMQX_SCENARIO.request, acknowledged: { _shared: [S], emqx: [K(1), K(3)] } };
  const { status, result } = drive(EMQX, { ...EMQX_SCENARIO, request });
  assert.equal(status, 1);
  const byName = Object.fromEntries(result.checks.map(item => [item.check, item.ok]));
  assert.equal(byName[EMQX.texts.intent], true);   // same number of keys: the old count comparison passes
  assert.equal(byName[EMQX.texts.keys], false);
  assert.equal(result.completed, false);
});

test('page-emqx refuses a blocked EMQX, a confirmation line missing on the page and an extra result row', () => {
  const blocked = { ...EMQX_SCENARIO, check: { ...EMQX_SCENARIO.check, apps: [{ app_id: 'emqx', importable: false,
    issues: [{ level: 'stop', message: 'hot database did not load' }] }] } };
  for (const [scenario, failing] of [[blocked, EMQX.texts.view], [{ ...EMQX_SCENARIO, lines_shown: 2 }, EMQX.texts.lines],
    [{ ...EMQX_SCENARIO, rows: [['emqx', 'imported'], ['hermes', 'excluded']] }, EMQX.texts.result]]) {
    const { status, result } = drive(EMQX, scenario);
    assert.equal(status, 1, failing);
    assert.deepEqual(result.checks.find(item => item.check === failing), { check: failing, ok: false });
    assert.equal(result.import_clicks, failing === EMQX.texts.result ? 1 : 0);
  }
});
