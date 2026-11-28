// Offline: the page script's optional waits (focus_page_bridge.py waits, config waits_ms: a large backup's own bounded
// waits for the upload with its upload-finish, each check and the import's result). Every earlier config (R8, page-emqx,
// the OpenDesign device config, the unencrypted Headscale config with choices, the Odoo database choice, the EMQX node
// recheck) must give byte-identical records and the same actions, DOM reads, device spawns AND wait timeouts as the page of
// this branch's base f9e5af00 (taken from git, pinned by SHA-256); a config with waits_ms waits exactly that long and records
// it, and nothing else of its flow changes.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DEFAULT_WAITS_MS, pageExpectations, validWaits } from './focus_acceptance_ui_protocol.mjs';

const HERE = dirname(new URL(import.meta.url).pathname);
const REPO = join(HERE, '..', '..', '..');
const BASE = 'f9e5af00e92392369d5fc70604c1ec0f72357759';
// The page of the base, by digest (the page every 2026-11-28 page run used: R8 and page-emqx before, then OpenDesign,
// code-server, Nextcloud no-share, Headscale, n8n, LiteLLM, Odoo).
const OLD = {
  'tests/e2e/lab/focus_acceptance_ui_page.mjs': '959d95f2a6009692e99affa052de23a81e8705b9ff1ff1c26ed1526b52e31c4d',
  'tests/e2e/lab/focus_acceptance_ui_protocol.mjs': 'bbf5ff4586ded555a47371345baa694b9d67fbd8542ed449df3659408a31f62b',
  'tests/e2e/lab/focus_acceptance_ui_cookies.mjs': '81b59407c7a7f0bc783c9ecc53c221cca76f393ccdcc6ffcbd501f7dd85baeb4',
  'tests/e2e/lab/focus_acceptance_ui_cookie_source.json': '23464fdf1c938adc6aa81b7d768f006f1fc47b8523755280f02c0e14ba20f43d',
  'snippets/focus-acceptance/r8-cookie-scan-rendered.py': '50b7639d16a14dbe309f5d440f4cdee9ef9a8c665b7244bf14b9675c86445f12',
};
const sha = data => createHash('sha256').update(data).digest('hex');
const HA = 'ha-' + 'f'.repeat(20);
const S = 'files.skipped:' + 'a'.repeat(16);
const K = n => `emqx.device-psk:${String(n).repeat(16)}`;
const OTHER = 'restore.other-databases:' + '7'.repeat(16);
const DB = n => `odoo.custom-modules:${String(n).repeat(16)}`;
const OD = n => `opendesign.unknown-entries:${String(n).repeat(16)}`;
const texts = app => ({ upload: 'UI uploaded the real fixture through the actual page', select: `UI selects exactly ${app}`,
  view: `UI check shows ${app} importable`, result: `UI result shows ${app} imported`,
  intent: `UI one click sends one real acknowledged import intent for ${app} only`,
  lines: 'UI lists every confirmation line of the check', keys: 'UI import carries every listed confirmation key exactly once' });
// focus_page_bridge.page_settings([app], [app], [], ...) for one app.
const one = (app, extra = {}) => ({ apps: [app], importable: [app], blocked: [], result_rows: [[app, 'imported']], exact: true,
  select_stage: 'select-apps', texts: texts(app), ...extra });
// Each different from the earlier 10, 10 and 20 minutes, so every one of the three is seen to change (the full-share
// case itself keeps the check at 10 minutes: focus_nextcloud_r6_fullshare_page.PAGE_WAITS).
const WAITS = { upload: 30 * 60 * 1000, check: 12 * 60 * 1000, result: 25 * 60 * 1000 };

// The wizard as a fake Playwright (the modes test's, focus_page_bridge_modes_test.mjs) that also records every wait with
// the timeout the page gave it.
const FAKE = String.raw`
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const scenario = JSON.parse(process.env.FAKE_PLAYWRIGHT_SCENARIO);
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const SESSION = 'fake-session-' + 'x'.repeat(24);
const digest = text => createHash('sha256').update(text, 'utf8').digest('hex');
const log = { actions: [], counts: [], unknown: [], spawns: [], waits: [] };
const checked = new Set(scenario.initially_checked);
const radios = { ...(scenario.radios || {}) };
const responseHandlers = [], ws = {};
let jar = [], view = 'list', ticked = false, channel = 0, runs = 0, shown = scenario.check;
const respond = (url, headers) => { for (const handler of responseHandlers) handler({ url: () => url,
  request: () => ({ method: () => 'GET' }), status: () => 200, headerValues: async () => headers }); };
const open = (id, command) => '\n' + JSON.stringify({ command: 'open', channel: id, spawn: [HELPER, command] });
const timeoutOf = options => (options && typeof options === 'object' && 'timeout' in options ? options.timeout : null);
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
function runCheck() {
  runs++;
  const picks = runs > 1 ? scenario.recheck_choices : undefined;
  const request = { ha_backup_id: scenario.ha_id, apps: [...checked].sort(), request_id: 'ha-check-' + runs };
  if (picks) request.choices = picks;
  if (!scenario.keyless) request.key = 'FAKE-HA-KEY';
  const c = 'c' + (++channel), s = 'c' + (++channel);
  ws.framesent({ payload: open(c, 'ha-check-start') });
  ws.framesent({ payload: c + '\n' + JSON.stringify(request) });
  ws.framesent({ payload: open(s, 'job-status') });
  if (runs > 1 && scenario.recheck) shown = scenario.recheck;
  ws.framereceived({ payload: s + '\n' + JSON.stringify({ job: { id: 'j20261128T0300' + String(runs).padStart(2, '0') + 'Z-0000c0c' + runs,
    type: 'verify', params: { ha_backup_id: scenario.ha_id, ...(picks ? { choices: picks } : {}) }, result: { ha_check: shown } } }) });
  view = 'confirm';
}
function count(selector) {
  let m;
  const app = id => shown.apps.find(row => row.app_id === id);
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-importable="no"\] \.ha-issue-stop$/)))
    return view === 'confirm' && app(m[1])?.importable === false && app(m[1]).issues.some(i => i.level === 'stop') ? 1 : 0;
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-importable="yes"\]$/)))
    return view === 'confirm' && app(m[1])?.importable === true ? 1 : 0;
  if ((m = selector.match(/^\[data-ha-app="([a-z0-9-]+)"\]\[data-status="([a-z-]+)"\]$/)))
    return view === 'result' ? scenario.rows.filter(([id, status]) => id === m[1] && status === m[2]).length : 0;
  if (selector === '#ha-confirm-list .ha-issue-confirm') return view === 'confirm' ? scenario.lines_shown : 0;
  if (selector === '#view li.ha-group-row') return view === 'result' ? scenario.rows.length : 0;
  if (selector === '#view li.ha-group-row.ha-kept-item') return 0;
  if (selector === '#ha-ack') return view === 'confirm' ? 1 : 0;
  if (selector === '#ha-key') return view === 'key' ? 1 : 0;
  if (selector === '.stepper li[data-step="key"]') return 0;
  log.unknown.push(selector);
  return 0;
}
function locator(selector) {
  const app = selector.match(/^#ha-app-([a-z0-9-]+)$/);
  const radio = selector.match(/^input\[name="([a-z0-9-]+)"\]\[value="([^"]+)"\]$/);
  return {
    async fill() { log.actions.push(['fill', selector]); },
    async click() {
      log.actions.push(['click', selector]);
      if (selector === '#login-button') {
        jar = [{ name: 'cockpit', value: SESSION, domain: '127.0.0.1', path: '/' }];
        respond(scenario.base + '/cockpit/login', ['cockpit=' + SESSION + '; Path=/; HttpOnly; Secure']);
      } else if (selector === '[data-focus="ha-apps-next"]') { if (scenario.keyless) runCheck(); else view = 'key'; }
      else if (selector === '[data-focus="ha-key-next"]' || selector === '[data-focus="ha-recheck"]') runCheck();
      else if (selector === '[data-focus="ha-import"]') {
        const c = 'c' + (++channel);
        ws.framesent({ payload: open(c, 'ha-import-start') });
        ws.framesent({ payload: c + '\n' + JSON.stringify(scenario.request) });
        view = 'result';
      }
    },
    async waitFor(options) { log.waits.push(['waitFor', selector, timeoutOf(options)]); },
    async setInputFiles() { log.actions.push(['setInputFiles', selector]); },
    async evaluateAll(fn) { return fn([...checked].map(id => ({ id: 'ha-app-' + id }))); },
    async check() {
      log.actions.push(['check', selector]);
      if (app) checked.add(app[1]);
      if (selector === '#ha-ack') ticked = true;
      if (radio) radios[radio[1]] = radio[2];
    },
    async uncheck() { log.actions.push(['uncheck', selector]); if (app) checked.delete(app[1]); },
    async count() { const n = count(selector); log.counts.push([selector, n]); return n; },
    async isChecked() { return radio ? radios[radio[1]] === radio[2] : selector === '#ha-ack' && ticked; },
    async isDisabled() { return selector === '[data-focus="ha-import"]' && !ticked; },
    async isEnabled() { return selector !== '[data-focus="ha-import"]' || ticked; },
    async screenshot({ path }) { writeFileSync(path, 'fake image'); },
    async textContent() { return 'Administrative access'; },
    async elementHandle() { return { contentFrame: async () => frame }; },
  };
}
const frame = { locator, async waitForFunction(fn, arg, options) { log.waits.push(['waitForFunction', timeoutOf(options)]); },
  async evaluate(fn, arg) {
    globalThis.window = { cockpit: { spawn } };
    try { return await fn(arg); } finally { delete globalThis.window; }
  } };
const page = { setDefaultTimeout(ms) { log.waits.push(['setDefaultTimeout', ms]); }, locator,
  async waitForURL(url, options) { log.waits.push(['waitForURL', timeoutOf(options)]); },
  getByRole: role => locator('role:' + role),
  on(event, handler) { if (event === 'websocket') handler({ on: (name, callback) => { ws[name] = callback; } }); },
  async goto(url) { log.actions.push(['goto', url.replace(scenario.base, '<base>')]); if (url === scenario.base) respond(url + '/', []); } };
export const chromium = { async launch() { return {
  async newContext() { return { on(event, handler) { if (event === 'response') responseHandlers.push(handler); },
    async newPage() { return page; }, async cookies() { return jar.map(cookie => ({ ...cookie })); } }; },
  async close() { writeFileSync(process.env.FAKE_PLAYWRIGHT_LOG, JSON.stringify({ ...log, checked: [...checked], radios })); } }; } };
`;

let oldTree;
function baseTree() {
  if (oldTree !== undefined) return oldTree;
  const root = mkdtempSync(join(tmpdir(), 'focus-page-waits-base-'));
  for (const [path, digest] of Object.entries(OLD)) {
    const shown = spawnSync('git', ['-C', REPO, 'show', `${BASE}:${path}`], { maxBuffer: 16 << 20 });
    if (shown.status !== 0) { rmSync(root, { recursive: true }); oldTree = null; return oldTree; }
    assert.equal(sha(shown.stdout), digest, `base file ${path} is the pinned one`);
    mkdirSync(join(root, dirname(path)), { recursive: true });
    writeFileSync(join(root, path), shown.stdout);
  }
  oldTree = root;
  process.on('exit', () => rmSync(root, { recursive: true, force: true }));
  return oldTree;
}

const PAGE = join(HERE, 'focus_acceptance_ui_page.mjs');
function drive(settings, scenario, { pagePath = PAGE, key = 'FAKE-HA-KEY' } = {}) {   // key null: none at all
  const folder = mkdtempSync(join(tmpdir(), 'focus-page-waits-drive-'));
  try {
    const evidence = join(folder, 'evidence'); mkdirSync(evidence, { mode: 0o700 });
    writeFileSync(join(folder, 'fake-playwright.mjs'), FAKE);
    writeFileSync(join(folder, 'fixture.tar'), 'fixture');
    const base = 'https://127.0.0.1:9';
    const config = { base, ha_id: HA, fixture: join(folder, 'fixture.tar'), password: 'fake-cockpit-password',
      ...(key === null ? {} : { key }), evidence, result: join(evidence, 'browser.json'),
      playwright: join(folder, 'fake-playwright.mjs'), chromium: join(folder, 'no-chromium'), since: 1, ...settings };
    const proc = spawnSync(process.execPath, [pagePath, '--run'], { input: JSON.stringify(config), timeout: 60000,
      env: { ...process.env, FAKE_PLAYWRIGHT_LOG: join(folder, 'log.json'),
        FAKE_PLAYWRIGHT_SCENARIO: JSON.stringify({ base, ha_id: HA, initially_checked: ['hermes'], hostname: 'woowbk-dev-d',
          ...scenario }) } });
    const result = existsSync(join(evidence, 'browser.json')) ? readFileSync(join(evidence, 'browser.json')) : null;
    let cookies = Buffer.from('absent');
    try { cookies = readFileSync(join(evidence, 'cookie-observations.json')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const log = existsSync(join(folder, 'log.json')) ? JSON.parse(readFileSync(join(folder, 'log.json'), 'utf8')) : null;
    return { status: proc.status, stdout: proc.stdout.toString(), browser: result, cookies, log,
      result: result && JSON.parse(result) };
  } finally { rmSync(folder, { recursive: true }); }
}

// ------------------------------------------------------------------ scenarios (focus_page_bridge_modes_test.mjs)
const R8 = { lines_shown: 0, rows: [['hermes', 'imported'], ['omnigent', 'imported'], ['emqx', 'excluded']],
  check: { schema: 2, shared: [], apps: [
    { app_id: 'emqx', importable: false, issues: [{ level: 'stop', message: 'corrupt member' }] },
    { app_id: 'omnigent', importable: true, issues: [{ level: 'notice', message: 'paused tasks' }] },
    { app_id: 'hermes', importable: true, issues: [] }] },
  request: { ha_backup_id: HA, apps: ['omnigent', 'hermes'], test_mode: false, then_restore: true, confirm: true,
    overwrite: true, request_id: 'ha-import-1', key: 'FAKE-HA-KEY' } };
const EMQX = { apps: ['emqx'], importable: ['emqx'], blocked: [], result_rows: [['emqx', 'imported']], exact: true,
  select_stage: 'select-emqx', texts: { upload: 'UI uploaded original real fixture through actual page',
    select: 'UI selects only EMQX', view: 'UI check shows EMQX importable',
    result: 'UI result shows EMQX imported as the only row',
    intent: 'UI one click sends one real acknowledged import intent for EMQX only',
    lines: 'UI lists every confirmation line of the EMQX check',
    keys: 'UI import carries every listed confirmation key exactly once' } };
const EMQX_RUN = { lines_shown: 3, rows: [['emqx', 'imported']],
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'emqx', importable: true, issues: [{ level: 'confirm', key: K(1), message: 'psk' },
      { level: 'confirm', key: K(2), message: 'routing' }, { level: 'notice', message: 'hot backup' }] }] },
  request: { ha_backup_id: HA, apps: ['emqx'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-2', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], emqx: [K(1), K(2)] } } };
const OD_RUN = { lines_shown: 2, rows: [['open-design', 'imported']], initially_checked: ['open-design'], hostname: 'woowbk-dev-e',
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'open-design', importable: true, issues: [{ level: 'confirm', key: OD(4), message: 'unknown entries' },
      { level: 'auto', message: 'links copied' }] }] },
  request: { ha_backup_id: HA, apps: ['open-design'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-3', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], 'open-design': [OD(4)] } } };
const HEADSCALE = one('headscale', { device: 'woowbk-dev-d', encrypted: false, choices: {} });
const HS_RUN = { keyless: true, lines_shown: 0, rows: [['headscale', 'imported']], initially_checked: ['headscale'],
  check: { schema: 2, shared: [], apps: [{ app_id: 'headscale', importable: true,
    issues: [{ id: 'headscale.api-keys', level: 'notice', message: 'API keys stay' }] }] },
  request: { ha_backup_id: HA, apps: ['headscale'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-4' } };
const ODOO_CHECK = { schema: 2, shared: [{ id: 'files.skipped', level: 'confirm', key: S, message: 'skipped' }], apps: [{
  app_id: 'odoo', importable: true,
  odoo: { databases: [{ name: 'woowtest', ok: true }, { name: 'woowtest2', ok: true }] },
  choices: { database: [{ value: 'woowtest', label: 'woowtest', ok: true }, { value: 'woowtest2', label: 'woowtest2', ok: true }] },
  issues: [{ id: 'restore.other-databases', level: 'confirm', key: OTHER, message: 'other target databases' },
    { id: 'odoo.custom-modules', level: 'confirm', key: DB(1), message: 'woowtest modules', database: 'woowtest' },
    { id: 'odoo.custom-modules', level: 'confirm', key: DB(2), message: 'woowtest2 modules', database: 'woowtest2' }] }] };
const ODOO = one('odoo', { device: 'woowbk-dev-c', choices: { odoo: { database: 'woowtest2' } } });
const ODOO_RUN = { lines_shown: 4, rows: [['odoo', 'imported']], initially_checked: ['odoo'], hostname: 'woowbk-dev-c',
  check: ODOO_CHECK, radios: {},
  request: { ha_backup_id: HA, apps: ['odoo'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-5', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], odoo: [OTHER, DB(2)] },
    choices: { odoo: { database: 'woowtest2' } } } };
const nodes = { node: [{ value: 'emqx@a.lab', label: 'a', default: true }, { value: 'emqx@b.lab', label: 'b' }] };
const NODE_CHECK = { ...EMQX_RUN.check, apps: [{ ...EMQX_RUN.check.apps[0], choices: nodes }] };
const NODES = one('emqx', { choices: { emqx: { node: 'emqx@b.lab' } } });
const NODE_RUN = { ...EMQX_RUN, initially_checked: ['emqx'], check: NODE_CHECK, recheck: NODE_CHECK,
  radios: { 'ha-node-emqx': 'emqx@a.lab' }, recheck_choices: { emqx: { node: 'emqx@b.lab' } },
  request: { ...EMQX_RUN.request, choices: { emqx: { node: 'emqx@b.lab' } } } };
// The Nextcloud full share (focus_nextcloud_r6_fullshare_page.py): nothing to confirm, a valid zero.
const NC_RUN = { lines_shown: 0, rows: [['nextcloud', 'imported']], initially_checked: ['nextcloud'], hostname: 'woowbk-dev-e',
  check: { schema: 2, shared: [], apps: [{ app_id: 'nextcloud', importable: true,
    issues: [{ id: 'nextcloud.office-cache', level: 'notice', message: 'office' }] }] },
  request: { ha_backup_id: HA, apps: ['nextcloud'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-6', key: 'FAKE-HA-KEY' } };
const NC = one('nextcloud', { device: 'woowbk-dev-e' });

test('every earlier config waits, acts and records exactly as the page of the branch base f9e5af00', t => {
  const tree = baseTree();
  if (!tree) return t.skip(`base commit ${BASE} is not in this checkout`);
  const cases = [['R8', {}, R8], ['page-emqx', EMQX, EMQX_RUN],
    ['page-emqx blocked', EMQX, { ...EMQX_RUN, check: { ...EMQX_RUN.check, apps: [{ app_id: 'emqx', importable: false,
      issues: [{ level: 'stop', message: 'hot database did not load' }] }] } }],
    ['OpenDesign on dev-e', { device: 'woowbk-dev-e', ...one('open-design') }, OD_RUN],
    ['Headscale, unencrypted, choices', HEADSCALE, HS_RUN, null], ['Odoo database', ODOO, ODOO_RUN],
    ['EMQX node recheck', NODES, NODE_RUN], ['Nextcloud full share without waits', NC, NC_RUN]];
  for (const [name, settings, scenario, key] of cases) {
    const options = key === null ? { key: null } : {};
    const before = drive(settings, scenario, { ...options, pagePath: join(tree, 'tests/e2e/lab/focus_acceptance_ui_page.mjs') });
    const after = drive(settings, scenario, options);
    assert.equal(after.status, before.status, name);
    assert.equal(after.stdout, before.stdout, name);
    assert.equal(sha(after.browser), sha(before.browser), `${name}: browser.json bytes`);
    assert.equal(sha(after.cookies), sha(before.cookies), `${name}: cookie-observations.json bytes`);
    assert.deepEqual(after.log, before.log, `${name}: actions, DOM reads, radios, spawns and every wait with its timeout`);
    assert.equal('waits_ms' in after.result, false, name);
    assert.ok(after.log.waits.length > 0, name);
  }
  // The comparison is meaningful: the good ones complete, and they waited the earlier 10, 10 and 20 minutes.
  const nc = drive(NC, NC_RUN);
  assert.equal(nc.status, 0, JSON.stringify(nc.result.checks));
  assert.deepEqual(nc.log.waits.filter(([kind]) => kind === 'waitForFunction'), [['waitForFunction', 10 * 60 * 1000]]);
  assert.deepEqual(nc.log.waits.find(([kind, selector]) => kind === 'waitFor' && selector === '#ha-ack'),
    ['waitFor', '#ha-ack', 10 * 60 * 1000]);
  assert.deepEqual(nc.log.waits.find(([kind, selector]) => kind === 'waitFor' && selector === '[data-result="group"]'),
    ['waitFor', '[data-result="group"]', 20 * 60 * 1000]);
  assert.deepEqual(DEFAULT_WAITS_MS, { upload: 10 * 60 * 1000, check: 10 * 60 * 1000, result: 20 * 60 * 1000 });
});

test('a config with waits_ms waits exactly that long, records it, and nothing else of its flow changes', () => {
  const plain = drive(NC, NC_RUN);
  const long = drive({ ...NC, waits_ms: WAITS }, NC_RUN);
  assert.equal(long.status, 0, JSON.stringify(long.result.checks));
  assert.deepEqual(long.result.waits_ms, WAITS);
  const changed = long.log.waits.map((row, index) => [row, plain.log.waits[index]]).filter(([a, b]) => JSON.stringify(a) !== JSON.stringify(b));
  assert.deepEqual(changed, [
    [['waitForFunction', WAITS.upload], ['waitForFunction', 10 * 60 * 1000]],
    [['waitFor', '#ha-ack', WAITS.check], ['waitFor', '#ha-ack', 10 * 60 * 1000]],
    [['waitFor', '[data-result="group"]', WAITS.result], ['waitFor', '[data-result="group"]', 20 * 60 * 1000]]]);
  const { waits: _a, ...longRest } = long.log;
  const { waits: _b, ...plainRest } = plain.log;
  assert.deepEqual(longRest, plainRest);                 // the same actions, DOM reads and device spawns
  const { waits_ms: _c, ...longResult } = long.result;
  assert.deepEqual(longResult, plain.result);            // the same record but the waits it was given
  assert.equal(long.stdout, plain.stdout);
});

test('a recheck waits for its check as long as the first check', () => {
  const run = drive({ ...NODES, waits_ms: WAITS }, NODE_RUN);
  assert.equal(run.status, 0, JSON.stringify(run.result.checks));
  assert.deepEqual(run.log.waits.filter(([kind, selector]) => kind === 'waitFor' && selector === '#ha-ack'),
    [['waitFor', '#ha-ack', WAITS.check], ['waitFor', '#ha-ack', WAITS.check]]);
});

test('malformed waits are refused before any browser starts', () => {
  for (const bad of [{ upload: WAITS.upload, check: WAITS.check }, { ...WAITS, scan: 60000 }, { ...WAITS, check: 59999 },
    { ...WAITS, upload: 3600001 }, { ...WAITS, result: 1500000.5 }, { ...WAITS, check: '600000' }, [1, 2, 3], null]) {
    const run = drive({ ...NC, waits_ms: bad }, NC_RUN);
    assert.notEqual(run.status, 0, JSON.stringify(bad));
    assert.equal(run.browser, null, JSON.stringify(bad));
    assert.equal(run.log, null, JSON.stringify(bad));
    assert.equal(validWaits(bad), false, JSON.stringify(bad));
    assert.throws(() => pageExpectations({ ...NC, waits_ms: bad }), /invalid page expectations/);
  }
  assert.equal(validWaits(WAITS), true);
  assert.deepEqual(pageExpectations({ ...NC, waits_ms: WAITS }).waits_ms, WAITS);
  assert.equal('waits_ms' in pageExpectations(NC), false);
});
