// Offline: the page script's two new modes (focus_page_bridge.py key=None and choices) driven through a fake Playwright that
// also plays the wizard's check requests, rechecks, radios and the stepper. Every earlier config (R8, page-emqx, the
// OpenDesign device config) must give byte-identical records, actions and device spawns to the reviewed page of a1ca42b2
// (taken from git, pinned by SHA-256); the new modes are checked for what they select, send and refuse.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pageExpectations, planChoices, usableDatabases, issueKeys, issueKeyCount, confirmLineCount, validChoices,
  validImportIntent } from './focus_acceptance_ui_protocol.mjs';

const HERE = dirname(new URL(import.meta.url).pathname);
const REPO = join(HERE, '..', '..', '..');
const BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac';
// The reviewed page of the base, by digest (the R8/page-emqx/OpenDesign page that ran 81/81, 85/85 and 103/103).
const OLD = {
  'tests/e2e/lab/focus_acceptance_ui_page.mjs': '31fc082ef7ac691bce5aee269c9037e84838d26fc72700fe32d54d51e45719d3',
  'tests/e2e/lab/focus_acceptance_ui_protocol.mjs': '800fe28f950314567841a177bef96c68ca9cd74e66e8c937b6f88f247dbb7a48',
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
const texts = app => ({ upload: 'UI uploaded the real fixture through the actual page', select: `UI selects exactly ${app}`,
  view: `UI check shows ${app} importable`, result: `UI result shows ${app} imported`,
  intent: `UI one click sends one real acknowledged import intent for ${app} only`,
  lines: 'UI lists every confirmation line of the check', keys: 'UI import carries every listed confirmation key exactly once' });
// focus_page_bridge.page_settings([app], [app], [], ...) for one app.
const one = (app, extra = {}) => ({ apps: [app], importable: [app], blocked: [], result_rows: [[app, 'imported']], exact: true,
  select_stage: 'select-apps', texts: texts(app), ...extra });
const EMQX = { apps: ['emqx'], importable: ['emqx'], blocked: [], result_rows: [['emqx', 'imported']], exact: true,
  select_stage: 'select-emqx', texts: { upload: 'UI uploaded original real fixture through actual page',
    select: 'UI selects only EMQX', view: 'UI check shows EMQX importable',
    result: 'UI result shows EMQX imported as the only row',
    intent: 'UI one click sends one real acknowledged import intent for EMQX only',
    lines: 'UI lists every confirmation line of the EMQX check',
    keys: 'UI import carries every listed confirmation key exactly once' } };

// The wizard as a fake Playwright: login, upload, the app selection, an optional key step, every check request (the
// first and a recheck with the page's picks) with its job-status answer, the radios, the one confirmation and the import.
const FAKE = String.raw`
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const scenario = JSON.parse(process.env.FAKE_PLAYWRIGHT_SCENARIO);
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const SESSION = 'fake-session-' + 'x'.repeat(24);
const digest = text => createHash('sha256').update(text, 'utf8').digest('hex');
const log = { actions: [], counts: [], unknown: [], spawns: [] };
const checked = new Set(scenario.initially_checked);
const radios = { ...(scenario.radios || {}) };
const responseHandlers = [], ws = {};
let jar = [], view = 'list', ticked = false, channel = 0, runs = 0, shown = scenario.check;
const respond = (url, headers) => { for (const handler of responseHandlers) handler({ url: () => url,
  request: () => ({ method: () => 'GET' }), status: () => 200, headerValues: async () => headers }); };
const open = (id, command) => '\n' + JSON.stringify({ command: 'open', channel: id, spawn: [HELPER, command] });
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
  if (!scenario.keyless || scenario.check_key_sent) request.key = 'FAKE-HA-KEY';
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
  if (selector === '#ha-ack') return view === 'confirm' ? 1 : 0;
  if (selector === '#ha-key') return view === 'key' || (view === 'confirm' && scenario.key_field_after_check) ? 1 : 0;
  if (selector === '.stepper li[data-step="key"]') return scenario.key_step_shown || 0;
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
    async waitFor() {},
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
  async close() { writeFileSync(process.env.FAKE_PLAYWRIGHT_LOG, JSON.stringify({ ...log, checked: [...checked], radios })); } }; } };
`;

let oldTree;
function baseTree() {
  if (oldTree !== undefined) return oldTree;
  const root = mkdtempSync(join(tmpdir(), 'focus-page-modes-base-'));
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

const PAGE = join(HERE, 'focus_acceptance_ui_page.mjs');
function drive(settings, scenario, { pagePath = PAGE, key = 'FAKE-HA-KEY' } = {}) {   // key null: none at all
  const folder = mkdtempSync(join(tmpdir(), 'focus-page-modes-drive-'));
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
const byName = result => Object.fromEntries(result.checks.map(item => [item.check, item.ok]));
const actions = run => run.log.actions.map(([kind, selector]) => `${kind} ${selector}`);

// ------------------------------------------------------------------ scenarios
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
const OD = n => `opendesign.unknown-entries:${String(n).repeat(16)}`;
const OD_RUN = { lines_shown: 2, rows: [['open-design', 'imported']], initially_checked: ['open-design'], hostname: 'woowbk-dev-e',
  check: { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped entries' }], apps: [
    { app_id: 'open-design', importable: true, issues: [{ level: 'confirm', key: OD(4), message: 'unknown entries' },
      { level: 'auto', message: 'links copied' }] }] },
  request: { ha_backup_id: HA, apps: ['open-design'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-3', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], 'open-design': [OD(4)] } } };

// Headscale's plain b1 backup: no key step, no confirmation line (a valid zero), nothing to choose.
const HEADSCALE = one('headscale', { device: 'woowbk-dev-d', encrypted: false, choices: {} });
const HS_RUN = { keyless: true, lines_shown: 0, rows: [['headscale', 'imported']], initially_checked: ['headscale'],
  check: { schema: 2, shared: [], apps: [{ app_id: 'headscale', importable: true,
    issues: [{ id: 'headscale.api-keys', level: 'notice', message: 'API keys stay' }] }] },
  request: { ha_backup_id: HA, apps: ['headscale'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-4' } };

// Odoo with two databases that can move; the run names woowtest2: its own line counts, woowtest's does not, and the page
// adds its line naming the database left on HA.
const ODOO_CHECK = { schema: 2, shared: [{ id: 'files.skipped', level: 'confirm', key: S, message: 'skipped' }], apps: [{
  app_id: 'odoo', importable: true,
  odoo: { databases: [{ name: 'woowtest', ok: true }, { name: 'woowtest2', ok: true }] },
  choices: { database: [{ value: 'woowtest', label: 'woowtest', ok: true }, { value: 'woowtest2', label: 'woowtest2', ok: true }] },
  issues: [{ id: 'restore.other-databases', level: 'confirm', key: OTHER, message: 'other target databases' },
    { id: 'odoo.custom-modules', level: 'confirm', key: DB(1), message: 'woowtest modules', database: 'woowtest' },
    { id: 'odoo.custom-modules', level: 'confirm', key: DB(2), message: 'woowtest2 modules', database: 'woowtest2' },
    { id: 'odoo.mail', level: 'notice', message: 'mail servers', database: 'woowtest2' }] }] };
const ODOO = one('odoo', { device: 'woowbk-dev-c', choices: { odoo: { database: 'woowtest2' } } });
const ODOO_RUN = { lines_shown: 4, rows: [['odoo', 'imported']], initially_checked: ['odoo'], hostname: 'woowbk-dev-c',
  check: ODOO_CHECK, radios: {},
  request: { ha_backup_id: HA, apps: ['odoo'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
    request_id: 'ha-import-5', key: 'FAKE-HA-KEY', acknowledged: { _shared: [S], odoo: [OTHER, DB(2)] },
    choices: { odoo: { database: 'woowtest2' } }, check_job_id: 'j20261128T030001Z-0000c0c1' } };

// EMQX offering two nodes (the default first): the run names the other one, so the page picks it and checks again.
const nodes = { node: [{ value: 'emqx@a.lab', label: 'a', default: true }, { value: 'emqx@b.lab', label: 'b' }] };
const NODE_CHECK = { ...EMQX_RUN.check, apps: [{ ...EMQX_RUN.check.apps[0], choices: nodes }] };
const NODES = one('emqx', { choices: { emqx: { node: 'emqx@b.lab' } } });
const NODE_RUN = { ...EMQX_RUN, initially_checked: ['emqx'], check: NODE_CHECK, recheck: NODE_CHECK,
  radios: { 'ha-node-emqx': 'emqx@a.lab' }, recheck_choices: { emqx: { node: 'emqx@b.lab' } },
  request: { ...EMQX_RUN.request, choices: { emqx: { node: 'emqx@b.lab' } } } };

test('every earlier config gives byte-identical records, actions and spawns to the reviewed a1ca42b2 page', t => {
  const tree = baseTree();
  if (!tree) return t.skip(`base commit ${BASE} is not in this checkout`);
  const cases = [['R8', {}, R8], ['page-emqx', EMQX, EMQX_RUN],
    ['page-emqx substituted key', EMQX, { ...EMQX_RUN, request: { ...EMQX_RUN.request, acknowledged: { _shared: [S], emqx: [K(1), K(3)] } } }],
    ['page-emqx blocked', EMQX, { ...EMQX_RUN, check: { ...EMQX_RUN.check, apps: [{ app_id: 'emqx', importable: false,
      issues: [{ level: 'stop', message: 'hot database did not load' }] }] } }],
    ['R8 on another host', {}, { ...R8, hostname: 'woowbk-dev-e' }],
    ['OpenDesign on dev-e', { device: 'woowbk-dev-e', ...one('open-design') }, OD_RUN],
    ['OpenDesign on the wrong host', { device: 'woowbk-dev-e', ...one('open-design') }, { ...OD_RUN, hostname: 'woowbk-dev-d' }],
    ['OpenDesign with an extra app in the request', { device: 'woowbk-dev-e', ...one('open-design') },
      { ...OD_RUN, request: { ...OD_RUN.request, apps: ['open-design', 'emqx'] } }],
    // A database line in an earlier config is counted exactly as before (keys yes, lines no): no mode is entered.
    ['an earlier config on an Odoo check', { device: 'woowbk-dev-c', ...one('odoo') }, { ...ODOO_RUN, radios: {} }]];
  for (const [name, settings, scenario] of cases) {
    const before = drive(settings, scenario, { pagePath: join(tree, 'tests/e2e/lab/focus_acceptance_ui_page.mjs') });
    const after = drive(settings, scenario);
    assert.equal(after.status, before.status, name);
    assert.equal(after.stdout, before.stdout, name);
    assert.equal(sha(after.browser), sha(before.browser), `${name}: browser.json bytes`);
    assert.equal(sha(after.cookies), sha(before.cookies), `${name}: cookie-observations.json bytes`);
    assert.deepEqual(after.log, before.log, `${name}: actions, DOM reads, radios and cockpit.spawn calls`);
    for (const record of ['key_step', 'choices', 'requests']) assert.equal(record in after.result, false, `${name}: ${record}`);
  }
  // The comparison is meaningful: the good ones complete.
  assert.equal(drive({ device: 'woowbk-dev-e', ...one('open-design') }, OD_RUN).status, 0);
  assert.equal(drive(EMQX, EMQX_RUN).status, 0);
});

test('an unencrypted HA backup: no key enters the page, the wizard asks for none and no request carries one', () => {
  const run = drive(HEADSCALE, HS_RUN, { key: null });
  assert.ok(run.result.checks.every(item => item.ok), JSON.stringify(run.result.checks));
  assert.equal(run.status, 0);
  assert.deepEqual(run.result.key_step, { stepper_key_steps: 0, key_fields_after_check: 0 });
  assert.deepEqual(run.result.requests, { check: [{ key: false, choices: null }], import: { key: false, choices: null } });
  assert.equal(run.result.stage, 'issued-value-scan');
  assert.equal(actions(run).some(line => line.includes('#ha-key') || line.includes('ha-key-next')), false);
  assert.deepEqual(run.result.confirmations, { expected_keys: {}, sent_keys: {}, lines_expected: 0, lines_shown: 0,
    check_importable: ['headscale'] });
  assert.deepEqual(run.result.choices, { named: {}, database: null, picks: {}, import_choices: {}, check_choices: {},
    rechecks: 0, problems: [] });
  // The exact sequence a keyless run with choices records (headscale_page_pilot_test.page_names uses the same list).
  const t = HEADSCALE.texts;
  assert.deepEqual(run.result.checks.map(item => item.check), ['UI real administrative Cockpit bridge reaches this device',
    t.upload, t.select, 'UI unencrypted HA backup: the wizard asks for no key',
    'UI unencrypted HA backup: the check ran without a key step',
    'UI selects each choice the run named, only from what the check offers',
    'UI actual check confirmation keys observed including valid zero', t.view, t.lines,
    'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
    'UI real key field removed before screenshot', 'UI one acknowledgement enables import', t.result, t.intent, t.keys,
    'UI unencrypted HA backup: neither the check nor the import request carried a key',
    'UI the check and import requests carry exactly the chosen choices', 'UI no page script errors during this page flow',
    'UI cookie observation completed without gaps',
    'UI every issued credential absent from records journal and private evidence; proved public markers counted separately']);
  // The same run with the key (a config that is not keyless) keeps the key step: no new record, no new check.
  const keyed = drive(one('headscale', { device: 'woowbk-dev-d' }), { ...HS_RUN, keyless: false,
    request: { ...HS_RUN.request, key: 'FAKE-HA-KEY' } });
  assert.equal(keyed.status, 0);
  assert.equal('key_step' in keyed.result, false);
  assert.ok(actions(keyed).includes('fill #ha-key'));
});

test('the unencrypted run stops when the wizard shows a key step, keeps a key field or a request carries a key', () => {
  const stepper = drive(HEADSCALE, { ...HS_RUN, key_step_shown: 1 }, { key: null });
  assert.equal(byName(stepper.result)['UI unencrypted HA backup: the wizard asks for no key'], false);
  assert.equal(stepper.status, 1);
  assert.equal(actions(stepper).includes('click [data-focus="ha-apps-next"]'), false);   // no check was started
  const field = drive(HEADSCALE, { ...HS_RUN, key_field_after_check: true }, { key: null });
  assert.equal(byName(field.result)['UI unencrypted HA backup: the check ran without a key step'], false);
  assert.equal(actions(field).includes('click [data-focus="ha-import"]'), false);
  const checkKey = drive(HEADSCALE, { ...HS_RUN, check_key_sent: true }, { key: null });
  assert.equal(byName(checkKey.result)['UI unencrypted HA backup: neither the check nor the import request carried a key'], false);
  assert.equal(checkKey.status, 1);
  const importKey = drive(HEADSCALE, { ...HS_RUN, request: { ...HS_RUN.request, key: 'x' } }, { key: null });
  assert.equal(byName(importKey.result)['UI unencrypted HA backup: neither the check nor the import request carried a key'], false);
  for (const run of [checkKey, importKey]) assert.equal(JSON.stringify(run.result).includes('FAKE-HA-KEY'), false);
  // A key handed to a keyless config is refused before any browser starts.
  const refused = drive(HEADSCALE, HS_RUN, { key: 'FAKE-HA-KEY' });
  assert.notEqual(refused.status, 0);
  assert.equal(refused.browser, null);
  assert.equal(refused.log, null);
});

test('Odoo: the named database of several is chosen; its lines, the line about the one left on HA and its keys count', () => {
  const run = drive(ODOO, ODOO_RUN);
  assert.ok(run.result.checks.every(item => item.ok), JSON.stringify(run.result.checks));
  assert.equal(run.status, 0);
  assert.ok(actions(run).includes('check input[name="ha-odoo-database"][value="woowtest2"]'));
  assert.deepEqual(run.log.radios, { 'ha-odoo-database': 'woowtest2' });
  assert.deepEqual(run.result.confirmations, { expected_keys: { _shared: [S], odoo: [DB(2), OTHER].sort() },
    sent_keys: { _shared: [S], odoo: [OTHER, DB(2)] }, lines_expected: 4, lines_shown: 4, check_importable: ['odoo'] });
  assert.equal(run.result.wire.expected_acknowledged_keys, 3);
  const { named, ...chosen } = run.result.choices;
  assert.deepEqual(named, { odoo: { database: 'woowtest2' } });
  assert.deepEqual(chosen, { database: 'woowtest2', picks: {}, import_choices: { odoo: { database: 'woowtest2' } },
    check_choices: {}, rechecks: 0, problems: [] });
  assert.deepEqual(run.result.requests.import, { key: true, choices: { odoo: { database: 'woowtest2' } } });
  // The database already shown chosen (a page that preselected it) is not clicked again.
  const preselected = drive(ODOO, { ...ODOO_RUN, radios: { 'ha-odoo-database': 'woowtest2' } });
  assert.equal(preselected.status, 0);
  assert.equal(actions(preselected).some(line => line.startsWith('check input[name="ha-odoo-database"]')), false);
});

test('Odoo: the only database that can move needs no name; several without a name or a named one that cannot move stop', () => {
  const single = { ...ODOO_CHECK, apps: [{ ...ODOO_CHECK.apps[0], choices: { database: [
    { value: 'woowtest', label: 'woowtest', ok: false }, { value: 'woowtest2', label: 'woowtest2', ok: true, default: true }] } }] };
  const run = drive(one('odoo', { device: 'woowbk-dev-c', choices: {} }), { ...ODOO_RUN, check: single,
    radios: { 'ha-odoo-database': 'woowtest2' } });
  assert.ok(run.result.checks.every(item => item.ok), JSON.stringify(run.result.checks));
  assert.equal(run.result.choices.database, 'woowtest2');
  const name = 'UI selects each choice the run named, only from what the check offers';
  const cannot = { ...ODOO_CHECK, apps: [{ ...ODOO_CHECK.apps[0], choices: { database: [
    { value: 'woowtest', label: 'woowtest', ok: true }, { value: 'woowtest2', label: 'woowtest2', ok: false }] } }] };
  for (const [label, settings, check] of [['several, none named', one('odoo', { device: 'woowbk-dev-c', choices: {} }), ODOO_CHECK],
    ['named cannot move', ODOO, cannot]]) {
    const stopped = drive(settings, { ...ODOO_RUN, check });
    assert.equal(byName(stopped.result)[name], false, label);
    assert.equal(stopped.status, 1, label);
    assert.equal(actions(stopped).includes('check #ha-ack'), false, `${label}: never acknowledged`);
    assert.equal(actions(stopped).includes('click [data-focus="ha-import"]'), false, `${label}: never imported`);
    assert.ok(stopped.result.choices.problems.length > 0, label);
  }
});

test('a named node other than the shown one is picked, the check runs again with it, and the import carries it', () => {
  const run = drive(NODES, NODE_RUN);
  assert.ok(run.result.checks.every(item => item.ok), JSON.stringify(run.result.checks));
  assert.equal(run.status, 0);
  const order = actions(run);
  const pick = order.indexOf('check input[name="ha-node-emqx"][value="emqx@b.lab"]');
  assert.ok(pick > 0 && order.indexOf('click [data-focus="ha-recheck"]') > pick, order.join('\n'));
  assert.ok(order.indexOf('check #ha-ack') > order.indexOf('click [data-focus="ha-recheck"]'));
  assert.equal(run.result.wire.check_starts, 2);
  assert.deepEqual(run.result.requests.check, [{ key: true, choices: null }, { key: true, choices: { emqx: { node: 'emqx@b.lab' } } }]);
  assert.deepEqual(run.result.choices.picks, { emqx: { node: 'emqx@b.lab' } });
  assert.equal(run.result.choices.rechecks, 1);
  // The default node named: nothing is clicked, one check, and the import carries no choice (the engine's default).
  const plain = drive(one('emqx', { choices: { emqx: { node: 'emqx@a.lab' } } }),
    { ...NODE_RUN, recheck: undefined, recheck_choices: undefined, request: EMQX_RUN.request });
  assert.ok(plain.result.checks.every(item => item.ok), JSON.stringify(plain.result.checks));
  assert.equal(actions(plain).includes('click [data-focus="ha-recheck"]'), false);
  assert.equal(plain.result.wire.check_starts, 1);
  // A recheck that the import then ignores, or nothing named for an offered choice: the page fails or stops.
  const lost = drive(NODES, { ...NODE_RUN, request: EMQX_RUN.request });
  assert.equal(byName(lost.result)['UI the check and import requests carry exactly the chosen choices'], false);
  const unnamed = drive(one('emqx', { choices: {} }), NODE_RUN);
  assert.equal(byName(unnamed.result)['UI selects each choice the run named, only from what the check offers'], false);
  assert.equal(actions(unnamed).includes('click [data-focus="ha-import"]'), false);
});

test('choice planning picks only what the check lists and says why it stops', () => {
  const emqx = { schema: 2, shared: [], apps: [{ app_id: 'emqx', importable: true, issues: [], choices: nodes }] };
  assert.deepEqual(planChoices(emqx, { emqx: { node: 'emqx@b.lab' } }), { problems: [], database: null,
    clicks: [{ app: 'emqx', kind: 'node', value: 'emqx@b.lab' }], importChoices: { emqx: { node: 'emqx@b.lab' } },
    checkChoices: { emqx: { node: 'emqx@b.lab' } } });
  assert.deepEqual(planChoices(emqx, { emqx: { node: 'emqx@b.lab' } }, { emqx: { node: 'emqx@b.lab' } }).clicks, []);
  assert.deepEqual(planChoices(emqx, { emqx: { node: 'emqx@a.lab' } }), { problems: [], clicks: [], database: null,
    importChoices: {}, checkChoices: {} });
  const stop = (check, named) => planChoices(check, named).problems;
  assert.match(stop(emqx, {})[0], /offers a node choice and the run named none/);
  assert.match(stop(emqx, { emqx: { node: 'emqx@c.lab' } })[0], /not one the check offers/);
  assert.match(stop(emqx, { hermes: { addon: 'x' } })[0], /does not import/);
  const single = { schema: 2, shared: [], apps: [{ app_id: 'n8n', importable: true, issues: [],
    choices: { addon: [{ value: 'abc_n8n', ok: true }] } }] };
  assert.deepEqual(stop(single, { n8n: { addon: 'abc_n8n' } }), []);   // one row: no radio, the engine takes it
  assert.match(stop(single, { n8n: { addon: 'other' } })[0], /not one the check offers/);
  assert.deepEqual(usableDatabases(ODOO_CHECK), ['woowtest', 'woowtest2']);
  assert.deepEqual(usableDatabases({ schema: 2, apps: [{ ...ODOO_CHECK.apps[0], importable: false }] }), []);
  assert.deepEqual(usableDatabases({ schema: 2, apps: [{ app_id: 'odoo', importable: true,
    odoo: { databases: [{ name: 'a', ok: true }, { name: 'b', ok: false }] } }] }), ['a']);   // an older check: the section's ok
  assert.equal(planChoices(ODOO_CHECK, { odoo: { database: 'woowtest' } }).database, 'woowtest');
});

test('database options count the lines and keys the confirmation really lists; without them nothing changes', () => {
  assert.deepEqual(issueKeys(ODOO_CHECK), { _shared: [S], odoo: [DB(1), DB(2), OTHER].sort() });   // earlier behaviour
  assert.equal(confirmLineCount(ODOO_CHECK), 2);
  assert.deepEqual(issueKeys(ODOO_CHECK, { database: 'woowtest2' }), { _shared: [S], odoo: [DB(2), OTHER].sort() });
  assert.equal(issueKeyCount(ODOO_CHECK, { database: 'woowtest2' }), 3);
  assert.equal(confirmLineCount(ODOO_CHECK, { database: 'woowtest2' }), 4);
  assert.equal(confirmLineCount(ODOO_CHECK, { database: null }), 2);
  const said = { ...ODOO_CHECK, apps: [{ ...ODOO_CHECK.apps[0], issues: [...ODOO_CHECK.apps[0].issues,
    { id: 'odoo.databases-left', level: 'confirm', key: 'odoo.databases-left:' + '3'.repeat(16), message: 'left' }] }] };
  assert.equal(confirmLineCount(said, { database: 'woowtest2' }), 4);   // the engine says it: the page adds no line of its own
  // A run with choices never counts a line without words, as the page never lists one.
  const silent = { schema: 2, shared: [{ level: 'confirm', key: S, message: '' }], apps: [] };
  assert.deepEqual(issueKeys(silent, { database: null }), {});
  assert.deepEqual(issueKeys(silent), { _shared: [S] });
});

test('the expectations carry encrypted and choices only when given, and refuse anything else', () => {
  assert.equal('encrypted' in pageExpectations(one('headscale')), false);
  assert.equal('choices' in pageExpectations(one('headscale')), false);
  assert.equal(pageExpectations(HEADSCALE).encrypted, false);
  assert.deepEqual(pageExpectations(ODOO).choices, { odoo: { database: 'woowtest2' } });
  for (const change of [{ encrypted: 'no' }, { choices: { odoo: { database: 'woowtest2' } } }, { choices: { headscale: {} } },
    { choices: { headscale: { database: 'x' } } }, { choices: { headscale: { colour: 'x' } } },
    { choices: { headscale: { addon: 'a"b' } } }, { choices: [] }, { exact: false, choices: {} }])
    assert.throws(() => pageExpectations({ ...one('headscale'), ...change }), /invalid page expectations/, JSON.stringify(change));
  assert.equal(validChoices({ odoo: { database: 'woowtest2', addon: 'a0d7b954_odoo' } }, ['odoo']), true);
  assert.equal(validChoices({ odoo: { database: 'woowtest2' } }, ['emqx']), false);
  assert.equal(validImportIntent({ check_starts: 2, unique_import_requests: 1, import_apps: ['emqx'], then_restore: true,
    confirm: true, overwrite: true, expected_acknowledged_keys: 0, acknowledged_keys: 0, separate_restore_starts: 0,
    malformed: 0 }, 1, 1, ['emqx'], 2), true);
});
