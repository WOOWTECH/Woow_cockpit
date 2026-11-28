#!/usr/bin/env node
// ONE real Cockpit page, current one-confirmation HA wizard. No mocked bridge.
// Controller supplies private JSON on stdin; no secret in argv/log/trace.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { issueKeyCount, validImportIntent, pageExpectations, issueKeys, confirmLineCount, acknowledgedOf,
  exactAcknowledged, planChoices } from './focus_acceptance_ui_protocol.mjs';
import { parseSetCookie, digest, coverage, observedValues, provedPublicTombstone,
  nativeCapabilityProgram, readPrimarySourceProof } from './focus_acceptance_ui_cookies.mjs';

if (process.argv.slice(2).join(' ') !== '--run') {
  console.log('R8 page prepared: syntax only; requires reviewed controller and dev-d lease');
  process.exit(process.argv.length === 2 ? 0 : 2);
}
const config = JSON.parse(readFileSync(0, 'utf8'));
if (!/^https:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(config.base)
    || !/^ha-[0-9a-f]{20}$/.test(config.ha_id)) throw new Error('invalid private transport configuration');
// The apps to select and what to expect come from the controller; without them the R8 three-selected case.
// `device` names the lab device whose Cockpit this is (focus_page_bridge.py); without it dev-d, exactly as before.
const expect = pageExpectations(config);
// The app ids the import request is read for: R8's three, and every app this run selects.
const wireApps = new Set(['hermes', 'omnigent', 'emqx', ...expect.apps]);
// Two modes only a config that says so enters (focus_page_bridge.py); every earlier config runs exactly as before:
// `encrypted: false` - an unencrypted HA backup: the wizard has no key step, the page has no key and none is sent;
// `choices` - the run names what the check may offer (an Odoo database, an add-on or a node); the page selects exactly
// that, only from what the check lists, and the check's lines, keys and the requests are judged with it.
const keyless = expect.encrypted === false;
const choosing = expect.choices !== undefined;
if (keyless && config.key !== undefined && config.key !== null) throw new Error('invalid private transport configuration');
const modes = keyless || choosing;
const requestsSeen = { check: [], import: null };   // modes only: what each request carried (key: present or not)
const checkIds = new Set();                         // modes only: the finished checks this page saw
let latestCheck = null, latestCheckChoices = null, chosenDatabase, rechecks = 0;
const picked = {};                                  // choices only: the add-on/node radios this page set
const keyStep = {};                                 // unencrypted only: what the wizard showed of a key step
let choiceRecord = null;                            // choices only: what was named, offered, chosen and sent
const { chromium } = await import(pathToFileURL(config.playwright).href);
const checks = [];
// Exact mode only: the check's confirmation keys and lines against the one request the page sent (keys, never values).
const confirmations = expect.exact
  ? { expected_keys: null, sent_keys: null, lines_expected: null, lines_shown: null, check_importable: null } : null;
const channels = new Map();
const requests = new Set();
const responseBuffers = new Map();
const wire = { check_starts: 0, import_starts: 0, unique_import_requests: 0,
  separate_restore_starts: 0, import_apps: [], then_restore: false, confirm: false,
  overwrite: false, acknowledged_keys: 0, expected_acknowledged_keys: null, malformed: 0 };
const check = (name, ok) => {
  checks.push({ check: name, ok: Boolean(ok) });
  if (!ok) throw new Error(name);
};
// Observe the actual Cockpit stream, discard payloads immediately. Never log a
// frame/request/reply. This does not intercept or replace cockpit.spawn.
function observe(payload) {
  if (typeof payload !== 'string') return;
  const newline = payload.indexOf('\n');
  if (newline < 0) return;
  const channel = payload.slice(0, newline);
  let value;
  try { value = JSON.parse(payload.slice(newline + 1)); } catch { return; }
  if (!channel && value.command === 'open' && Array.isArray(value.spawn)
      && value.spawn[0] === '/usr/local/libexec/woowtech-cockpit-backup') {
    const command = value.spawn[1];
    channels.set(value.channel, command);
    if (command === 'ha-check-start') wire.check_starts++;
    if (command === 'ha-import-start') wire.import_starts++;
    if (command === 'restore-start') wire.separate_restore_starts++;
  } else if (channel && channels.get(channel) === 'ha-import-start') {
    if (!Array.isArray(value.apps) || typeof value.request_id !== 'string') { wire.malformed++; return; }
    requests.add(value.request_id);
    wire.unique_import_requests = requests.size;
    wire.import_apps = value.apps.filter(x => wireApps.has(x)).sort();
    wire.then_restore = value.then_restore === true;
    wire.confirm = value.confirm === true;
    wire.overwrite = value.overwrite === true;
    wire.acknowledged_keys = Object.values(value.acknowledged || {}).reduce((n, xs) => n + (Array.isArray(xs) ? xs.length : 0), 0);
    if (confirmations) confirmations.sent_keys = acknowledgedOf(value.acknowledged);
    if (modes) requestsSeen.import = { key: Object.hasOwn(value, 'key'), choices: choicesOf(value.choices) };
  } else if (modes && channel && channels.get(channel) === 'ha-check-start') {
    // Whether the check request carried a key (never its value) and which choices it was given.
    requestsSeen.check.push({ key: Object.hasOwn(value, 'key'), choices: choicesOf(value.choices) });
  }
}

// The `choices` of a request as {app: {kind: value}} of plain strings (null: none sent; 'malformed': anything else).
function choicesOf(value) {
  if (value === undefined) return null;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return 'malformed';
  const result = {};
  for (const [app, kinds] of Object.entries(value)) {
    if (kinds === null || typeof kinds !== 'object' || Array.isArray(kinds)) return 'malformed';
    result[app] = {};
    for (const [kind, item] of Object.entries(kinds)) {
      if (typeof item !== 'string') return 'malformed';
      result[app][kind] = item;
    }
  }
  return result;
}

// The check's expected keys and lines, as the one confirmation lists them (with the chosen Odoo database, if any).
function expectFrom(check) {
  const options = choosing ? [{ database: chosenDatabase ?? null }] : [];
  try { wire.expected_acknowledged_keys = issueKeyCount(check, ...options); }
  catch { wire.malformed++; }
  if (confirmations) {
    try {
      confirmations.expected_keys = issueKeys(check, ...options);
      confirmations.lines_expected = confirmLineCount(check, ...options);
      confirmations.check_importable = check.apps.filter(app => app.importable === true)
        .map(app => String(app.app_id)).sort();
    } catch { wire.malformed++; }
  }
}

// Read only the real verify-job result already requested by the page. Buffers
// stay in memory and are discarded; no frame, key or response is persisted.
function observeReply(payload) {
  if (typeof payload !== 'string') return;
  const newline = payload.indexOf('\n');
  if (newline < 0) return;
  const channel = payload.slice(0, newline);
  const chunk = payload.slice(newline + 1);
  if (!channel) {
    try {
      const control = JSON.parse(chunk);
      if (control.command === 'init' && /^\d+(?:\.\d+)*$/.test(control.system?.version || '')) versions.add(control.system.version);
      if (control.command === 'close') {
        channels.delete(control.channel);
        responseBuffers.delete(control.channel);
      }
    } catch { /* never persist malformed input */ }
    return;
  }
  if (channels.get(channel) !== 'job-status') return;
  const text = (responseBuffers.get(channel) || '') + chunk;
  if (text.length > 4 * 1024 * 1024) { wire.malformed++; responseBuffers.delete(channel); return; }
  responseBuffers.set(channel, text);
  let reply;
  try { reply = JSON.parse(text); } catch { return; }
  responseBuffers.delete(channel);
  const job = reply.job;
  if (job?.type !== 'verify' || job.params?.ha_backup_id !== config.ha_id || !job.result?.ha_check) return;
  if (modes) {
    if (typeof job.id === 'string') checkIds.add(job.id);
    latestCheck = job.result.ha_check;
    latestCheckChoices = choicesOf(job.params?.choices);
  }
  // With choices the keys and lines wait for the choice: the chosen Odoo database decides which lines are listed.
  if (!choosing) expectFrom(job.result.ha_check);
}

// Bounded wait for something the page's own observers record (a recheck's finished check).
async function until(condition, ms) {
  const deadline = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('observed state deadline');
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}

let browser;
let context;
let frame;
const cookieRows = [], cookieObservations = new Set(), versions = new Set();
let cookieObservationErrors = 0, initialRoot = true;
let initialJar = [], rootVerified = false, nativeCapability, primarySource;
let finishing;
let pageErrors = 0;
let recording = false;
let clicks = 0;
let ticks = 0;
let completed = false;
let issuedScan = false;
let issuedScanCounts = null;
let stage = 'login';
let failureKind = null;
process.once('SIGTERM', async () => {
  completed = false;
  failureKind ||= 'controller-timeout';
  checks.push({ check: 'UI controller runtime stayed bounded', ok: false });
  try { await finishBrowser(); } finally { process.exit(124); }
});
try {
  primarySource = readPrimarySourceProof();
  browser = await chromium.launch({ executablePath: config.chromium,
    args: ['--disable-background-networking', '--disable-component-update'] });
  context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US',
    viewport: { width: 1440, height: 900 } });
  // Observe login/renewal Set-Cookie values as well as the final cookie jar.
  // No cookie/header is persisted; scan every observed value before teardown.
  context.on('response', observeCookies);
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
  page.on('websocket', ws => {
    ws.on('framesent', event => observe(event.payload));
    ws.on('framereceived', event => observeReply(event.payload));
  });
  page.on('pageerror', () => { if (recording) pageErrors++; });
  // Existing Cockpit password + administrative access, same as cockpit-login.mjs.
  await page.goto(config.base, { waitUntil: 'domcontentloaded' });
  await drainCookies();
  initialJar = await context.cookies(); initialRoot = false;
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(config.password);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 60000 });
  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access|受限存取|受限制的存取|管理員存取模式|管理員存取)$/ });
  await indicator.waitFor();
  if (/Limited|受限/.test(await indicator.textContent())) {
    await indicator.click();
    await page.locator('#switch-to-admin-access-password').fill(config.password);
    await page.getByRole('button', { name: /^(Authenticate|認證|驗證)$/ }).click();
    await page.locator('#switch-to-admin-access-password').waitFor({ state: 'detached' });
  }
  await page.getByRole('button', { name: /^(Administrative access|管理員存取模式|管理員存取)$/ }).waitFor();
  stage = 'open-backup-page';
  await page.goto(`${config.base}/woowtechbackup#/backups`, { waitUntil: 'domcontentloaded' });
  const iframe = page.locator('iframe[src*="woowtechbackup"]');
  await iframe.waitFor({ state: 'attached' });
  frame = await (await iframe.elementHandle()).contentFrame();
  await frame.locator('[data-focus="list-upload"]').waitFor();
  // A config without `device` passes the program alone, as R8 and page-emqx always did (their Cockpit is dev-d's); a
  // device's own run passes its name too. The same three spawns either way.
  const capability = await frame.evaluate(async probe => {
    const { program, device } = typeof probe === 'string' ? { program: probe, device: 'woowbk-dev-d' } : probe;
    const uid = await window.cockpit.spawn(['id', '-u'], { superuser: 'require', err: 'message' });
    const host = await window.cockpit.spawn(['hostname'], { err: 'message' });
    const native = JSON.parse(await window.cockpit.spawn(['python3', '-B', '-I', '-c', program],
      { superuser: 'require', err: 'ignore' }));
    return { root: uid.trim() === '0' && host.trim() === device, native };
  }, config.device === undefined ? nativeCapabilityProgram : { program: nativeCapabilityProgram, device: expect.device });
  rootVerified = capability.root === true; nativeCapability = capability.native;
  check('UI real administrative Cockpit bridge reaches this device', rootVerified);
  recording = true;
  stage = 'upload';
  await frame.locator('[data-focus="list-upload"]').click();
  await frame.locator('#restore-file').setInputFiles(config.fixture);
  await frame.locator('[data-focus="restore-upload"]:not([disabled])').waitFor();
  await frame.locator('[data-focus="restore-upload"]').click();
  await frame.waitForFunction(id => window.location.hash === `#/ha/${id}`, config.ha_id, { timeout: 10 * 60 * 1000 });
  await frame.locator('#ha-info').waitFor();
  check(expect.texts.upload, true);
  stage = expect.select_stage;
  await frame.locator(`[data-focus="ha-import-${config.ha_id}"]`).click();
  const initiallySelected = await frame.locator('input[id^="ha-app-"]:checked').evaluateAll(xs => xs.map(x => x.id));
  for (const id of initiallySelected) await frame.locator(`#${id}`).uncheck();
  for (const app of expect.apps) {
    await frame.locator(`#ha-app-${app}`).check();
  }
  const selected = await frame.locator('input[id^="ha-app-"]:checked').evaluateAll(xs => xs.map(x => x.id.slice(7)).sort());
  check(expect.texts.select, JSON.stringify(selected) === JSON.stringify([...expect.apps].sort()));
  if (keyless) {
    // The upload's record says no chosen add-on is encrypted: the wizard lists no key step and checks at once.
    keyStep.stepper_key_steps = await frame.locator('.stepper li[data-step="key"]').count();
    check('UI unencrypted HA backup: the wizard asks for no key', keyStep.stepper_key_steps === 0);
  }
  await frame.locator('[data-focus="ha-apps-next"]').click();
  if (keyless) stage = 'check';
  else {
    stage = 'key-and-check';
    await frame.locator('#ha-key').fill(config.key);
    await frame.locator('[data-focus="ha-key-next"]').click();
  }
  await frame.locator('#ha-ack').waitFor({ timeout: 10 * 60 * 1000 });
  if (keyless) {
    keyStep.key_fields_after_check = await frame.locator('#ha-key').count();
    check('UI unencrypted HA backup: the check ran without a key step', keyStep.key_fields_after_check === 0);
  }
  if (choosing) {
    stage = 'choices';
    check('UI selects each choice the run named, only from what the check offers', await chooseAsNamed());
  }
  stage = 'one-confirmation';
  check('UI actual check confirmation keys observed including valid zero', wire.expected_acknowledged_keys !== null);
  let viewOk = true;
  for (const app of expect.blocked)
    viewOk = viewOk && await frame.locator(`[data-ha-app="${app}"][data-importable="no"] .ha-issue-stop`).count() > 0;
  for (const app of expect.importable)
    viewOk = viewOk && await frame.locator(`[data-ha-app="${app}"][data-importable="yes"]`).count() === 1;
  check(expect.texts.view, viewOk);
  if (confirmations) {
    // Every confirmation line the check lists is on the page, and the check itself calls exactly the expected apps importable.
    confirmations.lines_shown = await frame.locator('#ha-confirm-list .ha-issue-confirm').count();
    check(expect.texts.lines, Number.isInteger(confirmations.lines_expected)
      && confirmations.lines_shown === confirmations.lines_expected
      && JSON.stringify(confirmations.check_importable) === JSON.stringify(expect.importApps));
  }
  check('UI has exactly one acknowledgement and import waits for it',
    await frame.locator('#ha-ack').count() === 1 && !(await frame.locator('#ha-ack').isChecked())
    && await frame.locator('[data-focus="ha-import"]').isDisabled());
  check('UI check did not start an import or separate restore', wire.import_starts === 0 && wire.separate_restore_starts === 0);
  // The real key input is gone. Every remaining input is additionally masked.
  check('UI real key field removed before screenshot', await frame.locator('#ha-key').count() === 0);
  await frame.locator('#view').screenshot({ path: join(config.evidence, 'confirmation.png'), mask: [frame.locator('input,textarea')] });
  await frame.locator('#ha-test-mode').uncheck();
  await frame.locator('#ha-ack').check(); ticks++;
  check('UI one acknowledgement enables import', await frame.locator('[data-focus="ha-import"]').isEnabled());
  await frame.locator('[data-focus="ha-import"]').click(); clicks++;
  stage = 'import-and-result';
  await frame.locator('[data-result="group"]').waitFor({ timeout: 20 * 60 * 1000 });
  let resultOk = true;
  for (const [app, status] of expect.result_rows)
    resultOk = resultOk && await frame.locator(`[data-ha-app="${app}"][data-status="${status}"]`).count() === 1;
  if (expect.exact && resultOk) {
    // A restore's kept copy (Odoo's cold cluster) is listed below the apps as an li.ha-group-row.ha-kept-item, not an app
    // row. It is counted only when the rows differ, so every earlier result asks exactly what it asked before.
    let rows = await frame.locator('#view li.ha-group-row').count();
    if (rows !== expect.result_rows.length) rows -= await frame.locator('#view li.ha-group-row.ha-kept-item').count();
    resultOk = rows === expect.result_rows.length;
  }
  check(expect.texts.result, resultOk);
  check(expect.texts.intent, choosing ? validImportIntent(wire, ticks, clicks, expect.importApps, 1 + rechecks)
    : validImportIntent(wire, ticks, clicks, expect.importApps));
  if (confirmations) check(expect.texts.keys, exactAcknowledged(confirmations.expected_keys, confirmations.sent_keys));
  if (keyless)
    check('UI unencrypted HA backup: neither the check nor the import request carried a key', requestsSeen.check.length > 0
      && requestsSeen.check.every(request => request.key === false) && requestsSeen.import?.key === false);
  if (choosing) check('UI the check and import requests carry exactly the chosen choices', requestsMatchChoices());
  check('UI no page script errors during this page flow', pageErrors === 0);
  await frame.locator('#view').screenshot({ path: join(config.evidence, 'result.png'), mask: [frame.locator('input,textarea')] });
  completed = true;

} catch (error) {
  // No raw Playwright errors: those can include a key or page text.
  failureKind = error?.name === 'TimeoutError' ? 'timeout' : 'check-or-browser-error';
  checks.push({ check: 'UI bounded flow completed', ok: false });
} finally {
  await finishBrowser();
}

// The choice step (choices only): every add-on/node the run named that is not what the radio already shows is picked and
// the check runs again with it (the page's own 「重新檢查」); then the Odoo database is chosen (the named one, or the single
// one that can move). Nothing the check does not list is ever picked; a choice the check offers but the run did not name
// stops the page before the confirmation is ticked.
async function chooseAsNamed() {
  choiceRecord = { named: expect.choices, database: null, picks: {}, import_choices: null, check_choices: null, rechecks: 0,
    problems: [] };
  let plan = latestCheck ? planChoices(latestCheck, expect.choices, picked)
    : { problems: ['no finished check observed'], clicks: [] };
  if (!plan.problems.length && plan.clicks.length) {
    for (const { app, kind, value } of plan.clicks) {
      await frame.locator(`input[name="ha-${kind}-${app}"][value="${value}"]`).check();
      (picked[app] ||= {})[kind] = value;
    }
    const seen = checkIds.size;
    await frame.locator('[data-focus="ha-recheck"]').click();
    rechecks++;
    await until(() => checkIds.size > seen, 10 * 60 * 1000);
    await frame.locator('#ha-ack').waitFor({ timeout: 10 * 60 * 1000 });
    plan = planChoices(latestCheck, expect.choices, picked);
    if (plan.clicks.length) plan.problems.push('the recheck did not keep the chosen add-on or node');
  }
  Object.assign(choiceRecord, { problems: plan.problems, rechecks });
  if (plan.problems.length) return false;
  const database = plan.database === null ? null : frame.locator(`input[name="ha-odoo-database"][value="${plan.database}"]`);
  if (database && !(await database.isChecked())) await database.check();
  chosenDatabase = plan.database;
  let shown = !database || await database.isChecked();
  for (const [app, kinds] of Object.entries(expect.choices))
    for (const [kind, value] of Object.entries(kinds))
      if (kind !== 'database' && offeredRows(latestCheck, app, kind) >= 2)
        shown = shown && await frame.locator(`input[name="ha-${kind}-${app}"][value="${value}"]`).isChecked();
  Object.assign(choiceRecord, { database: plan.database, picks: structuredClone(picked), import_choices: plan.importChoices,
    check_choices: plan.checkChoices });
  expectFrom(latestCheck);
  return shown;
}

// How many `choices.<kind>` rows the check lists for an app (radios appear from two on).
function offeredRows(check, app, kind) {
  const row = (check?.apps || []).find(item => item?.app_id === app);
  return Array.isArray(row?.choices?.[kind]) ? row.choices[kind].length : 0;
}

// Choices only: the first check carried none, a recheck exactly the picks, the import exactly the picks and the database.
function requestsMatchChoices() {
  const canonical = value => JSON.stringify(value, (key, item) => (item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(name => [name, item[name]])) : item));
  const empty = value => Object.keys(value || {}).length === 0;
  const checks = requestsSeen.check;
  return Boolean(choiceRecord) && checks.length === 1 + rechecks && checks[0].choices === null
    && (rechecks === 0 || canonical(checks[checks.length - 1].choices) === canonical(choiceRecord.check_choices))
    && (rechecks === 0 ? latestCheckChoices === null : canonical(latestCheckChoices) === canonical(choiceRecord.check_choices))
    && requestsSeen.import !== null && (empty(choiceRecord.import_choices) ? requestsSeen.import.choices === null
      : canonical(requestsSeen.import.choices) === canonical(choiceRecord.import_choices));
}

function observeCookies(response) {
  const url = new URL(response.url());
  if (url.origin !== config.base) return;
  const rootGet = initialRoot && url.pathname === '/' && !url.search
    && response.request().method() === 'GET' && response.status() === 200;
  const work = response.headerValues('set-cookie').then(headers => {
    for (const header of headers) {
      const row = parseSetCookie(header);
      const first = header.split(';', 1)[0];
      row.legacyValue = first.slice(first.indexOf('=') + 1);
      cookieRows.push({ ...row, rootGet });
    }
  }).catch(() => { cookieObservationErrors++; }).finally(() => cookieObservations.delete(work));
  cookieObservations.add(work);
}
async function drainCookies() {
  const deadline = Date.now() + 10000;
  while (cookieObservations.size) {
    if (Date.now() > deadline) throw new Error('cookie observation deadline');
    await Promise.race([Promise.all([...cookieObservations]), new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('cookie observation deadline')), 10000); timer.unref();
    })]);
  }
}
async function finishBrowser() {
  if (finishing) return finishing;
  finishing = (async () => {
  recording = false;
  // Observe the entire import flow; retain metadata before scanning on success
  // or failure. Raw headers/values/frames never leave memory or spawn stdin.
  try {
    if (!context || !frame || !rootVerified) throw new Error('authenticated frame unavailable');
    stage = 'issued-value-scan';
    await drainCookies();
    const liveJar = await context.cookies();
    const cov = coverage(cookieRows, initialJar, liveJar, cookieObservationErrors);
    const sourceVersion = versions.size === 1 ? [...versions][0] : 'unknown';
    const authObserved = liveJar.some(c => c.name === 'cockpit'
      && cookieRows.some(r => r.name === c.name && r.value === c.value && !r.rootGet));
    const proof = { source_version: sourceVersion, administrative_root_verified: rootVerified,
      authenticated_cookie_observed: authObserved, primary_source_hashes_verified: Boolean(primarySource),
      native_package_version: nativeCapability?.package_version, native_ws_binary_sha256: nativeCapability?.binary_sha256 };
    const values = observedValues(cookieRows, liveJar, initialJar);
    const publicValue = value => {
      const rows = cookieRows.filter(r => r.value === value || r.legacyValue === value);
      return rows.length > 0 && rows.every(r => r.value === value && provedPublicTombstone(r, liveJar, proof));
    };
    const metadata = cov.metadata.map((row, i) => ({ ...row,
      classification: cookieRows[i] && publicValue(cookieRows[i].value)
        ? 'proved-public-protocol-tombstone' : row.classification }));
    const identityProof = { cookie_metadata: metadata, observations_complete: cov.observations_complete,
      administrative_root_verified: rootVerified, source_version: sourceVersion,
      native_cockpit_capability: nativeCapability, primary_source_commit: primarySource?.commit,
      primary_sources: primarySource?.files.map(s => ({ url: s.url, sha256: s.sha256 })) };
    writeFileSync(join(config.evidence, 'cookie-observations.json'), JSON.stringify(identityProof, null, 2) + '\n',
      { mode: 0o600, flag: 'wx' });
    issuedScanCounts = { ...identityProof, observed_values: values.length, scan_completed: false };
    if (!values.length || values.some(value => !value)) throw new Error('issued values unavailable');
    // Reuse the exact strict per-value scanner exercised by the two read-only
    // probes. The controller separately scans all registered credentials.
    const script = readFileSync(new URL('../../../snippets/focus-acceptance/r8-cookie-scan-rendered.py', import.meta.url), 'utf8');
    const report = await frame.evaluate(async ({ script, values, since }) => {
      const request = window.cockpit.spawn(['python3', '-B', '-I', '-c', script], { superuser: 'require', err: 'ignore' });
      request.input(JSON.stringify({ values, registered: [], since }));
      return JSON.parse(await request);
    }, { script, values, since: config.since });
    const host = new Map(values.map(value => [digest(value), 0]));
    let hostFiles = 0;
    for (const entry of readdirSync(config.evidence, { withFileTypes: true })) {
      if (!entry.isFile()) throw new Error('unexpected private evidence path');
      const path = join(config.evidence, entry.name);
      if (path === config.fixture) continue;  // HA tar is original application data.
      const data = readFileSync(path); hostFiles++;
      for (const value of values) {
        const hits = [...new Set([value, JSON.stringify(value).slice(1, -1)])]
          .reduce((n, text) => n + (data.includes(Buffer.from(text)) ? 1 : 0), 0);
        host.set(digest(value), host.get(digest(value)) + hits);
      }
    }
    await drainCookies();
    const finalJar = await context.cookies();
    const jarStable = finalJar.length === liveJar.length && finalJar.every(c => liveJar.some(x =>
      x.name === c.name && x.value === c.value && x.domain === c.domain && x.path === c.path));
    const finalValues = observedValues(cookieRows, finalJar, initialJar);
    const noLateValues = finalValues.length === values.length && finalValues.every(v => values.includes(v));
    const complete = cov.observations_complete && coverage(cookieRows, initialJar, finalJar, cookieObservationErrors).observations_complete
      && jarStable && noLateValues;
    const matches = values.map(value => {
      const hash = digest(value);
      if (!report.values[hash]) throw new Error('per-value result unavailable');
      return { names: [...new Set([...cookieRows, ...initialJar, ...liveJar]
        .filter(r => r.value === value || r.legacyValue === value).map(r => r.name))].sort(),
        sha256: hash, length: Buffer.byteLength(value),
        classification: publicValue(value) ? 'proved-public-protocol-tombstone' : 'credential-zero-hits-required',
        device: report.values[hash], host_hits: host.get(hash) };
    });
    const credentials = matches.filter(v => v.classification === 'credential-zero-hits-required');
    const publicMarkers = matches.filter(v => v.classification === 'proved-public-protocol-tombstone');
    const credentialHits = credentials.reduce((n, v) => n + v.device.hits, 0);
    const credentialHostHits = credentials.reduce((n, v) => n + v.host_hits, 0);
    issuedScanCounts = { ...identityProof, observed_values: values.length, match_counts: matches,
      device_files: report.scanned, archive_index_sidecars: report.archive_index_sidecars_scanned,
      actual_archive_index_sidecars_expected: report.actual_archive_index_sidecars_expected,
      regular_json_roots: report.regular_json_roots_scanned, device_hits: report.all_values_hits,
      credential_device_hits: credentialHits, public_marker_device_hits: publicMarkers.reduce((n, v) => n + v.device.hits, 0),
      host_files: hostFiles, host_hits: matches.reduce((n, v) => n + v.host_hits, 0), credential_host_hits: credentialHostHits,
      observations_complete: complete, live_jar_stable_during_scan: jarStable, no_unscanned_late_values: noLateValues,
      unscanned_late_cookie_metadata: coverage(cookieRows, initialJar, finalJar, cookieObservationErrors).metadata
        .filter(c => !metadata.some(old => old.name === c.name && old.sha256 === c.sha256)), scan_completed: true };
    issuedScan = complete && authObserved && credentials.length > 0 && credentialHits === 0 && credentialHostHits === 0
      && report.scanned > 0 && report.regular_json_roots_scanned === 2
      && report.archive_index_sidecars_scanned > 0
      && report.archive_index_sidecars_scanned === report.actual_archive_index_sidecars_expected && hostFiles > 0;
    checks.push({ check: 'UI cookie observation completed without gaps', ok: complete });
    check('UI every issued credential absent from records journal and private evidence; proved public markers counted separately', issuedScan);
  } catch {
    failureKind ||= 'issued-value-scan-error';
    checks.push({ check: 'UI issued-value scan completed before close', ok: false });
  }
  if (browser) {
    try { await browser.close(); }
    catch { checks.push({ check: 'UI browser closed', ok: false }); }
  }
  const result = { stage, failure_kind: failureKind, completed, issued_values_scanned: issuedScan, page_errors: pageErrors,
    issued_scan_counts: issuedScanCounts, acknowledgement_ticks: ticks, import_clicks: clicks, wire, checks,
    ...(confirmations ? { confirmations } : {}),
    // Only the new modes add records (keys present or not, never a value): an earlier config's record is unchanged.
    ...(keyless ? { key_step: keyStep } : {}), ...(choosing ? { choices: choiceRecord } : {}),
    ...(modes ? { requests: requestsSeen } : {}) };
  writeFileSync(config.result, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  })();
  return finishing;
}
console.log(`R8 UI ${checks.filter(x => x.ok).length}/${checks.length} ${checks.every(x => x.ok) ? 'PASS' : 'FAIL'}`);
process.exit(checks.every(x => x.ok) ? 0 : 1);
