#!/usr/bin/env node
// ONE real Cockpit page, current one-confirmation HA wizard. No mocked bridge.
// Controller supplies private JSON on stdin; no secret in argv/log/trace.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { issueKeyCount, validImportIntent } from './focus_acceptance_ui_protocol.mjs';

if (process.argv.slice(2).join(' ') !== '--run') {
  console.log('R8 page prepared: syntax only; requires reviewed controller and dev-d lease');
  process.exit(process.argv.length === 2 ? 0 : 2);
}
const config = JSON.parse(readFileSync(0, 'utf8'));
if (!/^https:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(config.base)
    || !/^ha-[0-9a-f]{20}$/.test(config.ha_id)) throw new Error('invalid private transport configuration');
const { chromium } = await import(pathToFileURL(config.playwright).href);
const checks = [];
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
    wire.import_apps = value.apps.filter(x => ['hermes', 'omnigent', 'emqx'].includes(x)).sort();
    wire.then_restore = value.then_restore === true;
    wire.confirm = value.confirm === true;
    wire.overwrite = value.overwrite === true;
    wire.acknowledged_keys = Object.values(value.acknowledged || {}).reduce((n, xs) => n + (Array.isArray(xs) ? xs.length : 0), 0);
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
  try { wire.expected_acknowledged_keys = issueKeyCount(job.result.ha_check); }
  catch { wire.malformed++; }
}

let browser;
let context;
let frame;
const issued = new Set();
const cookieObservations = [];
let cookieObservationFailed = false;
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
  browser = await chromium.launch({ executablePath: config.chromium,
    args: ['--disable-background-networking', '--disable-component-update'] });
  context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US',
    viewport: { width: 1440, height: 900 } });
  // Observe login/renewal Set-Cookie values as well as the final cookie jar.
  // No cookie/header is persisted; scan every observed value before teardown.
  context.on('response', response => {
    if (!response.url().startsWith(config.base + '/')) return;
    cookieObservations.push(response.headerValues('set-cookie').then(headers => {
      for (const header of headers) {
        const first = header.split(';', 1)[0];
        const value = first.slice(first.indexOf('=') + 1);
        if (value) issued.add(value);
      }
    }).catch(() => { cookieObservationFailed = true; }));
  });
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
  page.on('websocket', ws => {
    ws.on('framesent', event => observe(event.payload));
    ws.on('framereceived', event => observeReply(event.payload));
  });
  page.on('pageerror', () => { if (recording) pageErrors++; });
  // Existing Cockpit password + administrative access, same as cockpit-login.mjs.
  await page.goto(config.base, { waitUntil: 'domcontentloaded' });
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
  check('UI real administrative Cockpit bridge reaches this device', await frame.evaluate(async () => {
    const uid = await window.cockpit.spawn(['id', '-u'], { superuser: 'require', err: 'message' });
    const host = await window.cockpit.spawn(['hostname'], { err: 'message' });
    return uid.trim() === '0' && host.trim() === 'woowbk-dev-d';
  }));
  recording = true;
  stage = 'upload';
  await frame.locator('[data-focus="list-upload"]').click();
  await frame.locator('#restore-file').setInputFiles(config.fixture);
  await frame.locator('[data-focus="restore-upload"]:not([disabled])').waitFor();
  await frame.locator('[data-focus="restore-upload"]').click();
  await frame.waitForFunction(id => window.location.hash === `#/ha/${id}`, config.ha_id, { timeout: 10 * 60 * 1000 });
  await frame.locator('#ha-info').waitFor();
  check('UI uploaded derived real fixture through actual page', true);
  stage = 'select-three-apps';
  await frame.locator(`[data-focus="ha-import-${config.ha_id}"]`).click();
  const initiallySelected = await frame.locator('input[id^="ha-app-"]:checked').evaluateAll(xs => xs.map(x => x.id));
  for (const id of initiallySelected) await frame.locator(`#${id}`).uncheck();
  for (const app of ['emqx', 'omnigent', 'hermes']) {
    await frame.locator(`#ha-app-${app}`).check();
  }
  const selected = await frame.locator('input[id^="ha-app-"]:checked').evaluateAll(xs => xs.map(x => x.id.slice(7)).sort());
  check('UI selects exactly the three reviewed apps', JSON.stringify(selected) === JSON.stringify(['emqx', 'hermes', 'omnigent']));
  await frame.locator('[data-focus="ha-apps-next"]').click();
  stage = 'key-and-check';
  await frame.locator('#ha-key').fill(config.key);
  await frame.locator('[data-focus="ha-key-next"]').click();
  await frame.locator('#ha-ack').waitFor({ timeout: 10 * 60 * 1000 });
  stage = 'one-confirmation';
  check('UI actual check confirmation keys observed including valid zero', wire.expected_acknowledged_keys !== null);
  check('UI corrupt EMQX blocked and both other apps importable',
    await frame.locator('[data-ha-app="emqx"][data-importable="no"] .ha-issue-stop').count() > 0
    && await frame.locator('[data-ha-app="hermes"][data-importable="yes"]').count() === 1
    && await frame.locator('[data-ha-app="omnigent"][data-importable="yes"]').count() === 1);
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
  check('UI result imports both apps and retains excluded EMQX row',
    await frame.locator('[data-ha-app="hermes"][data-status="imported"]').count() === 1
    && await frame.locator('[data-ha-app="omnigent"][data-status="imported"]').count() === 1
    && await frame.locator('[data-ha-app="emqx"][data-status="excluded"]').count() === 1);
  check('UI one click sends one real acknowledged import intent for only importable apps',
    validImportIntent(wire, ticks, clicks));
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

async function finishBrowser() {
  if (finishing) return finishing;
  finishing = (async () => {
  recording = false;
  // Capture and scan before closing even when a preceding assertion failed.
  try {
    if (!context || !frame) throw new Error('authenticated frame unavailable');
    stage = 'issued-value-scan';
    // Keep values in memory. Observe the jar even if one header callback failed;
    // scan what was captured, then report incomplete coverage as a failed check.
    const observed = await Promise.allSettled(cookieObservations);
    for (const cookie of await context.cookies()) if (cookie.value) issued.add(cookie.value);
    const values = [...issued];
    if (!values.length) throw new Error('issued values unavailable');
    const report = await frame.evaluate(async ({ script, values, since }) => {
      const request = window.cockpit.spawn(['python3', '-I', '-c', script], { superuser: 'require', err: 'message' });
      request.input(JSON.stringify({ values, since }));
      return JSON.parse(await request);
    }, { script: config.cookie_scan, values, since: config.since });
    // Cookies are ASCII HTTP values; cover raw and JSON string escaping in all
    // current private case files, including screenshots. The HA tar is data.
    const needles = values.flatMap(value => [Buffer.from(value), Buffer.from(JSON.stringify(value).slice(1, -1))]);
    let hostFiles = 0, hostHits = 0;
    for (const entry of readdirSync(config.evidence, { withFileTypes: true })) {
      if (!entry.isFile()) throw new Error('unexpected private evidence path');
      const path = join(config.evidence, entry.name);
      if (path === config.fixture) continue;
      const data = readFileSync(path); hostFiles++;
      for (const needle of needles) if (data.includes(needle)) hostHits++;
    }
    const complete = !cookieObservationFailed && observed.every(x => x.status === 'fulfilled');
    issuedScanCounts = { observed_values: values.length, device_files: report.scanned,
      archive_index_sidecars: report.archive_index_sidecars_scanned,
      regular_json_roots: report.regular_json_roots_scanned,
      device_hits: report.hits, host_files: hostFiles, host_hits: hostHits, observations_complete: complete };
    issuedScan = complete && report.hits === 0 && report.scanned > 0
      && report.regular_json_roots_scanned === 2
      && report.archive_index_sidecars_scanned > 0 && hostFiles > 0 && hostHits === 0;
    checks.push({ check: 'UI cookie observation completed without gaps', ok: complete });
    check('UI issued Cockpit values absent from records journal and private evidence', issuedScan);
  } catch {
    failureKind ||= 'issued-value-scan-error';
    checks.push({ check: 'UI issued-value scan completed before close', ok: false });
  }
  if (browser) {
    try { await browser.close(); }
    catch { checks.push({ check: 'UI browser closed', ok: false }); }
  }
  const result = { stage, failure_kind: failureKind, completed, issued_values_scanned: issuedScan, page_errors: pageErrors,
    issued_scan_counts: issuedScanCounts, acknowledgement_ticks: ticks, import_clicks: clicks, wire, checks };
  writeFileSync(config.result, JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  })();
  return finishing;
}
console.log(`R8 UI ${checks.filter(x => x.ok).length}/${checks.length} ${checks.every(x => x.ok) ? 'PASS' : 'FAIL'}`);
process.exit(checks.every(x => x.ok) ? 0 : 1);
