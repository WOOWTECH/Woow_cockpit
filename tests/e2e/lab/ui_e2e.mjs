#!/usr/bin/env node
// UI-level end-to-end on the lab devices: the real Cockpit 362 (cockpit-ws + bridge + superuser), the
// installed "備份與還原" page and the installed engine. Nothing is faked.
//   node tests/e2e/lab/ui_e2e.mjs [admin|s1|s2|all]
//   admin  dev-a: limited access -> admin-required state; switching to administrative access loads real data (F12)
//   s1     dev-a: create a backup with images in the page, close the tab mid-job and reopen (F11: the job finishes,
//          the page resumes), download it through the real external fsread1 channel, mutate the app, restore it
//          in place from the list, result table "資料一致", /api/summary == snapshot, safety backup listed
//   s2     dev-b, torn down first: upload the downloaded file in the page (fsreplace1 over the websocket), key step
//          with dev-a's kit key, preflight (fresh, UID 1007), confirm, progress, result; summary == snapshot;
//          the restored app accepts new notes and files
// The devadmin password and the kit key are read from ~/.woowbk-lab/secrets (0600) and never printed; no
// screenshot is taken while a password or key is on screen. Evidence: ~/.woowbk-lab/evidence/integration/ui-*.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const LAB = join(homedir(), '.woowbk-lab');
const LP = join(LAB, 'bin', 'labpodman');
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const DEV = { a: { name: 'woowbk-dev-a', port: 19091, uid: 1001 }, b: { name: 'woowbk-dev-b', port: 19092, uid: 1007 } };
const APP = 'woowbk-demo';
const COMPARE = ['notes', 'files', 'digest', 'title', 'signatures_valid'];
const SECRET_RE = /AGE-SECRET-KEY-1[0-9A-Za-z]+/g;
const PASSWORD = readFileSync(join(LAB, 'secrets', 'devadmin.pass'), 'utf8').trim();
const now = new Date();
const pad = n => String(n).padStart(2, '0');
// Local time, like cli_e2e.py, so the evidence folders sort together.
const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}T${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
const EVIDENCE = join(LAB, 'evidence', 'integration', `${stamp}-ui`);
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
const STATE_FILE = join(LAB, 'evidence', 'integration', 'ui-state.json');
const bundled = join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome');
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || (existsSync(bundled) ? bundled : undefined);

const checks = [];
const timings = {};
const t0 = Date.now();
const scrub = text => String(text).replace(SECRET_RE, '[secret]').split(PASSWORD).join('[password]');
function log(message) {
  const line = `${new Date().toISOString().slice(11, 19)} +${((Date.now() - t0) / 1000).toFixed(1).padStart(6)}s ${scrub(message)}`;
  console.log(line);
  writeFileSync(join(EVIDENCE, 'driver.log'), line + '\n', { flag: 'a' });
}
function check(name, condition, detail = '') {
  const ok = Boolean(condition);
  checks.push({ check: name, ok, detail: scrub(typeof detail === 'string' ? detail : JSON.stringify(detail)).slice(0, 500) });
  log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` -- ${scrub(typeof detail === 'string' ? detail : JSON.stringify(detail)).slice(0, 300)}` : ''}`);
  return ok;
}
class Abort extends Error {}
function require_(name, condition, detail = '') { if (!check(name, condition, detail)) throw new Abort(name); }
const loadState = () => { try { return JSON.parse(readFileSync(STATE_FILE, 'utf8')); } catch { return {}; } };
const saveState = fields => writeFileSync(STATE_FILE, JSON.stringify({ ...loadState(), ...fields }, null, 1));

// ------------------------------------------------------------------ device side (labpodman only)

function lp(args, input = '') {
  const result = spawnSync(LP, args, { input, maxBuffer: 64 * 1024 * 1024 });
  return { status: result.status, stdout: String(result.stdout || ''), stderr: String(result.stderr || '') };
}
function engine(dev, command, request) {
  const result = lp(['exec', '-i', DEV[dev].name, HELPER, command], request === undefined ? '' : JSON.stringify(request));
  const reply = JSON.parse(result.stdout.trim().split('\n').pop() || '{}');
  if (!reply.ok) log(`engine ${command} on dev-${dev}: ${JSON.stringify(reply.error)}`);
  return reply;
}
function sh(dev, script, input = '') {
  const result = lp(['exec', '-i', DEV[dev].name, 'sh', '-c', script], input);
  if (result.status !== 0) throw new Error(`dev-${dev}: ${script.slice(0, 80)} -> ${result.status} ${scrub(result.stderr).slice(-300)}`);
  return result.stdout;
}
function owner(dev, ...argv) {
  const result = lp(['exec', '-i', DEV[dev].name, '/usr/local/bin/woowbk-owner', ...argv]);
  if (result.status !== 0) throw new Error(`dev-${dev} owner ${argv.join(' ').slice(0, 80)} -> ${result.status} ${scrub(result.stderr).slice(-300)}`);
  return result.stdout;
}
const appGet = (dev, path) => JSON.parse(sh(dev, `curl -sS --max-time 20 http://127.0.0.1:18090${path}`));
const summary = dev => appGet(dev, '/api/summary');
const diff = (a, b) => Object.fromEntries(COMPARE.filter(k => JSON.stringify(a[k]) !== JSON.stringify(b[k])).map(k => [k, [a[k], b[k]]]));
function contentState(dev) {
  const notes = appGet(dev, '/api/notes').notes.map(n => [n.id, n.title, n.body, n.signature]).sort((x, y) => x[0] - y[0]);
  const files = appGet(dev, '/api/files').files.map(f => [f.name, f.size, f.sha256]).sort();
  return JSON.stringify({ notes, files });
}
function postNote(dev, title, body) {
  const out = sh(dev, 'curl -sS --max-time 20 -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" --data-binary @- http://127.0.0.1:18090/api/notes',
    JSON.stringify({ title, body }));
  return Number(out.trim());
}
function postFile(dev, name, data) {
  const out = sh(dev, `curl -sS --max-time 30 -X POST -H "Content-Type: application/octet-stream" --data-binary @- "http://127.0.0.1:18090/api/files?name=${name}"`, data);
  return JSON.parse(out);
}
function kitSecret() {
  const found = readFileSync(join(LAB, 'secrets', 'dev-a-kit.txt'), 'utf8').match(SECRET_RE) || [];
  if (found.length !== 1) throw new Abort('kit file must hold exactly one key');
  return found[0];
}
async function sha256File(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}
const TEARDOWN = `set -u; cd "$HOME"
systemctl --user stop woowbk-demo-app.service woowbk-demo-db.service woowbk-demo-network.service 2>/dev/null
rm -f .config/containers/systemd/woowbk-demo.network .config/containers/systemd/woowbk-demo-db.container .config/containers/systemd/woowbk-demo-app.container
systemctl --user daemon-reload; systemctl --user reset-failed 2>/dev/null
podman volume rm -f woowbk-demo-files woowbk-demo-pgdata >/dev/null
podman secret rm woowbk-demo-db-password woowbk-demo-app-key >/dev/null 2>&1
rm -f .config/woowbk-demo/app.env; podman network rm -f woowbk-demo >/dev/null 2>&1
podman rmi -f localhost/woowbk-demo-app:1 docker.io/library/postgres:16-alpine >/dev/null 2>&1; true`;

// ------------------------------------------------------------------ browser side

async function login(browser, dev, { admin }) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1440, height: 900 },
    acceptDownloads: true });
  const page = await context.newPage();
  const base = `https://127.0.0.1:${DEV[dev].port}`;
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').waitFor({ timeout: 30000 });
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(PASSWORD);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 45000 });
  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access)$/ });
  await indicator.waitFor({ timeout: 30000 });
  if (admin && /Limited/.test(await indicator.textContent())) await switchToAdmin(page);
  return { context, page, base };
}
async function switchToAdmin(page) {
  await page.getByRole('button', { name: /^Limited access$/ }).click();
  await page.locator('#switch-to-admin-access-password').waitFor({ timeout: 30000 });
  await page.locator('#switch-to-admin-access-password').fill(PASSWORD);
  await page.getByRole('button', { name: /^Authenticate$/ }).click();
  await page.locator('#switch-to-admin-access-password').waitFor({ state: 'detached', timeout: 30000 });
  await page.getByRole('button', { name: /^Administrative access$/ }).waitFor({ timeout: 30000 });
}
async function openBackupPage(page, base, hash = '') {
  await page.goto(`${base}/woowtechbackup${hash}`, { waitUntil: 'domcontentloaded' });
  const iframe = page.locator('iframe[src*="woowtechbackup"]');
  await iframe.waitFor({ state: 'attached', timeout: 30000 });
  const frame = await (await iframe.elementHandle()).contentFrame();
  await frame.waitForURL('**/woowtechbackup/**', { timeout: 30000 });
  await frame.locator('#view').waitFor({ timeout: 30000 });
  return frame;
}
async function shot(page, name) { await page.screenshot({ path: join(EVIDENCE, name), fullPage: false }); }
const frameHash = frame => frame.evaluate(() => window.location.hash);
async function waitHash(frame, re, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const hash = await frameHash(frame);
    if (re.test(hash)) return hash;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error(`hash did not match ${re}: ${await frameHash(frame)}`);
}
async function resultRows(frame) {
  return frame.locator('.compare tbody tr').evaluateAll(rows => rows.map(row => [...row.children].map(cell => cell.textContent.trim())));
}

// ------------------------------------------------------------------ scenarios

async function scenarioAdmin(browser) {
  const { context, page, base } = await login(browser, 'a', { admin: false });
  try {
    const frame = await openBackupPage(page, base);
    await frame.getByText('需要管理員權限').first().waitFor({ timeout: 30000 });
    await shot(page, 'ui-admin-required.png');
    check('F12 UI: limited access shows the admin-required state', true);
    check('F12 UI: no backup data rendered without admin access', (await frame.getByText('示範筆記應用').count()) === 0,
      'app list hidden');
    await switchToAdmin(page);
    await frame.getByText('示範筆記應用').first().waitFor({ timeout: 60000 });
    const text = await frame.locator('#view').textContent();
    check('after switching to administrative access the overview loads real engine data (app name, running state)',
      /示範筆記應用/.test(text) && /執行中/.test(text), text.slice(0, 200));
    await shot(page, 'ui-overview-dev-a.png');
  } finally {
    await context.close();
  }
}

async function scenarioS1(browser) {
  const dev = 'a';
  // Known data, then the snapshot the backup must reproduce.
  owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '2', '--files', '1');
  const snapshot = summary(dev);
  const content = contentState(dev);
  writeFileSync(join(EVIDENCE, 'ui-s1-snapshot.json'), JSON.stringify(snapshot, null, 1));
  log(`snapshot ${JSON.stringify(snapshot)}`);

  let { context, page, base } = await login(browser, dev, { admin: true });
  try {
    let frame = await openBackupPage(page, base);
    await frame.locator('#go-create').click();
    await frame.locator('[data-focus="create-app-woowbk-demo"]').waitFor({ timeout: 30000 });
    if (!(await frame.locator('[data-focus="create-app-woowbk-demo"]').isChecked())) await frame.locator('[data-focus="create-app-woowbk-demo"]').check();
    await frame.locator('#include-images').check();
    await frame.locator('#backup-note').fill('UI 整合測試（含映像）');
    const started = Date.now();
    await frame.locator('[data-focus="create-submit"]').click();
    const hash = await waitHash(frame, /^#\/jobs\/j\d{8}T\d{6}Z-[0-9a-f]{8}$/, 30000);
    const jobId = hash.split('/').pop();
    await frame.locator('.phase-active').first().waitFor({ timeout: 30000 });
    await shot(page, 'ui-s1-backup-running.png');
    check('UI create backup -> job page with an active phase', true, jobId);
    // F11: close the tab while the job runs; the job keeps going in systemd and the page resumes.
    await page.close();
    const runningAtClose = engine(dev, 'job-status', { job_id: jobId }).job.state;
    log(`closed the tab; job ${jobId} state ${runningAtClose}`);
    page = await context.newPage();
    frame = await openBackupPage(page, base);
    let resumed = false;
    try {
      await waitHash(frame, new RegExp(`^#/jobs/${jobId}$`), 30000);
      resumed = true;
    } catch { /* checked below */ }
    check('F11 reopened page resumes into the running job (status.active_job)', resumed || runningAtClose !== 'running',
      { runningAtClose, hash: await frameHash(frame) });
    if (!resumed) await frame.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, jobId);
    await frame.locator('#result-heading').filter({ hasText: '備份完成' }).waitFor({ timeout: 300000 });
    timings.ui_backup_with_images_s = Math.round((Date.now() - started) / 100) / 10;
    await shot(page, 'ui-s1-backup-done.png');
    const job = engine(dev, 'job-status', { job_id: jobId }).job;
    const backupId = job.result.backup_id;
    require_('UI backup job succeeded', job.state === 'succeeded', job.error);
    // Download through the real external channel (cockpit-ws /cockpit/channel/<csrf>?<fsread1 options>).
    const meta = engine(dev, 'list').backups.find(b => b.id === backupId);
    const dlStart = Date.now();
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 120000 }),
      frame.locator('[data-focus="result-download"]').click()]);
    mkdirSync(join(LAB, 'downloads'), { recursive: true, mode: 0o700 });
    const target = join(LAB, 'downloads', `ui-${download.suggestedFilename()}`);
    await download.saveAs(target);
    // saveAs copies with the default umask (0644 here); a downloaded backup stays private to the lab user.
    chmodSync(target, 0o600);
    timings.ui_download_s = Math.round((Date.now() - dlStart) / 100) / 10;
    const digest = await sha256File(target);
    check('UI download through cockpit-ws external fsread1 channel: filename, size and sha256 match the index',
      download.suggestedFilename() === meta.filename && statSync(target).size === meta.size && digest === meta.sha256,
      { filename: download.suggestedFilename(), size: statSync(target).size, seconds: timings.ui_download_s });
    check('the downloaded backup is private to the lab user (0600)', (statSync(target).mode & 0o777) === 0o600,
      (statSync(target).mode & 0o777).toString(8));
    const actionError = (await frame.locator('#action-error').textContent().catch(() => '')).trim();
    check('UI download is not reported as an error', actionError === '', actionError);

    // Mutate, then restore in place from the list.
    owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '1', '--files', '1', '--title', 'UI 測試後變更的標題');
    const mutated = summary(dev);
    check('mutation changed the app data', Object.keys(diff(mutated, snapshot)).length >= 3, diff(mutated, snapshot));
    await frame.evaluate(() => { window.location.hash = '#/backups'; });
    await frame.locator(`[data-focus="restore-${backupId}"]`).click({ timeout: 60000 });
    await frame.locator('[data-focus="pf-next"]').waitFor({ timeout: 120000 });
    const preflightText = await frame.locator('#view').textContent();
    check('UI preflight for the in-place restore names UID 1001 and the safety backup',
      /1001/.test(preflightText) && /還原前/.test(preflightText), preflightText.slice(0, 160));
    await shot(page, 'ui-s1-preflight.png');
    await frame.locator('[data-focus="pf-next"]').click();
    await frame.locator('#confirm-restore').waitFor({ timeout: 30000 });
    check('UI confirm step: start disabled until the checkbox is ticked',
      await frame.locator('[data-focus="confirm-start"]').isDisabled());
    await frame.locator('#confirm-restore').check();
    const restoreStart = Date.now();
    await frame.locator('[data-focus="confirm-start"]').click();
    const restoreHash = await waitHash(frame, /^#\/jobs\/j/, 30000);
    await frame.locator('#result-heading').filter({ hasText: /還原完成|還原失敗|作業/ }).waitFor({ timeout: 600000 });
    timings.ui_restore_inplace_s = Math.round((Date.now() - restoreStart) / 100) / 10;
    const heading = (await frame.locator('#result-heading').textContent()).trim();
    const rows = await resultRows(frame);
    await shot(page, 'ui-s1-restore-result.png');
    require_('UI in-place restore finished with 還原完成', heading === '還原完成', heading);
    check('UI result table: 資料一致 and summary.digest 相同',
      /資料一致/.test(rows[0]?.[0] || '') && rows.some(r => r[1] === 'summary.digest' && r[4] === '相同'), rows.slice(0, 3));
    const after = summary(dev);
    check('S1 via UI: /api/summary equals the backup-time snapshot', Object.keys(diff(after, snapshot)).length === 0, diff(after, snapshot));
    check('S1 via UI: full content equals the backup time', contentState(dev) === content);
    const restoreJob = engine(dev, 'job-status', { job_id: restoreHash.split('/').pop() }).job;
    const safetyId = restoreJob.result?.safety_backup_id;
    await frame.evaluate(() => { window.location.hash = '#/backups'; });
    await frame.locator(`[data-focus="restore-${safetyId}"]`).waitFor({ timeout: 60000 });
    check('S1 via UI: the safety backup is listed in the page', Boolean(safetyId), safetyId);
    await shot(page, 'ui-s1-backups-list.png');
    saveState({ s1: { backupId, snapshot, download: target, sha256: meta.sha256 } });
  } finally {
    await context.close();
  }
}

async function scenarioS2(browser) {
  const state = loadState().s1;
  if (!state) throw new Abort('run the ui s1 scenario first');
  const dev = 'b';
  // A device that never had the app: no deployment, no backups, no images.
  for (const backup of engine(dev, 'list').backups || []) engine(dev, 'delete', { backup_id: backup.id });
  owner(dev, 'sh', '-c', TEARDOWN);
  const before = engine(dev, 'status').apps.find(a => a.id === APP);
  require_('dev-b torn down: app not deployed, no images', before.state === 'not-deployed', before.state);
  const secret = kitSecret();
  const { context, page, base } = await login(browser, dev, { admin: true });
  try {
    const frame = await openBackupPage(page, base);
    await frame.locator('#go-restore').click();
    await frame.locator('#restore-file').setInputFiles(state.download);
    const upStart = Date.now();
    await frame.locator('[data-focus="restore-upload"]').click();
    await frame.locator('.stepper .step.active').filter({ hasText: '上傳' }).waitFor({ timeout: 30000 }).catch(() => {});
    await shot(page, 'ui-s2-upload-progress.png');
    await frame.locator('#key-text').waitFor({ timeout: 600000 });
    timings.ui_upload_s = Math.round((Date.now() - upStart) / 100) / 10;
    const uploaded = engine(dev, 'list').backups.find(b => b.id === state.backupId);
    check('S2 via UI: upload through the websocket fsreplace1 channel registered the backup (type uploaded, same sha256)',
      uploaded && uploaded.type === 'uploaded' && uploaded.sha256 === state.sha256, { seconds: timings.ui_upload_s });
    check('S2 via UI: the key step appears because the key is not on dev-b (key-required)',
      /金鑰/.test(await frame.locator('.stepper .step.active').textContent()));
    await frame.locator('#key-text').fill(secret);
    await frame.locator('[data-focus="key-submit"]').click();
    await frame.locator('.app-preflight').first().waitFor({ timeout: 120000 });
    check('the key text is cleared from the page after a successful inspect',
      !(await frame.locator('body').evaluate(body => /AGE-SECRET-KEY-1/i.test(body.innerText + [...document.querySelectorAll('input,textarea')].map(i => i.value).join(' ')))));
    const preflightText = await frame.locator('#view').textContent();
    check('S2 via UI preflight: fresh deployment with appowner UID 1007, app selectable',
      /1007/.test(preflightText) && await frame.locator('[data-focus="pf-select-woowbk-demo"]').isChecked(), preflightText.slice(0, 200));
    await shot(page, 'ui-s2-preflight.png');
    await frame.locator('[data-focus="pf-next"]').click();
    await frame.locator('#confirm-restore').check();
    const restoreStart = Date.now();
    await frame.locator('[data-focus="confirm-start"]').click();
    const hash = await waitHash(frame, /^#\/jobs\/j/, 30000);
    await frame.locator('#result-heading').filter({ hasText: /還原完成|還原失敗|作業/ }).waitFor({ timeout: 900000 });
    timings.ui_restore_fresh_s = Math.round((Date.now() - restoreStart) / 100) / 10;
    const heading = (await frame.locator('#result-heading').textContent()).trim();
    const rows = await resultRows(frame);
    await shot(page, 'ui-s2-restore-result.png');
    require_('S2 via UI: fresh restore finished with 還原完成', heading === '還原完成',
      { heading, job: engine(dev, 'job-status', { job_id: hash.split('/').pop() }).job.error });
    check('S2 via UI result table: 資料一致', /資料一致/.test(rows[0]?.[0] || ''), rows.slice(0, 2));
    const after = summary(dev);
    check('S2 via UI: /api/summary on dev-b equals the snapshot from dev-a', Object.keys(diff(after, state.snapshot)).length === 0,
      diff(after, state.snapshot));
    check('S2 via UI: POST /api/notes on dev-b -> 201', postNote(dev, 'UI 跨設備還原後新增', '可以寫入') === 201);
    const blob = randomBytes(2048);
    const file = postFile(dev, `ui-after-restore-${randomUUID().slice(0, 8)}.bin`, blob);
    check('S2 via UI: POST /api/files on dev-b stores the file', file.sha256 === createHash('sha256').update(blob).digest('hex'));
    const final = summary(dev);
    check('S2 via UI: new data counted and signatures valid', final.notes === state.snapshot.notes + 1 &&
      final.files === state.snapshot.files + 1 && final.signatures_valid === true, final);
    check('S2 via UI: no imported key and no job key left on dev-b',
      engine(dev, 'status').imported_keys.length === 0 && !/key-/.test(sh(dev, 'ls -A /run/woowtech-backup')));
  } finally {
    await context.close();
  }
}

// ------------------------------------------------------------------ main

const scenarios = { admin: scenarioAdmin, s1: scenarioS1, s2: scenarioS2 };
const wanted = process.argv[2] && process.argv[2] !== 'all' ? [process.argv[2]] : Object.keys(scenarios);
const browser = await chromium.launch({ executablePath });
let aborted = null;
try {
  for (const name of wanted) {
    if (!scenarios[name]) throw new Abort(`unknown scenario ${name}`);
    log(`== scenario ${name}`);
    await scenarios[name](browser);
  }
} catch (error) {
  aborted = scrub(error && error.message || error).split('\n')[0];
  log(`ABORTED: ${aborted}`);
} finally {
  await browser.close();
}
const passed = checks.filter(c => c.ok).length;
writeFileSync(join(EVIDENCE, 'result.json'), JSON.stringify({ checks, passed, total: checks.length, timings, aborted }, null, 1));
log(`RESULT ${passed}/${checks.length} checks passed${aborted ? ' (aborted)' : ''}; timings ${JSON.stringify(timings)}; evidence ${EVIDENCE}`);
process.exit(passed === checks.length && !aborted ? 0 : 1);
