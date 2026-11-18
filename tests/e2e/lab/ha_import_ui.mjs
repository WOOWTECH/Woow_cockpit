#!/usr/bin/env node
// Lab dev-c: ONE Home Assistant import through the REAL 備份與還原 page (Cockpit https://127.0.0.1:19093, administrative
// access) against the installed engine: 上傳備份檔 (an HA .tar; the same file uploaded again is its existing record) →
// the HA view → 檢查並匯入… → both apps → a WRONG key first (back to the key step with the engine's message) → the right
// key → the check job → the Odoo database (「這只是測試」 left unchecked) → the convert job → the restore wizard (HA
// banner, preflight, confirmation) → the restore job → the result with the HA reminders; then the chips in 備份列表 and
// the job titles in 活動紀錄. Screenshots at 1440 and 390 px; page script errors are recorded (there must be none).
//   node tests/e2e/lab/ha_import_ui.mjs [--fixture TAR] [--database NAME] [--creds FILE] [--evidence DIR]
//                                       [--verify] [--baseline ODOO_BACKUP_ID,N8N_BACKUP_ID]
// Right before the conversion `ha_import_e2e.py live` records the target's web.base.url and upgrade marker, so that
// --verify (`ha_import_e2e.py verify cleanup leaks`: the data checks from inside the device) compares with them;
// --baseline then puts dev-c back to its data from before any import (`ha_import_e2e.py baseline`).
// Secrets: the devadmin password (~/.woowbk-lab/secrets/devadmin.pass) and the HA key (HA_BACKUP_KEY in the creds file,
// default ~/.woowbk-lab/secrets/ha-import-creds.env) are never printed: every log line is scrubbed and no screenshot is taken
// while an input holds a key. Evidence: ~/.woowbk-lab/evidence/ha-import-ui/<time>/ (driver.log, results.json,
// page-errors.json, screenshots). Only ~/.woowbk-lab/bin/labpodman is used; nothing on the host itself is touched.
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const LAB = join(homedir(), '.woowbk-lab');
const LP = join(LAB, 'bin', 'labpodman');
const DEVICE = 'woowbk-dev-c';
const BASE = 'https://127.0.0.1:19093';
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const WRONG_KEY = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG';  // HA's key format, not this backup's key
const KEY_SOURCE = '[A-Z0-9]{4}(?:-[A-Z0-9]{4}){6}';
const DESKTOP = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844 };
const JOB_TIMEOUT = 30 * 60 * 1000;

function usage(message) {
  console.error(`${message}\nusage: ha_import_ui.mjs [--fixture TAR] [--database NAME] [--creds FILE] [--evidence DIR] `
    + '[--verify] [--baseline ODOO_BACKUP_ID,N8N_BACKUP_ID]');
  process.exit(2);
}

function options(argv) {
  const opts = {
    fixture: join(LAB, 'ha-fixtures', '20261118', 'woow-import-test-enc', 'woow-import-test-enc.tar'),
    database: 'woowtest', creds: join(LAB, 'secrets', 'ha-import-creds.env'), evidence: null, verify: false, baseline: null
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => (i + 1 < argv.length ? argv[++i] : usage(`${arg} needs a value`));
    if (arg === '--fixture') opts.fixture = value();
    else if (arg === '--database') opts.database = value();
    else if (arg === '--creds') opts.creds = value();
    else if (arg === '--evidence') opts.evidence = value();
    else if (arg === '--verify') opts.verify = true;
    else if (arg === '--baseline') opts.baseline = value();
    else usage(`unknown argument ${arg}`);
  }
  return opts;
}

const opts = options(process.argv.slice(2));
const PASSWORD = readFileSync(join(LAB, 'secrets', 'devadmin.pass'), 'utf8').trim();
const CREDS = Object.fromEntries(readFileSync(opts.creds, 'utf8').split('\n').map(line => line.trim())
  .filter(line => line && !line.startsWith('#') && line.includes('='))
  .map(line => [line.slice(0, line.indexOf('=')).trim(), line.slice(line.indexOf('=') + 1).trim().replace(/^["']|["']$/g, '')]));
const HA_KEY = CREDS.HA_BACKUP_KEY;
if (!HA_KEY) usage(`${opts.creds} has no HA_BACKUP_KEY`);
const SECRETS = [PASSWORD, ...Object.values(CREDS)].filter(Boolean).sort((a, b) => b.length - a.length);
const scrub = text => SECRETS.reduce((out, secret) => out.split(secret).join('<secret>'), String(text))
  .replace(new RegExp(KEY_SOURCE, 'g'), match => (match === WRONG_KEY ? match : '<HA-KEY>'));

const pad = n => String(n).padStart(2, '0');
const now = new Date();
const STAMP = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}T${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
const EVIDENCE = opts.evidence || join(LAB, 'evidence', 'ha-import-ui', STAMP);
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
const checks = [];
const run = { started: new Date().toISOString(), fixture: opts.fixture, database: opts.database, jobs: {}, timings: {} };

const show = detail => scrub(typeof detail === 'string' ? detail : JSON.stringify(detail));
function log(message) {
  const line = `${new Date().toTimeString().slice(0, 8)} ${scrub(message)}`;
  console.log(line);
  writeFileSync(join(EVIDENCE, 'driver.log'), `${line}\n`, { flag: 'a', mode: 0o600 });
}
function check(name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok), detail: show(detail).slice(0, 1000) });
  log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail === '' ? '' : ` -- ${show(detail).slice(0, 400)}`}`);
  return Boolean(ok);
}
function save(name, value) {
  writeFileSync(join(EVIDENCE, name), show(typeof value === 'string' ? value : JSON.stringify(value, null, 1)), { mode: 0o600 });
}

// Read-only cross-checks with the installed helper (as root in the device, like Cockpit); the flow itself is the page's.
function device(argv, input = '') {
  const result = spawnSync(LP, ['exec', '-i', DEVICE, ...argv], { input, maxBuffer: 64 * 1024 * 1024, timeout: 600000 });
  return { status: result.status, out: String(result.stdout || ''), err: String(result.stderr || '') };
}
function engine(command, request) {
  const result = device([HELPER, command], request === undefined ? '' : JSON.stringify(request));
  try {
    return JSON.parse(result.out.trim().split('\n').pop() || '{}');
  } catch {
    return { ok: false, error: { code: 'bad-output', message: result.err.slice(-300) } };
  }
}
function e2e(args, label) {
  log(`running ha_import_e2e.py ${args.join(' ')}`);
  const result = spawnSync('python3', ['-I', join(HERE, 'ha_import_e2e.py'), ...args, '--creds', opts.creds],
    { maxBuffer: 64 * 1024 * 1024, timeout: 3 * 3600 * 1000 });
  const out = String(result.stdout || '');
  save(`e2e-${label}.log`, out + String(result.stderr || ''));
  const summary = out.match(/RESULT (\d+)\/(\d+) passed; evidence (\S+)/);
  check(`ha_import_e2e.py ${args.join(' ')}`, result.status === 0, summary ? summary[0] : `exit ${result.status}, no RESULT line`);
  return { ok: result.status === 0, evidence: summary ? summary[3] : null };
}

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome');
const browser = await chromium.launch({ executablePath });
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: DESKTOP });
const page = await context.newPage();
page.setDefaultTimeout(30000);
let frame = null;
let stage = 'login';
let recording = false;
const pageErrors = [];
const consoleMessages = [];
page.on('pageerror', error => {
  if (recording) pageErrors.push({ stage, message: scrub(error.message), stack: scrub(String(error.stack || '').split('\n').slice(0, 5).join(' | ')) });
});
page.on('console', message => {
  if (!recording || !['error', 'warning'].includes(message.type())) return;
  consoleMessages.push({ stage, type: message.type(), text: scrub(message.text()).slice(0, 500), url: scrub(message.location()?.url || '') });
});

async function login() {
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(PASSWORD);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 60000 });
  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access|受限存取|受限制的存取|管理員存取模式|管理員存取)$/ });
  await indicator.waitFor();
  if (/Limited|受限/.test(await indicator.textContent())) {
    await indicator.click();
    await page.locator('#switch-to-admin-access-password').fill(PASSWORD);
    await page.getByRole('button', { name: /^(Authenticate|認證|驗證)$/ }).click();
    await page.locator('#switch-to-admin-access-password').waitFor({ state: 'detached' });
  }
  await page.getByRole('button', { name: /^(Administrative access|管理員存取模式|管理員存取)$/ }).waitFor();
  log('logged in to the dev-c Cockpit as devadmin with administrative access');
}

async function openPage(hash) {
  await page.goto(`${BASE}/woowtechbackup${hash}`, { waitUntil: 'domcontentloaded' });
  const iframe = page.locator('iframe[src*="woowtechbackup"]');
  await iframe.waitFor({ state: 'attached' });
  frame = await (await iframe.elementHandle()).contentFrame();
  await frame.locator('#view-heading').waitFor();
  await idle();
  // Cockpit's own shell throws at login and when its system page unloads: only errors while this page is open count.
  pageErrors.length = 0;
  consoleMessages.length = 0;
  recording = true;
}

const idle = () => frame.waitForFunction(() => document.querySelector('#view')?.getAttribute('aria-busy') === 'false', null, { timeout: 120000 });
const hash = () => frame.evaluate(() => window.location.hash);
const activeStep = () => frame.evaluate(() => document.querySelector('ol.stepper li.step.active')?.dataset.step || null);
const textOf = async locator => ((await locator.count()) ? (await locator.first().innerText()).trim() : '');
const texts = locator => locator.allInnerTexts().then(items => items.map(item => item.trim()));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(probe, { timeout = 120000, label, every = 20000 }) {
  const deadline = Date.now() + timeout;
  let last = Date.now();
  while (Date.now() < deadline) {
    const value = await probe().catch(() => null);
    if (value) return value;
    if (Date.now() - last >= every) {
      last = Date.now();
      const progress = await frame.evaluate(() => [...document.querySelectorAll('.progress-percent, .progress-message')]
        .map(node => node.textContent.trim()).filter(Boolean).join(' ')).catch(() => '');
      log(`  waiting for ${label}${progress ? `: ${progress}` : ''}`);
    }
    await sleep(1000);
  }
  throw new Error(`timed out after ${Math.round(timeout / 1000)} s waiting for ${label}`);
}

// An input holding the real key (anything in the key field but the wrong test key, or text in HA's key format) must
// never reach a screenshot.
const keyOnScreen = () => frame.evaluate(([wrong, source]) => [...document.querySelectorAll('input, textarea')]
  .some(node => node.value && node.value !== wrong && (node.id === 'ha-key' || new RegExp(source).test(node.value))), [WRONG_KEY, KEY_SOURCE])
  .catch(() => true);

let shots = 0;
async function shot(name, { phone = false } = {}) {
  if (await keyOnScreen()) {
    log(`screenshot ${name} skipped: an input holds a key`);
    return;
  }
  for (const [suffix, size] of phone ? [['', DESKTOP], ['-phone', PHONE]] : [['', DESKTOP]]) {
    try {
      await page.setViewportSize(size);
      await sleep(400);
      // The page scrolls inside Cockpit's iframe: a taller window shows all of it.
      const box = await page.locator('iframe[src*="woowtechbackup"]').boundingBox();
      const content = await frame.evaluate(() => document.documentElement.scrollHeight).catch(() => 0);
      if (box && content > box.height) {
        await page.setViewportSize({ width: size.width, height: Math.min(6000, Math.ceil(size.height - box.height + content)) });
        await sleep(400);
      }
      const file = `${pad(++shots)}-${name}${suffix}.png`;
      await page.screenshot({ path: join(EVIDENCE, file) });
    } catch (error) {
      log(`screenshot ${name}${suffix} failed: ${error.message.split('\n')[0]}`);
    }
  }
  await page.setViewportSize(DESKTOP);
  await sleep(300);
}

async function failure(name, error) {
  check(`${name}: ran to completion`, false, String(error?.message || error).split('\n')[0]);
  const alerts = await texts(frame.locator('[role="alert"]')).catch(() => []);
  if (alerts.length) log(`  alerts on the page: ${alerts.join(' | ')}`);
  if (await keyOnScreen()) await frame.locator('#ha-key').fill('').catch(() => {});
  await shot(`failure-${name}`, { phone: false });
}

const jobsNow = () => engine('jobs').jobs || [];
const jobsBefore = new Set(jobsNow().map(job => job.id));
const newJobs = () => jobsNow().filter(job => !jobsBefore.has(job.id));
const haBefore = (engine('list').ha_backups || []).map(ha => ha.id);
const uploadsBefore = device(['ls', '-A', '/var/lib/woowtech-backup/uploads']).out.split(/\s+/).filter(Boolean);
log(`evidence ${EVIDENCE}; ${jobsBefore.size} jobs and ${haBefore.length} HA backups on dev-c before this run`);

let haId = null;
let haName = '';
let backupId = null;
let restoreJob = null;
let restored = false;

// ---------------------------------------------------------------------------------------------- the import flow
async function flow() {
  stage = 'login';
  await login();
  await openPage('#/backups');

  // 上傳備份檔: the same HA file again; upload-finish answers the existing record and the page opens it.
  stage = 'upload';
  await frame.locator('[data-focus="list-upload"]').click();
  await frame.waitForFunction(() => window.location.hash === '#/restore');
  await frame.locator('#restore-file').setInputFiles(opts.fixture);
  await frame.locator('[data-focus="restore-upload"]:not([disabled])').waitFor();
  check('upload view: the chosen file is shown', (await textOf(frame.locator('.file-name'))) === opts.fixture.split('/').pop(),
    await textOf(frame.locator('.file-name')));
  await shot('upload-chosen');
  let started = Date.now();
  await frame.locator('[data-focus="restore-upload"]').click();
  const landed = await waitFor(async () => {
    const value = await hash();
    if (/^#\/ha\/ha-[0-9a-f]{20}$/.test(value)) return value;
    const alert = await textOf(frame.locator('.wizard-card [role="alert"]'));
    return alert ? `error: ${alert}` : null;
  }, { timeout: 600000, label: 'the HA view after the upload' });
  run.timings.upload_s = (Date.now() - started) / 1000;
  if (!check('upload: the page lands on the HA view #/ha/<id>', landed.startsWith('#/ha/'), `${landed} after ${run.timings.upload_s} s`)) {
    throw new Error(`the upload did not open the HA view: ${landed}`);
  }
  haId = landed.slice('#/ha/'.length);
  const haAfter = engine('list').ha_backups || [];
  check('upload: the identical file is the existing HA backup (no new record)', haBefore.includes(haId) && haAfter.length === haBefore.length,
    { haId, before: haBefore.length, after: haAfter.length });
  const uploads = device(['ls', '-A', '/var/lib/woowtech-backup/uploads']).out.split(/\s+/).filter(Boolean);
  check('upload: no upload data left, only the records of finished uploads (*.done)', uploads.every(name => name.endsWith('.done'))
    && uploads.length === uploadsBefore.length + 1, { before: uploadsBefore.length, after: uploads.length,
    other: uploads.filter(name => !name.endsWith('.done')) });
  haName = haAfter.find(ha => ha.id === haId)?.name || '';

  // The HA view: facts, chips, add-ons and 檢查並匯入….
  stage = 'ha-view';
  await frame.locator('#ha-info').waitFor();
  await idle();
  const heading = await textOf(frame.locator('#view-heading'));
  const chips = await texts(frame.locator('.card-head:has(#ha-info) .chip'));
  check('HA view: the heading is the HA backup\'s name, chips 「HA 備份」 and 「已加密」', heading === haName && chips.includes('HA 備份')
    && chips.includes('已加密'), { heading, chips });
  const addons = await texts(frame.locator('.ha-addons-table tbody tr'));
  check('HA view: both add-ons can be imported into this device\'s Odoo and n8n', addons.length === 2
    && addons.every(row => row.includes('可以匯入')) && addons.some(row => row.includes('Odoo')) && addons.some(row => row.includes('n8n')), addons);
  const importButton = frame.locator(`[data-focus="ha-import-${haId}"]`);
  check('HA view: 「檢查並匯入…」 is enabled', (await importButton.count()) === 1 && await importButton.isEnabled());
  await shot('ha-view', { phone: true });

  // 選擇應用.
  stage = 'wizard-apps';
  await importButton.click();
  await frame.locator('#ha-app-odoo').waitFor();
  const steps = await frame.evaluate(() => [...document.querySelectorAll('ol.stepper li.step')].map(node => node.dataset.step));
  check('wizard: steps apps, key, check, options, convert, restore', steps.join(',') === 'apps,key,check,options,convert,restore', steps);
  check('apps step: Odoo and n8n are ticked', await frame.locator('#ha-app-odoo').isChecked() && await frame.locator('#ha-app-n8n').isChecked());
  check('apps step: the next button leads to the key', (await textOf(frame.locator('[data-focus="ha-apps-next"]'))) === '下一步：金鑰');
  await shot('wizard-apps', { phone: true });
  await frame.locator('[data-focus="ha-apps-next"]').click();
  await frame.locator('#ha-key').waitFor();
  check('key step: shown for the encrypted HA backup', (await activeStep()) === 'key');
  await shot('wizard-key', { phone: true });

  // A wrong key first: the engine refuses it and the page stays on the key step with its message.
  stage = 'wizard-wrong-key';
  const jobsBeforeKey = newJobs().length;
  await frame.locator('#ha-key').fill(WRONG_KEY);
  await frame.locator('[data-focus="ha-key-next"]').click();
  const wrong = await waitFor(async () => {
    const alert = await textOf(frame.locator('.wizard-card [role="alert"]'));
    const busy = await frame.locator('[data-focus="ha-key-next"]').isDisabled().catch(() => true);
    return alert && !busy ? { alert, step: await activeStep() } : null;
  }, { timeout: 300000, label: 'the wrong-key message' });
  check('wrong key: back on the key step with the engine\'s message', wrong.step === 'key' && /金鑰不正確/.test(wrong.alert), wrong);
  const jobsAfterKey = newJobs();
  const wrongJobs = jobsAfterKey.slice(0, jobsAfterKey.length - jobsBeforeKey);
  log(`  wrong key: ${wrongJobs.length ? `job(s) ${wrongJobs.map(job => `${job.id} ${job.state} ${job.error?.code}`).join(', ')}` : 'refused before any job started'}`);
  await shot('wizard-wrong-key', { phone: true });

  // The right key: the check job starts and the key field is gone.
  stage = 'wizard-check';
  await frame.locator('#ha-key').fill(HA_KEY);
  started = Date.now();
  await frame.locator('[data-focus="ha-key-next"]').click();
  const afterKey = await waitFor(async () => {
    const step = await activeStep();
    if (step === 'check' || step === 'options') return step;
    const alert = await textOf(frame.locator('.wizard-card [role="alert"]'));
    const busy = await frame.locator('[data-focus="ha-key-next"]').isDisabled().catch(() => true);
    return step === 'key' && alert && !busy ? `key step: ${alert}` : null;
  }, { timeout: 300000, label: 'the check job to start' });
  if (!check('right key: the check job starts (the key field is gone)', ['check', 'options'].includes(afterKey)
    && (await frame.locator('#ha-key').count()) === 0, afterKey)) throw new Error(`the right key was not accepted: ${afterKey}`);
  if (afterKey === 'check') await shot('wizard-check', { phone: false });
  const checked = await waitFor(async () => {
    const step = await activeStep();
    if (step !== 'check') return step;
    return (await frame.locator('[data-focus="ha-job-retry"]').count()) ? 'failed' : null;
  }, { timeout: JOB_TIMEOUT, label: 'the check job' });
  run.timings.check_s = (Date.now() - started) / 1000;
  const checkJob = newJobs().find(job => job.type === 'verify' && job.params?.source === 'ha');
  run.jobs.check = checkJob?.id || null;
  if (!check('check job: succeeded and the page shows the results', checked === 'options' && checkJob?.state === 'succeeded',
    `${checked}; job ${checkJob?.id} ${checkJob?.state} in ${run.timings.check_s} s`)) throw new Error(`the check did not finish: ${checked}`);

  // 結果與選項: both apps can move, the database is chosen here, 「這只是測試」 stays unticked.
  stage = 'wizard-options';
  await frame.locator('[data-focus="ha-convert"]').waitFor();
  for (const app of ['odoo', 'n8n']) {
    const card = await texts(frame.locator(`[data-ha-app="${app}"] .app-preflight-head .chip`));
    check(`options: ${app} can be imported`, card.includes('可以匯入'), card);
  }
  const databases = await frame.locator('.ha-database').evaluateAll(nodes => nodes.map(node => ({
    name: node.dataset.database, enabled: !node.querySelector('input').disabled, text: node.innerText.replace(/\s+/g, ' ').slice(0, 300) })));
  check('options: woowtest and woowtest2 offered, woowtest with the custom module woow_import_probe', databases.length === 2
    && databases.every(db => db.enabled) && databases.some(db => db.name === 'woowtest' && db.text.includes('woow_import_probe'))
    && databases.some(db => db.name === 'woowtest2'), databases);
  const n8nText = (await textOf(frame.locator('[data-ha-app="n8n"]'))).replace(/\s+/g, ' ');
  check('options: n8n owner, 3 workflows (1 active), 1 credential and the workflow to fix', n8nText.includes('管理者帳號 ha-probe@probe.invalid')
    && n8nText.includes('工作流程 3 個（啟用中 1 個）') && n8nText.includes('憑證 1 個') && n8nText.includes('WOOW 匯入測試 - 需修正'),
  n8nText.slice(0, 600));
  check('options: 「這只是測試」 is unticked by default', !(await frame.locator('#ha-test-mode').isChecked()));
  check('options: converting waits for a database (two to choose from)', await frame.locator('[data-focus="ha-convert"]').isDisabled());
  await frame.locator(`.ha-database[data-database="${opts.database}"] input[type="radio"]`).check();
  check(`options: ${opts.database} chosen, converting enabled`, await frame.locator('[data-focus="ha-convert"]').isEnabled());
  await shot('wizard-options', { phone: true });

  // The target's facts right before the conversion, for `verify`.
  e2e(['live'], 'live');

  // 轉換: confirmation, then the job; on success the page hands over to the restore wizard.
  stage = 'wizard-convert';
  await frame.locator('[data-focus="ha-convert"]').click();
  await frame.locator('#confirm-dialog[open]').waitFor();
  const dialog = (await textOf(frame.locator('#confirm-dialog'))).replace(/\s+/g, ' ');
  check('convert confirmation: names the apps, the database and 「這只是測試」 否', dialog.includes('開始轉換 HA 備份？')
    && dialog.includes(opts.database) && /這只是測試 否/.test(dialog) && dialog.includes('Odoo') && dialog.includes('n8n'), dialog.slice(0, 500));
  await shot('convert-confirm');
  started = Date.now();
  await frame.locator('#confirm-ok').click();
  await waitFor(async () => (await activeStep()) === 'convert' || (await hash()).startsWith('#/restore/'), { timeout: 120000, label: 'the convert job to start' });
  if ((await activeStep()) === 'convert') await shot('wizard-convert', { phone: true });
  const converted = await waitFor(async () => {
    const value = await hash();
    if (value.startsWith('#/restore/')) return value;
    return (await frame.locator('[data-focus="ha-job-retry"]').count()) ? 'failed' : null;
  }, { timeout: JOB_TIMEOUT, label: 'the convert job' });
  run.timings.convert_s = (Date.now() - started) / 1000;
  const convertJob = newJobs().find(job => job.type === 'backup' && job.params?.source === 'ha');
  run.jobs.convert = convertJob?.id || null;
  backupId = convertJob?.result?.backup_id || null;
  if (!check('convert job: succeeded and the page opens the restore wizard of its backup', converted === `#/restore/${backupId}`
    && convertJob?.state === 'succeeded', `${converted}; job ${convertJob?.id} ${convertJob?.state} ${backupId} in ${run.timings.convert_s} s`)) {
    throw new Error(`the conversion did not hand over: ${converted}`);
  }
  run.backup = backupId;
  check('convert job: params source ha, odoo_database, test_mode false, the key only as key_provided', convertJob.params?.odoo_database === opts.database
    && convertJob.params?.test_mode === false && convertJob.params?.key_provided === true && !('key' in (convertJob.params || {})),
  convertJob.params);

  // The restore wizard at its preflight, with the HA banner.
  stage = 'restore-preflight';
  await waitFor(async () => (await frame.locator('[data-focus="pf-next"]').count()) || (await frame.locator('[data-focus="inspect-retry"]').count()),
    { timeout: 600000, label: 'the preflight of the converted backup' });
  const banner = (await textOf(frame.locator('.ha-banner'))).replace(/\s+/g, ' ');
  check('restore wizard: the HA banner names the HA backup and says to stop the HA add-ons afterwards', banner.includes('從 Home Assistant 匯入')
    && banner.includes(haName) && banner.includes('附加元件停掉'), banner.slice(0, 500));
  const source = await textOf(frame.locator('ol.stepper li[data-step="source"] .step-label'));
  check('restore wizard: its first step reads 「從 HA 轉換」, now at 預檢', source === '從 HA 轉換' && (await activeStep()) === 'preflight',
    { source, step: await activeStep() });
  const selected = { odoo: await frame.locator('[data-focus="pf-select-odoo"]').isChecked(), n8n: await frame.locator('[data-focus="pf-select-n8n"]').isChecked() };
  const blocked = await frame.locator('.app-preflight.is-blocked').count();
  const failedChecks = await texts(frame.locator('.wizard-card li.check-fail'));
  check('preflight: Odoo and n8n can be restored and are selected, no check fails', selected.odoo && selected.n8n && blocked === 0
    && !failedChecks.length && await frame.locator('[data-focus="pf-next"]').isEnabled(), { selected, blocked, failedChecks });
  await shot('restore-preflight', { phone: true });

  stage = 'restore-confirm';
  await frame.locator('[data-focus="pf-next"]').click();
  await frame.locator('#confirm-restore').waitFor();
  const affected = await texts(frame.locator('ul.affected li'));
  check('confirm: both apps are restored in place', affected.length === 2 && affected.every(item => item.includes('原位還原')), affected);
  check('confirm: 「開始還原」 waits for the acknowledgement', await frame.locator('[data-focus="confirm-start"]').isDisabled());
  await frame.locator('#confirm-restore').check();
  check('confirm: acknowledged, 「開始還原」 enabled', await frame.locator('[data-focus="confirm-start"]').isEnabled());
  await shot('restore-confirm', { phone: true });

  stage = 'restore-job';
  started = Date.now();
  await frame.locator('[data-focus="confirm-start"]').click();
  const jobHash = await waitFor(async () => {
    const value = await hash();
    return /^#\/jobs\/j[0-9TZ]+-[0-9a-f]{8}$/.test(value) ? value : null;
  }, { timeout: 120000, label: 'the restore job page' });
  restoreJob = jobHash.slice('#/jobs/'.length);
  run.jobs.restore = restoreJob;
  restored = true;
  await shot('restore-progress');
  await frame.locator('#result-heading').waitFor({ timeout: JOB_TIMEOUT });
  run.timings.restore_s = (Date.now() - started) / 1000;
  const status = engine('job-status', { job_id: restoreJob });
  save('job-restore.json', status);
  const title = await textOf(frame.locator('#result-heading'));
  if (!check('restore job: 「還原完成」', title === '還原完成' && status.job?.state === 'succeeded',
    `${title}; ${status.job?.state} in ${run.timings.restore_s} s; safety ${status.job?.result?.safety_backup_id}`)) {
    await shot('restore-result', { phone: true });
    throw new Error(`the restore did not succeed: ${title}`);
  }
  run.safety = status.job.result?.safety_backup_id || null;
  const reminders = await texts(frame.locator('.ha-reminders li'));
  check('result: the HA reminders say to stop both HA add-ons', reminders.some(line => line.includes('「Woow Odoo 18」附加元件停掉'))
    && reminders.some(line => line.includes('「Woow n8n」附加元件停掉')), reminders);
  const engineReminders = convertJob.result?.ha_import?.reminders || [];
  check('result: the engine\'s own reminders are listed too', engineReminders.every(line => reminders.includes(line)),
    { engine: engineReminders.length, shown: reminders.length });
  const workflows = await textOf(frame.locator('.job-result'));
  check('result: the n8n workflow to fix is listed', workflows.includes('WOOW 匯入測試 - 需修正'));
  const health = (status.job?.result?.health || []).map(item => `${item.id}:${item.status}`);
  check('result: every health check ok', health.length >= 4 && health.every(item => item.endsWith(':ok')), health);
  await shot('restore-result', { phone: true });
}

// ---------------------------------------------------------------------------------------------- 備份列表, 活動紀錄
async function listAndActivity() {
  stage = 'list';
  await frame.locator('[data-nav="backups"]').click();
  await frame.locator('.backups-table').waitFor({ timeout: 120000 });
  await idle();
  const rowChips = async selector => texts(frame.locator(`${selector} .chip`));
  for (const id of haBefore) {
    const chips = await rowChips(`tr[data-ha="${id}"]`);
    check(`備份列表: ${id} has the chip 「HA 備份」`, chips.includes('HA 備份'), chips);
  }
  if (backupId) {
    const chips = await rowChips(`tr[data-backup="${backupId}"]`);
    const note = await textOf(frame.locator(`tr[data-backup="${backupId}"] .note`));
    check('備份列表: the converted backup has the chip 「由 HA 轉換」 and the HA note', chips.includes('由 HA 轉換')
      && note.startsWith('由 HA 備份轉換：') && note.includes(haName), { chips, note });
  }
  if (run.safety) {
    const chips = await rowChips(`tr[data-backup="${run.safety}"]`);
    check('備份列表: the pre-restore backup of this import is listed', chips.length > 0 && !chips.includes('由 HA 轉換'), chips);
  }
  await frame.locator('[data-focus="filter-ha"]').click();
  const shown = await frame.locator('#backup-results tbody tr').evaluateAll(rows => rows.map(row => row.dataset.ha || row.dataset.backup));
  check('備份列表 「HA 備份」 filter: the HA uploads and the converted backups only', haBefore.every(id => shown.includes(id))
    && (!backupId || shown.includes(backupId)) && !shown.includes(run.safety), shown);
  await shot('list-ha-filter', { phone: true });
  await frame.locator('[data-focus="filter-all"]').click();

  stage = 'activity';
  await frame.locator('[data-nav="activity"]').click();
  await frame.locator('.jobs-table').waitFor({ timeout: 120000 });
  await idle();
  const column = async id => textOf(frame.locator(`tr[data-job="${id}"] td[data-label="作業"]`));
  const summary = async id => textOf(frame.locator(`tr[data-job="${id}"] td[data-label="內容"]`));
  if (run.jobs.check) {
    check('活動紀錄: the check is 「檢查 HA 備份」 and names the HA backup', (await column(run.jobs.check)) === '檢查 HA 備份'
      && (await summary(run.jobs.check)).includes(`HA 備份「${haName}」`), { title: await column(run.jobs.check), summary: await summary(run.jobs.check) });
  }
  if (run.jobs.convert) {
    check('活動紀錄: the conversion is 「轉換 HA 備份」 and names the HA backup', (await column(run.jobs.convert)) === '轉換 HA 備份'
      && (await summary(run.jobs.convert)).includes(`HA 備份「${haName}」`), { title: await column(run.jobs.convert), summary: await summary(run.jobs.convert) });
  }
  if (run.jobs.restore) check('活動紀錄: the restore is 「還原」', (await column(run.jobs.restore)) === '還原', await column(run.jobs.restore));
  await shot('activity');
  if (run.jobs.convert) {
    stage = 'convert-result';
    await frame.locator(`[data-focus="job-${run.jobs.convert}"]`).click();
    await frame.locator('#result-heading').waitFor({ timeout: 60000 });
    const body = (await textOf(frame.locator('.job-view'))).replace(/\s+/g, ' ');
    check('convert job page: 「HA 備份已轉換」 with the HA backup, 這只是測試 否 and the key not kept',
      (await textOf(frame.locator('#result-heading'))) === 'HA 備份已轉換' && body.includes(haName) && body.includes('這只是測試 否')
      && body.includes('作業結束後即刪除'), body.slice(0, 600));
    await shot('convert-job-result');
  }
}

let flowError = null;
try {
  await flow();
} catch (error) {
  flowError = error;
  await failure(stage, error);
}
try {
  if (frame) await listAndActivity();
} catch (error) {
  await failure(stage, error);
}
stage = 'done';
recording = false;
save('page-errors.json', { pageErrors, consoleMessages });
check('no page script errors while the page was open', pageErrors.length === 0, pageErrors.slice(0, 3));
if (consoleMessages.length) log(`console errors/warnings (see page-errors.json): ${consoleMessages.length}`);
await browser.close();

if (opts.verify && restored && !flowError) {
  const result = e2e(['verify', 'cleanup', 'leaks'], 'verify');
  run.verify = result.evidence;
} else if (opts.verify) {
  log('verify skipped: the import did not finish through the page');
}
if (opts.baseline && restored) {
  const result = e2e(['baseline', 'cleanup', '--baseline', opts.baseline], 'baseline');
  run.baseline = result.evidence;
} else if (opts.baseline) {
  log('baseline skipped: no restore ran, the apps still hold their own data');
}

// The evidence itself: no secret in any text file this run wrote.
const leaked = readdirSync(EVIDENCE).filter(name => /\.(log|json|txt)$/.test(name))
  .filter(name => SECRETS.some(secret => readFileSync(join(EVIDENCE, name), 'utf8').includes(secret)));
check('no secret in the evidence files', leaked.length === 0, leaked);
const failed = checks.filter(item => !item.ok);
save('results.json', { ...run, finished: new Date().toISOString(), passed: checks.length - failed.length, failed: failed.length, checks });
log(`RESULT ${checks.length - failed.length}/${checks.length} passed; evidence ${EVIDENCE}`);
process.exit(failed.length ? 1 : 0);
