#!/usr/bin/env node
// Lab: the strengthened 備份與還原 page against the REAL engine through the real Cockpit 362 (integrator).
//   node tests/e2e/lab/strengthen_ui.mjs <part...>
// Parts (run in this order; each part records its own checks):
//   catalog   dev-a 應用設定: scan appowner, JSON validation feedback in the editor, preview and install the drafts of
//             woowbk-demo and woowbk-dirs (installed entries + generated digest checks)
//   cleanup   dev-a 清理備份: keep-last policy for woowbk-demo, preview, delete the candidates, policy back to default
//   backups   dev-a: 預設加密備份 off/on, unencrypted and encrypted backups from the create view, the encrypted .tar
//             downloaded through the page opened with plain tar (backup.json, README decrypt with the kit), the
//             unencrypted copy, the deep verify, an in-place restore with the data-check table
//   devb      dev-b (no device key): an unencrypted backup from the create view, then (setting off) the unencrypted
//             .tar from dev-a uploaded through the page: unauthenticated warning and the extra acknowledgement
// The devadmin password is read from ~/.woowbk-lab/secrets and never printed; screenshots are only taken after the
// login fields are gone. Plaintext downloads stay in a 0700 directory and are deleted at the end. Evidence:
// ~/.woowbk-lab/evidence/strengthen/<time>-ui-<parts>/.
import { chromium } from 'playwright-core';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const LAB = join(homedir(), '.woowbk-lab');
const LP = join(LAB, 'bin', 'labpodman');
const DEVICES = { a: { name: 'woowbk-dev-a', base: 'https://127.0.0.1:19091' }, b: { name: 'woowbk-dev-b', base: 'https://127.0.0.1:19092' } };
const PASSWORD = readFileSync(join(LAB, 'secrets', 'devadmin.pass'), 'utf8').trim();
const KIT = join(LAB, 'secrets', 'dev-a-kit.txt');
const parts = process.argv.slice(2);
const KNOWN = ['catalog', 'cleanup', 'backups', 'devb', 'cleanup-lab'];
if (!parts.length || parts.some(part => !KNOWN.includes(part))) {
  console.error(`usage: strengthen_ui.mjs <${KNOWN.join('|')}>...`);
  process.exit(2);
}
const pad = n => String(n).padStart(2, '0');
const now = new Date();
const EVIDENCE = join(LAB, 'evidence', 'strengthen', `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}T${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}-ui-${parts.join('-')}`);
const PRIVATE = join(LAB, 'run', 'strengthen-ui');
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
mkdirSync(PRIVATE, { recursive: true, mode: 0o700 });
const STATE = join(LAB, 'evidence', 'strengthen', 'ui-state.json');
const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : { created: [] };
const saveState = () => writeFileSync(STATE, JSON.stringify(state, null, 1));
const checks = [];
const scrub = text => String(text).split(PASSWORD).join('[password]').replace(/AGE-SECRET-KEY-1[0-9A-Za-z]+/g, '[secret]');
const log = message => {
  const line = `${new Date().toISOString().slice(11, 19)} ${scrub(message)}`;
  console.log(line);
  writeFileSync(join(EVIDENCE, 'driver.log'), `${line}\n`, { flag: 'a' });
};
const show = detail => scrub(typeof detail === 'string' ? detail : JSON.stringify(detail));
const check = (name, ok, detail = '') => {
  checks.push({ name, ok: Boolean(ok), detail: show(detail).slice(0, 600) });
  log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` -- ${show(detail).slice(0, 300)}` : ''}`);
  return Boolean(ok);
};
function engine(dev, command, request) {
  const result = spawnSync(LP, ['exec', '-i', DEVICES[dev].name, '/usr/local/libexec/woowtech-cockpit-backup', command],
    { input: request === undefined ? '' : JSON.stringify(request), maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(String(result.stdout).trim().split('\n').pop() || '{}');
}
function onDevice(dev, script) {
  const result = spawnSync(LP, ['exec', '-i', DEVICES[dev].name, 'sh', '-c', script], { maxBuffer: 16 * 1024 * 1024 });
  return { status: result.status, out: String(result.stdout), err: String(result.stderr) };
}
function host(command, args, options = {}) {
  const result = spawnSync(command, args, { maxBuffer: 64 * 1024 * 1024, ...options });
  return { status: result.status, out: String(result.stdout), err: String(result.stderr) };
}
const remember = (dev, id) => { if (id && !state.created.some(([d, b]) => d === dev && b === id)) { state.created.push([dev, id]); saveState(); } };
const catalogEntry = (dev, id) => JSON.parse(onDevice(dev, `cat /etc/woowtech-cockpit/backup/apps/${id}.json`).out || 'null');

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome');
const browser = await chromium.launch({ executablePath });
const errors = [];
let page;
let frame;
let current;
const shot = name => page.screenshot({ path: join(EVIDENCE, name) }).catch(() => {});

async function login(dev) {
  if (page) await page.context().close();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  page = await context.newPage();
  page.setDefaultTimeout(30000);
  page.on('pageerror', error => errors.push(`${dev}: ${error.message}`));
  current = dev;
  await page.goto(DEVICES[dev].base, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(PASSWORD);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 60000 });
  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access|受限存取|管理員存取模式|管理員存取)$/ });
  await indicator.waitFor();
  if (/Limited|受限/.test(await indicator.textContent())) {
    await indicator.click();
    await page.locator('#switch-to-admin-access-password').fill(PASSWORD);
    await page.getByRole('button', { name: /^(Authenticate|認證|驗證)$/ }).click();
    await page.locator('#switch-to-admin-access-password').waitFor({ state: 'detached' });
  }
  log(`dev-${dev}: logged in with administrative access`);
}
async function openPage(hash = '') {
  await page.goto(`${DEVICES[current].base}/woowtechbackup${hash}`, { waitUntil: 'domcontentloaded' });
  const iframe = page.locator('iframe[src*="woowtechbackup"]');
  await iframe.waitFor({ state: 'attached' });
  frame = await (await iframe.elementHandle()).contentFrame();
  await frame.locator('#view-heading').waitFor();
  await frame.waitForFunction(() => document.querySelector('#view')?.getAttribute('aria-busy') === 'false');
  // Cockpit's own shell throws at login and when its system page unloads: only errors while this page is open count.
  errors.length = 0;
}
async function waitText(locator, re, timeout = 300000) {
  const deadline = Date.now() + timeout;
  let text = '';
  while (Date.now() < deadline) {
    text = await locator.textContent().catch(() => '');
    if (re.test(text || '')) return text;
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`timed out waiting for ${re} (last: ${String(text).slice(0, 160)})`);
}
async function jobResult() {
  await frame.waitForFunction(() => /^#\/jobs\//.test(window.location.hash), null, { timeout: 60000 });
  await frame.locator('#result-heading').waitFor({ timeout: 900000 });
  return { title: await frame.locator('#result-heading').textContent(), text: await frame.locator('.job-result').textContent(),
    hash: await frame.evaluate(() => window.location.hash) };
}
async function confirmDialog({ ack = true } = {}) {
  await frame.locator('#confirm-dialog').waitFor();
  if (ack) {
    check('confirm button waits for the acknowledgement', await frame.locator('#confirm-ok').isDisabled());
    await frame.locator('#confirm-ack').check();
  }
  await frame.locator('#confirm-ok').click();
}
async function createBackup(app, { encrypt }) {
  await frame.locator('[data-nav="overview"]').click().catch(() => {});
  await frame.locator('#go-create').click();
  await frame.locator('#encrypt-backup').waitFor();
  for (const box of await frame.locator('[data-focus^="create-app-"]').all()) {
    const id = (await box.getAttribute('data-focus')).slice('create-app-'.length);
    if (await box.isEnabled() && (await box.isChecked()) !== (id === app)) await box.click();
  }
  if (!encrypt) {
    await frame.locator('#encrypt-backup').uncheck();
    if (await frame.locator('#ack-plaintext').count()) await frame.locator('#ack-plaintext').check();
  }
  await frame.locator('[data-focus="create-submit"]').click();
  const result = await jobResult();
  const id = (result.text.match(/\d{8}T\d{6}Z-[0-9a-f]{8}/) || [])[0];
  remember(current, id);
  return { ...result, id };
}
async function section(name, body) {
  try {
    await body();
  } catch (error) {
    check(`${name}: ran to completion`, false, error.message.split('\n')[0]);
    await shot(`99-${name}-failure.png`);
  }
}

// ---------------------------------------------------------------------------------------------- 應用設定 (dev-a)
async function partCatalog() {
  await login('a');
  await openPage('#/catalog');
  await section('catalog', async () => {
    await frame.locator('[data-focus="catalog-scan"]').waitFor();
    await frame.waitForFunction(() => !document.querySelector('[data-focus="catalog-scan"]')?.disabled, null, { timeout: 120000 });
    check('應用設定: the owner appowner is offered (catalog-suggest {})', await frame.locator('[data-focus="owner-appowner"]').count() === 1);
    await frame.locator('[data-focus="owner-appowner"]').check();
    await frame.locator('[data-focus="catalog-scan"]').click();
    await frame.locator('[data-focus="draft-open-woowbk-demo"]').waitFor({ timeout: 300000 });
    const drafts = await frame.locator('[data-focus^="draft-open-"]').evaluateAll(nodes => nodes.map(node => node.dataset.focus.slice('draft-open-'.length)));
    check('scan lists drafts for woowbk-demo and woowbk-dirs', drafts.includes('woowbk-demo') && drafts.includes('woowbk-dirs'), drafts);
    await shot('10-catalog-scan.png');
    for (const app of ['woowbk-demo', 'woowbk-dirs']) {
      const before = catalogEntry('a', app);
      await frame.locator(`[data-focus="draft-open-${app}"]`).click();
      const editor = frame.locator('#catalog-editor');
      await editor.waitFor();
      const feedback = frame.locator('#catalog-feedback');
      await waitText(feedback, /與目前安裝的設定比較（\d+ 項變更）/, 120000);
      const original = await editor.inputValue();
      if (app === 'woowbk-demo') {
        // JSON validation feedback in the browser, then the loader's own validation through the preview.
        await editor.fill(original.slice(0, original.lastIndexOf('}')));
        const parse = await waitText(frame.locator('#catalog-parse'), /JSON 格式錯誤：第 \d+ 行/, 20000);
        check('editor: a JSON syntax error is reported with line and column, never sent', /第 \d+ 行、第 \d+ 個字元/.test(parse), parse);
        await editor.fill(original.replace('"owner": "appowner"', '"owner": "root"'));
        const refused = await waitText(feedback, /欄位：owner/, 60000);
        check('editor: the engine preview refuses owner root and names the field', /root/.test(refused), refused.slice(0, 200));
        check('install stays disabled for an invalid entry', await frame.locator('[data-focus="catalog-install"]').isDisabled());
        await editor.fill(original);
        await waitText(feedback, /與目前安裝的設定比較（2 項變更）/, 60000);
      }
      const changes = await feedback.textContent();
      check(`${app}: the preview shows the two generated digest checks as additions`, /與目前安裝的設定比較（2 項變更）/.test(changes)
        && /postgres-digest/.test(changes) && /files-digest/.test(changes), changes.slice(0, 300));
      const install = frame.locator('[data-focus="catalog-install"]');
      await frame.waitForFunction(() => !document.querySelector('[data-focus="catalog-install"]')?.disabled, null, { timeout: 60000 });
      await shot(`11-catalog-${app}-preview.png`);
      await install.click();
      await confirmDialog();
      await waitText(frame.locator('#view'), new RegExp(`已取代「${app}」的應用設定`), 120000);
      const after = catalogEntry('a', app);
      const types = (after?.verify || []).map(item => item.type || 'http-json').sort();
      check(`${app}: installed from the page (http-json + postgres-digest + files-digest, rest unchanged)`,
        JSON.stringify(types) === JSON.stringify(['files-digest', 'http-json', 'postgres-digest'])
        && JSON.stringify({ ...after, verify: null }) === JSON.stringify({ ...before, verify: null }), types);
      const history = onDevice('a', `ls /etc/woowtech-cockpit/backup/apps-history/ | grep -c "^${app}\\." || true`).out.trim();
      check(`${app}: the replaced entry is kept in apps-history`, Number(history) >= 1, history);
      await shot(`12-catalog-${app}-installed.png`);
      await frame.locator('[data-nav="catalog"]').click();
      await frame.locator('[data-focus="catalog-scan"]').waitFor();
    }
    const journal = onDevice('a', 'journalctl -t woowtech-cockpit-backup --since "-15 min" --no-pager -o cat | grep "^catalog-install " || true').out.trim().split('\n');
    // loginuid: the Cockpit session's audit login uid; inside the rootless lab container pam_loginuid cannot set it,
    // so every process there reports 0 (a real host records the administrator's uid).
    check('journal: one catalog-install line per installed entry, with sha256, previous digest and loginuid',
      journal.filter(line => /^catalog-install id=woowbk-(demo|dirs) owner=appowner sha256=[0-9a-f]{64} previous=[0-9a-f]{64} loginuid=\d+$/.test(line)).length >= 2, journal.slice(-2));
    const status = engine('a', 'status');
    check('status: both apps still load, no catalog warnings', status.ok && status.warnings.length === 0
      && ['woowbk-demo', 'woowbk-dirs'].every(id => status.apps.some(app => app.id === id)), status.warnings);
  });
}

// ---------------------------------------------------------------------------------------------- 清理備份 (dev-a)
async function partCleanup() {
  await login('a');
  await openPage('#/cleanup');
  await section('cleanup', async () => {
    const mode = frame.locator('#keep-woowbk-demo-mode');
    await mode.waitFor({ timeout: 120000 });
    const before = (engine('a', 'list').backups || []).filter(item => item.type === 'manual' && (item.apps || []).some(app => app.id === 'woowbk-demo'));
    await mode.selectOption('last');
    const count = frame.locator('#keep-woowbk-demo-count');
    await count.waitFor();
    await count.fill('5');
    await count.dispatchEvent('change');
    check('a changed policy must be previewed before anything can be deleted', /請先按「預覽清理」/.test(await frame.locator('#cleanup-footer').textContent()));
    await frame.locator('[data-focus="cleanup-preview"]').click();
    const list = frame.locator('ul[aria-label="依保留原則刪除的備份"]');
    await list.waitFor({ timeout: 120000 });
    let picked = await list.locator('input[type="checkbox"]:checked').evaluateAll(nodes => nodes.map(node => node.id.replace(/^pick-/, '')));
    const plan = engine('a', 'retention-plan', { policy: { schema: 1, default_keep_last: null, apps: { 'woowbk-demo': { keep_last: 5 } } } });
    const expected = (plan.candidates || []).map(item => item.id);
    check('preview lists exactly the engine plan\'s candidates (all checked)', picked.length > 0
      && JSON.stringify([...picked].sort()) === JSON.stringify([...expected].sort()), { page: picked.length, engine: expected.length });
    check('the newest 5 manual backups of woowbk-demo are not candidates', before.length - picked.length === 5
      || before.length <= 5, { manual: before.length, candidates: picked.length });
    // The administrator keeps one candidate: the newest format 1 backup (the v1 restore proof needs one).
    const v1 = before.filter(item => item.format === 1 && picked.includes(item.id)).sort((x, y) => (x.created < y.created ? 1 : -1))[0];
    if (v1) {
      await frame.locator(`#pick-${v1.id}`).uncheck();
      picked = picked.filter(id => id !== v1.id);
      check('a candidate can be unticked before deleting (the newest .woowbackup is kept)', !(await frame.locator(`#pick-${v1.id}`).isChecked()), v1.id);
    }
    await shot('20-cleanup-preview.png');
    await frame.locator('[data-focus="cleanup-apply"]').click();
    await confirmDialog();
    const heading = await waitText(frame.locator('#cleanup-result'), /已刪除 \d+ 份備份/, 600000);
    const left = new Set((engine('a', 'list').backups || []).map(item => item.id));
    check('cleanup deleted exactly the checked candidates', heading.includes(`已刪除 ${picked.length} 份備份`)
      && picked.every(id => !left.has(id)) && (!v1 || left.has(v1.id)), heading);
    const saved = engine('a', 'retention-plan', {});
    check('policy saved: woowbk-demo keeps 5 manual backups (retention.json root 0644)', saved.saved_policy?.apps?.['woowbk-demo']?.keep_last === 5
      && onDevice('a', 'stat -c "%U %a" /etc/woowtech-cockpit/backup/retention.json').out.trim() === 'root 644', saved.saved_policy);
    const journal = onDevice('a', 'journalctl -t woowtech-cockpit-backup --since "-15 min" --no-pager -o cat | grep -c "^retention-delete " || true').out.trim();
    check('journal: one retention-delete line per deleted backup', Number(journal) >= picked.length, journal);
    await shot('21-cleanup-result.png');
    // Back to keeping everything: a policy-only save.
    await frame.locator('[data-focus="cleanup-result-close"]').click().catch(() => {});
    await mode.selectOption('inherit');
    await frame.locator('[data-focus="cleanup-preview"]').click();
    await frame.waitForFunction(() => !document.querySelector('[data-focus="cleanup-apply"]')?.disabled, null, { timeout: 120000 });
    await frame.locator('[data-focus="cleanup-apply"]').click();
    await confirmDialog({ ack: false });
    await waitText(frame.locator('#cleanup-result'), /已儲存保留原則/, 120000);
    const reset = engine('a', 'retention-plan', {});
    check('policy back to keep everything (policy-only save)', reset.saved_policy && Object.keys(reset.saved_policy.apps).length === 0
      && reset.saved_policy.default_keep_last === null, reset.saved_policy);
    const usage = await frame.locator('table').first().textContent().catch(() => '');
    check('清理備份 shows storage per app from the engine', /woowbk-demo|示範筆記應用/.test(usage));
  });
}

// ---------------------------------------------------------------------------------------------- backups (dev-a)
async function manualUnpack(file) {
  const dir = join(PRIVATE, `unpack-${Date.now()}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    const listing = host('tar', ['-tf', file]).out.trim().split('\n');
    host('tar', ['-xf', file, '-C', dir, 'backup.json', 'README.txt']);
    const doc = JSON.parse(readFileSync(join(dir, 'backup.json'), 'utf8'));
    const readme = readFileSync(join(dir, 'README.txt'), 'utf8');
    const raw = readFileSync(join(dir, 'backup.json'), 'utf8');
    const app = doc.apps[0];
    host('tar', ['-xf', file, '-C', dir, app.file]);
    const sha = host('sha256sum', [join(dir, app.file)]).out.split(' ')[0];
    // The README's own command for this app, with the emergency kit file as the identity.
    const command = readme.split('\n').map(line => line.trim()).find(line => line.startsWith('age -d') && line.includes(app.file));
    const out = join(dir, 'out');
    mkdirSync(out, { mode: 0o700 });
    const shell = command ? command.replace('<emergency-kit>.txt', KIT).replace(/-C\s+\S+/, `-C ${out}`) : '';
    const run = command ? host('sh', ['-c', `cd ${dir} && ${shell}`]) : { status: -1, err: 'no command' };
    const manifest = existsSync(join(out, 'manifest.json')) ? JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')) : null;
    const entries = manifest ? manifest.entries.map(entry => ({ path: entry.path,
      ok: host('sha256sum', [join(out, entry.path)]).out.split(' ')[0] === entry.sha256 })) : [];
    return { listing, doc, raw, readmeCommand: command, shell: shell.replace(KIT, '<kit>'), run: { status: run.status, err: run.err.slice(-300) },
      memberSha: sha === app.sha256, manifest, entries };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function partBackups() {
  await login('a');
  await openPage('#/overview');
  let plain;
  let sealed;
  await section('settings', async () => {
    await frame.locator('[data-nav="keys"]').click();
    await frame.locator('#encrypt-default').waitFor();
    check('預設加密備份 shows the saved setting (on)', await frame.locator('#encrypt-default').isChecked());
    await frame.locator('#encrypt-default').click();
    await frame.locator('#confirm-dialog').waitFor();
    check('turning it off shows the engine warning about passwords, API keys and tokens', /資料庫密碼/.test(await frame.locator('#confirm-body').textContent()));
    await confirmDialog();
    await frame.locator('#view').getByText('已關閉「預設加密備份」').waitFor();
    check('engine settings-get false after the acknowledged dialog', engine('a', 'settings-get').settings?.encrypt_by_default === false);
    await shot('30-settings-off.png');
    await frame.locator('#encrypt-default').click();
    await frame.locator('#view').getByText('已開啟「預設加密備份」。').waitFor();
    check('turned on again without a dialog', engine('a', 'settings-get').settings?.encrypt_by_default === true);
  });
  await section('create', async () => {
    plain = await createBackup('woowbk-demo', { encrypt: false });
    check('unencrypted backup from the create view (加密此備份 unticked, acknowledged)', plain.title === '備份完成' && /未加密/.test(plain.text), plain.text.slice(0, 160));
    const timing = await frame.locator('table.timing tbody tr').evaluateAll(rows => rows.map(row => [...row.children].map(cell => cell.textContent)));
    check('backup result shows writer pause and unavailability', timing.length === 1, timing);
    sealed = await createBackup('woowbk-demo', { encrypt: true });
    check('encrypted backup from the create view (default)', sealed.title === '備份完成' && /以這台設備的金鑰完整解密驗證/.test(sealed.text), sealed.text.slice(0, 160));
    const meta = Object.fromEntries((engine('a', 'list').backups || []).map(item => [item.id, item]));
    check('engine: one unencrypted (key_id null) and one encrypted format 2 backup', meta[plain.id]?.encrypted === false && meta[plain.id]?.key_id === null
      && meta[sealed.id]?.encrypted === true && meta[sealed.id]?.format === 2, { plain: meta[plain.id]?.encrypted, sealed: meta[sealed.id]?.encrypted });
    await shot('31-backup-result.png');
  });
  await section('download', async () => {
    await frame.locator('[data-nav="backups"]').click();
    await frame.locator(`tr[data-backup="${sealed.id}"]`).waitFor();
    const [file] = await Promise.all([page.waitForEvent('download', { timeout: 300000 }), frame.locator(`[data-focus="download-${sealed.id}"]`).click()]);
    const path = join(PRIVATE, file.suggestedFilename());
    await file.saveAs(path);
    check('the page downloads woowtech-backup-<host>-<YYYYMMDD-HHMMSS>.tar', /^woowtech-backup-woowbk-dev-a-\d{8}-\d{6}\.tar$/.test(file.suggestedFilename()), file.suggestedFilename());
    const unpacked = await manualUnpack(path);
    rmSync(path, { force: true });
    check('plain tar lists backup.json, README.txt, apps/woowbk-demo.tar.zst.age', JSON.stringify(unpacked.listing) === JSON.stringify(['backup.json', 'README.txt', 'apps/woowbk-demo.tar.zst.age']), unpacked.listing);
    const doc = unpacked.doc;
    check('backup.json: format 2, age-x25519, key id, app names, member size and sha256', doc.format === 2 && doc.encryption === 'age-x25519'
      && /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/.test(doc.key_id) && doc.apps[0].id === 'woowbk-demo' && doc.apps[0].file === 'apps/woowbk-demo.tar.zst.age' && unpacked.memberSha,
      { format: doc.format, encryption: doc.encryption, apps: doc.apps.map(app => app.id) });
    check('backup.json holds no secret key, recipient or machine id', !/AGE-SECRET-KEY|age1[0-9a-z]{20}|machine_id/.test(unpacked.raw));
    check('README decrypt command (age | zstd | tar) with the emergency kit works', unpacked.run.status === 0 && unpacked.manifest?.backup_id === doc.backup_id, unpacked.run);
    check('every entry of the decrypted app matches its manifest sha256', unpacked.entries.length > 0 && unpacked.entries.every(entry => entry.ok),
      unpacked.entries.map(entry => `${entry.path}:${entry.ok}`));
    writeFileSync(join(EVIDENCE, 'download-backup-json.json'), JSON.stringify(doc, null, 1));
    writeFileSync(join(EVIDENCE, 'download-readme-command.txt'), `${unpacked.shell}\n`);
    // The unencrypted backup (for dev-b's upload test): kept in the 0700 run directory until the devb part.
    const [plainFile] = await Promise.all([page.waitForEvent('download', { timeout: 300000 }), frame.locator(`[data-focus="download-${plain.id}"]`).click()]);
    state.plainFile = join(PRIVATE, plainFile.suggestedFilename());
    await plainFile.saveAs(state.plainFile);
    saveState();
    const plainList = host('tar', ['-tf', state.plainFile]).out.trim().split('\n');
    check('the unencrypted backup is a plain tar with apps/woowbk-demo.tar.gz', plainList.includes('apps/woowbk-demo.tar.gz'), plainList);
  });
  await section('export', async () => {
    await frame.locator('[data-nav="backups"]').click();
    await frame.locator(`[data-focus="download-menu-row-${sealed.id}"]`).click();
    await frame.locator(`[data-focus="menu-export-row-${sealed.id}"]`).click();
    const copyEvent = page.waitForEvent('download', { timeout: 300000 });
    await confirmDialog();
    const exported = await jobResult();
    check('unencrypted copy job finished', exported.title === '未加密副本已建立', exported.text.slice(0, 120));
    const copy = await copyEvent;
    const copyPath = join(PRIVATE, copy.suggestedFilename());
    await copy.saveAs(copyPath);
    const inner = host('sh', ['-c', `tar -xOf '${copyPath}' apps/woowbk-demo.tar.gz | tar -tzf - | head -3`]).out.trim().split('\n');
    rmSync(copyPath, { force: true });
    check('the copy (-unencrypted.tar) opens with tar and gzip alone', /-unencrypted\.tar$/.test(copy.suggestedFilename()) && inner[0] === 'manifest.json', inner);
    const listed = (engine('a', 'list').exports || []).find(item => item.backup_id === sealed.id);
    const mode = listed ? onDevice('a', `stat -c "%U %a" /var/lib/woowtech-backup/exports /var/lib/woowtech-backup/exports/${listed.export_id}.tar`).out.trim().split('\n') : [];
    check('copy root 0600 in a root 0700 directory, expires in about 15 minutes', JSON.stringify(mode) === JSON.stringify(['root 700', 'root 600'])
      && listed.expires - Date.now() / 1000 > 600 && listed.expires - Date.now() / 1000 <= 900, { mode, expires: listed?.expires });
    await frame.locator('[data-focus="result-export-delete"]').click();
    await frame.locator('#status').getByText(/已刪除未加密副本|這份未加密副本已不存在/).waitFor();
    check('立即刪除 removed the copy', !(engine('a', 'list').exports || []).some(item => item.backup_id === sealed.id));
  });
  await section('verify', async () => {
    await frame.locator('[data-nav="backups"]').click();
    await frame.locator(`[data-focus="verify-${sealed.id}"]`).click();
    const verified = await jobResult();
    const checked = await frame.locator('ul[aria-label="各應用逐項檢查的內容"]').textContent().catch(() => '');
    check('deep verify through the page: volumes, dumps, secrets and the data digests checked', verified.title === '驗證完成' && /資料摘要/.test(checked), checked);
    await frame.locator('[data-nav="backups"]').click();
    await waitText(frame.locator(`tr[data-backup="${sealed.id}"]`), /已驗證（內容已逐項檢查）/, 60000);
    check('list: 已驗證（內容已逐項檢查）', true);
  });
  await section('restore', async () => {
    await frame.locator('[data-nav="backups"]').click();
    await frame.locator(`[data-focus="restore-${plain.id}"]`).click();
    await frame.locator('[data-focus="pf-next"]').waitFor({ timeout: 300000 });
    const preflight = await frame.locator('#view').textContent();
    check('preflight: the restore compares the data digests', /資料摘要/.test(preflight), preflight.slice(0, 200));
    await frame.locator('[data-focus="pf-next"]').click();
    await frame.locator('#confirm-restore').check();
    await frame.locator('[data-focus="confirm-start"]').click();
    const restored = await jobResult();
    const rows = await frame.locator('table.compare tbody tr[data-check]').evaluateAll(nodes => nodes.map(node => [node.dataset.check, node.lastElementChild.textContent]));
    check('restore result: one row per digest check, both 一致', restored.title === '還原完成' && rows.length === 2 && rows.every(([, verdict]) => /一致/.test(verdict) && !/不一致/.test(verdict)), rows);
    check('summary line counts every compared item', /共 \d+ 項：\d+ 項一致、0 項不一致、0 項未比對/.test(await frame.locator('.verify-summary').textContent()));
    const safety = (restored.text.match(/還原前備份(\d{8}T\d{6}Z-[0-9a-f]{8})/) || [])[1];
    remember('a', safety);
    await page.setViewportSize({ width: 1440, height: 1500 });
    await shot('32-restore-digest-table.png');
    await page.setViewportSize({ width: 1440, height: 900 });
  });
}

// ---------------------------------------------------------------------------------------------- dev-b without a key
async function plainDownload() {
  // The newest unencrypted manual backup of woowbk-demo on dev-a, downloaded through dev-a's page.
  const plain = (engine('a', 'list').backups || []).filter(item => item.type === 'manual' && item.encrypted === false
    && (item.apps || []).some(app => app.id === 'woowbk-demo')).sort((x, y) => (x.created < y.created ? 1 : -1))[0];
  if (!plain) throw new Error('no unencrypted backup on dev-a (run the backups part first)');
  await login('a');
  await openPage('#/backups');
  await frame.locator(`tr[data-backup="${plain.id}"]`).waitFor();
  const [file] = await Promise.all([page.waitForEvent('download', { timeout: 300000 }), frame.locator(`[data-focus="download-${plain.id}"]`).click()]);
  state.plainFile = join(PRIVATE, file.suggestedFilename());
  await file.saveAs(state.plainFile);
  saveState();
}

async function partDevB() {
  if (!state.plainFile || !existsSync(state.plainFile)) await section('devb-download', plainDownload);
  await login('b');
  await openPage('#/overview');
  await section('devb-create', async () => {
    check('dev-b has no device key', engine('b', 'status').key === null);
    await frame.locator('#go-create').click();
    await frame.locator('#encrypt-backup').waitFor();
    const notice = await frame.locator('#view').textContent();
    check('create view says a key is needed only for an encrypted backup', /取消勾選「加密此備份」建立不加密的備份/.test(notice));
    await frame.locator('[data-nav="overview"]').click();
    const plainB = await createBackup('woowbk-demo', { encrypt: false });
    check('dev-b: an unencrypted backup without any device key (the key banner does not block it)', plainB.title === '備份完成' && /未加密/.test(plainB.text), plainB.text.slice(0, 160));
    await shot('40-devb-unencrypted-backup.png');
  });
  await section('devb-upload', async () => {
    if (!state.plainFile || !existsSync(state.plainFile)) throw new Error('run the backups part first (no unencrypted download)');
    await frame.locator('[data-nav="keys"]').click();
    await frame.locator('#encrypt-default').waitFor();
    if (await frame.locator('#encrypt-default').isChecked()) {
      await frame.locator('#encrypt-default').click();
      await confirmDialog();
      await frame.locator('#view').getByText('已關閉「預設加密備份」').waitFor();
    }
    await openPage('#/restore');
    await frame.locator('#restore-file').setInputFiles(state.plainFile);
    await frame.locator('[data-focus="restore-upload"]').click();
    await frame.locator('[data-focus="pf-next"]').waitFor({ timeout: 600000 });
    const preflight = await frame.locator('#view').textContent();
    check('unencrypted upload: the preflight warns that its origin cannot be verified', /無法驗證/.test(preflight) && /來源/.test(preflight), preflight.slice(0, 300));
    await shot('41-devb-unauthenticated-preflight.png');
    await frame.locator('[data-focus="pf-next"]').click();
    await frame.locator('#confirm-restore').check();
    check('confirm needs the extra acknowledgement for an unauthenticated backup', await frame.locator('#confirm-unauthenticated').count() === 1
      && await frame.locator('[data-focus="confirm-start"]').isDisabled());
    await frame.locator('#confirm-unauthenticated').check();
    await shot('42-devb-confirm.png');
    await frame.locator('[data-focus="confirm-start"]').click();
    const restored = await jobResult();
    const id = (restored.hash.match(/jobs\/(j\S+)/) || [])[1];
    const job = engine('b', 'job-status', { job_id: id }).job || {};
    remember('b', job.params?.backup_id);
    remember('b', job.result?.safety_backup_id);
    check('restore with accept_unauthenticated succeeded; the safety backup follows the setting (unencrypted)', restored.title === '還原完成'
      && job.params?.accept_unauthenticated === true, { title: restored.title, params: job.params });
    const rows = await frame.locator('table.compare tbody tr[data-check]').evaluateAll(nodes => nodes.map(node => [node.dataset.check, node.lastElementChild.textContent]));
    check('dev-b result: the digest checks of the dev-a backup match on dev-b', rows.length === 2 && rows.every(([, verdict]) => /一致/.test(verdict) && !/不一致/.test(verdict)), rows);
    await shot('43-devb-restore-result.png');
  });
  await section('devb-setting-back', async () => {
    await frame.locator('[data-nav="keys"]').click();
    await frame.locator('#encrypt-default').waitFor();
    if (!await frame.locator('#encrypt-default').isChecked()) {
      await frame.locator('#encrypt-default').click();
      await frame.locator('#view').getByText('已開啟「預設加密備份」。').waitFor();
    }
    check('dev-b: 預設加密備份 on again', engine('b', 'settings-get').settings?.encrypt_by_default === true);
  });
  if (state.plainFile) rmSync(state.plainFile, { force: true });
  delete state.plainFile;
  saveState();
}

// ---------------------------------------------------------------------------------------------- lab clean-up
async function partCleanupLab() {
  for (const [dev, id] of state.created) {
    const reply = engine(dev, 'delete', { backup_id: id });
    check(`dev-${dev} ${id} deleted or already gone`, reply.ok || reply.error?.code === 'not-found', reply.error);
  }
  for (const dev of ['a', 'b']) {
    for (const item of engine(dev, 'list').exports || []) engine(dev, 'export-delete', { export_id: item.export_id });
  }
  state.created = [];
  saveState();
}

try {
  for (const part of parts) {
    log(`== part ${part}`);
    await { catalog: partCatalog, cleanup: partCleanup, backups: partBackups, devb: partDevB, 'cleanup-lab': partCleanupLab }[part]();
  }
  check('no script errors while the page was open', errors.length === 0, errors);
} catch (error) {
  check(`driver: ${error.message.split('\n')[0]}`, false);
  await shot('99-failure.png');
} finally {
  await browser.close();
  const failed = checks.filter(item => !item.ok);
  writeFileSync(join(EVIDENCE, 'result.json'), JSON.stringify({ parts, checks, passed: checks.length - failed.length, failed: failed.length }, null, 1));
  log(`RESULT ${checks.length - failed.length}/${checks.length} passed; evidence ${EVIDENCE}`);
  process.exitCode = failed.length ? 1 : 0;
}
