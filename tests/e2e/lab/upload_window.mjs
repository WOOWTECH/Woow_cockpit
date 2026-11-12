#!/usr/bin/env node
// H8: browser upload throughput through the real Cockpit 362 (cockpit-ws websocket -> superuser bridge ->
// fsreplace1) for different unacknowledged-byte windows of the installed "備份與還原" page.
//   node tests/e2e/lab/upload_window.mjs [windowsMiB=2,4,8] [repeats=3] [chunkKiB=64]
// The window is overridden only inside the test browser: Playwright intercepts backup.js and replaces
// `const WINDOW_SIZE = 2 * 1024 * 1024;` (the repo and the device keep 2 MiB). The same interception adds
// timestamps around sendFile() and upload-finish. Each run uploads the same ~142 MB backup to dev-b,
// stops at the key step (dev-b does not hold the key) and deletes the uploaded backup again.
// Evidence: ~/.woowbk-lab/evidence/hardening/<time>-h8/ (driver.log, result.json).
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const LAB = join(homedir(), '.woowbk-lab');
const LP = join(LAB, 'bin', 'labpodman');
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const DEVICE = { name: 'woowbk-dev-b', port: 19092 };
const PASSWORD = readFileSync(join(LAB, 'secrets', 'devadmin.pass'), 'utf8').trim();
const SOURCE = join(LAB, 'downloads', 'woowtech-backup-woowbk-dev-a-20261112-1905.woowbackup');
const SOURCE_ID = '20261112T190548Z-0381dc27';
const windows = (process.argv[2] || '2,4,8').split(',').map(Number);
const repeats = Number(process.argv[3] || 3);
const chunkKiB = Number(process.argv[4] || 64);  // experiment only: frame size read per File.slice()
const pad = n => String(n).padStart(2, '0');
const now = new Date();
const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}T${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
const EVIDENCE = join(LAB, 'evidence', 'hardening', `${stamp}-h8`);
mkdirSync(EVIDENCE, { recursive: true, mode: 0o700 });
const bundled = join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome');
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || (existsSync(bundled) ? bundled : undefined);
const t0 = Date.now();
const scrub = text => String(text).split(PASSWORD).join('[password]');
function log(message) {
  const line = `${new Date().toISOString().slice(11, 19)} +${((Date.now() - t0) / 1000).toFixed(1).padStart(6)}s ${scrub(message)}`;
  console.log(line);
  writeFileSync(join(EVIDENCE, 'driver.log'), line + '\n', { flag: 'a' });
}

function engine(command, request) {
  const result = spawnSync(LP, ['exec', '-i', DEVICE.name, HELPER, command],
    { input: request === undefined ? '' : JSON.stringify(request), maxBuffer: 16 * 1024 * 1024 });
  return JSON.parse(String(result.stdout).trim().split('\n').pop() || '{}');
}
function memAvailableMb() {
  const line = readFileSync('/proc/meminfo', 'utf8').split('\n').find(l => l.startsWith('MemAvailable:'));
  return Math.floor(Number(line.split(/\s+/)[1]) / 1024);
}

// Exact text replacements in the installed backup.js; every one must match exactly once.
function instrument(source, windowBytes) {
  const edits = [
    ['const WINDOW_SIZE = 2 * 1024 * 1024;', `const WINDOW_SIZE = ${windowBytes};`],
    ['const CHUNK_SIZE = 64 * 1024;', `const CHUNK_SIZE = ${chunkKiB * 1024};`],
    ['function sendFile(upload, file, path, onProgress) {',
      'function sendFile(upload, file, path, onProgress) { window.__h8 = { start: performance.now(), maxInflight: 0, acks: 0, frames: 0 };'],
    ['upload.acked = Math.min(upload.sent, upload.acked + amount);',
      'upload.acked = Math.min(upload.sent, upload.acked + amount); window.__h8.acks++;'],
    ['upload.sent += data.length;',
      'upload.sent += data.length; window.__h8.frames++; window.__h8.maxInflight = Math.max(window.__h8.maxInflight, upload.sent - upload.acked);'],
    ['channel.control({ command: "done" });', 'channel.control({ command: "done" }); window.__h8.doneAt = performance.now();'],
    ['upload.acked = upload.size;\n          onProgress();\n          resolve();',
      'upload.acked = upload.size;\n          onProgress();\n          window.__h8.closedAt = performance.now();\n          resolve();'],
    // finishUpload() passes a per-size timeout since the F6 fix; only the timestamp is added here.
    ['const finished = await call("upload-finish", { upload_id: upload.id }, { timeout: finishTimeout(upload.size) });',
      'const finished = await call("upload-finish", { upload_id: upload.id }, { timeout: finishTimeout(upload.size) }); window.__h8.finishedAt = performance.now();'],
  ];
  let out = source;
  for (const [from, to] of edits) {
    const count = out.split(from).length - 1;
    if (count !== 1) throw new Error(`backup.js instrumentation: expected 1 match, got ${count}: ${from.slice(0, 60)}`);
    out = out.replace(from, to);
  }
  return out;
}

async function login(browser, windowBytes) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1440, height: 900 } });
  let patched = 0;
  await context.route('**/woowtechbackup/backup.js', async route => {
    const response = await route.fetch();
    const body = instrument(await response.text(), windowBytes);
    patched += 1;
    const headers = Object.fromEntries(Object.entries(response.headers())
      .filter(([name]) => !['content-length', 'content-encoding', 'etag', 'last-modified'].includes(name)));
    await route.fulfill({ response, body, headers: { ...headers, 'cache-control': 'no-store' } });
  });
  const page = await context.newPage();
  const base = `https://127.0.0.1:${DEVICE.port}`;
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(PASSWORD);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 45000 });
  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access)$/ });
  await indicator.waitFor({ timeout: 30000 });
  if (/Limited/.test(await indicator.textContent())) {
    await page.getByRole('button', { name: /^Limited access$/ }).click();
    await page.locator('#switch-to-admin-access-password').fill(PASSWORD);
    await page.getByRole('button', { name: /^Authenticate$/ }).click();
    await page.getByRole('button', { name: /^Administrative access$/ }).waitFor({ timeout: 30000 });
  }
  await page.goto(`${base}/woowtechbackup`, { waitUntil: 'domcontentloaded' });
  const iframe = page.locator('iframe[src*="woowtechbackup"]');
  await iframe.waitFor({ state: 'attached', timeout: 30000 });
  const frame = await (await iframe.elementHandle()).contentFrame();
  await frame.locator('#view').waitFor({ timeout: 30000 });
  return { context, page, frame, patched: () => patched };
}

async function uploadOnce(browser, mib) {
  const { context, frame, patched } = await login(browser, mib * 1024 * 1024);
  try {
    if (patched() !== 1) throw new Error(`backup.js was not intercepted (${patched()})`);
    await frame.locator('#go-restore').click();
    await frame.locator('#restore-file').setInputFiles(SOURCE);
    const clicked = Date.now();
    await frame.locator('[data-focus="restore-upload"]').click();
    await frame.waitForFunction(() => window.__h8 && window.__h8.finishedAt, null, { timeout: 600000, polling: 200 });
    const total = (Date.now() - clicked) / 1000;
    const h8 = await frame.evaluate(() => window.__h8);
    await frame.locator('#key-text').waitFor({ timeout: 120000 });
    return { ...h8, total_s: total };
  } finally {
    await context.close();
  }
}

const size = statSync(SOURCE).size;
const sourceSha = await new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  createReadStream(SOURCE).on('data', chunk => hash.update(chunk)).on('end', () => resolve(hash.digest('hex'))).on('error', reject);
});
log(`source ${SOURCE} (${size} bytes); windows ${windows.join(', ')} MiB x ${repeats}; chunk ${chunkKiB} KiB; device ${DEVICE.name}`);
if (memAvailableMb() < 1200) { log(`host MemAvailable ${memAvailableMb()} MB < 1200: not starting Chromium`); process.exit(2); }
const listed = (engine('list').backups || []).map(b => b.id);
if (listed.includes(SOURCE_ID)) throw new Error(`${SOURCE_ID} already on ${DEVICE.name}; delete it first`);
const browser = await chromium.launch({ executablePath });
const runs = [];
let aborted = null;
try {
  for (let r = 0; r < repeats; r += 1) {
    for (const mib of windows) {
      const result = await uploadOnce(browser, mib);
      const transfer = (result.closedAt - result.start) / 1000;
      const row = {
        window_mib: mib, chunk_kib: chunkKiB, repeat: r + 1, transfer_s: Math.round(transfer * 100) / 100,
        mb_per_s: Math.round(size / 1e6 / transfer * 10) / 10,
        finish_s: Math.round((result.finishedAt - result.closedAt) / 10) / 100,
        until_finish_s: Math.round(result.total_s * 10) / 10, acks: result.acks, frames: result.frames,
        max_inflight_bytes: result.maxInflight,
      };
      const uploaded = (engine('list').backups || []).find(b => b.id === SOURCE_ID) || {};
      row.sha256_matches = uploaded.sha256 === sourceSha && uploaded.size === size;
      runs.push(row);
      log(JSON.stringify(row));
      if (!row.sha256_matches) throw new Error(`uploaded file differs from the source (${uploaded.sha256})`);
      const reply = engine('delete', { backup_id: SOURCE_ID });
      if (!reply.ok) throw new Error(`delete after upload failed: ${JSON.stringify(reply.error)}`);
    }
  }
} catch (error) {
  aborted = String(error && error.message || error).split('\n')[0];
  log(`ABORTED: ${aborted}`);
} finally {
  await browser.close();
}
const summary = {};
for (const mib of windows) {
  const rows = runs.filter(r => r.window_mib === mib);
  if (!rows.length) continue;
  const speeds = rows.map(r => r.mb_per_s).sort((a, b) => a - b);
  summary[`${mib}MiB/${chunkKiB}KiB`] = { runs: rows.length, median_mb_per_s: speeds[Math.floor(speeds.length / 2)],
    min_mb_per_s: speeds[0], max_mb_per_s: speeds[speeds.length - 1],
    max_inflight_bytes: Math.max(...rows.map(r => r.max_inflight_bytes)) };
}
const left = (engine('list').backups || []).map(b => b.id);
writeFileSync(join(EVIDENCE, 'result.json'), JSON.stringify({ size, runs, summary, aborted, dev_b_backups_after: left }, null, 1));
log(`SUMMARY ${JSON.stringify(summary)}; dev-b backups after: ${left.join(', ')}; evidence ${EVIDENCE}`);
process.exit(aborted ? 1 : 0);
