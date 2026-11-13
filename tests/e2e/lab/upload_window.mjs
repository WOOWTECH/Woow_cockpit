#!/usr/bin/env node
// H8: browser upload throughput through the real Cockpit 362 (cockpit-ws websocket -> superuser bridge ->
// fsreplace1) for different unacknowledged-byte windows and frame sizes of the installed "備份與還原" page.
//   node tests/e2e/lab/upload_window.mjs [windowsMiB=2,4] [repeats=3] [chunksKiB=64,256,512]
// The window and the frame size are overridden only inside the test browser: Playwright intercepts backup.js and
// rewrites the `const WINDOW_SIZE = …;` and `const CHUNK_SIZE = …;` lines (the repo and the device keep their
// defaults). The same interception adds timestamps around sendFile() and upload-finish. Every repeat runs each
// window x chunk configuration once, in a rotated order (host load drifts, so no configuration always runs first).
// Each run uploads the same ~142 MB backup to dev-b, checks size and sha256 of the stored file against the source,
// stops at the key step (dev-b does not hold the key) and deletes the uploaded backup again. A failed run is recorded
// with its error (and its upload aborted) and the next run starts; the summary counts errors per configuration.
// Host load is recorded per run: the 1-minute load average before and after, and the host CPU busy share and the
// lowest MemAvailable sampled during the transfer.
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
const BASELINE = '2MiB/64KiB';
const list = (text, fallback) => (text || fallback).split(',').map(Number).filter(n => Number.isFinite(n) && n > 0);
const windows = list(process.argv[2], '2,4');
const repeats = Number(process.argv[3] || 3);
const chunks = list(process.argv[4], '64,256,512');
const configs = windows.flatMap(mib => chunks.map(kib => ({ mib, kib, key: `${mib}MiB/${kib}KiB` })));
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
const load1 = () => Number(readFileSync('/proc/loadavg', 'utf8').split(' ')[0]);
function cpuTimes() {
  const fields = readFileSync('/proc/stat', 'utf8').split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  const idle = fields[3] + (fields[4] || 0);
  return { idle, total: fields.reduce((sum, value) => sum + value, 0) };
}
const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2 * 100) / 100;
};

// Text replacements in the installed backup.js. The two size constants are matched by name (any value), the
// instrumentation points literally; every one must match exactly once.
function instrument(source, windowBytes, chunkBytes) {
  const edits = [
    [/const WINDOW_SIZE = [^;\n]+;/, `const WINDOW_SIZE = ${windowBytes};`],
    [/const CHUNK_SIZE = [^;\n]+;/, `const CHUNK_SIZE = ${chunkBytes};`],
    ['function sendFile(upload, file, path, onProgress) {',
      'function sendFile(upload, file, path, onProgress) { window.__h8 = { start: performance.now(), maxInflight: 0, acks: 0, frames: 0, uploadId: upload.id };'],
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
    const count = typeof from === 'string' ? out.split(from).length - 1 : (out.match(new RegExp(from.source, 'g')) || []).length;
    if (count !== 1) throw new Error(`backup.js instrumentation: expected 1 match, got ${count}: ${String(from).slice(0, 60)}`);
    out = out.replace(from, to);
  }
  return out;
}

async function login(browser, config) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1440, height: 900 } });
  let patched = 0;
  await context.route('**/woowtechbackup/backup.js', async route => {
    const response = await route.fetch();
    const body = instrument(await response.text(), config.mib * 1024 * 1024, config.kib * 1024);
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

async function uploadOnce(browser, config, sampler) {
  const { context, frame, patched } = await login(browser, config);
  try {
    if (patched() !== 1) throw new Error(`backup.js was not intercepted (${patched()})`);
    await frame.locator('#go-restore').click();
    await frame.locator('#restore-file').setInputFiles(SOURCE);
    const clicked = Date.now();
    sampler.start();
    let host;
    try {
      await frame.locator('[data-focus="restore-upload"]').click();
      await frame.waitForFunction(() => window.__h8 && window.__h8.finishedAt, null, { timeout: 600000, polling: 200 });
    } catch (error) {
      const state = await frame.evaluate(() => window.__h8 || null).catch(() => null);
      error.uploadId = state && state.uploadId;
      throw error;
    } finally {
      host = sampler.stop();
    }
    const total = (Date.now() - clicked) / 1000;
    const h8 = await frame.evaluate(() => window.__h8);
    await frame.locator('#key-text').waitFor({ timeout: 120000 });
    return { ...h8, total_s: total, host };
  } finally {
    await context.close();
  }
}

// CPU busy share and lowest MemAvailable on the host while one upload runs (sampled every 500 ms).
function hostSampler() {
  let timer = null;
  let first = null;
  let minMem = Infinity;
  return {
    start() {
      first = { cpu: cpuTimes(), load: load1() };
      minMem = memAvailableMb();
      timer = setInterval(() => { minMem = Math.min(minMem, memAvailableMb()); }, 500);
    },
    stop() {
      clearInterval(timer);
      const last = cpuTimes();
      const total = last.total - first.cpu.total;
      return { load1_before: first.load, load1_after: load1(), cpu_busy_pct: total > 0 ? Math.round((1 - (last.idle - first.cpu.idle) / total) * 1000) / 10 : null,
        mem_available_min_mb: minMem };
    }
  };
}

const size = statSync(SOURCE).size;
const sourceSha = await new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  createReadStream(SOURCE).on('data', chunk => hash.update(chunk)).on('end', () => resolve(hash.digest('hex'))).on('error', reject);
});
log(`source ${SOURCE} (${size} bytes); configurations ${configs.map(c => c.key).join(', ')} x ${repeats}; device ${DEVICE.name}; ` +
  `host load ${readFileSync('/proc/loadavg', 'utf8').trim()}; MemAvailable ${memAvailableMb()} MB`);
if (memAvailableMb() < 1200) { log(`host MemAvailable ${memAvailableMb()} MB < 1200: not starting Chromium`); process.exit(2); }
const listed = (engine('list').backups || []).map(b => b.id);
if (listed.includes(SOURCE_ID)) throw new Error(`${SOURCE_ID} already on ${DEVICE.name}; delete it first`);
const browser = await chromium.launch({ executablePath });
const runs = [];
let aborted = null;
try {
  for (let r = 0; r < repeats && !aborted; r += 1) {
    const order = configs.map((_, i) => configs[(i + r) % configs.length]);
    for (const config of order) {
      if (memAvailableMb() < 1200) { aborted = `host MemAvailable ${memAvailableMb()} MB < 1200`; break; }
      const sampler = hostSampler();
      const row = { config: config.key, window_mib: config.mib, chunk_kib: config.kib, repeat: r + 1 };
      try {
        const result = await uploadOnce(browser, config, sampler);
        const transfer = (result.closedAt - result.start) / 1000;
        Object.assign(row, {
          transfer_s: Math.round(transfer * 100) / 100, mb_per_s: Math.round(size / 1e6 / transfer * 10) / 10,
          finish_s: Math.round((result.finishedAt - result.closedAt) / 10) / 100, until_finish_s: Math.round(result.total_s * 10) / 10,
          acks: result.acks, frames: result.frames, max_inflight_bytes: result.maxInflight, host: result.host,
        });
        const uploaded = (engine('list').backups || []).find(b => b.id === SOURCE_ID) || {};
        row.sha256_matches = uploaded.sha256 === sourceSha && uploaded.size === size;
        if (!row.sha256_matches) row.error = `stored file differs from the source (${uploaded.sha256}, ${uploaded.size})`;
        if (row.max_inflight_bytes > config.mib * 1024 * 1024) row.error = `window exceeded: ${row.max_inflight_bytes} bytes unacknowledged`;
      } catch (error) {
        row.error = String(error && error.message || error).split('\n')[0];
        if (error && error.uploadId) row.aborted_upload = engine('upload-abort', { upload_id: error.uploadId }).ok === true;
      }
      if ((engine('list').backups || []).some(b => b.id === SOURCE_ID)) {
        const reply = engine('delete', { backup_id: SOURCE_ID });
        if (!reply.ok) { row.error = row.error || `delete after upload failed: ${JSON.stringify(reply.error)}`; aborted = row.error; }
      }
      runs.push(row);
      log(JSON.stringify(row));
      if (aborted) break;
    }
  }
} catch (error) {
  aborted = String(error && error.message || error).split('\n')[0];
} finally {
  await browser.close();
}
if (aborted) log(`ABORTED: ${aborted}`);
const summary = {};
for (const config of configs) {
  const rows = runs.filter(r => r.config === config.key);
  if (!rows.length) continue;
  const good = rows.filter(r => !r.error);
  const speeds = good.map(r => r.mb_per_s);
  summary[config.key] = {
    runs: rows.length, errors: rows.length - good.length, median_mb_per_s: speeds.length ? median(speeds) : null,
    min_mb_per_s: speeds.length ? Math.min(...speeds) : null, max_mb_per_s: speeds.length ? Math.max(...speeds) : null,
    max_inflight_bytes: good.length ? Math.max(...good.map(r => r.max_inflight_bytes)) : null,
    median_host_cpu_busy_pct: good.length ? median(good.map(r => r.host.cpu_busy_pct)) : null,
    median_load1_before: good.length ? median(good.map(r => r.host.load1_before)) : null,
  };
}
const base = summary[BASELINE];
for (const [key, item] of Object.entries(summary)) {
  if (base && base.median_mb_per_s && item.median_mb_per_s) {
    item.vs_baseline_pct = Math.round((item.median_mb_per_s / base.median_mb_per_s - 1) * 1000) / 10;
    // Adoption rule (CONTRACT §11): at least 30 % faster than 2 MiB/64 KiB, no error in any of its runs, >= 3 runs.
    item.qualifies = key !== BASELINE && item.errors === 0 && item.runs >= 3 && item.vs_baseline_pct >= 30;
  }
}
const left = (engine('list').backups || []).map(b => b.id);
writeFileSync(join(EVIDENCE, 'result.json'), JSON.stringify({ size, sha256: sourceSha, configs: configs.map(c => c.key), repeats, runs,
  summary, aborted, dev_b_backups_after: left, host_load_end: readFileSync('/proc/loadavg', 'utf8').trim() }, null, 1));
log(`SUMMARY ${JSON.stringify(summary)}; dev-b backups after: ${left.join(', ')}; evidence ${EVIDENCE}`);
process.exit(aborted ? 1 : 0);
