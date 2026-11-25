// Fixture browser tests for the Cockpit package woowtechbackup (docs/backup/CONTRACT.md §7, §11).
// A fake window.cockpit records every helper call (argv, options, stdin) and simulates the bridge:
// fsreplace1 upload channels with "ack" control messages, the external fsread1 download URL,
// cockpit.location, permission, user and transport. No process is ever launched.
//   PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome node tests/backup-ui.mjs
//   BACKUP_UI_SCREENSHOTS=/some/dir  (optional) saves evidence screenshots there.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium } from 'playwright-core';

const root = process.env.BRAND_UI_ROOT || resolve(dirname(fileURLToPath(import.meta.url)), '..');
const apporo = process.env.UI_BRAND === 'apporo';
const HELPER = '/usr/local/libexec/woowtech-cockpit-backup';
const CSRF = 'fixture-csrf-7f3a91';
const SHOTS = process.env.BACKUP_UI_SCREENSHOTS || '';
const CSP = "default-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; " +
  "font-src 'self' data:; img-src 'self' data:; block-all-mixed-content";
const GiB = 1024 ** 3;
const MiB = 1024 ** 2;
const KiB = 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const KEY_ID = 'ABCD-EF01-2345-6789';
const OTHER_KEY_ID = '9F2C-1B7E-55AA-0D31';
const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const SECRET = `AGE-SECRET-KEY-1${(BECH + BECH).slice(0, 58).toUpperCase()}`;
const OTHER_SECRET = `AGE-SECRET-KEY-1${([...BECH].reverse().join('') + BECH).slice(0, 58).toUpperCase()}`;
const B_MANUAL = '20261112T020000Z-a1b2c3d4';
const B_SAFETY = '20261110T153000Z-0badf00d';
const B_UPLOADED = '20261113T010000Z-c0ffee01';
const B_NEW = '20261113T020500Z-feedbeef';
const B_SAFETY_NEW = '20261113T020700Z-5afe0001';
const J_ACTIVE = 'j20261113T015000Z-00a1b2c3';
const J_OTHER = 'j20261113T014500Z-0b0b0b0b';
const UPLOAD_ID = 'u3f9a0c1d2e';
const UPLOAD_PATH = `/var/lib/woowtech-backup/uploads/${UPLOAD_ID}.part`;
// 從 HA 備份匯入: uploaded HA backups, HA's backup key (test-only values) and the converted backup.
const HA_ID = 'ha-0123456789abcdef0123';
const HA_PLAIN = 'ha-fedcba9876543210fedc';
const HA_KEY = 'WOOW-TEST-KEY0-ABCD-1234-5678-9XYZ';
const HA_WRONG_KEY = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000';
const HA_KEYS = [HA_KEY, HA_WRONG_KEY];
const B_HA = '20261118T030500Z-4a4b4c4d';
const J_HA_CHECK = 'j20261118T020000Z-0aa00001';
const J_HA_CONVERT = 'j20261118T021000Z-0aa00002';
const J_HA_FAILED = 'j20261118T015000Z-0aa00003';
const J_HA_RUN = 'j20261118T022000Z-0aa00004';
const J_HA_RESTORE = 'j20261118T023000Z-0aa00005';

function kitText(secret, keyId, host = 'dev-a') {
  return ['WOOWTECH Cockpit 備份緊急金鑰', '================================', '',
    '這是還原加密備份檔（.woowbackup）所需的金鑰。請立即把本檔案保存到本設備以外的安全位置，', '',
    `金鑰 ID：${keyId}`, '建立時間：2026-11-01T08:00:00Z（UTC）', `建立設備：${host}`, '',
    '備份金鑰（請完整複製下一行，包含開頭的 AGE-SECRET-KEY-1）：', '', secret, '',
    '如何在另一台設備還原', '1. 在目標設備登入 Cockpit，以管理員身分開啟「備份與還原」頁面。', ''].join('\n');
}

const PHASES = {
  backup: [['prepare', '準備'], ['check', '檢查空間與應用'], ['stop', '暫停應用寫入'], ['dump', '匯出資料庫'],
    ['export', '匯出資料卷與設定'], ['start', '恢復應用'], ['package', '加密封裝'], ['verify', '驗證備份']],
  restore: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['preflight', '相容性檢查'], ['stage', '預先寫入主機資料夾'],
    ['safety', '建立還原前備份'], ['stop', '停止應用'], ['restore', '還原資料'], ['start', '啟動應用'], ['check', '健康與資料核對']],
  verify: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['check', '核對結果']],
  export: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['package', '封裝未加密副本'], ['verify', '驗證副本']],
  // 從 HA 備份匯入 (DESIGN §6): a `verify` and a `backup` job with params.source "ha"; labels come from the records.
  'ha-check': [['prepare', '準備'], ['decrypt', '解開 HA 備份'], ['check', '檢查內容與版本']],
  'ha-convert': [['prepare', '準備'], ['decrypt', '解開 HA 備份'], ['convert', '轉換資料'], ['package', '封裝備份'], ['verify', '驗證備份']],
};
const labelOf = (type, id) => [...PHASES[type], ['rollback', '自動回復']].find(([phase]) => phase === id)?.[1] || id;

function phasesAt(type, activeId, { failedAt = null, skipped = [], rollback = null } = {}) {
  const all = [...PHASES[type], ...(rollback ? [['rollback', '自動回復']] : [])];
  const index = activeId === null ? all.length : all.findIndex(([id]) => id === activeId);
  return all.map(([id, label], position) => {
    let phaseState = position < index ? 'done' : position === index ? 'active' : 'pending';
    if (skipped.includes(id)) phaseState = 'skipped';
    if (id === failedAt) phaseState = 'failed';
    if (id === 'rollback' && rollback) phaseState = rollback;
    return { id, label, state: phaseState };
  });
}

function runningStep(type, phase, percent, extra = {}) {
  return {
    job: { state: 'running', phase, phases: phasesAt(type, phase), progress: { percent, message: labelOf(type, phase) },
      started: '2026-11-13T02:00:11Z', cancellable: false, ...extra },
    log: [`2026-11-13T02:00:${String(10 + percent % 50).padStart(2, '0')}Z 階段：${labelOf(type, phase)}`],
  };
}

const RESTORE_NOTE = '資料卷 woowbk-demo-files 有 1 個檔案的 setuid／setgid 權限在還原時會被移除（例如 bin/helper）；需要這些權限的程式可能無法正常運作。';
const VERIFY_NOTE = '資料卷 woowbk-demo-files 有 1 個檔案的 setuid／setgid 權限在還原時會被移除（例如 bin/helper）。';
const PLAINTEXT = '未加密的備份會以明文儲存與下載資料庫密碼、API 金鑰與存取權杖等應用機密；任何取得備份檔的人都能讀取，也無法確認檔案在設備以外是否被修改過。';
const EXPORT_ID = 'x0123456789abcdef';
const EXPORT_NAME = 'woowtech-backup-dev-a-20261112-020000-unencrypted.tar';
// 30 minutes ahead of the real clock, so the copy never expires while a test runs.
const EXPORT_EXPIRES = Math.floor(Date.now() / 1000) + 1800;
const VERIFY_BEFORE = { summary: { notes: 12, files: 4, digest: '9c1d0f7a', title: '示範筆記', signatures_valid: true } };

function scripts() {
  return {
    backup: [
      runningStep('backup', 'dump', 40),
      runningStep('backup', 'package', 80, { cancellable: true }),
      {
        job: { state: 'succeeded', phase: 'verify', phases: phasesAt('backup', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-13T02:05:30Z', cancellable: false,
          result: { backup_id: B_NEW, size: 52 * MiB, apps: ['woowbk-demo'], downtime_seconds: 7, unavailable_seconds: 9.4, encrypted: true,
            timing: [{ app: 'woowbk-demo', writer_pause_seconds: 6.6, unavailable_seconds: 9.4 }] } },
        log: ['2026-11-13T02:05:29Z 備份 20261113T020500Z-feedbeef 已建立並通過完整驗證（52.0 MiB）', '2026-11-13T02:05:30Z 作業結束：已完成'],
        addBackup: {
          id: B_NEW, type: 'manual', created: '2026-11-13T02:05:00Z', note: '更新前備份', apps: [{ id: 'woowbk-demo', name: '示範筆記應用' }],
          size: 52 * MiB, sha256: 'e'.repeat(64), key_id: KEY_ID, key_available: true, include_images: true,
          filename: 'woowtech-backup-dev-a-20261113-020500.tar', source: { hostname: 'dev-a' },
          verified: { at: '2026-11-13T02:05:29Z', ok: true }, inspected: true, format: 2, encrypted: true, unauthenticated: false,
        },
      },
    ],
    restore: [
      runningStep('restore', 'decrypt', 15, { cancellable: true }),
      runningStep('restore', 'restore', 60, { safety_backup_id: B_SAFETY_NEW }),
      {
        job: { state: 'succeeded', phase: 'check', phases: phasesAt('restore', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-13T02:09:00Z', cancellable: false,
          result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY_NEW, rolled_back: false,
            health: [{ id: 'woowbk-demo/health/0', status: 'ok', message: '健康檢查通過：http://127.0.0.1:18090/healthz 回應 200。' }],
            verification: [{ app: 'woowbk-demo', match: true, before: VERIFY_BEFORE, after: structuredClone(VERIFY_BEFORE) }],
            warnings: [RESTORE_NOTE] } },
        log: ['2026-11-13T02:08:59Z 應用「示範筆記應用」資料核對一致', '2026-11-13T02:09:00Z 作業結束：已完成'],
      },
    ],
    verify: [
      runningStep('verify', 'decrypt', 50, { cancellable: true }),
      {
        job: { state: 'succeeded', phase: 'check', phases: phasesAt('verify', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-13T02:10:00Z', cancellable: false,
          result: { ok: true, entries: 9, bytes: 51 * MiB, deep: true, format: 2, encrypted: true, notes: [VERIFY_NOTE],
            apps: [{ id: 'woowbk-demo', name: '示範筆記應用', checked: { volumes: 1, dirs: 0, images: 2, digests: 2, globals: 0, dumps: 1, secrets: 2 },
              header_only: ['dumps'] }] } },
        log: ['2026-11-13T02:10:00Z 作業結束：已完成'],
        verified: { at: '2026-11-13T02:10:00Z', ok: true, deep: true },
      },
    ],
    export: [
      runningStep('export', 'package', 55, { cancellable: true }),
      {
        job: { state: 'succeeded', phase: 'verify', phases: phasesAt('export', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-13T02:11:00Z', cancellable: false,
          result: { export_id: EXPORT_ID, backup_id: B_MANUAL, filename: EXPORT_NAME, size: 96 * MiB, expires: EXPORT_EXPIRES } },
        log: ['2026-11-13T02:11:00Z 已建立未加密的下載副本（96.0 MiB），15 分鐘後自動刪除'],
        addExport: { export_id: EXPORT_ID, backup_id: B_MANUAL, filename: EXPORT_NAME, size: 96 * MiB, expires: EXPORT_EXPIRES },
      },
    ],
  };
}

function rolledBackScript() {
  return [
    runningStep('restore', 'restore', 62, { safety_backup_id: B_SAFETY_NEW }),
    {
      job: { state: 'rolled-back', phase: 'rollback',
        phases: phasesAt('restore', null, { failedAt: 'check', rollback: 'done' }).map(item =>
          ['start', 'check'].includes(item.id) ? { ...item, state: item.id === 'check' ? 'failed' : 'done' } : item),
        progress: { percent: 88, message: '已自動回復' }, finished: '2026-11-13T02:12:00Z', cancellable: false,
        error: { code: 'job-failed', message: '應用「示範筆記應用」還原後的資料與備份時不一致。' },
        result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY_NEW, rolled_back: true,
          health: [{ id: 'woowbk-demo/health/0', status: 'ok', message: '健康檢查通過。' }],
          verification: [{ app: 'woowbk-demo', match: false, before: VERIFY_BEFORE,
            after: { summary: { ...VERIFY_BEFORE.summary, notes: 11, digest: '00ff00ff' } } }] } },
      log: ['2026-11-13T02:11:30Z 還原失敗：應用「示範筆記應用」還原後的資料與備份時不一致。', '2026-11-13T02:12:00Z 已自動回復到還原前的狀態'],
    },
  ];
}

const backupMeta = (id, extra = {}) => ({
  id, type: 'manual', created: `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6, 8)}T${id.slice(9, 11)}:${id.slice(11, 13)}:${id.slice(13, 15)}Z`,
  note: '', apps: [{ id: 'woowbk-demo', name: '示範筆記應用' }], size: 48 * MiB, sha256: 'a'.repeat(64), key_id: KEY_ID,
  key_available: true, include_images: false, filename: `woowtech-backup-dev-a-${id.slice(0, 8)}-${id.slice(9, 15)}.tar`,
  source: { hostname: 'dev-a' }, verified: { at: '2026-11-12T02:01:00Z', ok: true }, inspected: true,
  format: 2, encrypted: true, unauthenticated: false, ...extra,
});

function app(id, name, extra = {}) {
  return {
    id, name, description: `${name}：PostgreSQL、上傳檔案與密鑰`, owner: 'appowner', adapter: 'quadlet-postgres', deployed: true,
    state: 'running', units: [{ name: `${id}-db.service`, active: true }, { name: `${id}-app.service`, active: true }],
    last_backup: null, problems: [], ...extra,
  };
}

function inspectResult(backup, { mode = 'inplace', hostname = 'dev-a', uid = 1001 } = {}) {
  return {
    backup: { ...backup, inspected: true, apps: [{ id: 'woowbk-demo', name: '示範筆記應用' }, { id: 'woowbk-wiki', name: '團隊知識庫' }], source: { hostname } },
    manifest: {
      backup_id: backup.id, created: backup.created, type: backup.type === 'safety' ? 'safety' : 'manual', note: '跨機測試',
      tool: { name: 'woowtech-cockpit-backup', version: '2026.11.13.1' },
      source: { hostname, arch: 'x86_64', os: 'Ubuntu 24.04.3 LTS', podman: '4.9.3', machine_id_sha256: 'b'.repeat(64) },
      consistency: { method: 'writers-stopped', downtime_seconds: 7 }, total_size: 50 * MiB,
      format: backup.format === 1 ? 1 : 2, encryption: backup.encrypted === false ? 'none' : 'age-x25519',
      apps: [
        { id: 'woowbk-demo', name: '示範筆記應用', adapter: 'quadlet-postgres', owner: { name: 'appowner', uid },
          images: [{ ref: 'docker.io/library/postgres:16-alpine', included: true }, { ref: 'localhost/woowbk-demo-app:1', included: true }],
          postgres: [{ id: 'main', database: 'notes', major: 16 }], volumes: [{ name: 'woowbk-demo-files' }],
          secrets_count: 2, config_files_count: 1, verify_snapshot: VERIFY_BEFORE },
        { id: 'woowbk-wiki', name: '團隊知識庫', adapter: 'quadlet-postgres', owner: { name: 'appowner', uid },
          images: [{ ref: 'docker.io/library/postgres:16-alpine', included: false }], postgres: [{ id: 'main', database: 'wiki', major: 16 }],
          volumes: [], secrets_count: 1, config_files_count: 0, verify_snapshot: {} },
      ],
    },
    preflight: {
      ok: true,
      checks: [
        { id: 'archive', status: 'ok', message: '備份檔格式與金鑰檢查通過；還原前會再完整驗證全部內容。' },
        { id: 'space', status: 'ok', message: '本設備空間足夠（可用 30.0 GiB）。' },
      ],
      apps: [
        { id: 'woowbk-demo', name: '示範筆記應用', restorable: true, mode, checks: [
          { id: 'woowbk-demo/images', status: 'ok', message: '容器映像已包含在備份中。' },
          { id: 'woowbk-demo/uid', status: 'warn', message: `備份來源的擁有者 UID（${uid}）與本設備不同，會以本設備的 appowner 寫入。` }] },
        { id: 'woowbk-wiki', name: '團隊知識庫', restorable: false, mode: 'fresh', checks: [
          { id: 'woowbk-wiki/catalog', status: 'fail', message: '此設備沒有設定這個應用，無法還原。' }] },
      ],
    },
  };
}

// Host directories (主機資料夾, catalog `data_dirs`) as the manifest summary lists them (paths relative to the owner's
// home), plus preflight checks with ids this page has never seen: they must render generically. The demo database is
// kept as files here (the cold pattern), so it has no pg_dump entry.
const HA_DIR = 'homeassistant/config-preinstalled';
const NC_DB_DIR = '.local/share/nextcloud-office/postgres';
const DIR_CHECKS = [
  { id: 'woowbk-demo/data-dir', status: 'ok', message: '主機資料夾 ~/homeassistant/config-preinstalled 已存在，將以備份內容整個取代。' },
  { id: 'woowbk-demo/data-dir-space', status: 'warn', message: '還原期間主機資料夾的新舊內容會同時存在：需要約 160.0 MiB，擁有者家目錄可用 2.0 GiB。' },
  { id: 'woowbk-demo/data-dir-idmap', status: 'ok', message: '主機資料夾內檔案擁有者的最大 UID／GID（100999）在 appowner 的使用者命名空間對應範圍內。' },
];
const DIR_ROWS = [[`~/${HA_DIR}`, '74.0 MiB'], [`~/${NC_DB_DIR}`, '資料庫資料（冷備份）']];

function withHostDirs(data, { mode = 'inplace', dirs = [{ path: HA_DIR, size: 74 * MiB }, { path: NC_DB_DIR, label: '資料庫資料（冷備份）' }] } = {}) {
  for (const result of Object.values(data.inspect)) {
    Object.assign(result.manifest.apps.find(item => item.id === 'woowbk-demo'), { postgres: [], data_dirs: structuredClone(dirs) });
    const planned = result.preflight.apps.find(item => item.id === 'woowbk-demo');
    planned.mode = mode;
    planned.checks.push(...structuredClone(DIR_CHECKS));
  }
  return data;
}

function fixture(overrides = {}) {
  const manual = backupMeta(B_MANUAL, { note: '每日備份', include_images: true });
  const safety = backupMeta(B_SAFETY, { type: 'safety', note: '還原前自動備份（還原來源 20261101T020000Z-11112222）', verified: null,
    format: 1, filename: 'woowtech-backup-dev-a-20261110-153000.woowbackup' });
  const uploaded = backupMeta(B_UPLOADED, {
    type: 'uploaded', note: '', apps: [], key_id: OTHER_KEY_ID, key_available: false, inspected: false, verified: null,
    source: null, uploaded_at: '2026-11-13T01:02:00Z', filename: 'woowtech-backup-dev-b-20261113-010000.tar',
  });
  const data = {
    allowed: true, latency: 0, ackMode: 'auto', channelFailure: null, failures: [], hold: [],
    status: {
      version: '2026.11.13.1', host: { hostname: 'dev-a', arch: 'x86_64', os: 'Ubuntu 24.04.3 LTS', podman: '4.9.3' },
      storage: { path: '/var/lib/woowtech-backup', free_bytes: 30 * GiB, total_bytes: 100 * GiB, backups_bytes: 144 * MiB, backup_count: 3 },
      key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: true }, imported_keys: [],
      apps: [
        app('woowbk-demo', '示範筆記應用', { last_backup: { id: B_MANUAL, created: manual.created } }),
        app('woowbk-wiki', '團隊知識庫', { deployed: false, state: 'not-deployed',
          units: [{ name: 'woowbk-wiki-db.service', active: false }, { name: 'woowbk-wiki-app.service', active: false }] }),
      ],
      active_job: null, warnings: [],
      settings: { encrypt_by_default: true, problem: null, plaintext_warning: PLAINTEXT },
    },
    backups: [manual, safety, uploaded],
    exports: [],
    kit: { key_id: KEY_ID, filename: `woowtech-backup-key-dev-a-${KEY_ID}.txt`, content: kitText(SECRET, KEY_ID) },
    secrets: { [OTHER_SECRET]: OTHER_KEY_ID, [SECRET]: KEY_ID },
    inspect: {
      [B_MANUAL]: inspectResult(manual),
      [B_SAFETY]: inspectResult(safety),
      [B_UPLOADED]: inspectResult({ ...uploaded, created: '2026-11-13T01:00:00Z' }, { mode: 'inplace', hostname: 'dev-b', uid: 1007 }),
      [B_NEW]: inspectResult(backupMeta(B_NEW)),
      [B_SAFETY_NEW]: inspectResult(backupMeta(B_SAFETY_NEW, { type: 'safety' })),
    },
    upload: {
      begin: { upload_id: UPLOAD_ID, path: UPLOAD_PATH, max_size: 20 * GiB },
      finish: uploaded,
    },
    downloads: Object.fromEntries([B_MANUAL, B_SAFETY, B_UPLOADED, B_NEW].map(id => {
      const extension = id === B_SAFETY ? 'woowbackup' : 'tar';
      return [id, { path: `/var/lib/woowtech-backup/archives/${id}.${extension}`, size: 48 * MiB,
        filename: `woowtech-backup-dev-a-${id.slice(0, 8)}-${id.slice(9, 15)}.${extension}` }];
    })),
    exportFiles: { [EXPORT_ID]: { path: `/var/lib/woowtech-backup/exports/${EXPORT_ID}.tar`, filename: EXPORT_NAME, size: 96 * MiB,
      expires: EXPORT_EXPIRES, backup_id: B_MANUAL } },
    retention: null,
    catalogData: null,
    // 排程備份 (2026.11.17.1): null is an engine older than the schedule (no status.schedule, commands unknown).
    schedule: scheduleData(),
    scripts: scripts(),
    jobs: {},
    ...overrides,
  };
  return data;
}

// The schedule as the engine keeps it (schedule.json, schedule-state.json, the timer), with the fixture's clock:
// 2026-11-17 10:00 UTC is Tuesday 18:00 in Asia/Taipei. Off and never saved, like a fresh install. `unusable`: a saved
// file the engine cannot use (the settings are then the defaults, `defaults` in schedule-get).
const SCHEDULE_NOW = '2026-11-17T10:00:00Z';
const ALL_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
function scheduleData(extra = {}) {
  return {
    now: SCHEDULE_NOW,
    settings: { enabled: false, days: [...ALL_DAYS], time: '03:00', apps: 'all', include_images: false, keep_last: 7, updated: null, armed_at: null },
    saved: false, problem: null, unusable: false, writes: 0,
    timezone: { name: 'Asia/Taipei', utc_offset: '+08:00' },
    timer: { enabled: true, active: true, last_tick_age: 140 },
    last_run: null, waiting: null, attention: null, events: [], protected: {}, summaryNull: false,
    ...extra,
  };
}

// Served in place of base1/cockpit.js. Runs inside the page; only reads window.__fixture.
function installCockpitFixture() {
  const data = window.__fixture;
  window.testcalls = [];
  window.testchannels = [];
  window.testjumps = [];
  window.fixtureErrors = [];
  data.waiting = [];
  const ACTIVE = ['queued', 'running'];
  const TERMINAL = ['succeeded', 'failed', 'rolled-back', 'interrupted', 'cancelled'];
  const SPECS = {
    inspect: { required: ['backup_id'], optional: ['key', 'save_key'] },
    'key-confirm': { required: ['key_id'], optional: [] },
    'key-import': { required: ['key'], optional: [] },
    'backup-start': { required: ['apps', 'request_id'], optional: ['include_images', 'note', 'encrypt', 'acknowledge_plaintext'] },
    'verify-start': { required: ['backup_id', 'request_id'], optional: ['key'] },
    'restore-start': { required: ['backup_id', 'apps', 'request_id', 'confirm'], optional: ['key', 'save_key', 'allow_no_safety', 'accept_unauthenticated', 'acknowledged'] },
    'settings-set': { required: ['encrypt_by_default'], optional: ['acknowledge_plaintext'] },
    'export-start': { required: ['backup_id', 'request_id', 'confirm'], optional: ['key'] },
    'export-info': { required: ['export_id'], optional: [] }, 'export-delete': { required: ['export_id'], optional: [] },
    'catalog-suggest': { required: [], optional: ['owner'] },
    'catalog-install': { required: ['entry'], optional: ['confirm', 'expected_sha256'] },
    'catalog-remove': { required: ['id'], optional: ['confirm', 'expected_sha256'] },
    'retention-plan': { required: [], optional: ['policy'] },
    'retention-apply': { required: ['confirm', 'backup_ids'], optional: ['policy'] },
    'schedule-set': { required: ['schedule'], optional: ['confirm'] },
    'schedule-run-now': { required: ['request_id'], optional: [] },
    'job-status': { required: ['job_id'], optional: [] }, 'job-cancel': { required: ['job_id'], optional: ['after_this'] },
    delete: { required: ['backup_id'], optional: [] }, 'upload-begin': { required: ['filename', 'size'], optional: [] },
    'upload-finish': { required: ['upload_id'], optional: [] }, 'upload-abort': { required: ['upload_id'], optional: [] },
    'download-info': { required: ['backup_id'], optional: [] },
    // 從 HA 備份匯入 (DESIGN §6, CONTRACT §7).
    'ha-check-start': { required: ['ha_backup_id', 'apps', 'request_id'], optional: ['key', 'choices'] },
    // HAOS parity: the whole import, with the customer's one confirmation (CONTRACT §7 ha-import-start).
    'ha-import-start': { required: ['ha_backup_id', 'apps', 'test_mode', 'then_restore', 'request_id', 'confirm'],
      optional: ['overwrite', 'acknowledged', 'choices', 'check_job_id', 'key'] },
    'ha-convert-start': { required: ['ha_backup_id', 'apps', 'test_mode', 'request_id', 'confirm'], optional: ['odoo_database', 'key'] },
    'ha-delete': { required: ['ha_backup_id', 'confirm'], optional: [] },
  };
  const NO_INPUT = ['status', 'list', 'key-init', 'key-kit', 'jobs', 'settings-get', 'schedule-get'];
  const PHASE_LABELS = {
    backup: [['prepare', '準備'], ['check', '檢查空間與應用'], ['stop', '暫停應用寫入'], ['dump', '匯出資料庫'],
      ['export', '匯出資料卷與設定'], ['start', '恢復應用'], ['package', '加密封裝'], ['verify', '驗證備份']],
    restore: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['preflight', '相容性檢查'], ['stage', '預先寫入主機資料夾'],
      ['safety', '建立還原前備份'], ['stop', '停止應用'], ['restore', '還原資料'], ['start', '啟動應用'], ['check', '健康與資料核對']],
    verify: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['check', '核對結果']],
    export: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['package', '封裝未加密副本'], ['verify', '驗證副本']],
    'ha-check': [['prepare', '準備'], ['decrypt', '解開 HA 備份'], ['check', '檢查內容與版本']],
    'ha-convert': [['prepare', '準備'], ['decrypt', '解開 HA 備份'], ['convert', '轉換資料'], ['package', '封裝備份'], ['verify', '驗證備份']],
  };
  // A stable stand-in for a sha256 (the page only compares and shortens it).
  const fakeSha = text => {
    let hash = 0x811c9dc5;
    for (const char of String(text)) hash = Math.imul(hash ^ char.codePointAt(0), 0x01000193) >>> 0;
    return hash.toString(16).padStart(8, '0').repeat(8);
  };
  const pretty = entry => JSON.stringify(entry, null, 2).split('\n');
  const unifiedDiff = (old, now, name) => {
    const before = old ? pretty(old) : [];
    const after = now ? pretty(now) : [];
    const lines = [`--- ${name}（目前）`, `+++ ${name}（新）`, `@@ -1,${before.length} +1,${after.length} @@`];
    for (const line of before) if (!after.includes(line)) lines.push(`-${line}`);
    for (const line of after) lines.push(after.includes(line) && before.includes(line) ? ` ${line}` : `+${line}`);
    return lines;
  };
  let jobSeq = 0;
  const requests = {};

  function mixin(target) {
    const handlers = {};
    Object.defineProperties(target, {
      addEventListener: { value: (type, handler) => { (handlers[type] ||= []).push(handler); } },
      removeEventListener: { value: (type, handler) => { handlers[type] = (handlers[type] || []).filter(item => item !== handler); } },
      emit: { value: (type, detail) => {
        const event = new CustomEvent(type, { detail });
        for (const handler of [...(handlers[type] || [])]) handler.call(target, event, detail);
      } },
    });
    return target;
  }

  class Refusal extends Error {
    constructor(code, message, details = {}) { super(message); this.code = code; this.details = details; }
  }
  const active = () => Object.values(data.jobs).find(item => ACTIVE.includes(item.job.state));
  const backup = id => data.backups.find(item => item.id === id);
  const keyKnown = keyId => keyId === data.status.key?.key_id || data.status.imported_keys.some(item => item.key_id === keyId);
  const refreshKeys = () => data.backups.forEach(item => { item.key_available = item.encrypted === false || keyKnown(item.key_id); });

  // `phases` and `script` name the phase list and the steps when a job type has more than one kind (the HA jobs).
  function startJob(type, params, requestId, { phases = type, script = type } = {}) {
    if (typeof requestId !== 'string' || requestId.length < 8) throw new Refusal('invalid-request', '請求識別碼格式不正確。');
    if (requests[requestId]) return { job_id: requests[requestId], deduplicated: true };
    const running = active();
    if (running) throw new Refusal('busy', '已有備份或還原作業正在進行，請等它完成後再試。', { job_id: running.job.id });
    jobSeq += 1;
    const id = `j20261113T0200${String(10 + jobSeq).padStart(2, '0')}Z-${(0xabc000 + jobSeq).toString(16).padStart(8, '0')}`;
    const job = { id, type, state: 'queued', phase: 'prepare', phases: PHASE_LABELS[phases].map(([phase, label]) => ({ id: phase, label, state: 'pending' })),
      progress: { percent: 0, message: '等待開始' }, created: `2026-11-13T02:00:${String(10 + jobSeq).padStart(2, '0')}Z`, started: null,
      finished: null, params, result: null, error: null, cancellable: true };
    data.jobs[id] = { job, log: [`${job.created} 作業已排入背景執行`], steps: structuredClone(data.scripts[script] || []) };
    data.status.active_job = structuredClone(job);
    requests[requestId] = id;
    return { job_id: id, deduplicated: false };
  }

  const KNOWN = ['schema', 'id', 'name', 'description', 'owner', 'adapter', 'quadlet', 'units', 'writer_units', 'postgres', 'volumes',
    'data_dirs', 'secrets', 'config_files', 'health', 'verify'];
  const appsOf = id => data.backups.filter(item => (item.apps || []).some(app => app.id === id)).length;

  // A stand-in for the loader's validation: enough rules to show a field error, an unknown key and a conflict.
  function validateEntry(entry) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return { message: '應用設定必須是 JSON 物件。', details: { field: '' } };
    if (typeof entry.id !== 'string' || !/^[a-z0-9][a-z0-9-]{1,40}$/.test(entry.id)) return { message: '欄位 id 格式不正確。', details: { field: 'id' } };
    if (!Array.isArray(entry.units) || !entry.units.length) return { message: '欄位 units 至少需要一個服務。', details: { field: 'units' } };
    const unknown = Object.keys(entry).filter(key => !KNOWN.includes(key));
    if (unknown.length) return { message: `應用設定含有不支援的欄位：${unknown.join(', ')}。`, details: { field: unknown[0] } };
    const taken = (entry.volumes || []).map(item => item?.name).filter(name => (data.catalogData.taken || []).includes(name));
    if (taken.length) {
      const conflicts = taken.map(name => `資料卷 ${name} 已屬於應用「other-app」；同一個項目不可由兩個應用設定管理。`);
      return { message: conflicts[0], details: { conflicts } };
    }
    return null;
  }

  function catalogCommand(command, request) {
    const cat = data.catalogData;
    if (!cat) throw new Refusal('invalid-request', '不支援的指令。');
    if (command === 'catalog-suggest') {
      if (request.owner === undefined) return { owners: structuredClone(cat.owners) };
      const scan = cat.scans[request.owner];
      if (!scan) throw new Refusal('owner-missing', `找不到帳號 ${request.owner}。`);
      const result = structuredClone(scan);
      for (const app of result.apps) {
        const current = cat.installed[app.id];
        if (current && !app.installed) {
          // Like the engine's installed-mode: an installed app keeps the mode it was installed with.
          const kept = (app.variants || []).find(variant => JSON.stringify(variant.entry) === JSON.stringify(current.entry));
          if (kept) Object.assign(app, { variant: kept.id, entry: structuredClone(kept.entry) });
          app.installed = { id: app.id, sha256: current.sha256, entry: structuredClone(current.entry), changes: [], drift: [],
            same: JSON.stringify(current.entry) === JSON.stringify(app.entry) };
        }
      }
      return result;
    }
    if (command === 'catalog-install') {
      const entry = request.entry;
      const id = typeof entry?.id === 'string' ? entry.id : null;
      const current = id ? cat.installed[id] : null;
      const result = { preview: true, valid: false, error: null, id, file: id ? `${id}.json` : null,
        current: current ? { sha256: current.sha256, entry: structuredClone(current.entry), owner: current.entry.owner } : null,
        expected_sha256: current ? current.sha256 : null, new_sha256: null, changes: [], diff: [], compat: [], warnings: [], backups: 0, history: [] };
      if (id) {
        result.diff = unifiedDiff(current?.entry, entry, `${id}.json`);
        result.backups = appsOf(id);
        if (current) {
          result.changes = Object.keys({ ...current.entry, ...entry }).filter(key => JSON.stringify(current.entry[key]) !== JSON.stringify(entry[key]))
            .map(key => ({ path: key, op: !(key in current.entry) ? 'add' : !(key in entry) ? 'remove' : 'change', old: current.entry[key], new: entry[key] }));
          if (JSON.stringify(current.entry.volumes) !== JSON.stringify(entry.volumes)) result.compat.push('新增的資料卷讓這個應用較舊的備份在新設定下無法還原。');
          result.history = [`${id}.20261112T020000Z.1a2b3c4d.json`];
        }
      }
      const problem = validateEntry(entry);
      if (problem) {
        result.error = { code: 'invalid-request', message: problem.message, details: problem.details };
        if (request.confirm) throw new Refusal('invalid-request', problem.message, problem.details);
        return result;
      }
      result.valid = true;
      result.new_sha256 = fakeSha(JSON.stringify(entry));
      if (!entry.quadlet?.template_dir) result.warnings.push('沒有部署範本（quadlet.template_dir）：只能在已部署此應用的設備上原位還原。');
      if (current && result.new_sha256 === current.sha256) result.warnings.push('與目前安裝的設定完全相同。');
      if (!request.confirm) return result;
      if ((request.expected_sha256 ?? null) !== result.expected_sha256) {
        throw new Refusal('invalid-request', '安裝的應用設定在預覽之後被變更了。', { reason: 'entry-changed', current_sha256: result.expected_sha256 });
      }
      cat.installed[id] = { entry: structuredClone(entry), sha256: result.new_sha256 };
      // The settings a backup carries (2026.11.15.2), installed: the next inspect compares them with these.
      for (const inspected of Object.values(data.inspect)) {
        for (const app of inspected.preflight.apps) {
          if (app.id !== id || !app.settings) continue;
          const same = JSON.stringify(app.settings.entry) === JSON.stringify(entry);
          app.settings.state = same ? 'same' : 'different';
          app.checks = app.checks.filter(check => check.id !== `${id}/catalog`);
          if (!same) app.checks.push({ id: `${id}/catalog`, status: 'warn', message: '此設備的應用設定與備份時不同；將以此設備的設定為準。也可以審查並改用備份中附上的設定。' });
          app.restorable = !app.checks.some(check => check.status === 'fail');
        }
      }
      if (!data.status.apps.some(app => app.id === id)) {
        data.status.apps.push({ id, name: entry.name || id, description: entry.description || '', owner: entry.owner, adapter: 'quadlet-postgres',
          deployed: true, state: 'running', units: (entry.units || []).map(name => ({ name, active: true })), last_backup: null, problems: [] });
      }
      return { installed: true, id, file: `${id}.json`, sha256: result.new_sha256,
        previous: current ? { sha256: current.sha256, backup: `${id}.20261113T020000Z.${current.sha256.slice(0, 8)}.json` } : null,
        changes: result.changes, compat: result.compat, warnings: result.warnings, backups: result.backups };
    }
    const current = cat.installed[request.id];
    if (!current) throw new Refusal('not-found', `沒有安裝應用「${request.id}」的設定。`);
    const backups = appsOf(request.id);
    if (!request.confirm) {
      return { preview: true, id: request.id, file: `${request.id}.json`, current: { sha256: current.sha256, entry: structuredClone(current.entry), owner: current.entry.owner },
        expected_sha256: current.sha256, backups, history: [], diff: unifiedDiff(current.entry, null, `${request.id}.json`),
        warnings: backups ? [`這個應用的 ${backups} 份備份會保留，但在重新安裝它的應用設定之前無法還原。`] : [] };
    }
    if ((request.expected_sha256 ?? null) !== current.sha256) throw new Refusal('invalid-request', '安裝的應用設定在預覽之後被變更了。', { reason: 'entry-changed' });
    delete cat.installed[request.id];
    data.status.apps = data.status.apps.filter(app => app.id !== request.id);
    return { removed: true, id: request.id, sha256: current.sha256, backup: `${request.id}.20261113T020000Z.${current.sha256.slice(0, 8)}.json`, backups };
  }

  // retention.plan / apply_command in miniature: keep-last-N of manual backups per app, protected ids never deleted.
  function retentionCommand(command, request) {
    const ret = data.retention;
    if (!ret) throw new Refusal('invalid-request', '不支援的指令。');
    const valid = value => value === null || (Number.isInteger(value) && value >= 1 && value <= 1000);
    if (request.policy && (!valid(request.policy.default_keep_last ?? null) ||
      Object.values(request.policy.apps || {}).some(item => !valid(item?.keep_last ?? null)))) {
      throw new Refusal('invalid-request', '保留原則 keep_last 必須是 1 到 1000 的整數或 null。', { field: 'policy' });
    }
    const policy = request.policy ? { schema: 1, default_keep_last: request.policy.default_keep_last ?? null, apps: structuredClone(request.policy.apps || {}) }
      : structuredClone(ret.saved);
    const keep = id => (policy.apps[id] ? policy.apps[id].keep_last : policy.default_keep_last);
    const brief = (item, reason) => ({ id: item.id, type: item.type, created: item.created, size: item.size, note: item.note || '',
      apps: (item.apps || []).map(app => ({ id: app.id, name: app.name || app.id })), ...(reason ? { reason } : {}) });
    // Two pools (2026.11.17.1): the manual policy never counts or deletes a scheduled backup.
    const manual = data.backups.filter(item => item.type === 'manual' && item.scheduled !== true).sort((a, b) => b.created.localeCompare(a.created));
    const rank = {};
    const positions = {};
    for (const item of manual) {
      positions[item.id] = {};
      for (const app of item.apps || []) { rank[app.id] = (rank[app.id] || 0) + 1; positions[item.id][app.id] = rank[app.id]; }
    }
    const candidates = [];
    const blocked = [];
    for (const item of manual) {
      const limits = (item.apps || []).map(app => [app, keep(app.id)]);
      if (!limits.length || limits.some(([, limit]) => limit === null) || !limits.every(([app, limit]) => positions[item.id][app.id] > limit)) continue;
      const reason = `超出保留份數：${limits.map(([app, limit]) => `「${app.name || app.id}」第 ${positions[item.id][app.id]} 新（保留最新 ${limit} 份）`).join('、')}`;
      if (ret.protected[item.id]) blocked.push(brief(item, ret.protected[item.id]));
      else candidates.push(brief(item, reason));
    }
    if (command === 'retention-plan') {
      return { policy, saved_policy: structuredClone(ret.saved), proposed: Boolean(request.policy), policy_problem: ret.problem || null,
        usage: structuredClone(ret.usage), candidates, blocked, freed_bytes: candidates.reduce((sum, item) => sum + item.size, 0),
        protected: Object.entries(ret.protected).filter(([id]) => backup(id)).map(([id, reason]) => brief(backup(id), reason)) };
    }
    if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
    if (request.policy) ret.saved = policy;
    const deleted = [];
    const skipped = [];
    for (const id of request.backup_ids) {
      const item = backup(id);
      if (!item) skipped.push({ id, reason: '找不到這份備份。' });
      else if (ret.protected[id]) skipped.push({ id, reason: ret.protected[id] });
      else {
        deleted.push(brief(item));
        data.backups = data.backups.filter(entry => entry.id !== id);
      }
    }
    return { policy: structuredClone(ret.saved), policy_problem: null, deleted, skipped, freed_bytes: deleted.reduce((sum, item) => sum + item.size, 0) };
  }

  // 排程備份 in miniature (schedule.py, cli.py): slots in the device zone's fixed offset (the fixture's zones keep no
  // DST at these dates), the gate, the scheduled pool's keep-last preview, the summary with the last run read live
  // from its job record. Nothing is saved without `confirm: true` (`writes` counts the saves).
  const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
  const scheduleOrRefuse = () => {
    if (!data.schedule) throw new Refusal('invalid-request', '不支援的指令。');
    return data.schedule;
  };
  const minutesOf = text => {
    const match = /^([+-])(\d{2}):(\d{2})$/.exec(text || '');
    return match ? (match[1] === '-' ? -1 : 1) * (Number(match[2]) * 60 + Number(match[3])) : 0;
  };
  const isoOf = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  // An instant in the device's time (its fixed offset), YYYY-MM-DDTHH:MM like the engine's `local` texts.
  const localOf = iso => (iso ? isoOf(Date.parse(iso) + minutesOf(data.schedule.timezone.utc_offset) * 60000).slice(0, 16) : null);
  function nextRuns(settings, count = 3) {
    const sched = data.schedule;
    if (!settings.enabled) return [];
    const offset = minutesOf(sched.timezone.utc_offset);
    const now = Date.parse(sched.now);
    const wall = new Date(now + offset * 60000);
    const [hour, minute] = settings.time.split(':').map(Number);
    const runs = [];
    for (let day = 0; runs.length < count && day < 15; day += 1) {
      const local = Date.UTC(wall.getUTCFullYear(), wall.getUTCMonth(), wall.getUTCDate() + day, hour, minute);
      const at = local - offset * 60000;
      if (at <= now || !settings.days.includes(DAYS[(new Date(local).getUTCDay() + 6) % 7])) continue;
      runs.push({ at: isoOf(at), local: isoOf(local).slice(0, 16), utc_offset: sched.timezone.utc_offset });
    }
    return runs;
  }
  function scheduleGate() {
    const encrypt = data.status.settings ? data.status.settings.encrypt_by_default !== false : true;
    const key = data.status.key;
    return { encrypt, device_key: Boolean(key), kit_confirmed: Boolean(key?.kit_confirmed),
      blocked: encrypt && !key ? 'no-device-key' : encrypt && !key.kit_confirmed ? 'kit-unconfirmed' : null };
  }
  function validSchedule(schedule) {
    const keys = Object.keys(schedule || {}).sort().join(',');
    if (keys !== 'apps,days,enabled,include_images,keep_last,time') return `keys ${keys}`;
    if (typeof schedule.enabled !== 'boolean' || typeof schedule.include_images !== 'boolean') return 'booleans';
    if (!Array.isArray(schedule.days) || !schedule.days.length || schedule.days.some(day => !DAYS.includes(day)) ||
      JSON.stringify(schedule.days) !== JSON.stringify(DAYS.filter(day => schedule.days.includes(day)))) return `days ${schedule.days}`;
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(schedule.time) || Number(schedule.time.slice(3)) % 5) return `time ${schedule.time}`;
    if (schedule.apps !== 'all' && (!Array.isArray(schedule.apps) || !schedule.apps.length || new Set(schedule.apps).size !== schedule.apps.length)) return 'apps';
    if (schedule.keep_last !== null && !(Number.isInteger(schedule.keep_last) && schedule.keep_last >= 1 && schedule.keep_last <= 1000)) return 'keep_last';
    return null;
  }
  // retention.schedule_plan: the next run's backup counts as the newest of each app; protected ones are `blocked`.
  function schedulePlan(appIds, keep) {
    if (keep === null || !appIds.length) return { delete: [], blocked: [], freed_bytes: 0 };
    const pool = data.backups.filter(item => item.type === 'manual' && item.scheduled === true).sort((a, b) => b.created.localeCompare(a.created));
    const rank = Object.fromEntries(appIds.map(id => [id, 1]));
    const positions = {};
    for (const item of pool) {
      positions[item.id] = {};
      for (const app of item.apps || []) { rank[app.id] = (rank[app.id] || 0) + 1; positions[item.id][app.id] = rank[app.id]; }
    }
    const brief = (item, reason) => ({ id: item.id, type: item.type, created: item.created, size: item.size, note: item.note || '',
      apps: (item.apps || []).map(app => ({ id: app.id, name: app.name || app.id })), scheduled: true, reason });
    const removals = [];
    const blocked = [];
    for (const item of pool) {
      const apps = item.apps || [];
      if (!apps.length || !apps.some(app => appIds.includes(app.id)) || !apps.every(app => positions[item.id][app.id] > keep)) continue;
      const reason = `超出排程備份的保留份數：${apps.map(app => `「${app.name || app.id}」第 ${positions[item.id][app.id]} 新（保留最新 ${keep} 份）`).join('、')}`;
      if (data.schedule.protected[item.id]) blocked.push(brief(item, data.schedule.protected[item.id]));
      else removals.push(brief(item, reason));
    }
    return { delete: removals, blocked, freed_bytes: removals.reduce((sum, item) => sum + item.size, 0) };
  }
  // schedule.last_run_view: the result follows the job record while it exists.
  function lastRun() {
    const last = data.schedule.last_run;
    const record = last?.job_id ? data.jobs[last.job_id] : null;
    if (!last || !record) return structuredClone(last);
    const job = record.job;
    const result = ACTIVE.includes(job.state) ? job.state : job.state === 'succeeded' ? (job.result?.partial ? 'partial' : 'succeeded') : job.state;
    return { ...structuredClone(last), state: job.state, result, backup_id: job.result?.backup_id || last.backup_id, finished: job.finished,
      finished_local: localOf(job.finished), skipped_apps: structuredClone(job.result?.skipped_apps || []), error: job.error ? structuredClone(job.error) : null };
  }
  function scheduleSummary() {
    const sched = data.schedule;
    if (sched.summaryNull) return null;
    const enabled = sched.settings.enabled && !sched.problem;
    return { enabled, saved: sched.saved, problem: sched.problem, days: [...sched.settings.days], time: sched.settings.time,
      apps: structuredClone(sched.settings.apps), include_images: sched.settings.include_images, keep_last: sched.settings.keep_last,
      next_run: enabled ? nextRuns(sched.settings, 1)[0] || null : null, last_run: lastRun(), waiting: structuredClone(sched.waiting),
      attention: structuredClone(sched.attention), timezone: structuredClone(sched.timezone), timer: structuredClone(sched.timer) };
  }

  function scheduleCommand(command, request) {
    const sched = scheduleOrRefuse();
    if (command === 'schedule-get') {
      return { schedule: { ...structuredClone(sched.settings), saved: sched.saved, problem: sched.problem, defaults: sched.unusable || !sched.saved },
        next_runs: sched.settings.enabled && !sched.problem ? nextRuns(sched.settings) : [], timer: structuredClone(sched.timer),
        last_run: lastRun(), waiting: structuredClone(sched.waiting), attention: structuredClone(sched.attention),
        events: structuredClone(sched.events), timezone: structuredClone(sched.timezone), gate: scheduleGate() };
    }
    if (command === 'schedule-set') {
      const invalid = validSchedule(request.schedule);
      if (invalid) {
        window.fixtureErrors.push(`schedule-set: ${invalid}`);
        throw new Refusal('invalid-request', '排程設定不正確。', { field: 'schedule' });
      }
      const proposed = structuredClone(request.schedule);
      const missing = Array.isArray(proposed.apps) ? proposed.apps.find(id => !data.status.apps.some(app => app.id === id)) : null;
      if (missing) throw new Refusal('app-not-in-catalog', `此設備沒有設定應用 ${missing}，無法處理。`, { app: missing });
      if (proposed.enabled) {
        const gate = scheduleGate();
        if (gate.blocked === 'no-device-key') throw new Refusal('no-device-key', '開啟排程備份前，請先到「加密金鑰」建立這台設備的加密金鑰，並保存緊急金鑰。');
        if (gate.blocked === 'kit-unconfirmed') throw new Refusal('invalid-request', '開啟排程備份前，請先保存緊急金鑰。', { reason: 'kit-unconfirmed', field: 'schedule.enabled' });
      }
      const before = sched.settings;
      const rearmed = proposed.enabled && (!before.enabled || !before.armed_at || before.time !== proposed.time || before.days.join() !== proposed.days.join());
      const record = { ...proposed, updated: sched.now, armed_at: rearmed ? sched.now : before.armed_at };
      const confirmed = request.confirm === true;
      if (confirmed) Object.assign(sched, { settings: record, saved: true, problem: null, unusable: false, writes: sched.writes + 1 });
      const apps = proposed.apps === 'all' ? data.status.apps.map(app => app.id) : proposed.apps;
      const plan = schedulePlan(apps, proposed.keep_last);
      return { saved: confirmed, schedule: { ...structuredClone(record), saved: confirmed || sched.saved, problem: null, defaults: false }, next_runs: nextRuns(proposed),
        retention: { keep_last: proposed.keep_last, apps, delete: plan.delete, blocked: plan.blocked, freed_bytes: plan.freed_bytes },
        timezone: structuredClone(sched.timezone) };
    }
    if (sched.problem) throw new Refusal('invalid-request', sched.problem, { reason: 'settings-problem' });
    if (!sched.saved) throw new Refusal('invalid-request', '請先儲存排程設定，再立即執行一次。', { reason: 'not-saved' });
    const settings = sched.settings;
    const apps = settings.apps === 'all' ? data.status.apps.map(app => app.id) : settings.apps;
    const encrypt = data.status.settings ? data.status.settings.encrypt_by_default !== false : true;
    if (encrypt && !data.status.key) throw new Refusal('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。');
    const started = startJob('backup', { apps, include_images: settings.include_images, note: '排程備份', encrypt,
      schedule: { slot: null, trigger: 'run-now', keep_last: settings.keep_last } }, request.request_id);
    if (!started.deduplicated) {
      sched.last_run = { slot: null, local: null, job_id: started.job_id, trigger: 'run-now', state: 'queued', result: 'queued', backup_id: null,
        started: sched.now, started_local: localOf(sched.now), finished: null, finished_local: null, skipped_apps: [], error: null };
    }
    return started;
  }

  // 從 HA 備份匯入 in miniature (DESIGN §6, cli.py): a start opens every selected encrypted add-on (`addons[].encrypted`)
  // with the key before any job exists, so key-required and wrong-key refuse the start (review F-03, F-04). The engine
  // drops a key the chosen add-ons do not need (key_provided false); the page never sends one (a fixture error).
  // ha-convert-start first refuses an app this device lacks and, with 預設加密 on, a device without its key (F-05).
  // `jobKeyFailure` ('key-required' | 'wrong-key') runs the rare key failure inside the job instead (HA's older formats).
  function haCommand(command, request) {
    const ha = data.ha;
    if (!ha) throw new Refusal('invalid-request', '不支援的指令。');
    const meta = ha.backups.find(item => item.id === request.ha_backup_id);
    if (!meta) throw new Refusal('not-found', '找不到指定的 HA 備份。');
    if (command === 'ha-delete') {
      if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
      const running = active();
      if (running?.job.params?.ha_backup_id === meta.id) {
        throw new Refusal('busy', '這份 HA 備份正被進行中的作業使用，請等作業完成後再刪除。', { job_id: running.job.id });
      }
      ha.backups = ha.backups.filter(item => item.id !== meta.id);
      return {};
    }
    if (!Array.isArray(request.apps) || !request.apps.length) {
      window.fixtureErrors.push(`${command}: apps ${JSON.stringify(request.apps)}`);
      throw new Refusal('invalid-request', '欄位 apps 不正確。', { field: 'apps' });
    }
    const selected = request.apps.map(id => {
      const item = (meta.importable_apps || []).find(entry => entry.app_id === id);
      if (!item) {
        window.fixtureErrors.push(`${command}: no add-on for ${id}`);
        throw new Refusal('invalid-request', `這份 HA 備份沒有可以匯入「${id}」的附加元件。`, { field: 'apps', app: id });
      }
      if (!item.installed) window.fixtureErrors.push(`${command}: ${id} is not installed here, the page never offers it`);
      return meta.addons.find(addon => addon.slug === item.slug);
    });
    const kind = command === 'ha-check-start' ? 'ha-check' : 'ha-convert';
    let encrypt = null;
    if (command === 'ha-convert-start') {
      if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
      if (typeof request.test_mode !== 'boolean') window.fixtureErrors.push('ha-convert-start: test_mode must be a boolean');
      if (request.apps.includes('odoo') !== (typeof request.odoo_database === 'string')) {
        window.fixtureErrors.push(`ha-convert-start: odoo_database ${request.odoo_database} for ${request.apps}`);
      }
      const missing = request.apps.find(id => !data.status.apps.some(app => app.id === id));
      if (missing) throw new Refusal('app-not-in-catalog', `請先到「應用軟體」安裝同版本的 ${missing}，再匯入。`, { app: missing });
      encrypt = data.status.settings ? data.status.settings.encrypt_by_default !== false : true;
      if (encrypt && !data.status.key) throw new Refusal('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。');
    }
    let key = request.key;
    if (selected.some(addon => addon?.encrypted === true)) {
      if (key === undefined) throw new Refusal('key-required', '這份 HA 備份已加密，請輸入 HA 備份金鑰。', { ha_backup_id: meta.id });
      if (key !== ha.key) throw new Refusal('wrong-key', 'HA 備份金鑰不正確，請確認後再試一次。');
    } else {
      if (key !== undefined) window.fixtureErrors.push(`${command}: a key for HA add-ons that are not encrypted`);
      key = undefined;
    }
    const script = ha.jobKeyFailure ? `${kind}-${ha.jobKeyFailure}` : kind;
    const params = { source: 'ha', ha_backup_id: meta.id, apps: [...request.apps], key_provided: key !== undefined };
    if (command === 'ha-check-start' && request.choices) params.choices = structuredClone(request.choices);
    if (command === 'ha-check-start') return startJob('verify', params, request.request_id, { phases: kind, script });
    return startJob('backup', { ...params, odoo_database: request.apps.includes('odoo') ? request.odoo_database : null,
      test_mode: request.test_mode, encrypt }, request.request_id, { phases: kind, script });
  }

  // ha-import-start in miniature (cli.py cmd_ha_import_start, hachain.py): the first job converts the first app, every job that
  // ends writes the next one (queued) before it is finished and carries `result.group` (next_job_id, every GroupResult known).
  // `data.ha.chain.outcomes[app] = {convert, restore}` decides what happens: convert 'ok' | 'fail' | 'confirmation-required',
  // restore 'ok' | 'rolled-back' | 'fail'; `data.ha.chain.backups[app]` is the backup a conversion adds.
  const KEY_RE = /^[a-z0-9.-]{4,70}:[0-9a-f]{16}$/;
  const GROUP_MESSAGES = {
    'rolled-back': () => '這個應用匯入失敗，已自動退回匯入前的狀態。這台的這個應用沒有任何變更；轉換好的備份還在備份列表，可以再試一次。',
    failed: () => '這個應用的轉換沒有成功。這台的這個應用沒有任何變更。',
    manual: () => '這個應用已經變更，沒有退回成功，需人工處理：請用匯入前備份還原。',
    'confirmation-required': () => '這次匯入和檢查時看到的不同，請再確認一次。這台的這個應用沒有任何變更。',
    'not-started': () => '匯入在這個應用開始之前就停止了。這台的這個應用沒有任何變更。',
    converted: () => '已轉換成備份，但匯入被停止，這台的這個應用沒有任何變更。轉換好的備份還在備份列表，要匯入時可以還原它。',
  };
  const stampOf = seq => `2026-11-13T02:${String(Math.floor(seq / 50)).padStart(2, '0')}:${String(10 + (seq % 50)).padStart(2, '0')}Z`;
  function nextJobId() {
    jobSeq += 1;
    return `j20261113T0200${String(10 + jobSeq).padStart(2, '0')}Z-${(0xabc000 + jobSeq).toString(16).padStart(8, '0')}`;
  }
  function groupResult(app, status, extra = {}) {
    return { app_id: app, status, convert_job_id: null, restore_job_id: null, backup_id: null, safety_backup_id: null, code: null, message: null, ...extra };
  }
  function chainJob(chain, index, step, results) {
    const id = nextJobId();
    const app = chain.apps[index];
    const type = step === 'convert' ? 'backup' : 'restore';
    const kind = step === 'convert' ? 'ha-convert' : 'restore';
    const params = step === 'convert'
      ? { source: 'ha', ha_backup_id: chain.haId, apps: [app], odoo_database: app === 'odoo' ? chain.database : null, test_mode: chain.testMode, encrypt: true, key_provided: false }
      : { backup_id: chain.backups[app].id, apps: [app], key_provided: false, ha_backup_id: chain.haId };
    params.group = { id: chain.group, index, count: chain.apps.length, kind: 'ha-import', step, app_id: app };
    params.chain = { apps: [...chain.apps], test_mode: chain.testMode, then_restore: chain.thenRestore, encrypt: true, key_provided: false, ha_backup_id: chain.haId,
      acknowledged: structuredClone(chain.acknowledged), choices: structuredClone(chain.choices), results: structuredClone(results) };
    const created = stampOf(jobSeq);
    const phases = PHASE_LABELS[kind].map(([phase, label]) => ({ id: phase, label, state: 'pending' }));
    const job = { id, type, state: 'queued', phase: 'prepare', phases, progress: { percent: 0, message: '等待開始' }, created, started: null, finished: null,
      params, result: null, error: null, cancellable: chain.uncancellable !== true };
    const running = structuredClone(job);
    Object.assign(running, { state: 'running', phase: PHASE_LABELS[kind][2][0], started: created, progress: { percent: 40, message: PHASE_LABELS[kind][2][1] },
      cancellable: chain.uncancellable !== true,
      phases: phases.map((item, position) => ({ ...item, state: position < 2 ? 'done' : position === 2 ? 'active' : 'pending' })) });
    const done = { state: 'succeeded', phase: PHASE_LABELS[kind].at(-1)[0], phases: phases.map(item => ({ ...item, state: 'done' })),
      progress: { percent: 100, message: '已完成' }, finished: created, cancellable: false };
    data.jobs[id] = { job, log: [`${created} 作業已排入背景執行`], steps: [{ job: running, log: [`${created} 階段：${running.progress.message}`] },
      { job: done, log: [`${created} 作業結束`], chainFinish: true }], chain: { ...chain, index, step, results: structuredClone(results) } };
    data.status.active_job = structuredClone(job);
    return job;
  }
  // The job just ended: decide what became of its app and what follows (hachain.conclude).
  function finishChainJob(record, { cancelled = false } = {}) {
    const chain = record.chain;
    const app = chain.apps[chain.index];
    const outcome = (chain.outcomes || {})[app] || {};
    const results = chain.results.filter(item => item.app_id !== app);
    let entry;
    let follow = null;
    let boundary = false;   // the app is over: the next one may start (a stop after this app is looked for here only)
    const nextApp = () => { boundary = true; return chain.index + 1 < chain.apps.length ? [chain.index + 1, 'convert'] : null; };
    if (chain.step === 'convert') {
      const convert = outcome.convert || 'ok';
      if (cancelled) {
        entry = groupResult(app, 'not-started', { code: 'cancelled', convert_job_id: record.job.id, message: GROUP_MESSAGES['not-started']() });
        record.job.state = 'cancelled';
      } else if (convert === 'fail') {
        entry = groupResult(app, 'failed', { code: 'corrupt-archive', convert_job_id: record.job.id, message: GROUP_MESSAGES.failed() });
        Object.assign(record.job, { state: 'failed', error: { code: 'corrupt-archive', message: '這個附加元件的資料損壞，無法轉換。' } });
        follow = nextApp();
      } else if (convert === 'confirmation-required') {
        entry = groupResult(app, 'skipped', { code: 'confirmation-required', convert_job_id: record.job.id, message: GROUP_MESSAGES['confirmation-required']() });
        Object.assign(record.job, { state: 'failed', error: { code: 'confirmation-required', message: entry.message } });
        follow = nextApp();
      } else {
        const meta = structuredClone(chain.backups[app]);
        if (!data.backups.some(item => item.id === meta.id)) data.backups.unshift(meta);
        record.job.result = { backup_id: meta.id, size: meta.size, apps: [app], encrypted: true, ha_import: structuredClone(meta.from_ha) };
        entry = groupResult(app, 'converted', { convert_job_id: record.job.id, backup_id: meta.id });
        follow = chain.thenRestore ? [chain.index, 'restore'] : nextApp();
      }
    } else {
      const restore = outcome.restore || 'ok';
      const convertJob = (chain.results.find(item => item.app_id === app) || {}).convert_job_id;
      const common = { convert_job_id: convertJob, restore_job_id: record.job.id, backup_id: chain.backups[app].id, safety_backup_id: chain.safety[app] };
      if (cancelled) {
        entry = groupResult(app, 'converted', { ...common, safety_backup_id: null, code: 'cancelled', message: GROUP_MESSAGES.converted() });
        record.job.state = 'cancelled';
      } else if (restore === 'ok') entry = groupResult(app, 'imported', common);
      else if (restore === 'rolled-back') {
        entry = groupResult(app, 'rolled-back', { ...common, code: 'job-failed', message: GROUP_MESSAGES['rolled-back']() });
        record.job.state = 'rolled-back';
      } else {
        entry = groupResult(app, 'failed', { ...common, code: 'job-failed', message: GROUP_MESSAGES.manual() });
        Object.assign(record.job, { state: 'failed', error: { code: 'job-failed', message: '還原失敗，自動退回也沒有成功。' } });
      }
      if (!cancelled) follow = nextApp();
      // What the restore job tells (RestoreResult): its warnings and, for a database service with other databases, the copy kept before.
      const told = { apps: [app] };
      if ((chain.restoreWarnings || {})[app]) told.warnings = [...chain.restoreWarnings[app]];
      const spec = (chain.kept || {})[app];
      if (spec && entry.status === 'imported') {
        const copy = structuredClone(spec.backup);
        if (!data.backups.some(item => item.id === copy.id)) data.backups.unshift(copy);
        data.downloads[copy.id] = { path: `/var/lib/woowtech-backup/archives/${copy.id}.tar`, filename: copy.filename, size: copy.size };
        // `pointer: false`: the converted backup does not name the copy; `told: false`: the restore result does not (the page has two sources).
        const converted = backup(chain.backups[app].id);
        if (converted?.from_ha && spec.pointer !== false) converted.from_ha.kept = copy.id;
        if (spec.told !== false) told.kept = { [app]: { backup_id: copy.id, ...structuredClone(spec.detail) } };
      }
      record.job.result = told;
    }
    results.push(entry);
    if (boundary && chain.stopAfter) follow = null;
    const nextId = follow ? chainJob(chain, follow[0], follow[1], results).id : null;
    if (!nextId) {
      for (const id of chain.apps.slice(chain.index + 1)) {
        if (!results.some(item => item.app_id === id)) results.push(groupResult(id, 'not-started', { code: cancelled ? 'cancelled' : 'stopped', message: GROUP_MESSAGES['not-started']() }));
      }
    }
    record.job.result = { ...(record.job.result || {}), group: { id: chain.group, index: chain.index, count: chain.apps.length, step: chain.step,
      next_job_id: nextId, results: structuredClone(results) } };
  }

  function haImportStart(request) {
    const ha = data.ha;
    if (!ha?.chain) throw new Refusal('invalid-request', '不支援的指令。');
    const meta = ha.backups.find(item => item.id === request.ha_backup_id);
    if (!meta) throw new Refusal('not-found', '找不到指定的 HA 備份。');
    const bad = text => { window.fixtureErrors.push(`ha-import-start: ${text}`); throw new Refusal('invalid-request', text, { field: text }); };
    if (request.confirm !== true) bad('confirm');
    if (typeof request.test_mode !== 'boolean' || typeof request.then_restore !== 'boolean') bad('flags');
    if (request.then_restore && request.overwrite !== true) bad('overwrite');
    if (!Array.isArray(request.apps) || !request.apps.length || new Set(request.apps).size !== request.apps.length) bad('apps');
    for (const [field, extra] of [['acknowledged', ['_shared']], ['choices', []]]) {
      for (const name of Object.keys(request[field] || {})) if (![...request.apps, ...extra].includes(name)) bad(`${field}.${name}`);
    }
    for (const [name, keys] of Object.entries(request.acknowledged || {})) {
      if (!Array.isArray(keys) || keys.length > 80 || new Set(keys).size !== keys.length || !keys.every(key => KEY_RE.test(key))) bad(`acknowledged.${name}`);
    }
    for (const [name, picks] of Object.entries(request.choices || {})) {
      for (const [kind, value] of Object.entries(picks)) if (!['addon', 'database', 'node'].includes(kind) || typeof value !== 'string') bad(`choices.${name}.${kind}`);
    }
    const missing = request.apps.find(id => !data.status.apps.some(item => item.id === id));
    if (missing) throw new Refusal('app-not-in-catalog', `請先到「應用軟體」安裝同版本的 ${missing}，再匯入。`, { app: missing });
    const encrypt = data.status.settings ? data.status.settings.encrypt_by_default !== false : true;
    let created = false;
    if (encrypt && !data.status.key) {
      data.status.key = { key_id: data.kit.key_id, created: '2026-11-13T02:00:00Z', kit_confirmed: false };
      created = true;
    }
    const selected = request.apps.map(id => meta.addons.find(addon => addon.slug === (meta.importable_apps.find(entry => entry.app_id === id) || {}).slug));
    if (selected.some(addon => addon?.encrypted === true)) {
      if (request.key === undefined) throw new Refusal('key-required', '這份 HA 備份已加密，請輸入 HA 備份金鑰。', { ha_backup_id: meta.id });
      if (request.key !== ha.key) throw new Refusal('wrong-key', 'HA 備份金鑰不正確，請確認後再試一次。');
    } else if (request.key !== undefined) window.fixtureErrors.push('ha-import-start: a key for add-ons that are not encrypted');
    if (typeof request.request_id !== 'string' || request.request_id.length < 8) throw new Refusal('invalid-request', '請求識別碼格式不正確。');
    if (requests[request.request_id]) return { job_id: requests[request.request_id], deduplicated: true, group: data.jobs[requests[request.request_id]].chain.group, key_created: false };
    const running = active();
    if (running) throw new Refusal('busy', '已有備份或還原作業正在進行，請等它完成後再試。', { job_id: running.job.id });
    const chain = { apps: [...request.apps], haId: meta.id, group: `g1a2b3c4d5e6f${String(jobSeq + 1).padStart(4, '0')}`,
      testMode: request.test_mode, thenRestore: request.then_restore, acknowledged: request.acknowledged || {}, choices: request.choices || {},
      database: ((request.choices || {}).odoo || {}).database ?? null, outcomes: ha.chain.outcomes || {}, backups: ha.chain.backups, safety: ha.chain.safety || {},
      uncancellable: ha.chain.uncancellable === true, kept: ha.chain.kept || {}, restoreWarnings: ha.chain.restoreWarnings || {} };
    const first = chainJob(chain, 0, 'convert', ha.chain.skipped ? structuredClone(ha.chain.skipped) : []);
    requests[request.request_id] = first.id;
    return { job_id: first.id, deduplicated: false, group: chain.group, key_created: created };
  }

  function handle(command, request) {
    switch (command) {
      case 'ha-import-start':
        return haImportStart(request);
      case 'ha-check-start':
      case 'ha-convert-start':
      case 'ha-delete':
        return haCommand(command, request);
      case 'status': {
        data.status.storage.backup_count = data.backups.length;
        // cli.py ha_usage: the uploaded HA backups, outside backups_bytes.
        if (data.ha) {
          Object.assign(data.status.storage, { ha_backups_bytes: data.ha.backups.reduce((sum, item) => sum + item.size, 0),
            ha_backup_count: data.ha.backups.length });
        }
        const result = structuredClone(data.status);
        if (data.schedule) result.schedule = scheduleSummary();
        return result;
      }
      case 'schedule-get':
      case 'schedule-set':
      case 'schedule-run-now':
        return scheduleCommand(command, request);
      case 'list':
        // An engine without HA imports (data.ha null) sends no ha_backups.
        return { backups: structuredClone(data.backups), exports: structuredClone(data.exports || []),
          ...(data.ha ? { ha_backups: structuredClone(data.ha.backups) } : {}) };
      case 'settings-set': {
        if (!request.encrypt_by_default && request.acknowledge_plaintext !== true) {
          throw new Refusal('invalid-request', `關閉預設加密前必須確認風險：${data.status.settings.plaintext_warning}`, { field: 'acknowledge_plaintext' });
        }
        data.status.settings = { ...data.status.settings, encrypt_by_default: request.encrypt_by_default, problem: null };
        return { settings: structuredClone(data.status.settings) };
      }
      case 'export-start': {
        if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
        const meta = backup(request.backup_id);
        if (!meta) throw new Refusal('not-found', '找不到指定的備份。');
        if (meta.encrypted === false) throw new Refusal('invalid-request', '這份備份沒有加密，可以直接下載，不需要建立未加密副本。');
        if (!keyKnown(meta.key_id) && request.key === undefined) throw new Refusal('key-required', '此備份使用的金鑰不在這台設備，請輸入緊急金鑰。', { key_id: meta.key_id });
        if (request.key !== undefined && data.secrets[request.key] !== meta.key_id) throw new Refusal('wrong-key', '金鑰不正確，無法解密這份備份。');
        return startJob('export', { backup_id: request.backup_id, key_provided: 'key' in request }, request.request_id);
      }
      case 'export-info': {
        const info = data.exportFiles[request.export_id];
        if (!info || !(data.exports || []).some(item => item.export_id === request.export_id)) throw new Refusal('not-found', '找不到這份未加密副本，它可能已過期並刪除。');
        return structuredClone(info);
      }
      case 'export-delete': {
        const before = (data.exports || []).length;
        data.exports = (data.exports || []).filter(item => item.export_id !== request.export_id);
        return { deleted: data.exports.length !== before };
      }
      case 'catalog-suggest':
      case 'catalog-install':
      case 'catalog-remove':
        return catalogCommand(command, request);
      case 'retention-plan':
      case 'retention-apply':
        return retentionCommand(command, request);
      case 'jobs':
        return { jobs: Object.values(data.jobs).map(item => structuredClone(item.job)).sort((a, b) => b.created.localeCompare(a.created)),
          ...(data.schedule ? { schedule_events: structuredClone(data.schedule.events) } : {}) };
      case 'key-init':
        if (!data.status.key) data.status.key = { key_id: data.kit.key_id, created: '2026-11-13T02:00:00Z', kit_confirmed: false };
        return { key: structuredClone(data.status.key), created: true };
      case 'key-kit':
        if (!data.status.key) throw new Refusal('no-device-key', '本設備尚未建立備份金鑰。');
        return structuredClone(data.kit);
      case 'key-confirm':
        if (request.key_id !== data.status.key?.key_id) throw new Refusal('invalid-request', '金鑰 ID 與本設備目前的備份金鑰不符。');
        data.status.key.kit_confirmed = true;
        return {};
      case 'key-import': {
        const keyId = data.secrets[request.key];
        if (!keyId) throw new Refusal('invalid-request', '金鑰格式不正確，請貼上以 AGE-SECRET-KEY-1 開頭的完整備份金鑰。');
        if (!data.status.imported_keys.some(item => item.key_id === keyId)) data.status.imported_keys.push({ key_id: keyId, created: '2026-11-13T02:30:00Z' });
        refreshKeys();
        return { key: { key_id: keyId, created: '2026-11-13T02:30:00Z' } };
      }
      case 'inspect': {
        const meta = backup(request.backup_id);
        let result = data.inspect[request.backup_id];
        if (!meta || !result) throw new Refusal('not-found', '找不到指定的備份。');
        // A backup converted from an HA backup holds only the apps that were converted.
        if (meta.from_ha) {
          const ids = meta.apps.map(app => app.id);
          result = structuredClone(result);
          for (const part of [result.backup.apps, result.manifest.apps, result.preflight.apps]) part.splice(0, part.length, ...part.filter(app => ids.includes(app.id)));
        }
        // X-PF-05 (HAOS parity): a key for a backup that is not encrypted is ignored, not refused.
        if (meta.encrypted !== false && !keyKnown(meta.key_id)) {
          if (request.key === undefined) throw new Refusal('key-required', '此備份使用的金鑰不在本設備，請輸入緊急金鑰。', { key_id: meta.key_id });
          if (data.secrets[request.key] !== meta.key_id) throw new Refusal('wrong-key', '金鑰不正確，無法解密這份備份。');
          if (request.save_key) {
            data.status.imported_keys.push({ key_id: meta.key_id, created: '2026-11-13T02:30:00Z' });
            refreshKeys();
          }
        }
        Object.assign(meta, { inspected: true, apps: structuredClone(result.backup.apps), source: structuredClone(result.backup.source) });
        // cli.py cmd_inspect: the backup as `list` has it, `from_ha` too (FIXPLAN §19a); the engine before that had none
        // (review F-01).
        const view = structuredClone(meta);
        if (data.ha?.legacy) delete view.from_ha;
        return { ...structuredClone(result), backup: view };
      }
      case 'backup-start': {
        if (!Array.isArray(request.apps) || !request.apps.length) throw new Refusal('invalid-request', '欄位 apps 必須是陣列。');
        const encrypt = request.encrypt ?? data.status.settings?.encrypt_by_default ?? true;
        if (encrypt && !data.status.key) throw new Refusal('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。');
        if (!encrypt && data.status.settings?.encrypt_by_default && request.acknowledge_plaintext !== true) {
          throw new Refusal('invalid-request', '建立未加密的備份前必須確認風險。', { field: 'acknowledge_plaintext' });
        }
        return startJob('backup', { apps: request.apps, include_images: Boolean(request.include_images), note: request.note || '', encrypt }, request.request_id);
      }
      case 'verify-start':
        if (!backup(request.backup_id)) throw new Refusal('not-found', '找不到指定的備份。');
        return startJob('verify', { backup_id: request.backup_id, key_provided: 'key' in request }, request.request_id);
      case 'restore-start':
        if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
        if (!backup(request.backup_id)) throw new Refusal('not-found', '找不到指定的備份。');
        if (backup(request.backup_id).unauthenticated && request.accept_unauthenticated !== true) {
          throw new Refusal('invalid-request', '這份上傳的備份沒有加密，內容無法驗證。', { field: 'accept_unauthenticated' });
        }
        return startJob('restore', { backup_id: request.backup_id, apps: request.apps, key_provided: 'key' in request && !request.save_key,
          ...(request.allow_no_safety ? { allow_no_safety: true } : {}),
          ...(request.accept_unauthenticated ? { accept_unauthenticated: true } : {}) }, request.request_id);
      case 'job-status': {
        const record = data.jobs[request.job_id];
        if (!record) throw new Refusal('not-found', '找不到指定的作業。');
        const step = record.steps.shift();
        if (step) {
          Object.assign(record.job, step.job);
          record.log.push(...(step.log || []));
          // An HA job answers for the apps (and the choices) of its own request.
          const haParams = record.job.params?.source === 'ha' ? record.job.params : null;
          if (haParams && record.job.result?.ha_check) {
            record.job.result.ha_check.apps = record.job.result.ha_check.apps.filter(app => haParams.apps.includes(app.app_id));
          }
          const source = haParams && data.ha?.backups.find(item => item.id === haParams.ha_backup_id);
          const choices = haParams && { ...(source ? { ha_backup_id: source.id, name: source.name, date: source.date } : {}),
            apps: haParams.apps, odoo_database: haParams.odoo_database, test_mode: haParams.test_mode };
          // The record of a conversion is the one of its HA backup and its own apps (haimport.py view_row), with its
          // database and test mode.
          const imported = choices && data.ha?.imports?.[choices.apps.join()];
          const importOf = base => ({ ...structuredClone(imported || base), ...choices });
          if (choices && record.job.result?.ha_import) record.job.result.ha_import = importOf(record.job.result.ha_import);
          if (choices && record.job.result?.apps) record.job.result.apps = [...choices.apps];
          if (step.addBackup) {
            const added = structuredClone(step.addBackup);
            if (choices && added.from_ha) {
              added.from_ha = importOf(added.from_ha);
              added.apps = added.apps.filter(app => choices.apps.includes(app.id));
            }
            data.backups.unshift(added);
          }
          if (step.removeBackups) data.backups = data.backups.filter(item => !step.removeBackups.includes(item.id));
          if (step.addExport) data.exports = [...(data.exports || []), structuredClone(step.addExport)];
          if (step.verified && record.job.params?.backup_id) {
            const meta = backup(record.job.params.backup_id);
            if (meta) meta.verified = structuredClone(step.verified);
          }
          if (step.chainFinish) finishChainJob(record);
        }
        data.status.active_job = ACTIVE.includes(record.job.state) ? structuredClone(record.job)
          : data.status.active_job?.id === record.job.id ? null : data.status.active_job;
        return { job: structuredClone(record.job), log: record.log.slice(-200) };
      }
      case 'job-cancel': {
        const record = data.jobs[request.job_id];
        if (!record) throw new Refusal('not-found', '找不到指定的作業。');
        if (record.chain) {
          const live = Object.values(data.jobs).find(item => item.chain?.group === record.chain.group && ACTIVE.includes(item.job.state));
          if (!live) return { state: record.job.state };
          if (request.after_this === true) {
            for (const item of Object.values(data.jobs)) if (item.chain?.group === record.chain.group) item.chain.stopAfter = true;
            return { state: live.job.state, after_this: true };
          }
          if (!live.job.cancellable) throw new Refusal('not-cancellable', '作業已進入不可中斷的階段，將繼續執行到完成或自動回復。');
          Object.assign(live.job, { cancellable: false, finished: '2026-11-13T02:03:00Z', progress: { ...live.job.progress, message: '已取消' },
            phases: live.job.phases.map(item => ({ ...item, state: ['pending', 'active'].includes(item.state) ? 'skipped' : item.state })) });
          live.steps = [];
          finishChainJob(live, { cancelled: true });
          live.log.push('2026-11-13T02:03:00Z 作業結束：已取消');
          data.status.active_job = null;
          return { state: 'cancelled' };
        }
        if (TERMINAL.includes(record.job.state)) return { state: record.job.state };
        if (!record.job.cancellable) throw new Refusal('not-cancellable', '作業已進入不可中斷的階段，將繼續執行到完成或自動回復。');
        Object.assign(record.job, { state: 'cancelled', cancellable: false, finished: '2026-11-13T02:03:00Z',
          progress: { ...record.job.progress, message: '已取消' },
          phases: record.job.phases.map(item => ({ ...item, state: ['pending', 'active'].includes(item.state) ? 'skipped' : item.state })) });
        record.steps = [];
        record.log.push('2026-11-13T02:03:00Z 作業結束：已取消');
        data.status.active_job = null;
        return { state: 'cancelled' };
      }
      case 'delete': {
        if (!backup(request.backup_id)) throw new Refusal('not-found', '找不到指定的備份。');
        data.backups = data.backups.filter(item => item.id !== request.backup_id);
        for (const item of data.backups) if (item.from_ha?.kept === request.backup_id) item.from_ha.kept = null;
        return {};
      }
      case 'upload-begin':
        if (request.size > data.upload.begin.max_size) throw new Refusal('insufficient-space', '磁碟空間不足，無法上傳此備份檔。');
        return structuredClone(data.upload.begin);
      case 'upload-finish': {
        if (request.upload_id !== data.upload.begin.upload_id) throw new Refusal('not-found', '找不到上傳工作。');
        const channel = window.testchannels.at(-1);
        if (!channel?.done || channel.sent !== channel.options.size) throw new Refusal('invalid-request', '上傳的檔案大小與宣告不符，上傳可能未完成。');
        // An HA OS backup goes to the HA store and is answered as `ha_backup` (DESIGN §6).
        if (data.upload.finishHa) {
          const ha = structuredClone(data.upload.finishHa);
          if (!data.ha.backups.some(item => item.id === ha.id)) data.ha.backups.unshift(ha);
          return { ha_backup: structuredClone(ha) };
        }
        const meta = structuredClone(data.upload.finish);
        if (!backup(meta.id)) data.backups.unshift(meta);
        return { backup: structuredClone(backup(meta.id)) };
      }
      case 'upload-abort':
        return {};
      case 'download-info': {
        const info = data.downloads[request.backup_id];
        if (!info) throw new Refusal('not-found', '找不到指定的備份。');
        return structuredClone(info);
      }
      default:
        throw new Error(`unexpected command ${command}`);
    }
  }

  function checkRequest(command, record) {
    if (NO_INPUT.includes(command)) {
      if (record.stdin !== '') window.fixtureErrors.push(`${command} must not send stdin: ${record.stdin}`);
      return {};
    }
    const spec = SPECS[command];
    if (!spec) {
      window.fixtureErrors.push(`Unexpected helper command: ${JSON.stringify(record.argv)}`);
      throw new Error('unexpected command');
    }
    let request;
    try {
      request = JSON.parse(record.stdin);
    } catch {
      window.fixtureErrors.push(`${command} stdin is not JSON: ${record.stdin}`);
      throw new Error('bad stdin');
    }
    const keys = Object.keys(request);
    const unknown = keys.filter(key => !spec.required.includes(key) && !spec.optional.includes(key));
    const missing = spec.required.filter(key => !keys.includes(key));
    if (unknown.length || missing.length) window.fixtureErrors.push(`${command} request keys: unknown ${unknown} missing ${missing}`);
    return request;
  }

  const permission = mixin({ allowed: data.allowed, close() {} });
  data.setAllowed = allowed => {
    permission.allowed = allowed;
    permission.emit('changed');
  };
  data.release = command => {
    data.hold = data.hold.filter(item => item !== command);
    const waiting = data.waiting.filter(item => item.command === command);
    data.waiting = data.waiting.filter(item => item.command !== command);
    waiting.forEach(item => item.resolve());
  };

  const cockpit = mixin({
    hidden: false,
    transport: { csrf_token: data.csrf, options: {}, uri: suffix => `ws://${window.location.host}/cockpit/${suffix || 'socket'}`, wait: callback => setTimeout(callback, 0) },
    permission: () => permission,
    user: () => Promise.resolve({ id: 1000, name: 'devadmin', full_name: 'Dev Admin', groups: ['sudo'], home: '/home/devadmin' }),
    jump: target => window.testjumps.push(target),
    spawn(argv, options) {
      const record = { argv: [...argv], options: { ...options }, stdin: '', done: false };
      window.testcalls.push(record);
      const command = argv[1];
      let stream = () => {};
      let closed = false;
      let inputDone;
      const input = new Promise(resolve => { inputDone = resolve; });
      const process = new Promise((resolve, reject) => {
        setTimeout(async () => {
          const emit = payload => {
            const output = JSON.stringify(payload);
            const middle = Math.floor(output.length / 2);
            stream(output.slice(0, middle));
            stream(output.slice(middle));
          };
          try {
            await input;
            while (data.hold.includes(command)) await new Promise(release => data.waiting.push({ command, resolve: release }));
            if (data.latency) await new Promise(release => setTimeout(release, data.latency));
            if (closed) return;
            if (!permission.allowed) throw Object.assign(new Error('Administrative access denied'), { problem: 'access-denied' });
            const request = checkRequest(command, record);
            const failed = data.failures.findIndex(item => item.command === command);
            if (failed >= 0) {
              const failure = data.failures.splice(failed, 1)[0];
              if (failure.problem) throw Object.assign(new Error(failure.message || failure.problem), { problem: failure.problem });
              emit({ ok: false, error: { code: failure.code, message: failure.message, details: failure.details || {} } });
              throw Object.assign(new Error('Process exited with code 1'), { exit_status: 1 });
            }
            let result;
            try {
              result = handle(command, request);
            } catch (error) {
              if (!(error instanceof Refusal)) throw error;
              emit({ ok: false, error: { code: error.code, message: error.message, details: error.details } });
              throw Object.assign(new Error('Process exited with code 1'), { exit_status: 1 });
            }
            emit({ ok: true, ...result });
            resolve('');
          } catch (error) {
            reject(error);
          }
        }, 0);
      });
      process.stream = callback => { stream = callback; return process; };
      process.input = (message, more) => {
        if (message !== null && message !== undefined) record.stdin += message;
        if (!more) {
          record.done = true;
          inputDone();
        }
        return process;
      };
      process.close = () => { closed = true; return process; };
      return process;
    },
    channel(options) {
      const record = { options: structuredClone(options), sent: 0, acked: 0, frames: 0, maxFrame: 0, maxUnacked: 0, pending: [], done: false, closedBy: null };
      window.testchannels.push(record);
      const channel = mixin({ valid: true, options, binary: options.binary === true });
      if (options.payload !== 'fsreplace1') window.fixtureErrors.push(`Unexpected channel payload ${options.payload}`);
      const finishIfDone = () => {
        if (!record.done || record.pending.length || !channel.valid) return;
        setTimeout(() => {
          if (!channel.valid) return;
          channel.valid = false;
          record.closedBy = 'bridge';
          const failure = data.channelFailure;
          channel.emit('close', failure ? { command: 'close', problem: failure.problem, message: failure.message } : { command: 'close', tag: '1731463200:1' });
        }, 5);
      };
      const ackOne = () => {
        const amount = record.pending.shift();
        if (amount === undefined || !channel.valid) return false;
        record.acked += amount;
        channel.emit('control', { command: 'ack', bytes: amount, channel: '7' });
        finishIfDone();
        return true;
      };
      record.ackOne = ackOne;
      data.releaseAcks = count => { let released = 0; while (released < count && ackOne()) released += 1; return released; };
      channel.send = payload => {
        if (!channel.valid) { window.fixtureErrors.push('send on closed channel'); return; }
        if (!(payload instanceof Uint8Array)) window.fixtureErrors.push('upload frames must be Uint8Array');
        const size = payload.byteLength;
        record.sent += size;
        record.frames += 1;
        record.maxFrame = Math.max(record.maxFrame, size);
        record.maxUnacked = Math.max(record.maxUnacked, record.sent - record.acked);
        record.pending.push(size);
        if (data.ackMode === 'auto') setTimeout(ackOne, 0);
      };
      channel.control = message => {
        if (message?.command === 'done') {
          record.done = true;
          finishIfDone();
        }
      };
      channel.close = problem => {
        if (!channel.valid) return;
        channel.valid = false;
        record.closedBy = 'client';
        channel.emit('close', { command: 'close', ...(typeof problem === 'string' ? { problem } : problem || {}) });
      };
      setTimeout(() => { if (channel.valid) channel.emit('control', { command: 'ready' }); }, 0);
      return channel;
    },
  });
  const encode = target => (typeof target === 'string' ? (target.startsWith('/') ? target : `/${target}`)
    : `/${target.map(item => encodeURIComponent(item)).join('/')}`);
  Object.defineProperty(cockpit, 'location', {
    get() {
      const href = window.location.hash.slice(1);
      const path = href.split('?')[0].split('/').filter(Boolean).map(decodeURIComponent);
      return {
        path, options: {}, href,
        go: target => { window.location.hash = `#${encode(target)}`; },
        replace: target => { window.location.replace(`${window.location.pathname}${window.location.search}#${encode(target)}`); },
      };
    },
  });
  window.addEventListener('hashchange', () => cockpit.emit('locationchanged'));
  window.cockpit = cockpit;
}

const mockCockpit = `(${installCockpitFixture.toString()})();`;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.ttf': 'font/ttf', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
const downloadRequests = [];

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  const headers = { 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP };
  if (pathname === '/cockpit/base1/cockpit.js') {
    res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript' }).end(mockCockpit);
    return;
  }
  if (pathname.startsWith('/cockpit/channel/')) {
    // Cockpit's external channel: /cockpit/channel/<csrf>?<base64 JSON open options>.
    const token = pathname.slice('/cockpit/channel/'.length);
    let open = null;
    try { open = JSON.parse(Buffer.from(url.search.slice(1), 'base64').toString('utf8')); } catch { /* recorded as null */ }
    downloadRequests.push({ token, query: url.search.slice(1), open });
    if (token !== CSRF || !open?.external) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Forbidden: invalid channel request');
      return;
    }
    if (open.path.includes('missing')) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('找不到備份檔（fixture）');
      return;
    }
    res.writeHead(200, { 'Content-Type': open.external['content-type'], 'Content-Disposition': open.external['content-disposition'] })
      .end(Buffer.concat([Buffer.from('WOOWTECH-BACKUP/1\n'), Buffer.alloc(4096, 1)]));
    return;
  }
  if (pathname === '/favicon.ico') { res.writeHead(204).end(); return; }
  const mount = [['/cockpit/woowtechbackup/', 'backup'], ['/static/', 'branding']].find(([prefix]) => pathname.startsWith(prefix));
  if (!mount) { res.writeHead(404).end(); return; }
  const directory = resolve(root, mount[1]);
  const path = resolve(directory, decodeURIComponent(pathname.slice(mount[0].length)));
  if (!path.startsWith(directory + sep)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(path);
    res.writeHead(200, { ...headers, 'Content-Type': types[extname(path)] || 'application/octet-stream' }).end(body);
  } catch { res.writeHead(404).end(); }
});

let browser;
let base;
const calls = (page, command) => page.evaluate(name => window.testcalls.filter(call => call.argv[1] === name), command);
const requestOf = call => (call.stdin ? JSON.parse(call.stdin) : {});
// [app name|null, path, label/size|null] for every line of a host-directory list.
const dirRows = list => list.locator('li').evaluateAll(items => items.map(item => [
  item.querySelector('.path-app')?.textContent ?? null, item.querySelector('.path')?.textContent ?? null,
  item.querySelector('.secondary')?.textContent ?? null]));
// Every <dl class="metadata"> under a locator as {label: value}.
const metadataOf = locator => locator.locator('dl.metadata').evaluateAll(lists => lists.map(dl =>
  Object.fromEntries([...dl.querySelectorAll(':scope > dt')].map(dt => [dt.textContent, dt.nextElementSibling?.textContent ?? null]))));
const channels = page => page.evaluate(() => window.testchannels.map(({ ackOne, ...rest }) => rest));
const enabled = (page, selector) => page.locator(`${selector}:enabled`).first().waitFor();
const view = page => page.locator('#view');

async function settled(page) {
  await page.waitForFunction(() => document.querySelector('#view')?.getAttribute('aria-busy') === 'false');
}

async function shot(page, name) {
  if (!SHOTS) return;
  await mkdir(SHOTS, { recursive: true });
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: join(SHOTS, name), fullPage: true });
}

async function fits(page, label) {
  const result = await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done)));
    const width = window.innerWidth;
    const offenders = [];
    for (const element of document.querySelectorAll('body *')) {
      if (element.closest('[data-scroll], .sr-only, #downloads, dialog:not([open]), [hidden]')) continue;
      const rect = element.getBoundingClientRect();
      if (!rect.width && !rect.height) continue;
      if (rect.right > width + 1 || rect.left < -1) {
        offenders.push(`${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ''}.${[...element.classList].join('.')}` +
          ` [${Math.round(rect.left)}..${Math.round(rect.right)}] ${String(element.textContent).trim().slice(0, 40)}`);
      }
    }
    const dialog = document.querySelector('dialog[open]');
    const leaked = (document.body.innerText.match(/\bnull\b|\bundefined\b|\[object Object\]|\bNaN\b/g) || []);
    return { width, leaked, document: document.documentElement.scrollWidth, body: document.body.scrollWidth, offenders: offenders.slice(0, 6),
      dialog: dialog ? { scroll: dialog.scrollWidth, client: dialog.clientWidth } : null };
  });
  assert.deepEqual(result.leaked, [], `${label}: placeholder values leaked into visible text`);
  assert(result.document <= result.width && result.body <= result.width && !result.offenders.length &&
    (!result.dialog || result.dialog.scroll <= result.dialog.client + 1), `${label}: horizontal overflow ${JSON.stringify(result)}`);
}

const WIDTHS = [1440, 1024, 768, 390, 360, 320];
async function allWidths(page, label) {
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: 900 });
    await fits(page, `${label} @${width}px`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

async function check(name, data, body, { allowHttpErrors = [], beforeGoto = null } = {}) {
  await test(name, async () => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, locale: 'zh-TW', timezoneId: 'Asia/Taipei' });
    try {
      const errors = [];
      await context.route('**/*', route => {
        if (new URL(route.request().url()).origin === base) return route.continue();
        errors.push(`External request: ${route.request().url()}`);
        return route.abort();
      });
      await context.addInitScript(fixtureData => {
        window.__fixture = fixtureData;
        window.__csp = [];
        document.addEventListener('securitypolicyviolation', event => window.__csp.push(`${event.violatedDirective} ${event.blockedURI}`));
      }, { csrf: CSRF, ...data });
      const page = await context.newPage();
      page.setDefaultTimeout(10000);
      page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
      page.on('response', response => {
        if (response.status() >= 400 && !allowHttpErrors.some(part => response.url().includes(part))) errors.push(`${response.status()} ${response.url()}`);
      });
      if (beforeGoto) await beforeGoto(page, context);
      await page.goto(`${base}/cockpit/woowtechbackup/index.html`);
      await body(page, context);
      assert.deepEqual(await page.evaluate(() => window.fixtureErrors), [], 'fixture saw malformed or unexpected helper usage');
      assert.deepEqual(await page.evaluate(() => window.__csp), [], 'no Content-Security-Policy violations');
      assert.deepEqual(errors, [], 'no script errors, missing assets or external requests');
      for (const call of await page.evaluate(() => window.testcalls)) {
        assert.equal(call.argv[0], HELPER, 'only the fixed helper is spawned');
        assert.equal(call.argv.length, 2, 'argv is exactly [helper, command]');
        assert.equal(call.options.superuser, 'require', 'every helper call requires administrative access');
        assert.equal(call.options.err, 'message');
        assert(!JSON.stringify(call.argv).includes('AGE-SECRET-KEY'), 'key material never travels in argv');
        if (call.stdin.includes('AGE-SECRET-KEY')) assert.match(call.stdin, /^\{.*"key":"AGE-SECRET-KEY-1[0-9A-Z]{58}".*\}$/, 'keys only in the stdin field "key"');
        // The HA backup key (DESIGN §0): only in the stdin field "key" of the two HA job starts.
        for (const key of HA_KEYS) {
          assert(!JSON.stringify(call.argv).includes(key), 'the HA key never travels in argv');
          if (!call.stdin.includes(key)) continue;
          const { key: sent, ...rest } = JSON.parse(call.stdin);
          assert(['ha-check-start', 'ha-convert-start', 'ha-import-start'].includes(call.argv[1]), `the HA key is sent only to start an HA job, not ${call.argv[1]}`);
          assert.equal(sent, key, 'the HA key travels as the stdin field "key"');
          assert(!JSON.stringify(rest).includes(key), 'the HA key is in no other field');
        }
      }
      const kept = await page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage), window.location.href,
        document.cookie, document.title]));
      for (const key of HA_KEYS) assert(!kept.includes(key), 'the HA key is never stored in the browser or put in the URL');
      for (const channel of await channels(page)) assert.equal(channel.options.superuser, 'require');
    } finally {
      await context.close();
    }
  });
}

async function ready(page) {
  await page.locator('#view-heading').waitFor();
  await settled(page);
}

// WCAG AA contrast of visible text (4.5:1, 3:1 for large text) against the nearest opaque background.
const contrastOf = (page, extra = '') => page.evaluate(extra => {
  const rgb = value => (value.match(/[\d.]+/g) || []).map(Number);
  const luminance = ([r, g, b]) => [r, g, b].map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; })
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  const backgroundOf = node => {
    for (let el = node; el; el = el.parentElement) {
      const [r, g, b, a = 1] = rgb(getComputedStyle(el).backgroundColor);
      if (a > 0.5) return [r, g, b];
    }
    return [255, 255, 255];
  };
  const failures = [];
  let checked = 0;
  for (const el of document.querySelectorAll(`h1, h2, h3, h4, p, a, button, .chip, label, dt, dd, td, th, li, small, .muted, select, textarea${extra}`)) {
    const box = el.getBoundingClientRect();
    if (!box.width || !box.height || !(el.value || el.textContent).trim()) continue;
    if (el.closest('[hidden], dialog:not([open])')) continue;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || Number(style.opacity) < 0.9) continue;
    const fg = luminance(rgb(style.color)), bg = luminance(backgroundOf(el));
    const ratio = (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
    const size = parseFloat(style.fontSize), bold = Number(style.fontWeight) >= 700;
    const minimum = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
    checked++;
    if (ratio < minimum) failures.push(`${el.tagName.toLowerCase()}.${el.className} "${(el.value || el.textContent).trim().slice(0, 24)}" ${ratio.toFixed(2)}`);
  }
  return { checked, failures };
}, extra);

// Tab through a view: every focused element has a visible 2px focus ring and stays inside the viewport.
async function tabKeys(page, label, count) {
  await page.evaluate(() => document.activeElement?.blur());
  const seen = [];
  for (let index = 0; index < count; index += 1) {
    await page.keyboard.press('Tab');
    const info = await page.evaluate(() => {
      const element = document.activeElement;
      if (!element || element === document.body) return null;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return { key: element.dataset.focus || element.id || element.tagName, visible: element.matches(':focus-visible'),
        outline: style.outlineStyle, width: parseFloat(style.outlineWidth), left: rect.left, right: rect.right, viewport: innerWidth };
    });
    if (!info) continue;
    seen.push(info.key);
    assert(info.visible && info.outline !== 'none' && info.width >= 2, `${label}: no visible focus ring on ${JSON.stringify(info)}`);
    assert(info.left >= -2 && info.right <= info.viewport + 2, `${label}: focused element outside the viewport ${JSON.stringify(info)}`);
  }
  return seen;
}

// ------------------------------------------------------------------ strengthen phase data (2026-11-13)

const B_PLAIN = '20261113T030000Z-0dd5a1e5';
const UNAUTH_MESSAGE = '這份上傳的備份沒有加密，內容無法驗證：無法確認它來自你的設備，也無法確認檔案在設備以外沒有被修改過。只有在確定檔案來源可信時才還原；確認還原時需要另外勾選這一點。';
const DB_SUMMARY = { databases: 1, tables: 3, sequences: 2, rows: 345, roles: 0 };
const FILES_BEFORE = { entries: 40, files: 30, dirs: 8, symlinks: 2, other: 0, bytes: 123456 };
const FILES_AFTER = { entries: 41, files: 31, dirs: 8, symlinks: 2, other: 0, bytes: 125000 };
const DIGEST_CHECKS = () => [
  { id: 'db', type: 'postgres-digest', target: 'postgres:main', label: '資料表', match: true, before: DB_SUMMARY, after: DB_SUMMARY, differences: null, note: null },
  { id: 'files', type: 'files-digest', target: 'volume:woowbk-demo-files', label: '上傳檔案', match: false, before: FILES_BEFORE, after: FILES_AFTER,
    differences: { missing: 0, extra: 1, changed: 1, samples: [
      { item: 'ticker', change: 'extra', detail: '還原後多出這個項目' },
      { item: 'notes/3.txt', change: 'changed', detail: '內容不同（大小 12 → 14）' }] }, note: null },
  { id: 'config', type: 'files-digest', target: `dir:${'homeassistant/config'}`, label: '', match: null, before: null, after: null, differences: null,
    note: '備份沒有這個項目的資料摘要（例如較舊的備份），未比對。' },
];

// A restore whose files digest differs: it stops before the app starts and rolls back (CONTRACT §7 DigestCheck).
function digestRollbackScript(checks = DIGEST_CHECKS()) {
  return [
    runningStep('restore', 'restore', 62, { safety_backup_id: B_SAFETY_NEW }),
    {
      job: { state: 'rolled-back', phase: 'rollback', phases: phasesAt('restore', null, { failedAt: 'restore', rollback: 'done' }),
        progress: { percent: 90, message: '已自動回復' }, finished: '2026-11-13T02:12:00Z', cancellable: false,
        error: { code: 'job-failed', message: '應用「示範筆記應用」還原後的資料與備份時不一致：files：遺失 0、多出 1、不同 1（例如 ticker：還原後多出這個項目）' },
        result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY_NEW, rolled_back: true, changed: true, health: [], warnings: [],
          timing: [{ app: 'woowbk-demo', writer_pause_seconds: 18, unavailable_seconds: 46.3 }],
          verification: [{ app: 'woowbk-demo', match: false,
            before: Object.fromEntries(checks.filter(check => check.before).map(check => [check.id, check.before])),
            after: Object.fromEntries(checks.filter(check => check.after).map(check => [check.id, check.after])), checks }] } },
      log: ['2026-11-13T02:11:30Z 資料摘要不一致：files：遺失 0、多出 1、不同 1', '2026-11-13T02:12:00Z 已自動回復到還原前的狀態'],
    },
  ];
}

// A successful restore with the app's JSON summary and two matching digests.
function digestSuccessScript() {
  const checks = DIGEST_CHECKS().slice(0, 2).map(check => ({ ...check, match: true, after: check.before, differences: null }));
  const steps = scripts().restore;
  Object.assign(steps.at(-1).job.result, {
    timing: [{ app: 'woowbk-demo', writer_pause_seconds: 12.25, unavailable_seconds: 31.75 }],
    verification: [{ app: 'woowbk-demo', match: true,
      before: { ...VERIFY_BEFORE, db: DB_SUMMARY, files: FILES_BEFORE }, after: { ...structuredClone(VERIFY_BEFORE), db: DB_SUMMARY, files: FILES_BEFORE }, checks }],
  });
  return steps;
}

// Draft entries for one app in the three PostgreSQL modes (catalog-suggest Draft.variants).
function notesEntry(mode) {
  const base = {
    schema: 1, id: 'notes', name: 'notes', description: '自動產生的草稿：2 個服務、PostgreSQL 16、2 個資料卷。請審查後再安裝。', owner: 'appowner',
    adapter: 'quadlet-postgres', quadlet: { files: ['notes.network', 'notes-db.container', 'notes-app.container'] },
    units: ['notes-db.service', 'notes-app.service'], writer_units: ['notes-app.service'], postgres: [],
    volumes: [{ name: 'notes-files', label: 'notes-app：/data' }], secrets: [{ name: 'notes-db-password' }],
    config_files: [{ path: '.config/notes/app.env', mode: '0600' }],
    health: [{ type: 'http', url: 'http://127.0.0.1:18095/healthz', expect_status: 200, timeout_seconds: 300 }],
    verify: [{ id: 'vol-notes-files', type: 'files-digest', volume: 'notes-files', label: '資料卷 notes-files' }],
  };
  const db = { id: 'main', container: 'notes-db', unit: 'notes-db.service', user: 'notes', data_volume: 'notes-pgdata' };
  if (mode === 'cold') {
    return { ...base, writer_units: ['notes-db.service', 'notes-app.service'],
      volumes: [{ name: 'notes-pgdata', label: 'PostgreSQL 資料（冷備份）' }, ...base.volumes],
      verify: [{ id: 'db-main', type: 'postgres-digest', container: 'notes-db', unit: 'notes-db.service', user: 'notes', label: 'PostgreSQL 資料表內容' }, ...base.verify] };
  }
  const item = mode === 'instance' ? { ...db, scope: 'instance' } : { ...db, database: 'notes' };
  return { ...base, postgres: [item], verify: [{ id: 'db-main', type: 'postgres-digest', postgres: 'main', label: 'PostgreSQL 資料表內容' }, ...base.verify] };
}

const VARIANT_LABELS = {
  cold: '冷備份（預設）：資料庫與應用一起停止，資料檔整份備份；保留整個執行個體（所有資料庫、角色與密碼），還原時 PostgreSQL 主版本必須相同。',
  instance: '整個執行個體：備份時資料庫保持執行，以 pg_dumpall 保存角色並逐一匯出每個資料庫；還原到相同或更新的主版本。',
  database: '單一資料庫：備份時資料庫保持執行，只以 pg_dump 匯出一個資料庫，不保留角色與權限；執行個體有其他資料庫時無法原位還原。',
};
const INSTALLED_SHA = 'c'.repeat(64);

function catalogData() {
  const demoInstalled = { schema: 1, id: 'woowbk-demo', name: '示範筆記應用', description: '示範', owner: 'appowner', adapter: 'quadlet-postgres',
    quadlet: { files: ['woowbk-demo-db.container', 'woowbk-demo-app.container'], template_dir: '/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet' },
    units: ['woowbk-demo-db.service', 'woowbk-demo-app.service'], writer_units: ['woowbk-demo-app.service'],
    postgres: [{ id: 'main', container: 'woowbk-demo-db', unit: 'woowbk-demo-db.service', database: 'notes', user: 'notes', data_volume: 'woowbk-demo-pgdata' }],
    volumes: [{ name: 'woowbk-demo-files', label: '上傳檔案' }], secrets: [{ name: 'woowbk-demo-db-password' }], config_files: [],
    health: [{ type: 'http', url: 'http://127.0.0.1:18090/healthz', expect_status: 200, timeout_seconds: 90 }], verify: [] };
  const demoDraft = structuredClone(demoInstalled);
  demoDraft.verify = [{ id: 'vol-woowbk-demo-files', type: 'files-digest', volume: 'woowbk-demo-files', label: '資料卷 woowbk-demo-files' }];
  const notes = {
    id: 'notes',
    containers: [
      { file: 'notes-db.container', unit: 'notes-db.service', container: 'notes-db', image: 'docker.io/library/postgres:16-alpine', state: 'active' },
      { file: 'notes-app.container', unit: 'notes-app.service', container: 'notes-app', image: 'localhost/notes-app:1', state: 'active' }],
    databases: [{ unit: 'notes-db.service', container: 'notes-db', kind: 'postgres', image: 'docker.io/library/postgres:16-alpine', major: 16,
      database: 'notes', user: 'notes', guessed: false, data: { volume: 'notes-pgdata' } }],
    entry: notesEntry('cold'), valid: true, problem: null, field: null, variant: 'cold',
    variants: ['cold', 'instance', 'database'].map(id => ({ id, label: VARIANT_LABELS[id], entry: notesEntry(id), valid: true, problem: null, field: null })),
    installed: null,
    warnings: [{ code: 'config-mode', level: 'warn', message: '~/.config/notes/start.sh 目前的權限是 0755，超過 0644；還原後會是 0644（不可執行、群組與其他人不可寫入）。', path: '.config/notes/start.sh' }],
    notes: [{ code: 'cache', level: 'info', message: 'notes-cache.container 是 Redis 類快取／佇列，資料卷會在停止後備份（AOF／RDB 已寫入磁碟）。', file: 'notes-cache.container' }],
    skipped: [{ kind: 'dir', path: '.ssh', reason: '與 ~/.ssh 重疊（登入金鑰、服務定義、Podman 或使用者環境），規則上禁止列為主機資料夾，未列入。' }],
    hints: ['健康檢查的預期狀態碼假設為 200、逾時 300 秒；請以實際回應與冷啟動時間確認。'],
  };
  const demo = {
    id: 'woowbk-demo', containers: [
      { file: 'woowbk-demo-db.container', unit: 'woowbk-demo-db.service', container: 'woowbk-demo-db', image: 'docker.io/library/postgres:16-alpine', state: 'active' },
      { file: 'woowbk-demo-app.container', unit: 'woowbk-demo-app.service', container: 'woowbk-demo-app', image: 'localhost/woowbk-demo-app:1', state: 'active' }],
    databases: [], entry: demoDraft, valid: true, problem: null, field: null, variant: 'database', variants: [],
    installed: { id: 'woowbk-demo', sha256: INSTALLED_SHA, entry: demoInstalled, same: false,
      changes: [{ path: 'verify[id=vol-woowbk-demo-files]', op: 'add', new: demoDraft.verify[0] }],
      drift: ['草稿多了內建資料核對 vol-woowbk-demo-files（資料卷 woowbk-demo-files）。'] },
    warnings: [], notes: [], skipped: [], hints: [],
  };
  return {
    owners: [{ name: 'appowner', uid: 1001, linger: true, catalog_apps: ['woowbk-demo', 'woowbk-wiki'] },
      { name: 'svcuser', uid: 1002, linger: false, catalog_apps: [] }],
    scans: { appowner: { owner: 'appowner', uid: 1001, quadlet_dir: '.config/containers/systemd', state: 'ok',
      owners: [{ name: 'appowner', uid: 1001, linger: true, catalog_apps: ['woowbk-demo', 'woowbk-wiki'] }], apps: [notes, demo],
      unassigned: [{ file: 'shared-proxy.network', reason: '沒有容器使用這個檔案，也無法依名稱歸入應用。' }],
      unsupported: [{ file: 'tools.kube', reason: '.kube 檔不在支援範圍，沒有分析。' }],
      warnings: [{ code: 'dropin', level: 'info', message: 'notes-app.container.d 是 drop-in 資料夾，沒有分析其中的設定。', file: 'notes-app.container.d' }] } },
    installed: { 'woowbk-demo': { entry: demoInstalled, sha256: INSTALLED_SHA } },
    taken: ['shared-volume'],
  };
}

const RET_IDS = ['20261105T020000Z-0000000a', '20261106T020000Z-0000000b', '20261107T020000Z-0000000c', '20261108T020000Z-0000000d',
  '20261109T020000Z-0000000e', '20261110T020000Z-0000000f'];

function retentionFixture(extra = {}) {
  const data = fixture(extra);
  data.backups.push(...RET_IDS.map((id, index) => backupMeta(id, { note: `每日備份 ${index + 1}`, size: 40 * MiB, verified: null })));
  data.retention = {
    saved: { schema: 1, default_keep_last: null, apps: {} }, problem: null,
    protected: { [B_SAFETY]: '失敗或中斷的還原仍需要這份還原前備份才能回到還原前的狀態。',
      [RET_IDS[0]]: '失敗或中斷的還原使用這份備份；在該應用成功還原之前保留。' },
    usage: {
      apps: [
        { id: 'woowbk-demo', name: '示範筆記應用', in_catalog: true, backups: 8, types: { manual: 7, safety: 1, uploaded: 0 }, bytes: 336 * MiB,
          estimated: false, shared: false, newest: '2026-11-12T02:00:00Z', oldest: '2026-11-05T02:00:00Z', keep_last: null },
        { id: 'woowbk-wiki', name: '團隊知識庫', in_catalog: true, backups: 0, types: { manual: 0, safety: 0, uploaded: 0 }, bytes: 0,
          estimated: false, shared: false, newest: null, oldest: null, keep_last: null }],
      unassigned: { backups: 1, bytes: 48 * MiB }, total: { backups: 9, bytes: 384 * MiB },
    },
  };
  return data;
}

// ------------------------------------------------------------------ 從 HA 備份匯入 data (2026-11-18, DESIGN §6)

const ODOO_SLUG = '1b7b4ce7_odoo18ce';
const N8N_SLUG = '1b7b4ce7_woow-n8n';
const HA_NAME = '每日完整備份 2026-11-17';
// Batch 1 (2026-11-19, CONTRACT §5 "Apps"): the WOOWTECH Omnigent, Hermes, EMQX and Headscale add-ons as the engine's
// tests name and version them (tests/backup/test_ha_*.py), this device's catalog names (haapps.IMPORTERS) and the product
// version each add-on version maps to, which this device runs too.
const B1_APPS = ['omnigent', 'hermes', 'emqx', 'headscale'];
const B1 = {
  omnigent: { slug: '1b7b4ce7_woow-omnigent', addon: 'Woow Omnigent', version: '0.1.23', app: 'Omnigent 協作平台', product: '0.21.0' },
  hermes: { slug: '1b7b4ce7_woow-hermes', addon: 'Woow Hermes Agent', version: '0.1.14', app: 'Hermes 代理', product: '0.22.5' },
  emqx: { slug: '1b7b4ce7_woow-emqx', addon: 'Woow EMQX', version: '5.9.1', app: 'EMQX MQTT 代理', product: '5.8.9' },
  headscale: { slug: '1b7b4ce7_woow-headscale', addon: 'Woow Headscale VPN', version: '0.1.3', app: 'Headscale VPN 控制伺服器', product: '0.29.4' },
};
const HA_B1 = 'ha-b1b1b1b1b1b1b1b1b1b1';
const B1_NAME = '樹莓派每週備份 2026-11-18';
const B_B1 = '20261119T040500Z-b1b1b1b1';
const HA_SOURCE = { id: HA_ID, name: HA_NAME, date: '2026-11-17T21:00:00Z' };
const B1_SOURCE = { id: HA_B1, name: B1_NAME, date: '2026-11-18T20:00:00Z' };
// An HA add-on has its own version; the check compares Odoo module by module, and reports this device's Odoo release
// (CONTRACT §7: `18.0-YYYYMMDD`) as `target_version` (review F-07).
const ODOO_ADDON_VERSION = '0.4.12';
const ODOO_RELEASE = '18.0-20260926';
const WORKFLOWS_TO_FIX = [
  { name: '開門通知', active: true, reasons: ['用到 Home Assistant 節點，網址要改成這台連得到的 HA。'] },
  { name: '每日報表', active: false, reasons: ['讀寫檔案的路徑 /share/reports 在這台不存在。', '用到 http://supervisor/core/api。'] },
];
// The engine's own words (hasecuretar.py, ha_odoo.py, haimport.py).
const NACL_MISSING = '系統缺少 python3-nacl，無法解開 2026 年 3 月以後的 HA 加密備份。請重新執行安裝程式。';
const MISSING_MODULE = '這台的 Odoo 缺少 HA 資料庫已安裝的模組：website_sale_extra。如果模組放在 HA 的 /share/odoo_addons，做 HA 備份時要把 share 資料夾也勾進去。';
const VERSION_BLOCKER = '這些模組的版本和這台不同：sale（HA 18.0.1.3，這台 18.0.1.2）。請先讓兩邊的 Odoo 版本一致後再匯入。';
const ODOO_ALL_BLOCKED = 'HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。';
const NO_FILESTORE = 'HA 備份裡沒有這個資料庫的附件檔案（filestore）；搬過來後附件會打不開。';
const KEY_REQUIRED = { code: 'key-required', message: '這份 HA 備份已加密，請輸入 HA 備份金鑰。' };
// The page's own reminder after an import, with a link to the HA file (review HA-SEC-06).
const HA_DELETE_LINE = `匯入完成後，建議刪除這份 HA 備份檔（裡面可能有 HA 的密碼與權杖）。 前往 HA 備份「${HA_NAME}」`;
const WRONG_HA_KEY = { code: 'wrong-key', message: 'HA 備份金鑰不正確，請確認後再試一次。' };

// HaBackupMeta: the sidecar plus `importable_apps` / `other_addons` (CONTRACT §7). Whether an add-on needs HA's key is
// its own `encrypted` (decided per member; review F-04): by default every member of a protected backup.
function haMeta(id, extra = {}) {
  const encrypted = extra.protected ?? true;
  return {
    id, ha_slug: 'a1b2c3d4', name: HA_NAME, date: '2026-11-17T21:00:00Z', type: 'partial', supervisor_version: '2026.11.1',
    protected: true, compressed: true,
    addons: [{ slug: ODOO_SLUG, name: 'Odoo 18 CE', version: ODOO_ADDON_VERSION, encrypted },
      { slug: N8N_SLUG, name: 'WOOW n8n', version: '2.43.6', encrypted },
      { slug: 'core_mosquitto', name: 'Mosquitto broker', version: '6.5.1', encrypted }],
    folders: ['share', 'ssl'], size: 1536 * MiB, sha256: 'd'.repeat(64), uploaded_at: '2026-11-18T01:00:00Z', filename: 'woow_import_test.tar',
    importable_apps: [{ slug: ODOO_SLUG, app_id: 'odoo', app_name: 'Odoo 18', installed: true },
      { slug: N8N_SLUG, app_id: 'n8n', app_name: 'n8n 工作流程', installed: true }],
    other_addons: [{ slug: 'core_mosquitto', name: 'Mosquitto broker', version: '6.5.1' }],
    ...extra,
  };
}

// An HA Odoo database as the check reports it (ha_odoo.py analyse): like the engine, it warns about active mail servers
// and scheduled actions, and about attachments whose files the HA backup lacks (review F-02).
function odooDb(name, extra = {}) {
  const db = { name, ok: true, blockers: [], partners: 1234, users: 5, attachments: 3210, attachment_bytes: 120 * MiB, modules: 87,
    custom_modules: [{ name: 'woow_paas_platform', version: '18.0.1.2.0', from: 'share/odoo_addons' }], crons_active: 12,
    mail_servers_active: 1, size: 310 * MiB, filestore_files: 3210, filestore_bytes: 120 * MiB, ...extra };
  db.warnings = extra.warnings ?? [
    ...(db.mail_servers_active ? [`HA 的資料庫有 ${db.mail_servers_active} 個啟用中的外寄郵件伺服器，搬過來後會開始寄信（包括 HA 上還沒寄出的信和每天的提醒信）；正式搬家前請先停掉 HA 那邊的 Odoo，避免兩邊各寄一次。`] : []),
    ...(db.crons_active ? [`HA 的資料庫有 ${db.crons_active} 個啟用中的排程工作，搬過來後會在這台執行。`] : []),
    ...(db.attachments && !db.filestore_files ? [NO_FILESTORE] : [])];
  return db;
}
const blockedDb = () => odooDb('demo-old', { ok: false, blockers: [MISSING_MODULE], partners: 40, users: 2, attachments: 9,
  attachment_bytes: 2 * MiB, modules: 45, custom_modules: [], crons_active: 3, mail_servers_active: 0, size: 25 * MiB,
  filestore_files: 9, filestore_bytes: 2 * MiB });

// result.ha_check of a check job (haimport.py run_ha_check); `odoo` / `n8n` replace fields of each app's verdict.
function haCheck({ odoo = {}, n8n = {}, databases = null } = {}) {
  return { ha_check: { ha_backup_id: HA_ID, apps: [
    { app_id: 'odoo', slug: ODOO_SLUG, name: 'Odoo 18 CE', arch: 'amd64', version: ODOO_ADDON_VERSION, target_version: ODOO_RELEASE, ok: true,
      blockers: [], warnings: [], odoo: { databases: databases || [odooDb('woowtest'), blockedDb()] }, ...odoo },
    { app_id: 'n8n', slug: N8N_SLUG, name: 'WOOW n8n', arch: 'amd64', version: '2.43.6', target_version: '2.43.6', ok: true, blockers: [],
      warnings: ['社群節點 n8n-nodes-mqtt-x 含有與這台不相容的程式，搬過來後需要重新安裝。', 'HA 的 n8n 裝了 1 個社群節點套件，搬過來後請確認它們能正常使用。'],
      n8n: { owner_email: 'owner@example.com', workflows: 14, workflows_active: 6, credentials: 9, executions: 1520, users: 2, projects: 2,
        variables: 0, data_tables: 0, community_packages: [{ name: 'n8n-nodes-mqtt-x', version: '1.4.2' }], workflows_to_fix: WORKFLOWS_TO_FIX },
      ...n8n },
  ] } };
}

const haStep = (kind, phase, percent, extra = {}) => runningStep(kind, phase, percent, { started: '2026-11-18T03:00:05Z', ...extra });
function haFailedStep(kind, phase, error) {
  return { job: { state: 'failed', phase, phases: phasesAt(kind, phase, { failedAt: phase }), progress: { percent: 40, message: labelOf(kind, phase) },
    finished: '2026-11-18T03:00:40Z', cancellable: false, error, result: null }, log: [`2026-11-18T03:00:40Z 作業失敗：${error.message}`] };
}

// What a conversion records (haimport.py view_row; FIXPLAN §19, UI-3): `notes` explain the import before the restore,
// `reminders_by_app` are the to-dos of each app and `reminders` those of no app; `addons` names HA's add-ons. The engine
// before that split (`legacy`) sent its explanations and to-dos together in `reminders`.
const HA_ADDON_OF = { odoo: [ODOO_SLUG, 'Odoo 18 CE'], n8n: [N8N_SLUG, 'WOOW n8n'],
  ...Object.fromEntries(B1_APPS.map(id => [id, [B1[id].slug, B1[id].addon]])) };
// Batch 1: each module's import_texts (ha_omnigent.py, ha_hermes.py, ha_emqx.py, ha_headscale.py) followed by the MCP lines
// the engine writes itself (haimport.mcp_lines: this device has the Hermes, EMQX and Headscale MCP admin apps).
const HA_NOTES = {
  odoo: ['Odoo 的使用者帳號和密碼會換成 HA 那邊的，這台原本的 Odoo 管理者密碼不再適用。', 'HA 的自訂模組 woow_paas_platform 會一起放進這台的自訂模組資料夾。'],
  n8n: ['n8n 的登入帳號會換成 HA 的管理者帳號（owner@example.com）。'],
  omnigent: ['Omnigent 的使用者帳號、工作階段、代理程式與排程會換成 HA 的；HA 的登入金鑰（accounts-cookie-secret）一起搬過來，這台目前登入的瀏覽器與裝置需要重新登入。',
    'Omnigent 只搬 HA 的資料：資料庫結構（資料表、欄位、預設值、檢查與索引）用這台 Omnigent 自己的，HA 備份裡的資料庫結構不會執行。',
    '這台 Omnigent 的管理者與 runner 帳號（admin、operator）會保留，密碼不變。', 'HA 的 Omnigent 分享與管理者執行期設定不會搬過來，這台維持自己的設定。'],
  hermes: ['Hermes 的對話、記憶、技能、排程、外掛與 HA 的設定檔（config.yaml）會換成 HA 的；這台的 Dashboard 密碼、API 金鑰、Webhook 與工作階段金鑰以及 hermes.env 保持不變，hermes.env 中的金鑰會蓋過 HA 的同名金鑰。',
    'HA 的 Hermes 外掛（omnigent、paseo）會取代這台的外掛與配對（例如 Omnigent、Paseo）。'],
  emqx: ['EMQX 的 MQTT 帳號、ACL 規則、Dashboard 帳號、API 金鑰、封鎖名單、PSK、保留訊息與規則、連接器設定會換成 HA 的；這台的節點名稱、連接埠、匿名登入限制與「未符合規則的主題拒絕」設定保持不變。',
    '這台 EMQX 的授權設定（ACL 檔案、授權來源與順序）與 bootstrap 帳號檔保持不變；還原後會再核對設定與內建資料庫都和轉換時相同，不同就自動回復。'],
  headscale: ['Headscale 的使用者、裝置、預先授權金鑰與 DNS 額外記錄會換成 HA 的，HA 的伺服器身分金鑰（noise）也一起搬過來；這台的伺服器網址、IP 位址範圍、存取政策與 API 金鑰保持不變。',
    'HA 的 2 把 Headscale API 金鑰不會搬過來，這台的 2 把（Headplane、MCP 管理）保持有效。'],
};
const mcpLines = (id, admin, server) => [`請到「${admin}」確認或重新設定 ${B1[id].app} 的連線資料（MCP 管理工具的設定不會從 HA 搬過來）。`,
  `如果 HA 上有「${server}」，請把它停掉，並把指向它的 MCP 連接器（例如 claude.ai）刪掉，改用這台的 MCP 網址重新建立。`];
const HERMES_REPAIR = '請重新配對 Hermes 的 Omnigent 與 Paseo 外掛，HA 上的配對不會沿用。';
const HEADSCALE_REPOINT = '請把每一台裝置的登入伺服器改成 https://hs.example.com（例如 tailscale up --login-server=https://hs.example.com），不再使用 HA 的 https://ha-hs.example.com。';
const HA_TODO = {
  odoo: ['請用 HA 那邊 Odoo 的帳號和密碼登入這台的 Odoo。'],
  n8n: ['請用 HA 的管理者帳號（owner@example.com）登入這台的 n8n。', '請確認 HA 搬過來的 n8n 社群節點能正常使用。'],
  omnigent: ['匯入後請用 HA 那邊的 Omnigent 帳號和密碼登入。',
    '請把每一台 runner（例如 HA 的 Pi Agent、其他電腦上的 omnigent host）改連到這台的 Omnigent 網址並重新登入；在那之前 HA 的 runner 會顯示離線。',
    'HA 的 1 個啟用中的排程會在這台執行，請確認它們有可用的 runner。'],
  hermes: ['匯入後請用這台的 Hermes Dashboard 密碼登入（不是 HA 的）。',
    '呼叫 Hermes API 或 Webhook 的地方請改用這台的網址與 API 金鑰；沒有自己金鑰的 Webhook 路由要改用這台的全域金鑰。', HERMES_REPAIR,
    'HA 的 Hermes 設定連到 HA 內部的位址（config.yaml：9c1a67eb-woow-hermes、.env：a0d7b954-litellm），請改成這台連得到的位址（例如這台的 LiteLLM：http://litellm:4000/v1）。',
    'HA 的 1 個 Hermes 排程會在這台執行，請先停掉 HA 的 Hermes，避免重複執行。', ...mcpLines('hermes', 'Hermes MCP 管理', 'Woow Hermes MCP Server')],
  emqx: ['請把 MQTT 裝置與服務（例如 Home Assistant 的 MQTT 整合、Zigbee2MQTT）改連到這台的 EMQX。', '匯入後請用 HA 那邊的 EMQX Dashboard 帳號和密碼登入。',
    'HA 的 EMQX API 金鑰已取代這台的，使用這台 EMQX API 的工具需要換成新的金鑰。', ...mcpLines('emqx', 'EMQX MCP 管理', 'Woow EMQX MCP Server')],
  headscale: [HEADSCALE_REPOINT, '請把 HA 的 Headscale 附加元件永久停用（關掉開機自動啟動）：兩台伺服器使用同一個身分金鑰卻有不同的資料，會讓裝置連線錯亂。',
    ...mcpLines('headscale', 'Headscale MCP 管理', 'Woow Headscale MCP Server')],
};
// A test import pauses Omnigent's active scheduled tasks; the engine says so instead of the line about running them.
const HA_TODO_TEST = { omnigent: [...HA_TODO.omnigent.slice(0, 2), '測試匯入已暫停 1 個排程，確認無誤後再到 Omnigent 重新啟用。'] };
const HA_LEGACY_REMINDERS = {
  odoo: ['Odoo 的使用者帳號和密碼會換成 HA 那邊的：這台原本的 Odoo 管理者密碼不再適用，請用 HA 的帳號登入。',
    'HA 的自訂模組 woow_paas_platform 會一起放進這台的自訂模組資料夾。'],
  n8n: ['n8n 的登入帳號會換成 HA 的管理者帳號（owner@example.com）。', 'HA 的 n8n 社群節點會一起搬過來，請在匯入後確認它們能正常使用。'],
};
function haImportView(apps, { legacy = false, database = 'woowtest', testMode = false, source = HA_SOURCE } = {}) {
  const view = { ha_backup_id: source.id, name: source.name, date: source.date, apps: [...apps],
    odoo_database: apps.includes('odoo') ? database : null, test_mode: testMode,
    workflows_to_fix: apps.includes('n8n') ? structuredClone(WORKFLOWS_TO_FIX) : [],
    addons: apps.map(id => ({ app_id: id, slug: HA_ADDON_OF[id][0], name: HA_ADDON_OF[id][1] })) };
  if (legacy) return { ...view, reminders: apps.flatMap(id => HA_LEGACY_REMINDERS[id]) };
  return { ...view, reminders: [], reminders_by_app: Object.fromEntries(apps.map(id => [id, [...((testMode && HA_TODO_TEST[id]) || HA_TODO[id])]])),
    notes: apps.flatMap(id => HA_NOTES[id]) };
}
// The record of each conversion the tests make, by its apps (the fixture fills in the database and test mode).
const haImports = legacy => Object.fromEntries([['odoo', 'n8n'], ['odoo'], ['n8n']].map(apps => [apps.join(), haImportView(apps, { legacy })]));

// The backup a conversion registers (BackupMeta.from_ha from ha-imports.json).
function convertedMeta(extra = {}, { legacy = false } = {}) {
  return backupMeta(B_HA, {
    note: `由 HA 備份轉換：${HA_NAME}（2026-11-17 21:00）`, apps: [{ id: 'odoo', name: 'Odoo 18' }, { id: 'n8n', name: 'n8n 工作流程' }],
    size: 420 * MiB, from_ha: haImportView(['odoo', 'n8n'], { legacy }),
    ...extra,
  });
}

// The engine refuses a start whose key is missing or wrong (cli.py _ha_selection, review F-03); `<kind>-key-required`
// and `<kind>-wrong-key` are the rare failure inside the job (HA's older formats), run when `data.ha.jobKeyFailure` says.
function haScripts({ check = haCheck(), converted = convertedMeta() } = {}) {
  return {
    'ha-check': [haStep('ha-check', 'decrypt', 30, { cancellable: true }),
      { job: { state: 'succeeded', phase: 'check', phases: phasesAt('ha-check', null), progress: { percent: 100, message: '已完成' },
        finished: '2026-11-18T03:01:00Z', cancellable: false, result: structuredClone(check) }, log: ['2026-11-18T03:01:00Z 檢查完成'] }],
    'ha-check-key-required': [haFailedStep('ha-check', 'decrypt', KEY_REQUIRED)],
    'ha-check-wrong-key': [haFailedStep('ha-check', 'decrypt', WRONG_HA_KEY)],
    'ha-convert': [haStep('ha-convert', 'convert', 45), haStep('ha-convert', 'package', 80),
      { job: { state: 'succeeded', phase: 'verify', phases: phasesAt('ha-convert', null), progress: { percent: 100, message: '已完成' },
        finished: '2026-11-18T03:05:30Z', cancellable: false,
        // The fixture replaces ha_import with the record of the job's own apps, database and test mode.
        result: { backup_id: converted.id, size: converted.size, apps: ['odoo', 'n8n'], encrypted: true, ha_import: haImportView(['odoo', 'n8n']) } },
      log: [`2026-11-18T03:05:30Z 已轉換成備份 ${converted.id} 並通過驗證`], addBackup: converted }],
    'ha-convert-key-required': [haFailedStep('ha-convert', 'decrypt', KEY_REQUIRED)],
    'ha-convert-wrong-key': [haFailedStep('ha-convert', 'decrypt', WRONG_HA_KEY)],
  };
}

function haRestoreScript() {
  return [
    runningStep('restore', 'restore', 60, { safety_backup_id: B_SAFETY_NEW }),
    { job: { state: 'succeeded', phase: 'check', phases: phasesAt('restore', null), progress: { percent: 100, message: '已完成' },
      finished: '2026-11-18T03:12:00Z', cancellable: false,
      result: { apps: ['odoo', 'n8n'], safety_backup_id: B_SAFETY_NEW, rolled_back: false, changed: true, verification: [], warnings: [],
        health: [{ id: 'odoo/health/0', status: 'ok', message: '健康檢查通過：http://127.0.0.1:18069/web/health 回應 200。' }] } },
    log: ['2026-11-18T03:12:00Z 作業結束：已完成'] },
  ];
}

// What inspect says about the converted backup (the fixture keeps only the apps that were converted).
function haInspect() {
  const meta = convertedMeta();
  const content = (id, name, extra) => ({ id, name, adapter: 'quadlet-postgres', owner: { name: 'appowner', uid: 1001 }, images: [], postgres: [],
    volumes: [], secrets_count: 3, config_files_count: 0, verify_snapshot: {}, settings_included: true, ...extra });
  const planned = (id, name) => ({ id, name, restorable: true, mode: 'inplace', checks: [{ id: `${id}/quadlet`, status: 'ok', message: '服務定義完整。' }] });
  return {
    backup: structuredClone(meta),
    manifest: { backup_id: B_HA, created: meta.created, type: 'manual', note: meta.note, tool: { name: 'woowtech-cockpit-backup', version: '2026.11.18.1' },
      source: { hostname: 'dev-a', arch: 'x86_64', os: 'Ubuntu 24.04.3 LTS', podman: '4.9.3', machine_id_sha256: 'b'.repeat(64) },
      consistency: { method: 'writers-stopped', downtime_seconds: 0 }, total_size: 400 * MiB, format: 2, encryption: 'age-x25519',
      apps: [content('odoo', 'Odoo 18', { volumes: [{ name: 'odoo18-db-data-isolated' }, { name: 'odoo18-web-data' }],
        data_dirs: [{ path: '.local/share/odoo18/addons', label: '自訂模組' }] }),
      content('n8n', 'n8n 工作流程', { postgres: [{ id: 'main', database: 'n8n', major: 16 }], volumes: [{ name: 'n8n_n8n_data' }, { name: 'n8n_valkey_data' }] })] },
    preflight: { ok: true, checks: [{ id: 'archive', status: 'ok', message: '備份檔格式與金鑰檢查通過；還原前會再完整驗證全部內容。' }],
      apps: [planned('odoo', 'Odoo 18'), planned('n8n', 'n8n 工作流程')] },
  };
}

// A device with Odoo and n8n (and, unless `mcp` is false, their MCP admin apps) holding uploaded HA backups. `legacy`:
// the engine before FIXPLAN §19 (inspect without from_ha; explanations and to-dos together in `reminders`).
function haFixture({ ha = {}, mcp = true, legacy = false, extra = {} } = {}) {
  const data = fixture(extra);
  data.status.apps.push(app('odoo', 'Odoo 18'), app('n8n', 'n8n 工作流程'),
    ...(mcp ? [app('odoo-mcp-admin', 'Odoo MCP 管理'), app('n8n-mcp-admin', 'n8n MCP 管理')] : []));
  data.ha = { backups: [haMeta(HA_ID)], key: HA_KEY, jobKeyFailure: null, legacy, imports: haImports(legacy), ...ha };
  Object.assign(data.scripts, haScripts(), { restore: haRestoreScript() });
  data.inspect[B_HA] = haInspect();
  return data;
}

// A finished or running HA job record as `jobs` and `job-status` return it.
function haJob(id, kind, state, created, extra = {}) {
  const type = kind === 'ha-check' ? 'verify' : 'backup';
  const running = state === 'running';
  return {
    id, type, state, phase: running ? 'decrypt' : PHASES[kind].at(-1)[0], phases: phasesAt(kind, running ? 'decrypt' : null),
    progress: { percent: running ? 30 : 100, message: running ? '解開 HA 備份' : JOB_STATE_TEXT[state] }, created, started: created,
    finished: running ? null : created.replace(/:00Z$/, ':40Z'), cancellable: false,
    params: { source: 'ha', ha_backup_id: HA_ID, apps: ['odoo', 'n8n'], key_provided: true,
      ...(type === 'backup' ? { odoo_database: 'woowtest', test_mode: false, encrypt: true } : {}) },
    result: null, error: null, ...extra,
  };
}
const JOB_STATE_TEXT = { succeeded: '已完成', failed: '失敗' };
const openHa = async (page, id = HA_ID) => {
  await page.locator('[data-nav="backups"]').click();
  await page.locator(`[data-focus="ha-import-${id}"]`).click();
  await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
};
const setScript = (page, name, steps) => page.evaluate(([key, value]) => { window.__fixture.scripts[key] = value; }, [name, steps]);
const activeStep = page => page.locator('.stepper .step.active .step-label').textContent();

// ------------------------------------------------------------------ 從 HA 備份匯入, batch 1 data (2026-11-19, CONTRACT §7, §9)

// An HA backup of a Raspberry Pi with the four batch 1 add-ons (HA did not encrypt it) and, unless `odoo` is false, the
// Odoo and n8n add-ons this device has not installed.
function haMetaB1(extra = {}, { odoo = true } = {}) {
  const addons = B1_APPS.map(id => ({ slug: B1[id].slug, name: B1[id].addon, version: B1[id].version, encrypted: false }));
  const legacy = odoo ? [{ slug: ODOO_SLUG, name: 'Odoo 18 CE', version: ODOO_ADDON_VERSION, encrypted: false },
    { slug: N8N_SLUG, name: 'WOOW n8n', version: '2.43.6', encrypted: false }] : [];
  return haMeta(HA_B1, {
    name: B1_NAME, date: B1_SOURCE.date, protected: false, size: 2 * GiB, filename: 'rpi5_weekly.tar',
    addons: [...legacy, ...addons, { slug: 'core_mosquitto', name: 'Mosquitto broker', version: '6.5.1', encrypted: false }],
    importable_apps: [...(odoo ? [{ slug: ODOO_SLUG, app_id: 'odoo', app_name: 'Odoo 18', installed: false },
      { slug: N8N_SLUG, app_id: 'n8n', app_name: 'n8n 工作流程', installed: false }] : []),
    ...B1_APPS.map(id => ({ slug: B1[id].slug, app_id: id, app_name: B1[id].app, installed: true }))],
    ...extra,
  });
}

// The engine's words (ha_emqx.py HOT_HINT, analyse; ha_hermes.py analyse; ha_omnigent.py verdict; ha_headscale.py analyse).
const EMQX_HOT_HINT = '這份備份是在 EMQX 執行中製作的，內建資料庫可能只寫了一半；請先在 HA 停止 EMQX 附加元件，再重新製作備份後匯入（附加元件停止時製作的備份最可靠）。';
const EMQX_HOT_WARNING = '這份 HA 備份是在 EMQX 執行中製作的；最近的變更可能還沒寫進內建資料庫。最可靠的做法是先在 HA 停止 EMQX 附加元件再製作備份。';
const EMQX_HALF_LOADED = `HA 的 EMQX 內建資料庫沒有完整載入（缺少 emqx_acl）。${EMQX_HOT_HINT}`;
const EMQX_IMPORT_FAILED = `HA 的 EMQX 資料匯入時發生錯誤（部分資料無法匯入），已停止。${EMQX_HOT_HINT}`;
const HERMES_PLUGINS = 'HA 的 Hermes 外掛（omnigent、paseo）會一起搬過來並取代這台的外掛；Omnigent、Paseo 等配對需要重新設定。';
const B1_WARNINGS = {
  omnigent: ['HA 的 Omnigent 執行期設定檔（sharing.json、admins.json）不會搬過來，這台維持自己的分享與管理者設定。',
    'HA 的 Omnigent 有 1 個啟用中的排程，搬過來後會在這台執行（測試匯入會先全部暫停）。'],
  hermes: ['HA 的 Hermes 設定連到 HA 內部的位址（config.yaml：9c1a67eb-woow-hermes、.env：a0d7b954-litellm），這台連不到，搬過來後請改成實際位址。',
    HERMES_PLUGINS],
  emqx: ['HA 的 EMQX API 金鑰會取代這台的，EMQX MCP 管理需要重新登入。', EMQX_HOT_WARNING],
  headscale: ['HA 的 2 把 Headscale API 金鑰不會搬過來，這台的 API 金鑰（Headplane、MCP 管理）保持有效。'],
};
// Each app's section of HaCheck (CONTRACT §7) as the engine's tests on the real backups found them.
const B1_SECTIONS = {
  omnigent: { omnigent_version: '0.21.0', alembic: 'd0a1f879a01d', users: 2, admins: 1, conversations: 3, scheduled_tasks: 2,
    scheduled_tasks_active: 1, hosts: 1, agents: 1, files: 1, public_sessions: 0, artifact_files: 4, artifact_bytes: 3 * MiB,
    override_files: ['sharing.json', 'admins.json'], account_conflicts: [] },
  hermes: { hermes_version: '0.22.5', target_release: '0.22.5', files: 412, bytes: 96 * MiB, dirs: 57, symlinks: 0, absolute_symlinks: 0,
    hardlinks: 0, databases: 6, sessions: 5, messages: 15, schema_version: 32, config_version: 51, skills: 64, cron_jobs: 1,
    plugins: ['omnigent', 'paseo'], env_keys: 12, ha_urls: ['config.yaml：9c1a67eb-woow-hermes', '.env：a0d7b954-litellm'], media_refs: 0,
    skipped: ['gateway.pid', 'state.db-shm', '.woow-image-version'] },
  emqx: { emqx_version: '5.8.9', target_version: '5.8.9', node_name: 'emqx@127.0.0.1', files: 38, bytes: 2 * MiB, mqtt_users: 3, acl_rules: 4,
    dashboard_users: 2, api_keys: 1, banned: 1, psk: 0, retained_messages: 2, default_dashboard_password: false, anonymous: false,
    hot_backup: true, plugins: [], ha_hosts: [], target_authorization: ['file', 'built_in_database'] },
  headscale: { headscale_version: '0.29.4', target_version: '0.29.4', db_version: 'v0.29.4', users: 3, nodes: 2, pre_auth_keys: 2, api_keys: 2,
    policies: 0, prefixes: { v4: '100.64.0.0/10', v6: 'fd7a:115c:a1e0::/48' }, server_url: 'https://ha-hs.example.com',
    target_server_url: 'https://hs.example.com', dns_records: 1 },
};
// result.ha_check of a batch 1 check (haimport.run_ha_check); `apps` replaces whole app results.
function b1Check(apps = {}) {
  const result = id => ({ app_id: id, slug: B1[id].slug, name: B1[id].addon, arch: 'aarch64', version: B1[id].version,
    target_version: B1[id].product, ok: true, blockers: [], warnings: [...B1_WARNINGS[id]], [id]: structuredClone(B1_SECTIONS[id]) });
  return { ha_check: { ha_backup_id: HA_B1, apps: B1_APPS.map(id => apps[id] || result(id)) } };
}
// A hot backup whose database did not load: the check stops at HA's broker (ha_emqx.ha_broker raises, haimport makes it
// the app's blocker), so the app has the advice and no section.
const emqxHalfLoaded = () => ({ app_id: 'emqx', slug: B1.emqx.slug, name: B1.emqx.addon, arch: 'aarch64', version: B1.emqx.version,
  target_version: '', ok: false, blockers: [EMQX_HALF_LOADED], warnings: [] });

// The record of each conversion of the batch 1 backup, by its apps in the engine's order.
function b1Imports({ testMode = false } = {}) {
  const sets = [];
  for (let mask = 1; mask < 1 << B1_APPS.length; mask += 1) sets.push(B1_APPS.filter((_id, index) => mask & (1 << index)));
  return Object.fromEntries(sets.map(apps => [apps.join(), haImportView(apps, { source: B1_SOURCE, testMode })]));
}
function convertedB1(apps = B1_APPS, { testMode = false } = {}) {
  return backupMeta(B_B1, {
    note: `由 HA 備份轉換：${B1_NAME}（2026-11-19 04:00）`, apps: apps.map(id => ({ id, name: B1[id].app })), size: 900 * MiB,
    from_ha: haImportView(apps, { source: B1_SOURCE, testMode }),
  });
}
function b1RestoreScript() {
  return [
    runningStep('restore', 'restore', 60, { safety_backup_id: B_SAFETY_NEW }),
    { job: { state: 'succeeded', phase: 'check', phases: phasesAt('restore', null), progress: { percent: 100, message: '已完成' },
      finished: '2026-11-19T04:12:00Z', cancellable: false,
      result: { apps: [...B1_APPS], safety_backup_id: B_SAFETY_NEW, rolled_back: false, changed: true, verification: [], warnings: [],
        health: [{ id: 'headscale/health/0', status: 'ok', message: '健康檢查通過：http://127.0.0.1:18080/health 回應 200。' }] } },
    log: ['2026-11-19T04:12:00Z 作業結束：已完成'] },
  ];
}
function b1Inspect() {
  const meta = convertedB1();
  const content = id => ({ id, name: B1[id].app, adapter: 'quadlet-postgres', owner: { name: 'appowner', uid: 1001 }, images: [], postgres: [],
    volumes: [{ name: `${id}-data` }], secrets_count: 2, config_files_count: 1, verify_snapshot: {}, settings_included: true });
  return {
    backup: structuredClone(meta),
    manifest: { backup_id: B_B1, created: meta.created, type: 'manual', note: meta.note, tool: { name: 'woowtech-cockpit-backup', version: '2026.11.19.3' },
      source: { hostname: 'dev-a', arch: 'x86_64', os: 'Ubuntu 24.04.3 LTS', podman: '4.9.3', machine_id_sha256: 'b'.repeat(64) },
      consistency: { method: 'writers-stopped', downtime_seconds: 0 }, total_size: 880 * MiB, format: 2, encryption: 'age-x25519',
      apps: B1_APPS.map(content) },
    preflight: { ok: true, checks: [{ id: 'archive', status: 'ok', message: '備份檔格式與金鑰檢查通過；還原前會再完整驗證全部內容。' }],
      apps: B1_APPS.map(id => ({ id, name: B1[id].app, restorable: true, mode: 'inplace', checks: [{ id: `${id}/quadlet`, status: 'ok', message: '服務定義完整。' }] })) },
  };
}
// A device with the four batch 1 apps and the MCP admin apps of Hermes, EMQX and Headscale (Omnigent has none), holding
// the batch 1 HA backup; `check` is the check job's result.
function b1Fixture({ check = b1Check(), testMode = false, extra = {} } = {}) {
  const data = fixture(extra);
  data.status.apps.push(...B1_APPS.map(id => app(id, B1[id].app)), app('hermes-mcp-admin', 'Hermes MCP 管理'),
    app('emqx-mcp-admin', 'EMQX MCP 管理'), app('headscale-mcp-admin', 'Headscale MCP 管理'));
  data.ha = { backups: [haMetaB1()], key: HA_KEY, jobKeyFailure: null, legacy: false, imports: b1Imports({ testMode }) };
  Object.assign(data.scripts, haScripts({ check, converted: convertedB1() }), { restore: b1RestoreScript() });
  data.inspect[B_B1] = b1Inspect();
  return data;
}
// LiteLLM (owner decision 2026-11-23, 「決定1 做」): the WOOWTECH LiteLLM add-on as the engine's tests name and version it
// (tests/backup/test_ha_litellm.py), its section and warnings (ha_litellm.check: the apps here that use LiteLLM keys,
// read from this device's catalog and configuration, option A).
const LL = { slug: '9663031d_woow-litellm', addon: 'Woow LiteLLM', version: '0.1.15', app: 'LiteLLM 閘道', product: '1.104.0' };
const HA_LL = 'ha-11111111111111111111';
const LL_KEY_USERS = ['Hermes 代理', 'OpenDesign'];
const LL_KEYS_WARNING = '這台的 Hermes 代理、OpenDesign 目前使用這台 LiteLLM 的金鑰；匯入後這台 LiteLLM 的虛擬金鑰會換成 HA 的，這些應用的 LiteLLM 金鑰會失效，請在匯入後為它們重新設定金鑰。';
const LL_SECTION = { litellm_version: '1.104.0', migrations: 118, pg_major: 18, target_pg_major: 17, users: 1, teams: 1, keys: 1, models: 24,
  credentials: 5, organizations: 0, spend_logs: 0, chatgpt_accounts: 0, salt_moves: true, key_users: LL_KEY_USERS };
function llCheck(section = LL_SECTION, warnings = [LL_KEYS_WARNING]) {
  return { ha_check: { ha_backup_id: HA_LL, apps: [{ app_id: 'litellm', slug: LL.slug, name: LL.addon, arch: 'amd64', version: LL.version,
    target_version: LL.product, ok: true, blockers: [], warnings: [...warnings], litellm: structuredClone(section) }] } };
}
// The refusal of an entry that is not the single-database mode (ha_litellm.TARGET_SHAPE) and what the page says before.
const LL_MODE_RULE = 'LiteLLM 的應用設定要用「單一資料庫」方式：在「應用設定」掃描時，還沒安裝的 LiteLLM 草稿已經選好；裝的是其他方式時，請先在那裡改選「單一資料庫」並安裝。';
const LL_MODE_BLOCKER = '這台的 LiteLLM 應用設定不是 HA 匯入支援的樣子：資料庫要用「單一資料庫」方式備份（只有一個資料庫匯出項目，沒有資料卷或主機資料夾；冷備份與整個執行個體都不能匯入）。請到「應用設定」掃描，在 LiteLLM 的草稿選「單一資料庫」並安裝，再匯入一次。改變方式後，這個應用之前的備份無法以新設定還原。';
function llBlockedCheck() {
  const check = llCheck(null, []);
  const [found] = check.ha_check.apps;
  delete found.litellm;
  Object.assign(found, { ok: false, blockers: [LL_MODE_BLOCKER], target_version: '' });
  return check;
}
// The package LiteLLM's draft as catalog-suggest makes it (tests/backup/test_suggest.py LiteLLMPackageTests).
const LL_MODE_NOTE = '草稿已選「單一資料庫」：從 Home Assistant 匯入這個應用只支援這個方式，資料庫執行個體只有這個應用的資料庫時也最適合。改選其他方式仍能備份與還原，但不能從 Home Assistant 匯入。';
function litellmEntry(mode) {
  const db = { id: 'main', container: 'litellm-postgres', unit: 'litellm-postgres.service', user: 'litellm', data_volume: 'litellm-pgdata' };
  const cold = mode === 'cold';
  return { schema: 1, id: 'litellm', name: 'litellm', description: '自動產生的草稿：2 個服務、PostgreSQL 17（單一資料庫）、2 個設定檔、5 個密鑰。請審查後再安裝。',
    owner: 'appowner', adapter: 'quadlet-postgres',
    quadlet: { files: ['litellm.network', 'litellm-pgdata.volume', 'litellm-postgres.container', 'litellm.container'] },
    units: ['litellm-postgres.service', 'litellm.service'],
    writer_units: cold ? ['litellm-postgres.service', 'litellm.service'] : ['litellm.service'],
    postgres: cold ? [] : [mode === 'instance' ? { ...db, scope: 'instance' } : { ...db, database: 'litellm' }],
    volumes: cold ? [{ name: 'litellm-pgdata', label: 'PostgreSQL 資料（冷備份）' }] : [],
    secrets: ['postgres-password', 'database-url', 'master-key', 'ui-password', 'salt-key'].map(name => ({ name: `litellm-${name}` })),
    config_files: [{ path: '.config/litellm/config.yaml', mode: '0644' }, { path: '.config/litellm/litellm.env', mode: '0600' }],
    health: [{ type: 'http', url: 'http://127.0.0.1:4000/health/readiness', expect_status: 200, timeout_seconds: 600 }],
    verify: [cold ? { id: 'db-main', type: 'postgres-digest', container: 'litellm-postgres', unit: 'litellm-postgres.service', user: 'litellm', label: 'PostgreSQL 資料表內容' }
      : { id: 'db-main', type: 'postgres-digest', postgres: 'main', label: 'PostgreSQL 資料表內容' }] };
}
function litellmCatalog() {
  const data = catalogData();
  const image = 'docker.io/library/postgres:17.11-alpine3.23';
  data.scans.appowner.apps = [{
    id: 'litellm',
    containers: [
      { file: 'litellm-postgres.container', unit: 'litellm-postgres.service', container: 'litellm-postgres', image, state: 'active' },
      { file: 'litellm.container', unit: 'litellm.service', container: 'litellm', image: 'localhost/woow-litellm:1.104.0-0.3.16', state: 'active' }],
    databases: [{ unit: 'litellm-postgres.service', container: 'litellm-postgres', kind: 'postgres', image, major: 17, database: 'litellm',
      user: 'litellm', guessed: false, data: { volume: 'litellm-pgdata' } }],
    entry: litellmEntry('database'), valid: true, problem: null, field: null, variant: 'database',
    variants: ['cold', 'instance', 'database'].map(id => ({ id, label: VARIANT_LABELS[id].replace('（預設）', ''), entry: litellmEntry(id),
      valid: true, problem: null, field: null })),
    installed: null, warnings: [], notes: [{ code: 'import-mode', level: 'info', message: LL_MODE_NOTE }], skipped: [],
    hints: ['litellm.container 的健康檢查 /health/liveliness 只表示程式有回應；草稿改用 /health/readiness（會確認資料庫，也是這個套件啟動時等待的檢查）。'] }];
  return data;
}
function llFixture({ check = llCheck() } = {}) {
  const data = fixture();
  data.status.apps.push(app('litellm', LL.app), app('hermes', 'Hermes 代理'), app('litellm-mcp-admin', 'LiteLLM MCP 管理'));
  const meta = haMeta(HA_LL, { name: 'LiteLLM 備份 2026-11-23', date: '2026-11-23T01:49:00Z', protected: false, size: 14 * MiB,
    filename: 'woow-litellm-x86.tar', addons: [{ slug: LL.slug, name: LL.addon, version: LL.version, encrypted: false }],
    importable_apps: [{ slug: LL.slug, app_id: 'litellm', app_name: LL.app, installed: true }] });
  data.ha = { backups: [meta], key: HA_KEY, jobKeyFailure: null, legacy: false, imports: {} };
  Object.assign(data.scripts, haScripts({ check, converted: convertedMeta() }));
  return data;
}
// The page's own reminder for the batch 1 HA file.
const B1_DELETE_LINE = `匯入完成後，建議刪除這份 HA 備份檔（裡面可能有 HA 的密碼與權杖）。 前往 HA 備份「${B1_NAME}」`;
const B1_STOP_LINES = B1_APPS.map(id => `請把 HA 那邊的「${B1[id].addon}」附加元件停掉，避免同一件事兩邊各做一次。`);
// Batch 2 (2026-11-23): the WOOWTECH OpenDesign add-on as ha_opendesign.py reports the real x86 HA backup (its
// section of HaCheck, CONTRACT §7; one engine warning), on a device with OpenDesign and its MCP admin app installed.
const OD = { slug: '1b7b4ce7_woow_ha_opendesign', addon: 'Woow HA OpenDesign', version: '0.2.15', app: 'OpenDesign 設計工具', product: '0.24.1' };
const HA_OD = 'ha-0d0d0d0d0d0d0d0d0d0d';
const OD_WARNING = 'HA 的 OpenDesign 資料中有 5 個指向資料以外的符號連結沒有搬過來（多半在代理程式的登入資料夾裡，這台保留自己的）。';
const OD_SECTION = { 'open-design_version': '0.24.1', source_revision: '05b23f5a', target_version: '0.24.1', target_revision: '05b23f5a',
  files: 77, bytes: 11212414, dirs: 55, symlinks: 0, hardlinks: 0, skipped_symlinks: 5, projects: 12, conversations: 12, messages: 22,
  routines: 0, routines_active: 0, project_folders: 0, mcp_servers: 0, mcp_integration_entries: 1, shared: 2, ha_urls: [],
  left_out: { home: 4600, paseo: 1940, integrations: 4, 'installation.json': 1 } };
function odFixture() {
  const data = fixture();
  data.status.apps.push(app('open-design', OD.app), app('opendesign-mcp-admin', 'OpenDesign MCP 管理'));
  const meta = haMeta(HA_OD, { name: 'OpenDesign 每週備份 2026-11-23', date: '2026-11-23T07:56:03Z', protected: false, size: 1065 * MiB,
    filename: 'woow-b2-opendesign.tar', folders: [], addons: [{ slug: OD.slug, name: OD.addon, version: OD.version, encrypted: false }],
    importable_apps: [{ slug: OD.slug, app_id: 'open-design', app_name: OD.app, installed: true }], other_addons: [] });
  const check = { ha_check: { ha_backup_id: HA_OD, apps: [{ app_id: 'open-design', slug: OD.slug, name: OD.addon, arch: 'amd64',
    version: OD.version, target_version: OD.product, ok: true, blockers: [], warnings: [OD_WARNING], 'open-design': structuredClone(OD_SECTION) }] } };
  data.ha = { backups: [meta], key: HA_KEY, jobKeyFailure: null, legacy: false, imports: {} };
  Object.assign(data.scripts, haScripts({ check }));
  return data;
}
// Batch 2 (2026-11-23): the WOOWTECH code-server add-on as ha_codeserver.py reports the real x86 HA backup (its
// section of HaCheck, CONTRACT §7; the engine's warnings), with a Cloudflare Tunnel and an MCP admin add-on that never
// move (CONTRACT §9 "Batch 2: add-ons that are not moved"), on a device with code-server and Odoo MCP 管理 installed.
const CS = { slug: '1b7b4ce7_woow_ha_code_server', addon: 'Woow Code Server', version: '0.1.14', app: 'code-server 開發環境', product: '4.139.1' };
const CS_CF = { slug: '1b7b4ce7_cloudflared', name: 'Woow Cloudflared', version: '1.1.3' };
const CS_MCP = { slug: '1b7b4ce7_woow_mcp_odoo', name: 'Woow Odoo MCP Server', version: '0.4.14' };
const HA_CS = 'ha-0c0c0c0c0c0c0c0c0c0c';
const CS_WARNINGS = ['這份 HA 備份沒有包含 share 資料夾，HA 的工作區專案（/share/projects）不會搬過來；要一起搬，請在 HA 建立備份時勾選 share，或自行複製。',
  'HA 的 code-server 資料中有這台不認得的項目（codex-bootstrap），不會搬過來；需要時請自行複製。'];
const CS_PINS = { 'code-server': '4.139.1', pi: '0.99.1', claude: '2.1.285', codex: '0.167.0' };
const CS_SECTION = { 'woow-code-server_version': '4.139.1', pins: CS_PINS, target_pins: CS_PINS, files: 386, bytes: 17570555,
  sessions: 28, claude_projects: 20, codex_sessions: 15, skills: 3, snippets: 1, settings: true, extensions: 0, mcp_servers: 9,
  workspace: false, share: false, workspace_files: 0, workspace_bytes: 0, skipped_symlinks: 7, ha_urls: [],
  left_out: { 'pi:own': 12, 'pi:programs': 5, 'pi:state': 1986, 'user:workspaceStorage': 226 }, unknown: ['codex-bootstrap'] };
const CS_CF_LINE = '「Woow Cloudflared」（Cloudflare Tunnel）不會搬過來：請在 HA 的 Cloudflared 頁面記下它的每一條路由（公開網址和對應的服務），'
  + '在這台的 Cloudflare Tunnel 重新加入，服務位址改成這台的應用；用 WOOW PaaS 連結的，請在這台重新連結（換機）。'
  + '確認這台的網址都正常後，再刪掉 HA 那邊的路由並停掉 HA 的 Cloudflared。';
const CS_MCP_LINE = '「Woow Odoo MCP Server」（Odoo 的 MCP 管理工具）不會搬過來：請到這台的「Odoo MCP 管理」重新設定連線，'
  + '再停掉 HA 的「Woow Odoo MCP Server」，並把指向它的 MCP 連接器（例如 claude.ai）刪掉，改用這台的 MCP 網址重新建立。';
function csFixture() {
  const data = fixture();
  data.status.apps.push(app('woow-code-server', CS.app), app('odoo-mcp-admin', 'Odoo MCP 管理'));
  const meta = haMeta(HA_CS, { name: 'code-server 每週備份 2026-11-23', date: '2026-11-23T08:00:19Z', protected: true, size: 598 * MiB,
    filename: 'woow-b2-codeserver.tar', folders: [],
    addons: [{ slug: CS.slug, name: CS.addon, version: CS.version, encrypted: true },
      { slug: CS_CF.slug, name: CS_CF.name, version: CS_CF.version, encrypted: true },
      { slug: CS_MCP.slug, name: CS_MCP.name, version: CS_MCP.version, encrypted: true }],
    importable_apps: [{ slug: CS.slug, app_id: 'woow-code-server', app_name: CS.app, installed: true }],
    other_addons: [CS_CF, CS_MCP] });
  const check = { ha_check: { ha_backup_id: HA_CS, apps: [{ app_id: 'woow-code-server', slug: CS.slug, name: CS.addon, arch: 'amd64',
    version: CS.version, target_version: CS.product, ok: true, blockers: [], warnings: [...CS_WARNINGS],
    'woow-code-server': structuredClone(CS_SECTION) }] } };
  data.ha = { backups: [meta], key: HA_KEY, jobKeyFailure: null, legacy: false, imports: {} };
  Object.assign(data.scripts, haScripts({ check }));
  return data;
}
// Batch 2 (2026-11-23): the WOOWTECH Nextcloud Office add-on as ha_nextcloud.py reports the real x86 HA backups
// (its section of HaCheck, CONTRACT §7 and §9 "Batch 2: Nextcloud"): with HA's share folder the users' files come along;
// without it the import is refused (a database without its files would lose them).
const NC = { slug: '1b7b4ce7_woow-nextcloud-office', addon: 'Woow Nextcloud Office', version: '0.2.3', app: 'Nextcloud 雲端硬碟' };
const HA_NC = 'ha-0e0e0e0e0e0e0e0e0e0e';
const NC_NO_SHARE = '這份 HA 備份沒有包含 share 資料夾，Nextcloud 的使用者檔案（/share/nextcloud）不在備份裡，無法匯入'
  + '（只搬資料庫會讓檔案遺失）。請在 HA 重新做一份備份，並勾選 share 資料夾。';
const NC_WARNINGS = ['HA 的 Nextcloud 設定 filelocking.enabled、defaultapp 不會搬過來（以這台的設定為準）。'];
const NC_SECTION = { nextcloud_version: '35.0.1.1', addon_nextcloud_version: '35.0.1', users: 4, files: 381, shares: 3, tokens: 125,
  calendar_objects: 7, contacts: 8, datadir: '/share/nextcloud', datadir_in_backup: true, datadir_files: 412, datadir_bytes: 210 * MiB,
  custom_apps: ['notes', 'richdocuments', 'tasks'], pg_version: '16', office: true, ha_url: 'https://nextcloud.example.test',
  target_url: 'http://192.0.2.46:18081' };
function ncFixture({ share = true } = {}) {
  const data = fixture();
  data.status.apps.push(app('nextcloud', NC.app));
  const meta = haMeta(HA_NC, { name: 'Nextcloud 備份 2026-11-23', date: '2026-11-23T12:38:18Z', protected: true,
    size: (share ? 4700 : 237) * MiB, filename: 'woow-b2-nextcloud.tar', folders: share ? ['share'] : [],
    addons: [{ slug: NC.slug, name: NC.addon, version: NC.version, encrypted: true }],
    importable_apps: [{ slug: NC.slug, app_id: 'nextcloud', app_name: NC.app, installed: true }], other_addons: [] });
  const section = share ? structuredClone(NC_SECTION)
    : { ...structuredClone(NC_SECTION), users: 3, files: 300, shares: 1, tokens: 125, calendar_objects: 2, contacts: 3,
      datadir_in_backup: false, datadir_files: 0, datadir_bytes: 0 };
  const check = { ha_check: { ha_backup_id: HA_NC, apps: [{ app_id: 'nextcloud', slug: NC.slug, name: NC.addon, arch: 'amd64',
    version: NC.version, target_version: '35.0.1.1', ok: share, blockers: share ? [] : [NC_NO_SHARE], warnings: [...NC_WARNINGS],
    nextcloud: section }] } };
  data.ha = { backups: [meta], key: HA_KEY, jobKeyFailure: null, legacy: false, imports: {} };
  Object.assign(data.scripts, haScripts({ check }));
  return data;
}
const NC_FACTS = { 'Nextcloud 版本': '35.0.1.1', 使用者: '4 位', 檔案: '381 筆檔案紀錄', 使用者檔案: '412 個檔案（210 MiB），來自 /share/nextcloud',
  分享: '3 個', 行事曆與聯絡人: '7 個行程、8 位聯絡人', 自訂應用: 'notes、richdocuments、tasks', Office: 'HA 有啟用，匯入後使用這台的 Collabora',
  'HA 的網址': 'https://nextcloud.example.test', 這台的網址: 'http://192.0.2.46:18081' };
const openNc = async page => {
  await ready(page);
  await page.locator('[data-nav="backups"]').click();
  await page.locator(`[data-focus="open-${HA_NC}"]`).click();
  await page.locator('.ha-addons-table').waitFor();
  const rows = await page.locator('.ha-addons-table tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
  assert.deepEqual(rows, [[`${NC.addon}${NC.slug}`, NC.version, `可以匯入這台的「${NC.app}」`]]);
  await page.locator(`[data-focus="ha-import-${HA_NC}"]`).click();
  await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
  assert.deepEqual(await page.locator('.wizard-card input[type="checkbox"]').evaluateAll(items => items.map(item => [item.id, item.checked, item.disabled])),
    [['ha-app-nextcloud', true, false]]);
  assert.equal(await page.locator('.ha-slow').textContent(), 'Nextcloud 的附加元件檔案比較大，檢查和轉換會花比較久的時間。');
  await page.locator('[data-focus="ha-apps-next"]').click();
  await page.locator('#ha-key').fill(HA_KEY);
  await page.locator('[data-focus="ha-key-next"]').click();
  await page.locator('[data-ha-app="nextcloud"]').waitFor();
  const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
  assert.deepEqual(start, { ha_backup_id: HA_NC, apps: ['nextcloud'], request_id: start.request_id, key: HA_KEY });
  return page.locator('[data-ha-app="nextcloud"]');
};
const openB1 = async page => {
  await page.locator('[data-nav="backups"]').click();
  await page.locator(`[data-focus="ha-import-${HA_B1}"]`).click();
  await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
};

// ------------------------------------------------------------------ 從 HA 備份匯入, HAOS parity (2026-11-25): one confirmation, schema 2
// The engine's words are the engine's: these are test sentences of the same kind as haissues.py's (CONTRACT §7 HaIssue).
const HA_V2 = 'ha-0a1b2c3d4e5f60718293';
const HA_V2_NAME = '每週完整備份 2026-11-24';
const V2_SOURCE = { id: HA_V2, name: HA_V2_NAME, date: '2026-11-24T20:00:00Z' };
const B_V2 = { odoo: '20261125T030100Z-0d00a001', n8n: '20261125T031500Z-0d00a002', emqx: '20261125T032500Z-0d00a003', hermes: '20261125T033500Z-0d00a004' };
const B_V2_SAFETY = { odoo: '20261125T030400Z-5afe0a01', n8n: '20261125T031800Z-5afe0a02', hermes: '20261125T033800Z-5afe0a04' };
// The confirmation key of the engine: id + the first 16 hex digits of a sha256 over [app, id, database, all names sorted].
const keyOf = (app, id, items = [], database = null) => `${id}:${createHash('sha256').update(JSON.stringify([app, id, database, [...items].sort()])).digest('hex').slice(0, 16)}`;
function v2Issue(app, level, id, message, { items = [], more = 0, action = '', database = null } = {}) {
  const issue = { id, level, message, items, more };
  if (action) issue.action = action;
  if (database !== null) issue.database = database;
  if (level === 'confirm') issue.key = keyOf(app, id, items, database);
  return issue;
}
// The record of one job of an import chain as `job-status` answers it (hachain.py `_step_job`): `done` are the GroupResults
// known when it was written.
const V2_GROUP = 'g1a2b3c4d5e6f0042';
function v2ChainRecord({ app = 'n8n', step = 'convert', index = 1, state = 'running', done = [], id = J_HA_RUN, apps = ['odoo', 'n8n'] } = {}) {
  const params = { ...(step === 'convert' ? { source: 'ha', ha_backup_id: HA_V2, apps: [app], odoo_database: app === 'odoo' ? 'prod' : null, test_mode: false, encrypt: true, key_provided: false }
    : { backup_id: B_V2[app], apps: [app], key_provided: false, ha_backup_id: HA_V2 }),
  group: { id: V2_GROUP, index, count: apps.length, kind: 'ha-import', step, app_id: app },
  chain: { apps, test_mode: false, then_restore: true, encrypt: true, key_provided: false, ha_backup_id: HA_V2, acknowledged: {}, choices: {}, results: done } };
  const kind = step === 'convert' ? 'ha-convert' : 'restore';
  const job = step === 'convert' ? haJob(id, kind, state, '2026-11-25T03:20:00Z', { params })
    : { ...haJob(id, 'ha-convert', state, '2026-11-25T03:20:00Z'), type: 'restore', phase: 'restore', phases: phasesAt('restore', 'restore'), params };
  if (step === 'convert') Object.assign(job, { phase: 'convert', phases: phasesAt('ha-convert', 'convert') });
  Object.assign(job, { cancellable: true, params });
  return { job, log: ['2026-11-25T03:20:01Z 階段：進行中'], steps: [] };
}
const V2_PAUSES = v2Issue('_shared', 'confirm', 'shared.pauses', '匯入時會先暫停下列服務，完成後自動啟動回來（約 2 分鐘）。', { items: ['檔案管理 filebrowser', 'code-server'] });
const V2_DEVICE_KEY = v2Issue('_shared', 'auto', 'shared.device-key', '這台還沒有加密金鑰：匯入開始時會自動建立一把，完成後請下載並保存緊急金鑰。');
const V2_ODOO_MODULES = v2Issue('odoo', 'confirm', 'odoo.missing-modules', 'HA 的資料庫「prod」有 1 個模組這台沒有；匯入後它們顯示為未安裝，下次更新 Odoo 會被擋下。', { items: ['website_sale_extra'], database: 'prod' });
const V2_ODOO_TEST_MODULES = v2Issue('odoo', 'confirm', 'odoo.missing-modules', 'HA 的資料庫「test」有 2 個模組這台沒有；匯入後它們顯示為未安裝，下次更新 Odoo 會被擋下。', { items: ['sale_extra', 'stock_extra'], database: 'test' });
const V2_ODOO_DEMO = v2Issue('odoo', 'stop', 'odoo.database-modules', 'HA 的資料庫「demo-old」缺少模組 website_sale_extra，不能搬。', { database: 'demo-old', action: '請把模組放進 HA 的 /share/odoo_addons，重新做 HA 備份後再匯入。' });
const V2_ODOO_AUTO = v2Issue('odoo', 'auto', 'odoo.start-db', '系統會先把資料庫啟動起來讀，讀完就關掉；這台正在用的 Odoo 不受影響。');
const V2_N8N_KEY = v2Issue('n8n', 'confirm', 'n8n.credentials-key', 'HA 的 n8n 沒有備份加密金鑰檔，搬過來的憑證要在匯入後重新輸入。');
const V2_N8N_NOTICE = v2Issue('n8n', 'notice', 'n8n.community-nodes', 'HA 的 n8n 裝了 1 個社群節點，匯入後請確認它能用。', { items: ['n8n-nodes-mqtt-x'] });
const V2_EMQX_HOT = v2Issue('emqx', 'stop', 'emqx.hot-backup', '這份備份是在 EMQX 執行中做的，內建資料庫可能只寫了一半，不能匯入。', { action: '請先在 HA 停止 EMQX 附加元件，再重新做備份後匯入。' });
const V2_ODOO_SECTION = () => ({ databases: [odooDb('prod'), odooDb('test', { partners: 55, custom_modules: [] }), { ...blockedDb(), name: 'demo-old' }] });

// The legacy words a schema 2 app still carries for older pages (blockers = stop and confirm, warnings = the others).
function v2App(app, { issues = [], ok, importable = true, choices = null, section = null, extra = {} }) {
  const sentences = levels => issues.filter(issue => levels.includes(issue.level)).map(issue => issue.message);
  const result = { app_id: app, slug: HA_ADDON_OF[app][0], name: HA_ADDON_OF[app][1], arch: 'amd64', version: app === 'odoo' ? ODOO_ADDON_VERSION : '2.43.6',
    target_version: app === 'odoo' ? ODOO_RELEASE : app === 'emqx' ? '5.8.9' : '2.43.6', importable, issues, ok: ok ?? (importable && !issues.some(issue => issue.level === 'confirm')),
    blockers: sentences(['stop', 'confirm']), warnings: sentences(['auto', 'notice']), ...extra };
  if (choices) result.choices = choices;
  if (section) Object.assign(result, section);
  return result;
}
// result.ha_check of schema 2: Odoo (two databases can move, one cannot), n8n (confirm line), EMQX (stopped), shared lines.
function v2Check({ shared = [V2_PAUSES, V2_DEVICE_KEY], odoo = {}, n8n = {}, emqx = {}, apps = ['odoo', 'n8n', 'emqx'] } = {}) {
  const all = {
    odoo: v2App('odoo', { issues: [V2_ODOO_MODULES, V2_ODOO_TEST_MODULES, V2_ODOO_DEMO, V2_ODOO_AUTO],
      choices: { database: [{ value: 'prod', label: 'prod', ok: true }, { value: 'test', label: 'test', ok: true }, { value: 'demo-old', label: 'demo-old', ok: false }] },
      section: { odoo: V2_ODOO_SECTION() }, ...odoo }),
    n8n: v2App('n8n', { issues: [V2_N8N_KEY, V2_N8N_NOTICE],
      section: { n8n: { owner_email: 'owner@example.com', workflows: 14, workflows_active: 6, credentials: 9, executions: 1520, users: 2, projects: 2,
        variables: 0, data_tables: 0, community_packages: [{ name: 'n8n-nodes-mqtt-x', version: '1.4.2' }], workflows_to_fix: WORKFLOWS_TO_FIX } }, ...n8n }),
    emqx: v2App('emqx', { issues: [V2_EMQX_HOT], importable: false, ok: false, ...emqx }),
  };
  return { ha_check: { schema: 2, ha_backup_id: HA_V2, shared: structuredClone(shared), apps: apps.map(id => structuredClone(all[id])) } };
}
function v2Meta(extra = {}) {
  return haMeta(HA_V2, { name: HA_V2_NAME, protected: false, date: '2026-11-24T20:00:00Z',
    addons: [{ slug: ODOO_SLUG, name: 'Odoo 18 CE', version: ODOO_ADDON_VERSION, encrypted: false }, { slug: N8N_SLUG, name: 'WOOW n8n', version: '2.43.6', encrypted: false },
      { slug: B1.emqx.slug, name: B1.emqx.addon, version: B1.emqx.version, encrypted: false }, { slug: B1.hermes.slug, name: B1.hermes.addon, version: B1.hermes.version, encrypted: false }],
    importable_apps: [{ slug: ODOO_SLUG, app_id: 'odoo', app_name: 'Odoo 18', installed: true }, { slug: N8N_SLUG, app_id: 'n8n', app_name: 'n8n 工作流程', installed: true },
      { slug: B1.emqx.slug, app_id: 'emqx', app_name: B1.emqx.app, installed: true }, { slug: B1.hermes.slug, app_id: 'hermes', app_name: B1.hermes.app, installed: true }],
    other_addons: [], ...extra });
}
// The backup each conversion registers (BackupMeta.from_ha).
function v2Backup(app) {
  return backupMeta(B_V2[app], { note: `由 HA 備份轉換：${HA_V2_NAME}`, apps: [{ id: app, name: haAppNameOf(app) }], size: 200 * MiB,
    from_ha: haImportView([app], { source: V2_SOURCE, database: 'prod' }) });
}
const haAppNameOf = app => ({ odoo: 'Odoo 18', n8n: 'n8n 工作流程', emqx: B1.emqx.app, hermes: B1.hermes.app })[app];
// The full copy of a database service that an import keeps (RESTORE lane, kept.py): a `safety` backup whose note starts 保留的複本：, `kept: true`.
const B_V2_KEPT = { n8n: '20261125T031700Z-6e97e001', odoo: '20261125T030500Z-6e97e002' };
const v2Kept = (app = 'n8n') => backupMeta(B_V2_KEPT[app], { type: 'safety', kept: true, size: 310 * MiB, verified: { at: '2026-11-25T03:17:30Z', ok: true },
  note: `保留的複本：${haAppNameOf(app)} 的資料庫服務（匯入 HA 備份「${HA_V2_NAME}」前）`, apps: [{ id: app, name: haAppNameOf(app) }] });
// What RestoreResult.kept says of it: the databases in it, what was put back and what was not.
const V2_KEPT_DETAIL = { databases: ['analytics', 'crm_old'], more: 3, put_back: ['analytics'],
  not_put_back: [{ name: 'crm_old', reason: '資料庫擁有者的角色在新的資料庫服務裡已經存在，沒有放回。' }], notes: ['放不回去的資料庫仍在這份複本裡。'] };
const V2_PAUSE_WARNING = '匯入時暫停的服務沒有重新啟動：filebrowser。請到「應用軟體」把它啟動起來。';
// A device with the four apps, holding one HA backup; the check job answers `check`, the chain does what `outcomes` says.
function v2Fixture({ check = v2Check(), outcomes = {}, key = true, extra = {}, meta = v2Meta(), skipped = [], chain = {}, left = null } = {}) {
  const data = haFixture({ extra });
  data.status.apps.push(app('emqx', B1.emqx.app), app('hermes', B1.hermes.app));
  if (!key) data.status.key = null;
  data.ha.backups = [meta];
  data.ha.key = HA_KEY;
  const apps = ['odoo', 'n8n', 'emqx', 'hermes'];
  data.ha.chain = { outcomes, backups: Object.fromEntries(apps.map(id => [id, v2Backup(id)])), safety: B_V2_SAFETY, skipped, ...chain };
  if (left) data.ha.chain.backups.odoo.from_ha.left_databases = [...left];
  data.scripts['ha-check'] = haScripts({ check })['ha-check'];
  return data;
}

try {
  await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });

  await test('static source rules: DOM-only rendering, fixed helper, no remote assets', async () => {
    const js = await readFile(join(root, 'backup/backup.js'), 'utf8');
    const html = await readFile(join(root, 'backup/index.html'), 'utf8');
    const css = await readFile(join(root, 'backup/backup.css'), 'utf8');
    const manifest = JSON.parse(await readFile(join(root, 'backup/manifest.json'), 'utf8'));
    for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'sessionStorage']) {
      assert(!js.includes(banned), `backup.js must not use ${banned}`);
    }
    // The page only reads Cockpit's own theme preference; it never stores anything in the browser.
    assert.deepEqual([...js.matchAll(/localStorage[.\w]*\([^)]*\)/g)].map(match => match[0]), ["localStorage.getItem('shell:style')"]);
    assert.equal(js.split('localStorage').length - 1, 1, 'localStorage is used exactly once, to read shell:style');
    assert(js.includes('"/usr/local/libexec/woowtech-cockpit-backup"'));
    // In the sidebar's Tools group, right below 應用軟體 (order 40); scripts/check_source.py checks the neighbours.
    assert.equal(manifest.menu, undefined, 'not in the System group');
    assert.equal(manifest.tools.index.label, '備份與還原');
    assert.equal(manifest.tools.index.order, 41);
    assert.deepEqual([...html.matchAll(/<script\b[^>]*>/g)].map(match => match[0]),
      ['<script src="../base1/cockpit.js" defer>', '<script src="backup.js" defer>'], 'only the two package scripts, no inline script');
    assert(!/\sstyle=/.test(html) && !/<style/.test(html), 'no inline styles');
    assert(html.includes('href="../../static/branding.css"') && html.includes('href="backup.css"'));
    assert(!/https?:\/\//.test(css) && !/@font-face|@import/.test(css), 'fonts come from branding.css; no remote assets');
    assert(!/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(js + html + css), 'no emoji');
  });

  await check('key setup shows the emergency kit once, downloads it as a Blob and confirms it',
    fixture({ status: { ...fixture().status, key: null } }), async (page) => {
      await ready(page);
      await page.locator('#key-banner').waitFor();
      assert.match(await page.locator('#key-banner').textContent(), /尚未建立加密金鑰/);
      await page.locator('#key-banner a').click();
      await page.waitForFunction(() => window.location.hash === '#/keys');
      await page.locator('[data-focus="key-create"]').click();
      await page.locator('#kit-secret').waitFor();
      assert.equal((await calls(page, 'key-init')).length, 1);
      assert.equal((await calls(page, 'key-kit')).length, 1);
      assert.equal(await page.locator('#kit-secret').textContent(), SECRET, 'the secret line is extracted from the kit and shown');
      assert.match(await view(page).textContent(), new RegExp(KEY_ID));
      await page.locator('#key-banner').waitFor();
      assert.match(await page.locator('#key-banner').textContent(), /尚未確認已保存緊急金鑰/, 'banner persists until the kit is confirmed');
      await shot(page, 'keys-emergency-kit-1440.png');
      const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-focus="kit-download"]').click()]);
      assert.equal(download.suggestedFilename(), `woowtech-backup-key-dev-a-${KEY_ID}.txt`);
      assert.equal(await readFile(await download.path(), 'utf8'), kitText(SECRET, KEY_ID), 'the downloaded kit is the helper text verbatim');
      assert.equal(await page.locator('[data-focus="kit-done"]').isDisabled(), true, 'confirmation needs the explicit checkbox');
      await page.locator('#kit-confirm').check();
      await enabled(page, '[data-focus="kit-done"]');
      await page.locator('[data-focus="kit-done"]').click();
      await page.locator('#key-banner').waitFor({ state: 'hidden' });
      assert.deepEqual(requestOf((await calls(page, 'key-confirm')).at(-1)), { key_id: KEY_ID });
      assert.equal(await page.locator('#kit-secret').count(), 0, 'the secret is not shown again after confirmation');
      assert(!(await page.content()).includes(SECRET), 'the secret is gone from the DOM');
      assert.match(await view(page).textContent(), /已保存緊急金鑰/);
      // Import another device's key: malformed text never reaches the helper; the kit text is reduced to its key line.
      await page.locator('#import-text').fill('hello');
      await page.locator('[data-focus="import-submit"]').click();
      await page.getByText('找不到以 AGE-SECRET-KEY-1 開頭的完整金鑰').waitFor();
      assert.equal((await calls(page, 'key-import')).length, 0);
      await page.locator('#import-file').setInputFiles({ name: 'kit-dev-b.txt', mimeType: 'text/plain', buffer: Buffer.from(kitText(OTHER_SECRET, OTHER_KEY_ID, 'dev-b')) });
      await page.waitForFunction(secret => document.querySelector('#import-text')?.value === secret, OTHER_SECRET);
      await page.locator('[data-focus="import-submit"]').click();
      await view(page).getByText(`已匯入金鑰 ${OTHER_KEY_ID}。`).waitFor();
      assert.deepEqual((await calls(page, 'key-import')).map(requestOf), [{ key: OTHER_SECRET }]);
      await page.locator('.item-title', { hasText: OTHER_KEY_ID }).waitFor();
      assert.equal(await page.locator('#import-text').inputValue(), '', 'the pasted key is cleared after import');
    });

  await check('create backup follows job phases to success; download uses the external fsread1 channel URL', fixture(), async (page) => {
    await ready(page);
    await page.locator('#go-create').click();
    await page.locator('[data-focus="create-app-woowbk-demo"]').waitFor();
    assert.equal(await page.locator('[data-focus="create-app-woowbk-demo"]').isChecked(), true);
    assert.equal(await page.locator('[data-focus="create-app-woowbk-wiki"]').isDisabled(), true, 'not-deployed apps cannot be selected');
    await page.locator('#include-images').check();
    await page.locator('#backup-note').fill('更新前備份');
    await shot(page, 'create-backup-1440.png');
    await page.locator('[data-focus="create-submit"]').click();
    await page.waitForFunction(() => /^#\/jobs\/j\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(window.location.hash));
    const start = requestOf((await calls(page, 'backup-start')).at(-1));
    assert.deepEqual(Object.keys(start).sort(), ['apps', 'encrypt', 'include_images', 'note', 'request_id']);
    assert.equal(start.encrypt, true, '加密此備份 follows 預設加密備份 (on)');
    assert.deepEqual(start.apps, ['woowbk-demo']);
    assert.equal(start.include_images, true);
    assert.equal(start.note, '更新前備份');
    assert.match(start.request_id, UUID_RE, 'request_id comes from crypto.randomUUID()');
    await page.locator('.phase-active').filter({ hasText: '匯出資料庫' }).waitFor();
    assert.equal(await page.locator('.phase-done').count(), 3);
    assert.equal(await page.locator('#job-progress').getAttribute('value'), '40');
    assert.equal(await page.locator('[data-focus="job-cancel"]').isVisible(), false, 'not cancellable after writers stopped');
    await shot(page, 'job-running-1440.png');
    await page.locator('.phase-active').filter({ hasText: '加密封裝' }).waitFor();
    assert.equal(await page.locator('[data-focus="job-cancel"]').isVisible(), true, 'cancellable again while packaging');
    await page.locator('#result-heading').filter({ hasText: '備份完成' }).waitFor();
    assert.match(await page.locator('.log').textContent(), /已建立並通過完整驗證/);
    assert.match(await view(page).textContent(), /52\.0 MiB/);
    assert.match(await view(page).textContent(), /7 秒/);
    // Writer pause and unavailability per app (CONTRACT §7 Timing), one decimal.
    assert.deepEqual(await page.locator('table.timing tbody tr').evaluateAll(rows => rows.map(row => [...row.children].map(cell => cell.textContent))),
      [['示範筆記應用', '6.6 秒', '9.4 秒']]);
    assert.match(await view(page).textContent(), /服務無法使用9\.4 秒/);
    const statusPolls = (await calls(page, 'job-status')).length;
    assert(statusPolls >= 3, 'polled job-status while active');
    await page.waitForTimeout(1800);
    assert.equal((await calls(page, 'job-status')).length, statusPolls, 'polling stops once the job is terminal');
    const before = downloadRequests.length;
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-focus="result-download"]').click()]);
    assert.deepEqual(requestOf((await calls(page, 'download-info')).at(-1)), { backup_id: B_NEW });
    assert.equal(download.suggestedFilename(), 'woowtech-backup-dev-a-20261113-020500.tar', 'names carry seconds');
    const request = downloadRequests[before];
    assert.equal(request.token, CSRF, 'the channel URL carries the CSRF token from cockpit.transport');
    assert.deepEqual(request.open, {
      payload: 'fsread1', binary: 'raw', path: `/var/lib/woowtech-backup/archives/${B_NEW}.tar`, superuser: 'require', max_read_size: -1,
      external: { 'content-disposition': "attachment; filename*=UTF-8''woowtech-backup-dev-a-20261113-020500.tar", 'content-type': 'application/octet-stream' },
    });
    const frame = await page.locator('#downloads iframe').last().getAttribute('src');
    assert(frame.startsWith(`/cockpit/channel/${CSRF}?`), 'prefix is the pathname of transport.uri("channel/" + csrf_token)');
    await page.waitForTimeout(600);
    assert.equal(await page.locator('#action-error').textContent(), '', 'a started download is not reported as an error');
    await shot(page, 'job-backup-succeeded-1440.png');
  });

  await check('upload streams 512 KiB frames within a 4 MiB ack window; cancel closes the channel and aborts',
    fixture({ ackMode: 'manual' }), async (page) => {
      await ready(page);
      await page.locator('[data-nav="restore"]').click();
      const size = 6 * MiB + 1234;
      await page.locator('#restore-file').setInputFiles({ name: 'woowtech-backup-dev-b-20261113-0100.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(size, 7) });
      await page.locator('[data-focus="restore-upload"]').click();
      await page.waitForFunction(() => window.testchannels.at(-1)?.sent >= 4 * 1024 * 1024);
      await page.waitForTimeout(300);
      let [channel] = await channels(page);
      assert.deepEqual(channel.options, { payload: 'fsreplace1', path: UPLOAD_PATH, binary: true, superuser: 'require', size, 'send-acks': 'bytes' });
      assert.equal(channel.sent, 4 * MiB, 'sending stops at 4 MiB unacknowledged');
      assert.equal(channel.frames, 8);
      assert.equal(channel.maxFrame, 512 * KiB);
      assert.deepEqual(requestOf((await calls(page, 'upload-begin')).at(-1)), { filename: 'woowtech-backup-dev-b-20261113-0100.woowbackup', size });
      assert.equal(await page.locator('#upload-percent').textContent(), '0%', 'progress comes from acks, not from sent bytes');
      await page.evaluate(() => window.__fixture.releaseAcks(2));
      await page.waitForFunction(() => document.querySelector('#upload-percent')?.textContent === '16%');
      assert.equal(await page.locator('#upload-bytes').textContent(), '已上傳 1.0 MiB / 6.0 MiB');
      await page.waitForFunction(() => window.testchannels.at(-1).sent === 5 * 1024 * 1024);
      [channel] = await channels(page);
      assert(channel.maxUnacked <= 4 * MiB, 'never more than 4 MiB unacknowledged');
      await shot(page, 'restore-upload-progress-1440.png');
      await page.locator('[data-focus="upload-cancel"]').click();
      await page.locator('[data-focus="restore-upload"]').waitFor();
      [channel] = await channels(page);
      assert.equal(channel.closedBy, 'client', 'cancel closes the fsreplace1 channel');
      assert.equal(channel.done, false, 'a cancelled upload never sends done');
      assert.deepEqual((await calls(page, 'upload-abort')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
      assert.equal((await calls(page, 'upload-finish')).length, 0);
      assert.match(await view(page).textContent(), /已取消上傳，暫存檔已清除/);
      // Cancelling while upload-begin is still running must still remove the placeholder it creates.
      await page.evaluate(() => window.__fixture.hold.push('upload-begin'));
      await page.locator('#restore-file').setInputFiles({ name: 'second.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(4096, 1) });
      await page.locator('[data-focus="restore-upload"]').click();
      await page.waitForFunction(() => window.__fixture.waiting.some(item => item.command === 'upload-begin'));
      await page.locator('[data-focus="upload-cancel"]').click();
      await page.locator('[data-focus="restore-upload"]').waitFor();
      await page.evaluate(() => window.__fixture.release('upload-begin'));
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'upload-abort').length === 2);
      assert.equal((await channels(page)).length, 1, 'no channel is opened after a cancel');
      assert.equal((await calls(page, 'upload-finish')).length, 0);
    });

  await check('key-required upload: kit key, per-app preflight, explicit confirmation, progress and result table', fixture(), async (page) => {
    await ready(page);
    await page.locator('#go-restore').click();
    const size = Math.round(1.5 * MiB) + 77;
    await page.locator('#restore-file').setInputFiles({ name: 'woowtech-backup-dev-b-20261113-0100.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(size, 3) });
    await page.locator('[data-focus="restore-upload"]').click();
    await page.locator('#key-text').waitFor();
    const [channel] = await channels(page);
    assert.equal(channel.sent, size);
    assert.equal(channel.done, true, 'channel.control({command: "done"}) after the last frame');
    assert.equal(channel.closedBy, 'bridge', 'waited for the bridge close before upload-finish');
    assert.equal(channel.frames, Math.ceil(size / (512 * KiB)));
    assert(channel.maxUnacked <= 4 * MiB);
    assert.deepEqual((await calls(page, 'upload-finish')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
    assert.deepEqual(requestOf((await calls(page, 'inspect'))[0]), { backup_id: B_UPLOADED }, 'first inspect has no key');
    assert.match(await view(page).textContent(), new RegExp(`金鑰 ${OTHER_KEY_ID} 加密`));
    assert.equal(await page.locator('.stepper .step.active').textContent(), '3金鑰（目前步驟）');
    await page.locator('#key-text').fill('not a key at all');
    await page.locator('[data-focus="key-submit"]').click();
    await page.getByText('找不到以 AGE-SECRET-KEY-1 開頭的完整金鑰').waitFor();
    assert.equal((await calls(page, 'inspect')).length, 1, 'malformed keys are rejected in the browser');
    await page.locator('#key-text').fill(`金鑰：\n${SECRET.toLowerCase()}\n`);
    await page.locator('[data-focus="key-submit"]').click();
    await page.getByText('這把金鑰無法解開這份備份（金鑰 ID 不符）').waitFor();  // review F4: a clear wrong-key message
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_UPLOADED, key: SECRET }, 'only the canonical key line is sent');
    await page.locator('#key-file').setInputFiles({ name: 'woowtech-backup-key-dev-b.txt', mimeType: 'text/plain', buffer: Buffer.from(kitText(OTHER_SECRET, OTHER_KEY_ID, 'dev-b')) });
    await page.waitForFunction(secret => document.querySelector('#key-text')?.value === secret, OTHER_SECRET);
    await shot(page, 'restore-key-1440.png');
    await page.locator('[data-focus="key-submit"]').click();
    await page.locator('.app-preflight').first().waitFor();
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_UPLOADED, key: OTHER_SECRET });
    const demo = page.locator('[data-focus="pf-select-woowbk-demo"]');
    const wiki = page.locator('[data-focus="pf-select-woowbk-wiki"]');
    assert.equal(await demo.isChecked(), true);
    assert.equal(await wiki.isDisabled(), true, 'failed apps cannot be selected');
    assert.match(await view(page).textContent(), /此設備沒有設定這個應用，無法還原。/);
    assert.match(await view(page).textContent(), /UID（1007）/);
    assert.equal(await page.locator('.check-fail').count(), 1);
    assert.equal(await page.locator('.check-warn').count(), 1);
    await shot(page, 'restore-preflight-1440.png');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    const start = page.locator('[data-focus="confirm-start"]');
    assert.equal(await start.isDisabled(), true, 'restore needs the explicit confirmation checkbox');
    const confirmText = await view(page).textContent();
    assert.match(confirmText, /示範筆記應用/);
    assert(!/團隊知識庫/.test(await page.locator('.affected').textContent()), 'only selected apps are listed as affected');
    // An archive from before host directories (no data_dirs) lists none and says nothing about them.
    assert.equal(await page.locator('.path-list').count(), 0);
    assert(!/主機資料夾/.test(await page.locator('.affected').textContent()));
    assert.match(confirmText, /停止服務/);
    assert.match(confirmText, /還原前自動備份/);
    assert.match(confirmText, /直接用這份資料回復/);
    assert.match(confirmText, /應用恢復執行後，這份資料會封裝並完整驗證成「還原前自動備份」/);
    assert.equal((await calls(page, 'restore-start')).length, 0);
    await page.locator('#confirm-restore').check();
    await enabled(page, '[data-focus="confirm-start"]');
    await shot(page, 'restore-confirm-1440.png');
    await start.click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    const restore = requestOf((await calls(page, 'restore-start')).at(-1));
    assert.deepEqual(Object.keys(restore).sort(), ['apps', 'backup_id', 'confirm', 'key', 'request_id']);
    assert.deepEqual(restore.apps, ['woowbk-demo']);
    assert.equal(restore.confirm, true);
    assert.equal(restore.key, OTHER_SECRET);
    assert.match(restore.request_id, UUID_RE);
    await page.locator('.stepper .step.active').filter({ hasText: '進度' }).waitFor();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.match(await page.locator('.stepper .step.active').textContent(), /結果/);
    const rows = await page.locator('.compare tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
    assert.deepEqual(rows.find(row => row[1] === 'summary.notes').slice(2), ['12', '12', '相同']);
    assert.deepEqual(rows.find(row => row[1] === 'summary.signatures_valid').slice(2), ['true', 'true', '相同']);
    assert.match(rows[0][0], /資料一致/);
    assert.match(await view(page).textContent(), /健康檢查通過/);
    assert.match(await view(page).textContent(), new RegExp(B_SAFETY_NEW));
    // Review HD-09: what the restore could not keep is said on the result, not only in the job log.
    assert.equal(await page.locator('ul[aria-label="還原注意事項"] .check-warn .check-message').textContent(), RESTORE_NOTE);
    for (const call of await calls(page, 'job-status')) assert(!call.stdin.includes('AGE-SECRET-KEY'), 'the key is not resent after the job started');
    await shot(page, 'restore-result-1440.png');
  });

  await check('failed restore that rolled back shows the error, safety backup and before/after comparison',
    fixture({ scripts: { ...scripts(), restore: rolledBackScript() } }), async (page) => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
      await page.locator('[data-focus="pf-next"]').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_MANUAL }, 'device key available: no key prompt');
      assert.equal(await page.locator('.stepper .step').filter({ hasText: '金鑰' }).count(), 0, 'key step only when key-required');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原失敗，已自動回復' }).waitFor();
      const text = await view(page).textContent();
      assert.match(text, /還原後的資料與備份時不一致/);
      assert.match(text, /已自動回復/);
      assert.match(text, new RegExp(B_SAFETY_NEW));
      assert.equal(await page.locator('.phase-failed').count(), 1);
      assert.match(await page.locator('.phase').filter({ hasText: '自動回復' }).textContent(), /完成/);
      const rows = await page.locator('.compare tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
      assert.deepEqual(rows.find(row => row[1] === 'summary.notes').slice(2), ['12', '11', '不同']);
      assert.match(rows[0][0], /資料不一致/);
      // Review F8: after a successful rollback the primary action is not another destructive restore.
      assert.equal(await page.locator('[data-focus="result-restore-safety"]').count(), 0);
      assert.match(await page.locator('[data-focus="result-overview"]').getAttribute('class'), /primary/);
      assert.match(text, /不需要再做其他處理/);
      await shot(page, 'restore-rolled-back-1440.png');
      const restore = requestOf((await calls(page, 'restore-start')).at(-1));
      assert.equal(restore.key, undefined, 'no key is sent when the device holds it');
    });

  const interrupted = fixture();
  interrupted.jobs[J_ACTIVE] = {
    job: { id: J_ACTIVE, type: 'restore', state: 'running', phase: 'restore', phases: phasesAt('restore', 'restore'),
      progress: { percent: 61, message: '還原資料' }, created: '2026-11-13T01:50:00Z', started: '2026-11-13T01:50:01Z', finished: null,
      params: { backup_id: B_MANUAL, apps: ['woowbk-demo'], key_provided: false }, result: null, error: null, cancellable: false },
    log: ['2026-11-13T01:50:00Z 作業已排入背景執行', '2026-11-13T01:51:00Z 階段：還原資料'],
    steps: [{
      job: { state: 'interrupted', finished: '2026-11-13T02:00:00Z', progress: { percent: 61, message: '已中斷' },
        phases: phasesAt('restore', 'restore', { failedAt: 'restore' }),
        error: { code: 'job-failed', message: `還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。請檢查應用狀態，必要時使用還原前備份再次還原。還原前備份：${B_SAFETY}。` },
        result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY, health: [], verification: [], rolled_back: false } },
      log: [`2026-11-13T02:00:00Z 作業被判定為已中斷`],
    }],
  };
  interrupted.status.active_job = structuredClone(interrupted.jobs[J_ACTIVE].job);
  await check('a reload resumes the active job; interrupted restore shows guidance and offers the safety backup', interrupted, async (page) => {
    await page.waitForFunction(id => window.location.hash === `#/jobs/${id}`, J_ACTIVE);
    await page.locator('#result-heading').filter({ hasText: '作業意外中斷' }).waitFor();
    const text = await view(page).textContent();
    assert.match(text, /應用可能處於不完整狀態/);
    assert.match(text, /接下來怎麼做/);
    assert.match(text, /系統不會自動重做中斷的作業/);
    assert.equal(await page.locator('#job-banner').isVisible(), false, 'no duplicate banner on the job page itself');
    await shot(page, 'job-interrupted-1440.png');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'job-interrupted-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-focus="result-restore-safety"]').click();
    await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_SAFETY);
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_SAFETY });
    assert.equal((await calls(page, 'restore-start')).length, 0, 'nothing is replayed automatically');
  });

  // 2026.11.14.2: a restore that had finished and passed its checks, interrupted only while packaging its safety backup
  // (the recovery packaged it afterwards), is not offered to be reverted.
  const finishedInterrupted = fixture();
  finishedInterrupted.jobs[J_ACTIVE] = structuredClone(interrupted.jobs[J_ACTIVE]);
  Object.assign(finishedInterrupted.jobs[J_ACTIVE].steps[0].job, {
    error: { code: 'job-failed', message: `還原已完成並通過檢查，但在封裝還原前備份時作業中斷（例如系統重新開機）。應用不需要再次還原。已將保留的還原前資料封裝成還原前備份 ${B_SAFETY}，可用它再次還原。` },
    result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY, safety_pending: false, finishing: true, health: [],
      verification: [], rolled_back: false, changed: true },
  });
  finishedInterrupted.status.active_job = structuredClone(finishedInterrupted.jobs[J_ACTIVE].job);
  await check('an interrupted restore that had already finished is not offered to be reverted', finishedInterrupted, async (page) => {
    await page.waitForFunction(id => window.location.hash === `#/jobs/${id}`, J_ACTIVE);
    await page.locator('#result-heading').filter({ hasText: '作業意外中斷' }).waitFor();
    const text = await view(page).textContent();
    assert.match(text, /應用不需要再次還原/);
    assert.match(text, /作業在最後的整理步驟中斷/);
    assert.equal(await page.locator('[data-focus="result-restore-safety"]').count(), 0, 'no revert offer');
    assert.equal(await page.locator('[data-focus="result-safety"]').count(), 1, 'the safety backup is still named');
  });

  await check('busy refusal links to the running job and keeps the request', fixture({
    failures: [{ command: 'backup-start', code: 'busy', message: '已有備份或還原作業正在進行，請等它完成後再試。', details: { job_id: J_OTHER } }],
  }), async (page) => {
    await ready(page);
    await page.locator('#go-create').click();
    await page.locator('[data-focus="create-submit"]').click();
    await page.getByText('已有備份或還原作業正在進行').waitFor();
    assert.equal(await page.locator('[data-focus="error-busy-job"]').getAttribute('href'), `#/jobs/${J_OTHER}`);
    const first = requestOf((await calls(page, 'backup-start'))[0]);
    await page.locator('[data-focus="create-submit"]').click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    const second = requestOf((await calls(page, 'backup-start'))[1]);
    assert.equal(second.request_id, first.request_id, 'a retry of the same intent reuses the request id');
  });

  await check('admin-required state runs nothing until access is granted, then reloads', fixture({ allowed: false }), async (page) => {
    await page.locator('#access-note').waitFor();
    await settled(page);
    assert.match(await page.locator('#access-note').textContent(), /管理員存取權限/);
    assert.match(await view(page).textContent(), /需要管理員權限/);
    await page.waitForFunction(() => document.querySelector('#access-text')?.textContent.includes('devadmin'));
    const attempted = (await page.evaluate(() => window.testcalls.map(call => call.argv[1])));
    assert.deepEqual([...new Set(attempted)], ['status'], 'only the initial status read was attempted');
    await shot(page, 'admin-required-1440.png');
    await page.evaluate(() => window.__fixture.setAllowed(true));
    await page.locator('#access-note').waitFor({ state: 'hidden' });
    await page.locator('.stat').first().waitFor();
    assert.match(await view(page).textContent(), /示範筆記應用/);
  });

  await check('empty catalog and empty backup list explain what to do', fixture({
    status: { ...fixture().status, apps: [] }, backups: [],
  }), async (page) => {
    await ready(page);
    await page.getByText('尚未設定可備份的應用').first().waitFor();
    await shot(page, 'empty-catalog-1440.png');
    await page.locator('#go-create').click();
    await page.getByRole('heading', { name: '尚未設定可備份的應用' }).waitFor();
    assert.equal(await page.locator('[data-focus="create-submit"]').count(), 0);
    await page.locator('[data-nav="backups"]').click();
    await page.getByText('還沒有備份').waitFor();
  });

  await check('delete asks for confirmation; cancel never deletes', fixture(), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="delete-${B_SAFETY}"]`).click();
    await page.locator('#confirm-dialog').waitFor();
    assert.match(await page.locator('#confirm-body').textContent(), new RegExp(B_SAFETY));
    assert.match(await page.locator('#confirm-body').textContent(), /還原前自動備份/);
    await shot(page, 'delete-confirm-1440.png');
    await page.locator('#confirm-cancel').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal((await calls(page, 'delete')).length, 0);
    await page.locator(`[data-focus="delete-${B_SAFETY}"]`).click();
    await page.locator('#confirm-ok').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.deepEqual((await calls(page, 'delete')).map(requestOf), [{ backup_id: B_SAFETY }]);
    await page.locator(`tr[data-backup="${B_SAFETY}"]`).waitFor({ state: 'detached' });
    assert.equal(await page.locator('tbody tr').count(), 2);
  });

  await check('a cancellable job can be cancelled after confirmation; nothing is cancelled on dismiss', fixture({
    scripts: { ...scripts(), verify: Array.from({ length: 12 }, (_, index) => runningStep('verify', 'decrypt', 20 + index, { cancellable: true })) },
  }), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="verify-${B_MANUAL}"]`).click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    const verify = requestOf((await calls(page, 'verify-start')).at(-1));
    assert.deepEqual(Object.keys(verify).sort(), ['backup_id', 'request_id'], 'no key prompt when the device holds the key');
    await page.locator('[data-focus="job-cancel"]').waitFor();
    // The overview shows the running job through the global banner and links back to it.
    await page.locator('[data-nav="overview"]').click();
    await page.locator('#job-banner').waitFor();
    assert.match(await page.locator('#job-banner').textContent(), /驗證作業進行中 · 解密並驗證檔案 · \d+%/);
    await page.locator('#job-banner a').click();
    await page.locator('[data-focus="job-cancel"]').waitFor();
    assert.equal(await page.locator('#job-banner').isVisible(), false);
    await page.locator('[data-focus="job-cancel"]').click();
    await page.locator('#confirm-dialog').waitFor();
    await page.locator('#confirm-cancel').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal((await calls(page, 'job-cancel')).length, 0);
    await page.locator('[data-focus="job-cancel"]').click();
    await page.locator('#confirm-ok').click();
    await page.locator('#result-heading').filter({ hasText: '作業已取消' }).waitFor();
    const jobId = (await page.evaluate(() => window.location.hash)).split('/').at(-1);
    assert.deepEqual((await calls(page, 'job-cancel')).map(requestOf), [{ job_id: jobId }]);
    assert.equal(await page.locator('[data-focus="job-cancel"]').isVisible(), false);
    assert.equal(await page.locator('.phase-skipped').count(), 2);
  });

  await check('verify asks for the key when this device does not hold it', fixture(), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="verify-${B_UPLOADED}"]`).click();
    await page.locator('#key-dialog').waitFor();
    assert.equal(await page.locator('#key-dialog-save-wrap').isVisible(), false, 'verify-start has no save_key');
    await page.locator('#key-dialog-ok').click();
    await page.locator('#key-dialog-error').waitFor();
    assert.equal((await calls(page, 'verify-start')).length, 0);
    await page.locator('#key-dialog-text').fill(kitText(OTHER_SECRET, OTHER_KEY_ID));
    await page.locator('#key-dialog-ok').click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    const request = requestOf((await calls(page, 'verify-start')).at(-1));
    assert.deepEqual(Object.keys(request).sort(), ['backup_id', 'key', 'request_id']);
    assert.equal(request.key, OTHER_SECRET);
    await page.locator('#result-heading').filter({ hasText: '驗證完成' }).waitFor();
  });

  const hostile = fixture();
  const evil = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script><b>bold</b>';
  const long = 'unbroken-'.repeat(60);
  hostile.status.apps[0].name = `${evil}示範`;
  hostile.status.apps[0].description = long;
  hostile.status.apps[0].problems = [`<iframe src="javascript:window.__xss=1"></iframe>${long}`];
  hostile.status.warnings = [`<svg onload="window.__xss=1"></svg>${long}`];
  hostile.backups[0].note = `${evil}${long}`;
  hostile.backups[0].apps = [{ id: 'woowbk-demo', name: evil }];
  hostile.inspect[B_MANUAL].preflight.apps[0].checks.push({ id: 'x', status: 'warn', message: `${evil}${long}` });
  hostile.inspect[B_MANUAL].manifest.note = evil;
  hostile.scripts.restore = [{ ...runningStep('restore', 'decrypt', 20), log: [`${evil} ${long}`] }, ...hostile.scripts.restore.slice(1)];
  hostile.scripts.restore.at(-1).job.result.health = [{ id: 'h', status: 'ok', message: evil }];
  hostile.scripts.restore.at(-1).job.result.verification[0].after = { summary: { ...VERIFY_BEFORE.summary, title: evil } };
  await check('hostile helper strings are rendered literally everywhere', hostile, async (page) => {
    const noInjection = async label => {
      const found = await page.evaluate(() => ({
        injected: document.querySelectorAll('body img, body script, body b, body iframe:not(#downloads iframe), body svg:not(.icon)').length,
        xss: Boolean(window.__xss),
      }));
      assert.deepEqual(found, { injected: 0, xss: false }, `${label}: no element created from data`);
    };
    await ready(page);
    await page.locator('.item-title').filter({ hasText: '<img src=x' }).first().waitFor();
    assert.match(await page.locator('#warning-list').textContent(), /<svg onload/);
    await noInjection('overview');
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    assert.match(await page.locator('.backups-table').textContent(), /<script>window.__xss=1<\/script>/);
    await noInjection('list');
    await page.locator(`[data-focus="open-${B_MANUAL}"]`).click();
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content').first().waitFor();
    await noInjection('detail');
    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.match(await view(page).textContent(), /<b>bold<\/b>/);
    await noInjection('preflight');
    await allWidths(page, 'hostile preflight');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.match(await page.locator('.log').textContent(), /<img src=x onerror/);
    await noInjection('job result');
    await allWidths(page, 'hostile job result');
  });

  await check('layouts fit 1440/1024/768/390/360/320 px for every view', fixture({
    status: { ...fixture().status, key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: false }, warnings: ['示範：部分應用的設定需要檢查。'] },
    ackMode: 'manual',
  }), async (page) => {
    await ready(page);
    await page.locator('.stat').first().waitFor();
    await page.locator('.item-list').nth(1).waitFor();
    await allWidths(page, 'overview');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'overview-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await shot(page, 'overview-1440.png');
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    await allWidths(page, 'backup list');
    await shot(page, 'backups-1440.png');
    await page.setViewportSize({ width: 360, height: 900 });
    await shot(page, 'backups-360.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator(`[data-focus="open-${B_MANUAL}"]`).click();
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content').first().waitFor();
    await allWidths(page, 'backup detail');
    await page.locator(`[data-focus="delete-${B_MANUAL}"]`).click();
    await page.locator('#confirm-dialog').waitFor();
    await allWidths(page, 'delete dialog');
    await page.locator('#confirm-cancel').click();
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="verify-${B_UPLOADED}"]`).click();
    await page.locator('#key-dialog').waitFor();
    await allWidths(page, 'key dialog');
    await page.locator('#key-dialog-cancel').click();
    await page.locator('#go-create').click();
    await page.locator('[data-focus="create-submit"]').waitFor();
    await allWidths(page, 'create backup');
    await page.locator('[data-nav="keys"]').click();
    await page.locator('[data-focus="kit-show"]').click();
    await page.locator('#kit-secret').waitFor();
    await allWidths(page, 'keys with emergency kit');
    await page.locator('[data-nav="restore"]').click();
    await page.locator('#restore-file').setInputFiles({ name: `${'very-long-backup-file-name-'.repeat(8)}.woowbackup`, mimeType: 'application/octet-stream', buffer: Buffer.alloc(3 * MiB, 1) });
    await allWidths(page, 'restore: choose file');
    await page.locator('[data-focus="restore-upload"]').click();
    await page.waitForFunction(() => window.testchannels.at(-1)?.sent >= 2 * 1024 * 1024);
    await allWidths(page, 'restore: upload progress');
    await page.evaluate(() => window.__fixture.releaseAcks(1000));
    await page.waitForFunction(() => window.testchannels.at(-1)?.sent === 3 * 1024 * 1024);
    await page.evaluate(() => window.__fixture.releaseAcks(1000));
    await page.locator('#key-text').waitFor();
    await allWidths(page, 'restore: key');
    await page.locator('#key-text').fill(OTHER_SECRET);
    await page.locator('[data-focus="key-submit"]').click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    await allWidths(page, 'restore: preflight');
    // Review F15: the controls that choose what gets overwritten are comfortable targets.
    for (const [width, minimum] of [[1440, 32], [390, 44]]) {
      await page.setViewportSize({ width, height: 900 });
      const heights = await page.locator('.app-select, .app-details summary').evaluateAll(items => items.map(item => item.getBoundingClientRect().height));
      assert(heights.length && heights.every(height => height >= minimum - 0.5), `targets at ${width}px: ${heights}`);
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'restore-preflight-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await allWidths(page, 'restore: confirm');
    await page.setViewportSize({ width: 320, height: 900 });
    await shot(page, 'restore-confirm-320.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('.phase-active').first().waitFor();
    await allWidths(page, 'job running');
    // Review F15: phase labels never break a word across lines at desktop widths (1176: the page inside Cockpit's
    // shell next to its sidebar on a 1440 px screen; the longest label is 預先寫入主機資料夾).
    for (const width of [1440, 1280, 1176, 1024]) {
      await page.setViewportSize({ width, height: 900 });
      const broken = await page.evaluate(() => [...document.querySelectorAll('.phase-label')].filter(label => {
        const range = document.createRange();
        range.selectNodeContents(label);
        return new Set([...range.getClientRects()].map(rect => Math.round(rect.top))).size > 1;
      }).map(label => label.textContent));
      assert.deepEqual(broken, [], `phase labels wrap at ${width}px`);
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('#result-heading').waitFor();
    await allWidths(page, 'job result');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'restore-result-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-nav="activity"]').click();
    await page.locator('.jobs-table').waitFor();
    await allWidths(page, 'activity');
    await shot(page, 'activity-1440.png');
  });

  await check('keyboard focus is visible and every view is reachable with Tab', fixture({
    status: { ...fixture().status, key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: false } },
  }), async (page) => {
    const tabThrough = async (label, count) => {
      await page.evaluate(() => document.activeElement?.blur());
      const seen = [];
      for (let index = 0; index < count; index += 1) {
        await page.keyboard.press('Tab');
        const info = await page.evaluate(() => {
          const element = document.activeElement;
          if (!element || element === document.body) return null;
          const style = getComputedStyle(element);
          const rect = element.getBoundingClientRect();
          return { key: element.dataset.focus || element.id || element.tagName, visible: element.matches(':focus-visible'),
            outline: style.outlineStyle, width: parseFloat(style.outlineWidth), left: rect.left, right: rect.right, viewport: innerWidth };
        });
        if (!info) continue;
        seen.push(info.key);
        assert(info.visible && info.outline !== 'none' && info.width >= 2, `${label}: no visible focus ring on ${JSON.stringify(info)}`);
        assert(info.left >= -2 && info.right <= info.viewport + 2, `${label}: focused element outside the viewport ${JSON.stringify(info)}`);
      }
      return seen;
    };
    await ready(page);
    await page.locator('.item-list').nth(1).waitFor();
    const overview = await tabThrough('overview', 22);
    for (const key of ['refresh', 'go-restore', 'go-create', 'nav-overview', 'nav-backups', 'nav-restore', 'nav-keys', 'nav-activity', 'banner-keys']) {
      assert(overview.includes(key), `overview: ${key} reachable (${overview})`);
    }
    await page.locator('[data-nav="backups"]').focus();
    await page.keyboard.press('Enter');
    await page.locator('.backups-table').waitFor();
    const listKeys = await tabThrough('backup list', 26);
    assert(listKeys.includes('backup-search') && listKeys.includes(`download-${B_MANUAL}`) && listKeys.includes(`delete-${B_MANUAL}`), String(listKeys));
    await page.setViewportSize({ width: 390, height: 900 });
    await tabThrough('backup list 390px', 20);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('#go-create').click();
    await page.locator('[data-focus="create-submit"]').waitFor();
    const createKeys = await tabThrough('create', 20);
    assert(createKeys.includes('create-app-woowbk-demo') && createKeys.includes('create-images') && createKeys.includes('create-note'), String(createKeys));
    await page.locator('[data-nav="keys"]').click();
    await page.locator('[data-focus="kit-show"]').click();
    await page.locator('#kit-secret').waitFor();
    const keyKeys = await tabThrough('keys', 20);
    assert(keyKeys.includes('kit-download') && keyKeys.includes('kit-confirm'), String(keyKeys));
    await page.locator('[data-nav="restore"]').click();
    await page.locator('[data-focus="restore-file-button"]').waitFor();
    assert.equal(await page.locator('[data-focus="restore-file-button"]').textContent(), '選擇檔案', 'zh-TW picker instead of the native control text');
    const restoreKeys = await tabThrough('restore', 16);
    assert(restoreKeys.includes('restore-file-button'), String(restoreKeys));
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="delete-${B_MANUAL}"]`).focus();
    await page.keyboard.press('Enter');
    await page.locator('#confirm-dialog').waitFor();
    assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm-cancel', 'destructive dialogs focus the safe choice');
    await page.keyboard.press('Escape');
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal(await page.evaluate(() => document.activeElement.dataset.focus), `delete-${B_MANUAL}`, 'focus returns to the trigger');
    assert.equal((await calls(page, 'delete')).length, 0);
  });

  await check('disconnected transport offers reconnect; a missing helper is explained', fixture(), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    await page.evaluate(() => window.__fixture.failures.push({ command: 'status', problem: 'disconnected', message: 'Transport closed' }));
    await page.locator('#refresh').click();
    await page.locator('#page-error').waitFor();
    assert.equal(await page.locator('#refresh').isDisabled(), true, 'no further helper calls once disconnected');
    assert.equal(await page.locator('#retry').textContent(), '重新連線');
    assert.match(await page.locator('#page-error-message').textContent(), /管理連線已中斷/);
    const navigation = page.waitForEvent('framenavigated', frame => frame === page.mainFrame());
    await page.locator('#retry').click();
    await navigation;
    await ready(page);
    await page.locator('.backups-table').waitFor();
    await page.evaluate(() => window.__fixture.failures.push({ command: 'status', problem: 'not-found', message: 'not found' }));
    await page.locator('#refresh').click();
    await page.locator('#page-error').waitFor();
    assert.match(await page.locator('#page-error-message').textContent(), /找不到備份管理程式/);
  });

  await check('a failed download page is reported instead of failing silently', fixture({
    downloads: { [B_MANUAL]: { path: '/var/lib/woowtech-backup/archives/missing.woowbackup', filename: 'woowtech-backup-dev-a-20261112-020000.woowbackup', size: 1 } },
  }), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="download-${B_MANUAL}"]`).click();
    await page.locator('#action-error').getByText('沒有開始').waitFor();
    assert.match(await page.locator('#action-error').textContent(), /找不到備份檔（fixture）/);
  }, { allowHttpErrors: ['/cockpit/channel/'] });

  // ------------------------------------------------------------------ review findings (F1–F16, CR-05/08/16)

  const terminalJob = (id, extra) => ({
    job: { id, type: 'restore', created: '2026-11-13T01:40:00Z', started: '2026-11-13T01:40:01Z', finished: '2026-11-13T01:45:00Z',
      params: { backup_id: B_MANUAL, apps: ['woowbk-demo'], key_provided: false }, cancellable: false,
      progress: { percent: 40, message: '失敗' }, ...extra },
    log: ['2026-11-13T01:45:00Z 作業結束'], steps: [],
  });
  const J_PRE = 'j20261113T014000Z-0000f2f2';
  const J_FRESH = 'j20261113T014100Z-0000f3f3';
  const J_SAFETYFAIL = 'j20261113T014200Z-0000c16c';
  const outcomes = fixture();
  outcomes.jobs[J_PRE] = terminalJob(J_PRE, {
    state: 'failed', phase: 'safety',
    phases: phasesAt('restore', 'stop').map(item => (item.id === 'stop' ? { ...item, state: 'pending' } : item)),
    error: { code: 'incompatible', message: '映像載入失敗。' },
    result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY_NEW, health: [], verification: [], rolled_back: false, changed: false,
      fresh_apps: [], safety_skipped: false, safety_failed: false },
  });
  outcomes.jobs[J_FRESH] = terminalJob(J_FRESH, {
    state: 'interrupted', phase: 'restore',
    phases: phasesAt('restore', 'restore', { failedAt: 'restore', skipped: ['safety'] }),
    error: { code: 'job-failed', message: '還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。全新部署（woowbk-demo）沒有完成；已清除未完成的全新部署，可再次還原。' },
    result: { apps: ['woowbk-demo'], safety_backup_id: null, health: [], verification: [], rolled_back: false, changed: true,
      fresh_apps: ['woowbk-demo'], safety_skipped: false, safety_failed: false },
  });
  outcomes.jobs[J_SAFETYFAIL] = terminalJob(J_SAFETYFAIL, {
    state: 'failed', phase: 'safety', phases: phasesAt('restore', 'safety', { failedAt: 'safety' }),
    error: { code: 'job-failed', message: '無法建立還原前備份，未做任何變更：資料庫服務 woowbk-demo-db.service 未執行。' },
    result: { apps: ['woowbk-demo'], safety_backup_id: null, health: [], verification: [], rolled_back: false, changed: false,
      fresh_apps: [], safety_skipped: false, safety_failed: true },
  });
  await check('restore results say what really happened (F2, F3, CR-05, CR-09, CR-16)', outcomes, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, J_PRE);
    await page.locator('#result-heading').filter({ hasText: '還原失敗' }).waitFor();
    let text = await view(page).textContent();
    assert.match(text, /還原在變更任何資料前失敗，應用維持原狀/);
    assert(!/自動回復未完成/.test(text), 'a failure before any change is not "rollback incomplete"');
    assert.equal(await page.locator('[data-focus="result-restore-safety"]').count(), 0);
    assert.match(await page.locator('[data-focus="result-overview"]').getAttribute('class'), /primary/);
    assert.match(await page.locator('.phase').filter({ hasText: '建立還原前備份' }).textContent(), /完成/);

    await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, J_FRESH);
    await page.locator('#result-heading').filter({ hasText: '作業意外中斷' }).waitFor();
    text = await view(page).textContent();
    assert(!/應用資料應未被變更/.test(text), 'never "unchanged" after a destructive phase');
    assert.match(text, /還原在變更資料途中中斷/);
    assert.match(text, /全新部署（示範筆記應用）沒有完成/);
    await page.locator('[data-focus="result-restore-again"]').click();
    await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').waitFor();

    await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, J_SAFETYFAIL);
    await page.locator('[data-focus="result-no-safety"]').waitFor();
    assert.match(await view(page).textContent(), /不建立還原前備份直接還原/);
    await page.locator('[data-focus="result-no-safety"]').click();
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-no-safety').waitFor();
    assert.match(await view(page).textContent(), /無法建立，會依你的選擇直接還原/);
    await page.locator('#confirm-restore').check();
    assert.equal(await page.locator('[data-focus="confirm-start"]').isDisabled(), true, 'the no-safety risk needs its own checkbox');
    await page.locator('#confirm-no-safety').check();
    await enabled(page, '[data-focus="confirm-start"]');
    await page.locator('[data-focus="confirm-start"]').click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/j2026'));
    const request = requestOf((await calls(page, 'restore-start')).at(-1));
    assert.equal(request.allow_no_safety, true);
    assert.deepEqual(request.apps, ['woowbk-demo']);
  });

  // 2026.11.14.2 host test: with too little space to package the pre-restore copy next to the running apps, it was
  // packaged in the downtime; the result says why the outage was longer.
  const J_DOWNTIME = 'j20261113T014300Z-0000d0d0';
  const downtime = fixture();
  downtime.jobs[J_DOWNTIME] = terminalJob(J_DOWNTIME, {
    state: 'succeeded', phase: 'check', phases: phasesAt('restore', null), progress: { percent: 100, message: '已完成' },
    result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY, safety_pending: false, safety_in_downtime: true,
      health: [{ id: 'woowbk-demo/health/0', status: 'ok', message: '健康檢查通過：http://127.0.0.1:18090/healthz 回應 200。' }],
      verification: [], rolled_back: false, changed: true, fresh_apps: [], safety_skipped: false, safety_failed: false,
      warnings: [] },
  });
  await check('a safety backup packaged in the downtime explains the longer outage', downtime, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, J_DOWNTIME);
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.match(await view(page).textContent(), /這次的還原前備份是在停機期間建立的，所以停機時間比較長：應用恢復後的空間可能不足以封裝/);
    assert.equal(await page.locator('[data-focus="result-safety"]').count(), 1, 'the safety backup is named');
  });

  // 2026.11.15.2 (the new-device drill): a backup carries the settings it was made with; the restore wizard offers
  // them for review where this device has none (or other ones), installs them like 應用設定 does, checks again.
  const wikiEntry = { schema: 1, id: 'woowbk-wiki', name: '團隊知識庫', description: '知識庫', owner: 'appowner', adapter: 'quadlet-postgres',
    quadlet: { files: ['woowbk-wiki-db.container', 'woowbk-wiki-app.container'] }, units: ['woowbk-wiki-db.service', 'woowbk-wiki-app.service'],
    writer_units: ['woowbk-wiki-app.service'], postgres: [{ id: 'main', container: 'woowbk-wiki-db', unit: 'woowbk-wiki-db.service', database: 'wiki', user: 'wiki', data_volume: 'woowbk-wiki-pgdata' }],
    volumes: [], secrets: [{ name: 'woowbk-wiki-db-password' }], config_files: [], health: [], verify: [] };
  const prettyEntry = entry => `${JSON.stringify(entry, null, 2)}\n`;
  const MISSING_CHECK = '此設備沒有這個應用的應用設定。這份備份附有建立時的設定，可以審查並安裝；安裝後會重新檢查能否還原。';
  const DIFFERENT_CHECK = '此設備的應用設定與備份時不同；將以此設備的設定為準。也可以審查並改用備份中附上的設定。';
  const carrySettings = (data, id, { demo = null, wiki = null } = {}) => {
    const result = data.inspect[id];
    for (const app of result.manifest.apps) app.settings_included = true;
    const [demoApp, wikiApp] = result.preflight.apps;
    if (demo) {
      demoApp.settings = { state: 'different', entry: demo };
      demoApp.checks.push({ id: 'woowbk-demo/catalog', status: 'warn', message: DIFFERENT_CHECK });
    }
    if (wiki) {
      wikiApp.checks = [{ id: 'woowbk-wiki/catalog', status: 'fail', message: MISSING_CHECK }];
      wikiApp.settings = { state: 'missing', entry: wiki };
    }
  };
  const focused = page => page.evaluate(() => document.activeElement?.dataset?.focus || document.activeElement?.tagName);

  const carried = fixture({ catalogData: catalogData() });
  carrySettings(carried, B_MANUAL, {
    demo: { ...structuredClone(carried.catalogData.installed['woowbk-demo'].entry), description: '備份時的說明' }, wiki: structuredClone(wikiEntry)
  });
  await check("a backup's settings are reviewed and installed from the restore wizard, then checked again", carried, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('.app-preflight').first().waitFor();
    assert.equal(await page.locator('[data-focus="pf-select-woowbk-wiki"]').isDisabled(), true, 'not restorable before its settings');
    assert.match(await view(page).textContent(), /這台設備沒有這個應用的設定。這份備份附有建立時的應用設定，可以審查並安裝；安裝後會重新檢查能否還原。/);
    assert.match(await view(page).textContent(), /這台設備的應用設定與備份時不同。可以維持目前的設定/);
    // The administrator unticks the in-place app: installing the other app's settings must not tick it again.
    await page.locator('[data-focus="pf-select-woowbk-demo"]').uncheck();
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').press('Enter');
    await page.getByText('檢查通過：可以安裝這份應用設定。').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'catalog-install')).at(-1)), { entry: wikiEntry }, 'a preview first, of the carried settings');
    assert.equal(await focused(page), 'pf-settings-title-woowbk-wiki', 'keyboard focus lands on the result, never on <body>');
    assert.match(await page.locator('#status').textContent(), /審查完成：這份設定通過這台設備的檢查。/);
    // What the settings declare, and their complete text (review 2026-11-15: not only a diff cut at 400 lines).
    const review = page.locator('section.settings-review').filter({ has: page.locator('[data-focus="pf-settings-title-woowbk-wiki"]') });
    const summary = Object.assign({}, ...(await metadataOf(review)));
    assert.equal(summary['擁有者'], 'appowner');
    assert.equal(summary['服務（啟動順序）'], 'woowbk-wiki-db.service → woowbk-wiki-app.service');
    assert.equal(await page.locator('#pf-settings-text-woowbk-wiki').textContent(), prettyEntry(wikiEntry), 'the complete text, as installed');
    assert.equal(await review.getByText('將寫入的內容').count(), 0, 'no second, cut copy of a new entry');
    await fits(page, 'settings review');
    await page.locator('[data-focus="pf-settings-install-woowbk-wiki"]').click();
    await page.locator('#confirm-dialog').waitFor();
    assert.equal(await page.locator('#confirm-ok').isDisabled(), true, 'the install waits for the acknowledgement');
    assert.equal(await page.locator('#confirm-dialog .dialog-ack strong').textContent(), '我已審查這份設定的內容、差異與影響');
    const dialogRows = Object.assign({}, ...(await metadataOf(page.locator('#confirm-dialog'))));
    assert.equal(dialogRows['擁有者'], 'appowner', 'the dialog names the owner');
    assert.equal(dialogRows['主機資料夾'], '無');
    await page.locator('#confirm-ack').check();
    await page.locator('#confirm-ok').click();
    await page.waitForFunction(() => document.querySelector('[data-focus="pf-select-woowbk-wiki"]')?.disabled === false);
    assert.deepEqual(requestOf((await calls(page, 'catalog-install')).at(-1)), { entry: wikiEntry, confirm: true, expected_sha256: null });
    assert.equal((await calls(page, 'inspect')).length, 2, 'the preflight ran again after the install');
    await page.locator('.notice-ok').getByText('已安裝備份中「團隊知識庫」的應用設定。').waitFor();
    assert.equal(await page.locator('[data-focus="pf-settings-woowbk-wiki"]').count(), 0, 'the same settings now: nothing to review');
    assert.equal(await page.locator('[data-focus="pf-settings-woowbk-demo"]').count(), 1, 'other settings here: still offered, never required');
    assert.equal(await page.locator('[data-focus="pf-select-woowbk-wiki"]').isChecked(), true, 'restorable now: selected');
    assert.equal(await page.locator('[data-focus="pf-select-woowbk-demo"]').isChecked(), false, 'the unticked in-place app stays unticked');
    await page.waitForFunction(() => document.activeElement?.dataset?.focus === 'pf-select-woowbk-wiki');
    await page.locator('[data-focus="pf-recheck"]').click();
    await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'inspect').length === 3);
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.equal(await page.locator('[data-focus="pf-select-woowbk-demo"]').isChecked(), false, '重新檢查 keeps the choice too');
    const details = page.locator('details.app-details').filter({ has: page.locator('[data-focus="pf-details-woowbk-wiki"]') });
    await page.locator('[data-focus="pf-details-woowbk-wiki"]').click();
    assert.equal(await details.evaluate(element => element.open), true);
    assert.match(await details.innerText(), /應用設定\s*已附上（還原時可審查並安裝）/);
    await shot(page, 'restore-settings-installed-1440.png');
  });

  // A loaded browser can deliver the dialog's close event after a fast reply already rendered the new preflight and
  // focused the app: the close handler must not move that focus to the heading (it did, the button that opened the
  // dialog being gone). Here every dialog close listener runs 300 ms late.
  const lateClose = fixture({ catalogData: catalogData() });
  carrySettings(lateClose, B_MANUAL, { wiki: structuredClone(wikiEntry) });
  await check('installed settings: a late dialog close event leaves the focus on the app the new preflight focused', lateClose, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').press('Enter');
    await page.getByText('檢查通過：可以安裝這份應用設定。').waitFor();
    await page.locator('[data-focus="pf-settings-install-woowbk-wiki"]').click();
    await page.locator('#confirm-ack').check();
    await page.locator('#confirm-ok').click();
    await page.waitForFunction(() => window.lateCloses === 1
      && window.testcalls.filter(call => call.argv[1] === 'inspect').length === 2
      && document.querySelector('[data-focus="pf-select-woowbk-wiki"]')?.disabled === false);
    assert.equal(await focused(page), 'pf-select-woowbk-wiki', 'the late close event did not take the focus away');
  }, { beforeGoto: page => page.addInitScript(() => {
    window.lateCloses = 0;
    const add = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, listener, options) {
      if (type !== 'close' || !(this instanceof HTMLDialogElement)) return add.call(this, type, listener, options);
      return add.call(this, type, event => setTimeout(() => { listener.call(this, event); window.lateCloses += 1; }, 300), options);
    };
  }) });

  // 改用: the installed digest goes with the install; settings changed after the review are never installed blind.
  const replaced = fixture({ catalogData: catalogData() });
  const backupDemo = { ...structuredClone(replaced.catalogData.installed['woowbk-demo'].entry), description: '備份時的說明' };
  carrySettings(replaced, B_UPLOADED, { demo: backupDemo });
  await check('replacing settings sends the reviewed digest; a change meanwhile is reviewed again; the entered key is kept', replaced, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_UPLOADED);
    await page.locator('#key-text').fill(OTHER_SECRET);
    await page.locator('[data-focus="key-submit"]').click();
    await page.locator('[data-focus="pf-settings-woowbk-demo"]').click();
    await page.getByText('檢查通過：可以取代目前安裝的設定。').waitFor();
    assert.match(await view(page).textContent(), /與目前安裝的設定比較（1 項變更）/);
    await page.locator('[data-focus="pf-settings-install-woowbk-demo"]').click();
    await page.locator('#confirm-ack').check();
    // Someone changes the installed settings while the dialog is open.
    await page.evaluate(() => { window.__fixture.catalogData.installed['woowbk-demo'].sha256 = 'd'.repeat(64); });
    await page.locator('#confirm-ok').click();
    await page.locator('#confirm-dialog').getByText('這台設備的設定在審查之後被變更了，頁面已重新審查。').waitFor();
    const installs = (await calls(page, 'catalog-install')).map(requestOf);
    assert.deepEqual(installs.slice(-2), [{ entry: backupDemo, confirm: true, expected_sha256: INSTALLED_SHA }, { entry: backupDemo }],
      'refused with the reviewed digest, then reviewed again');
    await page.locator('[data-focus="pf-settings-install-woowbk-demo"]').waitFor({ state: 'attached' });  // the new review
    await page.locator('#confirm-cancel').click();
    await page.waitForFunction(() => document.activeElement?.dataset?.focus === 'pf-settings-install-woowbk-demo');
    assert.match(await view(page).textContent(), /目前安裝是（SHA-256 dddddddddddd…）/, 'the new review shows the changed settings');
    await page.locator('[data-focus="pf-settings-install-woowbk-demo"]').click();
    await page.locator('#confirm-ack').check();
    await page.locator('#confirm-ok').click();
    await page.locator('.notice-ok').getByText('已改用備份中「示範筆記應用」的應用設定。').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'catalog-install')).at(-1)), { entry: backupDemo, confirm: true, expected_sha256: 'd'.repeat(64) });
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_UPLOADED, key: OTHER_SECRET }, 'checked again with the key entered');
    assert.equal((await calls(page, 'key-import')).length, 0, 'the key was not saved');
    assert.equal(await page.locator('[data-focus="pf-settings-woowbk-demo"]').count(), 0);
  });

  // An unencrypted upload, a review that fails, settings longer than the diff shows, a settings file that failed to load.
  const plainCarried = fixture({ catalogData: catalogData() });
  const longEntry = { ...structuredClone(wikiEntry), secrets: Array.from({ length: 150 }, (_, index) => ({ name: `woowbk-wiki-secret-${index}` })),
    data_dirs: [{ path: 'Documents' }] };
  {
    const meta = backupMeta(B_PLAIN, { type: 'uploaded', encrypted: false, unauthenticated: true, key_id: null, key_available: true, inspected: true,
      verified: null, uploaded_at: '2026-11-13T03:01:00Z', filename: 'woowtech-backup-dev-b-20261113-030000.tar' });
    plainCarried.backups.push(meta);
    plainCarried.inspect[B_PLAIN] = inspectResult({ ...meta, created: '2026-11-13T03:00:00Z' }, { hostname: 'dev-b', uid: 1007 });
    plainCarried.inspect[B_PLAIN].preflight.checks.unshift({ id: 'unauthenticated', status: 'warn', message: UNAUTH_MESSAGE });
    carrySettings(plainCarried, B_PLAIN, { wiki: structuredClone(longEntry) });
    const demo = plainCarried.inspect[B_PLAIN].preflight.apps[0];
    Object.assign(demo, { restorable: false, mode: 'fresh', checks: [{ id: 'woowbk-demo/catalog', status: 'fail',
      message: '應用設定 woowbk-demo.json 不是有效的 JSON，已略過。這份備份附有建立時的應用設定，可以審查後用它取代無法載入的設定檔；安裝後會重新檢查能否還原。' }],
      settings: { state: 'unloadable', entry: structuredClone(plainCarried.catalogData.installed['woowbk-demo'].entry) } });
  }
  await check('an unencrypted upload\'s settings: a failed review is retried or closed, long settings are shown whole, copied or selected', plainCarried, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_PLAIN);
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').waitFor();
    assert.match(await view(page).textContent(), /這台設備上這個應用的設定檔無法載入（原因見上方的檢查結果）/, 'a file that failed to load is not "no settings"');
    assert.match(await view(page).textContent(), /設定的內容無法確認來自你的設備，安裝前請逐項審查下方的摘要與完整內容/);
    await page.evaluate(() => { window.__savedCatalog = window.__fixture.catalogData; window.__fixture.catalogData = null; });
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').click();
    await page.locator('section.settings-review .notice-error').getByText('不支援的指令。').waitFor();
    assert.equal(await page.locator('section.settings-review .notice-error[role="alert"]').count(), 0, 'announced once, not re-inserted as an alert');
    assert.match(await page.locator('#status').textContent(), /無法審查備份中的應用設定：不支援的指令。/);
    await page.locator('section.settings-review').getByRole('button', { name: '關閉提示' }).click();
    assert.equal(await focused(page), 'pf-settings-woowbk-wiki', 'closing returns to the review button');
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').click();
    await page.locator('section.settings-review').getByRole('button', { name: '重試' }).waitFor();
    await page.evaluate(() => { window.__fixture.catalogData = window.__savedCatalog; });
    await page.locator('section.settings-review').getByRole('button', { name: '重試' }).click();
    await page.getByText('檢查通過：可以安裝這份應用設定。').waitFor();
    const text = prettyEntry(longEntry);
    assert(text.split('\n').length > 450, 'longer than the 400 lines a diff shows');
    assert.equal(await page.locator('#pf-settings-text-woowbk-wiki').textContent(), text);
    assert.match(await view(page).textContent(), new RegExp(`完整內容（${text.split('\n').length - 1} 行）`));
    const review = page.locator('section.settings-review').filter({ has: page.locator('[data-focus="pf-settings-title-woowbk-wiki"]') });
    const summary = Object.assign({}, ...(await metadataOf(review)));
    assert.equal(summary['主機資料夾'], '~/Documents', 'what the settings declare last is shown first');
    // No clipboard (plain HTTP): the complete text is selected instead, and the page says so.
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => Promise.reject(new Error('denied')) } }));
    await page.locator('[data-focus="pf-settings-copy-woowbk-wiki"]').click();
    await page.waitForFunction(() => /已選取設定的完整內容/.test(document.getElementById('status').textContent));
    assert.equal((await page.evaluate(() => String(window.getSelection()))).trim(), text.trim(), 'the complete text is selected');
    await page.locator('[data-focus="pf-settings-install-woowbk-wiki"]').click();
    assert.equal(await page.locator('#confirm-dialog .dialog-ack strong').textContent(), '我已逐項審查這份設定，並信任這個備份檔的來源');
    assert.equal(Object.assign({}, ...(await metadataOf(page.locator('#confirm-dialog'))))['主機資料夾'], '~/Documents');
    await page.locator('#confirm-cancel').click();
    assert.equal((await calls(page, 'catalog-install')).filter(call => requestOf(call).confirm).length, 0, 'nothing installed');
  });

  const carriedInvalid = fixture({ catalogData: catalogData() });
  carrySettings(carriedInvalid, B_MANUAL, { wiki: { ...structuredClone(wikiEntry), unknown_field: true } });
  await check("settings this device cannot take as they are are shown with the reason, never installed", carriedInvalid, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').click();
    await view(page).getByText('應用設定含有不支援的欄位：unknown_field。').waitFor();
    assert.equal(await page.locator('section.settings-review [role="alert"]').count(), 0, 'the reason is announced once, never again on each refresh');
    assert.match(await page.locator('#status').textContent(), /審查完成：這份設定沒有通過檢查。應用設定含有不支援的欄位：unknown_field。/);
    assert.equal(await page.locator('[data-focus="pf-settings-install-woowbk-wiki"]').count(), 0, 'no install of an invalid entry');
    assert.equal(await page.locator('[data-focus="pf-settings-copy-woowbk-wiki"]').count(), 1);
    assert.match(await view(page).textContent(), /請先依原因處理（例如建立擁有者帳號、安裝應用的套件），再按「重新檢查」/);
    assert.equal((await calls(page, 'catalog-install')).filter(call => requestOf(call).confirm).length, 0);
    await page.locator('[data-focus="pf-settings-close-woowbk-wiki"]').press('Enter');
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').waitFor();
    assert.equal(await focused(page), 'pf-settings-woowbk-wiki', '收合 returns to the review button');
    // 重新檢查 ends a review: it was made for the check before.
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').click();
    await view(page).getByText('應用設定含有不支援的欄位：unknown_field。').waitFor();
    await page.locator('[data-focus="pf-recheck"]').click();
    await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'inspect').length === 2);
    await page.locator('[data-focus="pf-settings-woowbk-wiki"]').waitFor();
    assert.equal(await view(page).getByText('應用設定含有不支援的欄位：unknown_field。').count(), 0, 'the old review is gone');
  });

  const safetyFlow = fixture();
  safetyFlow.backups.find(item => item.id === B_SAFETY).verified = { at: '2026-11-12T03:00:00Z', ok: false };
  await check('restoring a pre-restore backup never promises a new one; warnings repeat on 確認 (F1, F13)', safetyFlow, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_SAFETY);
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.match(await page.locator('.side-card').textContent(), /仍會直接還原，且還原失敗時無法自動回復/);
    assert(!/一定會/.test(await page.locator('.side-card').textContent()));
    assert.match(await view(page).textContent(), /上次驗證未通過/);
    assert.equal(await page.locator('.app-preflight.is-blocked').getByText('全新建立服務').count(), 0,
      'no "will deploy" sentence above a failing app');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    const text = await view(page).textContent();
    assert.match(text, /你正在還原一份還原前備份/);
    assert(!/建立失敗時不會變更任何資料/.test(text));
    assert.match(text, /注意事項/);
    assert.match(text, /UID（1001）/);
    assert.match(text, /上次驗證未通過/);
    assert.match(await page.locator('label.confirm-choice small').textContent(), /仍會直接還原/);
  });

  const freshOnly = fixture();
  freshOnly.inspect[B_MANUAL] = inspectResult(backupMeta(B_MANUAL), { mode: 'fresh' });
  await check('the confirmation names what happens for fresh deployments (F13)', freshOnly, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    assert.equal(await page.locator('label.confirm-choice strong').textContent(), '我了解還原會在這台設備全新部署上列 1 個應用');
  });

  await check('a wrong key is reported and never saved; a right key is saved only after it worked (F4)', fixture(), async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_UPLOADED);
    await page.locator('#key-text').waitFor();
    await page.locator('#key-text').fill(SECRET);
    await page.locator('#save-key').check();
    await page.locator('[data-focus="key-submit"]').click();
    await page.locator('.notice-error[role="alert"]').getByText('這把金鑰無法解開這份備份').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_UPLOADED, key: SECRET }, 'no save_key');
    assert.equal((await calls(page, 'key-import')).length, 0);
    await page.locator('#key-text').fill(OTHER_SECRET);
    await page.locator('[data-focus="key-submit"]').click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_UPLOADED, key: OTHER_SECRET });
    assert.deepEqual((await calls(page, 'key-import')).map(requestOf), [{ key: OTHER_SECRET }]);
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'view-heading', 'focus lands on the new step (F10)');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-back"]').click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'view-heading', '上一步 keeps keyboard focus (F10)');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    assert.equal(requestOf((await calls(page, 'restore-start')).at(-1)).key, undefined, 'a saved key is not sent again');
  });

  await check('background polls keep open sections and never break IME input (F5)', fixture(), async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-details-woowbk-demo"]').click();
    assert.equal(await page.locator('.app-details').first().evaluate(node => node.open), true);
    const polls = (await calls(page, 'status')).length;
    await page.clock.fastForward(31000);
    await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'status').length > count, polls);
    await settled(page);
    assert.equal(await page.locator('.app-details').first().evaluate(node => node.open), true, 'still open after the poll');
    assert.equal(await page.locator('.app-details summary').first().evaluate(node => getComputedStyle(node).listStyleType), 'none');
    assert.equal(await page.locator('.app-details summary svg.summary-icon').count() > 0, true, 'MDI chevron (F16)');

    await page.locator('#go-create').click();
    await page.locator('#backup-note').click();
    await page.keyboard.insertText('更新前');
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Input.imeSetComposition', { text: 'ㄅㄟˋ', selectionStart: 3, selectionEnd: 3 });
    const before = (await calls(page, 'status')).length;
    await page.clock.fastForward(31000);
    await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'status').length > count, before);
    await page.waitForTimeout(200);
    await cdp.send('Input.insertText', { text: '備' });
    assert.equal(await page.locator('#backup-note').inputValue(), '更新前備');
    await page.locator('#include-images').focus();
    await settled(page);
    assert.equal(await page.locator('#backup-note').inputValue(), '更新前備', 'the deferred refresh keeps the typed note');
  }, { beforeGoto: page => page.clock.install() });

  await check('an upload-finish timeout never discards the upload; it can be confirmed again (F6)', fixture(), async (page) => {
    await ready(page);
    await page.locator('[data-nav="restore"]').click();
    await page.evaluate(() => window.__fixture.hold.push('upload-finish'));
    await page.locator('#restore-file').setInputFiles({ name: 'big.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(200 * KiB, 4) });
    await page.locator('[data-focus="restore-upload"]').click();
    await page.locator('[data-focus="upload-recheck"]').waitFor();
    assert.match(await view(page).textContent(), /結果尚未確認/);
    assert.equal((await calls(page, 'upload-abort')).length, 0, 'an upload with an unknown result is kept');
    await page.evaluate(() => window.__fixture.release('upload-finish'));
    await page.locator('[data-focus="upload-recheck"]').click();
    await page.locator('#key-text').waitFor();
    assert.equal((await calls(page, 'upload-finish')).length, 2);
    assert.equal((await calls(page, 'upload-abort')).length, 0);
  }, {
    beforeGoto: async (page, context) => context.route('**/backup.js', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace('const finishTimeout = size =>', 'const finishTimeout = size => 400 ||');
      await route.fulfill({ response, body });
    }),
  });

  await check('an unconfirmed upload stays the active upload: banner, leave-page guard, never replaced (HD-08)', fixture(), async (page) => {
    await ready(page);
    await page.locator('[data-nav="restore"]').click();
    await page.evaluate(() => window.__fixture.hold.push('upload-finish'));
    await page.locator('#restore-file').setInputFiles({ name: 'big.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(200 * KiB, 4) });
    await page.locator('[data-focus="restore-upload"]').click();
    await page.locator('[data-focus="upload-recheck"]').waitFor();
    assert.match(await view(page).textContent(), /檢查也會繼續完成/);
    const guarded = () => page.evaluate(() => {
      const event = new Event('beforeunload', { cancelable: true });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    });
    assert.equal(await guarded(), true, 'leaving the page asks first while the result is unknown');
    await page.locator('[data-nav="backups"]').click();
    await page.locator('#upload-banner').getByText('上傳結果尚未確認').waitFor();
    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await view(page).getByText('目前有上傳尚待確認').waitFor();
    assert.equal((await calls(page, 'upload-abort')).length, 0, 'opening another restore keeps the upload');
    await page.locator('[data-focus="upload-busy-view"]').click();
    await page.locator('[data-focus="upload-recheck"]').waitFor();
    await page.locator(`[data-nav="backups"]`).click();
    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await page.locator('[data-focus="upload-busy-cancel"]').click();
    await page.waitForFunction(() => window.testcalls.some(call => call.argv[1] === 'upload-abort'));
    assert.deepEqual((await calls(page, 'upload-abort')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
    await page.locator('[data-focus="pf-next"]').waitFor();  // now the restore that was asked for opens
    assert.equal(await guarded(), false, 'an abandoned upload no longer guards the page');
    await page.evaluate(() => window.__fixture.release('upload-finish'));
  }, {
    beforeGoto: async (page, context) => context.route('**/backup.js', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace('const finishTimeout = size =>', 'const finishTimeout = size => 400 ||');
      await route.fulfill({ response, body });
    }),
  });

  await check('a running upload is never orphaned by opening another restore (F7, F10)', fixture({ ackMode: 'manual' }), async (page) => {
    await ready(page);
    await page.locator('[data-nav="restore"]').click();
    await page.locator('#restore-file').setInputFiles({ name: 'big.woowbackup', mimeType: 'application/octet-stream', buffer: Buffer.alloc(3 * MiB, 2) });
    await page.locator('[data-focus="restore-upload"]').click();
    await page.waitForFunction(() => window.testchannels.at(-1)?.sent >= 2 * 1024 * 1024);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('#upload-banner').waitFor();
    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await view(page).getByText('目前有上傳進行中').waitFor();
    const guarded = await page.evaluate(() => {
      const event = new Event('beforeunload', { cancelable: true });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    });
    assert.equal(guarded, true, 'the leave-page guard stays active');
    await page.locator('[data-focus="upload-busy-view"]').click();
    await page.locator('#upload-progress').waitFor();
    await page.locator('[data-focus="upload-cancel"]').click();
    await page.locator('[data-focus="restore-upload"]').waitFor();
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.focus), 'restore-file-button', 'focus after cancel (F10)');
    assert.deepEqual((await calls(page, 'upload-abort')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
  });

  await check('one persistent error is announced once; deletes wait for the running job (F9, CR-08)', fixture({
    scripts: { ...scripts(), verify: Array.from({ length: 30 }, (_, index) => runningStep('verify', 'decrypt', 10 + index, { cancellable: true })) },
    downloads: { [B_MANUAL]: { path: '/var/lib/woowtech-backup/archives/missing.woowbackup', filename: 'woowtech-backup-dev-a-20261112-020000.woowbackup', size: 1 } },
  }), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="verify-${B_MANUAL}"]`).click();
    await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    assert.equal(await page.locator(`[data-focus="delete-${B_SAFETY}"]`).isDisabled(), true, 'no deletes while a job runs');
    await page.locator(`[data-focus="download-${B_MANUAL}"]`).click();
    await page.locator('#action-error').getByText('沒有開始').waitFor();
    await page.evaluate(() => {
      window.__alerts = 0;
      new MutationObserver(records => {
        for (const record of records) for (const node of record.addedNodes) {
          if (node.nodeType === 1 && (node.matches('[role="alert"]') || node.querySelector('[role="alert"]'))) window.__alerts += 1;
        }
      }).observe(document.body, { childList: true, subtree: true });
    });
    const polls = (await calls(page, 'job-status')).length;
    await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'job-status').length >= count + 3, polls);
    assert.equal(await page.evaluate(() => window.__alerts), 0, 'the unchanged error is not re-inserted on every poll');
  }, { allowHttpErrors: ['/cockpit/channel/'] });

  await check('a busy refusal in the delete dialog links to the blocking job (F12)', fixture({
    failures: [{ command: 'delete', code: 'busy', message: '此備份正被進行中的作業使用，請等作業完成後再刪除。', details: { job_id: J_OTHER } }],
  }), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="delete-${B_SAFETY}"]`).click();
    await page.locator('#confirm-ok').click();
    await page.locator('#confirm-error').getByText('此備份正被進行中的作業使用').waitFor();
    const jobLink = page.locator('#confirm-dialog [data-focus="dialog-busy-job"]');
    assert.equal(await jobLink.getAttribute('href'), `#/jobs/${J_OTHER}`);
    await jobLink.click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    await page.waitForFunction(id => window.location.hash === `#/jobs/${id}`, J_OTHER);
  });

  await check('the kit secret is shown once; re-downloading needs a confirmation and never shows it (F11, decision 1)',
    fixture({ status: { ...fixture().status, key: null } }), async (page) => {
      await ready(page);
      await page.locator('[data-nav="keys"]').click();
      await page.locator('[data-focus="key-create"]').click();
      await page.locator('#kit-secret').waitFor();
      await page.locator('[data-nav="overview"]').click();
      await page.locator('.stat').first().waitFor();
      await page.locator('[data-nav="keys"]').click();
      await page.locator('[data-focus="kit-show"]').waitFor();
      assert.equal(await page.locator('#kit-secret').count(), 0, 'not shown again without a new request');
      assert.equal((await calls(page, 'key-kit')).length, 1);
      await page.locator('[data-focus="kit-show"]').click();
      await page.locator('#kit-confirm').check();
      await page.locator('[data-focus="kit-done"]').click();
      await page.locator('[data-focus="kit-redownload"]').waitFor();
      assert(!(await page.content()).includes(SECRET));
      const kitCalls = (await calls(page, 'key-kit')).length;
      await page.locator('[data-focus="kit-redownload"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.match(await page.locator('#confirm-body').textContent(), /可以解開這台設備所有備份的私密金鑰/);
      await page.locator('#confirm-cancel').click();
      assert.equal((await calls(page, 'key-kit')).length, kitCalls, 'cancel downloads nothing');
      await page.locator('[data-focus="kit-redownload"]').click();
      const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#confirm-ok').click()]);
      assert.equal(download.suggestedFilename(), `woowtech-backup-key-dev-a-${KEY_ID}.txt`);
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert(!(await page.content()).includes(SECRET), 'the secret never reaches the DOM');
    });

  await check('terms and labels follow the glossary; unhealthy apps are not "running" (F14, lab H5)', fixture({
    status: { ...fixture().status, apps: [app('woowbk-demo', '示範筆記應用', { state: 'error',
      problems: ['服務已啟動，但健康檢查未通過（http://127.0.0.1:18090/healthz，HTTP 503）。'] })] },
  }), async (page) => {
    await ready(page);
    await page.locator('.item-list').first().waitFor();
    assert.match(await view(page).textContent(), /異常/);
    assert.match(await view(page).textContent(), /HTTP 503/);
    assert.match(await page.locator('.host-line').textContent(), /設備 dev-a/);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    const chips = await page.locator(`tr[data-backup="${B_SAFETY}"] .chip`).first().textContent();
    assert.equal(chips.trim(), '還原前備份');
    assert(!/還原前自動備份備份|WOOWTECH|密鑰/.test(await page.locator('body').textContent()));
  });

  await check('host directories are listed in backup details, preflight, confirmation and the restore result', withHostDirs(fixture()), async (page) => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="open-${B_MANUAL}"]`).click();
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).waitFor();  // the detail view is rendered (no race)
    assert.match(await view(page).textContent(), /查看應用、資料庫、資料卷、主機資料夾與映像/);
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content .path-list').first().waitFor();
    const [demo, wiki] = await metadataOf(page.locator('.app-content'));
    assert.equal(demo['資料庫'], '沒有以 pg_dump 匯出的資料庫', 'a database kept as files has no dump of its own');
    assert.equal(wiki['主機資料夾'], '無', 'an app without host directories says so');
    assert.deepEqual(await dirRows(page.locator('.app-content .path-list').first()), DIR_ROWS.map(row => [null, ...row]));
    await allWidths(page, 'detail with host directories');

    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    const card = page.locator('.app-preflight').first();
    const checks = await card.locator('.check').evaluateAll(items => items.map(item => [item.className, item.querySelector('.check-message').textContent]));
    for (const check of DIR_CHECKS) {
      assert(checks.some(([className, message]) => className === `check check-${check.status}` && message === check.message),
        `new check id ${check.id} renders as ${check.status} with its own message`);
    }
    assert.deepEqual(await dirRows(card.locator('details.app-details ul[aria-label$="的主機資料夾"]')), DIR_ROWS.map(row => [null, ...row]),
      'the preflight card lists the backup contents, host directories included');
    await allWidths(page, 'preflight with host directories');

    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    assert.match(await page.locator('.affected').textContent(), /以備份內容覆寫資料庫、資料卷、主機資料夾、應用機密與設定檔/);
    assert.deepEqual(await dirRows(page.locator('ul[aria-label="原位還原會取代的主機資料夾"]')), DIR_ROWS.map(row => ['示範筆記應用', ...row]));
    assert.equal(await page.locator('ul[aria-label="全新部署會建立的主機資料夾"]').count(), 0);
    const text = await view(page).textContent();
    assert.match(text, /整個取代下列資料夾，不會合併/);
    assert.match(text, /原本的內容保留到整個還原成功後才刪除/);
    assert.match(text, /路徑中的 ~ 是這台設備上應用擁有者的家目錄/);
    assert.match(await page.locator('ul[aria-label="注意事項"]').textContent(), /新舊內容會同時存在/, 'the space warning repeats where the decision is made');
    await allWidths(page, 'confirm with host directories');
    await page.setViewportSize({ width: 320, height: 900 });
    await shot(page, 'restore-confirm-host-dirs-320.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.deepEqual(await dirRows(page.locator('ul[aria-label="原位還原的主機資料夾"]')), DIR_ROWS.map(row => ['示範筆記應用', ...row]));
    assert.match(await page.locator('.job-result').textContent(), /這台設備應用設定列出的，已整個換成備份時的內容，還原前的內容保留在上列還原前備份中/);
    await allWidths(page, 'result with host directories');
    await shot(page, 'restore-result-host-dirs-1440.png');
  });

  await check('a fresh restore names the host directories it creates', withHostDirs(fixture(), { mode: 'fresh' }), async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    assert.match(await page.locator('.affected').textContent(), /全新部署：會在這台設備建立服務、資料卷、主機資料夾與資料庫/);
    assert.equal(await page.locator('ul[aria-label="原位還原會取代的主機資料夾"]').count(), 0);
    assert.deepEqual(await dirRows(page.locator('ul[aria-label="全新部署會建立的主機資料夾"]')), DIR_ROWS.map(row => ['示範筆記應用', ...row]));
    assert.match(await view(page).textContent(), /必須不存在或是空的（預檢會確認），上層資料夾不存在時會以應用擁有者身分建立/);
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.equal(await page.locator('ul[aria-label="原位還原的主機資料夾"]').count(), 0);
    assert.equal(await page.locator('ul[aria-label="全新部署的主機資料夾"] li').count(), 2);
    assert.match(await page.locator('.job-result').textContent(), /已建立並寫入備份時的內容/);
  });

  // The engine reports what interruption recovery did with leftover <path>.woowbk-new-/.woowbk-old- folders in the
  // job's own message; the page adds guidance and never hides that message.
  const DIR_RECOVERY = '還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。'
    + `主機資料夾 ~/${HA_DIR} 不在原位，已把原本的內容（~/${HA_DIR}.woowbk-old-j20261113T020011Z-00abc001）移回；已移除未完成的新內容。`
    + `還原前備份：${B_SAFETY}。`;
  const dirsInterrupted = withHostDirs(fixture());
  dirsInterrupted.scripts.restore = [
    runningStep('restore', 'restore', 60, { safety_backup_id: B_SAFETY }),
    {
      job: { state: 'interrupted', finished: '2026-11-13T02:09:00Z', progress: { percent: 60, message: '已中斷' }, cancellable: false,
        phases: phasesAt('restore', 'restore', { failedAt: 'restore' }), error: { code: 'job-failed', message: DIR_RECOVERY },
        result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY, health: [], verification: [], rolled_back: false, changed: true,
          fresh_apps: [], safety_skipped: false, safety_failed: false, warnings: [] } },
      log: ['2026-11-13T02:09:00Z 作業被判定為已中斷'],
    },
  ];
  const manualDirs = [{
    job: { state: 'failed', phase: 'rollback', finished: '2026-11-13T02:12:00Z', progress: { percent: 90, message: '失敗' }, cancellable: false,
      phases: phasesAt('restore', null, { failedAt: 'start', rollback: 'failed' }),
      error: { code: 'job-failed', message: `自動回復未完成，需人工處理：無法把主機資料夾 ~/${NC_DB_DIR} 回復到還原前的狀態。` },
      result: { apps: ['woowbk-demo'], safety_backup_id: B_SAFETY_NEW, health: [], verification: [], rolled_back: false, changed: true,
        fresh_apps: [], safety_skipped: false, safety_failed: false, warnings: [] } },
    log: ['2026-11-13T02:12:00Z 作業結束：失敗'],
  }];
  await check('interrupted or unrecovered restores explain leftover host-directory copies', dirsInterrupted, async (page) => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '作業意外中斷' }).waitFor();
    assert.equal(await page.locator('.job-result .notice-error p').textContent(), DIR_RECOVERY, 'the engine report is shown verbatim');
    assert.match(await page.locator('.guidance').textContent(), /名稱含「\.woowbk-new-」或「\.woowbk-old-」的資料夾.*請勿手動刪除或改名/);
    await page.locator('[data-focus="result-restore-safety"]').waitFor();
    await allWidths(page, 'interrupted restore with host directories');

    // Rollback incomplete: the old copy may be the pre-restore content; the page says not to delete it.
    await page.evaluate(script => { window.__fixture.scripts.restore = script; }, manualDirs);
    await page.locator('[data-focus="result-restore-safety"]').click();
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原失敗' }).waitFor();
    const text = await page.locator('.job-result').textContent();
    assert.match(text, /自動回復未完成，需要人工處理/);
    assert.match(text, /名稱含「\.woowbk-old-」的資料夾可能是還原前的內容，處理完成前請勿刪除/);
  });

  const hostileDirs = withHostDirs(fixture(), { dirs: [
    { path: `${evil}/config`, label: evil },
    { path: `${'deep/'.repeat(12)}${long}`, label: long, size: 3 * GiB },
  ] });
  hostileDirs.inspect[B_MANUAL].preflight.apps[0].checks.push({ id: `woowbk-demo/${evil}`, status: '<i>odd</i>', message: `${evil}${long}` });
  hostileDirs.scripts.restore.at(-1).job.result.warnings = [`主機資料夾 ~/${evil}：${long}`];
  await check('hostile host-directory paths and labels are rendered literally and wrap at every width', hostileDirs, async (page) => {
    const noInjection = async label => {
      const found = await page.evaluate(() => ({
        injected: document.querySelectorAll('body img, body script, body b, body i, body iframe:not(#downloads iframe), body svg:not(.icon)').length,
        xss: Boolean(window.__xss),
      }));
      assert.deepEqual(found, { injected: 0, xss: false }, `${label}: no element created from data`);
    };
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="open-${B_MANUAL}"]`).click();
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content .path-list').first().waitFor();
    const rows = await dirRows(page.locator('.app-content .path-list').first());
    assert.deepEqual(rows[0], [null, `~/${evil}/config`, evil], 'path and label are text, character for character');
    assert.deepEqual(rows[1], [null, `~/${'deep/'.repeat(12)}${long}`, `${long} · 3.0 GiB`]);
    await noInjection('detail');
    await allWidths(page, 'hostile host directories: detail');
    await page.locator(`[data-focus="restore-${B_MANUAL}"]`).click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.match(await page.locator('.app-preflight').first().textContent(), /<img src=x onerror/);
    await noInjection('preflight');
    await allWidths(page, 'hostile host directories: preflight');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').waitFor();
    assert.equal((await dirRows(page.locator('ul[aria-label="原位還原會取代的主機資料夾"]')))[0][1], `~/${evil}/config`);
    await noInjection('confirm');
    await allWidths(page, 'hostile host directories: confirm');
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.equal((await dirRows(page.locator('ul[aria-label="原位還原的主機資料夾"]')))[0][1], `~/${evil}/config`);
    assert.equal(await page.locator('ul[aria-label="還原注意事項"] .check-message').textContent(), `主機資料夾 ~/${evil}：${long}`);
    await noInjection('result');
    await allWidths(page, 'hostile host directories: result');
  });

  await check('follows the Cockpit dark theme live with readable contrast in every surface', withHostDirs(fixture({
    status: { ...fixture().status, key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: false },
      warnings: ['示範：部分應用的設定需要檢查。'] },
  })), async (page) => {
    await ready(page);
    await page.locator('.stat').first().waitFor();
    const isDark = () => page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark'));
    const background = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert.equal(await isDark(), true, 'shell:style=dark from Cockpit applies before the first render');
    assert.equal(await background(), (apporo ? 'rgb(24, 24, 27)' : 'rgb(21, 23, 28)'));
    const steady = () => page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
    const contrast = (extra = '') => page.evaluate(extra => {
      const rgb = value => (value.match(/[\d.]+/g) || []).map(Number);
      const luminance = ([r, g, b]) => [r, g, b].map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; })
        .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
      const backgroundOf = node => {
        for (let el = node; el; el = el.parentElement) {
          const [r, g, b, a = 1] = rgb(getComputedStyle(el).backgroundColor);
          if (a > 0.5) return [r, g, b];
        }
        return [255, 255, 255];
      };
      const failures = [];
      let checked = 0;
      for (const el of document.querySelectorAll(`h1, h2, h3, p, a, button, .chip, label, dt, dd, td, th, li, small, .muted${extra}`)) {
        const box = el.getBoundingClientRect();
        if (!box.width || !box.height || !el.textContent.trim()) continue;
        const style = getComputedStyle(el);
        if (style.visibility === 'hidden' || Number(style.opacity) < 0.9) continue;
        const fg = luminance(rgb(style.color)), bg = luminance(backgroundOf(el));
        const ratio = (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
        const size = parseFloat(style.fontSize), bold = Number(style.fontWeight) >= 700;
        const minimum = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
        checked++;
        if (ratio < minimum) failures.push(`${el.tagName.toLowerCase()}.${el.className} "${el.textContent.trim().slice(0, 24)}" ${ratio.toFixed(2)}`);
      }
      return { checked, failures };
    }, extra);
    for (const route of ['overview', 'backups', 'keys']) {
      if (route !== 'overview') {
        await page.locator(`[data-nav="${route}"]`).click();
        await settled(page);
      }
      await steady();
      const result = await contrast();
      assert(result.checked > 10, `${route}: enough text was checked (${result.checked})`);
      assert.deepEqual(result.failures, [], `${route}: dark-theme text keeps WCAG AA contrast`);
      await allWidths(page, `dark ${route}`);
    }
    // Backup details with host directories: the path list keeps the same contrast and fits every width.
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="open-${B_MANUAL}"]`).click();
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content .path-list').first().waitFor();
    await steady();
    const detail = await contrast(', .path, .path-app, .path-list .secondary');
    assert(detail.checked > 10, `detail: enough text was checked (${detail.checked})`);
    assert.deepEqual(detail.failures, [], 'detail with host directories: dark-theme text keeps WCAG AA contrast');
    await allWidths(page, 'dark detail with host directories');
    await shot(page, 'detail-host-dirs-dark-1440.png');
    await page.locator('[data-nav="overview"]').click();
    await settled(page);
    await shot(page, 'overview-dark-1440.png');
    const transitionsDuringSwitch = await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('cockpit-style', { detail: { style: 'light' } }));
      getComputedStyle(document.body).backgroundColor;
      return document.getAnimations().filter(animation => animation instanceof CSSTransition).length;
    });
    assert.equal(transitionsDuringSwitch, 0, 'a theme switch starts no colour transitions (no unreadable mid-tones)');
    await steady();
    assert.equal(await isDark(), false, 'switching Cockpit to light applies live');
    assert.equal(await background(), 'rgb(255, 255, 255)');
    await page.evaluate(() => window.dispatchEvent(new CustomEvent('cockpit-style', { detail: { style: 'dark' } })));
    assert.equal(await isDark(), true, 'switching back to dark applies live');
  }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  // ------------------------------------------------------------------ strengthen phase (2026-11-13)

  const plainBackup = () => {
    const steps = scripts().backup;
    Object.assign(steps.at(-1).job.result, { encrypted: false });
    Object.assign(steps.at(-1).addBackup, { encrypted: false, key_id: null, key_available: true });
    return steps;
  };
  await check('an unencrypted backup needs no device key; while 預設加密備份 is on it needs its own acknowledgement',
    fixture({ status: { ...fixture().status, key: null }, scripts: { ...scripts(), backup: plainBackup() } }), async page => {
      await ready(page);
      assert.match(await page.locator('#key-banner').textContent(), /建立第一份加密備份前/);
      await page.locator('#go-create').click();
      await page.locator('#encrypt-backup').waitFor();
      assert.equal(await page.locator('#encrypt-backup').isChecked(), true, '加密此備份 defaults to 預設加密備份');
      assert.equal(await page.locator('[data-focus="create-submit"]').isDisabled(), true, 'an encrypted backup needs the device key');
      assert.match(await view(page).textContent(), /或取消勾選「加密此備份」建立不加密的備份/);
      await page.locator('#encrypt-backup').uncheck();
      await page.locator('#ack-plaintext').waitFor();
      assert.match(await view(page).textContent(), /這份備份不會加密。/);
      assert(await view(page).getByText(PLAINTEXT, { exact: false }).count() > 0, 'the engine warning is shown verbatim');
      assert.equal(await page.locator('[data-focus="create-keys"]').count(), 0, 'the missing key never blocks an unencrypted backup');
      assert.equal(await page.locator('[data-focus="create-submit"]').isDisabled(), true, 'plain text is a separately acknowledged decision');
      await allWidths(page, 'create an unencrypted backup');
      await page.locator('#ack-plaintext').check();
      await enabled(page, '[data-focus="create-submit"]');
      assert.match(await page.locator('[data-focus="create-submit"]').textContent(), /開始備份（不加密）/);
      await shot(page, 'create-unencrypted-1440.png');
      await page.locator('[data-focus="create-submit"]').click();
      await page.waitForFunction(() => /^#\/jobs\//.test(window.location.hash));
      const start = requestOf((await calls(page, 'backup-start')).at(-1));
      assert.deepEqual([start.encrypt, start.acknowledge_plaintext], [false, true]);
      await page.locator('#result-heading').filter({ hasText: '備份完成' }).waitFor();
      assert.match(await page.locator('.job-result').textContent(), /備份已建立（未加密）/);
      assert.match(await page.locator('.job-result').textContent(), /加密未加密/);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`tr[data-backup="${B_NEW}"]`).waitFor();
      assert.deepEqual(await page.locator(`tr[data-backup="${B_NEW}"] td[data-label="加密與驗證"] .chip`).allTextContents(), ['未加密']);
      assert.equal(await page.locator(`[data-focus="download-menu-row-${B_NEW}"]`).count(), 0, 'an unencrypted backup has no unencrypted-copy menu');
    });

  await check('預設加密備份: turning it off needs the acknowledged warning, turning it on does not', fixture(), async page => {
    await ready(page);
    await page.locator('[data-nav="keys"]').click();
    await page.locator('#encrypt-default').waitFor();
    assert.equal(await page.locator('#encrypt-default').isChecked(), true);
    await page.locator('#encrypt-default').click();
    await page.locator('#confirm-dialog').waitFor();
    assert.equal(await page.locator('#encrypt-default').isChecked(), true, 'nothing changes before the decision');
    assert.match(await page.locator('#confirm-body').textContent(), /應用機密；任何取得備份檔的人都能讀取/);
    assert.equal(await page.locator('#confirm-ok').isDisabled(), true, 'the button waits for the acknowledgement');
    await allWidths(page, 'turn off default encryption dialog');
    await page.locator('#confirm-cancel').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal((await calls(page, 'settings-set')).length, 0, 'cancel changes nothing');
    await page.locator('#encrypt-default').click();
    await page.locator('#confirm-ack').check();
    await page.locator('#confirm-ok').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.deepEqual(requestOf((await calls(page, 'settings-set')).at(-1)), { encrypt_by_default: false, acknowledge_plaintext: true });
    await view(page).getByText('已關閉「預設加密備份」').waitFor();
    assert.equal(await page.locator('#encrypt-default').isChecked(), false);
    assert.match(await page.locator('section[aria-labelledby="settings-heading"]').textContent(), /預設不加密/);
    await shot(page, 'keys-default-encryption-off-1440.png');
    // New backups now start unencrypted, without a second acknowledgement.
    await page.locator('#go-create').click();
    await page.locator('#encrypt-backup').waitFor();
    assert.equal(await page.locator('#encrypt-backup').isChecked(), false);
    assert.equal(await page.locator('#ack-plaintext').count(), 0);
    await page.locator('[data-focus="create-submit"]').click();
    await page.waitForFunction(() => /^#\/jobs\//.test(window.location.hash));
    const start = requestOf((await calls(page, 'backup-start')).at(-1));
    assert.deepEqual([start.encrypt, 'acknowledge_plaintext' in start], [false, false]);
    await page.locator('#result-heading').waitFor();
    await page.locator('[data-nav="keys"]').click();
    await page.locator('#encrypt-default').click();
    await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'settings-set').length === 2);
    assert.deepEqual(requestOf((await calls(page, 'settings-set')).at(-1)), { encrypt_by_default: true }, 'turning it on needs no acknowledgement');
    await view(page).getByText('已開啟「預設加密備份」。').waitFor();
    assert.equal(await page.locator('#confirm-dialog').isVisible(), false);
  });

  await check('download menu: the encrypted .tar by default; 下載未加密版本 warns, runs an export job and downloads the copy', fixture(), async page => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    const chipsOf = id => page.locator(`tr[data-backup="${id}"] td[data-label="加密與驗證"] .chip`).allTextContents();
    assert.deepEqual(await chipsOf(B_MANUAL), ['已加密', '金鑰可用']);
    assert.deepEqual(await chipsOf(B_UPLOADED), ['已加密', '需要緊急金鑰']);
    assert.match(await page.locator(`tr[data-backup="${B_SAFETY}"]`).textContent(), /舊格式（\.woowbackup）/);
    const toggle = page.locator(`[data-focus="download-menu-row-${B_MANUAL}"]`);
    const focused = () => page.evaluate(() => document.activeElement?.dataset?.focus);
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    await toggle.click();
    await page.locator(`#menu-row-${B_MANUAL}`).waitFor();
    assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(await focused(), `menu-download-row-${B_MANUAL}`, 'focus moves into the menu');
    assert.deepEqual(await page.locator(`#menu-row-${B_MANUAL} .menu-item-label`).allTextContents(), ['下載加密的備份檔（.tar）', '下載未加密版本…']);
    await page.keyboard.press('ArrowDown');
    assert.equal(await focused(), `menu-export-row-${B_MANUAL}`);
    await page.keyboard.press('ArrowDown');
    assert.equal(await focused(), `menu-download-row-${B_MANUAL}`, 'arrow keys wrap around');
    await page.keyboard.press('Escape');
    await page.locator(`#menu-row-${B_MANUAL}`).waitFor({ state: 'hidden' });
    assert.equal(await focused(), `download-menu-row-${B_MANUAL}`, 'Escape returns focus to the menu button');
    await toggle.click();
    await page.locator('#view-heading').click();
    await page.locator(`#menu-row-${B_MANUAL}`).waitFor({ state: 'hidden' });
    await toggle.click();
    await allWidths(page, 'download menu open');
    await page.setViewportSize({ width: 320, height: 900 });
    await shot(page, 'download-menu-320.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    const before = downloadRequests.length;
    const [stored] = await Promise.all([page.waitForEvent('download'), page.locator(`[data-focus="menu-download-row-${B_MANUAL}"]`).click()]);
    assert.equal(stored.suggestedFilename(), 'woowtech-backup-dev-a-20261112-020000.tar', 'the default is the stored, encrypted file');
    assert.equal(downloadRequests[before].open.path, `/var/lib/woowtech-backup/archives/${B_MANUAL}.tar`);
    await toggle.click();
    await page.locator(`[data-focus="menu-export-row-${B_MANUAL}"]`).click();
    await page.locator('#confirm-dialog').waitFor();
    const body = await page.locator('#confirm-body').textContent();
    assert.match(body, /資料庫密碼、API 金鑰與存取權杖都是明文/);
    assert.match(body, /15 分鐘/);
    assert.match(body, /系統日誌/);
    assert.equal(await page.locator('#confirm-ok').isDisabled(), true);
    await allWidths(page, 'unencrypted download dialog');
    await shot(page, 'download-unencrypted-dialog-1440.png');
    await page.locator('#confirm-cancel').click();
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal((await calls(page, 'export-start')).length, 0, 'cancel starts nothing');
    await toggle.click();
    await page.locator(`[data-focus="menu-export-row-${B_MANUAL}"]`).click();
    await page.locator('#confirm-ack').check();
    const copy = page.waitForEvent('download');
    await page.locator('#confirm-ok').click();
    await page.waitForFunction(() => /^#\/jobs\//.test(window.location.hash));
    const start = requestOf((await calls(page, 'export-start')).at(-1));
    assert.deepEqual(Object.keys(start).sort(), ['backup_id', 'confirm', 'request_id']);
    assert.deepEqual([start.backup_id, start.confirm], [B_MANUAL, true]);
    await page.locator('#result-heading').filter({ hasText: '未加密副本已建立' }).waitFor();
    assert.equal(await page.locator('#view-heading').textContent(), '建立未加密副本');
    assert.equal((await copy).suggestedFilename(), EXPORT_NAME, 'the copy downloads by itself once it is ready');
    assert.deepEqual((await calls(page, 'export-info')).map(requestOf), [{ export_id: EXPORT_ID }]);
    assert.equal(downloadRequests.at(-1).open.path, `/var/lib/woowtech-backup/exports/${EXPORT_ID}.tar`);
    assert.match(await page.locator('.job-result').textContent(), /自動刪除/);
    await allWidths(page, 'export result');
    await shot(page, 'export-result-1440.png');
    await page.locator('[data-nav="activity"]').click();
    await page.locator('.jobs-table').waitFor();
    assert.match(await page.locator('.jobs-table tbody tr').first().textContent(), /未加密副本/);
    await page.evaluate(id => { window.location.hash = `#/backups/${id}`; }, B_MANUAL);
    await page.locator('.export-card').waitFor();
    assert.match(await page.locator('.export-card').textContent(), new RegExp(EXPORT_NAME));
    await page.locator(`[data-focus="export-delete-${EXPORT_ID}"]`).click();
    await page.locator('.export-card').waitFor({ state: 'detached' });
    assert.deepEqual((await calls(page, 'export-delete')).map(requestOf), [{ export_id: EXPORT_ID }]);
  });

  await check('下載未加密版本 of a backup whose key is not on this device asks for the emergency key next',
    fixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="download-menu-row-${B_UPLOADED}"]`).click();
      await page.locator(`[data-focus="menu-export-row-${B_UPLOADED}"]`).click();
      await page.locator('#confirm-dialog').waitFor();
      assert.match(await page.locator('#confirm-body').textContent(), new RegExp(`金鑰 ${OTHER_KEY_ID} 加密，這台設備沒有這把金鑰`));
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#key-dialog').waitFor();
      await page.locator('#key-dialog-text').fill(SECRET);
      await page.locator('#key-dialog-ok').click();
      await page.locator('#key-dialog-error').getByText('這把金鑰無法解開這份備份').waitFor();
      await page.locator('#key-dialog-text').fill(OTHER_SECRET);
      await page.locator('#key-dialog-ok').click();
      await page.waitForFunction(() => /^#\/jobs\//.test(window.location.hash));
      const start = requestOf((await calls(page, 'export-start')).at(-1));
      assert.deepEqual([start.backup_id, start.key], [B_UPLOADED, OTHER_SECRET]);
      for (const call of await calls(page, 'job-status')) assert(!call.stdin.includes('AGE-SECRET-KEY'), 'the key is not resent after the job started');
    });

  const plainUpload = fixture();
  const plainMeta = backupMeta(B_PLAIN, { type: 'uploaded', encrypted: false, unauthenticated: true, key_id: null, key_available: true, inspected: false,
    apps: [], verified: null, source: null, uploaded_at: '2026-11-13T03:01:00Z', filename: 'woowtech-backup-dev-b-20261113-030000.tar' });
  plainUpload.upload.finish = plainMeta;
  plainUpload.inspect[B_PLAIN] = inspectResult({ ...plainMeta, created: '2026-11-13T03:00:00Z' }, { hostname: 'dev-b', uid: 1007 });
  plainUpload.inspect[B_PLAIN].preflight.checks.unshift({ id: 'unauthenticated', status: 'warn', message: UNAUTH_MESSAGE });
  await check('an unencrypted upload is unauthenticated: no key step, a preflight warning and a second acknowledgement on 確認', plainUpload, async page => {
    await ready(page);
    await page.locator('#go-restore').click();
    assert.equal(await page.locator('#restore-file').getAttribute('accept'), '.tar,.woowbackup');
    assert.match(await view(page).textContent(), /\.tar 或舊格式 \.woowbackup/);
    await page.locator('#restore-file').setInputFiles({ name: 'woowtech-backup-dev-b-20261113-030000.tar', mimeType: 'application/x-tar', buffer: Buffer.alloc(64 * KiB, 5) });
    assert.equal(await view(page).getByText('檔名不是').count(), 0, 'a .tar name raises no warning');
    await page.locator('[data-focus="restore-upload"]').click();
    await page.locator('[data-focus="pf-next"]').waitFor();
    assert.equal(await page.locator('.stepper .step').filter({ hasText: '金鑰' }).count(), 0, 'no key step for an unencrypted backup');
    assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_PLAIN });
    assert.match(await view(page).textContent(), /這是上傳的未加密備份/);
    assert.match(await view(page).textContent(), /未加密（來源無法驗證）/);
    assert.match(await page.locator('ul[aria-label="整體檢查結果"]').textContent(), /內容無法驗證/);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-unauthenticated').waitFor();
    await page.locator('#confirm-restore').check();
    assert.equal(await page.locator('[data-focus="confirm-start"]').isDisabled(), true, 'trusting the file is its own decision');
    assert.match(await page.locator('ul[aria-label="注意事項"]').textContent(), /內容無法驗證/, 'the warning repeats where the decision is made');
    await allWidths(page, 'confirm an unauthenticated upload');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'restore-confirm-unauthenticated-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('#confirm-unauthenticated').check();
    await enabled(page, '[data-focus="confirm-start"]');
    await page.locator('[data-focus="confirm-start"]').click();
    await page.waitForFunction(() => /^#\/jobs\//.test(window.location.hash));
    const restore = requestOf((await calls(page, 'restore-start')).at(-1));
    assert.equal(restore.accept_unauthenticated, true);
    assert.equal(restore.key, undefined);
    await page.locator('#result-heading').waitFor();
    assert.match(await page.locator('[aria-labelledby="job-params-heading"]').textContent(), /你已確認信任它的來源/);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`tr[data-backup="${B_PLAIN}"]`).waitFor();
    assert.deepEqual(await page.locator(`tr[data-backup="${B_PLAIN}"] td[data-label="加密與驗證"] .chip`).allTextContents(), ['未加密', '來源未驗證']);
  });

  await check('a digest mismatch is listed per item with its differences, and the restore reports its downtime',
    fixture({ scripts: { ...scripts(), restore: digestRollbackScript() } }), async page => {
      await ready(page);
      await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      assert.match(await view(page).textContent(), /還原前備份依「預設加密備份」設定以這台設備的金鑰加密/);
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原失敗，已自動回復' }).waitFor();
      assert.match(await page.locator('.verify-summary').textContent(), /共 3 項：1 項一致、1 項不一致、1 項未比對。/);
      const rows = await page.locator('.compare tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
      assert.deepEqual(rows.map(row => row.slice(1)), [
        ['資料表資料表內容 · PostgreSQL（main）', '資料庫 1、資料表 3、序列 2、資料列 345', '資料庫 1、資料表 3、序列 2、資料列 345', '一致'],
        ['上傳檔案檔案清單 · 資料卷 woowbk-demo-files', '項目 40、檔案 30、資料夾 8、符號連結 2、121 KiB', '項目 41、檔案 31、資料夾 8、符號連結 2、122 KiB', '不一致遺失 0、多出 1、不同 1'],
        ['config檔案清單 · 主機資料夾 ~/homeassistant/config', '—', '—', '未比對備份沒有這個項目的資料摘要（例如較舊的備份），未比對。']]);
      assert.match(rows[0][0], /資料不一致/);
      const diff = page.locator('details.app-details').filter({ hasText: '「上傳檔案」差異' });
      assert.match(await diff.locator('summary').textContent(), /遺失 0、多出 1、不同 1（列出 2 \/ 2 筆）/);
      await diff.locator('summary').click();
      assert.deepEqual(await diff.locator('li').evaluateAll(items => items.map(item => item.textContent)),
        ['多出ticker還原後多出這個項目', '不同notes/3.txt內容不同（大小 12 → 14）']);
      assert.deepEqual(await page.locator('table.timing tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent))),
        [['示範筆記應用', '18.0 秒', '46.3 秒']]);
      await allWidths(page, 'digest mismatch result');
      await shot(page, 'restore-digest-mismatch-1440.png');
      await page.setViewportSize({ width: 390, height: 900 });
      await shot(page, 'restore-digest-mismatch-390.png');
      await page.setViewportSize({ width: 1440, height: 900 });
    });

  await check('a successful restore lists the JSON summary fields and the digests that matched', fixture({ scripts: { ...scripts(), restore: digestSuccessScript() } }), async page => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.match(await page.locator('.verify-summary').textContent(), /共 7 項：7 項一致、0 項不一致、0 項未比對。/);
    const rows = await page.locator('.compare tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
    assert.deepEqual(rows.map(row => row[1]), ['summary.notes', 'summary.files', 'summary.digest', 'summary.title', 'summary.signatures_valid',
      '資料表資料表內容 · PostgreSQL（main）', '上傳檔案檔案清單 · 資料卷 woowbk-demo-files'], 'digest summaries are not repeated as raw fields');
    assert.deepEqual(await page.locator('table.timing tbody td').allTextContents(), ['12.3 秒', '31.8 秒']);
  });

  await check('deep verify: what was checked, what a restore would drop, and 已驗證（內容已逐項檢查）', fixture(), async page => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    assert.match(await page.locator(`tr[data-backup="${B_MANUAL}"]`).textContent(), /已驗證（檔案完整）/);
    await page.locator(`[data-focus="verify-${B_MANUAL}"]`).click();
    await page.locator('#result-heading').filter({ hasText: '驗證完成' }).waitFor();
    assert.match(await page.locator('.job-result').textContent(), /以還原時相同的規則逐項檢查了內容/);
    assert.deepEqual(await page.locator('ul[aria-label="各應用逐項檢查的內容"] li').allTextContents(),
      ['示範筆記應用資料卷 1、容器映像 2、資料摘要 2、資料庫匯出 1（只檢查格式）、應用機密 2']);
    // review L8: a dump is only recognized by its pg_dump header; the page says where its body is read in full
    assert.match(await page.locator('[data-note="dumps-header-only"]').textContent(), /建立備份時已完整讀取過一次，還原時會再完整讀取/);
    assert.equal(await page.locator('ul[aria-label="驗證注意事項"] .check-message').textContent(), VERIFY_NOTE);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`tr[data-backup="${B_MANUAL}"]`).getByText('已驗證（內容已逐項檢查）', { exact: false }).waitFor();
  });

  const instance = fixture();
  Object.assign(instance.inspect[B_MANUAL].manifest.apps[0], {
    postgres: [{ id: 'main', database: 'postgres', major: 16, scope: 'instance', roles_count: 4,
      databases: [{ name: 'nextcloud', owner: 'oc_admin' }, { name: 'odoo_prod', owner: 'odoo' }, { name: 'postgres', owner: 'notes' }] }],
    verify_digests: [{ id: 'db', type: 'postgres-digest', target: 'postgres:main', summary: { databases: 3, tables: 205, sequences: 12, rows: 98765, roles: 4 } },
      { id: 'files', type: 'files-digest', target: 'volume:woowbk-demo-files', summary: FILES_BEFORE }],
    archive_size: 51 * MiB });
  instance.backups[0].apps = [{ id: 'woowbk-demo', name: '示範筆記應用', size: 51 * MiB }];
  instance.inspect[B_MANUAL].backup.apps[0].size = 51 * MiB;
  await check('backup details name the PostgreSQL mode (整個執行個體／單一資料庫), the data checks and format 2 facts', instance, async page => {
    await ready(page);
    await page.evaluate(id => { window.location.hash = `#/backups/${id}`; }, B_MANUAL);
    await page.locator(`[data-focus="inspect-${B_MANUAL}"]`).click();
    await page.locator('.app-content').first().waitFor();
    const [demo, wiki] = await metadataOf(page.locator('.app-content'));
    assert.equal(demo['資料庫'], 'PostgreSQL 16整個執行個體3 個資料庫、4 個角色（含密碼雜湊）：nextcloud（擁有者 oc_admin）、odoo_prod（擁有者 odoo）、postgres（擁有者 notes）');
    assert.equal(wiki['資料庫'], 'PostgreSQL 16單一資料庫wiki');
    assert.equal(demo['資料核對'], '應用摘要 summary5 個欄位資料表內容PostgreSQL（main）資料庫 3、資料表 205、序列 12、資料列 98,765、角色 4'
      + '檔案清單資料卷 woowbk-demo-files項目 40、檔案 30、資料夾 8、符號連結 2、121 KiB');
    assert.equal(demo['應用封存檔'], '51.0 MiB');
    assert.equal(wiki['資料核對'], '沒有資料核對項目');
    const [general] = await metadataOf(page.locator('section[aria-labelledby="detail-content"] .card-body'));
    assert.deepEqual([general['格式'], general['加密']], ['備份檔（.tar，格式 2）', '已加密（age X25519）']);
    const [info] = await metadataOf(page.locator('section[aria-labelledby="detail-info"]'));
    assert.deepEqual([info['格式'], info['加密']], ['備份檔（.tar）', '已加密（age X25519，需要金鑰才能讀取）']);
    assert.match(await page.locator('section[aria-labelledby="detail-apps"]').textContent(), /應用封存檔 51\.0 MiB/);
    await allWidths(page, 'detail with instance mode and digests');
  });

  const usage = fixture();
  usage.status.storage.apps = [
    { id: 'woowbk-demo', name: '示範筆記應用', in_catalog: true, backups: 5, types: { manual: 3, safety: 2, uploaded: 0 }, bytes: 1.2 * GiB,
      estimated: false, shared: false, newest: '2026-11-12T02:00:00Z', oldest: '2026-11-01T02:00:00Z', keep_last: 5 },
    { id: 'old-app', name: 'old-app', in_catalog: false, backups: 1, types: { manual: 0, safety: 0, uploaded: 1 }, bytes: 200 * MiB,
      estimated: true, shared: true, newest: '2026-11-02T02:00:00Z', oldest: '2026-11-02T02:00:00Z', keep_last: null },
    { id: 'woowbk-wiki', name: '團隊知識庫', in_catalog: true, backups: 0, types: { manual: 0, safety: 0, uploaded: 0 }, bytes: 0,
      estimated: false, shared: false, newest: null, oldest: null, keep_last: null }];
  await check('the overview shows each app\'s backup storage; an engine without retention says so on 清理備份', usage, async page => {
    await ready(page);
    await page.locator('.usage-list').waitFor();
    const rows = await page.locator('.usage-row').evaluateAll(items => items.map(item => [item.dataset.usage,
      item.querySelector('.usage-size').textContent, item.querySelector(':scope > .secondary').textContent]));
    assert.deepEqual(rows.map(row => row.slice(0, 2)), [['woowbk-demo', '1.2 GiB'], ['old-app', '200 MiB（估計）']], 'apps without backups are left out');
    assert.match(rows[0][2], /^5 份備份（手動 3、還原前 2） · 最新 .+ · 保留最新 5 份手動備份$/);
    assert.match(rows[1][2], /保留全部手動備份/);
    assert.match(await page.locator('.usage-row[data-usage="old-app"]').textContent(), /這台設備沒有它的應用設定/);
    await allWidths(page, 'overview with storage per app');
    await page.locator('[data-focus="overview-cleanup"]').click();
    await page.waitForFunction(() => window.location.hash === '#/cleanup');
    await view(page).getByText('這台設備尚不支援清理備份').waitFor();
    assert.equal(await page.locator('[data-nav="backups"]').getAttribute('aria-current'), 'page');
  });

  await check('without engine figures the overview computes storage per app from the backup list', fixture(), async page => {
    await ready(page);
    await page.locator('.usage-list').waitFor();
    assert.deepEqual(await page.locator('.usage-row').evaluateAll(items => items.map(item => [item.dataset.usage, item.querySelector('.usage-size').textContent])),
      [['woowbk-demo', '96.0 MiB']]);
    assert.match(await page.locator('.usage-row').first().textContent(), /2 份備份（手動 1、還原前 1）/);
    assert.match(await page.locator('.usage-foot').textContent(), /另有 1 份尚未檢查內容的上傳備份，共 48\.0 MiB/);
  });

  await check('清理備份: usage, a keep-last policy, a preview with protected backups and a confirmed deletion', retentionFixture(), async page => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('[data-focus="list-cleanup"]').click();
    await page.locator('.usage-table').waitFor();
    assert.deepEqual(requestOf((await calls(page, 'retention-plan'))[0]), {}, 'the first plan is for the saved policy');
    assert.match(await view(page).textContent(), /目前的原則是全部保留，沒有要刪除的備份。/);
    assert.deepEqual(await page.locator('section[aria-labelledby="cleanup-protected"] .pick-reason').allTextContents(), [
      '失敗或中斷的還原仍需要這份還原前備份才能回到還原前的狀態。', '失敗或中斷的還原使用這份備份；在該應用成功還原之前保留。']);
    assert.equal(await page.locator('section[aria-labelledby="cleanup-protected"] input[type="checkbox"]:enabled').count(), 0, 'protected backups cannot be selected');
    await page.locator('#keep-woowbk-demo-mode').selectOption('last');
    await page.locator('#keep-woowbk-demo-count').fill('2');
    await page.locator('#keep-woowbk-demo-count').press('Tab');
    assert.equal(await page.locator('[data-focus="cleanup-apply"]').isDisabled(), true, 'a changed policy needs a preview first');
    assert.match(await page.locator('.cleanup-hint').textContent(), /請先按「預覽清理」/);
    await page.locator('#keep-woowbk-demo-count').fill('0');
    assert.match(await page.locator('.cleanup-hint').textContent(), /1 到 1000 的整數/);
    await page.locator('#keep-woowbk-demo-count').fill('2');
    await page.locator('[data-focus="cleanup-preview"]').click();
    await page.locator('section[aria-labelledby="cleanup-candidates"] .pick').first().waitFor();
    assert.deepEqual(requestOf((await calls(page, 'retention-plan')).at(-1)), { policy: { schema: 1, default_keep_last: null, apps: { 'woowbk-demo': { keep_last: 2 } } } });
    const picks = await page.locator('section[aria-labelledby="cleanup-candidates"] .pick').evaluateAll(items => items.map(item =>
      [item.dataset.brief, item.querySelector('input').checked, item.querySelector('input').disabled]));
    assert.deepEqual(picks, [[RET_IDS[4], true, false], [RET_IDS[3], true, false], [RET_IDS[2], true, false], [RET_IDS[1], true, false], [RET_IDS[0], false, true]],
      'candidates are checked; the pinned one is shown but cannot be selected');
    assert.match(await page.locator(`[data-brief="${RET_IDS[4]}"]`).textContent(), /「示範筆記應用」第 3 新（保留最新 2 份）/);
    await page.locator(`#pick-${RET_IDS[1]}`).uncheck();
    await page.locator('[data-focus="cleanup-others-list"]').click();
    await page.locator(`#pick-${B_UPLOADED}`).check();
    assert.match(await page.locator('.cleanup-hint').textContent(), /已選 4 份/);
    assert.equal(await page.evaluate(() => {
      const ids = [...document.querySelectorAll('#view [id]')].map(node => node.id);
      return ids.length - new Set(ids).size;
    }), 0, 'element ids are unique although a protected candidate is listed twice');
    // 重新計算 computes the previewed plan again and keeps what was unchecked.
    const plans = (await calls(page, 'retention-plan')).length;
    await page.locator('[data-focus="cleanup-refresh"]').click();
    await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'retention-plan').length > count, plans);
    await settled(page);
    await page.locator('section[aria-labelledby="cleanup-candidates"] .pick').first().waitFor();
    assert.equal(await page.locator(`#pick-${RET_IDS[1]}`).isChecked(), false, 'the unchecked candidate stays unchecked after a refresh');
    assert.deepEqual(requestOf((await calls(page, 'retention-plan')).at(-1)), { policy: { schema: 1, default_keep_last: null, apps: { 'woowbk-demo': { keep_last: 2 } } } },
      'the refresh is for the previewed policy');
    await allWidths(page, 'cleanup preview');
    await shot(page, 'cleanup-preview-1440.png');
    await page.setViewportSize({ width: 360, height: 900 });
    await shot(page, 'cleanup-preview-360.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-focus="cleanup-apply"]').click();
    await page.locator('#confirm-dialog').waitFor();
    assert.match(await page.locator('#confirm-title').textContent(), /刪除 4 份備份/);
    assert.match(await page.locator('#confirm-body').textContent(), /儲存保留原則：預設全部保留，1 個應用個別設定/);
    assert.equal(await page.locator('#confirm-ok').isDisabled(), true);
    await page.locator('#confirm-ack').check();
    await page.locator('#confirm-ok').click();
    await page.locator('#cleanup-result').waitFor();
    const apply = requestOf((await calls(page, 'retention-apply')).at(-1));
    assert.deepEqual(apply, { confirm: true, backup_ids: [RET_IDS[4], RET_IDS[3], RET_IDS[2], B_UPLOADED],
      policy: { schema: 1, default_keep_last: null, apps: { 'woowbk-demo': { keep_last: 2 } } } });
    assert.match(await page.locator('#cleanup-result').textContent(), /已刪除 4 份備份/);
    await page.locator('section[aria-labelledby="cleanup-policy"] .chip').filter({ hasText: '已儲存' }).waitFor();
    assert.equal(await page.locator(`[data-brief="${RET_IDS[4]}"]`).count(), 0, 'deleted backups left the lists');
  });

  await check('應用設定: owners, a scan, draft review, PostgreSQL mode, JSON editing with validation and diff, install and remove',
    fixture({ catalogData: catalogData() }), async page => {
      await ready(page);
      await page.locator('[data-nav="catalog"]').click();
      await page.locator('[data-focus="owner-appowner"]').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'catalog-suggest'))[0]), {}, 'owners first, without an owner');
      assert.equal(await page.locator('[data-focus="owner-appowner"]').isChecked(), true, 'the owner with installed apps is preselected');
      assert.match(await page.locator('section[aria-labelledby="catalog-installed"]').textContent(), /woowbk-demo\.json/);
      await page.locator('[data-focus="catalog-scan"]').click();
      await page.locator('.drafts').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'catalog-suggest')).at(-1)), { owner: 'appowner' });
      assert.deepEqual(await page.locator('.drafts > li').evaluateAll(items => items.map(item => [item.dataset.draft,
        [...item.querySelectorAll('.chip')].map(chipNode => chipNode.textContent).join('|')])),
      [['notes', '未安裝'], ['woowbk-demo', '已安裝・有 1 項差異']]);
      assert.match(await view(page).textContent(), /shared-proxy\.network/);
      assert.match(await view(page).textContent(), /tools\.kube/);
      await allWidths(page, 'catalog scan');
      await shot(page, 'catalog-scan-1440.png');
      await page.locator('[data-focus="draft-notes"]').click();
      await page.locator('#catalog-editor').waitFor();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'catalog-install').length === 1);
      await page.locator('#catalog-feedback').getByText('檢查通過：可以安裝這份應用設定。').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'catalog-install'))[0]), { entry: notesEntry('cold') }, 'the preview has no confirm');
      const [review] = await metadataOf(page.locator('#catalog-review'));
      assert.match(review['PostgreSQL'], /^冷備份（notes-db\.service）：資料庫與應用一起停止，資料檔隨資料卷 notes-pgdata整份備份/);
      assert.equal(review['服務（啟動順序）'], 'notes-db.service → notes-app.service');
      assert.match(await page.locator('section[aria-labelledby="draft-notes"]').textContent(), /目前的權限是 0755/);
      assert.match(await page.locator('section[aria-labelledby="draft-notes"]').textContent(), /~\/\.ssh/);
      assert(await page.locator('#catalog-feedback .diff-add').count() > 10, 'a new entry shows the lines it writes');
      await page.locator('[data-focus="variant-instance"]').check();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'catalog-install').length === 2);
      assert.deepEqual(requestOf((await calls(page, 'catalog-install')).at(-1)).entry.postgres, [notesEntry('instance').postgres[0]]);
      await page.locator('#catalog-feedback').getByText('檢查通過').waitFor();
      assert.match((await metadataOf(page.locator('#catalog-review')))[0]['PostgreSQL'], /^整個執行個體（notes-db）：備份時資料庫保持執行/);
      // Typing never rebuilds the editor; a JSON error is reported in the browser and never sent.
      const editor = await page.locator('#catalog-editor').elementHandle();
      const previews = (await calls(page, 'catalog-install')).length;
      const text = await page.locator('#catalog-editor').inputValue();
      await page.locator('#catalog-editor').fill(text.replace('"units": [', '"units": ['.slice(0, -1)));
      await page.locator('#catalog-parse').getByText(/JSON 格式錯誤：第 \d+ 行/).waitFor();
      assert.equal(await page.locator('[data-focus="catalog-install"]').isDisabled(), true);
      await page.waitForTimeout(1100);
      assert.equal((await calls(page, 'catalog-install')).length, previews, 'invalid JSON is not sent');
      await page.locator('#catalog-editor').fill(text.replace(/"units": \[[^\]]*\]/, '"units": []'));
      await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'catalog-install').length > count, previews);
      await page.locator('#catalog-feedback').getByText('欄位 units 至少需要一個服務。').waitFor();
      assert.match(await page.locator('#catalog-feedback').textContent(), /欄位：units/);
      assert.equal(await editor.evaluate(node => node.isConnected), true, 'the editor element survived the previews');
      await allWidths(page, 'draft with a validation error');
      await page.locator('#catalog-editor').fill(text.replace('"notes-files"', '"shared-volume"').replace('"notes-files"', '"shared-volume"'));
      await page.locator('#catalog-feedback').getByText('已屬於應用「other-app」').waitFor();
      await page.locator('[data-focus="catalog-revert"]').click();
      await page.locator('#catalog-feedback').getByText('檢查通過：可以安裝這份應用設定。').waitFor();
      await shot(page, 'catalog-draft-1440.png');
      await page.setViewportSize({ width: 390, height: 900 });
      await shot(page, 'catalog-draft-390.png');
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.locator('[data-focus="catalog-install"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.match(await page.locator('#confirm-title').textContent(), /安裝「notes」的應用設定/);
      assert.match(await page.locator('#confirm-body').textContent(), /沒有部署範本/);
      assert.equal(await page.locator('#confirm-ok').isDisabled(), true);
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      const install = (await calls(page, 'catalog-install')).map(requestOf).filter(request => request.confirm);
      assert.deepEqual(install, [{ entry: notesEntry('instance'), confirm: true, expected_sha256: null }]);
      await view(page).getByText('已安裝「notes」的應用設定').first().waitFor();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'catalog-suggest').length >= 3);
      // The rescan reports the installed entry, in the mode it was installed with.
      await page.locator('#catalog-feedback').getByText('內容與目前安裝的設定完全相同。').waitFor();
      assert.equal(await page.locator('[data-focus="variant-instance"]').isChecked(), true);
      assert.equal(await page.locator('[data-focus="catalog-install"]').isDisabled(), true, 'nothing to install');
      // The installed app is on the overview now; the demo app's installed entry can be replaced and removed.
      await page.locator('[data-focus="back-catalog"]').click();
      await page.locator('[data-focus="draft-woowbk-demo"]').click();
      await page.locator('#catalog-feedback').getByText('檢查通過：可以取代目前安裝的設定。').waitFor();
      assert.match(await page.locator('#catalog-feedback').textContent(), /與目前安裝的設定比較（1 項變更）/);
      assert.match(await page.locator('#catalog-feedback').textContent(), /新增的資料卷|verify/);
      assert.match(await page.locator('section[aria-labelledby="draft-summary"]').textContent(), /草稿多了內建資料核對/);
      await page.locator('[data-focus="catalog-remove"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'catalog-remove')).at(-1)), { id: 'woowbk-demo' }, 'a remove previews first');
      assert.match(await page.locator('#confirm-body').textContent(), /這個應用的備份2 份（會保留）/);
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.deepEqual(requestOf((await calls(page, 'catalog-remove')).at(-1)), { id: 'woowbk-demo', confirm: true, expected_sha256: INSTALLED_SHA });
      await view(page).getByText('已移除「woowbk-demo」的應用設定').first().waitFor();
      await page.locator('[data-nav="overview"]').click();
      await page.locator('.item-list').first().waitFor();
      const overview = await view(page).textContent();
      assert.match(overview, /notes/);
      assert(!/示範筆記應用：PostgreSQL/.test(overview), 'the removed app left the overview');
    });

  await check('應用設定 on an engine without catalog-suggest explains that this device cannot scan yet',
    fixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="catalog"]').click();
      await view(page).getByText('這台設備尚不支援應用設定掃描').waitFor();
      assert.equal((await calls(page, 'catalog-suggest')).length, 1);
    });

  const hostileStrengthen = fixture({ catalogData: catalogData(), scripts: { ...scripts(), restore: digestRollbackScript() } });
  const evilText = '<img src=x onerror="window.__xss=1"><b>bold</b>';
  const draft = hostileStrengthen.catalogData.scans.appowner.apps[0];
  draft.warnings.push({ code: 'environment-secret', level: 'warn', message: `${evilText}${'x'.repeat(300)}`, file: `${evilText}.container` });
  draft.hints.push(evilText);
  draft.entry.description = evilText;
  draft.variants.forEach(variant => { variant.label = `${evilText}${variant.label}`; variant.entry.volumes[0].label = evilText; });
  hostileStrengthen.scripts.restore.at(-1).job.result.verification[0].checks[1].differences.samples.push(
    { item: `${evilText}/${'deep/'.repeat(30)}`, change: 'missing', detail: evilText });
  hostileStrengthen.scripts.restore.at(-1).job.result.verification[0].checks[1].label = evilText;
  await check('hostile draft warnings, labels, diff lines and digest samples are rendered literally', hostileStrengthen, async page => {
    const noInjection = async label => {
      const found = await page.evaluate(() => ({ injected: document.querySelectorAll('body img, body script, body b').length, xss: Boolean(window.__xss) }));
      assert.deepEqual(found, { injected: 0, xss: false }, `${label}: no element created from data`);
    };
    await ready(page);
    await page.locator('[data-nav="catalog"]').click();
    await page.locator('[data-focus="catalog-scan"]').click();
    await page.locator('.drafts').waitFor();
    await noInjection('drafts');
    await page.locator('[data-focus="draft-notes"]').click();
    await page.locator('#catalog-feedback .diff').waitFor();
    assert.match(await page.locator('section[aria-labelledby="draft-notes"]').textContent(), /<img src=x/);
    assert.match(await page.locator('#catalog-feedback .diff').textContent(), /<b>bold<\/b>/);
    await noInjection('draft');
    await allWidths(page, 'hostile draft');
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '已自動回復' }).waitFor();
    await page.locator('details.app-details summary').filter({ hasText: '差異' }).click();
    assert.match(await page.locator('.differences').textContent(), /<img src=x/);
    await noInjection('digest samples');
    await allWidths(page, 'hostile digest samples');
  });

  const strengthenDark = retentionFixture({ catalogData: catalogData(), scripts: { ...scripts(), restore: digestRollbackScript() } });
  strengthenDark.status.settings.encrypt_by_default = false;
  strengthenDark.backups.push(backupMeta(B_PLAIN, { type: 'uploaded', encrypted: false, unauthenticated: true, key_id: null, key_available: true }));
  await check('dark theme: the new views keep WCAG AA contrast and fit every width', strengthenDark, async page => {
    await ready(page);
    const steady = () => page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
    const audit = async (label, extra = '') => {
      await steady();
      const result = await contrastOf(page, extra);
      assert(result.checked > 10, `${label}: enough text was checked (${result.checked})`);
      assert.deepEqual(result.failures, [], `${label}: dark-theme text keeps WCAG AA contrast`);
      await allWidths(page, `dark ${label}`);
    };
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark')), true);
    await page.locator('.usage-list').waitFor();
    await audit('overview with storage');
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    await page.locator(`[data-focus="download-menu-row-${B_MANUAL}"]`).click();
    await audit('backup list with an open menu', ', .menu-item-label');
    await page.keyboard.press('Escape');
    await page.locator('[data-nav="keys"]').click();
    await page.locator('#encrypt-default').waitFor();
    await audit('keys with the encryption setting off');
    await shot(page, 'keys-settings-dark-1440.png');
    await page.locator('#go-create').click();
    await page.locator('#encrypt-backup').waitFor();
    await audit('create without encryption');
    await page.evaluate(() => { window.location.hash = '#/cleanup'; });
    await page.locator('.usage-table').waitFor();
    await page.locator('#keep-woowbk-demo-mode').selectOption('last');
    await page.locator('[data-focus="cleanup-preview"]').click();
    await page.locator('section[aria-labelledby="cleanup-candidates"] .pick').first().waitFor();
    await audit('cleanup', ', .pick-reason, .keep-control span');
    await shot(page, 'cleanup-dark-1440.png');
    await page.locator('[data-nav="catalog"]').click();
    await page.locator('[data-focus="catalog-scan"]').click();
    await page.locator('.drafts').waitFor();
    await audit('catalog scan');
    await page.locator('[data-focus="draft-notes"]').click();
    await page.locator('#catalog-feedback .diff').waitFor();
    await audit('catalog draft', ', .diff span');
    await shot(page, 'catalog-draft-dark-1440.png');
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '已自動回復' }).waitFor();
    await page.locator('details.app-details summary').filter({ hasText: '差異' }).click();
    await audit('digest mismatch result', ', .check-name, .verify-summary');
    await shot(page, 'restore-digests-dark-1440.png');
  }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  const strengthenLight = retentionFixture({ catalogData: catalogData(), scripts: { ...scripts(), restore: digestRollbackScript() } });
  strengthenLight.status.settings.encrypt_by_default = false;
  await check('light theme and keyboard: the new views keep WCAG AA contrast, visible focus and every control reachable', strengthenLight, async page => {
    await ready(page);
    const audit = async (label, extra = '') => {
      const result = await contrastOf(page, extra);
      assert(result.checked > 10, `${label}: enough text was checked (${result.checked})`);
      assert.deepEqual(result.failures, [], `${label}: light-theme text keeps WCAG AA contrast`);
    };
    await page.locator('.usage-list').waitFor();
    await audit('overview with storage');
    const overview = await tabKeys(page, 'overview', 40);
    for (const key of ['nav-catalog', 'stat-cleanup', 'overview-cleanup']) assert(overview.includes(key), `overview: ${key} reachable (${overview})`);
    await page.locator('[data-nav="keys"]').click();
    await page.locator('#encrypt-default').waitFor();
    await audit('keys with the encryption setting off');
    assert((await tabKeys(page, 'keys', 14)).includes('encrypt-default'), 'the setting is reachable with Tab');
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    // The menu works from the keyboard alone: Enter opens it, Enter on an item runs it.
    await page.locator(`[data-focus="download-menu-row-${B_MANUAL}"]`).focus();
    await page.keyboard.press('Enter');
    await page.locator(`#menu-row-${B_MANUAL}`).waitFor();
    await audit('open download menu', ', .menu-item-label');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await page.locator('#confirm-dialog').waitFor();
    assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm-cancel', 'the dialog focuses the safe choice');
    await page.keyboard.press('Escape');
    await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
    assert.equal((await calls(page, 'export-start')).length, 0);
    await page.locator('[data-focus="list-cleanup"]').click();
    await page.locator('.usage-table').waitFor();
    await page.locator('#keep-woowbk-demo-mode').selectOption('last');
    await page.locator('[data-focus="cleanup-preview"]').click();
    await page.locator('section[aria-labelledby="cleanup-candidates"] .pick').first().waitFor();
    await audit('cleanup', ', .pick-reason, .keep-control span');
    const cleanupKeys = await tabKeys(page, 'cleanup', 30);
    for (const key of ['cleanup-refresh', 'keep-woowbk-demo-mode', 'keep-woowbk-demo-count', 'cleanup-preview']) {
      assert(cleanupKeys.includes(key), `cleanup: ${key} reachable (${cleanupKeys})`);
    }
    await page.locator('[data-nav="catalog"]').click();
    await page.locator('[data-focus="catalog-scan"]').click();
    await page.locator('.drafts').waitFor();
    await audit('catalog scan');
    await page.locator('[data-focus="draft-notes"]').click();
    await page.locator('#catalog-feedback .diff').waitFor();
    await audit('catalog draft', ', .diff span, .check-message');
    const draftKeys = await tabKeys(page, 'draft', 40);
    for (const key of ['variant-cold', 'catalog-editor']) assert(draftKeys.includes(key), `draft: ${key} reachable (${draftKeys})`);
    await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_MANUAL);
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '已自動回復' }).waitFor();
    await page.locator('details.app-details summary').filter({ hasText: '差異' }).click();
    await audit('digest mismatch result', ', .check-name, .verify-summary');
  });

  // ------------------------------------------------------------------ 排程備份 (2026.11.17.1)

  // Three scheduled backups of the demo app, made at 03:00 Taipei on 11-15, 11-16 and 11-17.
  const SCHED_IDS = ['20261114T190000Z-5c4ed001', '20261115T190000Z-5c4ed002', '20261116T190000Z-5c4ed003'];
  const PINNED = '失敗或中斷的還原使用這份備份；在該應用成功還原之前保留。';
  const SAVED_DAILY = { enabled: true, days: [...ALL_DAYS], time: '03:00', apps: 'all', include_images: false, keep_last: 3,
    updated: '2026-11-10T00:00:00Z', armed_at: '2026-11-10T00:00:00Z' };
  function scheduleFixture(extra = {}, schedule = {}) {
    const data = fixture(extra);
    data.backups.push(...SCHED_IDS.map((id, index) => backupMeta(id, { note: '排程備份', scheduled: true, size: (20 + index) * MiB })));
    data.schedule = scheduleData(schedule);
    return data;
  }
  // 立即執行一次 of a schedule that keeps 3: the demo app is backed up, the wiki (not deployed) is left out, and the oldest
  // scheduled backup goes (the schedule's keep-last after the run).
  function scheduledScript({ partial = true } = {}) {
    const steps = scripts().backup;
    Object.assign(steps.at(-1).job.result, { scheduled: true, slot: null, trigger: 'run-now', partial, retention_deleted: [SCHED_IDS[0]],
      skipped_apps: partial ? [{ id: 'woowbk-wiki', name: '團隊知識庫', reason: '應用「團隊知識庫」尚未部署在此設備，無法備份。' }] : [] });
    Object.assign(steps.at(-1).addBackup, { note: '排程備份', scheduled: true });
    steps.at(-1).removeBackups = [SCHED_IDS[0]];
    return steps;
  }
  const EVIL = '<img src=x onerror="window.__xss=1">';
  const SCHEDULE_EVENTS = [
    { at: '2026-11-17T02:30:00Z', kind: 'skipped', slot: '2026-11-16T19:00:00Z', local: '2026-11-17T03:00', first: '2026-11-16T19:00:00Z',
      first_local: '2026-11-17T03:00', count: 1, job_id: null, message: '2026-11-17 03:00 的排程備份沒有執行：當時有其他作業一直在進行。', not_run: true },
    { at: '2026-11-16T19:05:00Z', kind: 'waiting', slot: '2026-11-16T19:00:00Z', local: '2026-11-17T03:00', first: null, first_local: null,
      count: 1, job_id: J_OTHER, message: '2026-11-17 03:00 的排程備份等待其他作業完成後開始。', not_run: false },
    { at: '2026-11-15T19:05:00Z', kind: 'no-apps', slot: '2026-11-15T19:00:00Z', local: '2026-11-16T03:00', first: null, first_local: null,
      count: 1, job_id: null, message: `${EVIL}2026-11-16 03:00 的排程備份沒有執行：沒有可以備份的應用。`, not_run: true },
    { at: '2026-11-14T04:00:00Z', kind: 'missed', slot: '2026-11-13T19:00:00Z', local: '2026-11-14T03:00', first: '2026-11-11T19:00:00Z',
      first_local: '2026-11-12T03:00', count: 3, job_id: null,
      message: '2026-11-12 03:00 到 2026-11-14 03:00 共 3 次的排程備份沒有執行：設備當時沒有開機，或排程檢查沒有在執行。', not_run: true },
  ];

  await check('排程備份: overview card, the kit step before turning it on, the choices and a preview of the next runs and deletions before saving',
    scheduleFixture({ status: { ...fixture().status, key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: false } } },
      { protected: { [SCHED_IDS[0]]: PINNED } }), async page => {
      await ready(page);
      const card = page.locator('[data-stat="schedule"]');
      await card.waitFor();
      assert.equal(await card.textContent(), '排程備份已關閉開啟後，會在你選的時間自動備份應用。開啟排程備份');
      assert.equal(await page.locator('[data-focus="stat-schedule"]').getAttribute('href'), '#/schedule');
      assert.equal((await calls(page, 'schedule-get')).length, 0, 'the overview reads only the status');
      await page.locator('[data-focus="stat-schedule"]').click();
      await page.waitForFunction(() => window.location.hash === '#/schedule');
      await page.locator('#schedule-enabled').waitFor();
      assert.equal(await page.locator('#view-heading').textContent(), '排程備份');
      assert.equal(await page.locator('[data-nav="overview"]').getAttribute('aria-current'), 'page', 'under 總覽');
      assert.equal(await page.locator('.tabs a').count(), 6, 'no seventh tab');
      assert.equal((await calls(page, 'schedule-get')).length, 1);
      assert.equal(await page.locator('#schedule-time-hint').textContent(),
        '以這台設備的時間（Asia/Taipei，UTC+08:00）為準，會在這個時間後 5 分鐘內開始。備份時每個應用會暫停寫入約 10–90 秒。');
      assert.equal(await page.locator('#schedule-zone-hint').count(), 0, 'the browser keeps the device time');
      // The defaults: off, every day at 03:00, all apps, no images, keep the newest 7.
      assert.equal(await page.locator('#schedule-enabled').getAttribute('role'), 'switch');
      assert.equal(await page.locator('#schedule-enabled').isChecked(), false);
      assert.equal(await page.locator('#schedule-frequency-daily').isChecked(), true);
      assert.equal(await page.locator('fieldset.weekdays').count(), 0);
      assert.deepEqual([await page.locator('#schedule-hour').inputValue(), await page.locator('#schedule-minute').inputValue()], ['03', '00']);
      assert.deepEqual(await page.locator('#schedule-minute option').allTextContents(), ['00', '05', '10', '15', '20', '25', '30', '35', '40', '45', '50', '55']);
      assert.equal(await page.locator('#schedule-apps-all').isChecked(), true);
      assert.equal(await page.locator('label[for="schedule-apps-all"] strong').textContent(), '全部應用（之後新增的也會包含）');
      assert.equal(await page.locator('#schedule-images').isChecked(), false);
      assert.equal(await page.locator('#schedule-keep').inputValue(), '7');
      assert.match(await page.locator('#schedule-keep-help').textContent(), /手動備份、還原前自動備份與上傳的備份不會被刪除。$/);
      assert.match(await page.locator('.schedule-encryption').textContent(), /依「預設加密備份」（目前開啟）/);
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true, 'nothing saved yet');
      // On while the emergency kit is not confirmed: the kit step; nothing can be saved and the focus stays.
      await page.locator('#schedule-enabled').check();
      await page.locator('#schedule-kit-step').waitFor();
      assert.match(await page.locator('#schedule-kit-step').textContent(), /^開啟排程備份前，請先保存緊急金鑰。/);
      assert.equal(await page.locator('[data-focus="schedule-save"]').isDisabled(), true);
      assert.equal(await page.locator('#status').textContent(), '開啟排程備份前，請先保存緊急金鑰。', 'the kit step is announced');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'schedule-enabled');
      await allWidths(page, 'schedule kit step');
      await shot(page, 'schedule-kit-step-1440.png');
      assert.equal((await calls(page, 'schedule-set')).length, 0);
      await page.locator('[data-focus="schedule-kit-keys"]').click();
      await page.waitForFunction(() => window.location.hash === '#/keys');
      const back = page.locator('[data-focus="keys-back-schedule"]');
      await back.waitFor();
      assert.equal(await back.textContent(), '回到排程備份');
      assert.match(await view(page).textContent(), /開啟排程備份前，請先在下方顯示、下載並確認保存緊急金鑰。/);
      await page.locator('[data-focus="kit-show"]').click();
      await page.locator('#kit-confirm').check();
      await page.locator('[data-focus="kit-done"]').click();
      await view(page).getByText('緊急金鑰已保存，現在可以開啟排程備份。').waitFor();
      await back.click();
      await page.waitForFunction(() => window.location.hash === '#/schedule');
      await page.locator('#schedule-enabled').waitFor();
      assert.equal(await page.locator('#schedule-enabled').isChecked(), true, 'the choice made before the kit step is kept');
      assert.equal(await page.locator('#schedule-kit-step').count(), 0);
      assert.equal(await page.locator('[data-focus="keys-back-schedule"]').count(), 0);
      // Monday, Wednesday and Friday at 02:30; only the demo app; with images; keep 2.
      await page.locator('#schedule-frequency-weekly').check();
      assert.equal(await page.locator('fieldset.weekdays > legend').textContent(), '每週的哪幾天');
      for (const day of ['tue', 'thu', 'sat', 'sun']) await page.locator(`#schedule-day-${day}`).uncheck();
      await page.locator('#schedule-hour').selectOption('02');
      await page.locator('#schedule-minute').selectOption('30');
      await page.locator('#schedule-apps-some').check();
      assert.equal(await page.locator('#schedule-app-woowbk-demo').isChecked(), true, 'apps that can be backed up now start checked');
      assert.equal(await page.locator('#schedule-app-woowbk-wiki').isChecked(), false);
      assert.match(await page.locator('label[for="schedule-app-woowbk-wiki"]').textContent(), /會略過這個應用，結果標示「部分完成」/);
      await page.locator('#schedule-images').check();
      await page.locator('#schedule-keep').fill('0');
      assert.match(await page.locator('.schedule-hint').textContent(), /保留份數必須是 1 到 1000 的整數。/);
      assert.equal(await page.locator('[data-focus="schedule-save"]').isDisabled(), true);
      await page.locator('#schedule-keep').fill('2');
      await page.locator('#schedule-keep').press('Tab');
      assert.match(await page.locator('.form-title').textContent(), /尚未儲存/);
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true);
      // A reload of the saved settings (重新整理, the poll, the way back from 加密金鑰) keeps the edited draft.
      const reads = (await calls(page, 'schedule-get')).length;
      await page.locator('#refresh').click();
      await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'schedule-get').length > count, reads);
      await settled(page);
      assert.deepEqual(await page.evaluate(() => [...document.querySelectorAll('#view form input:checked')].map(input => input.id)),
        ['schedule-enabled', 'schedule-frequency-weekly', 'schedule-day-mon', 'schedule-day-wed', 'schedule-day-fri', 'schedule-apps-some',
          'schedule-app-woowbk-demo', 'schedule-images'], 'the edited choices are kept');
      assert.deepEqual([await page.locator('#schedule-hour').inputValue(), await page.locator('#schedule-minute').inputValue(),
        await page.locator('#schedule-keep').inputValue()], ['02', '30', '2']);
      assert.match(await page.locator('.form-title').textContent(), /尚未儲存/);
      await allWidths(page, 'schedule form');
      await shot(page, 'schedule-form-1440.png');
      await page.setViewportSize({ width: 320, height: 900 });
      await shot(page, 'schedule-form-320.png');
      await page.setViewportSize({ width: 1440, height: 900 });
      const expected = { enabled: true, days: ['mon', 'wed', 'fri'], time: '02:30', apps: ['woowbk-demo'], include_images: true, keep_last: 2 };
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.deepEqual((await calls(page, 'schedule-set')).map(requestOf), [{ schedule: expected }], 'a preview first, without confirm');
      assert.equal(await page.evaluate(() => window.__fixture.schedule.writes), 0, 'the preview writes nothing');
      assert.equal(await page.locator('#confirm-title').textContent(), '開啟排程備份？');
      const body = page.locator('#confirm-body');
      assert.deepEqual(await body.locator('ul[aria-label="接下來的排程"] li').allTextContents(),
        ['2026/11/18（週三）02:30', '2026/11/20（週五）02:30', '2026/11/23（週一）02:30']);
      assert.deepEqual(await body.locator('ul[aria-label="會刪除的排程備份"] li').allTextContents(),
        ['排程備份 · 2026/11/16 03:00 · 示範筆記應用 · 21.0 MiB超出排程備份的保留份數：「示範筆記應用」第 3 新（保留最新 2 份）']);
      assert.match(await body.textContent(), /會刪除下列 1 份較舊的排程備份（共 21\.0 MiB）：/);
      assert.deepEqual(await body.locator('ul[aria-label="暫時不會刪除的排程備份"] li').allTextContents(),
        [`排程備份 · 2026/11/15 03:00 · 示範筆記應用 · 20.0 MiB${PINNED}`]);
      const [summary] = await metadataOf(body);
      assert.deepEqual(summary, { 排程: '開啟', 日子與時間: '每週一、三、五 02:30（設備時間，Asia/Taipei，UTC+08:00）', 應用: '示範筆記應用',
        容器映像: '包含', 加密: '依「預設加密備份」加密', 保留: '每個應用保留最新 2 份排程備份' });
      assert.equal(await page.locator('#confirm-ok').isDisabled(), true, 'deletions need the acknowledgement');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm-cancel', 'the dialog focuses the safe choice');
      await allWidths(page, 'schedule preview dialog');
      await shot(page, 'schedule-preview-1440.png');
      await page.keyboard.press('Escape');
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.equal(await page.evaluate(() => document.activeElement.dataset.focus), 'schedule-save', 'the focus returns to 儲存排程…');
      assert.equal((await calls(page, 'schedule-set')).length, 1, 'closing the dialog writes nothing');
      assert.equal(await page.evaluate(() => window.__fixture.schedule.saved), false);
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.deepEqual((await calls(page, 'schedule-set')).map(requestOf).slice(1), [{ schedule: expected }, { schedule: expected, confirm: true }]);
      assert.equal(await page.evaluate(() => window.__fixture.schedule.writes), 1);
      const saved = '已儲存：排程備份會在每週一、三、五 02:30 自動執行，下一次在 2026/11/18（週三）02:30。';
      await view(page).getByText(saved).waitFor();
      assert.equal(await page.locator('#status').textContent(), saved);
      assert.match(await page.locator('.form-title').textContent(), /已儲存/);
      await enabled(page, '[data-focus="schedule-run-now"]');
      assert.deepEqual(await page.locator('section[aria-labelledby="schedule-state-heading"] ul[aria-label="接下來的排程"] li').allTextContents(),
        ['2026/11/18（週三）02:30', '2026/11/20（週五）02:30', '2026/11/23（週一）02:30']);
      await page.locator('[data-nav="overview"]').click();
      await page.locator('[data-stat="schedule"]').filter({ hasText: '已開啟' }).waitFor();
      assert.equal(await page.locator('[data-stat="schedule"]').textContent(),
        '排程備份已開啟每週一、三、五 02:30 · 1 個應用下次 2026/11/18（週三）02:30設定排程備份');
    });

  await check('排程備份: 立即執行一次 follows the job; a partial run is named in the result, the list, 清理備份 and 活動紀錄',
    (() => {
      const data = scheduleFixture({ scripts: { ...scripts(), backup: scheduledScript() } }, { settings: SAVED_DAILY, saved: true, events: SCHEDULE_EVENTS });
      data.retention = { saved: { schema: 1, default_keep_last: null, apps: {} }, problem: null, protected: {},
        usage: { apps: [{ id: 'woowbk-demo', name: '示範筆記應用', in_catalog: true, backups: 5, types: { manual: 1, safety: 1, uploaded: 0, scheduled: 3 },
          bytes: 157 * MiB, estimated: false, shared: false, newest: '2026-11-16T19:00:00Z', oldest: '2026-11-10T15:30:00Z', keep_last: null }],
        unassigned: { backups: 1, bytes: 48 * MiB }, total: { backups: 6, bytes: 205 * MiB } } };
      return data;
    })(), async page => {
      await ready(page);
      // Without engine figures the overview splits the list itself: the scheduled backups count apart.
      await page.locator('.usage-list').waitFor();
      assert.match(await page.locator('.usage-row').first().textContent(), /5 份備份（手動 1、排程 3、還原前 1）/);
      assert.match(await page.locator('[data-stat="schedule"]').textContent(), /已開啟每天 03:00 · 全部應用下次 2026\/11\/18（週三）03:00/);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      assert.match(await page.locator('.schedule-hint').textContent(), /「立即執行一次」會依已儲存的設定/);
      assert.equal(await page.locator('section[aria-labelledby="schedule-state-heading"] dd').nth(2).textContent(), '還沒有執行過');
      await page.locator('[data-focus="schedule-run-now"]').click();
      await page.waitForFunction(() => /^#\/jobs\/j\d{8}T\d{6}Z-[0-9a-f]{8}$/.test(window.location.hash));
      const [run] = (await calls(page, 'schedule-run-now')).map(requestOf);
      assert.deepEqual(Object.keys(run), ['request_id']);
      assert.match(run.request_id, UUID_RE);
      assert.equal(await page.locator('#view-heading').textContent(), '排程備份作業');
      await page.locator('#result-heading').filter({ hasText: '排程備份部分完成' }).waitFor();
      assert.equal(await page.locator('.job-state').textContent(), '部分完成');
      assert.equal(await page.locator('ul[aria-label="沒有包含的應用"] .check-message').textContent(), '「團隊知識庫」：應用「團隊知識庫」尚未部署在此設備，無法備份。');
      assert.match(await page.locator('.job-result').textContent(), new RegExp(`已依排程備份的保留份數刪除 1 份較舊的排程備份：${SCHED_IDS[0]}。`));
      const params = (await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0];
      assert.deepEqual([params['作業類型'], params['排程'], params['加密'], params['保留份數'], params['備註']],
        ['排程備份作業', '立即執行一次', '加密（依「預設加密備份」）', '每個應用保留最新 3 份排程備份', '排程備份']);
      await page.waitForFunction(() => document.querySelector('#status')?.textContent === '排程備份作業部分完成。');
      await allWidths(page, 'partial scheduled run');
      await shot(page, 'schedule-run-partial-1440.png');
      // The schedule page reads the last run from its job.
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('.last-run').waitFor();
      assert.match(await page.locator('.last-run').textContent(), /部分完成（立即執行一次）沒有包含「團隊知識庫」查看作業查看備份/);
      // 備份列表: the 排程 chip, title and filter; 手動 lists only the manual backups the schedule did not make.
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`tr[data-backup="${B_NEW}"]`).waitFor();
      assert.equal(await page.locator(`tr[data-backup="${B_NEW}"] td[data-label="類型"]`).textContent(), '排程');
      assert.match(await page.locator(`[data-focus="open-${B_NEW}"]`).getAttribute('aria-label'), /^查看 排程備份 · 2026\/11\/13 10:05 的詳細資料$/);
      assert.equal(await page.locator(`tr[data-backup="${SCHED_IDS[0]}"]`).count(), 0, 'the schedule kept 3');
      assert.deepEqual(await page.locator('.filter').allTextContents(), ['全部', '手動', '排程', '還原前備份', '上傳']);
      const shown = () => page.locator('.backups-table tbody tr').evaluateAll(rows => rows.map(row => row.dataset.backup));
      await page.locator('[data-focus="filter-scheduled"]').click();
      assert.deepEqual((await shown()).sort(), [B_NEW, SCHED_IDS[1], SCHED_IDS[2]].sort());
      await page.locator('[data-focus="filter-manual"]').click();
      assert.deepEqual(await shown(), [B_MANUAL]);
      await page.locator('[data-focus="filter-all"]').click();
      await page.locator('#backup-search').fill('排程');
      assert.deepEqual((await shown()).sort(), [B_NEW, SCHED_IDS[1], SCHED_IDS[2]].sort());
      await page.locator('#backup-search').fill('');
      await page.locator(`[data-focus="open-${B_NEW}"]`).click();
      await page.locator('section[aria-labelledby="detail-info"]').waitFor();
      assert.equal(await page.locator('#view-heading').textContent(), '排程備份 · 2026/11/13 10:05');
      assert.equal((await metadataOf(page.locator('section[aria-labelledby="detail-info"]')))[0]['類型'], '排程（由排程備份自動建立，依排程的保留份數清理）');
      // 清理備份: counts per type and the schedule's own keep-last.
      await page.evaluate(() => { window.location.hash = '#/cleanup'; });
      await page.locator('.usage-table').waitFor();
      assert.equal(await page.locator('.usage-table tbody td[data-label="備份"] .secondary').first().textContent(), '手動 1、排程 3、還原前 1');
      assert.equal(await page.locator('.schedule-keep-note').textContent(),
        '排程備份有自己的保留份數（目前每個應用保留最新 3 份），這裡的原則不會計算或刪除它們；要調整請到排程備份。');
      assert.equal(await page.locator('[data-focus="cleanup-schedule"]').getAttribute('href'), '#/schedule');
      await page.locator('[data-focus="cleanup-others-list"]').click();
      assert.equal(await page.locator(`[data-brief="${B_NEW}"] .chip`).first().textContent(), '排程');
      assert.match(await page.locator(`[data-brief="${B_NEW}"] .item-title`).textContent(), /^排程備份 · /);
      // 活動紀錄: the run as 排程備份 (部分完成) and, next to it, the slots that did not run (未執行), newest first.
      await page.locator('[data-nav="activity"]').click();
      await page.locator('.jobs-table').waitFor();
      const rows = await page.locator('.jobs-table tbody tr').evaluateAll(items => items.map(row => [row.dataset.event || 'job',
        ...[...row.children].map(cell => cell.textContent)]));
      assert.deepEqual(rows.map(row => row[0]), ['skipped', 'no-apps', 'missed', 'job'], 'not_run events only, sorted with the jobs');
      assert.deepEqual(rows[0].slice(1), ['2026/11/17 03:00排程時間', '排程備份', '未執行', '其他作業一直在進行', SCHEDULE_EVENTS[0].message]);
      assert.deepEqual(rows[2].slice(3, 5), ['未執行', '錯過的排程（共 3 次，從 2026/11/12 03:00 起）']);
      assert.equal(rows[1][5], SCHEDULE_EVENTS[2].message, 'event messages are text');
      assert.deepEqual(rows[3].slice(2, 6), ['排程備份', '部分完成', '示範筆記應用、團隊知識庫 · 立即執行一次', '部分完成：沒有包含「團隊知識庫」']);
      assert.deepEqual(await page.evaluate(() => ({ injected: document.querySelectorAll('#view img').length, xss: Boolean(window.__xss) })), { injected: 0, xss: false });
      await allWidths(page, 'activity with schedule events');
      await shot(page, 'activity-schedule-1440.png');
    });

  const ATTENTIONS = [
    { code: 'failed', message: '上次排程備份失敗：備份空間不足：預估需要 3.2 GiB，目前可用 1.1 GiB。應用未被暫停。', slot: '2026-11-16T19:00:00Z', job_id: J_OTHER },
    { code: 'failed', message: '上次排程備份失敗：2026-11-17 03:00 的排程備份沒有開始：無法啟動背景作業。', slot: '2026-11-16T19:00:00Z', job_id: null },
    { code: 'partial', message: '部分完成：上次排程備份沒有包含「團隊知識庫」。請查看作業結果了解原因。', slot: '2026-11-16T19:00:00Z', job_id: J_OTHER },
    { code: 'missed', message: '2026-11-15 03:00 到 2026-11-17 03:00 共 3 次的排程備份沒有執行：設備當時沒有開機，或排程檢查沒有在執行。',
      slot: '2026-11-16T19:00:00Z', reason: 'missed' },
    { code: 'skipped', message: '2026-11-17 03:00 的排程備份沒有執行：當時有其他作業一直在進行。', slot: '2026-11-16T19:00:00Z', reason: 'busy' },
    { code: 'skipped', message: '2026-11-17 03:00 的排程備份沒有執行：預設加密備份已開啟，但這台設備還沒有加密金鑰。', slot: '2026-11-16T19:00:00Z', reason: 'no-key' },
    { code: 'skipped', message: '2026-11-17 03:00 的排程備份沒有執行：沒有可以備份的應用。', slot: '2026-11-16T19:00:00Z', reason: 'no-apps' },
    { code: 'overdue', message: '排程備份已逾期：2026-11-17 03:00 的排程備份還沒有開始。', slot: '2026-11-16T19:00:00Z' },
    { code: 'timer-inactive', message: '排程檢查沒有在執行，排程備份不會自動開始。請重新執行備份元件的安裝程式來啟用它。' },
    { code: 'settings-problem', message: '排程備份設定檔 schedule.json 格式不正確，排程備份已暫停。請重新儲存排程設定。' },
  ];
  await check('排程備份 banners: every attention code as the engine words it, with the way to the schedule or the job; waiting is information',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      const banner = page.locator('#schedule-banner');
      assert.equal(await banner.isVisible(), false, 'nothing needs attention');
      for (const attention of ATTENTIONS) {
        await page.evaluate(item => { window.__fixture.schedule.attention = item; }, attention);
        await page.locator('#refresh').click();
        await page.waitForFunction(text => document.querySelector('#schedule-banner:not([hidden]) p')?.textContent.endsWith(text), attention.message);
        const label = `${attention.code}${attention.reason ? `/${attention.reason}` : ''}${attention.job_id === null ? '/no job' : ''}`;
        assert.equal(await banner.locator('p').textContent(), `排程備份 · ${attention.message}`, label);
        assert.equal(await banner.getAttribute('data-code'), attention.code, label);
        assert.match(await banner.getAttribute('class'), attention.code === 'failed' ? /notice-error/ : /notice-warn/, label);
        assert.equal(await banner.locator('[data-focus="banner-schedule"]').getAttribute('href'), '#/schedule', label);
        const job = banner.locator('[data-focus="banner-schedule-job"]');
        assert.equal(await job.count(), attention.job_id ? 1 : 0, label);
        if (attention.job_id) assert.equal(await job.getAttribute('href'), `#/jobs/${attention.job_id}`, label);
      }
      await allWidths(page, 'overview with a schedule banner');
      // On the schedule page the banner stays, without the link to itself; the problem is not said twice.
      await page.evaluate(() => { window.__fixture.schedule.problem = window.__fixture.schedule.attention.message; });
      await page.locator('[data-focus="banner-schedule"]').click();
      await page.waitForFunction(() => window.location.hash === '#/schedule');
      await page.locator('#schedule-state-heading').waitFor();
      assert.equal(await banner.isVisible(), true);
      assert.equal(await banner.locator('[data-focus="banner-schedule"]').count(), 0);
      assert.equal(await page.locator('section[aria-labelledby="schedule-state-heading"] .chip').textContent(), '已暫停');
      assert.equal(await view(page).getByText(ATTENTIONS.at(-1).message).count(), 0, 'the banner says it once');
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true, 'a paused schedule is not run');
      // A slot waiting for another job is information, not a problem.
      await page.evaluate(job => Object.assign(window.__fixture.schedule, { attention: null, problem: null,
        waiting: { slot: '2026-11-16T19:00:00Z', local: '2026-11-17T03:00', since: '2026-11-16T19:00:40Z', job_id: job } }), J_OTHER);
      await page.locator('#refresh').click();
      await banner.waitFor({ state: 'hidden' });
      await view(page).getByText('2026/11/17（週二）03:00 的排程備份正在等其他作業完成，會在它結束後 5 分鐘內開始。').waitFor();
      assert.match(await view(page).textContent(), /有其他作業進行中時，會在它結束後 5 分鐘內開始。/);
      assert.equal(await page.locator('section[aria-labelledby="schedule-state-heading"] p.muted').textContent(),
        '每一次排程備份與沒有執行的排程，都記錄在活動紀錄。');
      assert.equal(await page.locator('[data-focus="schedule-waiting-job"]').getAttribute('href'), `#/jobs/${J_OTHER}`);
      await page.locator('[data-nav="overview"]').click();
      await page.locator('[data-stat="schedule"]').filter({ hasText: '等其他作業完成後開始' }).waitFor();
      assert.equal(await banner.isVisible(), false);
    });

  await check('an engine without 排程備份 says 這台設備的備份元件不支援排程 and is never sent the commands', fixture({ schedule: null }), async page => {
    await ready(page);
    assert.equal(await page.locator('[data-stat="schedule"]').textContent(), '排程備份不支援這台設備的備份元件不支援排程。查看說明');
    await page.locator('[data-focus="stat-schedule"]').click();
    await view(page).getByRole('heading', { name: '這台設備的備份元件不支援排程' }).waitFor();
    assert.match(await view(page).textContent(), /請將備份元件更新到與這個頁面相同的版本後再試。/);
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    assert.deepEqual(await page.locator('.filter').allTextContents(), ['全部', '手動', '還原前備份', '上傳'], 'no 排程 filter');
    await page.locator('[data-focus="list-schedule"]').click();
    await view(page).getByRole('heading', { name: '這台設備的備份元件不支援排程' }).waitFor();
    await page.locator('[data-nav="activity"]').click();
    await page.locator('.empty-state').waitFor();
    assert.deepEqual((await page.evaluate(() => window.testcalls.map(call => call.argv[1]))).filter(name => name.startsWith('schedule-')), []);
    await allWidths(page, 'schedule unsupported');
  });

  await check('an engine that refuses schedule-get as unknown gets the same notice', fixture({
    failures: [{ command: 'schedule-get', code: 'invalid-request', message: '不支援的指令。' }],
  }), async page => {
    await ready(page);
    await page.evaluate(() => { window.location.hash = '#/schedule'; });
    await view(page).getByRole('heading', { name: '這台設備的備份元件不支援排程' }).waitFor();
    assert.equal((await calls(page, 'schedule-get')).length, 1);
  });

  await check('a device in another time zone: the hint says both times; a saved app the device no longer has is named and refused',
    scheduleFixture({}, { settings: { ...SAVED_DAILY, apps: ['woowbk-demo', 'old-app'], keep_last: 7 }, saved: true,
      timezone: { name: 'America/New_York', utc_offset: '-05:00' } }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-zone-hint').waitFor();
      assert.equal(await page.locator('#schedule-zone-hint').textContent(),
        '你目前使用的電腦時區（Asia/Taipei，UTC+08:00）和這台設備不同，排程時間一律以設備的時間為準。例如下一次排程在設備時間 2026/11/18（週三）03:00，也就是你這裡的 2026/11/18 16:00。');
      assert.match(await page.locator('#schedule-time-hint').textContent(), /^以這台設備的時間（America\/New_York，UTC-05:00）為準/);
      const [state] = await metadataOf(page.locator('section[aria-labelledby="schedule-state-heading"]'));
      assert.equal(state['設備時區'], 'America/New_York，UTC-05:00');
      assert.equal(state['排程'], '每天 03:00 · 示範筆記應用、old-app');
      assert.equal(state['排程檢查'], '正常，2 分鐘前檢查過（每 5 分鐘一次）');
      assert.equal(await page.locator('#schedule-apps-some').isChecked(), true);
      assert.equal(await page.locator('#schedule-app-old-app').isChecked(), true);
      assert.match(await page.locator('label[for="schedule-app-old-app"]').textContent(), /這台設備已沒有這個應用的設定；請取消勾選後再儲存。/);
      // The engine refuses the unknown app; nothing opens and nothing is written.
      await page.locator('[data-focus="schedule-save"]').click();
      await view(page).getByText('此設備沒有設定應用 old-app，無法處理。').waitFor();
      assert.equal(await page.locator('#confirm-dialog').isVisible(), false);
      await page.locator('#schedule-app-old-app').uncheck();
      assert.match(await page.locator('.schedule-hint').textContent(), /有尚未儲存的變更。「立即執行一次」只會使用已儲存的設定，請先儲存。/);
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true, 'unsaved changes are saved first');
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '儲存排程備份？');
      assert.equal(await page.locator('#confirm-ack').count(), 0, 'no deletions, no acknowledgement');
      assert.match(await page.locator('#confirm-body').textContent(), /下一次排程備份成功後不會刪除任何備份。/);
      assert.deepEqual(await page.locator('#confirm-body ul[aria-label="接下來的排程"] li').allTextContents(),
        ['2026/11/18（週三）03:00', '2026/11/19（週四）03:00', '2026/11/20（週五）03:00']);
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.deepEqual(requestOf((await calls(page, 'schedule-set')).at(-1)),
        { schedule: { enabled: true, days: ALL_DAYS, time: '03:00', apps: ['woowbk-demo'], include_images: false, keep_last: 7 }, confirm: true });
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      await allWidths(page, 'schedule in another time zone');
    });

  await check('a device without a key: the kit step creates one first; an engine refusal shows the kit step again',
    scheduleFixture({ status: { ...fixture().status, key: null } }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-enabled').check();
      await page.locator('#schedule-kit-step').waitFor();
      assert.match(await page.locator('#schedule-kit-step').textContent(), /^開啟排程備份前，請先建立加密金鑰並保存緊急金鑰。/);
      assert.match(await page.locator('.schedule-hint').textContent(), /請先完成上方的緊急金鑰步驟/);
      await page.locator('[data-focus="schedule-kit-keys"]').click();
      await page.locator('[data-focus="keys-back-schedule"]').waitFor();
      assert.match(await view(page).textContent(), /開啟排程備份前，請先在下方建立加密金鑰，並下載、確認保存緊急金鑰。/);
      await page.locator('[data-focus="key-create"]').click();
      await page.locator('#kit-confirm').check();
      await page.locator('[data-focus="kit-done"]').click();
      await view(page).getByText('緊急金鑰已保存，現在可以開啟排程備份。').waitFor();
      await page.locator('[data-focus="keys-back-schedule"]').click();
      await page.locator('#schedule-enabled').waitFor();
      assert.equal(await page.locator('#schedule-kit-step').count(), 0);
      // The engine decides: a refusal that asks for the kit first shows the kit step and opens no dialog.
      await page.evaluate(() => window.__fixture.failures.push({ command: 'schedule-set', code: 'invalid-request', message: '開啟排程備份前，請先保存緊急金鑰。',
        details: { reason: 'kit-unconfirmed', field: 'schedule.enabled' } }));
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#schedule-kit-step').waitFor();
      assert.equal(await page.locator('#confirm-dialog').isVisible(), false);
      assert.equal(await page.locator('#status').textContent(), '開啟排程備份前，請先保存緊急金鑰。');
      // Turning it off again is never gated.
      await page.locator('#schedule-enabled').uncheck();
      assert.equal(await page.locator('#schedule-kit-step').count(), 0);
      assert.equal(await page.locator('[data-focus="schedule-save"]').isDisabled(), false);
    });

  const scheduleDark = scheduleFixture({ status: { ...fixture().status, key: { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: false } },
    scripts: { ...scripts(), backup: scheduledScript() } },
  { settings: { ...SAVED_DAILY, days: ['mon', 'wed', 'fri'], apps: ['woowbk-demo'] }, saved: true, events: SCHEDULE_EVENTS,
    attention: ATTENTIONS[2], waiting: { slot: '2026-11-16T19:00:00Z', local: '2026-11-17T03:00', since: '2026-11-16T19:00:40Z', job_id: J_OTHER },
    last_run: { slot: '2026-11-15T19:00:00Z', local: '2026-11-16T03:00', job_id: J_OTHER, trigger: 'catch-up', state: 'succeeded', result: 'partial',
      backup_id: SCHED_IDS[1], started: '2026-11-16T02:10:00Z', finished: '2026-11-16T02:12:00Z',
      skipped_apps: [{ id: 'woowbk-wiki', name: '團隊知識庫', reason: '尚未部署' }], error: null } });
  await check('排程備份 in the dark theme: card, banner, form, kit step, dialog, list and activity keep WCAG AA contrast and fit every width', scheduleDark, async page => {
    await ready(page);
    const steady = () => page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
    const audit = async (label, extra = '') => {
      await steady();
      const result = await contrastOf(page, extra);
      assert(result.checked > 10, `${label}: enough text was checked (${result.checked})`);
      assert.deepEqual(result.failures, [], `${label}: dark-theme text keeps WCAG AA contrast`);
      await allWidths(page, `dark ${label}`);
    };
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark')), true);
    await page.locator('#schedule-banner:not([hidden])').waitFor();
    await audit('overview with the schedule card and banner', ', #schedule-banner strong');
    await shot(page, 'schedule-overview-dark-1440.png');
    await page.locator('[data-focus="banner-schedule"]').click();
    await page.locator('#schedule-kit-step').waitFor();
    assert.match(await page.locator('.last-run').textContent(), /^2026\/11\/16（週一）03:00 · 部分完成（補做錯過的排程）/);
    await audit('schedule page with the kit step', ', .weekday span, .schedule-hint, .last-run .secondary');
    await shot(page, 'schedule-dark-1440.png');
    await page.locator('#schedule-enabled').uncheck();
    await page.locator('[data-focus="schedule-save"]').click();
    await page.locator('#confirm-dialog').waitFor();
    assert.equal(await page.locator('#confirm-title').textContent(), '關閉排程備份？');
    await audit('schedule dialog', ', #confirm-body .secondary');
    await page.locator('#confirm-cancel').click();
    await page.locator('[data-nav="backups"]').click();
    await page.locator('.backups-table').waitFor();
    await audit('backup list with scheduled backups');
    await page.locator('[data-nav="activity"]').click();
    await page.locator('tr[data-event="missed"]').waitFor();
    await audit('activity with schedule events');
  }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  await check('排程備份 with the keyboard in the light theme: visible focus, every control reachable, the switch, the radios and the dialog',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      await page.locator('[data-focus="stat-schedule"]').focus();
      await page.keyboard.press('Enter');
      await page.locator('#schedule-enabled').waitFor();
      const result = await contrastOf(page, ', .weekday span, .schedule-hint');
      assert(result.checked > 10 && !result.failures.length, `light schedule contrast ${JSON.stringify(result)}`);
      const keys = await tabKeys(page, 'schedule', 40);
      for (const key of ['schedule-enabled', 'schedule-daily', 'schedule-hour', 'schedule-minute', 'schedule-apps-all', 'schedule-images',
        'schedule-encryption-settings', 'schedule-keep-mode', 'schedule-keep', 'schedule-run-now', 'schedule-save']) {
        assert(keys.includes(key), `schedule: ${key} reachable (${keys})`);
      }
      // Space toggles the switch; the arrow keys move within the radio group and show the weekdays.
      await page.locator('#schedule-enabled').focus();
      await page.keyboard.press('Space');
      assert.equal(await page.locator('#schedule-enabled').isChecked(), false);
      assert.equal(await page.evaluate(() => document.activeElement.id), 'schedule-enabled', 'the focus stays on the switch');
      await page.keyboard.press('Space');
      assert.equal(await page.locator('#schedule-enabled').isChecked(), true);
      await page.locator('#schedule-frequency-daily').focus();
      await page.keyboard.press('ArrowDown');
      await page.locator('fieldset.weekdays').waitFor();
      assert.equal(await page.evaluate(() => document.activeElement.id), 'schedule-frequency-weekly');
      const dayKeys = await tabKeys(page, 'weekdays', 40);
      for (const day of ALL_DAYS) assert(dayKeys.includes(`schedule-day-${day}`), `weekday ${day} reachable (${dayKeys})`);
      await page.locator('#schedule-day-sun').focus();
      await page.keyboard.press('Space');
      assert.equal(await page.locator('#schedule-day-sun').isChecked(), false);
      await page.locator('#schedule-day-mon').focus();
      await page.keyboard.press('Space');
      await page.keyboard.press('Space');
      assert.equal(await page.locator('#schedule-day-mon').isChecked(), true, 'Monday ticked again, after the others');
      await page.locator('[data-focus="schedule-save"]').focus();
      await page.keyboard.press('Enter');
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm-cancel');
      assert.deepEqual(requestOf((await calls(page, 'schedule-set')).at(-1)).schedule.days, ['mon', 'tue', 'wed', 'thu', 'fri', 'sat']);
      const dialog = await contrastOf(page, ', #confirm-body .secondary');
      assert(!dialog.failures.length, `light dialog contrast ${dialog.failures}`);
      await page.keyboard.press('Escape');
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.equal(await page.evaluate(() => document.activeElement.dataset.focus), 'schedule-save');
      assert.equal(await page.evaluate(() => window.__fixture.schedule.writes), 0);
    });

  // ------------------------------------------------------------------ 排程備份 review (2026-11-17)

  // A device in New York (UTC-05:00) and the administrator's browser in Taipei (UTC+08:00): 03:00 there is 16:00 here.
  const NY_SLOT = '2026-11-17T08:00:00Z';
  const NY_JOB = 'j20261117T080010Z-0000a001';
  const NY_RUN = 'j20261117T093000Z-0000a002';
  const nyJob = (id, schedule, created, finished) => ({ id, type: 'backup', state: 'succeeded', phase: 'verify', phases: phasesAt('backup', null),
    progress: { percent: 100, message: '已完成' }, created, started: created, finished,
    params: { apps: ['woowbk-demo'], include_images: false, note: '排程備份', encrypt: true, schedule },
    result: { backup_id: SCHED_IDS[2], size: 22 * MiB, apps: ['woowbk-demo'], downtime_seconds: 7, unavailable_seconds: 9, encrypted: true, timing: [],
      scheduled: true, slot: schedule.slot, trigger: schedule.trigger, partial: false, skipped_apps: [], retention_deleted: [] },
    error: null, cancellable: false });
  const NY_EVENTS = [
    { at: '2026-11-16T08:05:00Z', kind: 'no-key', slot: '2026-11-16T08:00:00Z', local: '2026-11-16T03:00', first: null, first_local: null, count: 1,
      job_id: null, message: '2026-11-16 03:00 的排程備份沒有執行：預設加密備份已開啟，但這台設備還沒有加密金鑰。', not_run: true },
    // Without the device's texts (an engine that sends none): the page converts the slots with the device's zone.
    { at: '2026-11-15T12:00:00Z', kind: 'missed', slot: '2026-11-15T08:00:00Z', first: '2026-11-13T08:00:00Z', count: 3, job_id: null,
      message: '2026-11-13 03:00 到 2026-11-15 03:00 共 3 次的排程備份沒有執行：設備當時沒有開機，或排程檢查沒有在執行。', not_run: true },
  ];
  const nyFixture = scheduleFixture({ jobs: {
    [NY_JOB]: { job: nyJob(NY_JOB, { slot: NY_SLOT, trigger: 'on-time', keep_last: 3 }, '2026-11-17T08:00:10Z', '2026-11-17T08:03:00Z'), log: [], steps: [] },
    [NY_RUN]: { job: nyJob(NY_RUN, { slot: null, trigger: 'run-now', keep_last: 3 }, '2026-11-17T09:30:00Z', '2026-11-17T09:33:00Z'), log: [], steps: [] },
  } }, { settings: SAVED_DAILY, saved: true, events: NY_EVENTS, timezone: { name: 'America/New_York', utc_offset: '-05:00' },
    last_run: { slot: null, local: null, job_id: NY_RUN, trigger: 'run-now', state: 'succeeded', result: 'succeeded', backup_id: SCHED_IDS[2],
      started: '2026-11-17T09:30:00Z', started_local: '2026-11-17T04:30', finished: '2026-11-17T09:33:00Z', finished_local: '2026-11-17T04:33',
      skipped_apps: [], error: null } });
  // The page trusts the zone's name only while it keeps the engine's offset now, so the browser's clock is the
  // fixture's (New York keeps -05:00 then, whatever the date of the test run).
  await check('schedule times are the device\'s on the overview card, the schedule card, 活動紀錄 and the job view when the browser keeps another time',
    nyFixture, async page => {
      await ready(page);
      // 上次 is the device's time like 下次 (立即執行一次: when it started, 04:30 in New York, not 17:30 in Taipei).
      await page.locator('[data-stat="schedule"]').filter({ hasText: '上次' }).waitFor();
      assert.equal(await page.locator('[data-stat="schedule"]').textContent(),
        '排程備份已開啟每天 03:00 · 全部應用下次 2026/11/18（週三）03:00上次 2026/11/17（週二）04:30 · 已完成設定排程備份');
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('.last-run').waitFor();
      assert.match(await page.locator('.last-run').textContent(), /^2026\/11\/17（週二）04:30 · 已完成（立即執行一次）/);
      // 活動紀錄: the jobs in this computer's time, the slots that did not run in the device's, marked as such.
      await page.locator('[data-nav="activity"]').click();
      await page.locator('tr[data-event="missed"]').waitFor();
      const rows = () => page.locator('.jobs-table tbody tr').evaluateAll(items => items.map(row => [row.dataset.event || row.dataset.job,
        ...[...row.children].map(cell => cell.textContent)]));
      const shown = await rows();
      assert.deepEqual(shown.map(row => row[0]), [NY_RUN, NY_JOB, 'no-key', 'missed']);
      assert.equal(shown[1][1], `2026/11/17 16:00${NY_JOB}`, 'a job keeps this computer\'s time');
      assert.deepEqual(shown[2].slice(1, 5), ['2026/11/16 03:00排程時間（設備時間）', '排程備份', '未執行', '沒有加密金鑰']);
      assert.deepEqual(shown[3].slice(1, 5), ['2026/11/15 03:00排程時間（設備時間）', '排程備份', '未執行', '錯過的排程（共 3 次，從 2026/11/13 03:00 起）']);
      await allWidths(page, 'activity with device times');
      await shot(page, 'activity-device-time-1440.png');
      // The job view: the slot of a scheduled job in the device's time (its record has no local text).
      await page.locator(`[data-focus="job-${NY_JOB}"]`).click();
      await page.locator('section[aria-labelledby="job-params-heading"]').waitFor();
      const params = async () => (await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0]['排程'];
      assert.equal(await params(), '依排程（排程時間 2026/11/17（週二）03:00，設備時間）');
      await shot(page, 'job-device-time-1440.png');
      // A zone this page cannot name (no IANA name): the computer's time, said so; the engine's texts stay the device's.
      await page.evaluate(() => { window.__fixture.schedule.timezone = { name: 'localtime', utc_offset: '-05:00' }; });
      const reads = (await calls(page, 'status')).length;
      await page.locator('#refresh').click();
      await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'status').length > count, reads);
      await settled(page);
      await page.locator('[data-nav="activity"]').click();
      await page.locator('tr[data-event="missed"]').waitFor();
      const after = await rows();
      assert.equal(after[2][1], '2026/11/16 03:00排程時間（設備時間）', 'the engine\'s local text');
      assert.equal(after[3][1], '2026/11/15 16:00排程時間（你電腦上的時間）');
      assert.equal(after[3][4], '錯過的排程（共 3 次，從 2026/11/13 16:00 起）');
      await page.locator(`[data-focus="job-${NY_JOB}"]`).click();
      await page.locator('section[aria-labelledby="job-params-heading"]').waitFor();
      assert.equal(await params(), '依排程（排程時間 2026/11/17（週二）16:00，你電腦上的時間）');
      await page.locator('[data-nav="overview"]').click();
      assert.match(await page.locator('[data-stat="schedule"]').textContent(), /上次 2026\/11\/17（週二）04:30 · 已完成/);
    }, { beforeGoto: page => page.clock.setFixedTime(new Date(SCHEDULE_NOW)) });

  await check('a device in the browser\'s zone: no 設備時間 marks, the same times as before',
    scheduleFixture({ jobs: { [NY_JOB]: { job: nyJob(NY_JOB, { slot: '2026-11-16T19:00:00Z', trigger: 'catch-up', keep_last: 3 }, '2026-11-16T19:20:00Z',
      '2026-11-16T19:23:00Z'), log: [], steps: [] } } }, { settings: SAVED_DAILY, saved: true, events: SCHEDULE_EVENTS }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/activity'; });
      await page.locator('tr[data-event="missed"]').waitFor();
      assert.equal(await page.locator('tr[data-event="missed"] th').textContent(), '2026/11/14 03:00排程時間');
      await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, NY_JOB);
      await page.locator('section[aria-labelledby="job-params-heading"]').waitFor();
      assert.equal((await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0]['排程'], '補做錯過的排程（排程時間 2026/11/17（週二）03:00）');
    });

  await check('turning 排程備份 off needs no deletion checkbox and saves it off; saving again while off says it stays off',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-enabled').waitFor();
      await page.locator('#schedule-enabled').uncheck();
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '關閉排程備份？');
      const body = page.locator('#confirm-body');
      assert.equal(await body.locator('p').first().textContent(), '排程會關閉，之後不會再自動建立或刪除備份；已建立的排程備份會保留。');
      assert.equal(await body.getByText('下一次排程備份成功後').count(), 0, 'nothing runs by itself, so nothing is listed for deletion');
      assert.equal(await body.locator('ul[aria-label="會刪除的排程備份"]').count(), 0);
      assert.equal(await body.locator('.schedule-run-now-note').textContent(),
        '之後仍可以按「立即執行一次」；它完成後才會依保留份數刪除較舊的排程備份（以目前的備份來說是 1 份，共 20.0 MiB）。');
      assert.equal(await page.locator('#confirm-ack').count(), 0, 'no acknowledgement to turn it off');
      assert.equal(await page.locator('#confirm-ok').isDisabled(), false);
      assert.equal(await page.locator('#confirm-ok').textContent(), '關閉排程備份');
      await allWidths(page, 'turning the schedule off');
      await shot(page, 'schedule-off-dialog-1440.png');
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      const off = { enabled: false, days: ALL_DAYS, time: '03:00', apps: 'all', include_images: false, keep_last: 3 };
      assert.deepEqual((await calls(page, 'schedule-set')).map(requestOf), [{ schedule: off }, { schedule: off, confirm: true }]);
      assert.deepEqual(await page.evaluate(() => [window.__fixture.schedule.settings.enabled, window.__fixture.schedule.writes]), [false, 1]);
      const notice = '已儲存：排程備份已關閉，不會再自動建立備份。';
      await view(page).getByText(notice).waitFor();
      assert.equal(await page.locator('#status').textContent(), notice);
      assert.equal(await page.locator('#schedule-enabled').isChecked(), false);
      assert.equal(await page.locator('section[aria-labelledby="schedule-state-heading"] .chip').textContent(), '已關閉');
      // Saved again while off (another time): it stays off and nothing is asked about deletions.
      await page.locator('#schedule-hour').selectOption('04');
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '儲存排程備份？');
      assert.equal(await body.locator('p').first().textContent(), '排程維持關閉，不會自動建立或刪除備份。儲存本身不會建立或刪除任何備份。');
      assert.equal(await page.locator('#confirm-ack').count(), 0);
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.deepEqual(requestOf((await calls(page, 'schedule-set')).at(-1)), { schedule: { ...off, time: '04:00' }, confirm: true });
      await page.locator('[data-nav="overview"]').click();
      await page.locator('[data-stat="schedule"]').filter({ hasText: '已關閉' }).waitFor();
    });

  await check('全部保留 saves keep_last null: the dialog lists no deletions and the form keeps 全部保留',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-keep-mode').waitFor();
      await page.locator('#schedule-keep-mode').selectOption('all');
      assert.equal(await page.locator('#schedule-keep').count(), 0);
      assert.match(await page.locator('#schedule-keep-help').textContent(), /^保留所有排程備份，不會自動刪除/);
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal((await metadataOf(page.locator('#confirm-body')))[0]['保留'], '保留全部排程備份');
      assert.match(await page.locator('#confirm-body').textContent(), /下一次排程備份成功後保留全部排程備份，不會自動刪除。/);
      assert.equal(await page.locator('#confirm-ack').count(), 0);
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      const all = { enabled: true, days: ALL_DAYS, time: '03:00', apps: 'all', include_images: false, keep_last: null };
      assert.deepEqual((await calls(page, 'schedule-set')).map(requestOf), [{ schedule: all }, { schedule: all, confirm: true }]);
      assert.equal(await page.evaluate(() => window.__fixture.schedule.settings.keep_last), null);
      await page.locator('.form-title').filter({ hasText: '已儲存' }).waitFor();
      assert.equal(await page.locator('#schedule-keep-mode').inputValue(), 'all');
    });

  await check('an engine refusal for a missing device key shows the kit step that creates the key and opens no dialog', scheduleFixture(), async page => {
    await ready(page);
    await page.evaluate(() => { window.location.hash = '#/schedule'; });
    await page.locator('#schedule-enabled').check();
    assert.equal(await page.locator('#schedule-kit-step').count(), 0, 'this page saw a key and a saved kit');
    const refusal = '開啟排程備份前，請先到「加密金鑰」建立這台設備的加密金鑰，並保存緊急金鑰。';
    await page.evaluate(message => window.__fixture.failures.push({ command: 'schedule-set', code: 'no-device-key', message }), refusal);
    await page.locator('[data-focus="schedule-save"]').click();
    await page.locator('#schedule-kit-step').waitFor();
    assert.match(await page.locator('#schedule-kit-step').textContent(), /^開啟排程備份前，請先建立加密金鑰並保存緊急金鑰。/);
    assert.equal(await page.locator('#confirm-dialog').isVisible(), false);
    assert.equal(await view(page).locator('.notice-error').count(), 0, 'the kit step, not an error');
    assert.equal(await page.locator('#status').textContent(), refusal);
    assert.equal(await page.locator('[data-focus="schedule-save"]').isDisabled(), true);
    assert.equal((await calls(page, 'schedule-set')).length, 1);
  });

  await check('立即執行一次: an error is shown, a retry sends the same request id and the next run a new one',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      const run = page.locator('[data-focus="schedule-run-now"]');
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      const failure = '無法啟動背景作業：systemd-run 沒有回應。';
      await page.evaluate(message => window.__fixture.failures.push({ command: 'schedule-run-now', code: 'internal-error', message }), failure);
      await run.click();
      await view(page).locator('.notice-error').filter({ hasText: failure }).waitFor();
      assert.equal(await page.evaluate(() => window.location.hash), '#/schedule');
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      await run.click();
      await page.waitForFunction(() => /^#\/jobs\/j/.test(window.location.hash));
      const [first, retry] = (await calls(page, 'schedule-run-now')).map(requestOf).map(item => item.request_id);
      assert.match(first, UUID_RE);
      assert.equal(retry, first, 'a retry may find the job the first request started');
      await page.locator('#result-heading').waitFor();
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      assert.equal(await view(page).locator('.notice-error').count(), 0, 'the old error is gone');
      await page.locator('[data-focus="schedule-run-now"]').click();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'schedule-run-now').length === 3);
      const third = requestOf((await calls(page, 'schedule-run-now'))[2]).request_id;
      assert.match(third, UUID_RE);
      assert.notEqual(third, first, 'a new run is a new request');
    });

  await check('立即執行一次 needs this device\'s key while 預設加密備份 is on; an unencrypted run needs none',
    scheduleFixture({ status: { ...fixture().status, key: null } }, { settings: { ...SAVED_DAILY, enabled: false }, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-state-heading').waitFor();
      await settled(page);
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true);
      assert.equal(await page.locator('.schedule-hint').textContent(), '加密的排程備份需要這台設備的加密金鑰，請先到「加密金鑰」建立。');
      await page.evaluate(() => { window.__fixture.status.settings.encrypt_by_default = false; });
      await page.locator('#refresh').click();
      await page.locator('[data-focus="schedule-run-now"]:enabled').waitFor();
      assert.match(await page.locator('.schedule-encryption').textContent(), /「預設加密備份」目前關閉，排程備份不會加密/);
      assert.equal(await page.locator('.schedule-hint').textContent(), '設定已儲存。「立即執行一次」會依已儲存的設定，馬上建立一份排程備份。');
    });

  await check('an error when confirming keeps the dialog open with the engine\'s words; nothing is saved and the edits stay',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-images').waitFor();
      await page.locator('#schedule-images').check();
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      const denied = '排程備份的設定檔權限不正確，無法儲存；請通知工程人員處理後再試。';
      await page.evaluate(message => window.__fixture.failures.push({ command: 'schedule-set', code: 'permission-denied', message,
        details: { file: 'schedule.json' } }), denied);
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error:not([hidden])').waitFor();
      assert.equal(await page.locator('#confirm-error-message').textContent(), denied);
      assert.equal(await page.locator('#confirm-status').textContent(), '操作未完成；不會自動重試。');
      assert.equal(await page.locator('#confirm-ok').isDisabled(), false, 'it can be confirmed again');
      assert.equal(await page.evaluate(() => window.__fixture.schedule.writes), 0);
      await page.locator('#confirm-cancel').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      assert.equal(await page.evaluate(() => document.activeElement.dataset.focus), 'schedule-save');
      assert.match(await page.locator('.form-title').textContent(), /尚未儲存/);
      assert.equal(await page.locator('#schedule-images').isChecked(), true, 'the edit is kept');
      assert.equal(await page.locator('#schedule-kit-step').count(), 0, 'a refusal that is not about the kit');
      // The kit was unconfirmed meanwhile: the engine refuses at the confirmation and the kit step comes back.
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      await page.evaluate(() => window.__fixture.failures.push({ command: 'schedule-set', code: 'invalid-request', message: '開啟排程備份前，請先保存緊急金鑰。',
        details: { reason: 'kit-unconfirmed', field: 'schedule.enabled' } }));
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error-message').filter({ hasText: '開啟排程備份前，請先保存緊急金鑰。' }).waitFor();
      await page.locator('#confirm-cancel').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      await page.locator('#schedule-kit-step').waitFor();
      assert.equal(await page.locator('#schedule-images').isChecked(), true);
      assert.equal(await page.evaluate(() => window.__fixture.schedule.writes), 0);
      assert.deepEqual((await calls(page, 'schedule-set')).map(call => requestOf(call).confirm === true), [false, true, false, true]);
    });

  await check('turning 預設加密備份 off while the schedule is on says that its runs will not be encrypted either',
    scheduleFixture({}, { settings: { ...SAVED_DAILY, days: ['mon', 'wed', 'fri'], time: '02:30' }, saved: true }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/keys'; });
      await page.locator('#encrypt-default').waitFor();
      await page.locator('#encrypt-default').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.deepEqual(await page.locator('#confirm-body li').allTextContents(), ['關閉後，新的備份預設不加密，「還原前自動備份」也不加密。',
        '排程備份（每週一、三、五 02:30）也會不加密。', '已建立的備份不受影響；每份備份仍可在建立時選擇加密。', '這項變更會記錄在系統日誌。']);
      await shot(page, 'encryption-off-schedule-1440.png');
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      const notice = '已關閉「預設加密備份」：新的備份、還原前自動備份與排程備份都不加密。';
      await view(page).getByText(notice).waitFor();
      assert.equal(await page.locator('#status').textContent(), notice);
      assert.match(await view(page).textContent(), /目前新的備份、還原前自動備份與排程備份都不加密。/);
      // The schedule turned off elsewhere: turning 預設加密備份 off again does not name it.
      await page.locator('#encrypt-default').click();
      await view(page).getByText('已開啟「預設加密備份」。').waitFor();
      await page.evaluate(() => { window.__fixture.schedule.settings.enabled = false; });
      const reads = (await calls(page, 'status')).length;
      await page.locator('#refresh').click();
      await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'status').length > count, reads);
      await settled(page);
      await page.locator('#encrypt-default').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-body li').count(), 3);
      assert.equal(await page.locator('#confirm-body').getByText('排程備份').count(), 0);
      await page.locator('#confirm-cancel').click();
    });

  await check('the 排程檢查 row says what the banner says: not running while the checks stopped, 正常 only after a recorded check',
    scheduleFixture({}, { settings: SAVED_DAILY, saved: true, timer: { enabled: true, active: true, last_tick_age: null },
      attention: ATTENTIONS.find(item => item.code === 'timer-inactive') }), async page => {
      await ready(page);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-state-heading').waitFor();
      await settled(page);
      const checks = async () => (await metadataOf(page.locator('section[aria-labelledby="schedule-state-heading"]')))[0]['排程檢查'];
      assert.match(await page.locator('#schedule-banner p').textContent(), /排程檢查沒有在執行/);
      assert.equal(await checks(), '沒有在執行：排程備份不會自動開始', 'no check recorded while the device has been up for long');
      const refresh = async change => {
        await page.evaluate(change);
        const reads = (await calls(page, 'schedule-get')).length;
        await page.locator('#refresh').click();
        await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'schedule-get').length > count, reads);
        await settled(page);
      };
      await refresh(() => { window.__fixture.schedule.attention = null; });
      assert.equal(await page.locator('#schedule-banner').isVisible(), false);
      assert.equal(await checks(), '等待第一次檢查（每 5 分鐘一次）', 'not 正常 before a check was recorded');
      await refresh(() => { window.__fixture.schedule.timer.last_tick_age = 140; });
      assert.equal(await checks(), '正常，2 分鐘前檢查過（每 5 分鐘一次）');
      await refresh(() => { window.__fixture.schedule.timer.active = false; });
      assert.equal(await checks(), '沒有在執行：排程備份不會自動開始');
    });

  await check('a saved settings file the engine cannot use: the form says it shows the defaults and needs saving again',
    (() => {
      const unusable = '排程備份的設定檔內容不正確，排程備份已暫停。請重新儲存排程設定。';
      return scheduleFixture({}, { saved: true, unusable: true, problem: unusable, attention: { code: 'settings-problem', message: unusable } });
    })(), async page => {
      await ready(page);
      assert.match(await page.locator('[data-stat="schedule"]').textContent(), /^排程備份已暫停/);
      await page.evaluate(() => { window.location.hash = '#/schedule'; });
      await page.locator('#schedule-state-heading').waitFor();
      await settled(page);
      assert.equal(await page.locator('.form-title .chip').textContent(), '需要重新儲存');
      assert.equal(await page.locator('.form-card .notice-warn p').textContent(),
        '儲存的排程設定無法使用（原因見上方），下面顯示的是預設值，不是上次儲存的設定。處理後請確認每個選項，再按「儲存排程…」重新儲存。');
      const [card] = await metadataOf(page.locator('section[aria-labelledby="schedule-state-heading"]'));
      assert.equal(card['排程'], '已暫停：設定無法使用，需要重新儲存');
      assert.equal(await page.locator('[data-focus="schedule-run-now"]').isDisabled(), true);
      await allWidths(page, 'schedule with an unusable settings file');
      await shot(page, 'schedule-unusable-1440.png');
      // Saving the shown settings writes a good file.
      await page.locator('[data-focus="schedule-save"]').click();
      await page.locator('#confirm-dialog').waitFor();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      await page.locator('.form-title').filter({ hasText: '已儲存' }).waitFor();
      assert.equal(await page.locator('.form-card .notice-warn').count(), 0);
    });

  await check('the 排程備份 switch keeps its knob with forced colors: on and off look different', scheduleFixture({}, { settings: SAVED_DAILY, saved: true }), async page => {
    await page.emulateMedia({ forcedColors: 'active' });
    await ready(page);
    await page.evaluate(() => { window.location.hash = '#/schedule'; });
    const toggle = page.locator('#schedule-enabled');
    await toggle.waitFor();
    const look = async () => {
      await page.evaluate(() => document.activeElement?.blur());
      const style = await toggle.evaluate(element => [getComputedStyle(element).backgroundImage, getComputedStyle(element).forcedColorAdjust]);
      return { style, shot: await toggle.screenshot({ animations: 'disabled' }) };
    };
    const on = await look();
    await toggle.uncheck();
    const off = await look();
    for (const [label, seen] of [['on', on], ['off', off]]) {
      assert.match(seen.style[0], /radial-gradient/, `${label}: the knob is still drawn`);
      assert.equal(seen.style[1], 'none', `${label}: drawn in system colors by the page`);
    }
    assert(!on.shot.equals(off.shot), 'on and off are told apart');
  });

  // ------------------------------------------------------------------ 從 HA 備份匯入 (2026-11-18, DESIGN §6, §7)

  await check('從 HA 備份匯入: an uploaded HA backup opens its own page, never inspect; 備份列表 lists it with its chip, filter, search and count; 總覽 counts its space',
    haFixture({ ha: { backups: [] }, extra: { upload: { begin: { upload_id: UPLOAD_ID, path: UPLOAD_PATH, max_size: 20 * GiB }, finishHa: haMeta(HA_ID) } } }),
    async page => {
      await ready(page);
      await page.locator('[data-nav="restore"]').click();
      await page.getByText('也可以上傳 Home Assistant 的備份檔（.tar），把其中的 Odoo、n8n、Omnigent、Hermes、EMQX、Headscale、OpenDesign、code-server、Nextcloud、LiteLLM 匯入這台。').waitFor();
      await page.locator('#restore-file').setInputFiles({ name: 'woow_import_test.tar', mimeType: 'application/x-tar', buffer: Buffer.alloc(256 * KiB, 5) });
      await page.locator('[data-focus="restore-upload"]').click();
      await page.waitForFunction(id => window.location.hash === `#/ha/${id}`, HA_ID);
      await page.locator('#view-heading').filter({ hasText: HA_NAME }).waitFor();
      assert.deepEqual((await calls(page, 'upload-finish')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
      assert.equal((await calls(page, 'inspect')).length, 0, 'an HA backup is never inspected like a backup');
      assert.equal((await calls(page, 'upload-abort')).length, 0, 'the upload is kept');
      assert.equal(await page.locator('[data-nav="backups"]').getAttribute('aria-current'), 'page', '#/ha/<id> sits under 備份列表');
      const [info] = await metadataOf(page.locator('section[aria-labelledby="ha-info"]'));
      assert.equal(info['名稱'], HA_NAME);
      assert.match(info['HA 建立時間'], /2026\/11\/18 05:00/);
      assert.equal(info['類型'], undefined, 'HA Core makes every backup partial: its type says nothing (review P-10)');
      assert.equal(info['加密'], '已加密：匯入時需要 HA 備份金鑰');
      assert.equal(info['大小'], '1.5 GiB');
      assert.match(info['上傳時間'], /2026\/11\/18 09:00/);
      assert.equal(info['資料夾'], 'share、ssl');
      assert.equal(info['HA 備份 ID'], HA_ID);
      assert.match(await page.locator('section[aria-labelledby="ha-info"]').textContent(), /設定 → 系統 → 備份/, 'where HA shows its key');
      const rows = await page.locator('.ha-addons-table tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
      assert.deepEqual(rows, [
        [`Odoo 18 CE${ODOO_SLUG}`, ODOO_ADDON_VERSION, '可以匯入這台的「Odoo 18」'],
        [`WOOW n8n${N8N_SLUG}`, '2.43.6', '可以匯入這台的「n8n 工作流程」'],
        ['Mosquitto brokercore_mosquitto', '6.5.1', '這台沒有對應的應用']]);
      await shot(page, 'ha-backup-1440.png');
      await page.locator('[data-focus="back-backups"]').click();
      await page.locator('.backups-table').waitFor();
      const first = page.locator('.backups-table tbody tr').first();
      assert.equal(await first.getAttribute('data-ha'), HA_ID, 'the HA backup is listed by its own date, the newest here');
      assert.equal(await first.locator('td[data-label="類型"]').textContent(), 'HA 備份');
      assert.equal(await first.locator('td[data-label="應用"]').textContent(), 'Odoo 18 CE、WOOW n8n、Mosquitto broker');
      assert.equal(await first.locator('td[data-label="加密與驗證"]').textContent(), '已加密匯入時需要 HA 備份金鑰');
      assert.equal(await first.locator('.note').textContent(), HA_NAME);
      assert.equal(await page.locator('#backup-count').textContent(), '顯示 4 / 4 份備份');
      await page.locator('[data-focus="filter-ha"]').click();
      await page.waitForFunction(() => document.querySelector('#backup-count')?.textContent === '顯示 1 / 4 份備份');
      await page.locator('[data-focus="filter-manual"]').click();
      await page.waitForFunction(() => document.querySelector('#backup-count')?.textContent === '顯示 1 / 4 份備份');
      assert.equal(await page.locator('tr[data-ha]').count(), 0, '手動 lists no HA backup');
      await page.locator('[data-focus="filter-all"]').click();
      await page.locator('#backup-search').fill('mosquitto');
      await page.waitForFunction(() => document.querySelector('#backup-count')?.textContent === '顯示 1 / 4 份備份');
      assert.equal(await page.locator('tr[data-ha]').count(), 1, 'an add-on name finds its HA backup');
      await page.locator('#backup-search').fill('');
      // The upload view is ready for another file.
      await page.locator('[data-nav="restore"]').click();
      await page.locator('[data-focus="restore-upload"]').waitFor();
      assert.equal(await page.locator('[data-focus="restore-upload"]').isDisabled(), true);
      // 總覽 counts the uploaded HA backups apart from the backups (status.storage.ha_*, review P-11).
      await page.locator('[data-nav="overview"]').click();
      await page.locator('#refresh').click();
      await page.locator('section[aria-label="本機儲存空間"]').getByText('上傳的 HA 備份 1 份，佔用 1.5 GiB').waitFor();
    });

  await check('從 HA 備份匯入: a wrong HA key goes back to the key step with the engine\'s words; the right one checks; the key is dropped when the wizard closes or the page changes',
    haFixture(), async page => {
      await ready(page);
      await openHa(page);
      assert.deepEqual(await page.locator('.stepper[aria-label="匯入步驟"] .step-label').allTextContents(), ['選擇應用', '金鑰', '檢查', '結果與選項', '轉換', '還原']);
      assert.equal(await page.locator('#ha-app-odoo').isChecked(), true);
      assert.equal(await page.locator('#ha-app-n8n').isChecked(), true);
      assert.match(await page.locator('#ha-app-odoo-help').textContent(), /資料來自 HA 附加元件「Odoo 18 CE」（版本 0\.4\.12）/);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('#ha-key').waitFor();
      assert.equal(await page.evaluate(() => document.activeElement?.id), 'ha-key', 'the key field takes the focus');
      assert.equal(await page.locator('#ha-key').getAttribute('type'), 'text');
      assert.equal(await page.locator('#ha-key').getAttribute('autocomplete'), 'off');
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.getByText('請輸入 HA 備份金鑰。').waitFor();
      assert.equal((await calls(page, 'ha-check-start')).length, 0, 'an empty key never reaches the helper');
      await page.locator('#ha-key').fill(HA_WRONG_KEY);
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText(WRONG_HA_KEY.message).waitFor();
      const wrong = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.match(wrong.request_id, UUID_RE);
      assert.deepEqual(wrong, { ha_backup_id: HA_ID, apps: ['odoo', 'n8n'], request_id: wrong.request_id, key: HA_WRONG_KEY });
      assert.equal(await activeStep(page), '金鑰');
      assert.equal(await page.locator('#ha-key').inputValue(), HA_WRONG_KEY, 'the typed key stays to be corrected');
      assert.equal(await page.evaluate(() => document.activeElement?.id), 'ha-key');
      // Spaces around a key in HA's own format come from copying it; Enter submits.
      await page.locator('#ha-key').fill(`  ${HA_KEY} `);
      await page.locator('#ha-key').press('Enter');
      await page.locator('.phase-label').filter({ hasText: '解開 HA 備份' }).waitFor();
      assert.equal(await activeStep(page), '檢查');
      assert.equal(await page.locator('#job-banner').isHidden(), true, 'no banner leads away from the wizard (and its key)');
      await page.locator('[data-ha-app="n8n"]').waitFor();
      const right = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.equal(right.key, HA_KEY);
      // The engine refused the wrong key before any job existed, so the retry may reuse the request id (review F-03).
      assert.equal(right.request_id, wrong.request_id, 'a refused start keeps its request id');
      assert.equal(await activeStep(page), '結果與選項');
      // Closing the wizard drops the key.
      await page.locator('[data-focus="ha-options-back"]').click();
      await page.locator('[data-focus="ha-cancel"]').click();
      await page.locator('section[aria-labelledby="ha-info"]').waitFor();
      assert(!(await page.content()).includes(HA_KEY), 'the key is gone from the page');
      await page.locator(`[data-focus="ha-import-${HA_ID}"]`).click();
      await page.locator('[data-focus="ha-apps-next"]').click();
      assert.equal(await page.locator('#ha-key').inputValue(), '', 'a new wizard asks for the key again');
      // So does leaving the page.
      await page.locator('#ha-key').fill(HA_KEY);
      await page.locator('[data-nav="overview"]').click();
      await page.locator('.stat').first().waitFor();
      await page.goBack();
      await page.locator('section[aria-labelledby="ha-info"]').waitFor();
      await page.locator(`[data-focus="ha-import-${HA_ID}"]`).click();
      await page.locator('[data-focus="ha-apps-next"]').click();
      assert.equal(await page.locator('#ha-key').inputValue(), '');
      assert.equal((await calls(page, 'ha-check-start')).length, 2, 'nothing was started again on its own');
      // HA's older formats tell a wrong key only inside the job: the check fails with wrong-key and the key step is back.
      await page.evaluate(() => { window.__fixture.ha.jobKeyFailure = 'wrong-key'; });
      await page.locator('#ha-key').fill(HA_KEY);
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText(WRONG_HA_KEY.message).waitFor();
      assert.equal(await activeStep(page), '金鑰');
      assert.equal(await page.evaluate(() => document.activeElement?.id), 'ha-key');
      assert.equal((await calls(page, 'ha-check-start')).length, 3);
    });

  await check('從 HA 備份匯入: HA\'s key is asked for when a chosen add-on is encrypted, whatever `protected` says (review P-04)',
    haFixture({ ha: { backups: [
      haMeta(HA_ID, { other_addons: [], addons: [{ slug: ODOO_SLUG, name: 'Odoo 18 CE', version: ODOO_ADDON_VERSION, encrypted: true },
        { slug: N8N_SLUG, name: 'WOOW n8n', version: '2.43.6', encrypted: false }] }),
      haMeta(HA_PLAIN, { protected: false, name: '從 HA 解密下載的備份', other_addons: [], addons: [
        { slug: ODOO_SLUG, name: 'Odoo 18 CE', version: ODOO_ADDON_VERSION, encrypted: true },
        { slug: N8N_SLUG, name: 'WOOW n8n', version: '2.43.6', encrypted: false }] })] } }), async page => {
      await ready(page);
      const steps = () => page.locator('.stepper[aria-label="匯入步驟"] .step-label').allTextContents();
      await openHa(page);
      assert.deepEqual(await steps(), ['選擇應用', '金鑰', '檢查', '結果與選項', '轉換', '還原'], 'the Odoo add-on is encrypted');
      await page.locator('#ha-app-odoo').uncheck();
      assert.deepEqual(await steps(), ['選擇應用', '檢查', '結果與選項', '轉換', '還原'], 'n8n alone needs no key');
      assert.equal(await page.locator('[data-focus="ha-apps-next"]').textContent(), '下一步：開始檢查');
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="n8n"]').waitFor();
      const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.deepEqual([start.apps, 'key' in start], [['n8n'], false], 'no key for an add-on HA did not encrypt');
      // A download HA decrypted says protected:false and may keep an encrypted member: the key is asked for anyway.
      await page.locator('[data-nav="backups"]').click();
      const row = page.locator(`tr[data-ha="${HA_PLAIN}"]`);
      assert.equal(await row.locator('td[data-label="加密與驗證"]').textContent(), '已加密匯入時需要 HA 備份金鑰');
      await row.locator(`[data-focus="ha-import-${HA_PLAIN}"]`).click();
      await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
      assert.deepEqual(await steps(), ['選擇應用', '金鑰', '檢查', '結果與選項', '轉換', '還原']);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('#ha-key').fill(HA_KEY);
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor();
      assert.equal(requestOf((await calls(page, 'ha-check-start')).at(-1)).key, HA_KEY);
    });

  const haNoDeviceKey = (() => {
    const data = haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false })] } });
    data.status.key = null;
    return data;
  })();
  await check('從 HA 備份匯入 without this device\'s key while 預設加密 is on: the wizard says so with a link from the start and keeps 轉換 off; a refusal in the dialog links to 加密金鑰 (review P-07, F-05)',
    haNoDeviceKey, async page => {
      await ready(page);
      await openHa(page, HA_PLAIN);
      // From the start, with the way to 加密金鑰. Before the check the page cannot know that this engine makes the key itself (UI-17):
      // it promises nothing and says where the answer will be.
      const early = page.locator('.wizard-card .notice-info').filter({ hasText: '這台還沒有加密金鑰，轉換好的備份要用它加密。' });
      await early.waitFor();
      assert.doesNotMatch(await early.textContent(), /匯入開始時會自動/, 'no promise of what an older engine does not do');
      assert.match(await early.textContent(), /檢查完成後，這一頁會說明匯入時會自動建立一把，還是要先到「加密金鑰」設定。/);
      assert.equal(await early.locator('[data-focus="ha-keys"]').getAttribute('href'), '#/keys');
      // The check needs no device key. This engine's check has no schema 2 (it does not make the key itself): the two steps
      // keep the old rule, the conversion waits for the key.
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor();
      const notice = page.locator('.wizard-card .notice-warn').filter({ hasText: '尚未建立加密金鑰。轉換好的備份會依「預設加密備份」用這台設備的金鑰加密' });
      await notice.waitFor();
      assert.equal(await notice.locator('[data-focus="ha-keys"]').getAttribute('href'), '#/keys');
      assert.equal(await page.locator('#ha-db-0').isChecked(), true);
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true, 'no conversion without the device key');
      assert.doesNotMatch(await page.locator('.wizard-card').textContent(), /匯入開始時會自動建立/, 'the page that keeps 轉換 off does not promise the key either');
      assert.equal(await page.locator('.wizard-card .notice-info').filter({ hasText: '轉換好的備份要用它加密。' }).count(), 0, 'the first-step hint is gone');
      // Set up meanwhile: the page hears of the key on its next status.
      await page.evaluate(key => { window.__fixture.status.key = key; }, { key_id: KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: true });
      await page.locator('#refresh').click();
      await enabled(page, '[data-focus="ha-convert"]');
      assert.equal(await notice.count(), 0);
      // A refusal the page could not foresee shows the engine's words and links to 加密金鑰.
      await page.evaluate(() => { window.__fixture.status.key = null; });
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error').getByText('這台設備尚未建立加密金鑰，請先完成金鑰設定。').waitFor();
      assert.equal((await calls(page, 'ha-convert-start')).length, 1);
      await page.locator('[data-focus="dialog-keys"]').click();
      await page.waitForFunction(() => window.location.hash === '#/keys');
      assert.equal(await page.locator('#confirm-dialog').evaluate(dialog => dialog.open), false);
    });

  await check('從 HA 備份匯入: a key refusal when the conversion starts closes the dialog on the key field (review P-08)',
    haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false })] } }), async page => {
      await ready(page);
      await openHa(page, HA_PLAIN);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor();
      await page.evaluate(message => window.__fixture.failures.push({ command: 'ha-convert-start', code: 'key-required', message }), KEY_REQUIRED.message);
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      await page.waitForFunction(() => document.activeElement?.id === 'ha-key');
      assert.equal(await activeStep(page), '金鑰');
      assert.equal(await page.locator('.wizard-card .notice-error').textContent(), KEY_REQUIRED.message);
    });

  await check('從 HA 備份匯入: check results — a blocker leaves out only its own app (UI-14); the Odoo database picker with its counts; n8n facts and workflows to fix; 「這只是測試」 starts unchecked',
    haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false, name: '未加密的 HA 備份' })] } }), async page => {
      await ready(page);
      // As the engine says it: every database is blocked (a module of another version), so Odoo is (review F-02).
      await setScript(page, 'ha-check', haScripts({ check: haCheck({ odoo: { ok: false, blockers: [ODOO_ALL_BLOCKED] },
        databases: [odooDb('woowtest', { ok: false, blockers: [VERSION_BLOCKER] }), blockedDb()] }) })['ha-check']);
      await openHa(page, HA_PLAIN);
      assert.deepEqual(await page.locator('.stepper[aria-label="匯入步驟"] .step-label').allTextContents(), ['選擇應用', '檢查', '結果與選項', '轉換', '還原'],
        'an unencrypted HA backup has no key step');
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor();
      const odoo = page.locator('[data-ha-app="odoo"]');
      assert.match(await odoo.getAttribute('class'), /is-blocked/);
      assert.equal(await odoo.locator('.chip').first().textContent(), '無法匯入');
      assert.equal(await odoo.locator('.check-fail .check-message').first().textContent(), ODOO_ALL_BLOCKED);
      assert.equal(await odoo.locator('.ha-database[data-database="woowtest"] .check-fail .check-message').textContent(), VERSION_BLOCKER);
      // The add-on version and this device's Odoo release are not compared: Odoo compares its modules (review P-09, UI-1).
      assert.equal(await odoo.locator('.muted').first().textContent(), 'HA 附加元件版本 0.4.12，這台的 Odoo 18.0-20260926；Odoo 逐一比對每個模組，結果見下方各資料庫。');
      assert.equal(await page.locator('[data-ha-app="n8n"] .muted').first().textContent(), 'HA 的版本 2.43.6，這台的版本 2.43.6。');
      assert.equal(await page.locator('#ha-db-0').isDisabled(), true, 'no database can be chosen while Odoo is blocked');
      // Odoo does not pass, n8n does: only Odoo is left out and the conversion of n8n can go on (UI-14).
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), false, 'one blocker never holds back the other app');
      await page.getByText('「Odoo 18」沒有通過檢查，這次不會匯入，這台的它也不會有任何變更；其他應用可以繼續轉換。').waitFor();
      // Odoo's custom modules and n8n's community nodes run here: import only a trusted backup.
      await page.locator('.wizard-card .notice-info').getByText('Odoo 的自訂模組和 n8n 的社群節點是會在這台執行的程式，只匯入你信任的備份。').waitFor();
      const n8n = page.locator('[data-ha-app="n8n"]');
      assert.deepEqual((await metadataOf(n8n))[0], { 管理者帳號: 'owner@example.com', 工作流程: '14 個（啟用中 6 個）', 憑證: '9 個', 執行紀錄: '1,520 筆',
        使用者: '2 位', 社群節點: 'n8n-nodes-mqtt-x 1.4.2' });
      assert.deepEqual(await n8n.locator('.check-warn .check-message').allTextContents(), ['社群節點 n8n-nodes-mqtt-x 含有與這台不相容的程式，搬過來後需要重新安裝。',
        'HA 的 n8n 裝了 1 個社群節點套件，搬過來後請確認它們能正常使用。']);
      assert.deepEqual(await n8n.locator('.workflow-list li').evaluateAll(items => items.map(item => item.textContent)), [
        '開門通知啟用中用到 Home Assistant 節點，網址要改成這台連得到的 HA。',
        '每日報表未啟用讀寫檔案的路徑 /share/reports 在這台不存在。 用到 http://supervisor/core/api。']);
      // Fixed on the device: check again. Two databases pass, so one has to be chosen.
      await setScript(page, 'ha-check', haScripts({ check: haCheck({ databases: [odooDb('woowtest'),
        odooDb('archive-2025', { partners: 800, size: 200 * MiB, custom_modules: [], crons_active: 0, mail_servers_active: 0, filestore_files: 0,
          filestore_bytes: 0 }), blockedDb()] }) })['ha-check']);
      await page.locator('[data-focus="ha-recheck"]').click();
      await page.locator('[data-ha-app="odoo"]:not(.is-blocked)').waitFor();
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true, 'two databases passed: one must be chosen');
      assert.equal(await page.locator('[data-ha-app="odoo"] .muted').first().textContent(), 'HA 附加元件版本 0.4.12，這台的 Odoo 18.0-20260926；Odoo 逐一比對每個模組，模組版本相同。');
      await page.getByText('請先選擇要搬過來的 Odoo 資料庫。').waitFor();
      const databases = page.locator('.ha-database');
      assert.equal(await databases.count(), 3);
      assert.deepEqual(await page.locator('.ha-database input[type="radio"]').evaluateAll(items => items.map(item => [item.value, item.checked, item.disabled])),
        [['woowtest', false, false], ['archive-2025', false, false], ['demo-old', false, true]]);
      assert.equal(await databases.nth(0).locator('small').first().textContent(),
        '聯絡人 1,234 · 可登入的使用者 5 · 附件 3,210（120 MiB） · 已安裝模組 87 · 大小 310 MiB');
      assert.match(await databases.nth(0).textContent(), /啟用中的排程動作 12 個 · 寄信伺服器 1 個/);
      assert.match(await databases.nth(0).textContent(), /會一起複製的自訂模組：woow_paas_platform（版本 18\.0\.1\.2\.0，來自 HA 的 \/share\/odoo_addons 資料夾）/);
      assert.match(await databases.nth(1).textContent(), /沒有要另外複製的自訂模組。/);
      assert.equal(await databases.nth(2).locator('.check-fail .check-message').textContent(), MISSING_MODULE);
      // What to know before moving a database: the engine says it per database only (review P-02).
      const issues = db => databases.nth(db).locator('.check').evaluateAll(items => items.map(item => [item.className.replace('check check-', ''),
        item.querySelector('.check-message').textContent]));
      assert.deepEqual(await issues(0), [['warn', 'HA 的資料庫有 1 個啟用中的外寄郵件伺服器，搬過來後會開始寄信（包括 HA 上還沒寄出的信和每天的提醒信）；正式搬家前請先停掉 HA 那邊的 Odoo，避免兩邊各寄一次。'],
        ['warn', 'HA 的資料庫有 12 個啟用中的排程工作，搬過來後會在這台執行。']]);
      assert.deepEqual(await issues(1), [['warn', NO_FILESTORE]]);
      assert.deepEqual(await issues(2), [['fail', MISSING_MODULE], ['warn', 'HA 的資料庫有 3 個啟用中的排程工作，搬過來後會在這台執行。']]);
      await page.locator('#ha-db-1').check();
      await enabled(page, '[data-focus="ha-convert"]');
      assert.equal(await page.locator('#ha-db-1').isChecked(), true);
      assert.equal(await page.locator('#ha-test-mode').isChecked(), false, '「這只是測試」 is off until ticked');
      assert.equal(await page.locator('label[for="ha-test-mode"] strong').textContent(), '這只是測試（先關掉排程、寄信和工作流程）');
      assert.match(await page.locator('#ha-test-mode-help').textContent(), /正式搬家請不要勾/);
      assert.match(await page.locator('#ha-test-mode-help').textContent(), /正式搬家時，Odoo 會接著寄出 HA 上還沒寄出的信和每天的提醒信，請先停掉 HA 那邊的 Odoo，避免兩邊各寄一次。$/);
      const starts = (await calls(page, 'ha-check-start')).map(requestOf);
      assert.equal(starts.length, 2);
      assert(starts.every(item => !('key' in item)), 'no key for an unencrypted HA backup');
      assert.notEqual(starts[0].request_id, starts[1].request_id);
      await shot(page, 'ha-import-options-1440.png');
    });

  await check('從 HA 備份匯入: convert, then the restore wizard takes over at its preflight with an HA notice; the result says what to do next',
    haFixture(), async page => {
      await ready(page);
      await openHa(page);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('#ha-key').fill(HA_KEY);
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('[data-ha-app="n8n"]').waitFor();
      assert.equal(await page.locator('#ha-db-0').isChecked(), true, 'the only database that passed is chosen');
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '開始轉換 HA 備份？');
      assert.match(await page.locator('#confirm-body').textContent(), /轉換時這台的應用照常運作，不會停機，也不會變更任何資料。/);
      assert.deepEqual((await metadataOf(page.locator('#confirm-body')))[0], { 應用: '「Odoo 18」、「n8n 工作流程」', 'Odoo 資料庫': 'woowtest', 這只是測試: '否' });
      await page.evaluate(() => {
        window.__announced = [];
        const status = document.querySelector('#status');
        new MutationObserver(() => window.__announced.push(status.textContent)).observe(status, { childList: true, characterData: true, subtree: true });
      });
      await page.locator('#confirm-ok').click();
      await page.locator('.phase-label').filter({ hasText: '轉換資料' }).waitFor();
      assert.equal(await activeStep(page), '轉換');
      assert.equal(await page.locator('#job-banner').isHidden(), true);
      const convert = requestOf((await calls(page, 'ha-convert-start')).at(-1));
      assert.match(convert.request_id, UUID_RE);
      assert.deepEqual(convert, { ha_backup_id: HA_ID, apps: ['odoo', 'n8n'], test_mode: false, confirm: true, request_id: convert.request_id,
        odoo_database: 'woowtest', key: HA_KEY });
      await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_HA, { timeout: 15000 });
      await page.locator('.app-preflight').first().waitFor();
      // A screen reader hears the conversion's phases as they change, not only its start and end (review P-11).
      const announced = await page.evaluate(() => window.__announced);
      for (const line of ['轉換 HA 備份：轉換資料', '轉換 HA 備份：封裝備份']) assert(announced.includes(line), `announced ${line}: ${announced}`);
      assert.equal(await page.locator('.stepper .step-label').first().textContent(), '從 HA 轉換');
      const banner = page.locator('.ha-banner');
      assert.match(await banner.textContent(), new RegExp(`這份備份由 HA 備份「${HA_NAME}」（2026/11/18 05:00）轉換而來。`));
      assert.match(await banner.textContent(), /取代這台「Odoo 18」、「n8n 工作流程」目前的資料；這台的網址、連接埠、資料庫密碼和設定檔都保持不變。/);
      assert.match(await banner.textContent(), /還原完成後，請把 HA 那邊的「Odoo 18 CE」、「WOOW n8n」附加元件停掉，避免同一件事兩邊各做一次。/);
      // The engine's explanations come before the restore, after what it replaces and keeps (UI-3).
      assert.deepEqual((await banner.locator('li').allTextContents()).slice(1, 4), [...HA_NOTES.odoo, ...HA_NOTES.n8n]);
      assert.equal(await page.locator('[data-focus="pf-select-odoo"]').isChecked(), true);
      assert.equal(await page.locator('[data-focus="pf-select-n8n"]').isChecked(), true);
      assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_HA }, 'the converted backup needs no HA key');
      await shot(page, 'ha-restore-preflight-1440.png');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      assert.equal(await page.locator('.ha-banner').count(), 1, 'the notice stays on 確認');
      await page.locator('[data-focus="confirm-start"]').click();
      await page.waitForFunction(() => window.location.hash.startsWith('#/jobs/'));
      const restore = requestOf((await calls(page, 'restore-start')).at(-1));
      assert.deepEqual(Object.keys(restore).sort(), ['apps', 'backup_id', 'confirm', 'request_id'], 'the restore gets no key');
      assert.deepEqual([restore.backup_id, restore.apps], [B_HA, ['odoo', 'n8n']]);
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      // To-dos only: the page's, the engine's of each restored app, and deleting the HA file (UI-3, review P-05, HA-SEC-06).
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [
        '請把 HA 那邊的「Odoo 18 CE」附加元件停掉，避免同一件事兩邊各做一次。',
        '請把 HA 那邊的「WOOW n8n」附加元件停掉，避免同一件事兩邊各做一次。',
        '請到「Odoo MCP 管理」重新設定 Odoo 的登入資料。',
        '請到「n8n MCP 管理」重新設定 n8n 的登入資料。',
        ...HA_TODO.odoo, ...HA_TODO.n8n, HA_DELETE_LINE]);
      assert.equal(await page.locator('.ha-reminders [data-focus="result-ha-delete"]').getAttribute('href'), `#/ha/${HA_ID}`);
      assert.deepEqual(await page.locator('.job-result .workflow-list .path-app').allTextContents(), ['開門通知', '每日報表']);
      await shot(page, 'ha-restore-result-1440.png');
      // The converted backup: 「由 HA 轉換」 in the list, where it came from in its details.
      await page.locator('[data-nav="backups"]').click();
      const row = page.locator(`tr[data-backup="${B_HA}"]`);
      await row.waitFor();
      assert.equal(await row.locator('td[data-label="類型"]').textContent(), '手動由 HA 轉換');
      await page.locator('[data-focus="filter-ha"]').click();
      await page.waitForFunction(() => document.querySelector('#backup-count')?.textContent === '顯示 2 / 5 份備份');
      await page.locator(`[data-focus="open-${B_HA}"]`).click();
      const source = page.locator('section[aria-labelledby="detail-ha"]');
      await source.waitFor();
      assert.match(await page.locator('section[aria-labelledby="detail-info"] .chips').textContent(), /由 HA 轉換/);
      const [origin] = await metadataOf(source);
      assert.deepEqual([origin['HA 備份'], origin['應用'], origin['Odoo 資料庫'], origin['這只是測試']], [HA_NAME, 'Odoo 18、n8n 工作流程', 'woowtest', '否']);
      assert.deepEqual(await source.locator('.workflow-list .path-app').allTextContents(), ['開門通知', '每日報表']);
      await source.locator('[data-focus="detail-ha-link"]').click();
      await page.waitForFunction(id => window.location.hash === `#/ha/${id}`, HA_ID);
    });

  await check('從 HA 備份匯入: an app this device lacks cannot be chosen; a test import sends test_mode and says so on the restore and its result; no MCP lines without the MCP apps',
    haFixture({ mcp: false, ha: { backups: [haMeta(HA_PLAIN, { protected: false, importable_apps: [
      { slug: ODOO_SLUG, app_id: 'odoo', app_name: 'Odoo 18', installed: false },
      { slug: N8N_SLUG, app_id: 'n8n', app_name: 'n8n 工作流程', installed: true }] })] } }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_PLAIN}"]`).click();
      const odooRow = page.locator(`.ha-addons-table tr[data-addon="${ODOO_SLUG}"]`);
      assert.equal(await odooRow.locator('td[data-label="匯入到這台"]').textContent(), '還沒安裝「Odoo 18」：這台還沒安裝，請先用它的安裝套件安裝並啟動，再到「應用設定」加入它');
      await page.locator(`[data-focus="ha-import-${HA_PLAIN}"]`).click();
      assert.equal(await page.locator('#ha-app-odoo').isDisabled(), true);
      assert.equal(await page.locator('#ha-app-odoo').isChecked(), false);
      assert.equal(await page.locator('#ha-app-odoo-help').textContent(), '這台還沒安裝，請先用它的安裝套件安裝並啟動，再到「應用設定」加入它。');
      assert.equal(await page.locator('#ha-app-n8n').isChecked(), true);
      assert.match(await page.locator('.wizard-card').textContent(), /其他附加元件（Mosquitto broker）這台沒有對應的應用，不會匯入。/);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="n8n"]').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'ha-check-start')).at(-1)).apps, ['n8n']);
      assert.equal(await page.locator('[data-ha-app="odoo"]').count(), 0, 'only the chosen app is shown');
      assert.equal(await page.locator('.ha-databases').count(), 0);
      await page.locator('#ha-test-mode').check();
      await page.locator('[data-focus="ha-convert"]').click();
      assert.equal((await metadataOf(page.locator('#confirm-body')))[0]['這只是測試'], '是：排程、寄信和工作流程會先關掉');
      await page.locator('#confirm-ok').click();
      await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_HA, { timeout: 15000 });
      const convert = requestOf((await calls(page, 'ha-convert-start')).at(-1));
      assert.deepEqual(Object.keys(convert).sort(), ['apps', 'confirm', 'ha_backup_id', 'request_id', 'test_mode'], 'no Odoo database and no key');
      assert.deepEqual([convert.apps, convert.test_mode], [['n8n'], true]);
      await page.locator('.app-preflight').first().waitFor();
      assert.equal(await page.locator('.app-preflight').count(), 1, 'the converted backup holds n8n only');
      const banner = await page.locator('.ha-banner').textContent();
      assert.match(banner, /這是測試匯入：搬過來的 n8n 工作流程都已停用，HA 那邊可以照常使用。/);
      assert.doesNotMatch(banner, /停掉/);
      assert(banner.includes(HA_NOTES.n8n[0]) && !banner.includes(HA_NOTES.odoo[0]), 'the notes of the converted app');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [
        '這是測試匯入：搬過來的 n8n 工作流程都已停用，HA 那邊可以照常使用。要正式搬過來時，請重新匯入一次，並且不要勾「這只是測試」。',
        ...HA_TODO.n8n, HA_DELETE_LINE]);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${B_HA}"]`).click();
      const haCard = page.locator('section[aria-labelledby="detail-ha"]');
      await haCard.locator('dl.metadata').first().waitFor();  // the detail renders on the hash change, after the click
      const [origin] = await metadataOf(haCard);
      assert.equal(origin['這只是測試'], '是：工作流程、排程和寄信都已先關掉');
      assert.equal(await page.locator('section[aria-labelledby="detail-ha"] .card-head .chip').textContent(), '測試匯入');
    });

  await check('從 HA 備份匯入: deleting an HA backup asks first; cancel never deletes; a busy refusal links to the job; the HA file goes, the converted backup stays',
    haFixture({ extra: { backups: [convertedMeta(), ...fixture().backups] } }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="ha-delete-${HA_ID}"]`).click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '刪除這份 HA 備份？');
      assert.match(await page.locator('#confirm-body').textContent(), /Home Assistant 那邊的備份不受影響，已經轉換好的備份也會保留/);
      assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm-cancel', 'the safe choice has the focus');
      await page.locator('#confirm-cancel').click();
      assert.equal((await calls(page, 'ha-delete')).length, 0, 'cancel never deletes');
      await page.evaluate(job => window.__fixture.failures.push({ command: 'ha-delete', code: 'busy',
        message: '這份 HA 備份正被進行中的作業使用，請等它完成後再刪除。', details: { job_id: job } }), J_OTHER);
      await page.locator(`[data-focus="open-${HA_ID}"]`).click();
      await page.locator(`[data-focus="ha-delete-${HA_ID}"]`).click();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error').getByText('正被進行中的作業使用').waitFor();
      assert.equal(await page.locator('[data-focus="dialog-busy-job"]').getAttribute('href'), `#/jobs/${J_OTHER}`);
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      await page.waitForFunction(() => window.location.hash === '#/backups');
      assert.deepEqual((await calls(page, 'ha-delete')).map(requestOf), [{ ha_backup_id: HA_ID, confirm: true }, { ha_backup_id: HA_ID, confirm: true }]);
      await page.locator(`tr[data-ha="${HA_ID}"]`).waitFor({ state: 'detached' });
      assert.equal(await page.locator(`tr[data-backup="${B_HA}"]`).count(), 1, 'the converted backup stays');
      await page.locator(`[data-focus="open-${B_HA}"]`).click();
      const haCard = page.locator('section[aria-labelledby="detail-ha"]');
      await haCard.locator('dl.metadata').first().waitFor();  // the detail renders on the hash change, after the click
      const [origin] = await metadataOf(haCard);
      assert.equal(origin['HA 備份'], `${HA_NAME}（HA 備份檔已從這台刪除）`);
      // Restoring it still names HA's add-ons (the import recorded them, review P-06); only n8n is restored, so only
      // n8n's to-dos are listed (review P-05); the HA file is gone, so there is nothing more to delete.
      await page.locator(`[data-focus="restore-${B_HA}"]`).click();
      await page.locator('.app-preflight').first().waitFor();
      assert.match(await page.locator('.ha-banner').textContent(), /請把 HA 那邊的「Odoo 18 CE」、「WOOW n8n」附加元件停掉/);
      await page.locator('[data-focus="pf-select-odoo"]').uncheck();
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      assert.deepEqual(requestOf((await calls(page, 'restore-start')).at(-1)).apps, ['n8n']);
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [
        '請把 HA 那邊的「WOOW n8n」附加元件停掉，避免同一件事兩邊各做一次。', '請到「n8n MCP 管理」重新設定 n8n 的登入資料。', ...HA_TODO.n8n]);
    });

  await check('從 HA 備份匯入, engine whose inspect does not name the import: a converted backup restored from 備份列表 keeps its HA notice; 檢視內容 keeps 由 HA 轉換 (review P-01)',
    haFixture({ legacy: true, extra: { backups: [convertedMeta({}, { legacy: true }), ...fixture().backups] } }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="restore-${B_HA}"]`).click();
      await page.locator('.app-preflight').first().waitFor();
      assert.deepEqual(requestOf((await calls(page, 'inspect')).at(-1)), { backup_id: B_HA });
      assert.equal(await page.locator('.stepper .step-label').first().textContent(), '從 HA 轉換');
      assert.match(await page.locator('.ha-banner').textContent(), new RegExp(`這份備份由 HA 備份「${HA_NAME}」（2026/11/18 05:00）轉換而來。`));
      assert.equal(await page.locator('.ha-banner li').count(), 3, 'that engine sends no notes');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').waitFor();
      assert.equal(await page.locator('.ha-banner').count(), 1, 'the notice stays on 確認');
      // That engine's `reminders` hold all its lines, of every converted app: they all follow the page's.
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [
        '請把 HA 那邊的「Odoo 18 CE」附加元件停掉，避免同一件事兩邊各做一次。',
        '請把 HA 那邊的「WOOW n8n」附加元件停掉，避免同一件事兩邊各做一次。',
        '請到「Odoo MCP 管理」重新設定 Odoo 的登入資料。',
        '請到「n8n MCP 管理」重新設定 n8n 的登入資料。',
        ...HA_LEGACY_REMINDERS.odoo, ...HA_LEGACY_REMINDERS.n8n, HA_DELETE_LINE]);
      // The details: 檢視內容 (inspect) keeps where the backup came from.
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${B_HA}"]`).click();
      await page.locator('section[aria-labelledby="detail-ha"]').waitFor();
      await page.locator(`[data-focus="inspect-${B_HA}"]`).click();
      await page.locator(`[data-focus="inspect-${B_HA}"]`).waitFor({ state: 'detached' });
      assert.equal((await calls(page, 'inspect')).length, 2);
      assert.equal(await page.locator('section[aria-labelledby="detail-ha"]').count(), 1, '由 HA 備份轉換 stays');
      assert.match(await page.locator('section[aria-labelledby="detail-info"] .chips').textContent(), /由 HA 轉換/);
    });

  const haJobs = (() => {
    const data = haFixture({ extra: { backups: [convertedMeta(), ...fixture().backups] } });
    const checked = haCheck({ n8n: { ok: false, blockers: ['HA 的 n8n 還沒建立管理者帳號，沒有可搬的資料。'] } });
    data.jobs = {
      [J_HA_FAILED]: { job: haJob(J_HA_FAILED, 'ha-check', 'failed', '2026-11-18T01:50:00Z', {
        phases: phasesAt('ha-check', 'decrypt', { failedAt: 'decrypt' }), error: { code: 'internal-error', message: NACL_MISSING } }), log: [], steps: [] },
      [J_HA_CHECK]: { job: haJob(J_HA_CHECK, 'ha-check', 'succeeded', '2026-11-18T02:00:00Z', { result: checked }), log: [], steps: [] },
      [J_HA_CONVERT]: { job: haJob(J_HA_CONVERT, 'ha-convert', 'succeeded', '2026-11-18T02:10:00Z', {
        result: { backup_id: B_HA, size: 420 * MiB, apps: ['odoo', 'n8n'], encrypted: true, ha_import: haImportView(['odoo', 'n8n']) } }),
        log: [], steps: [] },
      [J_HA_RUN]: { job: haJob(J_HA_RUN, 'ha-check', 'running', '2026-11-18T02:20:00Z'), log: ['2026-11-18T02:20:01Z 階段：解開 HA 備份'], steps: [
        haStep('ha-check', 'decrypt', 30), haStep('ha-check', 'check', 70),
        { job: { state: 'succeeded', phase: 'check', phases: phasesAt('ha-check', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-18T02:21:00Z', cancellable: false, result: haCheck() }, log: ['2026-11-18T02:21:00Z 檢查完成'] }] },
      // A restore of the converted backup this page did not start (e.g. after a reload): the list's from_ha speaks.
      [J_HA_RESTORE]: { job: { id: J_HA_RESTORE, type: 'restore', state: 'succeeded', phase: 'check', phases: phasesAt('restore', null),
        progress: { percent: 100, message: '已完成' }, created: '2026-11-18T02:30:00Z', started: '2026-11-18T02:30:00Z',
        finished: '2026-11-18T02:35:00Z', cancellable: false, params: { backup_id: B_HA, apps: ['odoo', 'n8n'], key_provided: false },
        result: haRestoreScript().at(-1).job.result, error: null }, log: [], steps: [] },
    };
    data.status.active_job = structuredClone(data.jobs[J_HA_RUN].job);
    // The MCP admin page as this device's catalog names it (review P-11).
    data.status.apps.find(entry => entry.id === 'odoo-mcp-admin').name = 'Odoo MCP 管理（woowtech）';
    // An engine that also sent the page's own line about deleting the HA file: it is listed once, with its link.
    data.backups[0].from_ha.reminders = ['匯入完成後，建議刪除這份 HA 備份檔（裡面可能有 HA 的密碼與權杖）'];
    return data;
  })();
  await check('從 HA 備份匯入 jobs: 檢查 HA 備份 and 轉換 HA 備份 are named in the banner, the job view and 活動紀錄; their results render; an active HA job is accepted',
    haJobs, async page => {
      // The running check resumes in the job view (status.active_job passes validJob: it is a `verify` job).
      await page.waitForFunction(id => window.location.hash === `#/jobs/${id}`, J_HA_RUN);
      await page.locator('#view-heading').filter({ hasText: '檢查 HA 備份' }).waitFor();
      assert.match(await page.locator('.phases').textContent(), /解開 HA 備份.*檢查內容與版本/);
      await page.locator('#result-heading').filter({ hasText: 'HA 備份檢查完成' }).waitFor();
      assert.match(await page.locator('.job-result').textContent(), /所選的應用都可以匯入這台。/);
      assert.equal(await page.locator('[data-focus="result-ha"]').getAttribute('href'), `#/ha/${HA_ID}`);
      assert.match(await page.locator('[data-focus="result-ha"]').getAttribute('class'), /primary/);
      await page.waitForFunction(name => document.querySelector('section[aria-labelledby="job-params-heading"]')?.textContent.includes(name), HA_NAME);
      assert.deepEqual((await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0], {
        作業類型: '檢查 HA 備份', 'HA 備份': HA_NAME, 應用: 'Odoo 18、n8n 工作流程', 金鑰: '使用你輸入的 HA 備份金鑰（作業結束後即刪除）' });
      // 活動紀錄
      await page.locator('[data-nav="activity"]').click();
      await page.locator('.jobs-table').waitFor();
      await page.waitForFunction(name => document.querySelector('.jobs-table')?.textContent.includes(name), HA_NAME);
      const rows = await page.locator('.jobs-table tbody tr').evaluateAll(items => items.map(row => [row.dataset.job,
        row.querySelector('[data-label="作業"]').textContent, row.querySelector('[data-label="內容"]').textContent, row.querySelector('[data-label="結果"]').textContent]));
      assert.deepEqual(rows, [
        [J_HA_RESTORE, '還原', `Odoo 18、n8n 工作流程 · 備份 ${B_HA}`, '已完成'],
        [J_HA_RUN, '檢查 HA 備份', `Odoo 18、n8n 工作流程 · HA 備份「${HA_NAME}」`, '已完成'],
        [J_HA_CONVERT, '轉換 HA 備份', `Odoo 18、n8n 工作流程 · HA 備份「${HA_NAME}」`, '已完成'],
        [J_HA_CHECK, '檢查 HA 備份', `Odoo 18、n8n 工作流程 · HA 備份「${HA_NAME}」`, '已完成'],
        [J_HA_FAILED, '檢查 HA 備份', `Odoo 18、n8n 工作流程 · HA 備份「${HA_NAME}」`, NACL_MISSING]]);
      await allWidths(page, 'activity with HA jobs');
      // A restore of a converted backup that no wizard of this page started still names the import and its reminders.
      await page.locator(`[data-focus="job-${J_HA_RESTORE}"]`).click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      assert.equal(await page.locator('.job-stepper .step-label').first().textContent(), '從 HA 轉換');
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [
        '請把 HA 那邊的「Odoo 18 CE」附加元件停掉，避免同一件事兩邊各做一次。',
        '請把 HA 那邊的「WOOW n8n」附加元件停掉，避免同一件事兩邊各做一次。',
        '請到「Odoo MCP 管理（woowtech）」重新設定 Odoo 的登入資料。',
        '請到「n8n MCP 管理」重新設定 n8n 的登入資料。',
        ...HA_TODO.odoo, ...HA_TODO.n8n, HA_DELETE_LINE]);
      await page.locator('[data-focus="back-activity"]').click();
      // A check with a blocker.
      await page.locator(`[data-focus="job-${J_HA_CHECK}"]`).click();
      await page.locator('#result-heading').filter({ hasText: 'HA 備份檢查完成' }).waitFor();
      assert.match(await page.locator('.job-result').textContent(), /有應用沒有通過檢查，要先處理下列問題才能匯入。/);
      assert.equal(await page.locator('.job-result [data-ha-app="n8n"] .check-fail .check-message').textContent(), 'HA 的 n8n 還沒建立管理者帳號，沒有可搬的資料。');
      // Each Odoo database with its verdict, blockers and warnings (review P-02, P-03).
      const jobDatabases = await page.locator('.job-result .ha-database-list > li').evaluateAll(items => items.map(item => [item.dataset.database,
        item.querySelector('.chip').textContent, [...item.querySelectorAll('.check-message')].map(message => message.textContent)]));
      assert.deepEqual(jobDatabases, [
        ['woowtest', '可以搬', ['HA 的資料庫有 1 個啟用中的外寄郵件伺服器，搬過來後會開始寄信（包括 HA 上還沒寄出的信和每天的提醒信）；正式搬家前請先停掉 HA 那邊的 Odoo，避免兩邊各寄一次。', 'HA 的資料庫有 12 個啟用中的排程工作，搬過來後會在這台執行。']],
        ['demo-old', '不能搬', [MISSING_MODULE, 'HA 的資料庫有 3 個啟用中的排程工作，搬過來後會在這台執行。']]]);
      assert.match(await page.locator('.job-result').textContent(), /要匯入，請回到 HA 備份按「檢查並匯入…」，並重新輸入 HA 備份金鑰。/);
      // A failed check shows the engine's words.
      await page.locator('[data-focus="back-activity"]').click();
      await page.locator(`[data-focus="job-${J_HA_FAILED}"]`).click();
      await page.locator('#result-heading').filter({ hasText: '檢查 HA 備份失敗' }).waitFor();
      assert.equal(await page.locator('.job-result .notice-error p').textContent(), NACL_MISSING);
      assert.match(await page.locator('[data-focus="result-ha"]').getAttribute('class'), /primary/);
      // A conversion leads on to restoring its backup.
      await page.locator('[data-focus="back-activity"]').click();
      await page.locator(`[data-focus="job-${J_HA_CONVERT}"]`).click();
      await page.locator('#result-heading').filter({ hasText: 'HA 備份已轉換' }).waitFor();
      assert.equal(await page.locator('#view-heading').textContent(), '轉換 HA 備份');
      const [converted] = await metadataOf(page.locator('.job-result'));
      assert.deepEqual(converted, { 備份: B_HA, 應用: 'Odoo 18、n8n 工作流程', 'Odoo 資料庫': 'woowtest', 這只是測試: '否' });
      assert.deepEqual((await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0], {
        作業類型: '轉換 HA 備份', 'HA 備份': HA_NAME, 應用: 'Odoo 18、n8n 工作流程', 'Odoo 資料庫': 'woowtest', 這只是測試: '否',
        金鑰: '使用你輸入的 HA 備份金鑰（作業結束後即刪除）' });
      assert.deepEqual(await page.locator('.result-actions > *').evaluateAll(items => items.map(item => item.textContent)),
        ['還原到這台…', '查看備份', '回到 HA 備份']);
      await page.locator('[data-focus="result-ha-restore"]').click();
      await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_HA);
      await page.locator('.app-preflight').first().waitFor();
      assert.match(await page.locator('.ha-banner').textContent(), new RegExp(`這份備份由 HA 備份「${HA_NAME}」`));
    });

  await check('從 HA 備份匯入 errors: a busy start links to the running job; an engine without the HA commands asks for an update; python3-nacl and space in the engine\'s words; a cancelled check',
    haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false })] } }), async page => {
      await ready(page);
      await openHa(page, HA_PLAIN);
      await page.evaluate(job => window.__fixture.failures.push({ command: 'ha-check-start', code: 'busy',
        message: '已有備份或還原作業正在進行，請等它完成後再試。', details: { job_id: job } }), J_OTHER);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText('已有備份或還原作業正在進行').waitFor();
      assert.equal(await page.locator('.wizard-card [data-focus="error-busy-job"]').getAttribute('href'), `#/jobs/${J_OTHER}`);
      assert.equal(await activeStep(page), '選擇應用');
      await page.evaluate(() => window.__fixture.failures.push({ command: 'ha-check-start', code: 'invalid-request', message: '不支援的指令。' }));
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText('這台設備的備份元件版本還不能匯入 Home Assistant 的備份。請先把備份元件更新到與這個頁面相同的版本，再試一次。').waitFor();
      // The check job fails without python3-nacl: the engine's sentence as it is.
      await setScript(page, 'ha-check', [haFailedStep('ha-check', 'decrypt', { code: 'internal-error', message: NACL_MISSING })]);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText(NACL_MISSING).waitFor();
      assert.equal(await page.locator('.phase-failed .phase-label').textContent(), '解開 HA 備份');
      assert.equal(await activeStep(page), '檢查');
      // A check can be cancelled while it may be.
      await setScript(page, 'ha-check', Array.from({ length: 8 }, () => haStep('ha-check', 'decrypt', 30, { cancellable: true })));
      await page.locator('[data-focus="ha-job-retry"]').click();
      await page.locator('[data-focus="ha-job-cancel"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.equal(await page.locator('#confirm-title').textContent(), '取消檢查？');
      await page.locator('#confirm-ok').click();
      await page.locator('.wizard-card').getByText('已取消檢查。').waitFor();
      assert.equal(await activeStep(page), '選擇應用');
      assert.equal((await calls(page, 'job-cancel')).length, 1);
      // Too little space for the conversion.
      await setScript(page, 'ha-check', haScripts()['ha-check']);
      await setScript(page, 'ha-convert', [haFailedStep('ha-convert', 'convert', { code: 'insufficient-space', message: '可用空間不足：轉換需要約 2.4 GiB，這台目前可用 1.1 GiB。' })]);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor();
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('.wizard-card .notice-error').getByText('可用空間不足：轉換需要約 2.4 GiB，這台目前可用 1.1 GiB。').waitFor();
      await page.locator('.wizard-card').getByText('可刪除不需要的備份後再試。').waitFor();
      assert.equal(await activeStep(page), '轉換');
      await page.locator('[data-focus="ha-job-back"]').click();
      assert.equal(await activeStep(page), '結果與選項');
      assert.equal(await page.locator('#ha-db-0').isChecked(), true, 'the choices stay');
      // ha-delete on an engine without it.
      await page.locator('[data-focus="back-backups"]').click();
      await page.evaluate(() => window.__fixture.failures.push({ command: 'ha-delete', code: 'invalid-request', message: '不支援的指令。' }));
      await page.locator(`[data-focus="ha-delete-${HA_PLAIN}"]`).click();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error').getByText('這台設備的備份元件版本還不能匯入 Home Assistant 的備份。').waitFor();
      await page.locator('#confirm-cancel').click();
    });

  await check('從 HA 備份匯入 on an engine without it: no HA filter; an HA file is refused with a hint to update the 備份元件; #/ha/<id> says so',
    fixture({ failures: [{ command: 'upload-finish', code: 'not-a-backup', message: '這不是 woowtech 備份檔（.tar 或 .woowbackup）。' }] }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator('.backups-table').waitFor();
      assert.equal(await page.locator('[data-focus="filter-ha"]').count(), 0);
      await page.locator('[data-nav="restore"]').click();
      await page.locator('[data-focus="restore-file-button"]').waitFor();
      assert.equal(await page.getByText('也可以上傳 Home Assistant 的備份檔').count(), 0, 'an engine without HA imports is not offered them');
      await page.locator('#restore-file').setInputFiles({ name: 'woow_import_test.tar', mimeType: 'application/x-tar', buffer: Buffer.alloc(64 * KiB, 5) });
      await page.locator('[data-focus="restore-upload"]').click();
      await page.getByText('這不是 woowtech 備份檔（.tar 或 .woowbackup）。').waitFor();
      await page.getByText('如果這是 Home Assistant 的備份檔：這台設備的備份元件版本還不能匯入 HA 備份，請先更新備份元件，再上傳一次。').waitFor();
      await page.waitForFunction(() => window.testcalls.some(call => call.argv[1] === 'upload-abort'));
      assert.deepEqual((await calls(page, 'upload-abort')).map(requestOf), [{ upload_id: UPLOAD_ID }]);
      await page.evaluate(id => { window.location.hash = `#/ha/${id}`; }, HA_ID);
      await page.getByText('這台設備還不能匯入 HA 備份').waitFor();
      assert.equal((await calls(page, 'ha-check-start')).length, 0);
    });

  // ------------------------------------------------------------------ 從 HA 備份匯入, LiteLLM (owner decision 2026-11-23)

  await check('從 HA 備份匯入, LiteLLM: the check shows the versions, what moves, the salt that replaces this device\'s, and before a real import the apps here whose LiteLLM keys stop working',
    llFixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_LL}"]`).click();
      await page.locator('.ha-addons-table').waitFor();
      assert.equal(await page.locator('.view-title-text p.muted').textContent(),
        '從 Home Assistant 上傳的備份。可以把其中的 LiteLLM 匯入這台的應用；匯入前會先檢查內容與版本。');
      await page.locator(`[data-focus="ha-import-${HA_LL}"]`).click();
      assert.deepEqual(await page.locator('.wizard-card input[type="checkbox"]').evaluateAll(items => items.map(item => [item.id, item.checked, item.disabled])),
        [['ha-app-litellm', true, false]]);
      // What the entry must look like is said before the check (only when LiteLLM is in the backup).
      assert.deepEqual((await page.locator('aside[aria-labelledby="ha-side"] li').allTextContents()).slice(2, 4),
        ['兩邊的版本必須相同：LiteLLM 本身都要同一個版本。', LL_MODE_RULE]);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="litellm"]').waitFor();
      const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.deepEqual(start, { ha_backup_id: HA_LL, apps: ['litellm'], request_id: start.request_id });
      const card = page.locator('[data-ha-app="litellm"]');
      assert.equal(await card.locator('.muted').first().textContent(), 'HA 附加元件版本 0.1.15（LiteLLM 1.104.0），這台的 LiteLLM 1.104.0。');
      assert.equal(await card.locator('.chip').first().textContent(), '可以匯入');
      // The engine's words: the apps here that use LiteLLM keys (read from this device's catalog and configuration).
      assert.deepEqual(await card.locator('.check-warn .check-message').allTextContents(), [LL_KEYS_WARNING]);
      assert.deepEqual((await metadataOf(card))[0], { 虛擬金鑰: '1 把（不含管理介面的登入工作階段）', 使用者與團隊: '1 位使用者，1 個團隊',
        模型: '24 個（儲存的供應商憑證 5 筆）', 用量紀錄: '0 筆', 資料庫: 'HA 的 PostgreSQL 18 → 這台的 17（只搬資料列，結構用這台的）',
        '這台用 LiteLLM 金鑰的應用': 'Hermes 代理、OpenDesign（匯入後要重新設定金鑰）' });
      assert.equal(await card.locator('p.muted').last().textContent(),
        '匯入後，用這台 LiteLLM 的主金鑰與管理介面密碼登入（不是 HA 的）；HA 的加密金鑰會取代這台的 litellm-salt-key，還原失敗或之後還原到匯入前時會放回這台原本的。');
      // Before a real import (option A): the reminder under 「這只是測試」, nothing else changes.
      assert.equal(await page.locator('label[for="ha-test-mode"] strong').textContent(), '這只是測試');
      assert.equal(await page.locator('#ha-test-mode-help').textContent(),
        '勾選時，LiteLLM 不會先關掉任何功能，還原後會照常運作；正式搬家請不要勾。正式搬家時，這台 LiteLLM 原本的虛擬金鑰會換成 HA 的：Hermes 代理、OpenDesign 目前用的 LiteLLM 金鑰會失效，匯入後要為它們重新設定金鑰。');
      await page.locator('.wizard-card .notice-info').getByText('搬過來的帳號、金鑰和設定都來自這份 HA 備份，只匯入你信任的備份。').waitFor();
    });

  await check('從 HA 備份匯入, LiteLLM: with no other app using LiteLLM keys the reminder still says this device\'s keys stop working',
    llFixture({ check: llCheck({ ...LL_SECTION, key_users: [] }, []) }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_LL}"]`).click();
      await page.locator(`[data-focus="ha-import-${HA_LL}"]`).click();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="litellm"]').waitFor();
      const card = page.locator('[data-ha-app="litellm"]');
      assert.equal((await metadataOf(card))[0]['這台用 LiteLLM 金鑰的應用'], '沒有找到');
      assert.match(await page.locator('#ha-test-mode-help').textContent(),
        /正式搬家時，這台 LiteLLM 原本的虛擬金鑰會換成 HA 的，這台原本發出的金鑰都會失效（這台沒有找到其他使用 LiteLLM 金鑰的應用）。$/);
    });

  await check('從 HA 備份匯入, LiteLLM: an entry in another backup mode is refused by the check with what to choose and where',
    llFixture({ check: llBlockedCheck() }), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_LL}"]`).click();
      await page.locator(`[data-focus="ha-import-${HA_LL}"]`).click();
      await page.locator('[data-focus="ha-apps-next"]').click();
      const card = page.locator('[data-ha-app="litellm"]');
      await card.waitFor();
      assert.equal(await card.locator('.chip').first().textContent(), '無法匯入');
      assert.deepEqual(await card.locator('.check-fail .check-message').allTextContents(), [LL_MODE_BLOCKER]);
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true);
      assert.equal((await calls(page, 'ha-convert-start')).length, 0);
    });

  await check('應用設定, LiteLLM: the draft has the single-database mode chosen (what the HA import fills) and says why; it installs as it is',
    fixture({ catalogData: litellmCatalog() }), async page => {
      await ready(page);
      await page.locator('[data-nav="catalog"]').click();
      await page.locator('[data-focus="catalog-scan"]').click();
      await page.locator('[data-focus="draft-litellm"]').click();
      await page.locator('#catalog-feedback').getByText('檢查通過：可以安裝這份應用設定。').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'catalog-install'))[0]), { entry: litellmEntry('database') });
      assert.deepEqual(await page.locator('[data-focus^="variant-"]').evaluateAll(items => items.map(item => [item.dataset.focus, item.checked])),
        [['variant-cold', false], ['variant-instance', false], ['variant-database', true]]);
      const choices = await page.locator('section[aria-labelledby="draft-variants"] .choice strong').allTextContents();
      assert.deepEqual(choices, ['冷備份', '整個執行個體', '單一資料庫（建議）']);
      assert(!(await page.locator('section[aria-labelledby="draft-variants"]').textContent()).includes('（預設）'), 'cold is not the default here');
      assert.deepEqual(await page.locator('section[aria-labelledby="draft-notes"] .check-message').allTextContents(), [LL_MODE_NOTE]);
      assert.match((await metadataOf(page.locator('#catalog-review')))[0]['PostgreSQL'], /^單一資料庫 litellm（litellm-postgres）：以 pg_dump 匯出/);
      await page.locator('[data-focus="catalog-install"]').click();
      await page.locator('#confirm-ack').check();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-dialog').waitFor({ state: 'hidden' });
      const install = (await calls(page, 'catalog-install')).map(requestOf).filter(request => request.confirm);
      assert.deepEqual(install, [{ entry: litellmEntry('database'), confirm: true, expected_sha256: null }]);
    });

  // ------------------------------------------------------------------ 從 HA 備份匯入, batch 1 (2026-11-19, CONTRACT §7, §9)

  await check('從 HA 備份匯入, batch 1: the HA page offers Omnigent, Hermes, EMQX and Headscale; the check shows each app\'s versions, facts and warnings; the trust notice and the test choice say what applies',
    b1Fixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_B1}"]`).click();
      await page.locator('.ha-addons-table').waitFor();
      assert.equal(await page.locator('.view-title-text p.muted').textContent(),
        '從 Home Assistant 上傳的備份。可以把其中的 Odoo、n8n、Omnigent、Hermes、EMQX、Headscale 匯入這台的應用；匯入前會先檢查內容與版本。');
      const rows = await page.locator('.ha-addons-table tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
      assert.deepEqual(rows, [
        [`Odoo 18 CE${ODOO_SLUG}`, ODOO_ADDON_VERSION, '還沒安裝「Odoo 18」：這台還沒安裝，請先用它的安裝套件安裝並啟動，再到「應用設定」加入它'],
        [`WOOW n8n${N8N_SLUG}`, '2.43.6', '還沒安裝「n8n 工作流程」：這台還沒安裝，請先用它的安裝套件安裝並啟動，再到「應用設定」加入它'],
        ...B1_APPS.map(id => [`${B1[id].addon}${B1[id].slug}`, B1[id].version, `可以匯入這台的「${B1[id].app}」`]),
        ['Mosquitto brokercore_mosquitto', '6.5.1', '這台沒有對應的應用']]);
      await page.getByText('只有支援的 Odoo、n8n、Omnigent、Hermes、EMQX、Headscale、OpenDesign、code-server、Nextcloud、LiteLLM 附加元件能匯入這台；Home Assistant 本身和其他附加元件不會匯入。').waitFor();
      await page.locator(`[data-focus="ha-import-${HA_B1}"]`).click();
      assert.deepEqual(await page.locator('.stepper[aria-label="匯入步驟"] .step-label').allTextContents(), ['選擇應用', '檢查', '結果與選項', '轉換', '還原'],
        'HA did not encrypt these add-ons: no key step');
      assert.deepEqual(await page.locator('.wizard-card input[type="checkbox"]').evaluateAll(items => items.map(item => [item.id, item.checked, item.disabled])),
        [['ha-app-odoo', false, true], ['ha-app-n8n', false, true], ...B1_APPS.map(id => [`ha-app-${id}`, true, false])]);
      assert.equal(await page.locator('#ha-app-hermes-help').textContent(), '資料來自 HA 附加元件「Woow Hermes Agent」（版本 0.1.14）。');
      // What an import moves and needs: Odoo compares its modules, the other apps their own versions (CONTRACT §9).
      const side = await page.locator('aside[aria-labelledby="ha-side"] li').allTextContents();
      assert.deepEqual(side.slice(1, 3), [
        '會搬過來的有：資料、資料本身的金鑰，以及大多數應用的登入帳號；每個應用搬什麼、留什麼，檢查結果和還原前都會寫出來。這台的網址、連接埠、資料庫密碼和應用機密保持不變。',
        '兩邊的版本必須相同：Odoo 的每個模組，以及 n8n、Omnigent、Hermes、EMQX、Headscale 本身都要同一個版本。']);
      // The large members take longer (HA's own image in every EMQX and Headscale member, a Hermes home of several GB).
      assert.equal(await page.locator('.ha-slow').textContent(), 'Hermes、EMQX、Headscale 的附加元件檔案比較大，檢查和轉換會花比較久的時間。');
      for (const id of ['hermes', 'emqx', 'headscale']) await page.locator(`#ha-app-${id}`).uncheck();
      assert.equal(await page.locator('.ha-slow').count(), 0, 'Omnigent alone is quick');
      for (const id of ['hermes', 'emqx', 'headscale']) await page.locator(`#ha-app-${id}`).check();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="headscale"]').waitFor();
      const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.deepEqual(start, { ha_backup_id: HA_B1, apps: B1_APPS, request_id: start.request_id });
      const card = id => page.locator(`[data-ha-app="${id}"]`);
      // The add-on's own version, the product version it maps to, and this device's (the section's `<app>_version`).
      assert.deepEqual(await Promise.all(B1_APPS.map(id => card(id).locator('.muted').first().textContent())), [
        'HA 附加元件版本 0.1.23（Omnigent 0.21.0），這台的 Omnigent 0.21.0。',
        'HA 附加元件版本 0.1.14（Hermes 0.22.5），這台的 Hermes 0.22.5。',
        'HA 附加元件版本 5.9.1（EMQX 5.8.9），這台的 EMQX 5.8.9。',
        'HA 附加元件版本 0.1.3（Headscale 0.29.4），這台的 Headscale 0.29.4。']);
      for (const id of B1_APPS) {
        assert.equal(await card(id).locator('.chip').first().textContent(), '可以匯入', id);
        // The warnings to know before moving, as the engine words them: Hermes's HA addresses and plugins to pair again,
        // EMQX's API keys and hot backup, Headscale's API keys, Omnigent's settings that stay.
        assert.deepEqual(await card(id).locator('.check-warn .check-message').allTextContents(), B1_WARNINGS[id], id);
      }
      assert.deepEqual((await metadataOf(card('omnigent')))[0], { 使用者: '2 位（管理者 1 位）', 工作階段: '3 個', 代理程式: '1 個',
        排程: '2 個（啟用中 1 個）', 'Runner 主機': '1 台', 檔案: '1 個', 檔案區: '4 個檔案（3.0 MiB）' });
      assert.deepEqual((await metadataOf(card('hermes')))[0], { 對話: '5 個工作階段，15 則訊息', 技能: '64 個', 排程: '1 個', 外掛: 'omnigent、paseo',
        資料: '412 個檔案（96.0 MiB）', 'HA 的 .env': '12 項設定（這台 hermes.env 的同名設定優先）' });
      assert.deepEqual((await metadataOf(card('emqx')))[0], { 'MQTT 帳號': '3 個', 'ACL 規則': '4 條', 'Dashboard 帳號': '2 個', 'API 金鑰': '1 把',
        封鎖名單: '1 筆', 保留訊息: '2 則', 匿名連線: '不允許', 這台的授權: 'ACL 檔案＋內建資料庫',
        製作備份時: 'EMQX 正在執行或狀態不明' });
      assert.deepEqual((await metadataOf(card('headscale')))[0], { 使用者: '3 位', 裝置: '2 台', 預先授權金鑰: '2 把', 'API 金鑰': '2 把（不會搬過來）',
        'DNS 額外記錄': '1 筆', 'IP 位址範圍': '100.64.0.0/10、fd7a:115c:a1e0::/48', 'HA 的伺服器網址': 'https://ha-hs.example.com',
        這台的伺服器網址: 'https://hs.example.com' });
      // How to log in afterwards: Hermes keeps this device's password, Headscale's devices move to this device's server.
      assert.deepEqual(await Promise.all(B1_APPS.map(id => card(id).locator('p.muted').last().textContent())), [
        '只搬 HA 的資料，資料庫結構用這台 Omnigent 自己的。匯入後，用 HA 那邊 Omnigent 的帳號和密碼登入；這台的管理者與 runner 帳號會保留（和 HA 同名的帳號以 HA 的為準）。',
        '匯入後，用這台的 Hermes Dashboard 密碼登入（不是 HA 的）。',
        '匯入後，用 HA 那邊 EMQX Dashboard 的帳號和密碼登入；MQTT 裝置與服務要改連到這台。',
        '匯入後，每一台裝置的登入伺服器都要改成這台的 https://hs.example.com。']);
      assert.equal(await page.locator('.ha-databases').count(), 0);
      // What runs here, and what a test import really does for these apps: only Omnigent pauses anything.
      await page.locator('.wizard-card .notice-info').getByText('Omnigent 的代理程式和 Hermes 的技能與外掛是會在這台執行的程式，只匯入你信任的備份。').waitFor();
      assert.equal(await page.locator('label[for="ha-test-mode"] strong').textContent(), '這只是測試');
      assert.equal(await page.locator('#ha-test-mode-help').textContent(), '勾選時，Omnigent 的排程都先暫停；Hermes 的排程和訊息機器人不會暫停，'
        + '測試時請停掉 HA 那邊的 Hermes 附加元件，避免兩邊各做一次；EMQX、Headscale 不會先關掉任何功能，還原後會照常運作；正式搬家請不要勾。');
      await enabled(page, '[data-focus="ha-convert"]');
      await allWidths(page, 'batch 1 results and options');
      assert.deepEqual((await contrastOf(page)).failures, [], 'batch 1 results and options keep WCAG AA contrast');
      await shot(page, 'ha-b1-options-1440.png');
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-dialog').waitFor();
      assert.deepEqual((await metadataOf(page.locator('#confirm-body')))[0], {
        應用: '「Omnigent 協作平台」、「Hermes 代理」、「EMQX MQTT 代理」、「Headscale VPN 控制伺服器」', 這只是測試: '否' });
      assert.match(await page.locator('#confirm-body').textContent(), /Hermes、EMQX、Headscale 的附加元件檔案比較大，檢查和轉換會花比較久的時間。/);
      await page.locator('#confirm-cancel').click();
      assert.equal((await calls(page, 'ha-convert-start')).length, 0);
    });

  await check('從 HA 備份匯入, batch 2: OpenDesign is importable; its check card shows the core revision both sides share, what moves and how to log in afterwards',
    odFixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="ha-import-${HA_OD}"]`).click();
      await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
      assert.deepEqual(await page.locator('.wizard-card input[type="checkbox"]').evaluateAll(items => items.map(item => [item.id, item.checked, item.disabled])),
        [['ha-app-open-design', true, false]]);
      // The member holds the agents' logins and Paseo's runtime (decrypted and skipped): it takes longer.
      assert.equal(await page.locator('.ha-slow').textContent(), 'OpenDesign 的附加元件檔案比較大，檢查和轉換會花比較久的時間。');
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="open-design"]').waitFor();
      const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.deepEqual(start, { ha_backup_id: HA_OD, apps: ['open-design'], request_id: start.request_id });
      const card = page.locator('[data-ha-app="open-design"]');
      // `open-design_version` of the section is the product version the add-on ships.
      assert.equal(await card.locator('.muted').first().textContent(), 'HA 附加元件版本 0.2.15（OpenDesign 0.24.1），這台的 OpenDesign 0.24.1。');
      assert.equal(await card.locator('.chip').first().textContent(), '可以匯入');
      assert.deepEqual(await card.locator('.check-warn .check-message').allTextContents(), [OD_WARNING]);
      assert.deepEqual((await metadataOf(card))[0], { 專案: '12 個', 對話: '12 個，22 則訊息', 例行工作: '0 個（啟用中 0 個）',
        '外部 MCP 伺服器': '0 個', 資料: '77 個檔案（10.7 MiB）', 核心版本: 'HA 05b23f5a，這台 05b23f5a' });
      assert.equal(await card.locator('p.muted').last().textContent(),
        '匯入後，用這台的 OpenDesign 登入資料（帳號 open-design 與這台的 API 權杖）登入；代理程式的登入、Omnigent 與 Paseo 維持這台的。');
      // Skills, plugins and external MCP servers run here: only import a trusted backup.
      await page.locator('.wizard-card .notice-info').getByText('OpenDesign 的技能、外掛與外部 MCP 伺服器是會在這台執行的程式，只匯入你信任的備份。').waitFor();
      await enabled(page, '[data-focus="ha-convert"]');
      await allWidths(page, 'batch 2 OpenDesign results');
      assert.deepEqual((await contrastOf(page)).failures, [], 'the OpenDesign check card keeps WCAG AA contrast');
    });

  await check('從 HA 備份匯入, batch 2: code-server is importable; Cloudflare Tunnel and the MCP admin add-on are never moved and say what to do here; the check card shows what moves and the four program versions',
    csFixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${HA_CS}"]`).click();
      await page.locator('.ha-addons-table').waitFor();
      const rows = await page.locator('.ha-addons-table tbody tr').evaluateAll(items => items.map(row => [...row.children].map(cell => cell.textContent.trim())));
      assert.deepEqual(rows, [
        [`${CS.addon}${CS.slug}`, CS.version, `可以匯入這台的「${CS.app}」`],
        [`${CS_CF.name}${CS_CF.slug}`, CS_CF.version, '不會搬過來請在這台重新設定（見下方說明）'],
        [`${CS_MCP.name}${CS_MCP.slug}`, CS_MCP.version, '不會搬過來請在這台重新設定（見下方說明）']]);
      assert.deepEqual(await page.locator('section[aria-labelledby="ha-addons"] .ha-not-moved li').allTextContents(), [CS_CF_LINE, CS_MCP_LINE]);
      await page.locator(`[data-focus="ha-import-${HA_CS}"]`).click();
      await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
      assert.deepEqual(await page.locator('.wizard-card input[type="checkbox"]').evaluateAll(items => items.map(item => [item.id, item.checked, item.disabled])),
        [['ha-app-woow-code-server', true, false]]);
      assert.match(await page.locator('.wizard-card').textContent(), /其他附加元件（Woow Cloudflared、Woow Odoo MCP Server）這台沒有對應的應用，不會匯入。/);
      assert.deepEqual(await page.locator('.wizard-card .ha-not-moved li').allTextContents(), [CS_CF_LINE, CS_MCP_LINE]);
      assert.equal(await page.locator('.ha-slow').textContent(), 'code-server 的附加元件檔案比較大，檢查和轉換會花比較久的時間。');
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('#ha-key').fill(HA_KEY);
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('[data-ha-app="woow-code-server"]').waitFor();
      const start = requestOf((await calls(page, 'ha-check-start')).at(-1));
      assert.deepEqual(start, { ha_backup_id: HA_CS, apps: ['woow-code-server'], request_id: start.request_id, key: HA_KEY });
      const card = page.locator('[data-ha-app="woow-code-server"]');
      // `woow-code-server_version` of the section is the code-server version the add-on ships.
      assert.equal(await card.locator('.muted').first().textContent(), 'HA 附加元件版本 0.1.14（code-server 4.139.1），這台的 code-server 4.139.1。');
      assert.equal(await card.locator('.chip').first().textContent(), '可以匯入');
      assert.deepEqual(await card.locator('.check-warn .check-message').allTextContents(), CS_WARNINGS);
      assert.deepEqual((await metadataOf(card))[0], { 代理程式對話: 'Pi 28 個、Claude Code 20 個、Codex 15 個（只能查看）', 技能: '3 個',
        'VS Code': '設定（合併）、1 個程式碼片段、0 個自己安裝的延伸模組', '共用 MCP 伺服器': '9 個',
        工作區: '這份備份沒有包含 share 資料夾，不會搬過來', 資料: '386 個檔案（16.8 MiB）',
        程式版本: 'code-server 4.139.1、Pi 0.99.1、Claude Code 2.1.285、Codex 0.167.0' });
      assert.equal(await card.locator('p.muted').last().textContent(),
        '匯入後，用這台 code-server 的密碼登入；Pi、Claude Code、Codex 沿用這台的登入，Omnigent 與 Paseo 連接器維持這台的。');
      await page.locator('.wizard-card .notice-info').getByText('code-server 的延伸模組、技能與共用 MCP 伺服器是會在這台執行的程式，只匯入你信任的備份。').waitFor();
      await enabled(page, '[data-focus="ha-convert"]');
      await allWidths(page, 'batch 2 code-server results');
      assert.deepEqual((await contrastOf(page)).failures, [], 'the code-server check card keeps WCAG AA contrast');
    });

  await check('從 HA 備份匯入, batch 2: Nextcloud with HA\'s share folder is importable; the check card shows the users, the users\' files from the share folder, shares, calendars, custom apps, Office and both URLs',
    ncFixture(), async page => {
      const card = await openNc(page);
      assert.equal(await card.locator('.muted').first().textContent(), 'HA 附加元件版本 0.2.3（Nextcloud 35.0.1.1），這台的 Nextcloud 35.0.1.1。');
      assert.equal(await card.locator('.chip').first().textContent(), '可以匯入');
      assert.deepEqual(await card.locator('.check-warn .check-message').allTextContents(), NC_WARNINGS);
      assert.deepEqual((await metadataOf(card))[0], NC_FACTS);
      assert.equal(await card.locator('p.muted').last().textContent(),
        '匯入後，用 HA 那邊 Nextcloud 的帳號和密碼登入；同步用戶端與行事曆、聯絡人要改連到這台的 http://192.0.2.46:18081。');
      await page.locator('.wizard-card .notice-info').getByText('Nextcloud 的自訂應用是會在這台執行的程式，只匯入你信任的備份。').waitFor();
      await enabled(page, '[data-focus="ha-convert"]');
      await allWidths(page, 'batch 2 Nextcloud results');
      assert.deepEqual((await contrastOf(page)).failures, [], 'the Nextcloud check card keeps WCAG AA contrast');
    });

  await check('從 HA 備份匯入, batch 2: Nextcloud without HA\'s share folder is refused with the engine\'s sentence (the users\' files are not in the backup); the card says where they were and convert stays disabled',
    ncFixture({ share: false }), async page => {
      const card = await openNc(page);
      assert.match(await card.getAttribute('class'), /is-blocked/);
      assert.equal(await card.locator('.chip').first().textContent(), '無法匯入');
      assert.deepEqual(await card.locator('.check-fail .check-message').allTextContents(), [NC_NO_SHARE]);
      const facts = (await metadataOf(card))[0];
      assert.equal(facts['使用者檔案'], '不在這份備份裡（/share/nextcloud）');
      assert.equal(facts['使用者'], '3 位');
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true);
      await page.getByText('沒有應用通過檢查，無法轉換。請依上面的說明處理後按「重新檢查」，或按「上一步」改選其他應用。').waitFor();
      assert.equal((await calls(page, 'ha-convert-start')).length, 0);
      await allWidths(page, 'batch 2 Nextcloud refused');
      assert.deepEqual((await contrastOf(page)).failures, [], 'the refused Nextcloud card keeps WCAG AA contrast');
    });

  await check('從 HA 備份匯入, batch 1: convert and restore; the notice says what each app replaces and keeps; the result lists each app\'s to-dos (Headscale\'s devices, Hermes\'s Omnigent and Paseo pairing, the engine\'s MCP lines) and no MCP line of the page; 由 HA 轉換 and 活動紀錄',
    b1Fixture(), async page => {
      await ready(page);
      await openB1(page);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="headscale"]').waitFor();
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_B1, { timeout: 15000 });
      await page.locator('.app-preflight').first().waitFor();
      const convert = requestOf((await calls(page, 'ha-convert-start')).at(-1));
      assert.deepEqual(convert, { ha_backup_id: HA_B1, apps: B1_APPS, test_mode: false, confirm: true, request_id: convert.request_id },
        'no Odoo database, no key, no new option');
      // What is replaced and what stays: the engine's line per app, never 「登入帳號」 or 「設定檔」 for all of them.
      assert.deepEqual(await page.locator('.ha-banner li').allTextContents(), [
        '還原會用 HA 的資料取代這台「Omnigent 協作平台」、「Hermes 代理」、「EMQX MQTT 代理」、「Headscale VPN 控制伺服器」目前的資料；'
          + '這台的網址、連接埠、資料庫密碼和應用機密都保持不變，各應用換掉和保留的內容如下。',
        ...B1_APPS.flatMap(id => HA_NOTES[id]),
        '開始前會先自動保存一份這台目前的資料（還原前備份）；還原失敗會自動回復。',
        '還原完成後，請把 HA 那邊的「Woow Omnigent」、「Woow Hermes Agent」、「Woow EMQX」、「Woow Headscale VPN」附加元件停掉，避免同一件事兩邊各做一次。']);
      assert.equal(await page.locator('.app-preflight').count(), 4);
      await shot(page, 'ha-b1-restore-preflight-1440.png');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      // The page's stop lines, then the engine's to-dos of each app (its MCP lines included), then the HA file.
      const reminders = await page.locator('.ha-reminders li').allTextContents();
      assert.deepEqual(reminders, [...B1_STOP_LINES, ...B1_APPS.flatMap(id => HA_TODO[id]), B1_DELETE_LINE]);
      assert(reminders.includes(HEADSCALE_REPOINT), 'Headscale: every device moves to this device\'s server');
      assert(reminders.includes(HERMES_REPAIR), 'Hermes: Omnigent and Paseo are paired again');
      assert(!reminders.some(line => line.endsWith('的登入資料。')), 'no MCP line of the page\'s own: the engine writes them for these apps');
      assert.equal(await page.locator('.job-result .workflow-list').count(), 0);
      await allWidths(page, 'batch 1 restore result');
      await shot(page, 'ha-b1-restore-result-1440.png');
      // The converted backup.
      await page.locator('[data-nav="backups"]').click();
      const row = page.locator(`tr[data-backup="${B_B1}"]`);
      await row.waitFor();
      assert.equal(await row.locator('td[data-label="類型"]').textContent(), '手動由 HA 轉換');
      await page.locator(`[data-focus="open-${B_B1}"]`).click();
      const source = page.locator('section[aria-labelledby="detail-ha"]');
      await source.locator('dl.metadata').first().waitFor();
      const names = B1_APPS.map(id => B1[id].app).join('、');
      const [origin] = await metadataOf(source);
      assert.deepEqual([origin['HA 備份'], origin['應用'], origin['Odoo 資料庫'], origin['這只是測試']], [B1_NAME, names, undefined, '否']);
      assert.equal(await source.locator('.card-head .chip').count(), 0, 'not a test import');
      // 活動紀錄 names the jobs and their apps; the conversion's job view says what it made.
      await page.locator('[data-nav="activity"]').click();
      await page.waitForFunction(name => document.querySelector('.jobs-table')?.textContent.includes(name), B1_NAME);
      const jobs = await page.locator('.jobs-table tbody tr').evaluateAll(items => items.map(item => [item.querySelector('[data-label="作業"]').textContent,
        item.querySelector('[data-label="內容"]').textContent, item.querySelector('[data-label="結果"]').textContent]));
      assert.deepEqual(jobs, [['還原', `${names} · 備份 ${B_B1}`, '已完成'], ['轉換 HA 備份', `${names} · HA 備份「${B1_NAME}」`, '已完成'],
        ['檢查 HA 備份', `${names} · HA 備份「${B1_NAME}」`, '已完成']]);
      await page.locator('.jobs-table tbody tr').filter({ hasText: '轉換 HA 備份' }).locator('a.row-title').click();
      await page.locator('#result-heading').filter({ hasText: 'HA 備份已轉換' }).waitFor();
      assert.deepEqual((await metadataOf(page.locator('.job-result')))[0], { 備份: B_B1, 應用: names, 這只是測試: '否' });
      await page.waitForFunction(name => document.querySelector('section[aria-labelledby="job-params-heading"]')?.textContent.includes(name), B1_NAME);
      assert.deepEqual((await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0],
        { 作業類型: '轉換 HA 備份', 'HA 備份': B1_NAME, 應用: names, 這只是測試: '否' });
    });

  await check('從 HA 備份匯入, batch 1 test import: Omnigent\'s schedules pause and Hermes keeps running (HA\'s add-on is stopped instead); the choice, the confirmation, the restore notice, the result, the converted backup and its job never say everything is off',
    b1Fixture({ testMode: true }), async page => {
      await ready(page);
      await openB1(page);
      for (const id of ['emqx', 'headscale']) await page.locator(`#ha-app-${id}`).uncheck();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="hermes"]').waitFor();
      assert.deepEqual(requestOf((await calls(page, 'ha-check-start')).at(-1)).apps, ['omnigent', 'hermes']);
      assert.equal(await page.locator('[data-ha-app="emqx"]').count(), 0, 'only the chosen apps are shown');
      assert.equal(await page.locator('label[for="ha-test-mode"] strong').textContent(), '這只是測試');
      assert.equal(await page.locator('#ha-test-mode-help').textContent(), '勾選時，Omnigent 的排程都先暫停；Hermes 的排程和訊息機器人不會暫停，'
        + '測試時請停掉 HA 那邊的 Hermes 附加元件，避免兩邊各做一次；正式搬家請不要勾。');
      await page.locator('#ha-test-mode').check();
      await page.locator('[data-focus="ha-convert"]').click();
      assert.equal((await metadataOf(page.locator('#confirm-body')))[0]['這只是測試'], '是：Omnigent 的排程會先關掉；Hermes 不會關掉任何功能');
      await page.locator('#confirm-ok').click();
      await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_B1, { timeout: 15000 });
      await page.locator('.app-preflight').first().waitFor();
      const convert = requestOf((await calls(page, 'ha-convert-start')).at(-1));
      assert.deepEqual([convert.apps, convert.test_mode], [['omnigent', 'hermes'], true]);
      assert.equal(await page.locator('.app-preflight').count(), 2, 'the converted backup holds the two apps');
      const testLine = '這是測試匯入：Omnigent 的排程都已暫停；Hermes 的排程和訊息機器人不會暫停，測試時請停掉 HA 那邊的 Hermes 附加元件，'
        + '避免兩邊各做一次。要正式搬過來時，請重新匯入一次，並且不要勾「這只是測試」。';
      const banner = await page.locator('.ha-banner').textContent();
      assert(banner.includes(testLine), banner);
      for (const claim of ['會自動執行的功能都已先關掉', 'HA 那邊可以照常使用', '排程、寄信和工作流程']) assert(!banner.includes(claim), `never claims ${claim}`);
      assert(banner.includes(HA_NOTES.hermes[1]), 'the engine\'s notes of the converted apps');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
      // The engine says how many schedules the test paused; Hermes's to-dos still ask for the pairing again.
      assert.deepEqual(await page.locator('.ha-reminders li').allTextContents(), [testLine, ...HA_TODO_TEST.omnigent, ...HA_TODO.hermes, B1_DELETE_LINE]);
      await page.locator('[data-nav="backups"]').click();
      await page.locator(`[data-focus="open-${B_B1}"]`).click();
      const card = page.locator('section[aria-labelledby="detail-ha"]');
      await card.locator('dl.metadata').first().waitFor();
      assert.equal((await metadataOf(card))[0]['這只是測試'], '是：Omnigent 的排程已先關掉；Hermes 不會關掉任何功能');
      assert.equal(await card.locator('.card-head .chip').textContent(), '測試匯入');
      await page.locator('[data-nav="activity"]').click();
      await page.locator('.jobs-table tbody tr').filter({ hasText: '轉換 HA 備份' }).locator('a.row-title').click();
      await page.locator('#result-heading').filter({ hasText: 'HA 備份已轉換' }).waitFor();
      assert.equal((await metadataOf(page.locator('.job-result')))[0]['這只是測試'], '是（Omnigent 的排程已先關掉；Hermes 不會關掉任何功能）');
      await page.waitForFunction(name => document.querySelector('section[aria-labelledby="job-params-heading"]')?.textContent.includes(name), B1_NAME);
      assert.equal((await metadataOf(page.locator('section[aria-labelledby="job-params-heading"]')))[0]['這只是測試'],
        '是（Omnigent 的排程會先關掉；Hermes 不會關掉任何功能）');
    });

  await check('從 HA 備份匯入, batch 1: a hot EMQX backup whose database did not load is refused with the engine\'s advice to stop the add-on and back up again; a conversion refused the same way keeps the choices',
    b1Fixture({ check: b1Check({ emqx: emqxHalfLoaded() }) }), async page => {
      await ready(page);
      await openB1(page);
      for (const id of ['omnigent', 'hermes', 'headscale']) await page.locator(`#ha-app-${id}`).uncheck();
      assert.equal(await page.locator('.ha-slow').textContent(), 'EMQX 的附加元件檔案比較大，檢查和轉換會花比較久的時間。');
      await page.locator('[data-focus="ha-apps-next"]').click();
      const emqx = page.locator('[data-ha-app="emqx"]');
      await emqx.waitFor();
      assert.match(await emqx.getAttribute('class'), /is-blocked/);
      assert.equal(await emqx.locator('.chip').first().textContent(), '無法匯入');
      assert.deepEqual(await emqx.locator('.check-fail .check-message').allTextContents(), [EMQX_HALF_LOADED]);
      assert.match(await emqx.textContent(), /請先在 HA 停止 EMQX 附加元件，再重新製作備份後匯入/, 'the engine\'s advice, as it is');
      // The check stopped at HA's broker: no section, so neither this device's version nor facts.
      assert.equal(await emqx.locator('.muted').first().textContent(), 'HA 附加元件版本 5.9.1。');
      assert.equal(await emqx.locator('dl.metadata').count(), 0);
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true);
      await page.getByText('沒有應用通過檢查，無法轉換。請依上面的說明處理後按「重新檢查」，或按「上一步」改選其他應用。').waitFor();
      // EMQX alone brings no code, and a test import turns nothing of it off.
      await page.locator('.wizard-card .notice-info').getByText('搬過來的帳號、金鑰和設定都來自這份 HA 備份，只匯入你信任的備份。').waitFor();
      assert.equal(await page.locator('#ha-test-mode-help').textContent(), '勾選時，EMQX 不會先關掉任何功能，還原後會照常運作；正式搬家請不要勾。');
      // Backed up again: HA's database loads, so the check passes with the hot-backup warning; EMQX's own import still
      // fails, and the conversion is refused with the same advice.
      await setScript(page, 'ha-check', haScripts({ check: b1Check() })['ha-check']);
      await setScript(page, 'ha-convert', [haFailedStep('ha-convert', 'convert', { code: 'incompatible', message: EMQX_IMPORT_FAILED })]);
      await page.locator('[data-focus="ha-recheck"]').click();
      await page.locator('[data-ha-app="emqx"]:not(.is-blocked)').waitFor();
      assert.deepEqual(await page.locator('[data-ha-app="emqx"] .check-warn .check-message').allTextContents(), B1_WARNINGS.emqx);
      assert.equal((await metadataOf(page.locator('[data-ha-app="emqx"]')))[0]['製作備份時'], 'EMQX 正在執行或狀態不明');
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('.wizard-card .notice-error').getByText(EMQX_IMPORT_FAILED).waitFor();
      assert.equal(await activeStep(page), '轉換');
      await page.locator('[data-focus="ha-job-back"]').click();
      assert.equal(await activeStep(page), '結果與選項');
      await enabled(page, '[data-focus="ha-convert"]');
      // 活動紀錄 keeps both: the refused check with its blocker, the failed conversion with the engine's words.
      await page.locator('[data-nav="activity"]').click();
      await page.waitForFunction(name => document.querySelector('.jobs-table')?.textContent.includes(name), B1_NAME);
      const failed = page.locator('.jobs-table tbody tr').filter({ hasText: '轉換 HA 備份' });
      assert.equal(await failed.locator('[data-label="結果"]').textContent(), EMQX_IMPORT_FAILED);
      await page.locator('.jobs-table tbody tr').filter({ hasText: '檢查 HA 備份' }).last().locator('a.row-title').click();
      await page.locator('#result-heading').filter({ hasText: 'HA 備份檢查完成' }).waitFor();
      assert.match(await page.locator('.job-result').textContent(), /有應用沒有通過檢查，要先處理下列問題才能匯入。/);
      assert.equal(await page.locator('.job-result [data-ha-app="emqx"] h4').textContent(), 'EMQX MQTT 代理 無法匯入');
      assert.equal(await page.locator('.job-result [data-ha-app="emqx"] .check-fail .check-message').textContent(), EMQX_HALF_LOADED);
    });

  // SR-5 (owner decision 2026-11-24, option C): the engine's texts (ha_emqx.ACCOUNTS_STOP for dev-d's woow, ha_emqx.PLAIN_REFUSED).
  const EMQX_HASH_WARNING = 'HA 的 EMQX 保存 MQTT 密碼的方式（bcrypt）和這台（sha256，鹽在後）不同，匯入後以 HA 的為準：這台現有的 MQTT 帳號（woow）匯入後無法再用原本的密碼登入，要在匯入後重新設定：到這台 EMQX 管理頁「存取控制 → 認證」的內建資料庫替這些帳號重設密碼或重新建立；由這台 bootstrap 帳號檔建立的帳號，刪除後重新啟動 EMQX 就會用原本的密碼建回。';
  const EMQX_PLAIN = 'HA 的 EMQX 用「plain」（不加密）的方式保存 MQTT 帳號的密碼，搬過來會把明文密碼留在這台，所以不能匯入。請先在 HA 的 EMQX 管理頁「存取控制 → 認證」把內建資料庫的密碼雜湊方式（password_hash_algorithm）改成 plain 以外的方式（例如 sha256 並加鹽，或 bcrypt），再替每個 MQTT 帳號重新設定一次密碼（EMQX 不會轉換已經存好的密碼，沒有重設的帳號在改完後就無法登入），然後重新製作 HA 備份再匯入。';
  const emqxChecked = changes => ({ app_id: 'emqx', slug: B1.emqx.slug, name: B1.emqx.addon, arch: 'aarch64', version: B1.emqx.version,
    target_version: B1.emqx.product, ok: true, blockers: [], warnings: [...B1_WARNINGS.emqx], emqx: structuredClone(B1_SECTIONS.emqx), ...changes });
  await check('從 HA 備份匯入, batch 1: SR-5 — a different MQTT password hashing is a warning that names this device\'s accounts before any conversion (the conversion stays possible); HA\'s plain hashing is refused and the conversion cannot start',
    b1Fixture({ check: b1Check({ emqx: emqxChecked({ warnings: [...B1_WARNINGS.emqx, EMQX_HASH_WARNING] }) }) }), async page => {
      await ready(page);
      await openB1(page);
      for (const id of ['omnigent', 'hermes', 'headscale']) await page.locator(`#ha-app-${id}`).uncheck();
      await page.locator('[data-focus="ha-apps-next"]').click();
      const emqx = page.locator('[data-ha-app="emqx"]:not(.is-blocked)');
      await emqx.waitFor();
      assert.equal(await emqx.locator('.chip').first().textContent(), '可以匯入');
      assert.deepEqual(await emqx.locator('.check-warn .check-message').allTextContents(), [...B1_WARNINGS.emqx, EMQX_HASH_WARNING],
        'the warning, as the engine words it, with the account names, shown before the conversion');
      assert.equal(await emqx.locator('.check-fail').count(), 0);
      await enabled(page, '[data-focus="ha-convert"]');
      await setScript(page, 'ha-check', haScripts({ check: b1Check({ emqx: emqxChecked({ ok: false, blockers: [EMQX_PLAIN] }) }) })['ha-check']);
      await page.locator('[data-focus="ha-recheck"]').click();
      const refused = page.locator('[data-ha-app="emqx"].is-blocked');
      await refused.waitFor();
      assert.equal(await refused.locator('.chip').first().textContent(), '無法匯入');
      assert.deepEqual(await refused.locator('.check-fail .check-message').allTextContents(), [EMQX_PLAIN]);
      assert.match(await refused.textContent(), /替每個 MQTT 帳號重新設定一次密碼/, 'the engine\'s advice, as it is');
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), true);
    });

  const haLong = (() => {
    const slug = `local_${'x'.repeat(70)}`;
    const addon = { slug, name: 'Very Long Add-on Name '.repeat(6).trim(), version: `1.0.0-${'9'.repeat(48)}` };
    const meta = haMeta(HA_ID, { name: `<img src=x onerror=alert(1)> ${'很長的 HA 備份名稱'.repeat(10)}`,
      filename: `${'very-long-home-assistant-backup-file-name-'.repeat(5)}.tar`, folders: ['share', 'ssl', 'media', 'addons_local'] });
    meta.addons.push(addon);
    meta.other_addons.push(addon);
    const data = haFixture({ ha: { backups: [meta] } });
    const long = haCheck({ databases: [odooDb(`woowtest_${'x'.repeat(64)}`), odooDb('archive'), blockedDb()],
      n8n: { n8n: { owner_email: `${'owner'.repeat(12)}@example.com`, workflows: 14, workflows_active: 6, credentials: 9, executions: 1520, users: 2,
        community_packages: [{ name: 'n8n-nodes-mqtt-x', version: '1.4.2' }, { name: `n8n-nodes-${'long'.repeat(20)}`, version: '0.0.1' }],
        workflows_to_fix: [...WORKFLOWS_TO_FIX, { name: '很長的工作流程名稱'.repeat(8), active: true, reasons: ['https://homeassistant.local:8123/api/states/'.repeat(4)] }] } } });
    Object.assign(data.scripts, haScripts({ check: long }));
    return data;
  })();
  await check('從 HA 備份匯入 screens fit 1440 to 320 px without horizontal scrolling, render HA text literally and keep WCAG AA contrast', haLong, async page => {
    await ready(page);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`tr[data-ha="${HA_ID}"]`).waitFor();
    await allWidths(page, 'list with an HA backup');
    await page.locator(`[data-focus="open-${HA_ID}"]`).click();
    await page.locator('.ha-addons-table').waitFor();
    assert.equal(await page.locator('#view img').count(), 0, 'HA text never becomes markup');
    assert.match(await page.locator('#view-heading').textContent(), /^<img src=x onerror=alert\(1\)> 很長的 HA 備份名稱/);
    await allWidths(page, 'HA backup page');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'ha-backup-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator(`[data-focus="ha-import-${HA_ID}"]`).click();
    await allWidths(page, 'import: choose apps');
    await page.locator('[data-focus="ha-apps-next"]').click();
    await page.locator('#ha-key').fill(HA_KEY);
    await allWidths(page, 'import: key');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'ha-import-key-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('[data-focus="ha-key-next"]').click();
    await page.locator('.phase-label').first().waitFor();
    await allWidths(page, 'import: check');
    await page.locator('[data-ha-app="n8n"]').waitFor();
    await allWidths(page, 'import: results and options');
    assert.deepEqual((await contrastOf(page)).failures, [], 'results and options keep WCAG AA contrast');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'ha-import-options-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.locator('#ha-db-1').check();
    await page.locator('[data-focus="ha-convert"]').click();
    await page.locator('#confirm-dialog').waitFor();
    await allWidths(page, 'import: convert dialog');
    await page.locator('#confirm-ok').click();
    await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_HA, { timeout: 15000 });
    await page.locator('.app-preflight').first().waitFor();
    await allWidths(page, 'restore with the HA notice');
    assert.deepEqual((await contrastOf(page)).failures, [], 'the HA notice keeps WCAG AA contrast');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    await allWidths(page, 'restore result with the HA reminders');
    await page.setViewportSize({ width: 390, height: 900 });
    await shot(page, 'ha-restore-result-390.png');
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  await check('從 HA 備份匯入 in the dark theme: the HA page, the results and options, the restore notice and its result keep WCAG AA contrast', haFixture(), async page => {
    await ready(page);
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark')), true);
    await page.locator('[data-nav="backups"]').click();
    await page.locator(`[data-focus="open-${HA_ID}"]`).click();
    await page.locator('.ha-addons-table').waitFor();
    assert.deepEqual((await contrastOf(page)).failures, [], 'HA backup page');
    await page.locator(`[data-focus="ha-import-${HA_ID}"]`).click();
    await page.locator('[data-focus="ha-apps-next"]').click();
    await page.locator('#ha-key').fill(HA_KEY);
    await page.locator('[data-focus="ha-key-next"]').click();
    await page.locator('[data-ha-app="n8n"]').waitFor();
    assert.deepEqual((await contrastOf(page)).failures, [], 'results and options');
    await page.locator('#ha-test-mode').check();
    assert.deepEqual((await contrastOf(page)).failures, [], 'a ticked choice');
    await page.locator('[data-focus="ha-convert"]').click();
    await page.locator('#confirm-ok').click();
    await page.waitForFunction(id => window.location.hash === `#/restore/${id}`, B_HA, { timeout: 15000 });
    await page.locator('.app-preflight').first().waitFor();
    assert.deepEqual((await contrastOf(page)).failures, [], 'restore with the HA notice');
    await page.locator('[data-focus="pf-next"]').click();
    await page.locator('#confirm-restore').check();
    await page.locator('[data-focus="confirm-start"]').click();
    await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor();
    assert.deepEqual((await contrastOf(page)).failures, [], 'restore result with the HA reminders');
    await shot(page, 'ha-restore-result-dark-1440.png');
  }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  // ================================================================ 從 HA 備份匯入, HAOS parity: one confirmation (schema 2)

  // Opens the wizard of the HA backup, leaves out Hermes (it has no result in the shared check script) and starts the check.
  const v2Check1 = async (page, { keep = [] } = {}) => {
    await openHa(page, HA_V2);
    for (const id of ['odoo', 'n8n', 'emqx', 'hermes']) {
      if (!keep.includes(id)) await page.locator(`#ha-app-${id}`).uncheck();
    }
    await page.locator('[data-focus="ha-apps-next"]').click();
    await page.locator('[data-summary="check"]').waitFor({ timeout: 30000 });
  };
  const v2Lines = page => page.locator('#ha-confirm-list > li').evaluateAll(items => items.map(item => ({
    label: item.querySelector('.ha-issue-label')?.textContent ?? null, text: item.querySelector('.ha-issue-text')?.textContent ?? null,
    names: [...item.querySelectorAll('.ha-names li')].map(name => name.textContent) })));
  const v2Import = page => page.locator('[data-focus="ha-import"]');

  await check('HAOS 一次確認: the check says what can and cannot be imported, the one confirmation lists every line, one tick starts the import and each app has its own result',
    v2Fixture({ outcomes: { n8n: { restore: 'rolled-back' } } }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n', 'emqx'] });
      // The steps of the new flow; no key step (nothing is encrypted); the check sent no choices.
      assert.deepEqual(await page.locator('.stepper[aria-label="匯入步驟"] .step-label').allTextContents(), ['選擇應用', '檢查', '結果與確認', '匯入']);
      assert.equal(await activeStep(page), '結果與確認');
      const check1 = (await calls(page, 'ha-check-start')).map(requestOf);
      assert.equal(check1.length, 1);
      assert.equal(check1[0].choices, undefined, 'the first check carries no choices');
      // One app that cannot go never stops the others (UI-14): counts, the reason with what to do, the card is out of the import.
      assert.equal(await page.locator('[data-summary="check"]').textContent(), '可以匯入 2 個，不能匯入 1 個');
      const emqx = page.locator('[data-ha-app="emqx"]');
      assert.equal(await emqx.getAttribute('data-importable'), 'no');
      assert.match(await emqx.textContent(), /不能匯入/);
      assert.match(await emqx.textContent(), /這份備份是在 EMQX 執行中做的，內建資料庫可能只寫了一半，不能匯入。/);
      assert.match(await emqx.textContent(), /請先在 HA 停止 EMQX 附加元件，再重新做備份後匯入。/);
      assert.match(await emqx.textContent(), /這次不會匯入這個應用，這台的它也不會有任何變更；其他應用照常匯入。/);
      assert.equal(await page.locator('[data-ha-app="odoo"]').getAttribute('data-importable'), 'yes');
      // The databases: the ones that can move are chosen by the customer, the one that cannot says why (UI-19, UI-16).
      assert.equal(await page.locator('#ha-db-0').isDisabled(), false);
      assert.equal(await page.locator('#ha-db-1').isDisabled(), false);
      assert.equal(await page.locator('#ha-db-2').isDisabled(), true, 'only the database with a real reason cannot be chosen');
      assert.equal(await page.locator('#ha-db-0').isChecked(), false, 'two can move: the customer chooses');
      assert.match(await page.locator('[data-database="demo-old"]').textContent(), /缺少模組 website_sale_extra，不能搬。/);
      assert.equal(await v2Import(page).isDisabled(), true);
      await page.getByText('請先選擇要搬過來的 Odoo 資料庫。').waitFor();
      // Nothing is listed twice and the confirmation holds no line of another database or of the app that cannot go.
      await page.locator('#ha-db-0').check();
      const lines = await v2Lines(page);
      assert.deepEqual(lines.map(line => line.label), ['全部', 'Odoo', '全部', 'Odoo', 'n8n']);
      assert.equal(lines[0].text, '匯入會取代這台這 2 個應用現在的資料。匯入前會自動各做一份備份，失敗會自動退回。');
      assert.equal(lines[1].text, 'HA 有 3 個資料庫。這次搬「prod」；「test」、「demo-old」會留在 HA，HA 停用後就看不到了。這台 Odoo 一次只放一個資料庫，以後再匯入另一個會取代這次的。');
      assert.deepEqual(lines[2], { label: '全部', text: V2_PAUSES.message, names: ['檔案管理 filebrowser', 'code-server'] });
      assert.deepEqual(lines[3], { label: 'Odoo', text: V2_ODOO_MODULES.message, names: ['website_sale_extra'] });
      assert.deepEqual(lines[4], { label: 'n8n', text: V2_N8N_KEY.message, names: [] });
      assert.equal(await page.locator('#ha-confirm-list').textContent().then(text => text.includes('EMQX')), false);
      // What the system does and what to know afterwards are listed under the app and need no tick.
      assert.match(await page.locator('[data-ha-app="odoo"]').textContent(), /系統會自動做[\s\S]*系統會先把資料庫啟動起來讀/);
      assert.match(await page.locator('[data-ha-app="n8n"]').textContent(), /匯入後請留意[\s\S]*HA 的 n8n 裝了 1 個社群節點/);
      // Without the tick nothing starts; the tick is one checkbox described by the list; another database is another confirmation.
      assert.equal(await v2Import(page).isDisabled(), true);
      assert.equal(await page.locator('#ha-ack').getAttribute('aria-describedby'), 'ha-confirm-list');
      await page.locator('#ha-ack').check();
      assert.equal(await v2Import(page).isDisabled(), false);
      await page.locator('#ha-db-1').check();
      assert.equal(await page.locator('#ha-ack').isChecked(), false, 'a different database has other lines: the tick is gone');
      assert.equal(await v2Import(page).isDisabled(), true);
      assert.deepEqual((await v2Lines(page)).map(line => line.names), [[], [], ['檔案管理 filebrowser', 'code-server'], ['sale_extra', 'stock_extra'], []]);
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      const checkJob = (await calls(page, 'ha-check-start')).length;
      await v2Import(page).click();
      // The app that cannot go is a row of the import from its start (not only of its result), with its reason.
      await page.locator('.ha-group-list').waitFor({ timeout: 30000 });
      assert.equal(await page.locator('[data-result="group"]').count(), 0, 'the import is still running');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="emqx"]').getAttribute('data-status'), 'excluded');
      assert.match(await page.locator('.ha-group-row[data-ha-app="emqx"]').textContent(), /這份備份是在 EMQX 執行中做的/);
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      // The request: the whole import, the one confirmation by its keys, the database; the HA backup is not touched twice.
      const starts = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.equal(starts.length, 1);
      const { request_id: requestId1, check_job_id: checkJobId, ...rest } = starts[0];
      assert.match(requestId1, /^[0-9a-f-]{36}$/);
      assert.match(checkJobId, /^j\d{8}T\d{6}Z-[0-9a-f]{8}$/, 'the audit knows which check the customer saw');
      assert.deepEqual(rest, { ha_backup_id: HA_V2, apps: ['odoo', 'n8n'], test_mode: false, then_restore: true, confirm: true, overwrite: true,
        acknowledged: { _shared: [V2_PAUSES.key], odoo: [V2_ODOO_MODULES.key], n8n: [V2_N8N_KEY.key] }, choices: { odoo: { database: 'prod' } } });
      assert.equal(checkJob, 1);
      assert.equal((await calls(page, 'ha-convert-start')).length, 0, 'the old two-step commands are not used');
      assert.equal((await calls(page, 'restore-start')).length, 0, 'the restore is part of the import');
      // The result: one line per app, what became of it and what to do; nothing was hidden.
      assert.equal(await activeStep(page), '匯入');
      assert.equal(await page.locator('[data-result="group"] .ha-summary').textContent(), '1 個應用已匯入，其他沒有');
      const odoo = page.locator('.ha-group-row[data-ha-app="odoo"]');
      assert.equal(await odoo.getAttribute('data-status'), 'imported');
      assert.equal(await odoo.locator(`a[href="#/backups/${B_V2_SAFETY.odoo}"]`).count(), 1, 'the pre-restore backup is linked');
      const n8n = page.locator('.ha-group-row[data-ha-app="n8n"]');
      assert.equal(await n8n.getAttribute('data-status'), 'rolled-back');
      assert.match(await n8n.textContent(), /已退回原狀/);
      assert.match(await n8n.textContent(), /已自動退回匯入前的狀態/);
      const out = page.locator('.ha-group-row[data-ha-app="emqx"]');
      assert.equal(await out.getAttribute('data-status'), 'excluded');
      assert.match(await out.textContent(), /沒有匯入[\s\S]*這份備份是在 EMQX 執行中做的[\s\S]*請先在 HA 停止 EMQX 附加元件[\s\S]*這台的這個應用沒有任何變更。/);
      assert.match(await page.locator('.ha-after').textContent(), /請用 HA 那邊 Odoo 的帳號和密碼登入這台的 Odoo。/);
      assert.equal(await page.locator('.ha-after').textContent().then(text => text.includes('n8n')), false, 'to-dos only for what was imported');
      assert.match(await page.locator('#status').textContent(), /匯入結束：1 個應用已匯入，1 個沒有匯入/);
      await allWidths(page, 'HAOS result');
    });

  await check('HAOS 一次確認: the only database that can move is chosen already, a line of another database is not asked, and an app the check has no result for is left out and named (UI-15, UI-16)',
    v2Fixture({ check: v2Check({ odoo: { choices: { database: [{ value: 'prod', label: 'prod', ok: true }, { value: 'test', label: 'test', ok: false }, { value: 'demo-old', label: 'demo-old', ok: false }] } },
      apps: ['odoo'] }) }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'hermes'] });
      assert.equal(await page.locator('[data-summary="check"]').textContent(), '可以匯入 1 個，不能匯入 1 個');
      await page.getByText('檢查結果沒有包含「Hermes 代理」，這次不會匯入它；可以按「重新檢查」再試。').waitFor();
      assert.equal(await page.locator('#ha-db-0').isChecked(), true, 'UI-16: the only one that can move is chosen');
      assert.equal(await page.locator('#ha-db-1').isDisabled(), true);
      assert.equal(await page.locator('#ha-db-2').isDisabled(), true);
      await page.getByText('只有一個資料庫可以搬，已經幫你選好。').waitFor();
      assert.equal(await page.getByText('請先選擇要搬過來的 Odoo 資料庫。').count(), 0);
      await page.locator('#ha-ack').check();
      assert.equal(await v2Import(page).isDisabled(), false);
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 30000 });
      const [request] = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.deepEqual(request.apps, ['odoo']);
      assert.deepEqual(request.choices, { odoo: { database: 'prod' } });
      assert.deepEqual(request.acknowledged, { _shared: [V2_PAUSES.key], odoo: [V2_ODOO_MODULES.key] });
    });

  await check('HAOS 一次確認: a choice the check asks for (the same add-on from two stores) is made on the page and sent again with the check',
    v2Fixture({ check: v2Check({ apps: ['n8n'], n8n: { importable: false, ok: false, issues: [v2Issue('n8n', 'stop', 'ha.addon-choice', '這份備份裡有兩個 n8n 附加元件，要先選一個。',
      { items: ['1b7b4ce7_woow-n8n', 'a1b2c3d4_woow-n8n'], action: '請選一個，再按「重新檢查」。' })],
    choices: { addon: [{ value: '1b7b4ce7_woow-n8n', label: 'n8n（商店 1b7b4ce7，2.43.6）' }, { value: 'a1b2c3d4_woow-n8n', label: 'n8n（商店 a1b2c3d4，1.3.4）' }] } } }) }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      assert.equal(await page.locator('[data-summary="check"]').textContent(), '可以匯入 0 個，不能匯入 1 個');
      assert.equal(await page.locator('[data-focus="ha-import"]').count(), 0, 'nothing can be imported yet');
      await page.getByText('沒有應用可以匯入。').waitFor();
      const radios = page.locator('input[name="ha-addon-n8n"]');
      assert.equal(await radios.count(), 2);
      await radios.nth(1).check();
      await page.getByText('選好後，請按下方的「重新檢查」。').waitFor();
      // The second check, with the pick, finds the app ready.
      await setScript(page, 'ha-check', haScripts({ check: v2Check({ apps: ['n8n'], n8n: { choices: { addon: [{ value: '1b7b4ce7_woow-n8n', label: 'n8n（商店 1b7b4ce7，2.43.6）' },
        { value: 'a1b2c3d4_woow-n8n', label: 'n8n（商店 a1b2c3d4，1.3.4）' }] } } }) })['ha-check']);
      await page.locator('[data-focus="ha-recheck"]').click();
      await page.locator('[data-ha-app="n8n"][data-importable="yes"]').waitFor({ timeout: 30000 });
      const second = (await calls(page, 'ha-check-start')).map(requestOf)[1];
      assert.deepEqual(second.choices, { n8n: { addon: 'a1b2c3d4_woow-n8n' } });
      assert.equal(await page.locator('input[name="ha-addon-n8n"]').nth(1).isChecked(), true, 'the pick is kept');
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 30000 });
      const [request] = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.deepEqual(request.choices, { n8n: { addon: 'a1b2c3d4_woow-n8n' } });
    });

  await check('HAOS 一次確認: an import whose start does not answer is asked again with the same request id and follows the one job (UI-22)',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await page.evaluate(() => window.__fixture.hold.push('ha-import-start'));
      await v2Import(page).click();
      await page.getByText('回應比較久，作業可能已經開始。正在重新確認它的狀態…').waitFor();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'ha-import-start').length >= 2);
      await page.evaluate(() => window.__fixture.release('ha-import-start'));
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const starts = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.equal(new Set(starts.map(request => request.request_id)).size, 1, 'every try carries the same request id');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="n8n"]').getAttribute('data-status'), 'imported');
      assert.equal((await page.evaluate(() => Object.values(window.__fixture.jobs).filter(item => item.chain && item.job.params.group.step === 'convert').length)), 1,
        'the engine started the import once');
    }, { beforeGoto: async (page, context) => context.route('**/backup.js', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace('"ha-import-start": 120000', '"ha-import-start": 1500').replace('const HA_START_PAUSE_MS = 3000;', 'const HA_START_PAUSE_MS = 50;');
      await route.fulfill({ response, body });
    }) });

  await check('HAOS 一次確認: a start that never answers ends in words that say the job may be running; pressing the button again reaches the same job (UI-22)',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await page.evaluate(() => window.__fixture.hold.push('ha-import-start'));
      await v2Import(page).click();
      await page.locator('.wizard-card .notice-error').getByText('這台設備還沒有回應，作業可能已經開始。請再按一次剛才的按鈕').waitFor({ timeout: 30000 });
      assert.equal((await calls(page, 'ha-import-start')).length, 3, 'three tries, then the page says so');
      await page.evaluate(() => window.__fixture.hold.splice(0));
      await page.evaluate(() => window.__fixture.release('ha-import-start'));
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const starts = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.equal(new Set(starts.map(request => request.request_id)).size, 1);
    }, { beforeGoto: async (page, context) => context.route('**/backup.js', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace('"ha-import-start": 120000', '"ha-import-start": 300').replace('const HA_START_PAUSE_MS = 3000;', 'const HA_START_PAUSE_MS = 50;');
      await route.fulfill({ response, body });
    }) });

  await check('HAOS 一次確認: when every try ran out of time the status decides: the job the engine started is found and followed (UI-22)',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n'] });
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      await page.evaluate(() => window.__fixture.hold.push('ha-import-start'));
      await v2Import(page).click();
      await page.waitForFunction(() => window.testcalls.filter(call => call.argv[1] === 'ha-import-start').length >= 1);
      // The engine did start the import (the answer was lost): its first job is the active one now.
      const record = v2ChainRecord({ app: 'odoo', index: 0, id: J_HA_RUN });
      await page.evaluate(([id, item]) => { window.__fixture.jobs[id] = item; window.__fixture.status.active_job = structuredClone(item.job); }, [J_HA_RUN, record]);
      await page.locator('.ha-group-list').waitFor({ timeout: 30000 });
      assert.equal(await activeStep(page), '匯入');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="odoo"]').getAttribute('data-status'), 'pending');
      assert.match(await page.locator('.ha-group-row[data-ha-app="odoo"]').textContent(), /轉換中/);
      assert.equal(await page.locator('.wizard-card .notice-error').count(), 0, 'nothing is reported as failed');
    }, { beforeGoto: async (page, context) => context.route('**/backup.js', async route => {
      const response = await route.fetch();
      const body = (await response.text()).replace('"ha-import-start": 120000', '"ha-import-start": 400').replace('const HA_START_PAUSE_MS = 3000;', 'const HA_START_PAUSE_MS = 50;');
      await route.fulfill({ response, body });
    }) });

  await check('HAOS 一次確認: a key with a Tab is tried as it is and a refusal says why it may have failed; only a key that can never be one (empty, too long, with a NUL) stops the page (UI-12)',
    v2Fixture({ meta: v2Meta({ protected: true, addons: v2Meta().addons.map(addon => ({ ...addon, encrypted: true })) }) }), async page => {
      await ready(page);
      await openHa(page, HA_V2);
      await page.locator('#ha-app-hermes').uncheck();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('#ha-key').waitFor();
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.getByText('請輸入 HA 備份金鑰。').waitFor();
      assert.equal((await calls(page, 'ha-check-start')).length, 0, 'an empty key is never sent');
      // The other two things that can never be a key, and a blank one: each says why, nothing is sent. (The field's own length limit
      // does not apply to a value set by a script, so the page's own rule is what is looked at.)
      const typeKey = text => page.locator('#ha-key').evaluate((input, value) => { input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); }, text);
      await typeKey('      ');
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.getByText('請輸入 HA 備份金鑰。').waitFor();
      await typeKey('A'.repeat(4097));
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.getByText('內容太長，不像是 HA 備份金鑰。').waitFor();
      assert.equal(await page.getByText('請輸入 HA 備份金鑰。').count(), 0, 'one message at a time');
      await typeKey('ABCD-EFGH\u0000IJKL');
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.getByText('金鑰不能包含空字元（NUL）。').waitFor();
      assert.equal((await calls(page, 'ha-check-start')).length, 0, 'a key that can never be one is never sent');
      await page.locator('#ha-key').fill('ABCD\tEFGH');
      await page.locator('#ha-key-odd').waitFor();   // a reminder while typing, not a stop
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText('HA 備份金鑰不正確，請確認後再試一次。').waitFor();
      assert.match(await page.locator('.wizard-card .notice-error').textContent(), /你輸入的金鑰含有 Tab 或換行等看不見的字元/);
      const [sent] = (await calls(page, 'ha-check-start')).map(requestOf);
      assert.equal(sent.key, 'ABCD\tEFGH', 'the key goes to the engine exactly as typed');
      assert.equal(await activeStep(page), '金鑰');
      // A plain wrong key has no such hint.
      await page.locator('#ha-key').fill('ZZZZ-YYYY-XXXX-WWWW-VVVV-UUUU-TTTT');
      await page.evaluate(() => window.__fixture.failures.push({ command: 'ha-check-start', code: 'wrong-key', message: 'HA 備份金鑰不正確，請確認後再試一次。' }));
      await page.locator('[data-focus="ha-key-next"]').click();
      await page.locator('.wizard-card .notice-error').getByText('HA 備份金鑰不正確，請確認後再試一次。').waitFor();
      assert.doesNotMatch(await page.locator('.wizard-card .notice-error').textContent(), /看不見的字元/);
    });

  await check('HAOS 一次確認: no device key yet — the page does not stop, the import makes one and asks for the emergency key (UI-17, D11)',
    v2Fixture({ key: false }), async page => {
      await ready(page);
      await openHa(page, HA_V2);
      // Before the check the page cannot know this engine: it promises nothing and says where the answer will be.
      const early = page.locator('.wizard-card .notice-info').filter({ hasText: '這台還沒有加密金鑰，轉換好的備份要用它加密。' });
      await early.waitFor();
      assert.doesNotMatch(await early.textContent(), /匯入開始時會自動/);
      assert.equal(await page.locator('.wizard-card .notice-warn').filter({ hasText: '尚未建立加密金鑰' }).count(), 0);
      for (const id of ['odoo', 'emqx', 'hermes']) await page.locator(`#ha-app-${id}`).uncheck();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-summary="check"]').waitFor({ timeout: 30000 });
      // The check said schema 2: this engine makes the key when the import starts, and now the page says so.
      await page.locator('.wizard-card .notice-info').filter({ hasText: '這台還沒有加密金鑰。匯入開始時會自動建立一把' }).waitFor();
      assert.equal(await page.locator('.wizard-card .notice-info').filter({ hasText: '轉換好的備份要用它加密。' }).count(), 0, 'the first-step hint is gone');
      await page.locator('#ha-ack').check();
      assert.equal(await v2Import(page).isDisabled(), false, 'no device key is no reason to stop');
      assert.match(await page.locator('#key-banner').textContent(), /需要設定加密金鑰/);
      await v2Import(page).click();
      // While the import runs (not only at its end) the page says that the key was made and asks for the emergency key.
      await page.locator('.ha-group-list').waitFor({ timeout: 30000 });
      assert.equal(await page.locator('[data-result="group"]').count(), 0, 'the import is still running');
      await page.locator('.notice-warn').filter({ hasText: '這次匯入已經自動建立一把' }).waitFor({ timeout: 30000 });
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      assert.match(await page.locator('#key-banner').textContent(), /請保存緊急金鑰。/);
      assert.equal(await page.locator('#key-banner a[href="#/keys"]').count(), 1, 'the banner links to the emergency key');
      assert.equal(await page.locator('.notice-warn').filter({ hasText: '這次匯入已經自動建立一把' }).count(), 1, 'the result keeps asking until it is saved');
      assert.equal((await calls(page, 'key-init')).length, 0, 'the engine made the key, not the page');
    });

  await check('HAOS 一次確認: 做完這個應用就停止 lets the app being worked on finish and does not start the next; the others say they did not start',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n'] });
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-focus="ha-stop-after"]').click();
      await page.locator('.wizard-card .notice-info').filter({ hasText: '已要求做完這個應用就停止；後面的應用不會開始。' }).waitFor();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const [cancel] = (await calls(page, 'job-cancel')).map(requestOf);
      assert.equal(cancel.after_this, true);
      assert.equal(await page.locator('.ha-group-row[data-ha-app="odoo"]').getAttribute('data-status'), 'imported');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="n8n"]').getAttribute('data-status'), 'not-started');
      assert.match(await page.locator('.ha-group-row[data-ha-app="n8n"]').textContent(), /這台的這個應用沒有任何變更。/);
    });

  await check('HAOS 一次確認: cancelling the import stops the whole chain; the app that was converted keeps its backup and can be restored from the result',
    v2Fixture({ outcomes: {} }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-focus="ha-cancel-import"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const cancels = (await calls(page, 'job-cancel')).map(requestOf);
      assert.equal(cancels.length, 1);
      assert.equal(cancels[0].after_this, undefined, 'the whole import');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="n8n"]').getAttribute('data-status'), 'not-started');
      assert.equal(await activeStep(page), '匯入');
    });

  await check('HAOS 一次確認: a line whose names changed since the check stops only that app; the result offers to check and confirm it again',
    v2Fixture({ outcomes: { n8n: { convert: 'confirmation-required' } } }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n'] });
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      assert.equal(await page.locator('.ha-group-row[data-ha-app="odoo"]').getAttribute('data-status'), 'imported', 'the other app went on');
      const row = page.locator('.ha-group-row[data-ha-app="n8n"]');
      assert.equal(await row.getAttribute('data-status'), 'skipped');
      assert.match(await row.textContent(), /這次匯入和檢查時看到的不同，請再確認一次。/);
      await row.locator('[data-focus="group-recheck-n8n"]').click();
      await page.locator('.stepper[aria-label="匯入步驟"]').waitFor();
      assert.equal(await activeStep(page), '選擇應用');
      assert.equal(await page.locator('#ha-app-n8n').isChecked(), true);
      assert.equal(await page.locator('#ha-app-odoo').isChecked(), false);
      await page.getByText('「n8n 工作流程」的內容和檢查時不一樣，請重新檢查後再確認一次。').waitFor();
    });

  await check('HAOS 一次確認: 只轉換 converts the apps and leaves the restore to the customer; nothing of this device is replaced',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await page.locator('[data-focus="ha-convert-only"]').click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const [request] = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.equal(request.then_restore, false);
      assert.equal(request.overwrite, undefined, 'nothing is replaced, so nothing to confirm to replace');
      assert.deepEqual(request.acknowledged, { _shared: [V2_PAUSES.key], n8n: [V2_N8N_KEY.key] }, 'the lines are still the ones the customer ticked');
      assert.equal(await page.locator('[data-result="group"] .ha-summary').textContent(), '全部應用都已轉換成備份');
      const row = page.locator('.ha-group-row[data-ha-app="n8n"]');
      assert.equal(await row.getAttribute('data-status'), 'converted');
      assert.equal(await row.locator(`a[href="#/backups/${B_V2.n8n}"]`).count(), 1, 'the converted backup is linked');
      await row.locator('[data-focus="group-restore-n8n"]').waitFor();
      assert.equal((await calls(page, 'restore-start')).length, 0);
      assert.equal(await page.locator('.ha-after').count(), 0, 'nothing was imported yet: no to-do list');
    });

  await check('HAOS 一次確認: the choices, the one tick and the buttons are reachable with the keyboard, each with a visible focus ring',
    v2Fixture(), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n', 'emqx'] });
      await page.locator('#ha-db-0').check();
      const seen = await tabKeys(page, 'HAOS options', 70);
      for (const key of ['ha-db-0', 'ha-test-mode', 'ha-ack', 'ha-recheck', 'ha-options-back']) assert(seen.includes(key), `${key} reachable with Tab (${seen})`);
      // The tick has its words: the box it confirms and the sentence next to it are what a screen reader reads.
      assert.equal(await page.locator('#ha-ack').getAttribute('aria-describedby'), 'ha-confirm-list');
      assert.equal(await page.locator('label[for="ha-ack"]').textContent(), '我了解上面列的事，開始匯入上面共 5 項；勾選一次，這些都算確認過。');
      assert.equal(await page.locator('#ha-confirm-title').textContent(), '匯入前請確認');
      assert.equal(await page.locator('section.ha-confirm').getAttribute('aria-labelledby'), 'ha-confirm-title');
    });

  await check('HAOS 一次確認 in the dark theme: the check, the one confirmation, the running import and its result keep WCAG AA contrast and fit every width',
    v2Fixture({ outcomes: { n8n: { restore: 'rolled-back' } } }), async page => {
      await ready(page);
      assert.equal(await page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark')), true);
      await v2Check1(page, { keep: ['odoo', 'n8n', 'emqx'] });
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      assert.deepEqual((await contrastOf(page)).failures, [], 'the check and the confirmation');
      await allWidths(page, 'HAOS dark options');
      await v2Import(page).click();
      await page.locator('.ha-group-list').waitFor({ timeout: 30000 });
      assert.deepEqual((await contrastOf(page)).failures, [], 'the running import');
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      assert.deepEqual((await contrastOf(page)).failures, [], 'the result');
      await allWidths(page, 'HAOS dark result');
    }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  await check('HAOS 一次確認: names from a backup are only ever text, and the screens fit 1440 to 320 px without sideways scrolling',
    v2Fixture({ check: v2Check({ shared: [v2Issue('_shared', 'confirm', 'shared.pauses', '會暫停 <img src=x onerror="window.__pwned=1">', { items: ['<b>bold</b>', '"><script>window.__pwned=2</script>'] })],
      odoo: { issues: [v2Issue('odoo', 'confirm', 'odoo.missing-modules', '缺少 <i>模組</i>', { items: ['a'.repeat(120)], database: 'prod' })] } }) }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n', 'emqx'] });
      await page.locator('#ha-db-0').check();
      assert.equal(await page.evaluate(() => window.__pwned), undefined);
      assert.equal(await page.locator('#view img, #view script, #view b, #view i').count(), 0, 'no element came out of a backup text');
      assert.match(await page.locator('#ha-confirm-list').textContent(), /<img src=x onerror="window.__pwned=1">/);
      assert.match(await page.locator('#ha-confirm-list').textContent(), /<b>bold<\/b>/);
      await page.locator('#ha-ack').check();
      await allWidths(page, 'HAOS confirm');
      assert.deepEqual((await contrastOf(page)).failures, [], 'the confirmation keeps WCAG AA contrast');
    });


  await check('HAOS 一次確認: a job of an import found again after a reload shows every app of the import, what became of each, and the way to the next job',
    (() => {
      const data = v2Fixture();
      const done = { app_id: 'odoo', status: 'imported', convert_job_id: J_HA_CONVERT, restore_job_id: J_HA_RESTORE, backup_id: B_V2.odoo, safety_backup_id: B_V2_SAFETY.odoo, code: null, message: null };
      const record = v2ChainRecord({ done: [done] });
      data.jobs = { [J_HA_RUN]: record };
      data.status.active_job = structuredClone(record.job);
      return data;
    })(), async page => {
      await ready(page);
      // A reload during an import lands on the job that is running; the page rebuilds the whole import from its record.
      await page.waitForFunction(id => window.location.hash === `#/jobs/${id}`, J_HA_RUN);
      const section = page.locator('[data-group="g1a2b3c4d5e6f0042"]');
      await section.waitFor();
      assert.equal(await section.locator('.ha-group-row[data-ha-app="odoo"]').getAttribute('data-status'), 'imported');
      assert.equal(await section.locator('.ha-group-row[data-ha-app="n8n"]').getAttribute('data-status'), 'pending');
      assert.match(await section.locator('.ha-group-row[data-ha-app="n8n"]').textContent(), /轉換中[\s\S]*正在把 HA 的資料轉成這台的備份/);
      assert.equal(await section.locator(`a[href="#/backups/${B_V2_SAFETY.odoo}"]`).count(), 1);
      assert.match(await page.locator('#view-heading').textContent(), /轉換 HA 備份「n8n 工作流程」/);
    });

  await check('HAOS 一次確認: a job that is not found says the job may still be running and offers to read it again (X-JOB-03)', fixture(), async page => {
    await ready(page);
    await page.evaluate(() => { window.location.hash = '#/jobs/j20261113T020000Z-deadbeef'; });
    const notice = page.locator('.job-error .notice-error');
    await notice.waitFor();
    assert.match(await notice.textContent(), /找不到指定的作業。看不到進度不代表作業停了，它可能還在執行；請按「重試」重新讀取，或到「活動紀錄」確認。/);
    const before = (await calls(page, 'job-status')).length;
    await notice.locator('[data-focus="error-retry"]').click();
    await page.waitForFunction(count => window.testcalls.filter(call => call.argv[1] === 'job-status').length > count, before);
  });

  await check('HAOS 一次確認: a conversion that reports no new backup is a hint to the backup list, not an error (UI-21), and one app that fails the check does not hold back the others in the two-step flow (UI-14, UI-15)',
    haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false })] } }), async page => {
      await ready(page);
      await setScript(page, 'ha-check', haScripts({ check: haCheck({ n8n: { ok: false, blockers: ['HA 的 n8n 還沒有建立管理者帳號。'] } }) })['ha-check']);
      await openHa(page, HA_PLAIN);
      await page.locator('#ha-app-n8n').check();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="n8n"]').waitFor({ timeout: 30000 });
      // The old engine's words: no schema 2, so the two steps stay; the app that does not pass is listed, the other one can go.
      assert.equal(await activeStep(page), '結果與選項');
      await page.locator('#ha-db-0').check();
      await page.getByText('「n8n 工作流程」沒有通過檢查，這次不會匯入，這台的它也不會有任何變更；其他應用可以繼續轉換。').waitFor();
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), false, 'one app that does not pass never holds back the other');
      await setScript(page, 'ha-convert', [{ job: { state: 'succeeded', phase: 'verify', phases: phasesAt('ha-convert', null), progress: { percent: 100, message: '已完成' },
        finished: '2026-11-18T03:05:30Z', cancellable: false, result: { size: 1, apps: ['odoo'], encrypted: true, ha_import: haImportView(['odoo']) } }, log: ['2026-11-18T03:05:30Z 完成'] }]);
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('.wizard-card .notice-info').filter({ hasText: '轉換已完成，但作業沒有回報新的備份編號' }).waitFor({ timeout: 30000 });
      assert.equal(await page.locator('.wizard-card .notice-error').count(), 0, 'it is a hint, not an error');
      assert.match(await page.locator('.wizard-card').textContent(), /標示「由 HA 轉換」/);
      const [convert] = (await calls(page, 'ha-convert-start')).map(requestOf);
      assert.deepEqual(convert.apps, ['odoo'], 'only the app that passed is converted');
    });

  await check('HAOS 一次確認: the engine could not make the device key — the refusal is shown with the way to 加密金鑰, the import is not started (UI-17)',
    v2Fixture({ key: false }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await page.evaluate(() => window.__fixture.failures.push({ command: 'ha-import-start', code: 'no-device-key', message: '這台設備尚未建立加密金鑰，而且無法自動建立。' }));
      await v2Import(page).click();
      const error = page.locator('.wizard-card .notice-error');
      await error.getByText('這台設備尚未建立加密金鑰，而且無法自動建立。').waitFor();
      assert.equal(await error.locator('a[href="#/keys"]').count(), 1);
      assert.equal(await activeStep(page), '結果與確認');
    });

  await check('HAOS 一次確認: the restore check of a converted backup lists its lines; an app that fails it is not offered and the others go on; the lines to confirm are sent with the restore (UI-25)',
    (() => {
      const data = haFixture();
      const inspected = haInspect();
      const [odoo, n8n] = inspected.preflight.apps;
      odoo.issues = [v2Issue('odoo', 'confirm', 'restore.pauses', '還原時會先暫停下列服務，完成後自動啟動回來。', { items: ['檔案管理 filebrowser'] }),
        v2Issue('odoo', 'auto', 'restore.device-key', '這台的加密金鑰會在還原開始時自動建立。')];
      Object.assign(n8n, { restorable: false, checks: [{ id: 'n8n/dir-in-use', status: 'fail', message: '這台 n8n 的資料夾被其他服務佔用，不能還原。' }],
        issues: [v2Issue('n8n', 'stop', 'restore.dir-in-use', '這台 n8n 的資料夾被其他服務佔用，不能還原。', { action: '請先停掉那個服務。' })] });
      data.inspect[B_HA] = inspected;
      data.backups.unshift(convertedMeta());
      return data;
    })(), async page => {
      await ready(page);
      await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_HA);
      await page.locator('.app-preflight').first().waitFor();
      assert.equal(await page.locator('.app-preflight').nth(1).locator('input[type="checkbox"]').isDisabled(), true, 'the app that fails is not offered');
      assert.match(await page.locator('.app-preflight').nth(1).textContent(), /請先停掉那個服務。/);
      assert.match(await page.locator('.app-preflight').first().textContent(), /要確認[\s\S]*還原時會先暫停下列服務[\s\S]*檔案管理 filebrowser[\s\S]*系統會自動做[\s\S]*這台的加密金鑰會在還原開始時自動建立。/);
      assert.equal(await page.locator('[data-focus="pf-next"]').isDisabled(), false, 'one app failing never stops the page while another can go');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#restore-confirm-list').waitFor();
      assert.equal(await page.locator('#restore-confirm-list > li').count(), 1);
      // The first start is refused: what has to be confirmed is not what was shown. The page checks again and says so.
      await page.evaluate(() => window.__fixture.failures.push({ command: 'restore-start', code: 'confirmation-required', message: '還原 Odoo 18 前還有事情要確認。',
        details: { apps: { odoo: [] } } }));
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.getByText('還原 Odoo 18 前還有事情要確認。這和剛才看到的不一樣，已經重新檢查；請看過新的內容後再確認一次。').waitFor();
      assert.equal((await calls(page, 'inspect')).length, 2, 'checked again');
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor({ timeout: 30000 });
      const starts = (await calls(page, 'restore-start')).map(requestOf);
      assert.equal(starts.length, 2);
      assert.deepEqual(starts[1].apps, ['odoo']);
      assert.deepEqual(starts[1].acknowledged, { odoo: [keyOf('odoo', 'restore.pauses', ['檔案管理 filebrowser'])] });
    });


  // ------------------------------------------------------------------ iteration 2 (2026-11-25 evening): the kept copies (S4), H-c and what the first verifier found untested

  const HC_SENTENCE = '檢查可能會暫時啟動這台停著的服務（例如資料庫）來讀取資料；檢查結束後，包括失敗或取消，會把它們恢復成原本停著的樣子。';
  const KEPT_ID = B_V2_KEPT.n8n;
  const v2KeptFixture = (extra = {}) => v2Fixture({ chain: { kept: { n8n: { backup: v2Kept('n8n'), detail: V2_KEPT_DETAIL } }, restoreWarnings: { n8n: [V2_PAUSE_WARNING] } },
    left: ['test', 'demo-old'], ...extra });
  const v2KeptImport = async page => {
    await v2Check1(page, { keep: ['odoo', 'n8n'] });
    await page.locator('#ha-db-0').check();
    await page.locator('#ha-ack').check();
    await v2Import(page).click();
    await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
    await page.locator(`[data-section="kept"] [data-kept="${KEPT_ID}"][data-state="present"]`).waitFor();
  };

  await check('HAOS 一次確認: the first step and the check page say that the check may start stopped services and puts them back (H-c)',
    (() => { const data = v2Fixture(); data.scripts['ha-check'] = [haStep('ha-check', 'decrypt', 30, { cancellable: true })]; return data; })(), async page => {
      await ready(page);
      await openHa(page, HA_V2);
      assert.equal(await page.locator('.wizard-card .ha-check-starts').textContent(), HC_SENTENCE);
      // The side card no longer says that nothing of this device is ever started: it says what stays true.
      assert.doesNotMatch(await page.locator('.side-card').textContent(), /不會停止或變更這台的應用/);
      assert.match(await page.locator('.side-card').textContent(), /檢查和轉換都不會停止這台正在運作的應用，也不會變更它們的資料/);
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('.ha-job').waitFor();
      assert.equal(await activeStep(page), '檢查');
      assert.equal(await page.locator('.wizard-card .ha-check-starts').count(), 1);
      assert.equal(await page.locator('.wizard-card .ha-check-starts').textContent(), HC_SENTENCE, 'the page that runs the check says it again');
    });

  await check('HAOS 一次確認: in the two-step flow of an older engine an app the check has no result for is named and left out, and the other one still goes (UI-15)',
    (() => {
      const data = haFixture({ ha: { backups: [haMeta(HA_PLAIN, { protected: false })] } });
      const only = haCheck();
      only.ha_check.apps = only.ha_check.apps.filter(item => item.app_id === 'odoo');
      data.scripts['ha-check'] = haScripts({ check: only })['ha-check'];
      return data;
    })(), async page => {
      await ready(page);
      await openHa(page, HA_PLAIN);
      await page.locator('#ha-app-n8n').check();
      await page.locator('[data-focus="ha-apps-next"]').click();
      await page.locator('[data-ha-app="odoo"]').waitFor({ timeout: 30000 });
      assert.equal(await activeStep(page), '結果與選項', 'no schema 2: the two steps stay');
      await page.getByText('檢查結果沒有包含「n8n 工作流程」，這次不會匯入它；可以按「重新檢查」再試。').waitFor();
      assert.equal(await page.locator('[data-ha-app="n8n"]').count(), 0, 'an app without a result has no card');
      await page.locator('#ha-db-0').check();
      assert.equal(await page.locator('[data-focus="ha-convert"]').isDisabled(), false, 'an app without a result never holds back the one that passed');
      await page.locator('[data-focus="ha-convert"]').click();
      await page.locator('#confirm-ok').click();
      await page.waitForFunction(() => window.testcalls.some(call => call.argv[1] === 'ha-convert-start'));
      const [convert] = (await calls(page, 'ha-convert-start')).map(requestOf);
      assert.deepEqual(convert.apps, ['odoo'], 'only the app that has a result is converted');
      assert.equal(requestOf((await calls(page, 'ha-check-start'))[0]).choices, undefined, 'an older engine is never sent the new fields');
      assert.equal((await calls(page, 'ha-import-start')).length, 0, 'and not the new command');
    });

  await check('HAOS 一次確認: when the backup holds several EMQX nodes the page asks which one, checks again with the pick and imports that node (B10 choices)',
    v2Fixture({ check: v2Check({ apps: ['emqx'], emqx: { issues: [], importable: true, ok: true, choices: { node: [
      { value: 'emqx@ha.local', label: 'emqx@ha.local（最後寫入 2026-11-20）', default: true }, { value: 'emqx@ha-old.local', label: 'emqx@ha-old.local（最後寫入 2026-11-02）' }] } } }) }),
    async page => {
      await ready(page);
      await v2Check1(page, { keep: ['emqx'] });
      const radios = page.locator('input[name="ha-node-emqx"]');
      assert.deepEqual(await radios.evaluateAll(items => items.map(item => [item.value, item.checked])), [['emqx@ha.local', true], ['emqx@ha-old.local', false]],
        'the default is shown as chosen');
      assert.match(await page.locator('.ha-choices[data-choice="node"]').textContent(), /emqx@ha.local（最後寫入 2026-11-20）[\s\S]*預設[\s\S]*emqx@ha-old.local（最後寫入 2026-11-02）/);
      await page.locator('#ha-ack').check();
      assert.equal(await v2Import(page).isDisabled(), false, 'the default node needs no new check');
      // Another node: the check has to run again with it before anything starts.
      await radios.nth(1).check();
      assert.equal(await v2Import(page).isDisabled(), true);
      await page.getByText('你改了選項，請先按「重新檢查」，用新的選擇再檢查一次。').waitFor();
      await page.getByText('選好後，請按下方的「重新檢查」。').waitFor();
      await page.locator('[data-focus="ha-recheck"]').click();
      await page.locator('#ha-ack:not(:checked)').waitFor({ timeout: 30000 });
      const checks = (await calls(page, 'ha-check-start')).map(requestOf);
      assert.equal(checks.length, 2);
      assert.equal(checks[0].choices, undefined, 'the first check asked nothing');
      assert.deepEqual(checks[1].choices, { emqx: { node: 'emqx@ha-old.local' } }, 'the second check is told the pick');
      assert.equal(await radios.nth(1).isChecked(), true, 'the pick stays');
      assert.equal(await page.getByText('你改了選項').count(), 0, 'the new check saw the pick');
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const [start] = (await calls(page, 'ha-import-start')).map(requestOf);
      assert.deepEqual(start.choices, { emqx: { node: 'emqx@ha-old.local' } });
      assert.deepEqual(start.apps, ['emqx']);
    });

  await check('HAOS 一次確認: cancelling an import that is in a stage that cannot be interrupted says so and points to 做完這個應用就停止, which stops the import after this app',
    v2Fixture({ chain: { uncancellable: true } }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['odoo', 'n8n'] });
      await page.locator('#ha-db-0').check();
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-focus="ha-cancel-import"]').click();
      await page.locator('#confirm-ok').click();
      await page.locator('#confirm-error').getByText('作業已進入不可中斷的階段，將繼續執行到完成或自動回復。 可以改按「做完這個應用就停止」。').waitFor();
      assert.equal(await page.locator('#confirm-dialog').evaluate(dialog => dialog.open), true, 'the refusal stays in the dialog');
      const [cancel] = (await calls(page, 'job-cancel')).map(requestOf);
      assert.equal(cancel.after_this, undefined, 'the whole import was asked to stop and refused');
      await page.locator('#confirm-cancel').click();
      await page.locator('[data-focus="ha-stop-after"]').click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const cancels = (await calls(page, 'job-cancel')).map(requestOf);
      assert.equal(cancels[1].after_this, true);
      assert.equal(await page.locator('.ha-group-row[data-ha-app="odoo"]').getAttribute('data-status'), 'imported', 'the app being worked on finished');
      assert.equal(await page.locator('.ha-group-row[data-ha-app="n8n"]').getAttribute('data-status'), 'not-started');
    });

  await check('HAOS 一次確認: a kept copy is listed after the import with what is in it, what was put back and what was not; it can be downloaded and is deleted only after a confirmation (S4)',
    v2KeptFixture(), async page => {
      await ready(page);
      await v2KeptImport(page);
      const copy = page.locator(`[data-kept="${KEPT_ID}"]`);
      const section = page.locator('[data-section="kept"]');
      assert.match(await section.textContent(), /匯入前，這台的資料庫服務裡有這次沒有搬走的其他資料，所以系統先把整個資料庫服務存成完整複本。複本不會自動刪除；確定用不到時可以下載保存，再刪除它。刪除後，複本裡的資料就沒有了。/);
      assert.match(await copy.locator('.ha-group-name').textContent(), /^保留的複本 · /);
      const text = await copy.textContent();
      assert.match(text, /屬於：n8n 工作流程/);
      assert.match(text, new RegExp(`備份 ID：${KEPT_ID}`));
      assert.match(text, /複本裡的資料庫：「analytics」、「crm_old」，另有 3 個沒有列出。/);
      assert.match(text, /匯入後已經放回這台的資料庫：「analytics」。/);
      assert.match(text, /下列資料庫沒有放回這台，資料仍在這份複本裡：[\s\S]*crm_old：資料庫擁有者的角色在新的資料庫服務裡已經存在，沒有放回。/);
      assert.match(text, /放不回去的資料庫仍在這份複本裡。/);
      assert.match(text, /已加密[\s\S]*金鑰可用/);
      assert.equal(await copy.locator(`a[href="#/backups/${KEPT_ID}"]`).count(), 1, 'the copy is linked');
      // What the restore said about the app is under its row, and only there.
      assert.match(await page.locator('.ha-group-row[data-ha-app="n8n"] .ha-group-notes').textContent(), /匯入時暫停的服務沒有重新啟動：filebrowser。請到「應用軟體」把它啟動起來。/);
      assert.equal(await page.locator('.ha-group-row[data-ha-app="odoo"] .ha-group-notes').count(), 0);
      // What stayed behind is in the to-dos too: the Odoo databases that stay on HA and the number of the copy.
      const after = await page.locator('.ha-reminders').textContent();
      assert.match(after, /HA 的 Odoo 還有「test」、「demo-old」沒有搬過來，它們留在 HA；HA 的 Odoo 停用後就看不到了。這台 Odoo 一次只放一個資料庫，以後再匯入另一個會取代這次的。/);
      assert.match(after, new RegExp(`匯入前，這台的資料庫服務裡其他資料已經先存成完整複本（${KEPT_ID}），不會自動刪除；可以下載它，確定用不到時再自己刪除（刪除後裡面的其他資料就沒有了）。`));
      await allWidths(page, 'HAOS kept copies');
      // A job running anywhere: nothing is deleted meanwhile (the engine would refuse it too); the download stays.
      await page.evaluate(job => { window.__fixture.status.active_job = job; }, haJob('j20261125T040000Z-7a7a7a7a', 'ha-check', 'running', '2026-11-25T04:00:00Z'));
      await page.locator('#refresh').click();
      await page.locator(`[data-focus="kept-delete-${KEPT_ID}"]:disabled`).waitFor();
      assert.equal(await copy.locator(`[data-focus="download-${KEPT_ID}"]`).isDisabled(), false);
      await page.evaluate(() => { window.__fixture.status.active_job = null; });
      await page.locator('#refresh').click();
      await page.locator(`[data-focus="kept-delete-${KEPT_ID}"]:enabled`).waitFor();
      // Download: the stored file as it is, like in the backup list.
      const before = downloadRequests.length;
      const [download] = await Promise.all([page.waitForEvent('download'), copy.locator(`[data-focus="download-${KEPT_ID}"]`).click()]);
      assert.deepEqual((await calls(page, 'download-info')).map(requestOf), [{ backup_id: KEPT_ID }]);
      assert.equal(download.suggestedFilename(), 'woowtech-backup-dev-a-20261125-031700.tar');
      assert.equal(downloadRequests[before].open.path, `/var/lib/woowtech-backup/archives/${KEPT_ID}.tar`);
      // Delete: the dialog says what is lost for good; no is no.
      await copy.locator(`[data-focus="kept-delete-${KEPT_ID}"]`).click();
      assert.equal(await page.locator('#confirm-title').textContent(), '刪除保留的複本？');
      assert.match(await page.locator('#confirm-body').textContent(), /這是匯入前保留的完整複本：裡面有那時這台資料庫服務的全部資料，包含這次匯入沒有搬走的其他資料庫。刪除後，這些資料就沒有了，也無法再用它回復到匯入之前；要保留，請先按「下載」。/);
      assert.doesNotMatch(await page.locator('#confirm-body').textContent(), /這是還原前自動備份。/, 'the words of the kept copy replace the general ones');
      assert.equal(await page.locator('#confirm-ok').textContent(), '刪除複本');
      await page.locator('#confirm-cancel').click();
      assert.equal((await calls(page, 'delete')).length, 0, 'nothing is deleted without the confirmation');
      assert.equal(await copy.getAttribute('data-state'), 'present');
      await copy.locator(`[data-focus="kept-delete-${KEPT_ID}"]`).click();
      await page.locator('#confirm-ok').click();
      await page.locator(`[data-kept="${KEPT_ID}"][data-state="deleted"]`).waitFor();
      assert.deepEqual((await calls(page, 'delete')).map(requestOf), [{ backup_id: KEPT_ID }]);
      assert.match(await copy.textContent(), /這份複本已經刪除。/);
      assert.equal(await copy.locator('button').count(), 0, 'nothing left to press on a deleted copy');
      await page.waitForFunction(() => !document.querySelector('.ha-reminders')?.textContent.includes('完整複本（'));
    });

  await check('HAOS 一次確認: the backup list has no filter for kept copies while the device holds none',
    haFixture(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      await page.locator('[data-focus="filter-all"]').waitFor();
      assert.equal(await page.locator('[data-focus="filter-kept"]').count(), 0);
    });

  await check('HAOS 一次確認: the kept copy is found from the converted backup alone, and from the restore result alone (the page has two sources)',
    v2Fixture({ chain: { kept: { n8n: { backup: v2Kept('n8n'), detail: V2_KEPT_DETAIL, told: false } } } }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const copy = page.locator(`[data-section="kept"] [data-kept="${KEPT_ID}"][data-state="present"]`);
      await copy.waitFor();
      // Named only by `from_ha.kept` of the converted backup: no databases, no put-back lines, but the copy and what can be done with it.
      assert.match(await copy.textContent(), /屬於：n8n 工作流程/);
      assert.doesNotMatch(await copy.textContent(), /複本裡的資料庫：|匯入後已經放回/);
      assert.equal(await copy.locator(`[data-focus="download-${KEPT_ID}"]`).count(), 1);
      assert.equal(await copy.locator(`[data-focus="kept-delete-${KEPT_ID}"]`).count(), 1);
    });

  await check('HAOS 一次確認: the kept copy is found from the restore result alone when the converted backup does not name it',
    v2Fixture({ chain: { kept: { n8n: { backup: v2Kept('n8n'), detail: V2_KEPT_DETAIL, pointer: false } } } }), async page => {
      await ready(page);
      await v2Check1(page, { keep: ['n8n'] });
      await page.locator('#ha-ack').check();
      await v2Import(page).click();
      await page.locator('[data-result="group"]').waitFor({ timeout: 60000 });
      const copy = page.locator(`[data-section="kept"] [data-kept="${KEPT_ID}"][data-state="present"]`);
      await copy.waitFor();
      assert.match(await copy.textContent(), /複本裡的資料庫：「analytics」、「crm_old」/);
      assert.doesNotMatch(await page.locator('.ha-reminders').textContent(), /完整複本（/, 'the to-dos name a copy only when the converted backup does');
      // The job view of the last job of the import (also after a reload) lists the copy once: with the import, not again under the restore result.
      const last = requestOf((await calls(page, 'job-status')).at(-1)).job_id;
      await page.evaluate(id => { window.location.hash = `#/jobs/${id}`; }, last);
      await page.locator('.ha-job-group').waitFor();
      await page.locator(`.ha-job-group [data-kept="${KEPT_ID}"][data-state="present"]`).waitFor();
      assert.equal(await page.locator('[data-section="kept"]').count(), 1);
      assert.equal(await page.locator(`[data-kept="${KEPT_ID}"]`).count(), 1);
    });

  await check('HAOS 一次確認: the result of a restore of a converted backup lists the copy kept before it, and the notes of the restore (S4)',
    (() => {
      const data = haFixture();
      const copy = v2Kept('n8n');
      data.backups.unshift(convertedMeta(), copy);
      data.downloads[copy.id] = { path: `/var/lib/woowtech-backup/archives/${copy.id}.tar`, filename: copy.filename, size: copy.size };
      const script = haRestoreScript();
      Object.assign(script[1].job.result, { kept: { n8n: { backup_id: copy.id, ...V2_KEPT_DETAIL } }, warnings: [V2_PAUSE_WARNING] });
      data.scripts.restore = script;
      return data;
    })(), async page => {
      await ready(page);
      await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_HA);
      await page.locator('.app-preflight').first().waitFor();
      await page.locator('[data-focus="pf-next"]').click();
      await page.locator('#confirm-restore').check();
      await page.locator('[data-focus="confirm-start"]').click();
      await page.locator('#result-heading').filter({ hasText: '還原完成' }).waitFor({ timeout: 30000 });
      const copy = page.locator(`[data-section="kept"] [data-kept="${KEPT_ID}"][data-state="present"]`);
      await copy.waitFor();
      assert.match(await copy.textContent(), /複本裡的資料庫：「analytics」、「crm_old」，另有 3 個沒有列出。/);
      assert.match(await copy.textContent(), /crm_old：資料庫擁有者的角色在新的資料庫服務裡已經存在，沒有放回。/);
      assert.equal(await page.locator('[data-section="kept"]').count(), 1);
      // The warnings of the restore are listed as for any restore.
      assert.match(await page.locator('.job-result').textContent(), /注意事項[\s\S]*匯入時暫停的服務沒有重新啟動：filebrowser/);
    });

  await check('HAOS 一次確認 in the dark theme: the kept copies and their delete dialog keep WCAG AA contrast and fit every width',
    v2KeptFixture(), async page => {
      await ready(page);
      assert.equal(await page.evaluate(() => document.documentElement.classList.contains('pf-v6-theme-dark')), true);
      await v2KeptImport(page);
      assert.deepEqual((await contrastOf(page)).failures, [], 'the kept copies');
      await allWidths(page, 'HAOS dark kept copies');
      await page.locator(`[data-focus="kept-delete-${KEPT_ID}"]`).click();
      await page.locator('#confirm-dialog[open]').waitFor();
      assert.deepEqual((await contrastOf(page)).failures, [], 'the delete dialog');
      await page.locator('#confirm-cancel').click();
    }, { beforeGoto: page => page.addInitScript(() => localStorage.setItem('shell:style', 'dark')) });

  await check('HAOS 一次確認: a kept copy is marked in the backup list and its delete dialog says what is lost; the restore wizard of the converted backup names the databases that stay on HA and the copy',
    (() => {
      const data = haFixture();
      const copy = v2Kept('n8n');
      data.backups.unshift(convertedMeta({ from_ha: { ...haImportView(['odoo', 'n8n']), left_databases: ['test'], kept: copy.id } }), copy);
      data.downloads[copy.id] = { path: `/var/lib/woowtech-backup/archives/${copy.id}.tar`, filename: copy.filename, size: copy.size };
      return data;
    })(), async page => {
      await ready(page);
      await page.locator('[data-nav="backups"]').click();
      const row = page.locator(`tr[data-backup="${KEPT_ID}"]`);
      await row.waitFor();
      assert.deepEqual(await row.locator('td[data-label="類型"] .chip').allTextContents(), ['還原前備份', '保留的複本']);
      assert.deepEqual(await row.locator('td[data-label="加密與驗證"] .chip').allTextContents(), ['已加密', '金鑰可用']);
      assert.equal(await page.locator(`tr[data-backup="${B_HA}"]`).getByText('保留的複本').count(), 0, 'only the copy is marked');
      // The list of the kept copies: a filter that exists only while the device holds one.
      await page.locator('[data-focus="filter-kept"]').click();
      assert.deepEqual(await page.locator('#backup-results tbody tr').evaluateAll(rows => rows.map(item => item.dataset.backup)), [KEPT_ID]);
      await page.locator('[data-focus="filter-all"]').click();
      assert.equal(await page.locator('#backup-results tbody tr').count() > 1, true);
      await page.locator('#backup-search').fill('保留的複本');
      assert.deepEqual(await page.locator('#backup-results tbody tr').evaluateAll(rows => rows.map(item => item.dataset.backup)), [KEPT_ID], 'the words find it too');
      await page.locator('#backup-search').fill('');
      await row.locator(`[data-focus="delete-${KEPT_ID}"]`).click();
      assert.equal(await page.locator('#confirm-title').textContent(), '刪除保留的複本？');
      assert.match(await page.locator('#confirm-body').textContent(), /刪除後，這些資料就沒有了/);
      await page.locator('#confirm-cancel').click();
      assert.equal((await calls(page, 'delete')).length, 0);
      // A converted backup's restore: what stayed behind is in the notice before anything is replaced.
      await page.evaluate(id => { window.location.hash = `#/restore/${id}`; }, B_HA);
      await page.locator('.ha-banner').waitFor();
      const banner = await page.locator('.ha-banner').textContent();
      assert.match(banner, /HA 的 Odoo 還有「test」沒有搬過來，它們留在 HA；HA 的 Odoo 停用後就看不到了。這台 Odoo 一次只放一個資料庫，以後再匯入另一個會取代這次的。/);
      assert.match(banner, new RegExp(`完整複本（${KEPT_ID}）`));
    });


} finally {
  try { await browser?.close(); } finally { if (server.listening) await new Promise(done => server.close(done)); }
}
