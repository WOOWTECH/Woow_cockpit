// Fixture browser tests for the Cockpit package woowtechbackup (docs/backup/CONTRACT.md §7, §11).
// A fake window.cockpit records every helper call (argv, options, stdin) and simulates the bridge:
// fsreplace1 upload channels with "ack" control messages, the external fsread1 download URL,
// cockpit.location, permission, user and transport. No process is ever launched.
//   PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chrome node tests/backup-ui.mjs
//   BACKUP_UI_SCREENSHOTS=/some/dir  (optional) saves evidence screenshots there.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium } from 'playwright-core';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
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
    scripts: scripts(),
    jobs: {},
    ...overrides,
  };
  return data;
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
    'restore-start': { required: ['backup_id', 'apps', 'request_id', 'confirm'], optional: ['key', 'save_key', 'allow_no_safety', 'accept_unauthenticated'] },
    'settings-set': { required: ['encrypt_by_default'], optional: ['acknowledge_plaintext'] },
    'export-start': { required: ['backup_id', 'request_id', 'confirm'], optional: ['key'] },
    'export-info': { required: ['export_id'], optional: [] }, 'export-delete': { required: ['export_id'], optional: [] },
    'catalog-suggest': { required: [], optional: ['owner'] },
    'catalog-install': { required: ['entry'], optional: ['confirm', 'expected_sha256'] },
    'catalog-remove': { required: ['id'], optional: ['confirm', 'expected_sha256'] },
    'retention-plan': { required: [], optional: ['policy'] },
    'retention-apply': { required: ['confirm', 'backup_ids'], optional: ['policy'] },
    'job-status': { required: ['job_id'], optional: [] }, 'job-cancel': { required: ['job_id'], optional: [] },
    delete: { required: ['backup_id'], optional: [] }, 'upload-begin': { required: ['filename', 'size'], optional: [] },
    'upload-finish': { required: ['upload_id'], optional: [] }, 'upload-abort': { required: ['upload_id'], optional: [] },
    'download-info': { required: ['backup_id'], optional: [] },
  };
  const NO_INPUT = ['status', 'list', 'key-init', 'key-kit', 'jobs', 'settings-get'];
  const PHASE_LABELS = {
    backup: [['prepare', '準備'], ['check', '檢查空間與應用'], ['stop', '暫停應用寫入'], ['dump', '匯出資料庫'],
      ['export', '匯出資料卷與設定'], ['start', '恢復應用'], ['package', '加密封裝'], ['verify', '驗證備份']],
    restore: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['preflight', '相容性檢查'], ['stage', '預先寫入主機資料夾'],
      ['safety', '建立還原前備份'], ['stop', '停止應用'], ['restore', '還原資料'], ['start', '啟動應用'], ['check', '健康與資料核對']],
    verify: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['check', '核對結果']],
    export: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['package', '封裝未加密副本'], ['verify', '驗證副本']],
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

  function startJob(type, params, requestId) {
    if (typeof requestId !== 'string' || requestId.length < 8) throw new Refusal('invalid-request', '請求識別碼格式不正確。');
    if (requests[requestId]) return { job_id: requests[requestId], deduplicated: true };
    const running = active();
    if (running) throw new Refusal('busy', '已有備份或還原作業正在進行，請等它完成後再試。', { job_id: running.job.id });
    jobSeq += 1;
    const id = `j20261113T0200${String(10 + jobSeq).padStart(2, '0')}Z-${(0xabc000 + jobSeq).toString(16).padStart(8, '0')}`;
    const job = { id, type, state: 'queued', phase: 'prepare', phases: PHASE_LABELS[type].map(([phase, label]) => ({ id: phase, label, state: 'pending' })),
      progress: { percent: 0, message: '等待開始' }, created: `2026-11-13T02:00:${String(10 + jobSeq).padStart(2, '0')}Z`, started: null,
      finished: null, params, result: null, error: null, cancellable: true };
    data.jobs[id] = { job, log: [`${job.created} 作業已排入背景執行`], steps: structuredClone(data.scripts[type] || []) };
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
    const manual = data.backups.filter(item => item.type === 'manual').sort((a, b) => b.created.localeCompare(a.created));
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

  function handle(command, request) {
    switch (command) {
      case 'status':
        data.status.storage.backup_count = data.backups.length;
        return structuredClone(data.status);
      case 'list':
        return { backups: structuredClone(data.backups), exports: structuredClone(data.exports || []) };
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
        return { jobs: Object.values(data.jobs).map(item => structuredClone(item.job)).sort((a, b) => b.created.localeCompare(a.created)) };
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
        const result = data.inspect[request.backup_id];
        if (!meta || !result) throw new Refusal('not-found', '找不到指定的備份。');
        if (meta.encrypted === false && request.key !== undefined) throw new Refusal('invalid-request', '這份備份沒有加密，不需要金鑰。', { field: 'key' });
        if (meta.encrypted !== false && !keyKnown(meta.key_id)) {
          if (request.key === undefined) throw new Refusal('key-required', '此備份使用的金鑰不在本設備，請輸入緊急金鑰。', { key_id: meta.key_id });
          if (data.secrets[request.key] !== meta.key_id) throw new Refusal('wrong-key', '金鑰不正確，無法解密這份備份。');
          if (request.save_key) {
            data.status.imported_keys.push({ key_id: meta.key_id, created: '2026-11-13T02:30:00Z' });
            refreshKeys();
          }
        }
        Object.assign(meta, { inspected: true, apps: structuredClone(result.backup.apps), source: structuredClone(result.backup.source) });
        return { ...structuredClone(result), backup: structuredClone(meta) };
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
          if (step.addBackup) data.backups.unshift(structuredClone(step.addBackup));
          if (step.addExport) data.exports = [...(data.exports || []), structuredClone(step.addExport)];
          if (step.verified && record.job.params?.backup_id) {
            const meta = backup(record.job.params.backup_id);
            if (meta) meta.verified = structuredClone(step.verified);
          }
        }
        data.status.active_job = ACTIVE.includes(record.job.state) ? structuredClone(record.job)
          : data.status.active_job?.id === record.job.id ? null : data.status.active_job;
        return { job: structuredClone(record.job), log: record.log.slice(-200) };
      }
      case 'job-cancel': {
        const record = data.jobs[request.job_id];
        if (!record) throw new Refusal('not-found', '找不到指定的作業。');
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
        return {};
      }
      case 'upload-begin':
        if (request.size > data.upload.begin.max_size) throw new Refusal('insufficient-space', '磁碟空間不足，無法上傳此備份檔。');
        return structuredClone(data.upload.begin);
      case 'upload-finish': {
        if (request.upload_id !== data.upload.begin.upload_id) throw new Refusal('not-found', '找不到上傳工作。');
        const channel = window.testchannels.at(-1);
        if (!channel?.done || channel.sent !== channel.options.size) throw new Refusal('invalid-request', '上傳的檔案大小與宣告不符，上傳可能未完成。');
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
      }
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
    assert.equal(manifest.menu.index.label, '備份與還原');
    assert.equal(manifest.menu.index.order, 46);
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
    assert.match(confirmText, /自動用它回復/);
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
    assert.equal(await background(), 'rgb(21, 23, 28)');
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

} finally {
  try { await browser?.close(); } finally { if (server.listening) await new Promise(done => server.close(done)); }
}
