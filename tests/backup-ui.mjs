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
  restore: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['preflight', '相容性檢查'], ['safety', '建立還原前備份'],
    ['stop', '停止應用'], ['restore', '還原資料'], ['start', '啟動應用'], ['check', '健康與資料核對']],
  verify: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['check', '核對結果']],
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
const VERIFY_BEFORE = { summary: { notes: 12, files: 4, digest: '9c1d0f7a', title: '示範筆記', signatures_valid: true } };

function scripts() {
  return {
    backup: [
      runningStep('backup', 'dump', 40),
      runningStep('backup', 'package', 80, { cancellable: true }),
      {
        job: { state: 'succeeded', phase: 'verify', phases: phasesAt('backup', null), progress: { percent: 100, message: '已完成' },
          finished: '2026-11-13T02:05:30Z', cancellable: false,
          result: { backup_id: B_NEW, size: 52 * MiB, apps: ['woowbk-demo'], downtime_seconds: 7 } },
        log: ['2026-11-13T02:05:29Z 備份 20261113T020500Z-feedbeef 已建立並通過完整驗證（52.0 MiB）', '2026-11-13T02:05:30Z 作業結束：已完成'],
        addBackup: {
          id: B_NEW, type: 'manual', created: '2026-11-13T02:05:00Z', note: '更新前備份', apps: [{ id: 'woowbk-demo', name: '示範筆記應用' }],
          size: 52 * MiB, sha256: 'e'.repeat(64), key_id: KEY_ID, key_available: true, include_images: true,
          filename: 'woowtech-backup-dev-a-20261113-020500.woowbackup', source: { hostname: 'dev-a' },
          verified: { at: '2026-11-13T02:05:29Z', ok: true }, inspected: true,
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
          finished: '2026-11-13T02:10:00Z', cancellable: false, result: { ok: true, entries: 9, bytes: 51 * MiB } },
        log: ['2026-11-13T02:10:00Z 作業結束：已完成'],
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
  key_available: true, include_images: false, filename: `woowtech-backup-dev-a-${id.slice(0, 8)}-${id.slice(9, 15)}.woowbackup`,
  source: { hostname: 'dev-a' }, verified: { at: '2026-11-12T02:01:00Z', ok: true }, inspected: true, ...extra,
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
  const safety = backupMeta(B_SAFETY, { type: 'safety', note: '還原前自動備份（還原來源 20261101T020000Z-11112222）', verified: null });
  const uploaded = backupMeta(B_UPLOADED, {
    type: 'uploaded', note: '', apps: [], key_id: OTHER_KEY_ID, key_available: false, inspected: false, verified: null,
    source: null, uploaded_at: '2026-11-13T01:02:00Z', filename: 'woowtech-backup-dev-b-20261113-010000.woowbackup',
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
    },
    backups: [manual, safety, uploaded],
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
    downloads: Object.fromEntries([B_MANUAL, B_SAFETY, B_UPLOADED, B_NEW].map(id => [id, {
      path: `/var/lib/woowtech-backup/archives/${id}.woowbackup`, size: 48 * MiB,
      filename: id === B_NEW ? 'woowtech-backup-dev-a-20261113-020500.woowbackup' : `woowtech-backup-dev-a-${id.slice(0, 8)}-${id.slice(9, 15)}.woowbackup`,
    }])),
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
    'backup-start': { required: ['apps', 'request_id'], optional: ['include_images', 'note'] },
    'verify-start': { required: ['backup_id', 'request_id'], optional: ['key'] },
    'restore-start': { required: ['backup_id', 'apps', 'request_id', 'confirm'], optional: ['key', 'save_key', 'allow_no_safety'] },
    'job-status': { required: ['job_id'], optional: [] }, 'job-cancel': { required: ['job_id'], optional: [] },
    delete: { required: ['backup_id'], optional: [] }, 'upload-begin': { required: ['filename', 'size'], optional: [] },
    'upload-finish': { required: ['upload_id'], optional: [] }, 'upload-abort': { required: ['upload_id'], optional: [] },
    'download-info': { required: ['backup_id'], optional: [] },
  };
  const NO_INPUT = ['status', 'list', 'key-init', 'key-kit', 'jobs'];
  const PHASE_LABELS = {
    backup: [['prepare', '準備'], ['check', '檢查空間與應用'], ['stop', '暫停應用寫入'], ['dump', '匯出資料庫'],
      ['export', '匯出資料卷與設定'], ['start', '恢復應用'], ['package', '加密封裝'], ['verify', '驗證備份']],
    restore: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['preflight', '相容性檢查'], ['safety', '建立還原前備份'],
      ['stop', '停止應用'], ['restore', '還原資料'], ['start', '啟動應用'], ['check', '健康與資料核對']],
    verify: [['prepare', '準備'], ['decrypt', '解密並驗證檔案'], ['check', '核對結果']],
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
  const refreshKeys = () => data.backups.forEach(item => { item.key_available = keyKnown(item.key_id); });

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

  function handle(command, request) {
    switch (command) {
      case 'status':
        data.status.storage.backup_count = data.backups.length;
        return structuredClone(data.status);
      case 'list':
        return { backups: structuredClone(data.backups) };
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
        if (!keyKnown(meta.key_id)) {
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
      case 'backup-start':
        if (!Array.isArray(request.apps) || !request.apps.length) throw new Refusal('invalid-request', '欄位 apps 必須是陣列。');
        return startJob('backup', { apps: request.apps, include_images: Boolean(request.include_images), note: request.note || '' }, request.request_id);
      case 'verify-start':
        if (!backup(request.backup_id)) throw new Refusal('not-found', '找不到指定的備份。');
        return startJob('verify', { backup_id: request.backup_id, key_provided: 'key' in request }, request.request_id);
      case 'restore-start':
        if (request.confirm !== true) throw new Refusal('invalid-request', '欄位 confirm 必須為 true（需要明確確認）。');
        if (!backup(request.backup_id)) throw new Refusal('not-found', '找不到指定的備份。');
        return startJob('restore', { backup_id: request.backup_id, apps: request.apps, key_provided: 'key' in request && !request.save_key,
          ...(request.allow_no_safety ? { allow_no_safety: true } : {}) }, request.request_id);
      case 'job-status': {
        const record = data.jobs[request.job_id];
        if (!record) throw new Refusal('not-found', '找不到指定的作業。');
        const step = record.steps.shift();
        if (step) {
          Object.assign(record.job, step.job);
          record.log.push(...(step.log || []));
          if (step.addBackup) data.backups.unshift(structuredClone(step.addBackup));
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
    assert.deepEqual(Object.keys(start).sort(), ['apps', 'include_images', 'note', 'request_id']);
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
    const statusPolls = (await calls(page, 'job-status')).length;
    assert(statusPolls >= 3, 'polled job-status while active');
    await page.waitForTimeout(1800);
    assert.equal((await calls(page, 'job-status')).length, statusPolls, 'polling stops once the job is terminal');
    const before = downloadRequests.length;
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-focus="result-download"]').click()]);
    assert.deepEqual(requestOf((await calls(page, 'download-info')).at(-1)), { backup_id: B_NEW });
    assert.equal(download.suggestedFilename(), 'woowtech-backup-dev-a-20261113-020500.woowbackup', 'names carry seconds');
    const request = downloadRequests[before];
    assert.equal(request.token, CSRF, 'the channel URL carries the CSRF token from cockpit.transport');
    assert.deepEqual(request.open, {
      payload: 'fsread1', binary: 'raw', path: `/var/lib/woowtech-backup/archives/${B_NEW}.woowbackup`, superuser: 'require', max_read_size: -1,
      external: { 'content-disposition': "attachment; filename*=UTF-8''woowtech-backup-dev-a-20261113-020500.woowbackup", 'content-type': 'application/octet-stream' },
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
    // Review F15: phase labels never break a word across lines at desktop widths.
    for (const width of [1440, 1280, 1024]) {
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
    assert.deepEqual(await dirRows(card.locator('details.app-details .path-list')), DIR_ROWS.map(row => [null, ...row]),
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

} finally {
  try { await browser?.close(); } finally { if (server.listening) await new Promise(done => server.close(done)); }
}
