/* woowtech Cockpit「備份與還原」(Cockpit package woowtechbackup).
 *
 * Binding contract: docs/backup/CONTRACT.md §7 (helper CLI) and §11 (UI).
 * - Every privileged action runs the fixed root helper through cockpit.spawn with the request as
 *   JSON on stdin; the reply is exactly one JSON object on stdout, captured as it streams so it
 *   survives a process that exits with status 1.
 * - Uploads stream File.slice() chunks over an fsreplace1 channel with "send-acks": "bytes"
 *   flow control; downloads navigate a hidden iframe to Cockpit's external fsread1 channel URL.
 * - Helper data is rendered with textContent/createElement only; nothing is parsed as HTML.
 * - Key material is only ever sent in the stdin field `key` and is dropped once a job started.
 * - Backups are encrypted unless the administrator chose otherwise (預設加密備份 / 加密此備份, CONTRACT §3, §7);
 *   every unencrypted backup, copy or upload is a separately acknowledged decision with the engine's warning text.
 * - 應用設定 (catalog drafts) and 清理備份 (retention) call the read-only previews first and confirm with the
 *   preview's own values (expected_sha256, the kept backup ids); docs/backup/CONTRACT.md sections 4, 7, 8.
 * Icons: Material Design Icons path data (Pictogrammers, Apache-2.0), built with DOM APIs; lock-open-variant-outline
 * is the lock-outline path with its shackle opened.
 */

/* Match Cockpit's shell:style preference and OS theme, including live changes.
 * Same bridge as service management; see cockpit/pkg/lib/cockpit-dark-theme.ts (LGPL-2.1-or-later).
 * The preference is only read here, never written. */
(() => {
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  function applyTheme(override) {
    let preference = override;
    if (!preference) {
      try { preference = localStorage.getItem('shell:style'); } catch { /* use system preference */ }
    }
    preference ||= 'auto';
    const root = document.documentElement;
    const dark = preference === 'dark' || (preference === 'auto' && system.matches);
    if (root.classList.contains('pf-v6-theme-dark') === dark) return;
    // Switch without colour transitions, so controls never pass through unreadable mid-tones.
    root.classList.add('theme-switching');
    root.classList.toggle('pf-v6-theme-dark', dark);
    requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('theme-switching')));
  }
  window.addEventListener('storage', event => {
    if (event.key === 'shell:style' || event.key === null) applyTheme();
  });
  window.addEventListener('cockpit-style', event => applyTheme(event.detail?.style));
  system.addEventListener('change', () => applyTheme());
  applyTheme();
})();
(() => {
  "use strict";

  const cockpit = window.cockpit;
  const HELPER = "/usr/local/libexec/woowtech-cockpit-backup";
  // Upload frames and the unacknowledged window (CONTRACT §11). Measured through the real Cockpit 362 on the lab
  // (H8, 2026-11-13, 6 sha256-checked runs each): 512 KiB frames in a 4 MiB window 12.8 MB/s median against
  // 6.7 MB/s for 64 KiB in 2 MiB; the frame size, not the window, was the bottleneck.
  const CHUNK_SIZE = 512 * 1024;
  const WINDOW_SIZE = 4 * 1024 * 1024;
  const JOB_POLL_MS = 1500;
  const STATUS_POLL_MS = 30000;
  const BACKUP_ID_RE = /^\d{8}T\d{6}Z-[0-9a-f]{8}$/;
  const JOB_ID_RE = /^j\d{8}T\d{6}Z-[0-9a-f]{8}$/;
  const SECRET_RE = /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/gi;
  const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
  const ACCESS_HELP = "請在 Cockpit 頂端開啟「管理員存取權限」，再重試。";
  const ACTIVE = new Set(["queued", "running"]);
  const TERMINAL = new Set(["succeeded", "failed", "rolled-back", "interrupted", "cancelled"]);
  const READS = new Set(["status", "list", "jobs", "job-status", "inspect", "key-kit", "download-info", "settings-get",
    "catalog-suggest", "retention-plan"]);
  const TIMEOUTS = {
    inspect: 300000, "upload-begin": 120000, "upload-finish": 900000, "upload-abort": 120000, "key-import": 120000,
    "backup-start": 120000, "restore-start": 120000, "verify-start": 120000, "key-init": 120000, delete: 120000,
    "settings-set": 120000, "export-start": 120000, "export-info": 120000, "export-delete": 120000,
    // The scan runs owner-side helpers and podman/systemctl as the owner; a cleanup may delete many large files.
    "catalog-suggest": 300000, "catalog-install": 180000, "catalog-remove": 180000, "retention-plan": 180000,
    "retention-apply": 600000
  };
  // upload-finish hashes the whole file before it answers: allow 20 MB/s plus two minutes, at least 15 minutes.
  const finishTimeout = size => Math.max(TIMEOUTS["upload-finish"], 120000 + Math.ceil((Number(size) || 0) / (20 * 1000 * 1000)) * 1000);
  const UPLOADING = new Set(["begin", "sending", "finishing"]);
  // An upload whose check timed out is still on the device, and the device keeps checking it (review finding HD-08):
  // it stays the active upload, so another restore never replaces it and leaving the page asks first.
  const UPLOAD_PENDING = new Set([...UPLOADING, "unconfirmed"]);
  const WRONG_KEY = "這把金鑰無法解開這份備份（金鑰 ID 不符）。請確認是建立這份備份的設備所產生的緊急金鑰。";
  const VERIFY_FAILED = "這份備份上次驗證未通過。還原時會先完整驗證整份備份，驗證不通過就不會變更任何資料，但這份備份很可能無法使用。";
  const ROUTES = new Set(["overview", "backups", "create", "restore", "jobs", "keys", "activity", "catalog", "cleanup"]);
  const NAV_FOR = {
    overview: "overview", backups: "backups", create: "overview", restore: "restore", jobs: "activity", keys: "keys",
    activity: "activity", catalog: "catalog", cleanup: "backups"
  };
  // The engine's text (settings.PLAINTEXT_WARNING); the status reply carries the authoritative copy.
  const PLAINTEXT_FALLBACK = "未加密的備份會以明文儲存與下載資料庫密碼、API 金鑰與存取權杖等應用機密；任何取得備份檔的人都能讀取，也無法確認檔案在設備以外是否被修改過。";
  const UNSUPPORTED = "這台設備的備份元件版本尚未提供這項功能。請將備份元件更新到與這個頁面相同的版本後再試。";
  const KEEP_MAX = 1000;
  const APP_ID_RE = /^[a-z0-9][a-z0-9-]{1,40}$/;
  const OWNER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
  const EXPORT_ID_RE = /^x[0-9a-f]{16}$/;
  const CATALOG_MAX = 256 * 1024;

  const TYPE_LABELS = { manual: "手動", safety: "還原前備份", uploaded: "上傳" };
  const JOB_TYPES = { backup: "備份", restore: "還原", verify: "驗證", export: "未加密副本" };
  const JOB_TITLES = { backup: "備份作業", restore: "還原作業", verify: "驗證作業", export: "建立未加密副本" };
  const jobTitle = type => JOB_TITLES[type] || "作業";
  const JOB_STATES = {
    queued: "等待開始", running: "執行中", succeeded: "已完成", failed: "失敗",
    "rolled-back": "已自動回復", interrupted: "已中斷", cancelled: "已取消"
  };
  const APP_STATES = { running: "執行中", stopped: "已停止", partial: "部分執行", "not-deployed": "未部署", error: "異常" };
  const PHASE_STATES = { pending: "等待", active: "進行中", done: "完成", failed: "失敗", skipped: "略過" };
  const CHECK_STATES = { ok: "通過", warn: "注意", fail: "未通過" };
  const MODES = { inplace: "原位還原", fresh: "全新部署" };

  const ICONS = {
    "alert-circle-outline": "M11,15H13V17H11V15M11,7H13V13H11V7M12,2C6.47,2 2,6.5 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20Z",
    "alert-outline": "M12,2L1,21H23M12,6L19.53,19H4.47M11,10V14H13V10M11,16V18H13V16",
    "arrow-left": "M20,11V13H8L13.5,18.5L12.08,19.92L4.16,12L12.08,4.08L13.5,5.5L8,11H20Z",
    "backup-restore": "M12,3A9,9 0 0,0 3,12H0L4,16L8,12H5A7,7 0 0,1 12,5A7,7 0 0,1 19,12A7,7 0 0,1 12,19C10.5,19 9.09,18.5 7.94,17.7L6.5,19.14C8.04,20.3 9.94,21 12,21A9,9 0 0,0 21,12A9,9 0 0,0 12,3M14,12A2,2 0 0,0 12,10A2,2 0 0,0 10,12A2,2 0 0,0 12,14A2,2 0 0,0 14,12Z",
    "check": "M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z",
    "check-circle": "M12 2C6.5 2 2 6.5 2 12S6.5 22 12 22 22 17.5 22 12 17.5 2 12 2M10 17L5 12L6.41 10.59L10 14.17L17.59 6.58L19 8L10 17Z",
    "check-circle-outline": "M12 2C6.5 2 2 6.5 2 12S6.5 22 12 22 22 17.5 22 12 17.5 2 12 2M12 20C7.59 20 4 16.41 4 12S7.59 4 12 4 20 7.59 20 12 16.41 20 12 20M16.59 7.58L10 14.17L7.41 11.59L6 13L10 17L18 9L16.59 7.58Z",
    "chevron-down": "M7.41,8.59L12,13.17L16.59,8.59L18,10L12,16L6,10L7.41,8.59Z",
    "chevron-right": "M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z",
    "circle-medium": "M12,8A4,4 0 0,0 8,12A4,4 0 0,0 12,16A4,4 0 0,0 16,12A4,4 0 0,0 12,8Z",
    "clipboard-text-outline": "M19,3H14.82C14.25,1.44 12.53,0.64 11,1.2C10.14,1.5 9.5,2.16 9.18,3H5A2,2 0 0,0 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V5A2,2 0 0,0 19,3M12,3A1,1 0 0,1 13,4A1,1 0 0,1 12,5A1,1 0 0,1 11,4A1,1 0 0,1 12,3M7,7H17V5H19V19H5V5H7V7M17,11H7V9H17V11M15,15H7V13H15V15Z",
    "close-circle-outline": "M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2C6.47,2 2,6.47 2,12C2,17.53 6.47,22 12,22C17.53,22 22,17.53 22,12C22,6.47 17.53,2 12,2M14.59,8L12,10.59L9.41,8L8,9.41L10.59,12L8,14.59L9.41,16L12,13.41L14.59,16L16,14.59L13.41,12L16,9.41L14.59,8Z",
    "content-copy": "M19,21H8V7H19M19,5H8A2,2 0 0,0 6,7V21A2,2 0 0,0 8,23H19A2,2 0 0,0 21,21V7A2,2 0 0,0 19,5M16,1H4A2,2 0 0,0 2,3V17H4V3H16V1Z",
    "database-outline": "M12 3C7.58 3 4 4.79 4 7V17C4 19.21 7.59 21 12 21S20 19.21 20 17V7C20 4.79 16.42 3 12 3M18 17C18 17.5 15.87 19 12 19S6 17.5 6 17V14.77C7.61 15.55 9.72 16 12 16S16.39 15.55 18 14.77V17M18 12.45C16.7 13.4 14.42 14 12 14C9.58 14 7.3 13.4 6 12.45V9.64C7.47 10.47 9.61 11 12 11C14.39 11 16.53 10.47 18 9.64V12.45M12 9C8.13 9 6 7.5 6 7S8.13 5 12 5C15.87 5 18 6.5 18 7S15.87 9 12 9Z",
    "delete-outline": "M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19M8,9H16V19H8V9M15.5,4L14.5,3H9.5L8.5,4H5V6H19V4H15.5Z",
    "eye-outline": "M12,9A3,3 0 0,1 15,12A3,3 0 0,1 12,15A3,3 0 0,1 9,12A3,3 0 0,1 12,9M12,4.5C17,4.5 21.27,7.61 23,12C21.27,16.39 17,19.5 12,19.5C7,19.5 2.73,16.39 1,12C2.73,7.61 7,4.5 12,4.5M3.18,12C4.83,15.36 8.24,17.5 12,17.5C15.76,17.5 19.17,15.36 20.82,12C19.17,8.64 15.76,6.5 12,6.5C8.24,6.5 4.83,8.64 3.18,12Z",
    "file-document-outline": "M6,2A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6M6,4H13V9H18V20H6V4M8,12V14H16V12H8M8,16V18H13V16H8Z",
    "file-key-outline": "M14 2H6A2 2 0 0 0 4 4V20A2 2 0 0 0 6 22H18A2 2 0 0 0 20 20V8L14 2M18 20H6V4H13V9H18M12.83 15A3 3 0 1 0 12.83 17H14V19H16V17H17V15M10 17A1 1 0 1 1 11 16A1 1 0 0 1 10 17Z",
    "harddisk": "M6,2H18A2,2 0 0,1 20,4V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V4A2,2 0 0,1 6,2M12,4A6,6 0 0,0 6,10C6,13.31 8.69,16 12.1,16L11.22,13.77C10.95,13.29 11.11,12.68 11.59,12.4L12.45,11.9C12.93,11.63 13.54,11.79 13.82,12.27L15.74,14.69C17.12,13.59 18,11.9 18,10A6,6 0 0,0 12,4M12,9A1,1 0 0,1 13,10A1,1 0 0,1 12,11A1,1 0 0,1 11,10A1,1 0 0,1 12,9M7,18A1,1 0 0,0 6,19A1,1 0 0,0 7,20A1,1 0 0,0 8,19A1,1 0 0,0 7,18M12.09,13.27L14.58,19.58L17.17,18.08L12.95,12.77L12.09,13.27Z",
    "information-outline": "M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z",
    "key-outline": "M21 18H15V15H13.3C12.2 17.4 9.7 19 7 19C3.1 19 0 15.9 0 12S3.1 5 7 5C9.7 5 12.2 6.6 13.3 9H24V15H21V18M17 16H19V13H22V11H11.9L11.7 10.3C11 8.3 9.1 7 7 7C4.2 7 2 9.2 2 12S4.2 17 7 17C9.1 17 11 15.7 11.7 13.7L11.9 13H17V16M7 15C5.3 15 4 13.7 4 12S5.3 9 7 9 10 10.3 10 12 8.7 15 7 15M7 11C6.4 11 6 11.4 6 12S6.4 13 7 13 8 12.6 8 12 7.6 11 7 11Z",
    "key-variant": "M22,18V22H18V19H15V16H12L9.74,13.74C9.19,13.91 8.61,14 8,14A6,6 0 0,1 2,8A6,6 0 0,1 8,2A6,6 0 0,1 14,8C14,8.61 13.91,9.19 13.74,9.74L22,18M7,5A2,2 0 0,0 5,7A2,2 0 0,0 7,9A2,2 0 0,0 9,7A2,2 0 0,0 7,5Z",
    "lock-outline": "M12,17C10.89,17 10,16.1 10,15C10,13.89 10.89,13 12,13A2,2 0 0,1 14,15A2,2 0 0,1 12,17M18,20V10H6V20H18M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V10C4,8.89 4.89,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z",
    "lock-open-variant-outline": "M12,17C10.89,17 10,16.1 10,15C10,13.89 10.89,13 12,13A2,2 0 0,1 14,15A2,2 0 0,1 12,17M18,20V10H6V20H18M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V10C4,8.89 4.89,8 6,8H15V6A3,3 0 0,0 12,3A3,3 0 0,0 9,6H7A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18Z",
    "magnify": "M9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.44,13.73L14.71,14H15.5L20.5,19L19,20.5L14,15.5V14.71L13.73,14.44C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3M9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5Z",
    "minus-circle-outline": "M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M7,13H17V11H7",
    "package-variant-closed": "M21,16.5C21,16.88 20.79,17.21 20.47,17.38L12.57,21.82C12.41,21.94 12.21,22 12,22C11.79,22 11.59,21.94 11.43,21.82L3.53,17.38C3.21,17.21 3,16.88 3,16.5V7.5C3,7.12 3.21,6.79 3.53,6.62L11.43,2.18C11.59,2.06 11.79,2 12,2C12.21,2 12.41,2.06 12.57,2.18L20.47,6.62C20.79,6.79 21,7.12 21,7.5V16.5M12,4.15L10.11,5.22L16,8.61L17.96,7.5L12,4.15M6.04,7.5L12,10.85L13.96,9.75L8.08,6.35L6.04,7.5M5,15.91L11,19.29V12.58L5,9.21V15.91M19,15.91V9.21L13,12.58V19.29L19,15.91Z",
    "plus": "M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z",
    "progress-clock": "M13,2.03V2.05L13,4.05C17.39,4.59 20.5,8.58 19.96,12.97C19.5,16.61 16.64,19.5 13,19.93V21.93C18.5,21.38 22.5,16.5 21.95,11C21.5,6.25 17.73,2.5 13,2.03M11,2.06C9.05,2.25 7.19,3 5.67,4.26L7.1,5.74C8.22,4.84 9.57,4.26 11,4.06V2.06M4.26,5.67C3,7.19 2.25,9.04 2.05,11H4.05C4.24,9.58 4.8,8.23 5.69,7.1L4.26,5.67M2.06,13C2.26,14.96 3.03,16.81 4.27,18.33L5.69,16.9C4.81,15.77 4.24,14.42 4.06,13H2.06M7.1,18.37L5.67,19.74C7.18,21 9.04,21.79 11,22V20C9.58,19.82 8.23,19.25 7.1,18.37M12.5,7V12.25L17,14.92L16.25,16.15L11,13V7H12.5Z",
    "refresh": "M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z",
    "server-network": "M13,19H14A1,1 0 0,1 15,20H22V22H15A1,1 0 0,1 14,23H10A1,1 0 0,1 9,22H2V20H9A1,1 0 0,1 10,19H11V17H4A1,1 0 0,1 3,16V12A1,1 0 0,1 4,11H20A1,1 0 0,1 21,12V16A1,1 0 0,1 20,17H13V19M4,3H20A1,1 0 0,1 21,4V8A1,1 0 0,1 20,9H4A1,1 0 0,1 3,8V4A1,1 0 0,1 4,3M9,7H10V5H9V7M9,15H10V13H9V15M5,5V7H7V5H5M5,13V15H7V13H5Z",
    "shield-check-outline": "M21,11C21,16.55 17.16,21.74 12,23C6.84,21.74 3,16.55 3,11V5L12,1L21,5V11M12,21C15.75,20 19,15.54 19,11.22V6.3L12,3.18L5,6.3V11.22C5,15.54 8.25,20 12,21M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9",
    "stop-circle-outline": "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4M9,9V15H15V9",
    "timer-sand": "M6,2H18V8H18V8L14,12L18,16V16H18V22H6V16H6V16L10,12L6,8V8H6V2M16,16.5L12,12.5L8,16.5V20H16V16.5M12,11.5L16,7.5V4H8V7.5L12,11.5M10,6H14V6.75L12,8.75L10,6.75V6Z",
    "tray-arrow-down": "M2 12H4V17H20V12H22V17C22 18.11 21.11 19 20 19H4C2.9 19 2 18.11 2 17V12M12 15L17.55 9.54L16.13 8.13L13 11.25V2H11V11.25L7.88 8.13L6.46 9.55L12 15Z",
    "tray-arrow-up": "M2 12H4V17H20V12H22V17C22 18.11 21.11 19 20 19H4C2.9 19 2 18.11 2 17V12M12 2L6.46 7.46L7.88 8.88L11 5.75V15H13V5.75L16.13 8.88L17.55 7.45L12 2Z"
  };

  // ------------------------------------------------------------------ small helpers

  const $ = id => document.getElementById(id);
  const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const isString = value => typeof value === "string";
  const isNumber = value => typeof value === "number" && Number.isFinite(value);
  const str = value => (isString(value) ? value : value === null || value === undefined ? "" : String(value));
  const list = value => (Array.isArray(value) ? value : []);
  const text = (node, value) => { node.textContent = str(value); };
  const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
  const visible = () => !document.hidden && !cockpit?.hidden;
  const SVG_NS = "http://www.w3.org/2000/svg";
  const PROPS = new Set(["id", "type", "value", "checked", "disabled", "hidden", "href", "htmlFor", "name", "title",
    "tabIndex", "maxLength", "rows", "accept", "placeholder", "readOnly", "max", "min", "colSpan", "download"]);

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = str(value);
        else if (key === "on") for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler);
        else if (key === "dataset") {
          for (const [name, item] of Object.entries(value)) if (item !== undefined && item !== null) node.dataset[name] = str(item);
        } else if (PROPS.has(key)) node[key] = value;
        else node.setAttribute(key, value === true ? "" : str(value));
      }
    }
    return add(node, children);
  }

  function add(node, children) {
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      if (Array.isArray(child)) add(node, child);
      else if (child instanceof Node) node.append(child);
      else node.append(document.createTextNode(str(child)));
    }
    return node;
  }

  // replaceChildren() stringifies null; fill() skips empty slots and flattens arrays instead.
  function fill(node, ...children) {
    node.replaceChildren();
    return add(node, children);
  }

  function icon(name, className = "icon") {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    svg.setAttribute("class", className);
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", ICONS[name] || ICONS["information-outline"]);
    svg.append(path);
    return svg;
  }

  const tile = (name, small = false) => h("span", { class: small ? "tile tile-sm" : "tile" }, icon(name));
  const hrefFor = path => "#/" + path.filter(item => item !== null && item !== undefined && item !== "").map(item => encodeURIComponent(item)).join("/");

  function link(content, path, props = {}) {
    return h("a", { ...props, href: hrefFor(path) }, content);
  }

  // Native file inputs print browser-language text; a zh-TW button opens a hidden input instead.
  function filePicker({ id, accept, buttonLabel = "選擇檔案", label, fileName = "", disabled = false, focus, describedBy, onFile }) {
    const input = h("input", {
      id, type: "file", accept, hidden: true, tabIndex: -1, disabled,
      on: { change: event => { const file = event.target.files?.[0] || null; event.target.value = ""; onFile(file); } }
    });
    const trigger = button(buttonLabel, () => input.click(), { icon: "file-document-outline", disabled, focus, label });
    if (describedBy) trigger.setAttribute("aria-describedby", describedBy);
    return h("div", { class: "file-picker" }, input, trigger, h("span", { class: "file-name", text: fileName || "尚未選擇檔案" }));
  }

  function button(label, onClick, options = {}) {
    const classes = ["btn"];
    if (options.primary) classes.push("primary");
    if (options.danger) classes.push("danger");
    if (options.small) classes.push("small");
    return h("button", {
      type: options.submit ? "submit" : "button", class: classes.join(" "), disabled: options.disabled,
      title: options.title, "aria-label": options.label, dataset: { focus: options.focus },
      on: onClick ? { click: onClick } : undefined
    }, options.icon ? icon(options.icon) : null, h("span", { text: label }));
  }

  function bytes(value) {
    if (!isNumber(value) || value < 0) return "—";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let amount = value;
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
    if (unit === 0) return `${amount} B`;
    return `${amount.toFixed(amount >= 100 ? 0 : 1)} ${units[unit]}`;
  }

  function date(value) {
    if (!isString(value) || !value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleString("zh-TW", {
      hour12: false, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"
    });
  }

  function duration(seconds) {
    if (!isNumber(seconds) || seconds < 0) return "—";
    const total = Math.round(seconds);
    if (total < 60) return `${total} 秒`;
    const minutes = Math.floor(total / 60);
    const rest = total % 60;
    if (minutes < 60) return rest ? `${minutes} 分 ${rest} 秒` : `${minutes} 分`;
    const hours = Math.floor(minutes / 60);
    return minutes % 60 ? `${hours} 小時 ${minutes % 60} 分` : `${hours} 小時`;
  }

  function requestId() {
    if (typeof window.crypto?.randomUUID === "function") return window.crypto.randomUUID();
    // Non-secure origins lack randomUUID; build an RFC 4122 v4 id from getRandomValues instead.
    const data = window.crypto.getRandomValues(new Uint8Array(16));
    data[6] = (data[6] & 0x0f) | 0x40;
    data[8] = (data[8] & 0x3f) | 0x80;
    const hex = Array.from(data, item => item.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function extractSecret(value) {
    if (!isString(value) || !value.trim()) return { error: "請貼上緊急金鑰，或讀取緊急金鑰檔案。" };
    if (value.length > 65536) return { error: "內容過長，不像是緊急金鑰。請只貼上金鑰那一行。" };
    const found = new Set((value.match(SECRET_RE) || []).map(item => item.toUpperCase()));
    if (found.size === 0) {
      return { error: "找不到以 AGE-SECRET-KEY-1 開頭的完整金鑰。請貼上緊急金鑰檔中的金鑰那一行，或直接讀取緊急金鑰檔案。" };
    }
    if (found.size > 1) return { error: "內容中有多把不同的金鑰，請只提供這份備份使用的那一把。" };
    return { key: [...found][0] };
  }

  async function readKeyFile(file) {
    if (!file) return { error: "請選擇緊急金鑰檔案。" };
    if (file.size > 65536) return { error: "檔案太大，不像是緊急金鑰檔（.txt）。" };
    try {
      return extractSecret(await file.text());
    } catch {
      return { error: "無法讀取這個檔案，請重新選擇。" };
    }
  }

  const appName = id => state.status?.apps?.find(app => app.id === id)?.name || id;
  // Glossary (review F14): the full name is 還原前自動備份; chips and filters say 還原前備份.
  const TITLE_LABELS = { manual: "手動備份", safety: "還原前自動備份", uploaded: "上傳備份" };
  const backupTitle = backup => `${TITLE_LABELS[backup.type] || "其他備份"} · ${date(backup.created || backup.uploaded_at)}`;

  // Sidecars written before format 2 have no `encrypted`: they are encrypted (CONTRACT §7 BackupMeta).
  const isEncrypted = backup => backup?.encrypted !== false;
  // `status.settings` (預設加密備份); an engine without the encryption choice has none, and then the page neither
  // offers the choice nor sends `encrypt`.
  const settingsOf = () => {
    const settings = state.status?.settings;
    return isObject(settings) && typeof settings.encrypt_by_default === "boolean" ? settings : null;
  };
  const encryptByDefault = () => settingsOf()?.encrypt_by_default !== false;
  const plaintextWarning = () => {
    const warning = settingsOf()?.plaintext_warning;
    return isString(warning) && warning.trim() ? warning : PLAINTEXT_FALLBACK;
  };
  // An engine older than this page answers a command it does not know with this refusal (cli.py).
  const unsupported = error => error?.code === "invalid-request" && /不支援的指令/.test(str(error?.message));

  // Measured durations keep one decimal below a minute (CONTRACT §7 Timing).
  function seconds(value) {
    if (!isNumber(value) || value < 0) return "未測量";
    if (value < 60) return `${(Math.round(value * 10) / 10).toFixed(1)} 秒`;
    return duration(value);
  }

  function clockTime(epochSeconds) {
    if (!isNumber(epochSeconds)) return "—";
    return new Date(epochSeconds * 1000).toLocaleTimeString("zh-TW", { hour12: false, hour: "2-digit", minute: "2-digit" });
  }

  const minutesLeft = epochSeconds => Math.max(0, Math.ceil((epochSeconds * 1000 - Date.now()) / 60000));

  // ------------------------------------------------------------------ helper calls

  class HelperError extends Error {
    constructor(message, { code = "", details = {}, problem = null } = {}) {
      super(message);
      this.code = code;
      this.details = isObject(details) ? details : {};
      this.problem = problem;
    }
  }

  function parseObject(value) {
    if (!isString(value) || !value.trim()) return null;
    try {
      const parsed = JSON.parse(value);
      return isObject(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  function fromPayload(error) {
    const code = isString(error.code) ? error.code : "internal-error";
    const message = isString(error.message) && error.message.trim() ? error.message : "無法完成要求，請重試。";
    return new HelperError(message, { code, details: error.details });
  }

  function fromTransport(error) {
    const problem = isString(error?.problem) ? error.problem : null;
    if (["access-denied", "not-authorized", "authentication-failed"].includes(problem)) {
      const result = new HelperError(`需要管理員權限才能管理備份。${ACCESS_HELP}`, { code: "access-denied", problem });
      result.accessDenied = true;
      return result;
    }
    if (problem === "not-found") {
      const result = new HelperError("找不到備份管理程式。請確認這台設備已安裝 woowtech 備份元件後再試。", { code: "helper-missing", problem });
      result.helperMissing = true;
      return result;
    }
    if (["disconnected", "terminated", "no-session", "timeout-transport"].includes(problem)) {
      const result = new HelperError("與這台設備的管理連線已中斷。請按「重新連線」重新載入頁面；已送出的背景作業會繼續執行，不會自動重做。", { code: "disconnected", problem });
      result.disconnected = true;
      return result;
    }
    let message = isString(error?.message) ? error.message.trim() : "";
    if (message.length > 300) message = `${message.slice(0, 300)}…`;
    return new HelperError(message ? `無法完成要求：${message}` : "無法完成要求，請重試。", { code: problem || "transport", problem });
  }

  // One helper command: argv is fixed, the request is JSON on stdin, the reply one JSON object.
  function call(command, request, { timeout = null } = {}) {
    return new Promise((resolve, reject) => {
      let stdout = "";
      let settled = false;
      let timer = null;
      let process = null;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) {
          noteFailure(error);
          reject(error);
        } else {
          noteSuccess();
          resolve(value);
        }
      };
      const settle = (output, failure) => {
        const payload = parseObject(output);
        if (payload?.ok === true && !failure) finish(null, payload);
        else if (payload?.ok === false && isObject(payload.error)) finish(fromPayload(payload.error));
        else if (failure) finish(fromTransport(failure));
        else finish(new HelperError("備份管理程式回傳的資料格式不正確，請重試。", { code: "bad-output" }));
      };
      try {
        process = cockpit.spawn([HELPER, command], { superuser: "require", err: "message" });
        process.stream(chunk => { stdout += chunk; });
        timer = setTimeout(() => {
          finish(new HelperError(READS.has(command)
            ? "讀取資料逾時，請重試。"
            : "操作回應逾時，結果尚未確認。請重新整理確認狀態後再決定是否重試。", { code: "timeout" }));
          try { process.close("timeout"); } catch { /* already closed */ }
        }, timeout || TIMEOUTS[command] || 60000);
        process.then(
          output => settle(stdout + (isString(output) ? output : "")),
          (error, output) => settle(stdout + (isString(output) ? output : ""), error || {}));
        process.input(request === undefined ? undefined : JSON.stringify(request));
      } catch (error) {
        finish(fromTransport(error));
      }
    });
  }

  function noteFailure(error) {
    if (error.accessDenied) state.accessDenied = true;
    if (error.helperMissing) state.helperMissing = true;
    if (error.disconnected) {
      state.disconnected = true;
      stopWatch();
    }
    renderBanners();
  }

  function noteSuccess() {
    if (state.accessDenied || state.helperMissing) {
      state.accessDenied = false;
      state.helperMissing = false;
      renderBanners();
    }
  }

  function requireShape(condition, what) {
    if (!condition) throw new HelperError(`備份管理程式回傳的${what}不完整，請重新整理。`, { code: "bad-output" });
  }

  const validJob = job => isObject(job) && isString(job.id) && JOB_ID_RE.test(job.id) && Object.hasOwn(JOB_TYPES, job.type) &&
    isString(job.state) && Array.isArray(job.phases) &&
    job.phases.every(phase => isObject(phase) && isString(phase.id) && isString(phase.label) && isString(phase.state));
  const validBackup = backup => isObject(backup) && isString(backup.id) && BACKUP_ID_RE.test(backup.id) &&
    isString(backup.type) && Array.isArray(backup.apps);
  const validApp = app => isObject(app) && isString(app.id) && isString(app.name) && isString(app.state);
  const validExport = item => isObject(item) && isString(item.export_id) && EXPORT_ID_RE.test(item.export_id) &&
    isString(item.backup_id) && BACKUP_ID_RE.test(item.backup_id) && isNumber(item.expires);

  // ------------------------------------------------------------------ state

  const state = {
    status: null, statusAt: 0, statusTried: 0, statusError: null, backups: null, backupsAt: 0, jobs: null, jobsAt: 0,
    loading: new Set(), accessDenied: false, helperMissing: false, disconnected: false,
    permission: null, permissionRetry: false, user: null, pageError: null, actionError: null,
    jobCache: new Map(), watch: { id: null, timer: null, busy: false, failures: 0 },
    wizard: null, detail: null, busy: new Set(), initialRouteHandled: false, lastPage: null,
    // `encrypt` null follows 預設加密備份; `ackPlaintext` is the explicit acknowledgement of an unencrypted backup.
    create: { selected: null, includeImages: false, note: "", requestId: null, signature: "", busy: false, error: null, encrypt: null, ackPlaintext: false },
    keys: { kit: null, busy: false, error: null, confirmChecked: false, importText: "", importBusy: false, importError: null, imported: null },
    settings: { busy: false, error: null, notice: null },
    list: { query: "", type: "all" },
    verifyRequest: null, openDetails: new Set(), composing: false, viewStale: false, pendingWizard: null,
    jobUi: { id: null, root: null, nodes: null, cancelBusy: false, cancelError: null },
    // Unencrypted download copies (`list.exports`), the request id of an export being started, and the export jobs
    // this page started (their copy downloads by itself once ready).
    exports: [], exportRequest: null, exportAuto: new Set(), deletedExports: new Set(), menu: null,
    cleanup: { plan: null, loading: false, error: null, draft: null, previewBusy: false, previewError: null, selected: new Set(), extra: new Set(), applyBusy: false, applied: null },
    catalog: {
      owners: null, ownersBusy: false, ownersError: null, owner: null, scan: null, scanBusy: false, scanError: null,
      drafts: new Map(), notice: null, busy: false
    }
  };

  function activeJob() {
    const watched = state.watch.id ? state.jobCache.get(state.watch.id)?.job : null;
    if (watched && ACTIVE.has(watched.state)) return watched;
    const active = state.status?.active_job;
    if (isObject(active) && ACTIVE.has(active.state)) {
      const cached = state.jobCache.get(active.id)?.job;
      if (cached && TERMINAL.has(cached.state)) return null;
      return cached || active;
    }
    return null;
  }

  // ------------------------------------------------------------------ data loading

  async function loadStatus({ quiet = false } = {}) {
    if (state.loading.has("status")) return;
    state.loading.add("status");
    state.statusTried = Date.now();
    if (!quiet) announce("正在載入備份狀態…");
    render({ background: quiet });
    try {
      const data = await call("status");
      requireShape(isObject(data.host) && isObject(data.storage) && (data.key === null || isObject(data.key)) &&
        Array.isArray(data.apps) && data.apps.every(validApp) &&
        (data.active_job === null || data.active_job === undefined || validJob(data.active_job)), "狀態資料");
      data.warnings = list(data.warnings).filter(isString);
      data.imported_keys = list(data.imported_keys).filter(isObject);
      state.status = data;
      state.statusAt = Date.now();
      state.statusError = null;
      if (state.pageError?.source === "status") state.pageError = null;
      if (data.active_job && ACTIVE.has(data.active_job.state)) {
        const cached = state.jobCache.get(data.active_job.id);
        // A status read can race with the job finishing; never restart polling for a finished job.
        if (!cached) state.jobCache.set(data.active_job.id, { job: data.active_job, log: [], error: null, at: Date.now() });
        if (!cached?.job || !TERMINAL.has(cached.job.state)) watchJob(data.active_job.id);
      }
      if (!quiet) announce("已更新備份狀態。");
      resumeActiveJob();
    } catch (error) {
      state.statusError = error;
      if (!error.accessDenied) state.pageError = { source: "status", error };
      if (!quiet) announce(error.accessDenied ? "需要管理員權限才能載入備份狀態。" : "備份狀態載入失敗。");
    } finally {
      state.loading.delete("status");
      render({ background: quiet });
    }
  }

  async function loadBackups({ quiet = true } = {}) {
    if (state.loading.has("backups")) return;
    state.loading.add("backups");
    render({ background: quiet });
    try {
      const data = await call("list");
      requireShape(Array.isArray(data.backups) && data.backups.every(validBackup), "備份清單");
      state.backups = data.backups;
      state.exports = list(data.exports).filter(validExport);
      state.backupsAt = Date.now();
      if (state.pageError?.source === "backups") state.pageError = null;
      if (!quiet) announce(`已更新備份清單，共 ${data.backups.length} 份。`);
    } catch (error) {
      if (!error.accessDenied) state.pageError = { source: "backups", error };
    } finally {
      state.loading.delete("backups");
      render({ background: quiet });
    }
  }

  async function loadJobs() {
    if (state.loading.has("jobs")) return;
    state.loading.add("jobs");
    render();
    try {
      const data = await call("jobs");
      requireShape(Array.isArray(data.jobs) && data.jobs.every(validJob), "活動紀錄");
      state.jobs = data.jobs;
      state.jobsAt = Date.now();
      if (state.pageError?.source === "jobs") state.pageError = null;
    } catch (error) {
      if (!error.accessDenied) state.pageError = { source: "jobs", error };
    } finally {
      state.loading.delete("jobs");
      render();
    }
  }

  function upsertBackup(backup) {
    if (!validBackup(backup) || !state.backups) return;
    const index = state.backups.findIndex(item => item.id === backup.id);
    if (index >= 0) state.backups[index] = backup;
    else state.backups.unshift(backup);
  }

  function ensureData(route, force = false) {
    if (state.accessDenied || state.disconnected || state.helperMissing) return;
    const stale = (at, age) => force || !at || Date.now() - at > age;
    if (!state.status || stale(state.statusAt, 15000)) loadStatus({ quiet: true });
    if (["overview", "backups", "cleanup"].includes(route.page) && (!state.backups || stale(state.backupsAt, 10000))) loadBackups();
    if (route.page === "jobs" && route.arg && JOB_ID_RE.test(route.arg) && !state.backups) loadBackups();
    if (route.page === "activity" && (!state.jobs || stale(state.jobsAt, 5000))) loadJobs();
    if (route.page === "cleanup" && (!state.cleanup.plan || force) && !state.cleanup.loading) loadPlan();
    if (route.page === "catalog" && !state.catalog.owners && !state.catalog.ownersBusy && !state.catalog.ownersError) loadOwners();
    if (route.page === "jobs" && route.arg && JOB_ID_RE.test(route.arg)) {
      const cached = state.jobCache.get(route.arg);
      if (force || !cached?.job || (!TERMINAL.has(cached.job.state) && state.watch.id !== route.arg)) {
        fetchJob(route.arg).then(entry => { if (ACTIVE.has(entry.job.state)) watchJob(route.arg); }, () => {});
      }
    }
  }

  // ------------------------------------------------------------------ jobs

  async function fetchJob(id) {
    try {
      const data = await call("job-status", { job_id: id });
      requireShape(validJob(data.job) && data.job.id === id && Array.isArray(data.log), "作業狀態");
      const entry = { job: data.job, log: data.log.filter(isString), error: null, at: Date.now() };
      state.jobCache.set(id, entry);
      jobChanged(id);
      return entry;
    } catch (error) {
      const previous = state.jobCache.get(id);
      state.jobCache.set(id, { job: previous?.job || null, log: previous?.log || [], error, at: Date.now() });
      jobChanged(id);
      throw error;
    }
  }

  function watchJob(id) {
    if (state.watch.id === id) return;
    stopWatch();
    state.watch = { id, timer: null, busy: false, failures: 0 };
    pollJob();
  }

  function stopWatch() {
    clearTimeout(state.watch.timer);
    state.watch = { id: null, timer: null, busy: false, failures: 0 };
  }

  async function pollJob() {
    const watch = state.watch;
    if (!watch.id || watch.busy) return;
    watch.busy = true;
    let delay = JOB_POLL_MS;
    try {
      const entry = await fetchJob(watch.id);
      if (state.watch !== watch) return;
      watch.failures = 0;
      if (TERMINAL.has(entry.job.state)) {
        stopWatch();
        jobFinished(entry.job);
      }
    } catch (error) {
      if (state.watch !== watch) return;
      watch.failures += 1;
      if (error.accessDenied || error.disconnected || error.helperMissing || error.code === "not-found") stopWatch();
      else delay = Math.min(15000, JOB_POLL_MS * 2 ** watch.failures);
    } finally {
      watch.busy = false;
      if (state.watch === watch && watch.id) watch.timer = setTimeout(pollJob, visible() ? delay : Math.max(delay, 10000));
    }
  }

  function jobFinished(job) {
    const label = `${jobTitle(job.type)}${JOB_STATES[job.state] || job.state}`;
    announce(`${label}。`);
    loadStatus({ quiet: true });
    if (job.type !== "verify" || state.backups) loadBackups();
    if (state.jobs) loadJobs();
    if (currentRoute().page === "cleanup") loadPlan({ quiet: true });
    // The copy this page asked for downloads by itself once; the result keeps a button for another try.
    if (job.type === "export" && state.exportAuto.has(job.id)) {
      state.exportAuto.delete(job.id);
      const exported = exportOf(job);
      if (job.state === "succeeded" && exported) downloadExport(exported);
    }
  }

  function jobChanged(id) {
    renderBanners();
    const route = currentRoute();
    if (route.page === "jobs" && route.arg === id && state.jobUi.id === id) {
      const job = state.jobCache.get(id)?.job;
      const label = job && ACTIVE.has(job.state) ? job.phases.find(item => item.id === job.phase)?.label : null;
      if (label && state.jobUi.announced !== `${job.state}:${label}`) {
        state.jobUi.announced = `${job.state}:${label}`;
        announce(`${jobTitle(job.type)}：${label}`);
      }
      updateJobUi();
    }
  }

  // Resume the progress view after a reload (CONTRACT §11): only on the first status of a page load.
  function resumeActiveJob() {
    if (state.initialRouteHandled) return;
    state.initialRouteHandled = true;
    const job = state.status?.active_job;
    const route = currentRoute();
    if (job && ACTIVE.has(job.state) && route.page === "overview") {
      try { cockpit.location.replace(["jobs", job.id]); } catch { window.location.hash = hrefFor(["jobs", job.id]); }
    }
  }

  // ------------------------------------------------------------------ routing

  function currentRoute() {
    let path = [];
    try {
      path = list(cockpit.location.path).filter(item => isString(item) && item);
    } catch {
      path = [];
    }
    const [page = "overview", arg = null] = path;
    if (!ROUTES.has(page)) return { page: "overview", arg: null, unknown: true };
    return { page, arg };
  }

  function go(path) {
    try {
      cockpit.location.go(path);
    } catch {
      window.location.hash = hrefFor(path);
    }
  }

  function onRouteChange() {
    const route = currentRoute();
    const changed = state.lastPage !== `${route.page}/${route.arg || ""}`;
    state.lastPage = `${route.page}/${route.arg || ""}`;
    state.actionError = null;
    state.menu = null;
    if (route.page !== "keys") {
      // The emergency kit secret is shown once: leaving the page drops it (review finding F11).
      state.keys.kit = null;
      state.keys.confirmChecked = false;
    }
    render();
    ensureData(route);
    if (changed) {
      window.scrollTo(0, 0);
      const heading = $("view-heading");
      if (heading) heading.focus({ preventScroll: true });
    }
  }

  // ------------------------------------------------------------------ rendering

  function announce(message) {
    text($("status"), message);
  }

  function captureFocus() {
    const element = document.activeElement;
    if (!element || element === document.body || !element.dataset?.focus) return null;
    let start = null;
    let end = null;
    try {
      start = element.selectionStart ?? null;
      end = element.selectionEnd ?? null;
    } catch { /* not a text control */ }
    return { key: element.dataset.focus, element, start, end };
  }

  function restoreFocus(snapshot) {
    if (!snapshot || snapshot.element.isConnected) return;
    const target = document.querySelector(`[data-focus="${CSS.escape(snapshot.key)}"]`);
    if (!target || target.disabled) return;
    target.focus({ preventScroll: true });
    if (snapshot.start !== null && typeof target.setSelectionRange === "function") {
      try { target.setSelectionRange(snapshot.start, snapshot.end); } catch { /* not a text control */ }
    }
  }

  const EDITABLE = 'input:not([type]), input[type="text"], input[type="search"], input[type="number"], textarea';

  function editingInView() {
    const element = document.activeElement;
    return Boolean(element && element !== document.body && $("view").contains(element) && element.matches?.(EDITABLE));
  }

  // A background refresh (status poll, finished job) never rebuilds the view under a focused text field or an
  // IME composition: rebuilding replaced the field and corrupted Zhuyin/Cangjie input (review finding F5). The
  // view catches up when the field loses focus.
  function render({ background = false } = {}) {
    const route = currentRoute();
    const view = $("view");
    if (background && (state.composing || editingInView())) {
      state.viewStale = true;
      renderNav(route);
      renderBanners(route);
      view.setAttribute("aria-busy", String(state.loading.size > 0));
      $("refresh").disabled = state.loading.has("status") || state.disconnected;
      return;
    }
    state.viewStale = false;
    const snapshot = captureFocus();
    renderNav(route);
    renderBanners(route);
    const nodes = buildView(route);
    if (!(nodes.length === 1 && view.childNodes.length === 1 && view.firstChild === nodes[0])) fill(view, ...nodes);
    view.setAttribute("aria-busy", String(state.loading.size > 0));
    $("refresh").disabled = state.loading.has("status") || state.disconnected;
    restoreFocus(snapshot);
    restoreMenu();
  }

  // Replace a container's content only when it changed: re-inserting an unchanged role=alert notice made
  // screen readers announce the same error on every poll (review finding F9).
  function setOnly(container, node) {
    if (node ? container.childNodes.length === 1 && container.firstChild === node : !container.childNodes.length) return;
    fill(container, node);
  }

  const noticeSlots = new Map();
  function stableNotice(slot, error, options) {
    const cached = noticeSlots.get(slot);
    if (cached && cached.error === error) return cached.node;
    const node = errorNotice(error, options);
    noticeSlots.set(slot, { error, node });
    return node;
  }

  function activeUpload() {
    const upload = state.wizard?.source === "upload" ? state.wizard.upload : null;
    return upload && !upload.cancelled && UPLOAD_PENDING.has(upload.phase) ? upload : null;
  }

  function toggleDetails(key, open) {
    if (open) state.openDetails.add(key);
    else state.openDetails.delete(key);
  }

  function disclosure(key, label, ...content) {
    return h("details", { class: "app-details", open: state.openDetails.has(key), on: { toggle: event => toggleDetails(key, event.target.open) } },
      h("summary", { dataset: { focus: key } }, icon("chevron-right", "icon summary-icon"), h("span", { text: label })), ...content);
  }

  function renderNav(route = currentRoute()) {
    const current = NAV_FOR[route.page] ?? "";
    document.querySelectorAll("[data-nav]").forEach(item => {
      if (item.dataset.nav === current) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
  }

  function renderBanners(route = currentRoute()) {
    const access = $("access-note");
    access.hidden = !state.accessDenied;
    const who = isString(state.user?.name) && state.user.name ? `目前登入的帳號為 ${state.user.name}。` : "";
    text($("access-text"), `${who}${ACCESS_HELP}權限啟用後會自動重新載入資料。`);

    const pageError = state.disconnected
      ? new HelperError("與這台設備的管理連線已中斷。請按「重新連線」重新載入頁面；已送出的背景作業會繼續執行，不會自動重做。")
      : state.helperMissing
        ? new HelperError("找不到備份管理程式。請確認這台設備已安裝 woowtech 備份元件（woowtech-cockpit-backup）後再重試。")
        : state.pageError?.error || null;
    $("page-error").hidden = !pageError;
    text($("page-error-message"), pageError ? pageError.message : "");
    text($("retry"), state.disconnected ? "重新連線" : "重試");

    const key = state.status?.key;
    const keyBanner = $("key-banner");
    if (state.status && !state.accessDenied && (!key || !key.kit_confirmed)) {
      keyBanner.hidden = false;
      // Never a blocker: an unencrypted backup needs no device key (CONTRACT §11).
      const message = key
        ? "尚未確認已保存緊急金鑰。沒有緊急金鑰，就無法在其他設備或重新安裝後還原加密的備份。"
        : encryptByDefault()
          ? "尚未建立加密金鑰。建立第一份加密備份前，請先建立金鑰並保存緊急金鑰。"
          : "尚未建立加密金鑰。目前預設建立未加密的備份；要建立加密的備份，請先建立金鑰並保存緊急金鑰。";
      fill(keyBanner, 
        icon("key-outline"),
        h("p", null, h("strong", { text: key ? "請保存緊急金鑰。" : "需要設定加密金鑰。" }), " ", message),
        route.page === "keys" ? null : link(key ? "保存緊急金鑰" : "設定加密金鑰", ["keys"], { class: "button small", dataset: { focus: "banner-keys" } }));
    } else {
      keyBanner.hidden = true;
      fill(keyBanner);
    }

    const upload = activeUpload();
    const uploadBanner = $("upload-banner");
    if (upload && !(route.page === "restore" && !route.arg)) {
      uploadBanner.hidden = false;
      fill(uploadBanner,
        icon("tray-arrow-up"),
        upload.phase === "unconfirmed"
          ? h("p", null, h("strong", { text: "上傳結果尚未確認" }), " · 檔案仍在這台設備上檢查中，請回到上傳頁按「重新確認」。")
          : h("p", null, h("strong", { text: "上傳進行中" }), " · 重新整理或關閉這一頁會中斷上傳。"),
        link("查看上傳", ["restore"], { class: "button small", dataset: { focus: "banner-upload" } }));
    } else {
      uploadBanner.hidden = true;
      fill(uploadBanner);
    }

    const job = activeJob();
    const jobBanner = $("job-banner");
    if (job && !(route.page === "jobs" && route.arg === job.id)) {
      const percent = clamp(Number(job.progress?.percent) || 0, 0, 100);
      const phase = job.phases.find(item => item.id === job.phase)?.label || str(job.progress?.message);
      jobBanner.hidden = false;
      fill(jobBanner, 
        icon("progress-clock"),
        h("p", null, h("strong", { text: `${jobTitle(job.type)}進行中` }), ` · ${phase || JOB_STATES[job.state]} · ${percent}%`),
        link("查看進度", ["jobs", job.id], { class: "button small", dataset: { focus: "banner-job" } }));
    } else {
      jobBanner.hidden = true;
      fill(jobBanner);
    }

    setOnly($("action-error"), state.actionError
      ? stableNotice("action", state.actionError, { dismiss: () => { state.actionError = null; renderBanners(); } }) : null);

    const warnings = state.status?.warnings || [];
    $("warnings").hidden = !warnings.length || state.accessDenied;
    const title = `備份設定提示（${warnings.length}）`;
    if ($("warnings-title").textContent !== title) {
      fill($("warnings-title"), icon("chevron-right", "icon summary-icon"), h("span", { text: title }));
    }
    fill($("warning-list"), ...warnings.map(item => h("li", { text: item })));
  }

  function buildView(route) {
    if (state.accessDenied) return [adminRequired()];
    if (route.unknown) return [viewTitle("找不到頁面", "這個網址不是備份與還原的頁面。"), notFound("找不到頁面", "請使用上方的分頁切換。")];
    if (!state.status && state.helperMissing) {
      return [h("section", { class: "card" }, emptyState("alert-circle-outline", "找不到備份管理程式",
        "這台設備尚未安裝 woowtech 備份元件，或安裝不完整。請由系統管理員安裝後，再按上方的「重試」。"))];
    }
    if (!state.status && state.disconnected) {
      return [h("section", { class: "card" }, emptyState("alert-circle-outline", "管理連線已中斷", "請按上方的「重新連線」重新載入頁面。"))];
    }
    switch (route.page) {
      case "backups": return route.arg ? viewDetail(route.arg) : viewBackups();
      case "create": return viewCreate();
      case "restore": return viewRestore(route.arg);
      case "jobs": return viewJob(route.arg);
      case "keys": return viewKeys();
      case "activity": return viewActivity();
      case "cleanup": return viewCleanup();
      case "catalog": return route.arg ? viewDraft(route.arg) : viewCatalog();
      default: return viewOverview();
    }
  }

  // ------------------------------------------------------------------ shared UI pieces

  function viewTitle(title, description, actions = []) {
    return h("div", { class: "view-title" },
      h("div", { class: "view-title-text" },
        h("h2", { id: "view-heading", tabIndex: -1, text: title, dataset: { focus: "view-heading" } }),
        description ? h("p", { class: "muted", text: description }) : null),
      actions.length ? h("div", { class: "button-group" }, actions) : null);
  }

  function backLink(label, path) {
    return link([icon("arrow-left"), h("span", { text: label })], path, { class: "back-link", dataset: { focus: `back-${path.join("-")}` } });
  }

  function loadingCard(message = "正在載入…") {
    return h("section", { class: "card loading-card", "aria-busy": "true" }, h("p", { text: message }));
  }

  // A placeholder that says "loading" only while the named load is really in flight.
  function pendingCard(name, message) {
    if (state.loading.has(name) || (!state.pageError && !state.accessDenied)) return loadingCard(message);
    return h("section", { class: "card" }, emptyState("alert-circle-outline", "目前無法載入資料", "請使用上方的「重試」，或稍後再試。"));
  }

  function emptyState(iconName, title, description, actions = []) {
    return h("div", { class: "empty-state" }, tile(iconName), h("h3", { text: title }),
      description ? h("p", { class: "muted", text: description }) : null,
      actions.length ? h("div", { class: "button-group" }, actions) : null);
  }

  function notFound(title, description) {
    return h("section", { class: "card" }, emptyState("alert-circle-outline", title, description, [
      link("回到總覽", ["overview"], { class: "button", dataset: { focus: "notfound-overview" } })]));
  }

  function adminRequired() {
    return h("section", { class: "card" }, emptyState("lock-outline", "需要管理員權限",
      "備份與還原會讀取所有應用的資料與加密金鑰，只有取得管理員存取權限後才能使用。開啟管理員存取權限後，此頁會自動重新載入。"));
  }

  function emptyCatalog() {
    return h("section", { class: "card" }, emptyState("package-variant-closed", "尚未設定可備份的應用",
      "這台設備還沒有受信任的應用備份設定。請由系統管理員安裝應用的備份設定後，再回來建立備份。"));
  }

  function chip(label, tone = "neutral", iconName = null) {
    return h("span", { class: `chip chip-${tone}` }, iconName ? icon(iconName) : null, h("span", { text: label }));
  }

  function typeChip(type) {
    const icons = { manual: "database-outline", safety: "shield-check-outline", uploaded: "tray-arrow-up" };
    return chip(TYPE_LABELS[type] || str(type) || "未知", type === "safety" ? "info" : "neutral", icons[type] || null);
  }

  function jobStateChip(jobState) {
    const tones = { succeeded: "ok", failed: "fail", "rolled-back": "warn", interrupted: "warn", cancelled: "neutral", queued: "info", running: "info" };
    const icons = { succeeded: "check-circle-outline", failed: "close-circle-outline", "rolled-back": "backup-restore",
      interrupted: "alert-outline", cancelled: "stop-circle-outline", queued: "timer-sand", running: "progress-clock" };
    return chip(JOB_STATES[jobState] || str(jobState), tones[jobState] || "neutral", icons[jobState] || null);
  }

  function appStateChip(appState) {
    const tones = { running: "ok", stopped: "neutral", partial: "warn", "not-deployed": "neutral", error: "fail" };
    return chip(APP_STATES[appState] || str(appState), tones[appState] || "neutral");
  }

  function keyChip(backup) {
    return backup.key_available
      ? chip("金鑰可用", "ok", "key-outline")
      : chip("需要緊急金鑰", "warn", "key-outline");
  }

  // Every backup says whether it is encrypted (已加密／未加密); an unencrypted upload is also marked as unverifiable.
  function encryptionChip(backup) {
    return isEncrypted(backup) ? chip("已加密", "ok", "lock-outline") : chip("未加密", "warn", "lock-open-variant-outline");
  }

  function backupChips(backup, { key = true } = {}) {
    return [
      encryptionChip(backup),
      key && isEncrypted(backup) ? keyChip(backup) : null,
      backup.unauthenticated === true ? chip("來源未驗證", "warn", "alert-outline") : null
    ];
  }

  const formatText = backup => (backup.format === 1 ? "舊格式（.woowbackup）" : "備份檔（.tar）");

  // 已驗證 after the verify job means a restore's content checks pass too (`verified.deep`); a backup's own check at
  // creation, an older verify and an upload's outer check only prove the file is whole.
  function verifiedText(backup) {
    if (!isObject(backup.verified)) return "尚未驗證";
    if (!backup.verified.ok) return `驗證未通過 · ${date(backup.verified.at)}`;
    return backup.verified.deep
      ? `已驗證（內容已逐項檢查）· ${date(backup.verified.at)}`
      : `已驗證（檔案完整）· ${date(backup.verified.at)}`;
  }

  function appsText(backup) {
    const names = list(backup.apps).map(app => str(app?.name || app?.id)).filter(Boolean);
    if (names.length) return names.join("、");
    return backup.inspected === false ? "尚未檢查內容" : "—";
  }

  function checkList(checks, label) {
    const items = list(checks).filter(isObject);
    if (!items.length) return h("p", { class: "muted", text: "沒有檢查項目。" });
    return h("ul", { class: "checks", "aria-label": label }, items.map(check => {
      const status = Object.hasOwn(CHECK_STATES, check.status) ? check.status : "warn";
      const glyph = { ok: "check-circle-outline", warn: "alert-outline", fail: "close-circle-outline" }[status];
      return h("li", { class: `check check-${status}` }, icon(glyph),
        h("span", { class: "check-label", text: CHECK_STATES[status] }),
        h("span", { class: "check-message", text: str(check.message) || str(check.id) }));
    }));
  }

  function metadata(rows) {
    return h("dl", { class: "metadata" }, rows.filter(Boolean).flatMap(([label, value, className]) => [
      h("dt", { text: label }), h("dd", { class: className || null }, value instanceof Node ? value : str(value) || "—")]));
  }

  // Host directories (主機資料夾): manifest summary apps[].data_dirs, paths relative to the app owner's home, shown as
  // ~/<path>. Archives and engines from before host directories have none; malformed entries are skipped, never guessed.
  function dataDirs(app) {
    return list(app?.data_dirs).filter(item => isObject(item) && isString(item.path) && item.path.length > 0)
      .map(item => ({ path: item.path, label: isString(item.label) ? item.label : "", size: isNumber(item.size) && item.size >= 0 ? item.size : null }));
  }

  // One line per directory: optional app name, the path (never shortened) and the catalog label or size when known.
  function dirList(entries, label) {
    return h("ul", { class: "path-list", "aria-label": label }, entries.map(({ app = null, dir }) => h("li", null,
      app ? h("span", { class: "path-app", text: app }) : null,
      h("span", { class: "mono path", text: `~/${dir.path}` }),
      dir.label || dir.size !== null
        ? h("span", { class: "secondary", text: [dir.label, dir.size !== null ? bytes(dir.size) : ""].filter(Boolean).join(" · ") }) : null)));
  }

  function errorNotice(error, { retry = null, dismiss = null } = {}) {
    const extras = [];
    const jobId = error?.details?.job_id;
    if (error?.code === "busy" && isString(jobId) && JOB_ID_RE.test(jobId)) {
      extras.push(link("查看進行中的作業", ["jobs", jobId], { class: "button small", dataset: { focus: "error-busy-job" } }));
    }
    if (error?.code === "no-device-key") extras.push(link("前往設定加密金鑰", ["keys"], { class: "button small", dataset: { focus: "error-keys" } }));
    if (error?.code === "insufficient-space") extras.push(h("span", { class: "muted", text: "可刪除不需要的備份後再試。" }));
    if (retry) extras.push(button("重試", retry, { small: true, focus: "error-retry" }));
    if (dismiss) extras.push(button("關閉提示", dismiss, { small: true, focus: "error-dismiss" }));
    return h("div", { class: "notice notice-error", role: "alert" },
      icon("alert-circle-outline"),
      h("div", { class: "notice-body" }, h("p", { text: error?.message || "發生錯誤，請重試。" }),
        extras.length ? h("div", { class: "button-group" }, extras) : null));
  }

  function infoNotice(message, tone = "info", iconName = "information-outline", extra = null) {
    return h("div", { class: `notice notice-${tone}` }, icon(iconName), h("div", { class: "notice-body" }, h("p", { text: message }), extra));
  }

  function sectionHead(title, description, action = null) {
    return h("div", { class: "section-head" },
      h("div", null, h("h3", { text: title }), description ? h("p", { class: "muted", text: description }) : null), action);
  }

  // ------------------------------------------------------------------ overview

  function viewOverview() {
    const head = viewTitle("總覽", "檢查儲存空間、加密金鑰、應用與最近的備份。");
    const status = state.status;
    if (!status) return [head, state.statusError ? errorNotice(state.statusError, { retry: () => loadStatus() }) : loadingCard("正在載入備份狀態…")];
    const storage = status.storage;
    const used = isNumber(storage.total_bytes) && storage.total_bytes > 0 && isNumber(storage.free_bytes)
      ? clamp((storage.total_bytes - storage.free_bytes) / storage.total_bytes, 0, 1) : null;
    const meter = used === null ? null : h("div", { class: "meter", role: "img", "aria-label": `磁碟已使用 ${Math.round(used * 100)}%` }, h("span", { class: "meter-fill" }));
    if (meter) meter.firstChild.style.inlineSize = `${Math.round(used * 100)}%`;
    const key = status.key;
    const apps = status.apps;
    const running = apps.filter(app => app.state === "running").length;
    const deployed = apps.filter(app => app.deployed).length;
    const settings = settingsOf();
    const stats = h("div", { class: "grid stats" },
      h("section", { class: "card stat", "aria-label": "本機儲存空間" }, tile("harddisk"),
        h("div", { class: "stat-main" }, h("p", { class: "stat-label", text: "本機儲存空間" }),
          h("p", { class: "stat-value", text: `${bytes(storage.free_bytes)} 可用` }),
          h("p", { class: "secondary", text: `共 ${bytes(storage.total_bytes)} · 備份 ${Number(storage.backup_count) || 0} 份，佔用 ${bytes(storage.backups_bytes)}` }),
          meter, storage.path ? h("p", { class: "secondary mono", text: storage.path }) : null,
          link("依應用查看與清理", ["cleanup"], { class: "text-link", dataset: { focus: "stat-cleanup" } }))),
      h("section", { class: "card stat", "aria-label": "加密金鑰" }, tile("key-outline"),
        h("div", { class: "stat-main" }, h("p", { class: "stat-label", text: "加密金鑰" }),
          h("p", { class: "stat-value", text: key ? (key.kit_confirmed ? "已保存緊急金鑰" : "待確認保存") : "尚未建立" }),
          h("p", { class: "secondary", text: key ? `金鑰 ID ${str(key.key_id)}` : encryptByDefault() ? "建立加密備份前需要先設定" : "未加密的備份不需要金鑰" }),
          settings ? h("p", { class: "secondary", text: `預設加密備份：${settings.encrypt_by_default ? "開啟" : "關閉（新備份不加密）"}` }) : null,
          link(key ? "管理金鑰與加密設定" : "設定加密金鑰", ["keys"], { class: "text-link", dataset: { focus: "stat-keys" } }))),
      h("section", { class: "card stat", "aria-label": "可備份的應用" }, tile("package-variant-closed"),
        h("div", { class: "stat-main" }, h("p", { class: "stat-label", text: "可備份的應用" }),
          h("p", { class: "stat-value", text: `${apps.length} 個` }),
          h("p", { class: "secondary", text: apps.length ? `已部署 ${deployed} 個 · 執行中 ${running} 個` : "尚未設定可備份的應用" }))));

    const appSection = h("section", { class: "section", "aria-labelledby": "apps-heading" },
      h("div", { class: "section-head" }, h("div", null, h("h3", { id: "apps-heading", text: "應用" }),
        h("p", { class: "muted", text: "可備份的 Podman 應用、執行狀態與最近一次備份。" })),
        apps.length ? link([icon("plus"), h("span", { text: "建立備份" })], ["create"], { class: "button small", dataset: { focus: "overview-create" } }) : null),
      apps.length ? h("ul", { class: "card item-list" }, apps.map(appRow)) : emptyCatalog());

    const recent = state.backups ? state.backups.slice(0, 5) : null;
    const backupSection = h("section", { class: "section", "aria-labelledby": "recent-heading" },
      h("div", { class: "section-head" }, h("div", null, h("h3", { id: "recent-heading", text: "最近的備份" }),
        h("p", { class: "muted", text: "最新的 5 份備份；完整清單可下載、還原、驗證或刪除。" })),
        link("查看全部", ["backups"], { class: "text-link", dataset: { focus: "overview-all-backups" } })),
      !recent ? pendingCard("backups", "正在載入備份清單…") : recent.length
        ? h("ul", { class: "card item-list" }, recent.map(backup => h("li", { class: "item-row" }, tile("database-outline", true),
          h("div", { class: "item-main" },
            link(backupTitle(backup), ["backups", backup.id], { class: "item-title", dataset: { focus: `recent-${backup.id}` } }),
            h("span", { class: "secondary", text: [appsText(backup), bytes(backup.size), backup.note].filter(Boolean).join(" · ") })),
          h("div", { class: "item-side" }, h("span", { class: "chips" }, typeChip(backup.type), backupChips(backup, { key: !backup.key_available }))))))
        : h("section", { class: "card" }, emptyState("database-outline", "還沒有備份", "建立第一份備份後，會顯示在這裡。", apps.length ? [
          link("建立備份", ["create"], { class: "button primary", dataset: { focus: "overview-first-backup" } })] : [])));

    const host = status.host;
    const hostLine = h("p", { class: "host-line muted" }, icon("server-network"),
      h("span", { text: [host.hostname && `設備 ${host.hostname}`, host.os, host.arch, host.podman && `Podman ${host.podman}`,
        status.version && `備份元件 ${status.version}`].filter(Boolean).map(str).join(" · ") }));
    return [head, stats, appSection, usageSection(), backupSection, hostLine];
  }

  // ------------------------------------------------------------------ storage per app

  // Bytes of each app's backups: `status.storage.apps` from the engine (with its keep-last policy), else the same split
  // computed here from the backup list (retention.app_usage): a multi-app backup by the per-app archive sizes when the
  // index has them, else evenly (estimated).
  function usageOf(backups, catalogApps) {
    const rows = new Map();
    const row = (id, name) => {
      if (!rows.has(id)) {
        rows.set(id, { id, name: name || id, in_catalog: false, backups: 0, types: { manual: 0, safety: 0, uploaded: 0 }, bytes: 0,
          estimated: false, shared: false, newest: null, oldest: null, keep_last: undefined });
      }
      return rows.get(id);
    };
    for (const app of list(catalogApps)) if (isObject(app) && isString(app.id)) row(app.id, app.name).in_catalog = true;
    const unassigned = { backups: 0, bytes: 0 };
    const total = { backups: 0, bytes: 0 };
    for (const backup of list(backups)) {
      const size = isNumber(backup.size) && backup.size > 0 ? Math.floor(backup.size) : 0;
      total.backups += 1;
      total.bytes += size;
      const items = list(backup.apps).filter(item => isObject(item) && isString(item.id));
      if (!items.length) {
        unassigned.backups += 1;
        unassigned.bytes += size;
        continue;
      }
      const sizes = items.map(item => item.size);
      const known = sizes.every(value => Number.isInteger(value) && value >= 0) && sizes.reduce((a, b) => a + b, 0) > 0;
      const sum = known ? sizes.reduce((a, b) => a + b, 0) : 0;
      const shares = items.map((_, index) => (known ? Math.floor(size * sizes[index] / sum) : Math.floor(size / items.length)));
      shares[0] += size - shares.reduce((a, b) => a + b, 0);
      items.forEach((item, index) => {
        const entry = row(item.id, item.name);
        entry.backups += 1;
        if (Object.hasOwn(entry.types, backup.type)) entry.types[backup.type] += 1;
        entry.bytes += shares[index];
        entry.estimated ||= !known && items.length > 1;
        entry.shared ||= items.length > 1;
        if (isString(backup.created)) {
          entry.newest = !entry.newest || backup.created > entry.newest ? backup.created : entry.newest;
          entry.oldest = !entry.oldest || backup.created < entry.oldest ? backup.created : entry.oldest;
        }
      });
    }
    const ordered = [...rows.values()].sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id));
    return { apps: ordered, unassigned, total };
  }

  const validUsage = row => isObject(row) && isString(row.id) && isNumber(row.bytes) && isNumber(row.backups);

  function storageUsage() {
    const engine = list(state.status?.storage?.apps).filter(validUsage);
    if (engine.length) return { apps: engine, unassigned: null, total: null, engine: true };
    if (!state.backups) return null;
    return { ...usageOf(state.backups, state.status?.apps), engine: false };
  }

  function keepText(value) {
    if (value === undefined) return "";
    return value === null ? "保留全部手動備份" : `保留最新 ${value} 份手動備份`;
  }

  function typeCounts(types) {
    const counts = isObject(types) ? types : {};
    return [["manual", "手動"], ["safety", "還原前"], ["uploaded", "上傳"]]
      .filter(([type]) => Number(counts[type]) > 0).map(([type, label]) => `${label} ${Number(counts[type])}`).join("、");
  }

  function usageMeter(value, maximum, label) {
    const share = maximum > 0 ? clamp(value / maximum, 0, 1) : 0;
    const meter = h("div", { class: "meter usage-meter", role: "img", "aria-label": label }, h("span", { class: "meter-fill" }));
    meter.firstChild.style.inlineSize = `${Math.max(share > 0 ? 2 : 0, Math.round(share * 100))}%`;
    return meter;
  }

  function usageSection() {
    const usage = storageUsage();
    const head = h("div", { class: "section-head" },
      h("div", null, h("h3", { id: "usage-heading", text: "各應用的備份空間" }),
        h("p", { class: "muted", text: "這台設備保存的備份依應用分計；同一份備份含多個應用時，依各應用封存檔的大小分攤。" })),
      link([icon("delete-outline"), h("span", { text: "清理備份" })], ["cleanup"], { class: "button small", dataset: { focus: "overview-cleanup" } }));
    if (!usage) return h("section", { class: "section", "aria-labelledby": "usage-heading" }, head, pendingCard("backups", "正在計算各應用的備份空間…"));
    const rows = usage.apps.filter(row => row.backups > 0);
    if (!rows.length) {
      return h("section", { class: "section", "aria-labelledby": "usage-heading" }, head,
        h("section", { class: "card" }, h("div", { class: "card-body" }, h("p", { class: "muted", text: "還沒有備份佔用空間。" }))));
    }
    const maximum = Math.max(...rows.map(row => row.bytes));
    const items = rows.map(row => h("li", { class: "usage-row", dataset: { usage: row.id } },
      h("div", { class: "usage-main" },
        h("span", { class: "usage-name" }, h("strong", { text: str(row.name || row.id) }),
          row.in_catalog === false ? h("small", { class: "muted", text: "（這台設備沒有它的應用設定）" }) : null),
        h("span", { class: "usage-size", text: `${bytes(row.bytes)}${row.estimated ? "（估計）" : ""}` })),
      usageMeter(row.bytes, maximum, `${str(row.name || row.id)} 佔用 ${bytes(row.bytes)}`),
      h("span", { class: "secondary", text: [`${row.backups} 份備份${typeCounts(row.types) ? `（${typeCounts(row.types)}）` : ""}`,
        row.newest ? `最新 ${date(row.newest)}` : "", keepText(row.keep_last)].filter(Boolean).join(" · ") })));
    const unassigned = usage.unassigned?.backups ? h("p", { class: "secondary", text: `另有 ${usage.unassigned.backups} 份尚未檢查內容的上傳備份，共 ${bytes(usage.unassigned.bytes)}。` }) : null;
    return h("section", { class: "section", "aria-labelledby": "usage-heading" }, head,
      h("section", { class: "card" }, h("ul", { class: "usage-list", "aria-label": "各應用的備份空間" }, items),
        unassigned ? h("div", { class: "card-body usage-foot" }, unassigned) : null));
  }

  function appRow(app) {
    const units = list(app.units).filter(isObject);
    const problems = list(app.problems).filter(isString);
    const last = isObject(app.last_backup) && isString(app.last_backup.id) && BACKUP_ID_RE.test(app.last_backup.id) ? app.last_backup : null;
    return h("li", { class: "item-row" }, tile("package-variant-closed", true),
      h("div", { class: "item-main" },
        h("strong", { class: "item-title", text: app.name || app.id }),
        h("span", { class: "secondary", text: [app.description, app.owner && `擁有者 ${app.owner}`].filter(Boolean).map(str).join(" · ") }),
        units.length ? h("span", { class: "secondary", text: `服務：${units.map(unit => `${str(unit.name)}（${unit.active ? "執行中" : "未執行"}）`).join("、")}` }) : null,
        problems.length ? h("ul", { class: "problems" }, problems.map(problem => h("li", null, icon("alert-outline"), h("span", { text: problem })))) : null),
      h("div", { class: "item-side" }, appStateChip(app.state),
        last ? h("span", { class: "secondary" }, "最近備份 ", link(date(last.created), ["backups", last.id], { dataset: { focus: `app-last-${app.id}` } }))
          : h("span", { class: "secondary", text: "尚未備份" })));
  }

  // ------------------------------------------------------------------ backup list

  function filteredBackups() {
    const query = state.list.query.trim().toLocaleLowerCase();
    return (state.backups || []).filter(backup => {
      if (state.list.type !== "all" && backup.type !== state.list.type) return false;
      if (!query) return true;
      const values = [backup.id, backup.note, backup.filename, backup.key_id, backup.source?.hostname, TYPE_LABELS[backup.type],
        ...list(backup.apps).flatMap(app => [app?.id, app?.name])];
      return values.some(value => str(value).toLocaleLowerCase().includes(query));
    });
  }

  function viewBackups() {
    const head = viewTitle("備份列表", "這台設備保存的備份。可下載成單一檔案、還原、驗證或刪除。", [
      link([icon("delete-outline"), h("span", { text: "清理備份" })], ["cleanup"], { class: "button", dataset: { focus: "list-cleanup" } }),
      link([icon("tray-arrow-up"), h("span", { text: "上傳備份檔" })], ["restore"], { class: "button", dataset: { focus: "list-upload" } }),
      link([icon("plus"), h("span", { text: "建立備份" })], ["create"], { class: "button primary", dataset: { focus: "list-create" } })]);
    if (!state.backups) return [head, pendingCard("backups", "正在載入備份清單…")];
    if (!state.backups.length) {
      return [head, h("section", { class: "card" }, emptyState("database-outline", "還沒有備份",
        "建立第一份備份，或上傳從其他設備下載的備份檔（.tar 或舊格式 .woowbackup）。", [
          link("建立備份", ["create"], { class: "button primary", dataset: { focus: "empty-create" } }),
          link("從檔案還原", ["restore"], { class: "button", dataset: { focus: "empty-restore" } })]))];
    }
    const search = h("input", {
      id: "backup-search", type: "search", value: state.list.query, placeholder: "日期、備註、應用或備份 ID",
      autocomplete: "off", dataset: { focus: "backup-search" },
      on: { input: event => { state.list.query = event.target.value; updateBackupResults(); } }
    });
    const filters = h("div", { class: "filter-group", role: "group", "aria-label": "依類型篩選" },
      [["all", "全部"], ["manual", "手動"], ["safety", "還原前備份"], ["uploaded", "上傳"]].map(([value, label]) =>
        h("button", {
          type: "button", class: "filter", "aria-pressed": String(state.list.type === value), dataset: { focus: `filter-${value}` },
          on: { click: () => { state.list.type = value; render(); } }
        }, label)));
    const toolbar = h("div", { class: "toolbar" },
      h("div", { class: "field search-field" }, h("label", { htmlFor: "backup-search", text: "搜尋備份" }), search),
      h("div", { class: "field" }, h("span", { class: "field-label", text: "類型" }), filters));
    const card = h("section", { class: "card list-card backups-card" }, toolbar,
      h("p", { id: "backup-count", class: "muted result-count", role: "status", "aria-live": "polite" }),
      h("div", { id: "backup-results" }));
    fillBackupResults(card);
    return [head, card];
  }

  function updateBackupResults() {
    const card = document.querySelector(".backups-card");
    if (card) fillBackupResults(card);
    restoreMenu();
  }

  function fillBackupResults(card) {
    const results = card.querySelector("#backup-results");
    const rows = filteredBackups();
    text(card.querySelector("#backup-count"), `顯示 ${rows.length} / ${state.backups.length} 份備份`);
    if (!rows.length) {
      fill(results, emptyState("magnify", "沒有符合條件的備份", "請調整搜尋文字或類型篩選。", [
        button("顯示全部", () => { state.list = { query: "", type: "all" }; render(); $("backup-search")?.focus(); }, { focus: "clear-filters" })]));
      return;
    }
    fill(results, h("table", { class: "data backups-table" },
      h("caption", { class: "sr-only", text: "備份清單" }),
      h("thead", null, h("tr", null, ["備份", "類型", "應用", "大小", "加密與驗證", "操作"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows.map(backupRow))));
  }

  function backupRow(backup) {
    return h("tr", { dataset: { backup: backup.id } },
      h("th", { scope: "row", "data-label": "備份" },
        link(date(backup.created || backup.uploaded_at), ["backups", backup.id], {
          class: "row-title", dataset: { focus: `open-${backup.id}` }, "aria-label": `查看 ${backupTitle(backup)} 的詳細資料`
        }),
        backup.note ? h("span", { class: "secondary note", text: backup.note }) : null,
        h("span", { class: "secondary mono", text: backup.id })),
      h("td", { "data-label": "類型" }, typeChip(backup.type)),
      h("td", { "data-label": "應用", text: appsText(backup) }),
      h("td", { "data-label": "大小" }, h("span", { text: bytes(backup.size) }),
        backup.include_images ? h("span", { class: "secondary", text: "含容器映像" }) : null,
        backup.format === 1 ? h("span", { class: "secondary", text: "舊格式（.woowbackup）" }) : null),
      h("td", { "data-label": "加密與驗證" }, h("span", { class: "chips" }, backupChips(backup)),
        h("span", { class: "secondary", text: verifiedText(backup) })),
      h("td", { "data-label": "操作" }, backupActions(backup, true)));
  }

  function backupActions(backup, compact) {
    const active = activeJob();
    const inUse = active && active.params?.backup_id === backup.id;
    const title = backupTitle(backup);
    return h("div", { class: compact ? "row-actions" : "button-group" },
      downloadControl(backup, compact),
      button("還原", () => go(["restore", backup.id]), { small: compact, icon: "backup-restore", label: `還原 ${title}`, focus: `restore-${backup.id}` }),
      button("驗證", () => verifyBackup(backup), {
        small: compact, icon: "shield-check-outline", disabled: Boolean(active), label: `驗證 ${title}`, focus: `verify-${backup.id}`,
        title: active ? "已有作業進行中，請等它完成後再驗證。" : undefined
      }),
      // No deletes while a job runs: a restore may need any safety backup to roll back (review finding CR-08).
      button("刪除", () => deleteBackup(backup), {
        small: compact, icon: "delete-outline", danger: true, disabled: Boolean(active), label: `刪除 ${title}`, focus: `delete-${backup.id}`,
        title: inUse ? "此備份正被進行中的作業使用。" : active ? "有作業進行中，請等它完成後再刪除。" : undefined
      }));
  }

  // ------------------------------------------------------------------ download menu

  // 「下載」 always downloads the file exactly as stored (an encrypted backup stays encrypted). For an encrypted backup
  // the menu next to it repeats that default and adds 下載未加密版本 (CONTRACT §11). It is a menu button: the arrow keys
  // move between the items, Escape and Tab close it, and so does a click anywhere else.
  function downloadControl(backup, compact) {
    const title = backupTitle(backup);
    const downloading = state.busy.has(`download:${backup.id}`);
    const kind = backup.format === 1 ? ".woowbackup" : ".tar";
    const main = button(downloading ? "準備下載…" : "下載", () => downloadBackup(backup), {
      small: compact, icon: "tray-arrow-down", disabled: downloading, focus: `download-${backup.id}`,
      label: `下載 ${title}（${isEncrypted(backup) ? "加密" : "未加密"}的備份檔 ${kind}）`
    });
    if (!isEncrypted(backup)) return main;
    const key = `${compact ? "row" : "detail"}-${backup.id}`;
    const open = state.menu === key;
    const panelId = `menu-${key}`;
    const toggle = h("button", {
      type: "button", class: compact ? "btn small menu-toggle" : "btn menu-toggle", "aria-haspopup": "menu", "aria-expanded": String(open),
      "aria-controls": panelId, "aria-label": `更多下載方式：${title}`, title: "更多下載方式", dataset: { focus: `download-menu-${key}` },
      on: { click: event => { event.stopPropagation(); if (state.menu === key) closeMenu(true); else openMenu(key); } }
    }, icon("chevron-down"));
    const item = (label, hint, action, focus, warn = false) => h("button", {
      type: "button", role: "menuitem", class: warn ? "menu-item menu-item-warn" : "menu-item", tabIndex: -1, dataset: { focus },
      on: { click: () => { closeMenu(); action(); } }
    }, h("span", { class: "menu-item-label", text: label }), h("small", { text: hint }));
    const panel = h("div", {
      id: panelId, class: "menu-panel", role: "menu", "aria-label": `下載方式：${title}`, hidden: !open,
      on: { keydown: menuKeys }
    },
    item(`下載加密的備份檔（${kind}）`, "預設；保存或傳送時請用這個檔案", () => downloadBackup(backup), `menu-download-${key}`),
    item("下載未加密版本…", "暫時副本：應用機密是明文，15 分鐘後自動刪除", () => exportUnencrypted(backup), `menu-export-${key}`, true));
    return h("div", { class: "menu-group", dataset: { menu: key } }, main, h("div", { class: "menu-anchor" }, toggle, panel));
  }

  function menuNodes(key) {
    const group = key ? document.querySelector(`[data-menu="${CSS.escape(key)}"]`) : null;
    return group ? { toggle: group.querySelector(".menu-toggle"), panel: group.querySelector(".menu-panel") } : null;
  }

  function openMenu(key) {
    closeMenu();
    const nodes = menuNodes(key);
    if (!nodes) return;
    state.menu = key;
    nodes.panel.hidden = false;
    nodes.toggle.setAttribute("aria-expanded", "true");
    placeMenu(nodes.panel);
    nodes.panel.querySelector('[role="menuitem"]')?.focus();
  }

  function closeMenu(focusToggle = false) {
    const nodes = menuNodes(state.menu);
    state.menu = null;
    if (!nodes) return;
    nodes.panel.hidden = true;
    nodes.toggle.setAttribute("aria-expanded", "false");
    if (focusToggle) nodes.toggle.focus();
  }

  // The panel opens under its button and is moved sideways so it always stays 8 px inside the viewport.
  function placeMenu(panel) {
    panel.style.insetInlineEnd = "0px";
    const rect = panel.getBoundingClientRect();
    const room = document.documentElement.clientWidth - 8;
    const shift = rect.left < 8 ? rect.left - 8 : rect.right > room ? rect.right - room : 0;
    if (shift) panel.style.insetInlineEnd = `${Math.round(shift)}px`;
  }

  // A rebuilt view keeps an open menu open (background refreshes): place it again once it is in the document.
  function restoreMenu() {
    const nodes = menuNodes(state.menu);
    if (nodes && !nodes.panel.hidden) placeMenu(nodes.panel);
  }

  function menuKeys(event) {
    const items = [...event.currentTarget.querySelectorAll('[role="menuitem"]')];
    const index = items.indexOf(document.activeElement);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      items[(index + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus();
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      items[event.key === "Home" ? 0 : items.length - 1]?.focus();
    } else if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeMenu(true);
    } else if (event.key === "Tab") {
      closeMenu();
    }
  }

  // ------------------------------------------------------------------ unencrypted download copies

  const exportOf = job => {
    const result = isObject(job?.result) ? job.result : null;
    return result && isString(result.export_id) && EXPORT_ID_RE.test(result.export_id) ? result : null;
  };

  // 下載未加密版本: an explicit, separately acknowledged decision (the engine's warning), then a background job that
  // decrypts and verifies the backup into a temporary unencrypted copy (CONTRACT §8: root 0600, deleted after 15
  // minutes, every step in the journal). The copy downloads through the same fsread1 channel as a backup.
  function exportUnencrypted(backup) {
    const active = activeJob();
    if (active) {
      state.actionError = new HelperError("已有作業正在進行，請等它完成後再建立未加密副本。", { code: "busy", details: { job_id: active.id } });
      render();
      return;
    }
    confirmDialog({
      title: "下載未加密版本？",
      body: [
        h("p", { text: "系統會在背景解密這份備份、完整驗證內容，再建立一份未加密的暫時副本給你下載。保存的加密備份不會改變。" }),
        h("div", { class: "notice notice-warn" }, icon("alert-outline"), h("p", { text: plaintextWarning() })),
        h("ul", { class: "bullet-list warning-list" },
          h("li", { text: "下載的檔案中，資料庫密碼、API 金鑰與存取權杖都是明文；請像保管密碼一樣保管它，用完就刪除。" }),
          h("li", { text: "副本只在這台設備保留 15 分鐘，之後自動刪除；建立、下載與刪除都會記錄在系統日誌。" }),
          h("li", { text: "要保存或傳送備份時，請改用預設的「下載」（加密的備份檔）。" })),
        metadata([["備份", backupTitle(backup)], ["備份 ID", backup.id, "mono"], ["應用", appsText(backup)]]),
        backup.key_available ? null
          : h("p", { class: "muted", text: `這份備份以金鑰 ${str(backup.key_id) || "（未知）"} 加密，這台設備沒有這把金鑰；下一步請輸入緊急金鑰。` })
      ],
      acknowledge: "我了解下載的檔案沒有加密，任何取得它的人都能讀取其中的資料庫密碼、API 金鑰與存取權杖",
      confirmLabel: backup.key_available ? "建立未加密副本" : "下一步：輸入金鑰",
      action: async () => {
        if (backup.key_available) {
          await startExport(backup, null);
          return;
        }
        setTimeout(() => keyDialog({
          title: "輸入緊急金鑰以建立未加密副本", allowSave: false, confirmLabel: "建立未加密副本",
          description: `這份備份以金鑰 ${str(backup.key_id) || "（未知）"} 加密。金鑰只交給這次作業使用，作業結束後即刪除。`,
          action: ({ key }) => startExport(backup, key)
        }), 0);
      }
    });
  }

  async function startExport(backup, key) {
    if (!state.exportRequest || state.exportRequest.backupId !== backup.id) state.exportRequest = { backupId: backup.id, id: requestId() };
    const request = { backup_id: backup.id, request_id: state.exportRequest.id, confirm: true };
    if (key) request.key = key;
    let data;
    try {
      data = await call("export-start", request);
    } catch (error) {
      if (key && ["key-required", "wrong-key"].includes(error.code)) throw new HelperError(WRONG_KEY, { code: error.code });
      throw error;
    }
    requireShape(isString(data.job_id) && JOB_ID_RE.test(data.job_id), "作業資訊");
    state.exportRequest = null;
    state.exportAuto.add(data.job_id);
    announce(data.deduplicated ? "這個要求先前已送出，正在顯示同一個作業。" : "已開始建立未加密副本，完成後會自動開始下載。");
    watchJob(data.job_id);
    go(["jobs", data.job_id]);
    loadStatus({ quiet: true });
  }

  async function downloadExport(copy) {
    const busyKey = `export:${copy.export_id}`;
    if (state.busy.has(busyKey)) return;
    state.busy.add(busyKey);
    state.actionError = null;
    render();
    try {
      const info = await call("export-info", { export_id: copy.export_id });
      requireShape(isString(info.path) && info.path.startsWith("/") && isString(info.filename) && info.filename && isNumber(info.size), "下載資訊");
      await frameDownload(info.path, info.filename);
      const expires = isNumber(info.expires) ? info.expires : copy.expires;
      announce(`已開始下載未加密副本 ${info.filename}（${bytes(info.size)}）。副本會在 ${clockTime(expires)} 自動刪除。`);
    } catch (error) {
      state.actionError = error.code === "not-found"
        ? new HelperError("這份未加密副本已過期並刪除。需要時請再建立一次。", { code: "not-found" }) : error;
      if (error.code === "not-found") loadBackups();
    } finally {
      state.busy.delete(busyKey);
      render();
    }
  }

  async function deleteExport(copy) {
    const busyKey = `export-delete:${copy.export_id}`;
    if (state.busy.has(busyKey)) return;
    state.busy.add(busyKey);
    state.actionError = null;
    render();
    try {
      const data = await call("export-delete", { export_id: copy.export_id });
      state.exports = state.exports.filter(item => item.export_id !== copy.export_id);
      state.deletedExports.add(copy.export_id);
      announce(data.deleted ? "已刪除未加密副本。" : "這份未加密副本已不存在。");
      loadBackups();
    } catch (error) {
      state.actionError = error;
    } finally {
      state.busy.delete(busyKey);
      render();
    }
  }

  // The copies of one backup that can still be downloaded (`list.exports`).
  const exportsFor = backupId => state.exports.filter(item => item.backup_id === backupId && item.expires * 1000 > Date.now());

  function exportCard(copies) {
    if (!copies.length) return null;
    return h("section", { class: "card export-card", "aria-labelledby": "export-heading" },
      h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile("lock-open-variant-outline", true),
        h("h3", { id: "export-heading", text: "未加密副本" })), chip("明文", "warn", "alert-outline")),
      h("div", { class: "card-body" },
        h("p", { text: "這份備份目前有可下載的未加密副本。副本中的應用機密是明文，到期後自動刪除；不再需要時請立即刪除。" }),
        h("ul", { class: "item-list export-list" }, copies.map(copy => h("li", { class: "item-row" },
          h("div", { class: "item-main" }, h("span", { class: "item-title mono", text: str(copy.filename) || copy.export_id }),
            h("span", { class: "secondary", text: `${bytes(copy.size)} · ${clockTime(copy.expires)} 自動刪除（約 ${minutesLeft(copy.expires)} 分鐘後）` })),
          h("div", { class: "button-group" },
            button(state.busy.has(`export:${copy.export_id}`) ? "準備下載…" : "下載副本", () => downloadExport(copy), {
              small: true, icon: "tray-arrow-down", focus: `export-download-${copy.export_id}`, disabled: state.busy.has(`export:${copy.export_id}`)
            }),
            button("立即刪除", () => deleteExport(copy), {
              small: true, icon: "delete-outline", danger: true, focus: `export-delete-${copy.export_id}`,
              disabled: state.busy.has(`export-delete:${copy.export_id}`)
            })))))));
  }

  // ------------------------------------------------------------------ backup detail

  function viewDetail(id) {
    const back = backLink("返回備份列表", ["backups"]);
    if (!BACKUP_ID_RE.test(id)) return [back, viewTitle("備份詳情"), notFound("找不到這份備份", "網址中的備份 ID 格式不正確。")];
    if (!state.backups) return [back, viewTitle("備份詳情"), pendingCard("backups", "正在載入備份資料…")];
    const backup = state.backups.find(item => item.id === id);
    if (!backup) return [back, viewTitle("備份詳情"), notFound("找不到這份備份", "它可能已被刪除，或不是這台設備上的備份。")];
    const head = viewTitle(backupTitle(backup), backup.note || "沒有備註。");
    const encrypted = isEncrypted(backup);
    const verified = isObject(backup.verified) && backup.verified.ok === true;
    const info = h("section", { class: "card", "aria-labelledby": "detail-info" },
      h("div", { class: "card-head" }, h("h3", { id: "detail-info", text: "備份資訊" }), h("span", { class: "chips" }, typeChip(backup.type), backupChips(backup, { key: false }))),
      h("div", { class: "card-body" }, metadata([
        ["備份 ID", backup.id, "mono"],
        ["類型", TYPE_LABELS[backup.type] || backup.type],
        ["建立時間", date(backup.created)],
        backup.uploaded_at ? ["上傳時間", date(backup.uploaded_at)] : null,
        ["來源設備", backup.source?.hostname || "—"],
        ["大小", bytes(backup.size)],
        ["格式", formatText(backup)],
        ["加密", encrypted ? "已加密（age X25519，需要金鑰才能讀取）" : "未加密：資料庫密碼、API 金鑰與存取權杖以明文保存"],
        backup.unauthenticated === true ? ["來源", "無法驗證：這是上傳的未加密備份，還原時需要另外確認信任它"] : null,
        ["容器映像", backup.include_images ? "已包含" : "未包含（還原時需已有或可下載相同映像）"],
        ["下載檔名", backup.filename || "—", "mono"],
        ["SHA-256", backup.sha256 || "—", "mono"],
        encrypted ? ["金鑰", h("span", null, keyChip(backup), " ", h("span", { class: "mono", text: str(backup.key_id) }))] : null,
        ["驗證", verifiedText(backup)]
      ]),
      verified && !backup.verified.deep
        ? h("p", { class: "muted", text: "「驗證」會完整解密這份備份，並以還原時相同的規則逐項檢查資料卷、主機資料夾、映像、資料摘要與資料庫匯出的格式；通過後顯示「內容已逐項檢查」。" }) : null,
      h("div", { class: "card-actions" }, backupActions(backup, false))));
    const apps = h("section", { class: "card", "aria-labelledby": "detail-apps" },
      h("div", { class: "card-head" }, h("h3", { id: "detail-apps", text: "包含的應用" })),
      list(backup.apps).length
        ? h("ul", { class: "item-list" }, list(backup.apps).map(app => h("li", { class: "item-row" }, tile("package-variant-closed", true),
          h("div", { class: "item-main" }, h("strong", { class: "item-title", text: str(app?.name || app?.id) }),
            h("span", { class: "secondary mono", text: str(app?.id) }),
            isNumber(app?.size) ? h("span", { class: "secondary", text: `應用封存檔 ${bytes(app.size)}` }) : null))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: backup.inspected === false
          ? "這份上傳的備份尚未檢查內容。檢視內容或開始還原時，會先讀取它包含的應用。"
          : "沒有應用資料。" })));
    return [back, head, h("div", { class: "detail-grid" }, h("div", { class: "stack" }, info, exportCard(exportsFor(backup.id))),
      h("div", { class: "stack" }, apps, contentCard(backup)))];
  }

  function contentCard(backup) {
    const detail = state.detail?.id === backup.id ? state.detail : null;
    const body = [];
    if (detail?.busy) body.push(h("p", { class: "muted", role: "status", text: isEncrypted(backup) ? "正在解密並讀取備份內容…" : "正在讀取備份內容…" }));
    else if (detail?.data) body.push(...manifestSummary(detail.data.manifest));
    else {
      body.push(h("p", { class: "muted", text: backup.key_available
        ? `${isEncrypted(backup) ? "解密" : "讀取"}備份的內容清單，查看應用、資料庫、資料卷、主機資料夾與映像。這不會變更任何資料。`
        : "這台設備沒有這份備份的金鑰。輸入建立它的設備所產生的緊急金鑰後，才能檢視內容。" }));
      if (detail?.error) body.push(errorNotice(detail.error));
      body.push(h("div", { class: "button-group" }, button(backup.key_available ? "檢視內容" : "輸入金鑰並檢視", () => inspectDetail(backup), {
        icon: "eye-outline", focus: `inspect-${backup.id}`
      })));
    }
    return h("section", { class: "card", "aria-labelledby": "detail-content" },
      h("div", { class: "card-head" }, h("h3", { id: "detail-content", text: "備份內容" })), h("div", { class: "card-body" }, body));
  }

  function inspectDetail(backup) {
    const run = async (key = null, save = false) => {
      // The key alone; it is saved only after it opened this backup (review finding F4).
      const request = { backup_id: backup.id };
      if (key) request.key = key;
      let data;
      try {
        data = await call("inspect", request);
      } catch (error) {
        if (key && ["key-required", "wrong-key"].includes(error.code)) throw new HelperError(WRONG_KEY, { code: error.code });
        throw error;
      }
      requireShape(validBackup(data.backup) && isObject(data.manifest) && isObject(data.preflight), "備份內容");
      upsertBackup(data.backup);
      if (key && save) {
        try {
          await call("key-import", { key });
          loadStatus({ quiet: true });
          loadBackups();
        } catch (error) {
          state.actionError = new HelperError(`這把金鑰可以解開這份備份，但保存到這台設備失敗：${error.message}`, { code: error.code });
        }
      }
      return data;
    };
    if (!backup.key_available) {
      keyDialog({
        title: "輸入緊急金鑰以檢視內容", allowSave: true, confirmLabel: "檢視內容",
        description: `這份備份以金鑰 ${str(backup.key_id) || "（未知）"} 加密。金鑰只用於這次解密，除非你選擇保存到這台設備。`,
        action: async ({ key, save }) => {
          const data = await run(key, save);
          state.detail = { id: backup.id, busy: false, data, error: null };
          render();
        }
      });
      return;
    }
    state.detail = { id: backup.id, busy: true, data: null, error: null };
    render();
    run().then(data => {
      if (state.detail?.id === backup.id) state.detail = { id: backup.id, busy: false, data, error: null };
    }, error => {
      if (state.detail?.id === backup.id) state.detail = { id: backup.id, busy: false, data: null, error };
    }).finally(render);
  }

  function manifestSummary(manifest) {
    const source = isObject(manifest.source) ? manifest.source : {};
    const tool = isObject(manifest.tool) ? manifest.tool : {};
    const consistency = isObject(manifest.consistency) ? manifest.consistency : {};
    const general = metadata([
      ["建立時間", date(manifest.created)],
      ["類型", TYPE_LABELS[manifest.type] || str(manifest.type)],
      ["來源設備", [source.hostname, source.os, source.arch, source.podman && `Podman ${source.podman}`].filter(Boolean).map(str).join(" · ") || "—"],
      ["建立工具", [tool.name, tool.version].filter(Boolean).map(str).join(" ") || "—"],
      ["一致性", consistency.method === "writers-stopped"
        ? `備份時暫停應用寫入 ${duration(consistency.downtime_seconds)}`
        : str(consistency.method) || "—"],
      ["內容大小", bytes(manifest.total_size)],
      ["格式", manifest.format === 1 ? "舊格式（.woowbackup）" : "備份檔（.tar，格式 2）"],
      ["加密", manifest.encryption === "none" ? "未加密" : "已加密（age X25519）"],
      ["備註", str(manifest.note) || "—"]
    ]);
    const apps = list(manifest.apps).filter(isObject).map(app => h("article", { class: "app-content" },
      h("h4", { text: `${str(app.name || app.id)}` }), appContents(app)));
    return [general, ...apps];
  }

  // Built-in data checks (CONTRACT §4/§7): what a digest covers and its counts, in the engine's words.
  const DIGEST_TYPES = { "postgres-digest": "資料表內容", "files-digest": "檔案清單", "http-json": "應用摘要" };
  const SUMMARY_KEYS = {
    "files-digest": [["entries", "項目", true], ["files", "檔案", true], ["dirs", "資料夾", false], ["symlinks", "符號連結", false], ["other", "其他", false]],
    "postgres-digest": [["databases", "資料庫", true], ["tables", "資料表", true], ["sequences", "序列", false], ["rows", "資料列", true], ["roles", "角色", false]]
  };

  function summaryText(type, summary) {
    if (!isObject(summary)) return "—";
    const parts = (SUMMARY_KEYS[type] || [])
      .filter(([key, , always]) => isNumber(summary[key]) && (always || summary[key] > 0))
      .map(([key, label]) => `${label} ${summary[key].toLocaleString("zh-TW")}`);
    if (type === "files-digest" && isNumber(summary.bytes)) parts.push(bytes(summary.bytes));
    return parts.join("、") || "—";
  }

  function targetText(target) {
    const text = str(target);
    const at = text.indexOf(":");
    const [kind, value] = at > 0 ? [text.slice(0, at), text.slice(at + 1)] : ["", text];
    return { volume: `資料卷 ${value}`, dir: `主機資料夾 ~/${value}`, postgres: `PostgreSQL（${value}）`,
      container: `資料庫容器 ${value}（冷備份）` }[kind] || text || "—";
  }

  // single-database (pg_dump of one database) or instance mode (roles with password hashes and every database);
  // a cold database has no item of its own: it is inside a volume or host directory.
  function databaseList(app) {
    const databases = list(app.postgres).filter(isObject);
    if (!databases.length) return "沒有以 pg_dump 匯出的資料庫";
    return h("ul", { class: "path-list", "aria-label": `${str(app.name || app.id)} 的資料庫` }, databases.map(db => {
      const instance = db.scope === "instance";
      const names = list(db.databases).filter(isObject).map(item => (item.owner ? `${str(item.name)}（擁有者 ${str(item.owner)}）` : str(item.name)));
      return h("li", null, h("span", { class: "path-app", text: `PostgreSQL ${str(db.major)}` }),
        chip(instance ? "整個執行個體" : "單一資料庫", instance ? "info" : "neutral"),
        instance
          ? h("span", { class: "secondary", text: `${names.length} 個資料庫${isNumber(db.roles_count) ? `、${db.roles_count} 個角色（含密碼雜湊）` : ""}：${names.join("、") || "—"}` })
          : h("span", { class: "mono path", text: str(db.database) }));
    }));
  }

  function verifyList(app) {
    const snapshot = isObject(app.verify_snapshot) ? app.verify_snapshot : {};
    const items = [
      ...Object.entries(snapshot).map(([id, value]) => h("li", null, h("span", { class: "path-app", text: `應用摘要 ${id}` }),
        h("span", { class: "secondary", text: isObject(value) ? `${Object.keys(value).length} 個欄位` : "已記錄" }))),
      ...list(app.verify_digests).filter(isObject).map(digest => h("li", null,
        h("span", { class: "path-app", text: DIGEST_TYPES[digest.type] || str(digest.type) }),
        h("span", { class: "target", text: targetText(digest.target) }),
        h("span", { class: "secondary", text: summaryText(digest.type, digest.summary) })))
    ];
    return items.length ? h("ul", { class: "path-list", "aria-label": `${str(app.name || app.id)} 的資料核對項目` }, items) : "沒有資料核對項目";
  }

  function appContents(app) {
    const owner = isObject(app.owner) ? app.owner : {};
    const images = list(app.images).filter(isObject);
    const volumes = list(app.volumes).filter(isObject);
    const dirs = dataDirs(app);
    return metadata([
      ["應用 ID", str(app.id), "mono"],
      ["擁有者", owner.name ? `${str(owner.name)}（UID ${str(owner.uid)}）` : "—"],
      // A database kept as files (stopped with the app, inside a volume or host directory) has no dump of its own.
      ["資料庫", databaseList(app)],
      ["資料卷", volumes.length ? volumes.map(volume => str(volume.name)).join("、") : "無"],
      ["主機資料夾", dirs.length ? dirList(dirs.map(dir => ({ dir })), `${str(app.name || app.id)} 的主機資料夾`) : "無"],
      ["容器映像", images.length ? images.map(image => `${str(image.ref)}（${image.included ? "已包含" : "未包含"}）`).join("、") : "無"],
      ["應用機密與設定", `${Number(app.secrets_count) || 0} 個應用機密 · ${Number(app.config_files_count) || 0} 個設定檔`],
      ["資料核對", verifyList(app)],
      isNumber(app.archive_size) ? ["應用封存檔", bytes(app.archive_size)] : null
    ]);
  }

  // ------------------------------------------------------------------ create backup

  const selectable = app => app.deployed === true && !["not-deployed", "error"].includes(app.state);

  // 加密此備份 (CONTRACT §11) follows 預設加密備份 until the administrator changes it for this backup. An unencrypted
  // backup needs no device key (the key banner never blocks it); while the setting is on it needs the explicit
  // acknowledgement of the engine's warning, sent as `acknowledge_plaintext`. An engine without the choice has no
  // `status.settings`: then every backup is encrypted and `encrypt` is not sent.
  const createEncrypt = () => (settingsOf() ? (state.create.encrypt === null ? encryptByDefault() : state.create.encrypt) : true);
  const plaintextAckNeeded = () => Boolean(settingsOf()) && !createEncrypt() && encryptByDefault();

  function createBlocked() {
    const create = state.create;
    const status = state.status;
    if (!status || create.busy || !create.selected?.size || activeJob() || CONTROL_RE.test(create.note)) return true;
    if (createEncrypt()) return !status.key;
    return plaintextAckNeeded() && !create.ackPlaintext;
  }

  function viewCreate() {
    const head = viewTitle("建立備份", "選擇要備份的應用。備份保存在這台設備，完成後可下載成單一檔案。");
    const back = backLink("返回總覽", ["overview"]);
    const status = state.status;
    if (!status) return [back, head, state.statusError ? errorNotice(state.statusError, { retry: () => loadStatus() }) : loadingCard("正在載入應用…")];
    const apps = status.apps;
    if (!apps.length) return [back, head, emptyCatalog()];
    const create = state.create;
    if (create.selected === null) create.selected = new Set(apps.filter(selectable).map(app => app.id));
    for (const id of [...create.selected]) if (!apps.some(app => app.id === id && selectable(app))) create.selected.delete(id);
    const active = activeJob();
    const settings = settingsOf();
    const encrypt = createEncrypt();
    const blockers = [];
    if (encrypt && !status.key) {
      blockers.push(infoNotice(settings
        ? "尚未建立加密金鑰。加密的備份需要這台設備的金鑰：請先完成金鑰設定，或取消勾選「加密此備份」建立不加密的備份。"
        : "尚未建立加密金鑰。所有備份都會用這台設備的金鑰加密，請先完成金鑰設定。", "warn", "key-outline",
      link("設定加密金鑰", ["keys"], { class: "button small", dataset: { focus: "create-keys" } })));
    }
    if (active) {
      blockers.push(infoNotice(`目前有作業正在進行（${jobTitle(active.type)}），需等它完成後才能建立新的備份。`, "info", "progress-clock",
        link("查看進度", ["jobs", active.id], { class: "button small", dataset: { focus: "create-active-job" } })));
    }
    const canSubmit = !createBlocked();
    const choices = apps.map(app => {
      const enabled = selectable(app);
      const problems = list(app.problems).filter(isString);
      const last = isObject(app.last_backup) ? `最近備份 ${date(app.last_backup.created)}` : "尚未備份";
      return h("label", { class: enabled ? "choice" : "choice is-disabled" },
        h("input", {
          type: "checkbox", value: app.id, checked: create.selected.has(app.id), disabled: !enabled || create.busy,
          dataset: { focus: `create-app-${app.id}` },
          on: { change: event => { if (event.target.checked) create.selected.add(app.id); else create.selected.delete(app.id); render(); } }
        }),
        h("span", { class: "choice-body" },
          h("strong", { text: app.name || app.id }),
          app.description ? h("small", { text: app.description }) : null,
          h("span", { class: "choice-meta" }, appStateChip(app.state), h("small", { text: enabled ? last : app.state === "not-deployed" || !app.deployed ? "尚未部署在這台設備，無法備份" : "無法讀取應用狀態，暫時無法備份" })),
          problems.length ? h("ul", { class: "problems" }, problems.map(problem => h("li", null, icon("alert-outline"), h("span", { text: problem })))) : null));
    });
    const note = h("input", {
      id: "backup-note", type: "text", maxLength: 200, value: create.note, autocomplete: "off", disabled: create.busy,
      placeholder: "例如：更新前備份", "aria-describedby": "backup-note-hint", dataset: { focus: "create-note" },
      on: { input: event => { create.note = event.target.value; updateNoteHint(); } }
    });
    const encryption = settings ? h("div", { class: "form-section" }, h("h3", { text: "加密" }),
      h("label", { class: "choice" },
        h("input", {
          type: "checkbox", id: "encrypt-backup", checked: encrypt, disabled: create.busy, dataset: { focus: "create-encrypt" },
          "aria-describedby": "encrypt-backup-help",
          on: { change: event => { create.encrypt = event.target.checked; create.ackPlaintext = false; render(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "加密此備份" }),
          h("small", { id: "encrypt-backup-help", text: `以這台設備的金鑰加密；下載的檔案沒有金鑰或緊急金鑰就無法讀取。預設依「加密金鑰」頁的「預設加密備份」設定（目前${settings.encrypt_by_default ? "開啟" : "關閉"}）。` }))),
      encrypt ? null : h("div", { class: "notice notice-warn", role: "note" }, icon("alert-outline"),
        h("div", { class: "notice-body" }, h("p", null, h("strong", { text: "這份備份不會加密。" }), " ", plaintextWarning()),
          h("p", { class: "muted", text: "不加密的備份不需要設備金鑰，下載後任何支援 tar 的工具都能直接打開。" }))),
      plaintextAckNeeded() ? h("label", { class: "choice confirm-choice" },
        h("input", {
          type: "checkbox", id: "ack-plaintext", checked: create.ackPlaintext, disabled: create.busy, dataset: { focus: "create-ack-plaintext" },
          on: { change: event => { create.ackPlaintext = event.target.checked; updateNoteHint(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "我了解這份備份不加密，資料庫密碼、API 金鑰與存取權杖會以明文保存與下載" }),
          h("small", { text: "「預設加密備份」目前開啟，所以不加密的備份需要你另外確認。" }))) : null) : null;
    const form = h("form", {
      class: "form-layout", "aria-labelledby": "view-heading",
      on: { submit: event => { event.preventDefault(); startBackup(); } }
    },
    h("section", { class: "card form-card" },
      h("fieldset", { class: "form-section" }, h("legend", { text: "選擇應用" }),
        h("p", { class: "muted", text: "可一次備份多個應用；尚未部署或無法讀取狀態的應用不能選擇。" }),
        h("div", { class: "choices" }, choices)),
      h("div", { class: "form-section" }, h("h3", { text: "選項" }),
        h("label", { class: "choice" },
          h("input", {
            type: "checkbox", id: "include-images", checked: create.includeImages, disabled: create.busy, dataset: { focus: "create-images" },
            "aria-describedby": "include-images-help", on: { change: event => { create.includeImages = event.target.checked; } }
          }),
          h("span", { class: "choice-body" }, h("strong", { text: "包含容器映像" }),
            h("small", { id: "include-images-help", text: "勾選後會把應用使用的容器映像一起封裝。備份檔會明顯變大（每個映像可能數百 MB），但還原到無法連網或沒有相同映像的設備時仍可使用。未勾選時，還原的設備必須已有相同映像，或能從映像登錄庫下載；否則預檢會失敗且不會變更資料。" }))),
        h("div", { class: "field" }, h("label", { htmlFor: "backup-note", text: "備註（選填）" }), note,
          h("p", { id: "backup-note-hint", class: "hint", text: "" }))),
      encryption,
      h("div", { class: "form-section" }, h("h3", { text: "備份期間" }),
        h("p", { class: "muted", text: "為了取得一致的資料，備份時會一次停止應用設定列出的寫入服務（systemd 依服務之間的相依關係同時停止），匯出資料與計算資料摘要後立即自動恢復。以 pg_dump 匯出的資料庫保持運作；冷備份（資料庫檔案隨資料卷或主機資料夾整份備份）的資料庫也會一起停止。結果頁會列出每個應用的寫入暫停時間，以及從停止到健康檢查通過的服務無法使用時間。" })),
      ...blockers,
      create.error ? errorNotice(create.error) : null,
      h("div", { class: "form-footer button-group" },
        link("取消", ["overview"], { class: "button", dataset: { focus: "create-cancel" } }),
        h("button", { type: "submit", class: "btn primary", disabled: !canSubmit, dataset: { focus: "create-submit" } },
          icon("database-outline"), h("span", { text: create.busy ? "正在開始…" : encrypt ? "開始備份" : "開始備份（不加密）" })))),
    h("aside", { class: "card side-card", "aria-labelledby": "create-side" },
      h("h3", { id: "create-side", text: "這份備份包含什麼？" }),
      h("ul", { class: "bullet-list" },
        ["PostgreSQL 資料庫（單一資料庫或整個執行個體以 pg_dump 匯出；冷備份的資料庫隨資料卷或主機資料夾備份）",
          "應用的資料卷與主機資料夾", "應用機密（Podman secrets）與設定檔", "Quadlet 服務定義",
          "資料摘要（應用設定有內建資料核對時：資料表筆數與內容雜湊、檔案清單與雜湊），還原後在應用啟動前比對", "容器映像（僅在勾選時）"]
          .map(item => h("li", { text: item }))),
      h("p", { class: "muted", text: !encrypt ? "這份備份不加密：內容（包括應用機密）以明文保存，完成後會完整驗證才列出。"
        : status.key ? `使用這台設備的金鑰（${str(status.key.key_id)}）加密，完成後會完整驗證才列出。` : "使用這台設備的金鑰加密，完成後會完整驗證才列出。" }),
      h("p", { class: "muted", text: `保存位置：這台設備的 ${str(status.storage.path) || "備份目錄"}。備份與原資料在同一顆磁碟上，請另外下載保存到其他位置。` })));
    queueMicrotask(updateNoteHint);
    return [back, head, form];
  }

  function updateNoteHint() {
    const hint = $("backup-note-hint");
    if (!hint) return;
    const note = state.create.note;
    if (CONTROL_RE.test(note)) {
      hint.classList.add("hint-error");
      text(hint, "備註不能包含控制字元（例如換行或 Tab）。");
    } else {
      hint.classList.remove("hint-error");
      text(hint, `${note.length} / 200 字`);
    }
    const submit = document.querySelector('[data-focus="create-submit"]');
    if (submit && state.status) submit.disabled = createBlocked();
  }

  async function startBackup() {
    const create = state.create;
    const status = state.status;
    if (createBlocked()) return;
    const apps = status.apps.filter(app => create.selected.has(app.id)).map(app => app.id);
    const note = create.note.trim();
    const encrypt = createEncrypt();
    const signature = JSON.stringify([apps, create.includeImages, note, encrypt]);
    // Retries of the same intent reuse the request id so the helper deduplicates them.
    if (!create.requestId || create.signature !== signature) {
      create.requestId = requestId();
      create.signature = signature;
    }
    const request = { apps, include_images: create.includeImages, note, request_id: create.requestId };
    if (settingsOf()) request.encrypt = encrypt;
    if (plaintextAckNeeded()) request.acknowledge_plaintext = true;
    create.busy = true;
    create.error = null;
    render();
    try {
      const data = await call("backup-start", request);
      requireShape(isString(data.job_id) && JOB_ID_RE.test(data.job_id), "作業資訊");
      create.requestId = null;
      create.signature = "";
      create.note = "";
      // The next backup starts from the setting again, and an unencrypted one needs a new acknowledgement.
      create.encrypt = null;
      create.ackPlaintext = false;
      announce(data.deduplicated ? "這個備份要求先前已送出，正在顯示同一個作業。" : encrypt ? "已開始備份作業。" : "已開始備份作業（不加密）。");
      watchJob(data.job_id);
      go(["jobs", data.job_id]);
      loadStatus({ quiet: true });
    } catch (error) {
      create.error = error;
    } finally {
      create.busy = false;
      render();
    }
  }

  // ------------------------------------------------------------------ restore wizard

  function newWizard(source, backupId = null) {
    // A result page can open the wizard with options (review CR-16: restore without a safety backup).
    const pending = state.pendingWizard && state.pendingWizard.backupId === backupId ? state.pendingWizard : null;
    state.pendingWizard = null;
    return {
      source, backupId, file: null, fileError: null, upload: null, backup: null,
      step: source === "upload" ? "file" : "inspect", keyNeeded: false, keyId: null, keyText: "", key: null,
      keySaved: false, saveKey: false, keyError: null, inspect: null, inspectError: null, selected: new Set(),
      confirmed: false, requestId: null, signature: "", busy: false, error: null, jobId: null, notice: null,
      allowNoSafety: Boolean(pending?.allowNoSafety), confirmedNoSafety: false, preselect: pending ? list(pending.apps) : null,
      acceptUnauthenticated: false
    };
  }

  function wizardSteps(wizard) {
    const steps = wizard.source === "upload" ? [["file", "選擇檔案"], ["upload", "上傳"]] : [["source", "選擇備份"]];
    if (wizard.keyNeeded) steps.push(["key", "金鑰"]);
    steps.push(["preflight", "預檢"], ["confirm", "確認"], ["progress", "進度"], ["result", "結果"]);
    return steps;
  }

  function stepper(steps, current) {
    const index = steps.findIndex(([id]) => id === current);
    return h("ol", { class: "stepper", "aria-label": "還原步驟" }, steps.map(([id, label], position) => {
      const done = position < index;
      const active = position === index;
      return h("li", { class: done ? "step done" : active ? "step active" : "step", "aria-current": active ? "step" : null, dataset: { step: id } },
        h("span", { class: "step-index" }, done ? icon("check") : String(position + 1)),
        h("span", { class: "step-label", text: label }),
        h("span", { class: "sr-only", text: done ? "（已完成）" : active ? "（目前步驟）" : "" }));
    }));
  }

  function viewRestore(arg) {
    if (arg && !BACKUP_ID_RE.test(arg)) return [backLink("返回備份列表", ["backups"]), viewTitle("還原備份"), notFound("找不到這份備份", "網址中的備份 ID 格式不正確。")];
    let wizard = state.wizard;
    if (arg) {
      // Never drop a running upload for another restore: it kept streaming with no page to see or cancel it
      // and lost its leave-page guard (review finding F7).
      if (activeUpload()) return uploadBusyView();
      const pending = state.pendingWizard?.backupId === arg;  // options from a result page start a new wizard
      if (pending || !wizard || wizard.source !== "local" || wizard.backupId !== arg || wizard.jobId) {
        wizard = state.wizard = newWizard("local", arg);
        queueMicrotask(() => runInspect(wizard));
      }
    } else if (!wizard || wizard.source !== "upload" || wizard.jobId) {
      wizard = state.wizard = newWizard("upload");
    }
    const local = wizard.source === "local";
    const known = local ? state.backups?.find(item => item.id === wizard.backupId) || wizard.backup : wizard.backup;
    const head = viewTitle(local ? "還原備份" : "從檔案還原", local
      ? `還原${known ? `「${backupTitle(known)}」` : "這份備份"}。完成預檢與確認前，不會變更任何應用。`
      : "上傳在這台或其他設備下載的備份檔（.tar，或舊格式 .woowbackup），檢查相容性後再還原。");
    const current = wizard.step === "inspect" ? "preflight" : wizard.step;
    const body = {
      file: stepFile, upload: stepUpload, inspect: stepInspect, key: stepKey, preflight: stepPreflight, confirm: stepConfirm
    }[wizard.step]?.(wizard) || [];
    const sourceSafety = (known?.type || wizard.inspect?.manifest?.type) === "safety";
    const side = h("aside", { class: "card side-card", "aria-labelledby": "restore-side" },
      h("h3", { id: "restore-side", text: "還原如何保護你的資料" }),
      h("ul", { class: "bullet-list" }, [
        "完整驗證備份檔（解密、逐項核對大小與 SHA-256）之前，不會變更任何資料。",
        "只會寫入這台設備已設定的應用；備份檔中其他內容會被忽略並列出。",
        // Review F1: restoring a pre-restore backup may proceed without a new one; say so instead of "一定會".
        sourceSafety
          ? "還原這份還原前備份時，會先嘗試再建立一份還原前備份；若應用目前無法運作而無法建立，仍會直接還原，且還原失敗時無法自動回復。"
          : wizard.allowNoSafety
            ? "你已選擇在無法建立還原前備份時直接還原：這時還原失敗將無法自動回復。"
            : "原位還原前會先建立並驗證「還原前自動備份」；建立失敗時不會變更任何資料，還原失敗時自動回復。",
        "應用設定有資料核對時，資料回到原處後、應用啟動前，先比對資料表筆數與內容、檔案清單與雜湊；不一致就不啟動應用並自動回復。",
        "還原後會做健康檢查，並比對備份時與還原後的業務資料。"
      ].map(item => h("li", { text: item }))));
    return [
      local ? backLink("返回備份列表", ["backups"]) : backLink("返回總覽", ["overview"]),
      head, stepper(wizardSteps(wizard), current),
      h("div", { class: "form-layout" }, h("section", { class: "card form-card wizard-card" }, body), side)
    ];
  }

  function wizardError(wizard) {
    return wizard.error ? errorNotice(wizard.error) : null;
  }

  function uploadBusyView() {
    const unconfirmed = activeUpload()?.phase === "unconfirmed";
    return [backLink("返回備份列表", ["backups"]), viewTitle("還原備份"),
      h("section", { class: "card" }, emptyState("tray-arrow-up", unconfirmed ? "目前有上傳尚待確認" : "目前有上傳進行中",
        unconfirmed
          ? "上傳的檔案仍在這台設備上檢查中。請先回到上傳頁按「重新確認」，或放棄這次上傳，再還原其他備份。"
          : "請先等上傳完成，或取消上傳，再還原其他備份。", [
          link("查看上傳", ["restore"], { class: "button primary", dataset: { focus: "upload-busy-view" } }),
          button(unconfirmed ? "放棄這次上傳" : "取消上傳", () => cancelUpload(state.wizard), { focus: "upload-busy-cancel" })]))];
  }

  function stepFile(wizard) {
    const file = wizard.file;
    const picker = filePicker({
      id: "restore-file", accept: ".tar,.woowbackup", label: "選擇檔案：備份檔（.tar 或 .woowbackup）", fileName: file?.name, disabled: wizard.busy,
      focus: "restore-file-button", describedBy: "restore-file-hint", onFile: chosen => chooseFile(wizard, chosen)
    });
    const zone = h("div", {
      class: "dropzone", on: {
        dragover: event => { event.preventDefault(); event.currentTarget.classList.add("dragging"); },
        dragleave: event => event.currentTarget.classList.remove("dragging"),
        drop: event => {
          event.preventDefault();
          event.currentTarget.classList.remove("dragging");
          chooseFile(wizard, event.dataTransfer?.files?.[0] || null);
        }
      }
    }, tile("file-document-outline"),
    h("p", { class: "dropzone-label", text: "把備份檔（.tar 或舊格式 .woowbackup）拖放到這裡，或選擇檔案" }),
    picker,
    h("p", { id: "restore-file-hint", class: "hint", text: "檔案會先上傳到這台設備的私有暫存區；上傳本身不會變更任何應用。" }));
    const nameWarning = file && !/\.(tar|woowbackup)$/i.test(file.name)
      ? infoNotice("檔名不是 .tar 或 .woowbackup。仍可上傳，系統會檢查檔案格式；若不是備份檔會被拒絕。", "warn", "alert-outline") : null;
    return [
      h("h3", { class: "step-title", text: "選擇備份檔" }),
      wizard.notice ? infoNotice(wizard.notice, "info") : null,
      wizardError(wizard),
      zone,
      file ? metadata([["檔名", file.name], ["大小", bytes(file.size)]]) : null,
      wizard.fileError ? h("p", { class: "hint hint-error", role: "alert", text: wizard.fileError }) : null,
      nameWarning,
      h("p", { class: "muted" }, "要還原這台設備上已有的備份嗎？請到", link("備份列表", ["backups"], { dataset: { focus: "restore-to-list" } }), "選擇「還原」。"),
      h("div", { class: "form-footer button-group" },
        link("取消", ["overview"], { class: "button", dataset: { focus: "restore-cancel" } }),
        button("開始上傳", () => startUpload(wizard), { primary: true, icon: "tray-arrow-up", disabled: !file || wizard.busy, focus: "restore-upload" }))
    ];
  }

  function chooseFile(wizard, file) {
    if (wizard.busy) return;
    wizard.file = file;
    wizard.error = null;
    wizard.notice = null;
    wizard.fileError = file && !file.size ? "這個檔案是空的，請選擇有效的備份檔（.tar 或 .woowbackup）。" : null;
    render();
  }

  function stepUpload(wizard) {
    const upload = wizard.upload || {};
    const unconfirmed = upload.phase === "unconfirmed";
    const nodes = [
      h("h3", { class: "step-title", text: "上傳備份檔" }),
      metadata([["檔名", wizard.file?.name || "—"], ["大小", bytes(wizard.file?.size)]]),
      unconfirmed ? infoNotice("檢查上傳檔案的時間比預期久，結果尚未確認。檔案仍保留在這台設備上，檢查也會繼續完成；請稍候再按「重新確認」。", "warn", "timer-sand",
        h("div", { class: "button-group" },
          button(wizard.busy ? "正在確認…" : "重新確認", () => recheckUpload(wizard), { small: true, primary: true, disabled: wizard.busy, focus: "upload-recheck" }))) : null,
      h("div", { class: "progress-block" },
        h("p", { id: "upload-progress-label", class: "progress-label" },
          h("span", { id: "upload-percent", class: "progress-percent" }), h("span", { id: "upload-message", class: "progress-message" })),
        h("progress", { id: "upload-progress", max: 100, value: 0, "aria-labelledby": "upload-progress-label" }),
        h("p", { id: "upload-bytes", class: "muted" })),
      h("div", { class: "form-footer button-group" },
        button(unconfirmed ? "放棄這次上傳" : "取消上傳", () => cancelUpload(wizard), {
          icon: "stop-circle-outline", focus: "upload-cancel",
          disabled: upload.cancelled || ["finishing", "done"].includes(upload.phase) || wizard.busy
        }))
    ];
    queueMicrotask(() => updateUploadUi(wizard));
    return nodes;
  }

  function updateUploadUi(wizard) {
    const upload = wizard.upload;
    const progress = $("upload-progress");
    if (!upload || !progress || state.wizard !== wizard) return;
    const percent = upload.size ? Math.floor((upload.acked / upload.size) * 100) : 0;
    progress.value = percent;
    text($("upload-percent"), `${percent}%`);
    text($("upload-message"), {
      begin: "正在準備上傳…", sending: "上傳中", finishing: "正在確認上傳的檔案…", done: "上傳完成", cancelling: "正在取消上傳…",
      unconfirmed: "結果尚未確認"
    }[upload.phase] || "");
    text($("upload-bytes"), `已上傳 ${bytes(upload.acked)} / ${bytes(upload.size)}`);
    const cancel = document.querySelector('[data-focus="upload-cancel"]');
    if (cancel) cancel.disabled = upload.cancelled || ["finishing", "done"].includes(upload.phase);
  }

  function safeUploadName(name) {
    const cleaned = str(name).replace(/[\u0000-\u001f\u007f-\u009f/\\]/g, "_").slice(0, 255);
    return cleaned || "backup.tar";
  }

  async function startUpload(wizard) {
    const file = wizard.file;
    if (!file || wizard.busy) return;
    if (!file.size) {
      wizard.fileError = "這個檔案是空的，請選擇有效的備份檔（.tar 或 .woowbackup）。";
      render();
      return;
    }
    const upload = { id: null, size: file.size, sent: 0, acked: 0, phase: "begin", cancelled: false, channel: null };
    Object.assign(wizard, { busy: true, error: null, notice: null, upload, step: "upload" });
    render();
    try {
      const begin = await call("upload-begin", { filename: safeUploadName(file.name), size: file.size });
      requireShape(isString(begin.upload_id) && begin.upload_id && isString(begin.path) && begin.path.startsWith("/"), "上傳資訊");
      upload.id = begin.upload_id;
      if (upload.cancelled) {
        // Cancelled while upload-begin was in flight: remove the placeholder it created.
        call("upload-abort", { upload_id: upload.id }).catch(() => {});
        return;
      }
      if (isNumber(begin.max_size) && file.size > begin.max_size) {
        throw new HelperError(`這台設備的可用空間不足：最多可上傳 ${bytes(begin.max_size)}。請刪除不需要的備份後再試。`, { code: "insufficient-space" });
      }
      upload.phase = "sending";
      updateUploadUi(wizard);
      await sendFile(upload, file, begin.path, () => updateUploadUi(wizard));
      if (upload.cancelled) return;
      upload.phase = "finishing";
      updateUploadUi(wizard);
      await finishUpload(wizard, upload);
    } catch (error) {
      if (upload.cancelled) return;
      if (error.code === "timeout" && upload.phase === "finishing") {
        // The helper may still be hashing a large file: never discard an upload whose result is unknown
        // (review finding F6). The user can confirm again later.
        upload.phase = "unconfirmed";
        wizard.busy = false;
        if (state.wizard === wizard) render();
        return;
      }
      // Always remove a failed upload, also when another view replaced this wizard (review finding F7).
      if (upload.id && upload.phase !== "done") call("upload-abort", { upload_id: upload.id }).catch(() => {});
      if (state.wizard !== wizard) return;
      Object.assign(wizard, { busy: false, error, step: "file", upload: null });
      render();
    }
  }

  async function finishUpload(wizard, upload) {
    const finished = await call("upload-finish", { upload_id: upload.id }, { timeout: finishTimeout(upload.size) });
    requireShape(validBackup(finished.backup), "備份資訊");
    upload.phase = "done";
    wizard.backup = finished.backup;
    wizard.backupId = finished.backup.id;
    upsertBackup(finished.backup);
    if (!state.backups) loadBackups();
    wizard.busy = false;
    if (state.wizard !== wizard) return;
    announce("上傳完成，正在檢查備份內容。");
    await runInspect(wizard);
  }

  async function recheckUpload(wizard) {
    const upload = wizard.upload;
    if (!upload || upload.phase !== "unconfirmed" || wizard.busy) return;
    wizard.busy = true;
    upload.phase = "finishing";
    render();
    try {
      await finishUpload(wizard, upload);
    } catch (error) {
      if (state.wizard !== wizard) return;
      if (error.code === "timeout") {
        upload.phase = "unconfirmed";
        wizard.busy = false;
      } else {
        const missing = error.code === "not-found";
        if (missing) loadBackups();
        Object.assign(wizard, {
          busy: false, step: "file", upload: null,
          error: missing ? new HelperError("找不到這次上傳。若檔案已檢查完成，它會出現在「備份列表」（類型：上傳）；否則請重新上傳。", { code: "not-found" }) : error
        });
      }
      render();
    }
  }

  // Stream the file over fsreplace1: 512 KiB frames, at most 4 MiB unacknowledged (CONTRACT §11).
  function sendFile(upload, file, path, onProgress) {
    return new Promise((resolve, reject) => {
      let channel;
      try {
        channel = cockpit.channel({
          payload: "fsreplace1", path, binary: true, superuser: "require", size: file.size, "send-acks": "bytes"
        });
      } catch (error) {
        reject(fromTransport(error));
        return;
      }
      upload.channel = channel;
      let offset = 0;
      let pumping = false;
      let doneSent = false;
      let finished = false;
      const roomFor = () => offset < file.size && upload.sent - upload.acked + Math.min(CHUNK_SIZE, file.size - offset) <= WINDOW_SIZE;
      const detach = () => {
        channel.removeEventListener?.("control", onControl);
        channel.removeEventListener?.("close", onClose);
      };
      const fail = error => {
        if (finished) return;
        finished = true;
        detach();
        try { channel.close(); } catch { /* already closed */ }
        reject(error);
      };
      function onControl(event, message) {
        const control = isObject(message) ? message : isObject(event?.detail) ? event.detail : null;
        if (!control || control.command !== "ack") return;
        const amount = Number(control.bytes);
        if (!Number.isFinite(amount) || amount < 0) return;
        upload.acked = Math.min(upload.sent, upload.acked + amount);
        onProgress();
        pump();
      }
      function onClose(event, options) {
        const closed = isObject(options) ? options : isObject(event?.detail) ? event.detail : {};
        if (finished) return;
        finished = true;
        detach();
        if (upload.cancelled) reject(new HelperError("已取消上傳。", { code: "cancelled" }));
        else if (closed.problem) reject(channelError(closed));
        else if (!doneSent) reject(new HelperError("上傳連線意外結束，請重試。", { code: "upload-closed" }));
        else {
          upload.acked = upload.size;
          onProgress();
          resolve();
        }
      }
      async function pump() {
        if (pumping || doneSent || finished || upload.cancelled) return;
        pumping = true;
        try {
          while (roomFor() && !finished && !upload.cancelled) {
            const end = Math.min(offset + CHUNK_SIZE, file.size);
            const data = new Uint8Array(await file.slice(offset, end).arrayBuffer());
            if (finished || upload.cancelled) return;
            if (data.length !== end - offset) throw new Error("short read");
            channel.send(data);
            offset = end;
            upload.sent += data.length;
          }
          if (offset >= file.size && !doneSent && !finished && !upload.cancelled) {
            doneSent = true;
            channel.control({ command: "done" });
          }
        } catch {
          fail(new HelperError("讀取本機檔案失敗，請重新選擇檔案後再試。", { code: "file-read" }));
        } finally {
          pumping = false;
        }
        if (!doneSent && !finished && !upload.cancelled && roomFor()) pump();
      }
      channel.addEventListener("control", onControl);
      channel.addEventListener("close", onClose);
      pump();
    });
  }

  function channelError(closed) {
    const problem = str(closed.problem);
    const transport = fromTransport({ problem, message: closed.message });
    if (transport.accessDenied || transport.disconnected) {
      noteFailure(transport);
      return transport;
    }
    if (problem === "not-found") return new HelperError("找不到上傳目的地，這次上傳可能已逾時或被清除，請重新上傳。", { code: "upload-missing" });
    const detail = isString(closed.message) && closed.message ? `：${closed.message.slice(0, 200)}` : "";
    return new HelperError(`上傳失敗（${problem}）${detail}。請確認可用空間後重試。`, { code: "upload-failed" });
  }

  async function cancelUpload(wizard) {
    const upload = wizard?.upload;
    if (!upload || upload.cancelled || ["finishing", "done"].includes(upload.phase)) return;
    upload.cancelled = true;
    upload.phase = "cancelling";
    updateUploadUi(wizard);
    try { upload.channel?.close(); } catch { /* already closed */ }
    let cleaned = true;
    if (upload.id) {
      try { await call("upload-abort", { upload_id: upload.id }); } catch { cleaned = false; }
    }
    if (state.wizard !== wizard) return;
    Object.assign(wizard, {
      busy: false, upload: null, step: "file",
      notice: cleaned ? "已取消上傳，暫存檔已清除。" : "已取消上傳，但暫存檔清除失敗；系統會在 24 小時後自動清理。"
    });
    announce(wizard.notice);
    render();
    document.querySelector('[data-focus="restore-file-button"]')?.focus();  // not the hidden file input (F10)
  }

  function stepInspect(wizard) {
    if (wizard.inspectError) {
      const error = wizard.inspectError;
      const unreadable = ["not-a-backup", "unsupported-format", "corrupt-archive", "invalid-manifest", "limit-exceeded"].includes(error.code);
      const backup = wizard.backup || state.backups?.find(item => item.id === wizard.backupId);
      return [
        h("h3", { class: "step-title", text: unreadable ? "無法讀取這個備份檔" : "無法檢查備份內容" }),
        errorNotice(error),
        h("div", { class: "form-footer button-group" },
          wizard.source === "upload" ? button("重新選擇檔案", () => { state.wizard = newWizard("upload"); render(); }, { focus: "inspect-new-file" }) : null,
          unreadable && backup ? button("刪除這份備份檔", () => deleteBackup(backup), { danger: true, icon: "delete-outline", focus: "inspect-delete", disabled: Boolean(activeJob()) }) : null,
          button("重新檢查", () => runInspect(wizard), { primary: true, focus: "inspect-retry", disabled: wizard.busy }))
      ];
    }
    return [h("h3", { class: "step-title", text: "正在檢查備份" }),
      h("p", { class: "muted", role: "status", text: "正在讀取備份檔並檢查與這台設備的相容性…" })];
  }

  async function runInspect(wizard, key = null, saveKey = false) {
    if (state.wizard !== wizard) return;
    Object.assign(wizard, { busy: true, inspectError: null, keyError: null, error: null });
    if (!key) wizard.step = "inspect";
    render();
    try {
      // The key alone, never `save_key`: only a key that just opened this backup is saved (review finding F4).
      const request = { backup_id: wizard.backupId };
      if (key) request.key = key;
      const data = await call("inspect", request);
      requireShape(validBackup(data.backup) && isObject(data.manifest) && isObject(data.preflight) &&
        Array.isArray(data.preflight.apps) && Array.isArray(data.preflight.checks), "備份內容");
      if (state.wizard !== wizard) return;
      upsertBackup(data.backup);
      const restorable = data.preflight.apps.filter(app => isObject(app) && app.restorable === true).map(app => app.id);
      const preferred = wizard.preselect ? restorable.filter(id => wizard.preselect.includes(id)) : [];
      Object.assign(wizard, {
        inspect: data, backup: data.backup, step: "preflight", confirmed: false, confirmedNoSafety: false, acceptUnauthenticated: false, keyText: "",
        selected: new Set(preferred.length ? preferred : restorable)
      });
      if (key) {
        wizard.key = key;
        if (saveKey) await saveVerifiedKey(wizard, key);
      }
      announce("備份內容與相容性檢查完成。");
    } catch (error) {
      if (state.wizard !== wizard) return;
      if (key && ["key-required", "wrong-key"].includes(error.code)) {
        wizard.step = "key";
        wizard.keyError = WRONG_KEY;
      } else if (error.code === "key-required") {
        wizard.keyNeeded = true;
        wizard.keyId = isString(error.details.key_id) ? error.details.key_id : wizard.backup?.key_id || null;
        wizard.step = "key";
      } else if (key && error.code === "invalid-request") {
        wizard.step = "key";
        wizard.keyError = error.message;
      } else {
        wizard.inspectError = error;
        wizard.step = "inspect";
      }
    } finally {
      if (state.wizard === wizard) {
        wizard.busy = false;
        render();
        // Keyboard users land on the new step, never on <body> (review finding F10).
        if (wizard.step === "key") $("key-text")?.focus();
        else if (wizard.step === "preflight") $("view-heading")?.focus({ preventScroll: true });
      }
    }
  }

  async function saveVerifiedKey(wizard, key) {
    try {
      const data = await call("key-import", { key });
      requireShape(isObject(data.key) && isString(data.key.key_id), "金鑰資訊");
      wizard.key = null;
      wizard.keySaved = true;
      loadStatus({ quiet: true });
      if (state.backups) loadBackups();
    } catch (error) {
      wizard.notice = `這把金鑰可以解開這份備份，但保存到這台設備失敗（${error.message}）；這次還原仍會使用你輸入的金鑰。`;
    }
  }

  function stepKey(wizard) {
    const textarea = h("textarea", {
      id: "key-text", class: "mono", rows: 3, autocomplete: "off", autocapitalize: "off", spellcheck: "false",
      "aria-describedby": "key-text-hint", disabled: wizard.busy, dataset: { focus: "key-text" },
      on: { input: event => { wizard.keyText = event.target.value; } }
    });
    textarea.value = wizard.keyText;
    return [
      h("h3", { class: "step-title", text: "輸入緊急金鑰" }),
      h("p", { class: "muted", text: `這份備份以金鑰 ${wizard.keyId || "（未知）"} 加密，這台設備沒有這把金鑰。請貼上建立備份的設備所產生的緊急金鑰，或讀取緊急金鑰檔案。金鑰只透過加密連線傳給這台設備的備份程式。` }),
      wizard.source === "upload" ? h("p", { class: "hint", text: "已上傳的備份檔會保留在「備份列表」，之後可再還原或刪除。" }) : null,
      h("div", { class: "field" }, h("label", { htmlFor: "key-text", text: "緊急金鑰" }), textarea,
        h("p", { id: "key-text-hint", class: "hint", text: "貼上以 AGE-SECRET-KEY-1 開頭的整行金鑰，或整份緊急金鑰檔內容。" })),
      h("div", { class: "field" }, h("span", { class: "field-label", id: "key-file-label", text: "或讀取緊急金鑰檔案（.txt）" }),
        filePicker({
          id: "key-file", accept: ".txt,text/plain", label: "選擇檔案：緊急金鑰檔（.txt）", disabled: wizard.busy, focus: "key-file-button",
          describedBy: "key-file-label", fileName: "只會在瀏覽器讀取，不會上傳檔案",
          onFile: async chosen => {
            const parsed = await readKeyFile(chosen);
            if (parsed.error) wizard.keyError = parsed.error;
            else {
              wizard.keyText = parsed.key;
              wizard.keyError = null;
            }
            render();
          }
        })),
      h("label", { class: "choice" },
        h("input", {
          type: "checkbox", id: "save-key", checked: wizard.saveKey, disabled: wizard.busy, dataset: { focus: "save-key" },
          on: { change: event => { wizard.saveKey = event.target.checked; } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "保存此金鑰到這台設備" }),
          h("small", { text: "確認金鑰可以解開這份備份後才會保存；日後還原以同一把金鑰加密的備份時不必再次輸入。不保存時，金鑰只用於這次還原。" }))),
      wizard.keyError ? h("div", { class: "notice notice-error", role: "alert" }, icon("alert-circle-outline"), h("p", { text: wizard.keyError })) : null,
      h("div", { class: "form-footer button-group" },
        button("取消", () => { state.wizard = null; go(wizard.source === "upload" ? ["overview"] : ["backups"]); }, { focus: "key-cancel" }),
        button(wizard.busy ? "正在驗證金鑰…" : "驗證金鑰並檢查", () => submitKey(wizard), { primary: true, icon: "key-outline", disabled: wizard.busy, focus: "key-submit" }))
    ];
  }

  function submitKey(wizard) {
    if (wizard.busy) return;
    const parsed = extractSecret(wizard.keyText);
    if (parsed.error) {
      wizard.keyError = parsed.error;
      render();
      $("key-text")?.focus();
      return;
    }
    runInspect(wizard, parsed.key, wizard.saveKey);
  }

  function stepPreflight(wizard) {
    const { manifest, preflight } = wizard.inspect;
    const globalFail = list(preflight.checks).some(check => check?.status === "fail");
    const apps = list(preflight.apps).filter(isObject);
    const restorable = apps.filter(app => app.restorable === true);
    const manifestApps = new Map(list(manifest.apps).filter(isObject).map(app => [app.id, app]));
    const canContinue = !globalFail && wizard.selected.size > 0;
    const verifiedFailed = isObject(wizard.backup?.verified) && wizard.backup.verified.ok === false;
    const cards = apps.map(app => {
      const content = manifestApps.get(app.id);
      const enabled = app.restorable === true;
      return h("article", { class: enabled ? "app-preflight" : "app-preflight is-blocked", "aria-labelledby": `pf-${app.id}` },
        h("div", { class: "app-preflight-head" },
          h("label", { class: "app-select" },
            h("input", {
              type: "checkbox", checked: wizard.selected.has(app.id), disabled: !enabled || wizard.busy,
              "aria-describedby": `pf-mode-${app.id}`, dataset: { focus: `pf-select-${app.id}` },
              on: { change: event => { if (event.target.checked) wizard.selected.add(app.id); else wizard.selected.delete(app.id); wizard.confirmed = false; render(); } }
            }),
            h("span", { id: `pf-${app.id}`, class: "app-select-name", text: str(app.name || app.id) })),
          h("span", { id: `pf-mode-${app.id}`, class: "chips" },
            chip(MODES[app.mode] || str(app.mode), app.mode === "inplace" ? "warn" : "info"),
            enabled ? chip("可還原", "ok", "check-circle-outline") : chip("無法還原", "fail", "close-circle-outline"))),
        // Only for apps that can be restored: a blocked app's checks say why (review finding F13).
        enabled ? h("p", { class: "muted", text: app.mode === "inplace"
          ? "這台設備已部署此應用：會覆寫目前的資料，還原前會先自動建立還原前備份。"
          : "這台設備尚未部署此應用：會依這台設備的受信任設定全新建立服務、資料卷與資料庫。" }) : null,
        checkList(app.checks, `${str(app.name || app.id)} 的檢查結果`),
        content ? disclosure(`pf-details-${app.id}`, "備份內容", appContents(content)) : null);
    });
    const unauthenticated = wizard.backup?.unauthenticated === true;
    return [
      h("h3", { class: "step-title", text: "預檢結果" }),
      h("p", { class: "muted", text: "以下檢查不會變更任何資料。選擇要還原的應用；未通過檢查的應用無法選擇。" }),
      wizard.notice ? infoNotice(wizard.notice, "warn", "alert-outline") : null,
      verifiedFailed ? infoNotice(VERIFY_FAILED, "warn", "alert-outline") : null,
      unauthenticated ? infoNotice("這是上傳的未加密備份：無法確認它來自你的設備，也無法確認檔案在設備以外沒有被修改過。確認還原時，需要另外勾選你信任這個檔案的來源。", "warn", "lock-open-variant-outline") : null,
      h("div", { class: "preflight-summary" }, metadata([
        ["備份", `${backupTitle(wizard.backup || { type: manifest.type, created: manifest.created })}`],
        ["備份 ID", str(manifest.backup_id), "mono"],
        ["來源設備", [manifest.source?.hostname, manifest.source?.os, manifest.source?.arch].filter(Boolean).map(str).join(" · ") || "—"],
        ["內容大小", bytes(manifest.total_size)],
        ["加密", manifest.encryption === "none" ? (unauthenticated ? "未加密（來源無法驗證）" : "未加密") : "已加密"],
        ["備註", str(manifest.note) || "—"]
      ])),
      h("h4", { class: "subheading", text: "整體檢查" }),
      checkList(preflight.checks, "整體檢查結果"),
      h("h4", { class: "subheading", text: `應用（${restorable.length} / ${apps.length} 個可還原）` }),
      apps.length ? h("div", { class: "app-preflight-list" }, cards) : h("p", { class: "muted", text: "這份備份沒有可還原的應用。" }),
      globalFail ? infoNotice("整體檢查未通過，無法還原。請依上方說明處理後按「重新檢查」。", "fail", "close-circle-outline") : null,
      !globalFail && !restorable.length ? infoNotice("沒有可還原的應用。請依各應用的檢查結果處理後重新檢查。", "fail", "close-circle-outline") : null,
      wizardError(wizard),
      h("div", { class: "form-footer button-group" },
        button("重新檢查", () => runInspect(wizard, wizard.key, false), { focus: "pf-recheck", disabled: wizard.busy }),
        button("下一步：確認", () => { wizard.step = "confirm"; wizard.confirmed = false; render(); $("view-heading")?.focus({ preventScroll: true }); }, {
          primary: true, disabled: !canContinue || wizard.busy, focus: "pf-next"
        }))
    ];
  }

  function stepConfirm(wizard) {
    const { manifest, preflight } = wizard.inspect;
    const apps = list(preflight.apps).filter(app => isObject(app) && wizard.selected.has(app.id));
    const inplace = apps.filter(app => app.mode === "inplace");
    const fresh = apps.filter(app => app.mode !== "inplace");
    const names = items => items.map(app => str(app.name || app.id)).join("、");
    const sourceSafety = (wizard.backup?.type || manifest.type) === "safety";
    const noSafety = wizard.allowNoSafety && inplace.length > 0;
    const active = activeJob();
    const downtime = manifest.consistency?.downtime_seconds;
    const verifiedFailed = isObject(wizard.backup?.verified) && wizard.backup.verified.ok === false;
    // Warnings shown on 預檢 are repeated here, where the decision is made (review finding F13).
    const warnings = [...list(preflight.checks), ...apps.flatMap(app => list(app.checks))]
      .filter(check => isObject(check) && check.status === "warn");
    // Host directories are replaced as a whole, not merged: say which ones before the decision. The list comes from
    // the backup; only those this device's catalog declares are written (CONTRACT §4 authority rule).
    const contents = new Map(list(manifest.apps).filter(isObject).map(app => [app.id, app]));
    const dirsOf = app => dataDirs(contents.get(app.id));
    const dirEntries = mode => apps.filter(app => (app.mode === "inplace") === (mode === "inplace"))
      .flatMap(app => dirsOf(app).map(dir => ({ app: str(app.name || app.id), dir })));
    const inplaceDirs = dirEntries("inplace");
    const freshDirs = dirEntries("fresh");
    // An uploaded unencrypted file is unauthenticated: the restore needs its own acknowledgement (CONTRACT §7).
    const unauthenticated = wizard.backup?.unauthenticated === true;
    const canStart = wizard.confirmed && (!noSafety || wizard.confirmedNoSafety) && (!unauthenticated || wizard.acceptUnauthenticated) &&
      apps.length > 0 && !wizard.busy && !active;
    // Review F1: restoring a pre-restore backup (or an explicit "without safety backup" restore) may proceed
    // without a new safety backup, so the page must not promise one.
    let safetyText = null;
    if (inplace.length && sourceSafety) {
      safetyText = `你正在還原一份還原前備份。系統會先嘗試為 ${names(inplace)} 再建立一份還原前備份；若應用目前無法運作而無法建立，仍會直接還原，且還原失敗時無法自動回復。`;
    } else if (noSafety) {
      safetyText = `系統會先嘗試為 ${names(inplace)} 建立還原前備份；若無法建立，會依你的選擇直接還原，這時還原失敗將無法自動回復，資料可能只還原一部分。`;
    } else if (inplace.length) {
      safetyText = `開始還原前，系統會先為 ${names(inplace)} 建立並完整驗證「還原前自動備份」；建立失敗時不會變更任何資料。還原失敗時，會自動用它回復到還原前的狀態。每個應用保留最近 3 份還原前備份。`;
    }
    // Safety backups follow 預設加密備份 (CONTRACT §9); the writers it stops stay stopped for the restore.
    const safetyMode = inplace.length && settingsOf()
      ? `還原前備份依「預設加密備份」設定${encryptByDefault() ? "以這台設備的金鑰加密" : "不加密（應用機密以明文保存）"}。建立還原前備份時停止的服務會直接交給還原，應用只停止一次。`
      : null;
    const checkboxText = !inplace.length ? `我了解還原會在這台設備全新部署上列 ${apps.length} 個應用`
      : !fresh.length ? `我了解還原會停止並覆寫上列 ${apps.length} 個應用的資料`
        : `我了解還原會停止並覆寫 ${inplace.length} 個應用的資料，並全新部署 ${fresh.length} 個應用`;
    const checkboxHint = inplace.length && (sourceSafety || noSafety)
      ? "已確認受影響的應用與停機時間；若無法建立新的還原前備份，仍會直接還原，且還原失敗時無法自動回復。"
      : "已確認受影響的應用、停機時間，以及還原前備份與自動回復的方式。";
    return [
      h("h3", { class: "step-title", text: "確認還原" }),
      h("p", { class: "muted", text: "請確認以下影響。按下「開始還原」後，作業會在背景執行，關閉瀏覽器也會繼續。" }),
      h("h4", { class: "subheading", text: "受影響的應用" }),
      h("ul", { class: "card item-list affected" }, apps.map(app => h("li", { class: "item-row" }, tile("package-variant-closed", true),
        h("div", { class: "item-main" }, h("strong", { class: "item-title", text: str(app.name || app.id) }),
          h("span", { class: "secondary", text: app.mode === "inplace"
            ? `原位還原：會停止服務，並以備份內容覆寫資料庫、資料卷、${dirsOf(app).length ? "主機資料夾、" : ""}應用機密與設定檔。`
            : `全新部署：會在這台設備建立服務、資料卷${dirsOf(app).length ? "、主機資料夾" : ""}與資料庫。` })),
        h("div", { class: "item-side" }, chip(MODES[app.mode] || str(app.mode), app.mode === "inplace" ? "warn" : "info"))))),
      inplaceDirs.length || freshDirs.length ? h("h4", { class: "subheading", text: "主機資料夾" }) : null,
      inplaceDirs.length ? [
        h("p", { text: "原位還原會以備份內容整個取代下列資料夾，不會合併：資料夾回到備份時的內容，之後新增的檔案會被移除。系統先在同一層寫入新的資料夾，再與原資料夾對調；原本的內容保留到整個還原成功後才刪除，所以還原期間需要能同時存放新舊兩份內容的空間。" }),
        dirList(inplaceDirs, "原位還原會取代的主機資料夾")] : null,
      freshDirs.length ? [
        h("p", { text: "全新部署會建立下列資料夾；它們在這台設備上必須不存在或是空的（預檢會確認），上層資料夾不存在時會以應用擁有者身分建立。" }),
        dirList(freshDirs, "全新部署會建立的主機資料夾")] : null,
      inplaceDirs.length || freshDirs.length
        ? h("p", { class: "muted", text: "路徑中的 ~ 是這台設備上應用擁有者的家目錄。只會寫入這台設備應用設定列出的資料夾；備份中其他資料夾會被略過，預檢會列出。" }) : null,
      h("h4", { class: "subheading", text: "停機時間" }),
      h("p", { text: `還原期間，上列應用會停止服務，直到資料還原、啟動與健康檢查完成。這份備份內容約 ${bytes(manifest.total_size)}；備份當時暫停寫入約 ${duration(downtime)}，還原通常需要更久。${inplaceDirs.length || freshDirs.length ? "主機資料夾會在應用停止前先寫到旁邊的新資料夾，停機期間只需對調。" : ""}結果頁會列出每個應用實際無法使用的時間。` }),
      h("h4", { class: "subheading", text: "還原前備份與自動回復" }),
      safetyText ? h("p", { text: safetyText }) : null,
      safetyMode ? h("p", { class: "muted", text: safetyMode }) : null,
      fresh.length
        ? h("p", { text: `${names(fresh)} 是全新部署；若還原失敗，系統會移除這次新建立的服務、資料卷與資料庫。` })
        : null,
      warnings.length ? [h("h4", { class: "subheading", text: "注意事項" }), checkList(warnings, "注意事項")] : null,
      verifiedFailed ? infoNotice(VERIFY_FAILED, "warn", "alert-outline") : null,
      wizard.key && !wizard.keySaved ? h("p", { class: "muted", text: "你輸入的緊急金鑰只會交給這次還原作業使用，作業結束後即刪除，不會保存在這台設備。" }) : null,
      active ? infoNotice(`目前有作業正在進行（${jobTitle(active.type)}），需等它完成後才能開始還原。`, "info", "progress-clock",
        link("查看進度", ["jobs", active.id], { class: "button small", dataset: { focus: "confirm-active-job" } })) : null,
      noSafety ? h("label", { class: "choice confirm-choice" },
        h("input", {
          type: "checkbox", id: "confirm-no-safety", checked: wizard.confirmedNoSafety, disabled: wizard.busy, dataset: { focus: "confirm-no-safety" },
          on: { change: event => { wizard.confirmedNoSafety = event.target.checked; render(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "我了解這次還原可能沒有還原前備份，失敗時無法自動回復" }),
          h("small", { text: "只有在應用已無法運作（例如資料庫無法啟動）、又沒有可用的還原前備份時才這樣做。資料庫無法連線時，"
            + "也無法確認執行個體中是否還有其他資料庫；還原會重建整個資料庫資料卷。" }))) : null,
      unauthenticated ? h("label", { class: "choice confirm-choice" },
        h("input", {
          type: "checkbox", id: "confirm-unauthenticated", checked: wizard.acceptUnauthenticated, disabled: wizard.busy,
          dataset: { focus: "confirm-unauthenticated" },
          on: { change: event => { wizard.acceptUnauthenticated = event.target.checked; render(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "我確認信任這個未加密備份檔的來源" }),
          h("small", { text: "這份上傳的備份沒有加密，無法確認它來自你的設備，也無法確認檔案在設備以外沒有被修改過；還原的資料庫內容與設定檔會被應用直接使用。只在確定檔案來源可信時勾選。" }))) : null,
      h("label", { class: "choice confirm-choice" },
        h("input", {
          type: "checkbox", id: "confirm-restore", checked: wizard.confirmed, disabled: wizard.busy, dataset: { focus: "confirm-restore" },
          on: { change: event => { wizard.confirmed = event.target.checked; render(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: checkboxText }), h("small", { text: checkboxHint }))),
      wizardError(wizard),
      h("div", { class: "form-footer button-group" },
        button("上一步", () => {
          wizard.step = "preflight";
          wizard.confirmed = false;
          wizard.acceptUnauthenticated = false;
          render();
          $("view-heading")?.focus({ preventScroll: true });
        }, { focus: "confirm-back", disabled: wizard.busy }),
        button(wizard.busy ? "正在開始…" : "開始還原", () => startRestore(wizard), {
          primary: true, icon: "backup-restore", disabled: !canStart, focus: "confirm-start"
        }))
    ];
  }

  async function startRestore(wizard) {
    if (!wizard.confirmed || wizard.busy || !wizard.selected.size || activeJob()) return;
    const selected = list(wizard.inspect.preflight.apps).filter(app => isObject(app) && wizard.selected.has(app.id));
    const apps = selected.map(app => app.id);
    const noSafety = wizard.allowNoSafety && selected.some(app => app.mode === "inplace");
    if (noSafety && !wizard.confirmedNoSafety) return;
    const unauthenticated = wizard.backup?.unauthenticated === true;
    if (unauthenticated && !wizard.acceptUnauthenticated) return;
    const signature = JSON.stringify([wizard.backupId, apps, Boolean(wizard.key), noSafety, unauthenticated]);
    if (!wizard.requestId || wizard.signature !== signature) {
      wizard.requestId = requestId();
      wizard.signature = signature;
    }
    const request = { backup_id: wizard.backupId, apps, request_id: wizard.requestId, confirm: true };
    if (wizard.key) request.key = wizard.key;
    if (noSafety) request.allow_no_safety = true;
    if (unauthenticated) request.accept_unauthenticated = true;
    wizard.busy = true;
    wizard.error = null;
    render();
    try {
      const data = await call("restore-start", request);
      requireShape(isString(data.job_id) && JOB_ID_RE.test(data.job_id), "作業資訊");
      wizard.jobId = data.job_id;
      wizard.key = null;
      announce(data.deduplicated ? "這個還原要求先前已送出，正在顯示同一個作業。" : "已開始還原作業。");
      watchJob(data.job_id);
      go(["jobs", data.job_id]);
      loadStatus({ quiet: true });
    } catch (error) {
      wizard.error = error;
    } finally {
      wizard.busy = false;
      render();
    }
  }

  // ------------------------------------------------------------------ job progress & result

  function viewJob(id) {
    if (!id || !JOB_ID_RE.test(id)) return [backLink("返回活動紀錄", ["activity"]), viewTitle("作業進度"), notFound("找不到這個作業", "網址中的作業 ID 格式不正確。")];
    const ui = state.jobUi;
    if (ui.id !== id || !ui.root) createJobUi(id);
    updateJobUi();
    return [ui.root];
  }

  function createJobUi(id) {
    const ui = state.jobUi;
    const nodes = {};
    nodes.stepper = h("div", { class: "job-stepper" });
    nodes.title = h("h2", { id: "view-heading", tabIndex: -1, text: "作業進度", dataset: { focus: "view-heading" } });
    nodes.state = h("span", { class: "job-state" });
    nodes.meta = h("p", { class: "muted job-meta" });
    nodes.error = h("div", { class: "job-error" });
    nodes.phases = h("ol", { class: "phases", "aria-label": "作業階段" });
    nodes.progress = h("progress", { id: "job-progress", max: 100, value: 0, "aria-labelledby": "job-progress-label" });
    nodes.percent = h("span", { class: "progress-percent" });
    nodes.message = h("span", { class: "progress-message" });
    nodes.cancel = button("取消作業", () => cancelJob(id), { icon: "stop-circle-outline", focus: "job-cancel" });
    nodes.cancelHint = h("p", { class: "hint" });
    nodes.cancelError = h("div", { class: "job-cancel-error" });
    nodes.result = h("div", { class: "job-result" });
    nodes.log = h("pre", { class: "log", tabIndex: 0, role: "log", "aria-live": "off", "aria-label": "作業紀錄", "data-scroll": "", dataset: { focus: "job-log" } });
    nodes.params = h("div", { class: "card-body" });
    ui.root = h("div", { class: "job-view" },
      backLink("返回活動紀錄", ["activity"]), nodes.stepper,
      h("section", { class: "card job-head" }, tile("progress-clock"),
        h("div", { class: "job-head-main" }, h("div", { class: "title-row" }, nodes.title, nodes.state), nodes.meta)),
      nodes.error,
      h("section", { class: "card", "aria-labelledby": "job-progress-heading" },
        h("div", { class: "card-head" }, h("h3", { id: "job-progress-heading", text: "進度" })),
        h("div", { class: "card-body" }, nodes.phases,
          h("div", { class: "progress-block" },
            h("p", { id: "job-progress-label", class: "progress-label" }, nodes.percent, nodes.message), nodes.progress),
          h("div", { class: "button-group job-actions" }, nodes.cancel), nodes.cancelHint, nodes.cancelError)),
      nodes.result,
      h("section", { class: "card", "aria-labelledby": "job-log-heading" },
        h("div", { class: "card-head" }, h("h3", { id: "job-log-heading", text: "作業紀錄" }),
          h("span", { class: "muted small-text", text: "最近 200 行；不含金鑰與應用機密內容" })),
        h("div", { class: "card-body" }, nodes.log)),
      h("section", { class: "card", "aria-labelledby": "job-params-heading" },
        h("div", { class: "card-head" }, h("h3", { id: "job-params-heading", text: "作業內容" })), nodes.params));
    Object.assign(ui, { id, nodes, cancelBusy: false, cancelError: null, announced: null });
  }

  function updateJobUi() {
    const ui = state.jobUi;
    const nodes = ui.nodes;
    const entry = state.jobCache.get(ui.id);
    const job = entry?.job;
    setOnly(nodes.error, entry?.error ? stableNotice(`job-${ui.id}`, entry.error, {
      retry: () => fetchJob(ui.id).then(item => { if (ACTIVE.has(item.job.state)) watchJob(ui.id); }, () => {})
    }) : null);
    if (!job) {
      text(nodes.title, "作業進度");
      text(nodes.meta, entry?.error ? "無法取得作業狀態。" : "正在載入作業狀態…");
      fill(nodes.state);
      nodes.cancel.hidden = true;
      return;
    }
    text(nodes.title, jobTitle(job.type));
    fill(nodes.state, jobStateChip(job.state));
    text(nodes.meta, [`作業 ID ${job.id}`, `建立於 ${date(job.created)}`,
      job.finished ? `結束於 ${date(job.finished)}` : job.started ? `開始於 ${date(job.started)}` : null].filter(Boolean).join(" · "));
    fill(nodes.stepper, ...(job.type === "restore" ? [jobWizardStepper(job)] : []));
    fill(nodes.phases, ...job.phases.map(phaseItem));
    const percent = clamp(Math.round(Number(job.progress?.percent) || 0), 0, 100);
    nodes.progress.value = percent;
    text(nodes.percent, `${percent}%`);
    text(nodes.message, str(job.progress?.message) || JOB_STATES[job.state] || "");
    const active = ACTIVE.has(job.state);
    nodes.cancel.hidden = !active || !job.cancellable;
    nodes.cancel.disabled = ui.cancelBusy;
    text(nodes.cancel.querySelector("span"), ui.cancelBusy ? "正在取消…" : "取消作業");
    text(nodes.cancelHint, active
      ? job.cancellable ? "目前階段可以安全取消，不會變更應用資料。" : "目前階段無法取消；作業會繼續執行到完成，失敗時會自動回復。"
      : "");
    setOnly(nodes.cancelError, ui.cancelError ? stableNotice(`cancel-${ui.id}`, ui.cancelError) : null);
    fill(nodes.result, ...(TERMINAL.has(job.state) ? buildResult(job) : []));
    const log = nodes.log;
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    const content = entry.log.length ? entry.log.join("\n") : "尚無紀錄。";
    if (log.textContent !== content) {
      log.textContent = content;
      if (atBottom) log.scrollTop = log.scrollHeight;
    }
    fill(nodes.params, jobParams(job));
  }

  function jobWizardStepper(job) {
    const wizard = state.wizard?.jobId === job.id ? state.wizard : null;
    let steps;
    if (wizard) steps = wizardSteps(wizard);
    else {
      const uploaded = state.backups?.find(item => item.id === job.params?.backup_id)?.type === "uploaded";
      steps = uploaded ? [["file", "選擇檔案"], ["upload", "上傳"]] : [["source", "選擇備份"]];
      if (job.params?.key_provided) steps.push(["key", "金鑰"]);
      steps.push(["preflight", "預檢"], ["confirm", "確認"], ["progress", "進度"], ["result", "結果"]);
    }
    return stepper(steps, TERMINAL.has(job.state) ? "result" : "progress");
  }

  function phaseItem(phase) {
    const phaseState = Object.hasOwn(PHASE_STATES, phase.state) ? phase.state : "pending";
    const glyph = { pending: "circle-medium", active: "progress-clock", done: "check-circle", failed: "close-circle-outline", skipped: "minus-circle-outline" }[phaseState];
    return h("li", { class: `phase phase-${phaseState}`, "aria-current": phaseState === "active" ? "step" : null },
      h("span", { class: "phase-icon" }, icon(glyph)),
      h("span", { class: "phase-label", text: phase.label }),
      h("span", { class: "phase-state", text: PHASE_STATES[phaseState] }));
  }

  function jobParams(job) {
    const params = isObject(job.params) ? job.params : {};
    const backupId = isString(params.backup_id) && BACKUP_ID_RE.test(params.backup_id) ? params.backup_id : null;
    return metadata([
      ["作業類型", jobTitle(job.type)],
      list(params.apps).length ? ["應用", list(params.apps).map(id => appName(str(id))).join("、")] : null,
      backupId ? ["備份", link(backupId, ["backups", backupId], { class: "mono", dataset: { focus: "job-param-backup" } })] : null,
      job.type === "backup" ? ["容器映像", params.include_images ? "包含" : "不包含"] : null,
      job.type === "backup" && typeof params.encrypt === "boolean" ? ["加密", params.encrypt ? "加密此備份" : "不加密（你已確認）"] : null,
      job.type === "backup" && params.note ? ["備註", str(params.note)] : null,
      params.key_provided ? ["金鑰", "使用輸入的緊急金鑰（作業結束後即刪除）"] : null,
      params.allow_no_safety ? ["還原前備份", "無法建立時直接還原（你已確認；失敗時無法自動回復）"] : null,
      params.accept_unauthenticated ? ["檔案來源", "未加密的上傳檔，你已確認信任它的來源"] : null
    ]);
  }

  // Host directories of the apps a restore job covers, known only while this page still holds the backup's contents
  // (the wizard that started the job); after a reload the engine's own messages say what happened. What is written
  // follows this device's catalog (CONTRACT §4), so the copy around these lists never claims more than that.
  function restoreDirs(job) {
    const wizard = state.wizard?.jobId === job.id ? state.wizard : null;
    if (!isObject(wizard?.inspect)) return [];
    const contents = new Map(list(wizard.inspect.manifest?.apps).filter(isObject).map(app => [app.id, app]));
    const planned = new Map(list(wizard.inspect.preflight?.apps).filter(isObject).map(app => [app.id, app]));
    return list(job.params?.apps).filter(isString).flatMap(id => dataDirs(contents.get(id)).map(dir => ({
      app: str(planned.get(id)?.name || appName(id)), mode: planned.get(id)?.mode === "inplace" ? "inplace" : "fresh", dir
    })));
  }

  function buildResult(job) {
    const result = isObject(job.result) ? job.result : null;
    const error = isObject(job.error) ? job.error : null;
    const params = isObject(job.params) ? job.params : {};
    const safetyId = isString(result?.safety_backup_id) && BACKUP_ID_RE.test(result.safety_backup_id) ? result.safety_backup_id : null;
    const backupId = isString(params.backup_id) && BACKUP_ID_RE.test(params.backup_id) ? params.backup_id : null;
    const restore = job.type === "restore";
    // What really happened comes from the phases (and `changed` from newer engines), never from rolled_back
    // alone: a failure before any change is not "rollback incomplete" (review findings F2, F3, CR-09).
    const reached = id => job.phases.some(item => item.id === id && !["pending", "skipped"].includes(item.state));
    const rollbackPhase = job.phases.some(item => item.id === "rollback");
    const touched = typeof result?.changed === "boolean" ? result.changed
      : ["stop", "restore", "start", "check", "rollback"].some(reached);
    const freshApps = list(result?.fresh_apps).filter(isString);
    const manualWork = restore && job.state === "failed" && rollbackPhase && result?.rolled_back === false;
    const dirs = restore ? restoreDirs(job) : [];
    const body = [];
    const actions = [];
    let title = "作業結束";
    let tone = "neutral";
    let glyph = "information-outline";
    if (job.state === "succeeded") {
      tone = "ok";
      glyph = "check-circle";
      title = { backup: "備份完成", restore: "還原完成", verify: "驗證完成", export: "未加密副本已建立" }[job.type];
    } else if (job.state === "rolled-back") {
      tone = "warn";
      glyph = "backup-restore";
      title = "還原失敗，已自動回復";
    } else if (job.state === "failed") {
      tone = "fail";
      glyph = "close-circle-outline";
      title = job.type === "export" ? "建立未加密副本失敗" : `${JOB_TYPES[job.type]}失敗`;
    } else if (job.state === "interrupted") {
      tone = "warn";
      glyph = "alert-outline";
      title = "作業意外中斷";
    } else if (job.state === "cancelled") {
      glyph = "stop-circle-outline";
      title = "作業已取消";
    }

    if (job.type === "backup" && job.state === "succeeded" && result) {
      const createdId = isString(result.backup_id) && BACKUP_ID_RE.test(result.backup_id) ? result.backup_id : null;
      const encrypted = result.encrypted !== false;
      const deleted = list(result.retention_deleted).filter(isString);
      body.push(h("p", { text: encrypted ? "備份已建立，並以這台設備的金鑰完整解密驗證後才列出。"
        : "備份已建立（未加密），並完整驗證後才列出。其中的應用機密是明文，請像保管密碼一樣保管下載的檔案。" }), metadata([
        ["備份", createdId ? link(createdId, ["backups", createdId], { class: "mono", dataset: { focus: "result-backup" } }) : "—"],
        ["大小", bytes(result.size)],
        ["加密", encrypted ? "已加密" : "未加密"],
        ["應用寫入暫停", duration(result.downtime_seconds)],
        isNumber(result.unavailable_seconds) ? ["服務無法使用", `${seconds(result.unavailable_seconds)}（各應用從停止到健康檢查通過的合計）`] : null,
        ["應用", list(result.apps).map(id => appName(str(id))).join("、") || "—"]
      ]), timingTable(result.timing, "backup"));
      if (deleted.length) {
        body.push(infoNotice(`已依保留原則刪除 ${deleted.length} 份較舊的手動備份：${deleted.join("、")}。`, "info", "delete-outline"));
      }
      const backup = createdId ? state.backups?.find(item => item.id === createdId) || { id: createdId, type: "manual", created: job.finished, encrypted } : null;
      if (backup) {
        actions.push(button("下載備份", () => downloadBackup(backup), { primary: true, icon: "tray-arrow-down", focus: "result-download" }),
          link("查看備份", ["backups", createdId], { class: "button", dataset: { focus: "result-open" } }));
      }
    } else if (job.type === "verify" && job.state === "succeeded" && result) {
      body.push(...verifyResult(result));
    } else if (job.type === "export" && job.state === "succeeded" && result) {
      const copy = exportOf(job);
      body.push(...exportResult(copy));
      if (copy && !state.deletedExports.has(copy.export_id) && copy.expires * 1000 > Date.now()) {
        actions.push(button(state.busy.has(`export:${copy.export_id}`) ? "準備下載…" : "下載未加密副本", () => downloadExport(copy), {
          primary: true, icon: "tray-arrow-down", focus: "result-export-download", disabled: state.busy.has(`export:${copy.export_id}`)
        }), button("立即刪除副本", () => deleteExport(copy), {
          icon: "delete-outline", danger: true, focus: "result-export-delete", disabled: state.busy.has(`export-delete:${copy.export_id}`)
        }));
      }
    } else if (restore && job.state === "succeeded") {
      body.push(h("p", { text: "所選應用已還原並啟動，健康檢查與資料核對結果如下。" }));
      if (result?.safety_skipped) {
        body.push(infoNotice("這次還原沒有建立還原前備份（無法建立，而你還原的是還原前備份，或已選擇直接還原）。", "warn", "alert-outline"));
      }
    }

    if (job.state === "rolled-back") {
      body.push(h("p", { text: "還原過程發生錯誤。系統已使用還原前備份，把應用回復到還原前的狀態（全新部署的項目已移除）。不需要再做其他處理。" }));
    }
    if (error && job.state !== "succeeded") body.push(h("div", { class: "notice notice-error" }, icon("alert-circle-outline"), h("p", { text: str(error.message) })));
    if (restore && job.state === "failed") {
      if (manualWork) {
        body.push(h("p", { class: "muted", text: safetyId
          ? "自動回復未完成，需要人工處理。可以使用上列還原前備份再次還原。"
          : "自動回復未完成，需要人工處理；請聯絡系統管理員檢查應用。" }));
        if (dirs.length) {
          body.push(h("p", { class: "muted", text: "主機資料夾旁名稱含「.woowbk-old-」的資料夾可能是還原前的內容，處理完成前請勿刪除。" }));
        }
      } else if (!touched) {
        body.push(h("p", { text: safetyId
          ? "還原在變更任何資料前失敗，應用維持原狀。已建立的還原前備份可保留，或到備份列表刪除。"
          : "還原在變更任何資料前失敗，應用維持原狀。" }));
        if (result?.safety_failed && backupId) {
          // Review CR-16: an app whose database cannot start has no other way back from the page.
          body.push(h("p", { class: "muted", text: "若應用已無法運作（例如資料庫無法啟動），又沒有可用的還原前備份，可以選擇不建立還原前備份直接還原；這時還原失敗將無法自動回復。" }));
          actions.push(button("不建立還原前備份，直接還原…", () => {
            state.pendingWizard = { backupId, apps: list(params.apps).filter(isString), allowNoSafety: true };
            go(["restore", backupId]);
          }, { icon: "backup-restore", focus: "result-no-safety" }));
        }
      }
    }
    if (job.state === "interrupted") {
      const steps = [h("li", { text: "到「總覽」確認各應用的狀態是否為「執行中」。" })];
      if (restore) {
        steps.push(h("li", { text: safetyId && touched
          ? "若應用無法正常運作，請使用下方的還原前備份再次還原，把資料回復到這次還原開始前的狀態。"
          : touched
            ? "還原在變更資料途中中斷（全新部署或沒有還原前備份），應用可能只完成一部分。請再次還原這份備份，或聯絡系統管理員。"
            : "還原在變更任何資料前就中斷，應用資料應未被變更；請確認應用狀態後再決定是否重新還原。" }));
        if (freshApps.length) {
          steps.push(h("li", { text: `全新部署（${freshApps.map(appName).join("、")}）沒有完成；系統會清除未完成的部署（結果見上方訊息），之後可以再次還原同一份備份。` }));
        }
        if (dirs.length) {
          steps.push(h("li", { text: "主機資料夾旁名稱含「.woowbk-new-」或「.woowbk-old-」的資料夾，是還原寫到一半的新內容或原本的內容。"
            + "系統判定中斷時會整理它們（原資料夾不在時把原本的內容移回、移除沒寫完的新內容，絕不刪除僅存的一份），結果見上方訊息與作業紀錄；請勿手動刪除或改名。" }));
        }
        if (!safetyId && (touched || freshApps.length) && backupId) {
          actions.push(button("再次還原這份備份", () => go(["restore", backupId]), { primary: true, icon: "backup-restore", focus: "result-restore-again" }));
        }
      } else {
        steps.push(h("li", { text: job.type === "backup" ? "確認應用已恢復執行後，重新建立備份。中斷的備份不會被列出。" : "重新執行驗證。" }));
      }
      steps.push(h("li", { text: "系統不會自動重做中斷的作業；若不確定應用狀態，請先聯絡系統管理員。" }));
      body.push(h("h4", { class: "subheading", text: "接下來怎麼做" }), h("ol", { class: "guidance" }, steps));
    }
    if (job.state === "cancelled") {
      body.push(h("p", { text: job.type === "backup" ? "沒有建立備份；應用的寫入服務已恢復。" : restore ? "還原在變更任何資料前已取消。" : "驗證已取消。" }));
    }
    if (restore && result) {
      if (safetyId) {
        body.push(metadata([["還原前備份", link(safetyId, ["backups", safetyId], { class: "mono", dataset: { focus: "result-safety" } })]]));
      }
      const health = list(result.health).filter(isObject);
      if (health.length) body.push(h("h4", { class: "subheading", text: "健康檢查" }), checkList(health, "健康檢查結果"));
      if (job.state === "succeeded" && dirs.length) {
        const replaced = dirs.filter(item => item.mode === "inplace");
        const created = dirs.filter(item => item.mode !== "inplace");
        body.push(h("h4", { class: "subheading", text: "主機資料夾" }));
        if (replaced.length) {
          body.push(h("p", { text: `原位還原的應用在備份中有下列主機資料夾；這台設備應用設定列出的，已整個換成備份時的內容${safetyId ? "，還原前的內容保留在上列還原前備份中" : ""}。` }),
            dirList(replaced, "原位還原的主機資料夾"));
        }
        if (created.length) {
          body.push(h("p", { text: "全新部署的應用在備份中有下列主機資料夾；這台設備應用設定列出的，已建立並寫入備份時的內容。" }),
            dirList(created, "全新部署的主機資料夾"));
        }
      }
      // What the restore could not keep, e.g. setuid bits or file capabilities in a volume (review finding HD-09).
      const notes = list(result.warnings).filter(isString).slice(0, 50);
      if (notes.length) body.push(h("h4", { class: "subheading", text: "注意事項" }),
        checkList(notes.map((message, index) => ({ id: `warning-${index}`, status: "warn", message })), "還原注意事項"));
      const timing = list(result.timing).filter(isObject);
      if (timing.length) {
        body.push(h("h4", { class: "subheading", text: "停機時間" }),
          h("p", { class: "muted", text: "服務停止：從第一個服務停止（原位還原為建立還原前備份時的停止）到全部服務再次執行；無法使用：到每個健康檢查都通過。" }),
          timingTable(timing, "restore"));
      }
      const verification = list(result.verification).filter(isObject);
      if (verification.length) body.push(h("h4", { class: "subheading", text: "資料核對（備份時與還原後）" }), ...verificationBlock(verification));
      else if (job.state === "succeeded") body.push(h("p", { class: "muted", text: "這份備份沒有資料核對快照，已略過資料比對。" }));
    }
    // Another destructive restore is offered as the primary step only when recovery is really needed: not after a
    // successful rollback and not after a failure that changed nothing (review findings F2, F8).
    if (safetyId && (manualWork || (job.state === "interrupted" && touched))) {
      actions.unshift(button("使用還原前備份還原", () => go(["restore", safetyId]), { primary: true, icon: "backup-restore", focus: "result-restore-safety" }));
    }
    if (job.state !== "succeeded") {
      const primary = !actions.some(item => item.classList?.contains("primary"));
      actions.push(link("查看總覽", ["overview"], { class: primary ? "button primary" : "button", dataset: { focus: "result-overview" } }));
    }
    if (job.state === "interrupted" && job.type === "backup") actions.push(link("重新建立備份", ["create"], { class: "button", dataset: { focus: "result-create" } }));
    if (restore && job.state === "succeeded") actions.push(link("查看總覽", ["overview"], { class: "button", dataset: { focus: "result-overview" } }));
    return [h("section", { class: `card result result-${tone}`, "aria-labelledby": "result-heading" },
      h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile(glyph, true), h("h3", { id: "result-heading", text: title }))),
      h("div", { class: "card-body" }, body, actions.length ? h("div", { class: "button-group result-actions" }, actions) : null))];
  }

  function formatValue(value) {
    if (value === undefined) return "（無）";
    if (value === null) return "null";
    if (isString(value)) return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    const json = JSON.stringify(value);
    return json.length > 500 ? `${json.slice(0, 500)}…` : json;
  }

  const CHANGE_LABELS = { missing: "遺失", extra: "多出", changed: "不同" };

  function diffCounts(differences) {
    return ["missing", "extra", "changed"].map(key => `${CHANGE_LABELS[key]} ${Number(differences[key]) || 0}`).join("、");
  }

  // The differing items of one digest check (at most 20 from the engine), under the table.
  function differenceList(appLabel, label, differences) {
    const samples = list(differences.samples).filter(isObject).slice(0, 20);
    const total = ["missing", "extra", "changed"].reduce((sum, key) => sum + (Number(differences[key]) || 0), 0);
    const key = `diff-${appLabel}-${label}`;
    return disclosure(key, `「${appLabel}」的「${label}」差異：${diffCounts(differences)}（列出 ${samples.length} / ${total} 筆）`,
      samples.length ? h("ul", { class: "path-list differences", "aria-label": `${label} 的差異` }, samples.map(sample => h("li", null,
        chip(CHANGE_LABELS[sample.change] || str(sample.change), sample.change === "extra" ? "warn" : "fail"),
        h("span", { class: "mono path", text: str(sample.item) }),
        sample.detail ? h("span", { class: "secondary", text: str(sample.detail) }) : null)))
        : h("p", { class: "muted", text: "引擎沒有提供差異的例子；完整內容見作業紀錄。" }));
  }

  // Restore result (CONTRACT §7 verification[]): the app's own JSON summary field by field, then one row per built-in
  // digest check with its counts and verdict; differing items are listed under the table. The line above counts rows.
  function verificationBlock(entries) {
    const rows = [];
    const details = [];
    const tally = { ok: 0, fail: 0, none: 0 };
    const count = match => { tally[match === true ? "ok" : match === false ? "fail" : "none"] += 1; };
    for (const entry of entries) {
      const checks = list(entry.checks).filter(item => isObject(item) && isString(item.id));
      const checkIds = new Set(checks.map(check => check.id));
      const before = isObject(entry.before) ? entry.before : {};
      const after = isObject(entry.after) ? entry.after : {};
      const fields = [];
      for (const id of [...new Set([...Object.keys(before), ...Object.keys(after)])]) {
        if (checkIds.has(id)) continue;  // a digest check's summary: shown in its own row
        if (isObject(before[id]) || isObject(after[id])) {
          const left = isObject(before[id]) ? before[id] : {};
          const right = isObject(after[id]) ? after[id] : {};
          for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])]) fields.push([`${id}.${key}`, left[key], right[key]]);
        } else fields.push([id, before[id], after[id]]);
      }
      const appLabel = appName(str(entry.app));
      const verdict = entry.match === true ? chip("資料一致", "ok", "check-circle-outline")
        : entry.match === false ? chip("資料不一致", "fail", "close-circle-outline") : chip("未比對", "neutral");
      let first = true;
      const appCell = () => {
        const cell = first ? [h("span", { text: appLabel }), " ", verdict] : h("span", { class: "muted", text: appLabel });
        first = false;
        return cell;
      };
      for (const [label, left, right] of fields) {
        const match = left === undefined ? null : JSON.stringify(left) === JSON.stringify(right);
        count(match);
        rows.push(h("tr", null,
          h("th", { scope: "row", "data-label": "應用" }, appCell()),
          h("td", { "data-label": "項目", class: "mono", text: label }),
          h("td", { "data-label": "備份時", class: "mono", text: formatValue(left) }),
          h("td", { "data-label": "還原後", class: "mono", text: formatValue(right) }),
          h("td", { "data-label": "比對" }, match === null ? chip("未比對", "neutral") : match ? chip("相同", "ok") : chip("不同", "fail"))));
      }
      for (const check of checks) {
        count(check.match);
        const label = str(check.label) || str(check.id);
        const differences = isObject(check.differences) ? check.differences : null;
        rows.push(h("tr", { dataset: { check: check.id } },
          h("th", { scope: "row", "data-label": "應用" }, appCell()),
          h("td", { "data-label": "項目" }, h("span", { class: "check-name", text: label }),
            h("span", { class: "secondary", text: `${DIGEST_TYPES[check.type] || str(check.type)} · ${targetText(check.target)}` })),
          h("td", { "data-label": "備份時", text: summaryText(check.type, check.before) }),
          h("td", { "data-label": "還原後", text: summaryText(check.type, check.after) }),
          h("td", { "data-label": "比對" }, check.match === true ? chip("一致", "ok", "check-circle-outline")
            : check.match === false ? chip("不一致", "fail", "close-circle-outline") : chip("未比對", "neutral"),
          differences ? h("span", { class: "secondary", text: diffCounts(differences) }) : null,
          check.note ? h("span", { class: "secondary", text: str(check.note) }) : null)));
        if (check.match === false && differences) details.push(differenceList(appLabel, label, differences));
      }
      if (!fields.length && !checks.length) {
        count(entry.match);
        rows.push(h("tr", null, h("th", { scope: "row", "data-label": "應用" }, appCell()),
          h("td", { "data-label": "項目", colSpan: 4, text: "沒有可比對的資料。" })));
      }
    }
    const total = tally.ok + tally.fail + tally.none;
    const summary = h("p", { class: "verify-summary" },
      h("strong", { text: `共 ${total} 項：` }), `${tally.ok} 項一致、${tally.fail} 項不一致、${tally.none} 項未比對。`,
      tally.fail ? " 資料不一致時，還原會自動回復到還原前的狀態；資料摘要不一致時應用不會啟動。" : "");
    const table = h("table", { class: "data compare" },
      h("caption", { class: "sr-only", text: "備份時與還原後的資料核對" }),
      h("thead", null, h("tr", null, ["應用", "項目", "備份時", "還原後", "比對"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows));
    return [summary, table, ...details];
  }

  // Writer pause and unavailability per app (CONTRACT §7 Timing); null means not measured.
  function timingTable(timing, kind) {
    const rows = list(timing).filter(item => isObject(item) && isString(item.app));
    if (!rows.length) return null;
    const pause = kind === "backup" ? "寫入暫停" : "服務停止";
    return h("table", { class: "data compact timing" },
      h("caption", { class: "sr-only", text: kind === "backup" ? "各應用的寫入暫停與無法使用時間" : "各應用的停機時間" }),
      h("thead", null, h("tr", null, ["應用", pause, "無法使用（到健康檢查通過）"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows.map(item => h("tr", { dataset: { timing: item.app } },
        h("th", { scope: "row", "data-label": "應用", text: appName(item.app) }),
        h("td", { "data-label": pause, text: seconds(item.writer_pause_seconds) }),
        h("td", { "data-label": "無法使用（到健康檢查通過）", text: seconds(item.unavailable_seconds) })))));
  }

  const CHECKED_LABELS = [["volumes", "資料卷"], ["dirs", "主機資料夾"], ["images", "容器映像"], ["digests", "資料摘要"],
    ["globals", "資料庫角色定義"], ["dumps", "資料庫匯出"], ["secrets", "應用機密"]];

  // The verify job checks every entry the way a restore does (`deep`); the device-specific checks stay with the
  // restore's preflight (CONTRACT §5).
  function verifyResult(result) {
    const deep = result.deep === true;
    const apps = list(result.apps).filter(isObject);
    const notes = list(result.notes).filter(isString).slice(0, 50);
    const nodes = [h("p", { text: !result.ok ? "驗證未通過：備份檔內容與內容清單不一致，請勿使用這份備份還原。"
      : deep ? "備份檔已完整讀取，每個項目的大小與 SHA-256 都與內容清單一致，並以還原時相同的規則逐項檢查了內容。這份備份顯示為「已驗證（內容已逐項檢查）」。"
        : "備份檔已完整解密，每個項目的大小與 SHA-256 都與內容清單一致。" }), metadata([
      ["項目數", str(result.entries)], ["資料量", bytes(result.bytes)],
      isNumber(result.format) ? ["格式", result.format === 1 ? "舊格式（.woowbackup）" : "備份檔（.tar）"] : null,
      typeof result.encrypted === "boolean" ? ["加密", result.encrypted ? "已加密" : "未加密"] : null])];
    if (deep && apps.length) {
      // `header_only`: kinds the verify job recognizes only by their format (database dumps; review L8).
      const headerOnly = app => list(app.header_only).filter(isString);
      nodes.push(h("h4", { class: "subheading", text: "逐項檢查的內容" }),
        h("ul", { class: "path-list checked-list", "aria-label": "各應用逐項檢查的內容" }, apps.map(app => {
          const counts = isObject(app.checked) ? app.checked : {};
          const parts = CHECKED_LABELS.filter(([key]) => Number(counts[key]) > 0)
            .map(([key, label]) => `${label} ${Number(counts[key])}${headerOnly(app).includes(key) ? "（只檢查格式）" : ""}`);
          return h("li", null, h("span", { class: "path-app", text: str(app.name || app.id) }),
            h("span", { class: "secondary", text: parts.join("、") || "沒有需要額外檢查的項目" }));
        })),
        apps.some(app => headerOnly(app).includes("dumps"))
          ? h("p", { class: "muted", dataset: { note: "dumps-header-only" }, text: "資料庫匯出在驗證時只確認是 pg_dump 的匯出格式：這台設備建立備份時已完整讀取過一次，還原時會再完整讀取；上傳的備份要到還原時才會完整讀取資料庫匯出的內容。" })
          : null,
        h("p", { class: "muted", text: "與這台設備有關的檢查（應用擁有者的 ID 範圍、需要的映像名稱、PostgreSQL 版本、應用設定）仍在還原的相容性檢查進行。" }));
    }
    if (notes.length) {
      nodes.push(h("h4", { class: "subheading", text: "還原時無法保留的內容" }),
        checkList(notes.map((message, index) => ({ id: `note-${index}`, status: "warn", message })), "驗證注意事項"));
    }
    return nodes;
  }

  function exportResult(copy) {
    if (!copy) return [h("p", { text: "未加密副本已建立。" })];
    const gone = state.deletedExports.has(copy.export_id) || copy.expires * 1000 <= Date.now();
    return [
      h("p", { text: gone ? "這份未加密副本已刪除或過期。需要時請從備份重新建立。"
        : `未加密副本已建立並驗證，會在 ${clockTime(copy.expires)} 自動刪除（約 ${minutesLeft(copy.expires)} 分鐘後）。從這個頁面開始的作業會自動開始下載；沒有開始時請按「下載未加密副本」。` }),
      h("div", { class: "notice notice-warn" }, icon("alert-outline"), h("p", { text: plaintextWarning() })),
      metadata([["檔名", str(copy.filename) || "—", "mono"], ["大小", bytes(copy.size)],
        ["備份", isString(copy.backup_id) && BACKUP_ID_RE.test(copy.backup_id)
          ? link(copy.backup_id, ["backups", copy.backup_id], { class: "mono", dataset: { focus: "result-export-backup" } }) : "—"],
        ["自動刪除", gone ? "已刪除" : `${clockTime(copy.expires)}（約 ${minutesLeft(copy.expires)} 分鐘後）`]])
    ];
  }

  function cancelJob(id) {
    const ui = state.jobUi;
    confirmDialog({
      title: "取消作業？",
      body: [h("p", { text: "作業會在下一個安全的檢查點停止。已完成的部分會被丟棄，應用會維持或恢復正常運作。" })],
      confirmLabel: "取消作業", cancelLabel: "繼續執行",
      action: async () => {
        ui.cancelBusy = true;
        ui.cancelError = null;
        updateJobUi();
        try {
          const data = await call("job-cancel", { job_id: id });
          announce(`已送出取消要求，目前狀態：${JOB_STATES[data.state] || str(data.state)}。`);
        } catch (error) {
          ui.cancelError = error;
        } finally {
          ui.cancelBusy = false;
          try {
            const entry = await fetchJob(id);
            if (ACTIVE.has(entry.job.state)) watchJob(id);
            else if (TERMINAL.has(entry.job.state)) jobFinished(entry.job);
          } catch { /* the error is shown in the job view */ }
          if (state.jobUi.id === id) updateJobUi();
        }
      }
    });
  }

  // ------------------------------------------------------------------ keys & emergency kit

  // 預設加密備份 (CONTRACT §3, §7): on by default; turning it off needs the explicit acknowledgement of the engine's
  // warning (`acknowledge_plaintext`), turning it on needs nothing. A damaged settings file means "encrypted" and is
  // reported in `settings.problem`.
  function settingsCard() {
    const settings = settingsOf();
    if (!settings) return null;
    const ui = state.settings;
    const on = settings.encrypt_by_default;
    return h("section", { class: "card", "aria-labelledby": "settings-heading" },
      h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile(on ? "lock-outline" : "lock-open-variant-outline", true),
        h("h3", { id: "settings-heading", text: "加密設定" })), on ? chip("預設加密", "ok", "lock-outline") : chip("預設不加密", "warn", "lock-open-variant-outline")),
      h("div", { class: "card-body" },
        h("label", { class: on ? "choice" : "choice is-off" },
          h("input", {
            type: "checkbox", id: "encrypt-default", checked: on, disabled: ui.busy, dataset: { focus: "encrypt-default" },
            "aria-describedby": "encrypt-default-help",
            on: { change: event => { event.target.checked = on; changeEncryptDefault(!on); } }
          }),
          h("span", { class: "choice-body" }, h("strong", { text: "預設加密備份" }),
            h("small", { id: "encrypt-default-help", text: "開啟時，新的備份預設以這台設備的金鑰加密，「還原前自動備份」也一律加密（建議）。建立備份時仍可為單一備份取消加密；關閉需要另外確認風險。" }))),
        settings.problem ? infoNotice(str(settings.problem), "warn", "alert-outline") : null,
        on ? null : infoNotice(`目前新的備份與還原前自動備份都不加密。${plaintextWarning()}`, "warn", "lock-open-variant-outline"),
        on && !state.status?.key ? h("p", { class: "muted", text: "加密的備份需要這台設備的加密金鑰；請在下方建立金鑰並保存緊急金鑰。" }) : null,
        ui.notice ? infoNotice(ui.notice, "ok", "check-circle-outline") : null,
        ui.error ? errorNotice(ui.error) : null,
        ui.busy ? h("p", { class: "muted", role: "status", text: "正在儲存設定…" }) : null));
  }

  function changeEncryptDefault(value) {
    const ui = state.settings;
    if (ui.busy) return;
    const save = async request => {
      ui.busy = true;
      ui.error = null;
      ui.notice = null;
      render();
      try {
        const data = await call("settings-set", request);
        requireShape(isObject(data.settings) && typeof data.settings.encrypt_by_default === "boolean", "設定");
        if (state.status) state.status.settings = data.settings;
        ui.notice = data.settings.encrypt_by_default ? "已開啟「預設加密備份」。" : "已關閉「預設加密備份」：新的備份與還原前自動備份都不加密。";
        announce(ui.notice);
      } finally {
        ui.busy = false;
        render();
      }
    };
    if (value) {
      save({ encrypt_by_default: true }).catch(error => { ui.error = error; render(); });
      return;
    }
    confirmDialog({
      title: "關閉預設加密備份？",
      body: [
        h("div", { class: "notice notice-warn" }, icon("alert-outline"), h("p", { text: plaintextWarning() })),
        h("ul", { class: "bullet-list warning-list" },
          h("li", { text: "關閉後，新的備份預設不加密，「還原前自動備份」也不加密。" }),
          h("li", { text: "已建立的備份不受影響；每份備份仍可在建立時選擇加密。" }),
          h("li", { text: "這項變更會記錄在系統日誌。" }))
      ],
      acknowledge: "我了解未加密的備份會以明文保存與下載資料庫密碼、API 金鑰與存取權杖",
      confirmLabel: "關閉預設加密", danger: true,
      action: () => save({ encrypt_by_default: false, acknowledge_plaintext: true })
    });
  }

  function viewKeys() {
    const head = viewTitle("加密金鑰", "備份預設以這台設備的金鑰加密。請保存緊急金鑰，才能在其他設備或重新安裝後還原加密的備份。");
    const status = state.status;
    if (!status) return [head, state.statusError ? errorNotice(state.statusError, { retry: () => loadStatus() }) : loadingCard("正在載入金鑰狀態…")];
    const keys = state.keys;
    const key = status.key;
    let deviceCard;
    if (!key) {
      deviceCard = h("section", { class: "card", "aria-labelledby": "key-setup" },
        h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile("key-outline", true), h("h3", { id: "key-setup", text: "建立加密金鑰" }))),
        h("div", { class: "card-body" },
          h("p", { text: "這台設備還沒有加密金鑰。建立後，所有備份都會用它加密；系統會顯示一次緊急金鑰，請下載並保存到這台設備以外的地方。" }),
          h("ul", { class: "bullet-list" },
            h("li", { text: "金鑰保存在這台設備的受保護目錄，只有管理員可以使用。" }),
            h("li", { text: "在其他設備還原，或這台設備重新安裝後，需要緊急金鑰才能解密備份。" }),
            h("li", { text: "遺失緊急金鑰且這台設備故障時，任何人（包括 woowtech）都無法還原備份。" })),
          keys.error ? errorNotice(keys.error) : null,
          h("div", { class: "button-group" }, button(keys.busy ? "正在建立…" : "建立加密金鑰", createKey, { primary: true, icon: "key-outline", disabled: keys.busy, focus: "key-create" }))));
    } else if (!key.kit_confirmed || keys.kit) {
      deviceCard = kitCard(key);
    } else {
      deviceCard = h("section", { class: "card", "aria-labelledby": "key-ready" },
        h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile("shield-check-outline", true), h("h3", { id: "key-ready", text: "這台設備的金鑰" })),
          chip("已保存緊急金鑰", "ok", "check-circle-outline")),
        h("div", { class: "card-body" }, metadata([["金鑰 ID", str(key.key_id), "mono"], ["建立時間", date(key.created)]]),
          h("p", { class: "muted", text: "緊急金鑰已確認保存。需要另一份時可以重新下載；請像保管密碼一樣保管它。" }),
          keys.error ? errorNotice(keys.error) : null,
          h("div", { class: "button-group" }, button("重新下載緊急金鑰…", redownloadKit, { icon: "tray-arrow-down", disabled: keys.busy, focus: "kit-redownload" }))));
    }
    const imported = status.imported_keys;
    const importedCard = h("section", { class: "card", "aria-labelledby": "imported-keys" },
      h("div", { class: "card-head" }, h("h3", { id: "imported-keys", text: "已匯入的金鑰" })),
      imported.length
        ? h("ul", { class: "item-list" }, imported.map(item => h("li", { class: "item-row" }, tile("key-variant", true),
          h("div", { class: "item-main" }, h("strong", { class: "item-title mono", text: str(item.key_id) }), h("span", { class: "secondary", text: `匯入於 ${date(item.created)}` })))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: "尚未匯入其他設備的金鑰。還原時輸入緊急金鑰並選擇保存，或在下方匯入。" })));
    const importText = h("textarea", {
      id: "import-text", class: "mono", rows: 3, autocomplete: "off", autocapitalize: "off", spellcheck: "false",
      disabled: keys.importBusy, "aria-describedby": "import-hint", dataset: { focus: "import-text" },
      on: { input: event => { keys.importText = event.target.value; } }
    });
    importText.value = keys.importText;
    const importCard = h("section", { class: "card", "aria-labelledby": "import-key" },
      h("div", { class: "card-head" }, h("h3", { id: "import-key", text: "匯入其他設備的金鑰" })),
      h("div", { class: "card-body" },
        h("p", { class: "muted", text: "匯入後，這台設備就能直接檢視與還原以該金鑰加密的備份，不必每次輸入。" }),
        h("div", { class: "field" }, h("label", { htmlFor: "import-text", text: "緊急金鑰" }), importText,
          h("p", { id: "import-hint", class: "hint", text: "貼上以 AGE-SECRET-KEY-1 開頭的整行金鑰，或整份緊急金鑰檔內容。" })),
        h("div", { class: "field" }, h("span", { class: "field-label", id: "import-file-label", text: "或讀取緊急金鑰檔案（.txt）" }),
          filePicker({
            id: "import-file", accept: ".txt,text/plain", label: "選擇檔案：緊急金鑰檔（.txt）", disabled: keys.importBusy, focus: "import-file-button",
            describedBy: "import-file-label", fileName: "只會在瀏覽器讀取，不會上傳檔案",
            onFile: async chosen => {
              const parsed = await readKeyFile(chosen);
              if (parsed.error) keys.importError = new HelperError(parsed.error);
              else {
                keys.importText = parsed.key;
                keys.importError = null;
              }
              render();
            }
          })),
        keys.imported ? infoNotice(`已匯入金鑰 ${keys.imported}。`, "ok", "check-circle-outline") : null,
        keys.importError ? errorNotice(keys.importError) : null,
        h("div", { class: "button-group" }, button(keys.importBusy ? "正在匯入…" : "匯入金鑰", importKey, { icon: "key-variant", disabled: keys.importBusy, focus: "import-submit" }))));
    return [head, settingsCard(), deviceCard, h("div", { class: "grid two" }, importedCard, importCard)];
  }

  function kitCard(key) {
    const keys = state.keys;
    const kit = keys.kit;
    const body = [];
    if (!kit) {
      body.push(h("p", { text: "金鑰已建立，但尚未確認已保存緊急金鑰。請顯示並下載緊急金鑰，保存到這台設備以外的安全位置。" }),
        keys.error ? errorNotice(keys.error) : null,
        h("div", { class: "button-group" }, button(keys.busy ? "正在讀取…" : "顯示並下載緊急金鑰", showKit, { primary: true, icon: "file-key-outline", disabled: keys.busy, focus: "kit-show" })));
    } else {
      body.push(
        h("p", { text: "這是金鑰內容唯一顯示的地方。請下載緊急金鑰檔，或抄寫下方金鑰，保存到密碼管理器、加密隨身碟，或列印後上鎖保管。" }),
        metadata([["金鑰 ID", kit.key_id, "mono"], ["檔名", kit.filename, "mono"]]),
        h("div", { class: "field" }, h("span", { class: "field-label", id: "kit-secret-label", text: "緊急金鑰" }),
          h("code", { id: "kit-secret", class: "secret", "aria-labelledby": "kit-secret-label", text: kit.secret || "（請下載緊急金鑰檔查看）" })),
        h("div", { class: "button-group kit-actions" },
          button("下載緊急金鑰", downloadKit, { primary: true, icon: "tray-arrow-down", focus: "kit-download" }),
          kit.secret ? button("複製金鑰", copySecret, { icon: "content-copy", focus: "kit-copy" }) : null),
        kit.downloaded ? infoNotice(`已下載 ${kit.filename}。請把它移到這台設備以外的安全位置。`, "ok", "check-circle-outline") : null,
        h("ul", { class: "bullet-list warning-list" },
          h("li", { text: "遺失這把金鑰後，以它加密的備份將無法在其他設備還原；任何人都無法替你找回。" }),
          h("li", { text: "任何同時取得金鑰與備份檔的人，都能讀取備份中的資料庫、檔案與應用機密。請勿以電子郵件或聊天訊息傳送。" })),
        h("label", { class: "choice confirm-choice" },
          h("input", {
            type: "checkbox", id: "kit-confirm", checked: keys.confirmChecked, disabled: keys.busy, dataset: { focus: "kit-confirm" },
            on: { change: event => { keys.confirmChecked = event.target.checked; render(); } }
          }),
          h("span", { class: "choice-body" }, h("strong", { text: "我已將緊急金鑰保存到這台設備以外的安全位置" }),
            h("small", { text: "確認後頁面不再顯示金鑰內容，並移除提醒。" }))),
        keys.error ? errorNotice(keys.error) : null,
        h("div", { class: "button-group" }, button(keys.busy ? "正在確認…" : "完成", confirmKit, {
          primary: true, icon: "check", disabled: !keys.confirmChecked || keys.busy, focus: "kit-done"
        })));
    }
    return h("section", { class: "card kit-card", "aria-labelledby": "kit-heading" },
      h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile("file-key-outline", true), h("h3", { id: "kit-heading", text: "緊急金鑰" })),
        chip(key.kit_confirmed ? "已確認保存" : "尚未確認保存", key.kit_confirmed ? "ok" : "warn")),
      h("div", { class: "card-body" }, body));
  }

  async function fetchKit() {
    const data = await call("key-kit");
    requireShape(isString(data.key_id) && isString(data.filename) && isString(data.content) && data.content.length < 65536, "緊急金鑰");
    const filename = data.filename.replace(/[\u0000-\u001f\u007f/\\]/g, "_").slice(0, 200) || "woowtech-backup-key.txt";
    return { key_id: data.key_id, filename, content: data.content, secret: extractSecret(data.content).key || null, downloaded: false };
  }

  async function createKey() {
    const keys = state.keys;
    if (keys.busy) return;
    keys.busy = true;
    keys.error = null;
    render();
    try {
      const data = await call("key-init");
      requireShape(isObject(data.key) && isString(data.key.key_id), "金鑰資訊");
      keys.kit = await fetchKit();
      keys.confirmChecked = false;
      announce(`已建立加密金鑰 ${data.key.key_id}。請下載並保存緊急金鑰。`);
      await loadStatus({ quiet: true });
    } catch (error) {
      keys.error = error;
    } finally {
      keys.busy = false;
      render();
      if (keys.kit) document.querySelector('[data-focus="kit-download"]')?.focus();
    }
  }

  async function showKit() {
    const keys = state.keys;
    if (keys.busy) return;
    keys.busy = true;
    keys.error = null;
    render();
    try {
      keys.kit = await fetchKit();
      keys.confirmChecked = false;
    } catch (error) {
      keys.error = error;
    } finally {
      keys.busy = false;
      render();
    }
  }

  function saveText(filename, content) {
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    const anchor = h("a", { href: url, download: filename, hidden: true });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  function downloadKit() {
    const kit = state.keys.kit;
    if (!kit) return;
    saveText(kit.filename, kit.content);
    kit.downloaded = true;
    announce(`已下載緊急金鑰 ${kit.filename}。`);
    render();
  }

  async function copySecret() {
    const secret = state.keys.kit?.secret;
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      announce("已複製金鑰。請貼到安全的地方保存，不要傳送給他人。");
    } catch {
      const node = $("kit-secret");
      if (node) {
        const range = document.createRange();
        range.selectNodeContents(node);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
      announce("無法自動複製，已選取金鑰文字，請按 Ctrl+C（Mac 為 Command+C）複製。");
    }
  }

  async function confirmKit() {
    const keys = state.keys;
    const kit = keys.kit;
    if (!kit || !keys.confirmChecked || keys.busy) return;
    keys.busy = true;
    keys.error = null;
    render();
    try {
      await call("key-confirm", { key_id: kit.key_id });
      keys.kit = null;
      keys.confirmChecked = false;
      announce("已確認保存緊急金鑰。");
      await loadStatus({ quiet: true });
    } catch (error) {
      keys.error = error;
    } finally {
      keys.busy = false;
      render();
    }
  }

  // Coordinator decision: the kit can be downloaded again after confirmation (like Home Assistant), but only
  // through a dialog that explains its sensitivity; the secret is never put into the page (review F11).
  function redownloadKit() {
    const keys = state.keys;
    if (keys.busy) return;
    confirmDialog({
      title: "重新下載緊急金鑰？",
      body: [
        h("p", { text: "緊急金鑰檔含有可以解開這台設備所有備份的私密金鑰。任何同時取得它與備份檔的人，都能讀取備份中的資料庫、檔案與應用機密。" }),
        h("ul", { class: "bullet-list" },
          h("li", { text: "下載後請直接移到密碼管理器、加密隨身碟等這台設備以外的安全位置。" }),
          h("li", { text: "不要以電子郵件、聊天訊息或公開雲端分享傳送，也不要和備份檔放在一起。" })),
        h("p", { class: "muted", text: "金鑰內容不會顯示在頁面上；檔案只在這台電腦的瀏覽器中產生。" })
      ],
      confirmLabel: "下載緊急金鑰",
      action: async () => {
        const kit = await fetchKit();
        saveText(kit.filename, kit.content);
        announce(`已下載緊急金鑰 ${kit.filename}。請把它移到這台設備以外的安全位置。`);
      }
    });
  }

  async function importKey() {
    const keys = state.keys;
    if (keys.importBusy) return;
    const parsed = extractSecret(keys.importText);
    keys.imported = null;
    if (parsed.error) {
      keys.importError = new HelperError(parsed.error);
      render();
      $("import-text")?.focus();
      return;
    }
    keys.importBusy = true;
    keys.importError = null;
    render();
    try {
      const data = await call("key-import", { key: parsed.key });
      requireShape(isObject(data.key) && isString(data.key.key_id), "金鑰資訊");
      keys.imported = data.key.key_id;
      keys.importText = "";
      announce(`已匯入金鑰 ${data.key.key_id}。`);
      await loadStatus({ quiet: true });
      if (state.backups) loadBackups();
    } catch (error) {
      keys.importError = error;
    } finally {
      keys.importBusy = false;
      render();
    }
  }

  // ------------------------------------------------------------------ cleanup (retention)

  // 清理備份 (docs/backup/CONTRACT.md section 8): per-app usage, a keep-last-N policy for manual backups, a
  // preview of what it would delete (`retention-plan`, read-only) and a confirmed deletion of exactly the backups the
  // administrator kept checked (`retention-apply`). Safety backups keep their own rule, uploads are deleted only when
  // selected here, and the engine never deletes a backup a running job or a failed/interrupted restore still needs.
  const policyOf = value => {
    const policy = isObject(value) ? value : {};
    const keep = item => (Number.isInteger(item) && item >= 1 && item <= KEEP_MAX ? item : null);
    const apps = {};
    for (const [id, item] of Object.entries(isObject(policy.apps) ? policy.apps : {})) {
      if (APP_ID_RE.test(id) && isObject(item)) apps[id] = { keep_last: keep(item.keep_last) };
    }
    return { schema: 1, default_keep_last: keep(policy.default_keep_last), apps };
  };
  const policyKey = policy => JSON.stringify([policy.default_keep_last,
    Object.keys(policy.apps).sort().map(id => [id, policy.apps[id].keep_last])]);
  const validBrief = item => isObject(item) && isString(item.id) && BACKUP_ID_RE.test(item.id);
  const validPlan = data => isObject(data) && isObject(data.policy) && isObject(data.saved_policy) && isObject(data.usage) &&
    Array.isArray(data.usage.apps) && Array.isArray(data.candidates) && Array.isArray(data.blocked) && Array.isArray(data.protected);

  // Without `policy` the plan on screen is computed again (a previewed policy stays previewed); `saved` asks for the
  // saved policy's plan.
  async function loadPlan({ quiet = false, policy = null, saved = false } = {}) {
    const cleanup = state.cleanup;
    if (cleanup.loading) return;
    if (!policy && !saved && cleanup.plan?.proposed === true) policy = policyOf(cleanup.plan.policy);
    cleanup.loading = true;
    if (policy) cleanup.previewBusy = true;
    else if (!quiet) cleanup.error = null;
    render({ background: quiet });
    try {
      const data = await call("retention-plan", policy ? { policy } : {});
      requireShape(validPlan(data), "保留原則資料");
      data.candidates = data.candidates.filter(validBrief);
      data.blocked = data.blocked.filter(validBrief);
      data.protected = data.protected.filter(validBrief);
      data.usage.apps = data.usage.apps.filter(validUsage);
      const savedBefore = cleanup.plan ? policyKey(policyOf(cleanup.plan.saved_policy)) : null;
      // A draft nobody changed follows the saved policy; an edited draft is kept across refreshes.
      if (!cleanup.draft || (savedBefore && policyKey(cleanup.draft) === savedBefore)) cleanup.draft = policyOf(data.saved_policy);
      // A refresh of the same policy keeps what the administrator unchecked; new candidates start checked.
      const samePolicy = cleanup.plan && policyKey(policyOf(cleanup.plan.policy)) === policyKey(policyOf(data.policy));
      const shown = new Set((cleanup.plan?.candidates || []).map(item => item.id));
      cleanup.selected = new Set(data.candidates.map(item => item.id)
        .filter(id => !samePolicy || !shown.has(id) || cleanup.selected.has(id)));
      cleanup.plan = data;
      const blocked = new Set([...data.candidates, ...data.protected].map(item => item.id));
      cleanup.extra = new Set([...cleanup.extra].filter(id => !blocked.has(id) && state.backups?.some(item => item.id === id)));
      cleanup.previewError = null;
      cleanup.error = null;
    } catch (error) {
      if (policy) cleanup.previewError = error;
      else cleanup.error = error;
    } finally {
      cleanup.loading = false;
      cleanup.previewBusy = false;
      render({ background: quiet });
    }
  }

  // The plan on screen is for the policy being edited: only then may its candidates be deleted.
  function planCurrent() {
    const { plan, draft } = state.cleanup;
    return Boolean(plan && draft && policyKey(policyOf(plan.policy)) === policyKey(draft));
  }

  const policyChanged = () => {
    const { plan, draft } = state.cleanup;
    return Boolean(plan && draft && policyKey(policyOf(plan.saved_policy)) !== policyKey(draft));
  };

  function deletionIds() {
    const cleanup = state.cleanup;
    return [...(planCurrent() ? cleanup.selected : []), ...cleanup.extra];
  }

  // One keep-last control: 「依預設」 (only per app), 「全部保留」 or 「最新 N 份」.
  function keepControl({ id, value, inherit, label, onChange }) {
    const mode = value === undefined ? "inherit" : value === null ? "all" : "last";
    const select = h("select", {
      id: `${id}-mode`, "aria-label": `${label}：保留方式`, dataset: { focus: `${id}-mode` }, disabled: state.cleanup.applyBusy,
      on: { change: event => {
        const next = event.target.value;
        onChange(next === "inherit" ? undefined : next === "all" ? null : (Number.isInteger(value) ? value : 5));
        render();
      } }
    }, [inherit ? ["inherit", inherit] : null, ["all", "全部保留"], ["last", "保留最新幾份"]].filter(Boolean)
      .map(([option, text]) => h("option", { value: option, text, selected: option === mode })));
    const number = mode === "last" ? h("input", {
      id: `${id}-count`, type: "number", min: 1, max: KEEP_MAX, step: 1, inputmode: "numeric", value: String(value),
      "aria-label": `${label}：保留最新幾份手動備份`, dataset: { focus: `${id}-count` }, disabled: state.cleanup.applyBusy,
      on: { input: event => {
        const count = Number(event.target.value);
        const valid = Number.isInteger(count) && count >= 1 && count <= KEEP_MAX;
        event.target.setAttribute("aria-invalid", String(!valid));
        if (valid) onChange(count);
        updateCleanupFooter();
      }, change: () => render() }
    }) : null;
    return h("div", { class: "keep-control" }, select, number, number ? h("span", { class: "muted", text: "份" }) : null);
  }

  function setAppKeep(id, value) {
    const draft = state.cleanup.draft;
    if (value === undefined) delete draft.apps[id];
    else draft.apps[id] = { keep_last: value };
  }

  // `prefix` keeps element ids unique: a protected candidate is listed under 依保留原則刪除 and 受保護的備份.
  function briefRow(item, { checked, disabled, onToggle, reason, prefix = "pick" }) {
    const backup = state.backups?.find(entry => entry.id === item.id) || item;
    const apps = list(item.apps).map(app => str(app?.name || app?.id)).filter(Boolean).join("、") || appsText(backup);
    const id = `${prefix}-${item.id}`;
    return h("li", { class: disabled ? "item-row pick is-disabled" : "item-row pick", dataset: { brief: item.id } },
      h("input", {
        type: "checkbox", id, checked, disabled: disabled || state.cleanup.applyBusy,
        "aria-describedby": `${id}-meta`, dataset: { focus: id },
        on: { change: event => { onToggle(event.target.checked); updateCleanupFooter(); } }
      }),
      h("label", { class: "item-main", htmlFor: id },
        h("span", { class: "item-title", text: backupTitle({ type: item.type, created: item.created || backup.created || backup.uploaded_at }) }),
        h("span", { id: `${id}-meta`, class: "secondary", text: [apps, bytes(item.size ?? backup.size), item.note].filter(Boolean).join(" · ") }),
        reason ? h("span", { class: "secondary pick-reason", text: reason }) : null),
      h("span", { class: "chips" }, typeChip(item.type || backup.type), backup.encrypted === false ? chip("未加密", "warn", "lock-open-variant-outline") : null));
  }

  function viewCleanup() {
    const cleanup = state.cleanup;
    const back = backLink("返回備份列表", ["backups"]);
    const head = viewTitle("清理備份", "依應用查看備份佔用的空間，設定手動備份要保留幾份，預覽後再刪除。", [
      button("重新計算", () => loadPlan(), { icon: "refresh", focus: "cleanup-refresh", disabled: cleanup.loading })]);
    if (cleanup.error && unsupported(cleanup.error)) {
      return [back, head, h("section", { class: "card" }, emptyState("alert-circle-outline", "這台設備尚不支援清理備份", UNSUPPORTED))];
    }
    if (!cleanup.plan) {
      return [back, head, cleanup.error ? errorNotice(cleanup.error, { retry: () => loadPlan() }) : loadingCard("正在計算各應用的備份空間…")];
    }
    const plan = cleanup.plan;
    const draft = cleanup.draft || policyOf(plan.saved_policy);
    cleanup.draft = draft;
    const usage = plan.usage;
    const rows = usage.apps;
    const maximum = Math.max(1, ...rows.map(row => row.bytes));
    const defaultText = draft.default_keep_last === null ? "依預設（全部保留）" : `依預設（最新 ${draft.default_keep_last} 份）`;
    const usageTable = h("table", { class: "data usage-table" },
      h("caption", { class: "sr-only", text: "各應用的備份空間與保留原則" }),
      h("thead", null, h("tr", null, ["應用", "備份", "佔用空間", "手動備份保留份數"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows.map(row => h("tr", { dataset: { usage: row.id } },
        h("th", { scope: "row", "data-label": "應用" }, h("strong", { text: str(row.name || row.id) }),
          h("span", { class: "secondary mono", text: row.id }),
          row.in_catalog === false ? h("span", { class: "secondary", text: "這台設備沒有它的應用設定" }) : null),
        h("td", { "data-label": "備份" }, h("span", { text: `${row.backups} 份` }),
          typeCounts(row.types) ? h("span", { class: "secondary", text: typeCounts(row.types) }) : null,
          row.newest ? h("span", { class: "secondary", text: `最新 ${date(row.newest)}` }) : null),
        h("td", { "data-label": "佔用空間" }, h("span", { text: `${bytes(row.bytes)}${row.estimated ? "（估計）" : ""}` }),
          usageMeter(row.bytes, maximum, `${str(row.name || row.id)} 佔用 ${bytes(row.bytes)}`),
          row.shared ? h("span", { class: "secondary", text: "含與其他應用共用的備份" }) : null),
        h("td", { "data-label": "手動備份保留份數" }, keepControl({
          id: `keep-${row.id}`, value: draft.apps[row.id] ? draft.apps[row.id].keep_last : undefined, inherit: defaultText,
          label: str(row.name || row.id), onChange: value => setAppKeep(row.id, value)
        }))))));
    const totals = isObject(usage.total) ? usage.total : { backups: 0, bytes: 0 };
    const unassigned = isObject(usage.unassigned) && usage.unassigned.backups ? usage.unassigned : null;
    const usageCard = h("section", { class: "card", "aria-labelledby": "cleanup-usage" },
      h("div", { class: "card-head" }, h("h3", { id: "cleanup-usage", text: "各應用的備份空間" }),
        h("span", { class: "muted small-text", text: `共 ${Number(totals.backups) || 0} 份，${bytes(totals.bytes)}` })),
      rows.length ? usageTable : h("div", { class: "card-body" }, h("p", { class: "muted", text: "還沒有備份。" })),
      unassigned ? h("div", { class: "card-body" }, h("p", { class: "secondary", text: `另有 ${unassigned.backups} 份尚未檢查內容的上傳備份（${bytes(unassigned.bytes)}），可在下方「其他備份」選擇刪除。` })) : null);
    const policyCard = h("section", { class: "card", "aria-labelledby": "cleanup-policy" },
      h("div", { class: "card-head" }, h("h3", { id: "cleanup-policy", text: "保留原則" }),
        policyChanged() ? chip("尚未儲存", "warn") : chip("已儲存", "ok", "check-circle-outline")),
      h("div", { class: "card-body" },
        h("p", { class: "muted", text: "只計算與刪除「手動」備份：一份備份含多個應用時，要超出每個應用的保留份數才會刪除。還原前自動備份維持原規則（每個應用最新 3 份），上傳的備份只會在你勾選時刪除。儲存後，每次手動備份成功都會依這個原則刪除較舊的手動備份。" }),
        plan.policy_problem ? infoNotice(str(plan.policy_problem), "warn", "alert-outline") : null,
        h("div", { class: "field policy-default" }, h("span", { class: "field-label", id: "keep-default-label", text: "預設（未個別設定的應用）" }),
          keepControl({ id: "keep-default", value: draft.default_keep_last, inherit: null, label: "預設保留原則",
            onChange: value => { draft.default_keep_last = value === undefined ? null : value; } })),
        h("div", { class: "button-group" },
          button(cleanup.previewBusy ? "正在預覽…" : "預覽清理", () => loadPlan({ policy: policyOf(draft) }), {
            primary: !planCurrent(), icon: "eye-outline", focus: "cleanup-preview", disabled: cleanup.previewBusy || cleanup.applyBusy
          }),
          policyChanged() ? button("還原為已儲存的原則", () => { cleanup.draft = policyOf(plan.saved_policy); loadPlan({ saved: true }); }, {
            focus: "cleanup-reset", disabled: cleanup.previewBusy || cleanup.applyBusy
          }) : null),
        cleanup.previewError ? errorNotice(cleanup.previewError) : null));
    const candidates = plan.candidates;
    const stale = !planCurrent();
    const planCard = h("section", { class: "card", "aria-labelledby": "cleanup-candidates" },
      h("div", { class: "card-head" }, h("h3", { id: "cleanup-candidates", text: "依保留原則刪除" }),
        h("span", { class: "muted small-text", text: stale ? "原則已變更，請先預覽" : `${candidates.length} 份，可釋放 ${bytes(plan.freed_bytes)}` })),
      stale ? h("div", { class: "card-body" }, infoNotice("保留原則已變更。按「預覽清理」計算新的原則會刪除哪些備份。", "info", "information-outline"))
        : candidates.length || plan.blocked.length ? h("ul", { class: "item-list picks", "aria-label": "依保留原則刪除的備份" },
          candidates.map(item => briefRow(item, { checked: cleanup.selected.has(item.id), reason: str(item.reason),
            onToggle: on => { if (on) cleanup.selected.add(item.id); else cleanup.selected.delete(item.id); } })),
          plan.blocked.map(item => briefRow(item, { checked: false, disabled: true, prefix: "blocked", reason: `受保護，不會刪除：${str(item.reason)}`, onToggle: () => {} })))
          : h("div", { class: "card-body" }, h("p", { class: "muted", text: draft.default_keep_last === null && !Object.values(draft.apps).some(item => item.keep_last !== null)
            ? "目前的原則是全部保留，沒有要刪除的備份。" : "沒有超出保留份數的手動備份。" })));
    const listed = new Set([...candidates, ...plan.blocked, ...plan.protected].map(item => item.id));
    const others = (state.backups || []).filter(item => !listed.has(item.id));
    const otherCard = h("section", { class: "card", "aria-labelledby": "cleanup-others" },
      h("div", { class: "card-head" }, h("h3", { id: "cleanup-others", text: "其他備份" }),
        h("span", { class: "muted small-text", text: `${others.length} 份；勾選的也會一起刪除` })),
      others.length ? disclosure("cleanup-others-list", "手動選擇要刪除的其他備份",
        h("ul", { class: "item-list picks", "aria-label": "其他可刪除的備份" }, others.map(item => briefRow({
          id: item.id, type: item.type, created: item.created || item.uploaded_at, size: item.size, note: item.note, apps: item.apps
        }, { checked: cleanup.extra.has(item.id), onToggle: on => { if (on) cleanup.extra.add(item.id); else cleanup.extra.delete(item.id); } }))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: "沒有其他可刪除的備份。" })));
    const protectedCard = plan.protected.length ? h("section", { class: "card", "aria-labelledby": "cleanup-protected" },
      h("div", { class: "card-head" }, h("h3", { id: "cleanup-protected", text: "受保護的備份" }),
        h("span", { class: "muted small-text", text: `${plan.protected.length} 份，不會被刪除` })),
      h("ul", { class: "item-list picks", "aria-label": "受保護的備份" }, plan.protected.map(item => briefRow(item, {
        checked: false, disabled: true, prefix: "protected", reason: str(item.reason), onToggle: () => {}
      })))) : null;
    return [back, head,
      cleanup.applied ? cleanupResult(cleanup.applied) : null,
      usageCard, policyCard, planCard, otherCard, protectedCard,
      h("div", { id: "cleanup-footer", class: "form-footer button-group cleanup-footer" }, cleanupFooter())];
  }

  function cleanupFooter() {
    const cleanup = state.cleanup;
    const ids = deletionIds();
    const size = ids.reduce((sum, id) => sum + (Number(state.backups?.find(item => item.id === id)?.size) || 0), 0);
    const active = activeJob();
    const changed = policyChanged();
    const invalid = document.querySelector('.keep-control input[aria-invalid="true"]');
    const blocked = cleanup.applyBusy || Boolean(active) || Boolean(invalid) || (!ids.length && !changed) || (changed && !planCurrent());
    const label = cleanup.applyBusy ? "正在處理…" : ids.length
      ? `刪除 ${ids.length} 份備份${changed ? "並儲存原則" : ""}…` : "儲存保留原則…";
    return [
      h("p", { class: "muted cleanup-hint", role: "status", text: active ? "有作業進行中，請等它完成後再刪除。"
        : invalid ? "保留份數必須是 1 到 1000 的整數。"
          : changed && !planCurrent() ? "原則已變更：請先按「預覽清理」，確認要刪除的備份。"
            : ids.length ? `已選 ${ids.length} 份，共 ${bytes(size)}。` : changed ? "沒有勾選要刪除的備份；可以只儲存原則。" : "沒有勾選要刪除的備份。" }),
      button(label, applyCleanup, { primary: !ids.length, danger: ids.length > 0, icon: ids.length ? "delete-outline" : "check", focus: "cleanup-apply", disabled: blocked })
    ];
  }

  function updateCleanupFooter() {
    const footer = $("cleanup-footer");
    if (!footer) return;
    const snapshot = captureFocus();
    fill(footer, ...cleanupFooter());
    restoreFocus(snapshot);
  }

  function applyCleanup() {
    const cleanup = state.cleanup;
    const ids = deletionIds();
    const changed = policyChanged();
    if (cleanup.applyBusy || activeJob() || (!ids.length && !changed) || (changed && !planCurrent())) return;
    const chosen = ids.map(id => state.backups?.find(item => item.id === id) || { id, type: "manual" });
    const total = chosen.reduce((sum, item) => sum + (Number(item.size) || 0), 0);
    const draft = policyOf(cleanup.draft);
    confirmDialog({
      title: ids.length ? `刪除 ${ids.length} 份備份？` : "儲存保留原則？",
      body: [
        ids.length ? h("p", { text: `會永久刪除下列 ${ids.length} 份備份（共 ${bytes(total)}），無法復原；需要保留的請先下載。` }) : null,
        ids.length ? h("ul", { class: "bullet-list" }, chosen.slice(0, 12).map(item => h("li", { text: `${backupTitle(item)} · ${appsText(item)} · ${bytes(item.size)}` })),
          chosen.length > 12 ? h("li", { text: `…另外 ${chosen.length - 12} 份` }) : null) : null,
        changed ? h("p", { text: `儲存保留原則：${draft.default_keep_last === null ? "預設全部保留" : `預設保留最新 ${draft.default_keep_last} 份手動備份`}${Object.keys(draft.apps).length ? `，${Object.keys(draft.apps).length} 個應用個別設定` : ""}。之後每次手動備份成功，都會依這個原則自動刪除較舊的手動備份。` }) : null,
        h("p", { class: "muted", text: "刪除時若有備份正被作業使用，或失敗、中斷的還原仍需要它，系統會略過並說明原因。每一筆刪除與原則變更都會記錄在系統日誌。" })
      ],
      acknowledge: ids.length ? "我了解這些備份刪除後無法復原" : null,
      confirmLabel: ids.length ? "刪除備份" : "儲存原則", danger: ids.length > 0,
      action: async () => {
        cleanup.applyBusy = true;
        updateCleanupFooter();
        try {
          const request = { confirm: true, backup_ids: ids };
          if (changed) request.policy = draft;
          const data = await call("retention-apply", request);
          requireShape(Array.isArray(data.deleted) && Array.isArray(data.skipped), "清理結果");
          cleanup.applied = data;
          cleanup.extra = new Set();
          if (changed) cleanup.draft = policyOf(data.policy || draft);
          if (state.backups) {
            const gone = new Set(data.deleted.filter(validBrief).map(item => item.id));
            state.backups = state.backups.filter(item => !gone.has(item.id));
          }
          announce(`已刪除 ${data.deleted.length} 份備份${data.skipped.length ? `，略過 ${data.skipped.length} 份` : ""}。`);
        } finally {
          cleanup.applyBusy = false;
          loadBackups();
          loadStatus({ quiet: true });
          loadPlan({ quiet: true });
        }
      }
    });
  }

  function cleanupResult(result) {
    const deleted = list(result.deleted).filter(validBrief);
    const skipped = list(result.skipped).filter(item => isObject(item) && isString(item.id));
    return h("section", { class: "card result result-ok", "aria-labelledby": "cleanup-result" },
      h("div", { class: "card-head" }, h("div", { class: "result-title" }, tile("check-circle", true),
        h("h3", { id: "cleanup-result", text: deleted.length ? `已刪除 ${deleted.length} 份備份` : "已儲存保留原則" })),
        button("關閉", () => { state.cleanup.applied = null; render(); }, { small: true, focus: "cleanup-result-close" })),
      h("div", { class: "card-body" },
        deleted.length ? h("p", { text: `釋放 ${bytes(result.freed_bytes)}。` }) : null,
        result.policy_problem ? infoNotice(str(result.policy_problem), "warn", "alert-outline") : null,
        skipped.length ? [h("h4", { class: "subheading", text: `略過 ${skipped.length} 份` }),
          checkList(skipped.map(item => ({ id: item.id, status: "warn", message: `${item.id}：${str(item.reason)}` })), "略過的備份")] : null));
  }

  // ------------------------------------------------------------------ 應用設定 (catalog drafts)

  // catalog-suggest reads an owner's Quadlet directory as that owner and proposes catalog entries (read-only);
  // catalog-install / catalog-remove preview without `confirm` and change the trusted catalog only when confirmed with
  // the preview's `expected_sha256` (docs/backup/CONTRACT.md section 4). Owner-controlled text arrives in the
  // drafts' warnings, names and labels: it is rendered as text only, like everything else on this page.
  const VARIANT_NAMES = { cold: "冷備份", instance: "整個執行個體", database: "單一資料庫" };
  const OP_LABELS = { add: "新增", remove: "移除", change: "變更", order: "順序" };
  const validOwner = item => isObject(item) && isString(item.name) && OWNER_RE.test(item.name);
  const validDraft = item => isObject(item) && isString(item.id) && APP_ID_RE.test(item.id) && isObject(item.entry);
  const pretty = entry => `${JSON.stringify(entry, null, 2)}\n`;

  async function loadOwners() {
    const catalog = state.catalog;
    if (catalog.ownersBusy) return;
    catalog.ownersBusy = true;
    catalog.ownersError = null;
    render();
    try {
      const data = await call("catalog-suggest", {});
      requireShape(Array.isArray(data.owners), "應用擁有者清單");
      catalog.owners = data.owners.filter(validOwner);
      if (!catalog.owner || !catalog.owners.some(item => item.name === catalog.owner)) {
        const preferred = catalog.owners.find(item => list(item.catalog_apps).length) || catalog.owners.find(item => item.linger) || catalog.owners[0];
        catalog.owner = preferred?.name || null;
      }
    } catch (error) {
      catalog.ownersError = error;
    } finally {
      catalog.ownersBusy = false;
      render();
    }
  }

  async function scanOwner({ quiet = false } = {}) {
    const catalog = state.catalog;
    const owner = catalog.owner;
    if (!owner || catalog.scanBusy) return;
    catalog.scanBusy = true;
    if (!quiet) {
      catalog.scanError = null;
      catalog.notice = null;
    }
    render({ background: quiet });
    try {
      const data = await call("catalog-suggest", { owner });
      requireShape(isString(data.owner) && Array.isArray(data.apps), "掃描結果");
      data.apps = data.apps.filter(validDraft);
      catalog.scan = data;
      // Drafts nobody edited follow the new scan; an edited draft keeps its text (its preview is redone).
      for (const app of data.apps) {
        const draft = catalog.drafts.get(app.id);
        if (draft && draft.owner === data.owner && draft.text !== draft.pristine) {
          draft.app = app;
          draft.preview = null;
          draft.previewFor = null;
        } else catalog.drafts.delete(app.id);
      }
      if (!quiet) announce(`掃描完成：${data.apps.length} 個應用草稿。`);
    } catch (error) {
      catalog.scanError = error;
    } finally {
      catalog.scanBusy = false;
      render({ background: quiet });
    }
  }

  function variantOf(app, id) {
    return list(app.variants).find(item => isObject(item) && item.id === id && isObject(item.entry)) || null;
  }

  function draftState(app) {
    const catalog = state.catalog;
    let draft = catalog.drafts.get(app.id);
    if (!draft) {
      const variant = variantOf(app, app.variant);
      const text = pretty(variant ? variant.entry : app.entry);
      draft = { id: app.id, owner: catalog.scan?.owner, app, variant: variant ? variant.id : null, text, pristine: text,
        lastGood: variant ? variant.entry : app.entry, preview: null, previewFor: null, previewBusy: false, previewError: null,
        seq: 0, timer: null, busy: false, error: null };
      catalog.drafts.set(app.id, draft);
      queueMicrotask(() => previewDraft(app.id));
    }
    return draft;
  }

  function parseEntry(text) {
    if (!text.trim()) return { error: "內容是空的。" };
    if (new TextEncoder().encode(text).length > CATALOG_MAX) return { error: "內容超過 256 KiB，應用設定不可能這麼大。" };
    try {
      const entry = JSON.parse(text);
      return isObject(entry) ? { entry } : { error: "內容必須是一個 JSON 物件（以 { 開頭、} 結尾）。" };
    } catch (error) {
      // V8 reports "position N (line L column C)", Firefox "line L column C": either gives the place to look.
      const message = str(error?.message);
      const lineColumn = /line (\d+) column (\d+)/.exec(message);
      if (lineColumn) return { error: `JSON 格式錯誤：第 ${lineColumn[1]} 行、第 ${lineColumn[2]} 個字元附近。` };
      const match = /position (\d+)/.exec(message);
      if (!match) return { error: "JSON 格式錯誤：請檢查括號、引號與逗號。" };
      const before = text.slice(0, Number(match[1]));
      return { error: `JSON 格式錯誤：第 ${before.split("\n").length} 行、第 ${Number(match[1]) - before.lastIndexOf("\n")} 個字元附近。` };
    }
  }

  function scheduleDraftPreview(id) {
    const draft = state.catalog.drafts.get(id);
    if (!draft) return;
    clearTimeout(draft.timer);
    draft.timer = setTimeout(() => previewDraft(id), 800);
  }

  // catalog-install without `confirm`: the loader's own validation, conflicts with the owner's other entries, the
  // diff against the installed file and what the change means for existing backups. Nothing is written.
  async function previewDraft(id) {
    const draft = state.catalog.drafts.get(id);
    if (!draft) return;
    clearTimeout(draft.timer);
    const parsed = parseEntry(draft.text);
    if (parsed.error) {
      draft.preview = null;
      draft.previewFor = null;
      updateDraftPanels(id);
      return;
    }
    const seq = ++draft.seq;
    const text = draft.text;
    draft.previewBusy = true;
    draft.previewError = null;
    updateDraftPanels(id);
    try {
      const data = await call("catalog-install", { entry: parsed.entry });
      requireShape(isObject(data) && data.preview === true && typeof data.valid === "boolean", "預覽結果");
      if (draft.seq !== seq) return;
      Object.assign(draft, { preview: data, previewFor: text, previewError: null });
    } catch (error) {
      if (draft.seq !== seq) return;
      Object.assign(draft, { preview: null, previewFor: null, previewError: error });
    } finally {
      if (draft.seq === seq) {
        draft.previewBusy = false;
        updateDraftPanels(id);
      }
    }
  }

  function replaceSection(id, nodes) {
    const node = $(id);
    if (!node) return;
    const snapshot = captureFocus();
    fill(node, ...nodes);
    restoreFocus(snapshot);
  }

  // Typing and previews update these sections only: the editor itself is never rebuilt under the cursor.
  function updateDraftPanels(id) {
    const route = currentRoute();
    if (route.page !== "catalog" || route.arg !== id) return;
    const draft = state.catalog.drafts.get(id);
    if (!draft) return;
    replaceSection("catalog-parse", draftParseLine(draft));
    replaceSection("catalog-review", draftReview(draft));
    replaceSection("catalog-feedback", draftFeedback(draft));
    replaceSection("catalog-footer", draftFooter(draft));
  }

  function noteList(items, label) {
    const rows = list(items).filter(item => isObject(item) && isString(item.message));
    if (!rows.length) return null;
    return h("ul", { class: "checks", "aria-label": label }, rows.map(item => {
      const warn = item.level === "warn";
      const where = [item.file, item.path ? `~/${item.path}` : null].filter(isString).join(" · ");
      return h("li", { class: warn ? "check check-warn" : "check check-info" }, icon(warn ? "alert-outline" : "information-outline"),
        h("span", { class: "check-label", text: warn ? "注意" : "說明" }),
        h("span", { class: "check-message" }, h("span", { text: item.message }), where ? h("span", { class: "secondary mono", text: where }) : null));
    }));
  }

  function draftMode(entry, app) {
    const items = list(entry.postgres).filter(isObject);
    if (items.length) {
      return items.map(item => (item.scope === "instance"
        ? `整個執行個體（${str(item.container)}）：備份時資料庫保持執行，保留角色、密碼雜湊與所有資料庫；可還原到相同或更新的主版本`
        : `單一資料庫 ${str(item.database)}（${str(item.container)}）：以 pg_dump 匯出，不保留角色與權限；執行個體有其他資料庫時無法原位還原`)).join("\n");
    }
    const cold = list(app?.databases).filter(db => isObject(db) && db.kind === "postgres");
    if (cold.length) {
      return cold.map(db => `冷備份（${str(db.unit)}）：資料庫與應用一起停止，資料檔隨${db.data?.dir ? `主機資料夾 ~/${str(db.data.dir)}` : `資料卷 ${str(db.data?.volume || "")}`}整份備份；還原需要相同的 PostgreSQL 主版本`).join("\n");
    }
    return "沒有 PostgreSQL";
  }

  function draftReview(draft) {
    const parsed = parseEntry(draft.text);
    if (parsed.entry) draft.lastGood = parsed.entry;
    const entry = isObject(draft.lastGood) ? draft.lastGood : {};
    const names = (items, key, extra) => {
      const rows = list(items).filter(isObject);
      return rows.length ? rows.map(item => `${str(item[key])}${extra ? extra(item) : ""}`).join("\n") : "無";
    };
    return [
      parsed.error ? infoNotice("JSON 有錯誤，下方摘要是最後一次可讀取的內容。", "warn", "alert-outline") : null,
      metadata([
        ["應用 ID", str(entry.id) || "—", "mono"],
        ["名稱", str(entry.name) || "—"],
        ["擁有者", str(entry.owner) || "—"],
        ["服務（啟動順序）", list(entry.units).map(str).join(" → ") || "無"],
        ["備份時停止", list(entry.writer_units).map(str).join("、") || "無"],
        ["PostgreSQL", draftMode(entry, draft.app)],
        ["資料卷", names(entry.volumes, "name", item => (item.label ? `（${str(item.label)}）` : ""))],
        ["主機資料夾", list(entry.data_dirs).filter(isObject).length
          ? dirList(list(entry.data_dirs).filter(isObject).map(dir => ({ dir: { path: str(dir.path), label: str(dir.label), size: null } })), "草稿的主機資料夾") : "無"],
        ["應用機密", names(entry.secrets, "name")],
        ["設定檔", names(entry.config_files, "path", item => `（權限 ${str(item.mode)}）`)],
        ["健康檢查", names(entry.health, "url")],
        ["資料核對", list(entry.verify).filter(isObject).length ? list(entry.verify).filter(isObject).map(item =>
          `${DIGEST_TYPES[item.type] || str(item.type)}：${str(item.label) || targetText(item.volume ? `volume:${item.volume}` : item.data_dir ? `dir:${item.data_dir}`
            : item.postgres ? `postgres:${item.postgres}` : item.container ? `container:${item.container}` : str(item.url))}`).join("\n") : "無"],
        ["部署範本", isObject(entry.quadlet) && entry.quadlet.template_dir ? str(entry.quadlet.template_dir) : "未設定：只能還原到已部署此應用的設備（原位還原）"]
      ])
    ];
  }

  function draftParseLine(draft) {
    const parsed = parseEntry(draft.text);
    const stale = draft.previewFor !== draft.text;
    return [h("p", { class: parsed.error ? "hint hint-error" : "hint", role: "status" },
      parsed.error ? parsed.error
        : draft.previewBusy ? "JSON 格式正確，正在檢查…" : stale ? "JSON 格式正確，停止輸入後會自動檢查。" : "JSON 格式正確，已檢查最新內容。")];
  }

  function changeList(changes) {
    const rows = list(changes).filter(item => isObject(item) && isString(item.path)).slice(0, 60);
    if (!rows.length) return null;
    return h("ul", { class: "path-list changes", "aria-label": "結構化差異" }, rows.map(item => h("li", null,
      chip(OP_LABELS[item.op] || str(item.op), item.op === "remove" ? "fail" : item.op === "add" ? "info" : "neutral"),
      h("span", { class: "mono path", text: item.path }),
      item.op === "change" || item.op === "order"
        ? h("span", { class: "secondary", text: `${formatValue(item.old)} → ${formatValue(item.new)}` }) : null)));
  }

  function diffView(lines, label) {
    const rows = list(lines).filter(isString);
    if (!rows.length) return h("p", { class: "muted", text: "沒有文字差異。" });
    return h("pre", { class: "diff", tabIndex: 0, "aria-label": label, "data-scroll": "", dataset: { focus: "catalog-diff" } }, rows.map(line => h("span", {
      class: line.startsWith("+++") || line.startsWith("---") ? "diff-file" : line.startsWith("@@") ? "diff-hunk"
        : line.startsWith("+") ? "diff-add" : line.startsWith("-") ? "diff-del" : "diff-same",
      text: `${line}\n`
    })));
  }

  function draftFeedback(draft) {
    const preview = draft.previewFor === draft.text ? draft.preview : null;
    if (draft.previewError) {
      return [unsupported(draft.previewError) ? infoNotice(UNSUPPORTED, "warn", "alert-outline") : errorNotice(draft.previewError, { retry: () => previewDraft(draft.id) })];
    }
    if (!preview) {
      return [h("p", { class: "muted", text: draft.previewBusy ? "正在以這台設備的規則檢查草稿…" : "內容變更後會自動檢查；也可以按「預覽變更」。" })];
    }
    const error = isObject(preview.error) ? preview.error : null;
    const conflicts = list(error?.details?.conflicts).filter(isString);
    const field = isString(error?.details?.field) && error.details.field ? error.details.field : null;
    const same = preview.valid && preview.current && preview.expected_sha256 === preview.new_sha256;
    return [
      preview.valid
        ? infoNotice(same ? "內容與目前安裝的設定完全相同。" : preview.current ? "檢查通過：可以取代目前安裝的設定。" : "檢查通過：可以安裝這份應用設定。", "ok", "check-circle-outline")
        : h("div", { class: "notice notice-error", role: "alert" }, icon("alert-circle-outline"), h("div", { class: "notice-body" },
          h("p", { text: str(error?.message) || "這份應用設定沒有通過檢查。" }),
          field ? h("p", { class: "secondary", text: `欄位：${field}` }) : null,
          conflicts.length > 1 ? h("ul", { class: "bullet-list" }, conflicts.map(item => h("li", { text: item }))) : null)),
      metadata([
        ["檔案", `/etc/woowtech-cockpit/backup/apps/${str(preview.file) || `${draft.id}.json`}`, "mono"],
        ["目前安裝", preview.current ? `是（SHA-256 ${str(preview.expected_sha256).slice(0, 12)}…）` : "否：這是新的應用設定"],
        ["這個應用的備份", `${Number(preview.backups) || 0} 份`],
        ["先前的設定", list(preview.history).length ? `${list(preview.history).length} 份保留在 apps-history` : "無"]
      ]),
      list(preview.compat).length ? [h("h4", { class: "subheading", text: "對既有備份的影響" }),
        checkList(list(preview.compat).filter(isString).map((message, index) => ({ id: `compat-${index}`, status: "warn", message })), "對既有備份的影響")] : null,
      list(preview.warnings).length ? [h("h4", { class: "subheading", text: "提醒" }),
        checkList(list(preview.warnings).filter(isString).map((message, index) => ({ id: `warn-${index}`, status: "warn", message })), "安裝提醒")] : null,
      preview.current ? [h("h4", { class: "subheading", text: `與目前安裝的設定比較（${list(preview.changes).length} 項變更）` }), changeList(preview.changes)] : null,
      h("h4", { class: "subheading", text: preview.current ? "文字差異" : "將寫入的內容" }),
      diffView(preview.diff, "應用設定的文字差異")
    ];
  }

  function draftFooter(draft) {
    const preview = draft.previewFor === draft.text ? draft.preview : null;
    const same = preview?.valid && preview.current && preview.expected_sha256 === preview.new_sha256;
    const installed = Boolean(draft.app?.installed) || Boolean(preview?.current);
    const ready = Boolean(preview?.valid) && !same && !draft.busy && !draft.previewBusy;
    return [
      h("p", { class: "muted cleanup-hint", text: draft.busy ? "正在處理…" : !preview ? "安裝前需要先完成檢查。"
        : !preview.valid ? "修正上面的問題後才能安裝。" : same ? "與目前安裝的設定相同，不需要安裝。" : "安裝前會再確認一次。" }),
      installed ? button("移除已安裝的設定…", () => removeEntry(draft.id), { danger: true, icon: "delete-outline", focus: "catalog-remove", disabled: draft.busy }) : null,
      button(draft.busy ? "正在安裝…" : preview?.current ? "取代已安裝的設定…" : "安裝應用設定…", () => installDraft(draft.id), {
        primary: true, icon: "check", focus: "catalog-install", disabled: !ready
      })
    ];
  }

  function chooseVariant(draft, id) {
    const variant = variantOf(draft.app, id);
    if (!variant || draft.variant === id) return;
    const apply = () => {
      const text = pretty(variant.entry);
      Object.assign(draft, { variant: id, text, pristine: text, lastGood: variant.entry, preview: null, previewFor: null, previewError: null });
      render();
      previewDraft(draft.id);
    };
    if (draft.text === draft.pristine) {
      apply();
      return;
    }
    confirmDialog({
      title: "放棄目前的編輯？",
      body: [h("p", { text: `切換到「${VARIANT_NAMES[id] || id}」會以該模式的草稿取代編輯中的內容。` })],
      confirmLabel: "切換並放棄編輯",
      action: async () => apply()
    });
  }

  function loadInstalled(draft) {
    const entry = draft.app?.installed?.entry;
    if (!isObject(entry)) return;
    const text = pretty(entry);
    const apply = () => {
      Object.assign(draft, { text, lastGood: entry, preview: null, previewFor: null, previewError: null });
      render();
      previewDraft(draft.id);
    };
    if (draft.text === draft.pristine) apply();
    else confirmDialog({ title: "放棄目前的編輯？", body: [h("p", { text: "編輯器會改為目前安裝的設定內容。" })], confirmLabel: "載入", action: async () => apply() });
  }

  function viewCatalog() {
    const catalog = state.catalog;
    const head = viewTitle("應用設定", "掃描應用擁有者的 Quadlet 服務定義，產生可備份的應用設定草稿；審查、編輯並預覽差異後再安裝。掃描只會讀取，不會變更任何服務。");
    if (catalog.ownersError && unsupported(catalog.ownersError)) {
      return [head, h("section", { class: "card" }, emptyState("alert-circle-outline", "這台設備尚不支援應用設定掃描", UNSUPPORTED))];
    }
    const apps = state.status?.apps || [];
    const installedCard = h("section", { class: "card", "aria-labelledby": "catalog-installed" },
      h("div", { class: "card-head" }, h("h3", { id: "catalog-installed", text: "已安裝的應用設定" }),
        h("span", { class: "muted small-text", text: `${apps.length} 個` })),
      apps.length ? h("ul", { class: "item-list" }, apps.map(app => h("li", { class: "item-row" }, tile("package-variant-closed", true),
        h("div", { class: "item-main" }, h("strong", { class: "item-title", text: app.name || app.id }),
          h("span", { class: "secondary mono", text: `${app.id}.json` }),
          h("span", { class: "secondary", text: [app.owner && `擁有者 ${app.owner}`, app.description].filter(Boolean).map(str).join(" · ") })),
        h("div", { class: "item-side" }, button("移除…", () => removeEntry(app.id), {
          small: true, danger: true, icon: "delete-outline", focus: `catalog-remove-${app.id}`, label: `移除「${str(app.name || app.id)}」的應用設定`,
          disabled: catalog.busy
        })))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: "尚未安裝任何應用設定。掃描應用擁有者後，可從草稿安裝。" })));
    const owners = catalog.owners;
    const ownerChoices = owners ? owners.map(owner => h("label", { class: "choice" },
      h("input", {
        type: "radio", name: "catalog-owner", value: owner.name, checked: catalog.owner === owner.name, dataset: { focus: `owner-${owner.name}` },
        disabled: catalog.scanBusy, on: { change: () => { catalog.owner = owner.name; render(); } }
      }),
      h("span", { class: "choice-body" }, h("strong", { text: `${owner.name}（UID ${str(owner.uid)}）` }),
        h("small", { text: [owner.linger ? "已啟用 linger" : "未啟用 linger：使用者服務不會在開機時啟動",
          list(owner.catalog_apps).length ? `已安裝：${list(owner.catalog_apps).map(str).join("、")}` : "沒有已安裝的應用設定"].join(" · ") })))) : null;
    const scanCard = h("section", { class: "card", "aria-labelledby": "catalog-scan" },
      h("div", { class: "card-head" }, h("h3", { id: "catalog-scan", text: "掃描應用擁有者" })),
      h("div", { class: "card-body" },
        h("p", { class: "muted", text: "以該帳號的身分讀取 ~/.config/containers/systemd 的 Quadlet 檔，依網路、相依關係、資料卷與標籤分組成應用。不會讀取環境變數檔，也不會顯示 Environment= 的值或健康檢查指令。" }),
        catalog.ownersError ? errorNotice(catalog.ownersError, { retry: () => loadOwners() }) : null,
        !owners ? h("p", { class: "muted", role: "status", text: catalog.ownersBusy ? "正在列出應用擁有者…" : "尚未載入應用擁有者。" })
          : owners.length ? h("fieldset", { class: "form-section" }, h("legend", { class: "sr-only", text: "應用擁有者" }), h("div", { class: "choices" }, ownerChoices))
            : h("p", { class: "muted", text: "找不到可掃描的帳號（需要啟用 linger 的非 root 帳號）。" }),
        h("div", { class: "button-group" }, button(catalog.scanBusy ? "正在掃描…" : "掃描 Quadlet 服務定義", () => scanOwner(), {
          primary: true, icon: "magnify", focus: "catalog-scan", disabled: !catalog.owner || catalog.scanBusy
        })),
        catalog.scanError ? errorNotice(catalog.scanError, { retry: () => scanOwner() }) : null));
    return [head, catalog.notice ? infoNotice(catalog.notice, "ok", "check-circle-outline") : null, installedCard, scanCard, scanResult()];
  }

  function scanResult() {
    const scan = state.catalog.scan;
    if (!scan) return null;
    const files = (items, label) => {
      const rows = list(items).filter(item => isObject(item) && isString(item.file));
      return rows.length ? [h("h4", { class: "subheading", text: label }),
        h("ul", { class: "path-list" }, rows.map(item => h("li", null, h("span", { class: "mono path", text: item.file }),
          h("span", { class: "secondary", text: str(item.reason) }))))] : null;
    };
    const drafts = scan.apps.map(app => {
      const variant = VARIANT_NAMES[app.variant];
      const installed = isObject(app.installed) ? app.installed : null;
      const warnings = list(app.warnings).filter(item => isObject(item) && item.level === "warn").length;
      return h("li", { class: "item-row", dataset: { draft: app.id } }, tile("package-variant-closed", true),
        h("div", { class: "item-main" },
          link(app.id, ["catalog", app.id], { class: "item-title", dataset: { focus: `draft-${app.id}` } }),
          h("span", { class: "secondary", text: str(app.entry.description) }),
          h("span", { class: "secondary", text: [`${list(app.containers).length} 個容器`, variant ? `PostgreSQL：${variant}` : "沒有 PostgreSQL",
            warnings ? `${warnings} 項注意` : null].filter(Boolean).join(" · ") })),
        h("div", { class: "item-side" }, h("span", { class: "chips" },
          installed ? (installed.same ? chip("與已安裝的相同", "ok", "check-circle-outline") : chip(`已安裝・有 ${list(installed.changes).length} 項差異`, "warn"))
            : chip("未安裝", "neutral"),
          app.valid ? null : chip("草稿需要修改", "fail", "alert-circle-outline")),
        link("審查草稿", ["catalog", app.id], { class: "button small", dataset: { focus: `draft-open-${app.id}` } })));
    });
    return h("section", { class: "card", "aria-labelledby": "catalog-drafts" },
      h("div", { class: "card-head" }, h("h3", { id: "catalog-drafts", text: `${str(scan.owner)} 的應用草稿（${scan.apps.length}）` }),
        h("span", { class: "muted small-text mono", text: `~/${str(scan.quadlet_dir) || ".config/containers/systemd"}` })),
      h("div", { class: "card-body" },
        scan.state === "missing" ? infoNotice("這個帳號沒有 Quadlet 服務定義資料夾。", "info", "information-outline")
          : scan.state === "blocked" ? infoNotice("Quadlet 服務定義資料夾不安全（例如是符號連結），沒有讀取。", "warn", "alert-outline") : null,
        noteList(scan.warnings, "掃描提醒"),
        drafts.length ? null : h("p", { class: "muted", text: "沒有找到可以組成應用的容器服務。" })),
      drafts.length ? h("ul", { class: "item-list drafts" }, drafts) : null,
      list(scan.unassigned).length || list(scan.unsupported).length
        ? h("div", { class: "card-body" }, files(scan.unassigned, "沒有歸入應用的檔案"), files(scan.unsupported, "不支援的檔案")) : null);
  }

  function viewDraft(id) {
    const back = backLink("返回應用設定", ["catalog"]);
    const head = viewTitle(`應用設定草稿：${id}`, "審查草稿、依需要編輯 JSON，確認檢查與差異後再安裝。安裝只寫入應用設定檔，不會變更任何服務或資料。");
    const scan = state.catalog.scan;
    const app = APP_ID_RE.test(id) ? scan?.apps.find(item => item.id === id) : null;
    if (!app) {
      return [back, head, h("section", { class: "card" }, emptyState("magnify", scan ? "找不到這個草稿" : "請先掃描應用擁有者",
        scan ? "重新掃描後，這個應用可能已改名或不再存在。" : "草稿只保存在這個頁面；重新整理後請回到「應用設定」重新掃描。", [
          link("回到應用設定", ["catalog"], { class: "button primary", dataset: { focus: "draft-back-catalog" } })]))];
    }
    const draft = draftState(app);
    draft.app = app;
    const installed = isObject(app.installed) ? app.installed : null;
    const variants = list(app.variants).filter(item => isObject(item) && isString(item.id));
    const containers = list(app.containers).filter(isObject);
    const summary = h("section", { class: "card", "aria-labelledby": "draft-summary" },
      h("div", { class: "card-head" }, h("h3", { id: "draft-summary", text: "掃描到的服務" }),
        h("span", { class: "chips" }, installed ? (installed.same ? chip("與已安裝的相同", "ok", "check-circle-outline") : chip("已安裝・有差異", "warn")) : chip("未安裝", "neutral"))),
      containers.length ? h("table", { class: "data containers-table" },
        h("caption", { class: "sr-only", text: "草稿包含的容器" }),
        h("thead", null, h("tr", null, ["Quadlet 檔", "服務", "映像", "狀態"].map(label => h("th", { scope: "col", text: label })))),
        h("tbody", null, containers.map(item => h("tr", null,
          h("th", { scope: "row", "data-label": "Quadlet 檔", class: "mono", text: str(item.file) }),
          h("td", { "data-label": "服務", class: "mono", text: str(item.unit) }),
          h("td", { "data-label": "映像", class: "mono", text: str(item.image) || "—" }),
          h("td", { "data-label": "狀態", text: item.state === "active" ? "執行中" : str(item.state) || "—" })))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: "沒有容器。" })),
      installed && list(installed.drift).length ? h("div", { class: "card-body" }, h("h4", { text: "與已安裝設定的結構差異" }),
        checkList(list(installed.drift).filter(isString).map((message, index) => ({ id: `drift-${index}`, status: "warn", message })), "與已安裝設定的結構差異")) : null);
    const variantCard = variants.length ? h("section", { class: "card", "aria-labelledby": "draft-variants" },
      h("div", { class: "card-head" }, h("h3", { id: "draft-variants", text: "PostgreSQL 備份方式" })),
      h("div", { class: "card-body" },
        h("fieldset", { class: "form-section" }, h("legend", { class: "sr-only", text: "PostgreSQL 備份方式" }),
          h("div", { class: "choices" }, variants.map(variant => h("label", { class: variant.valid === false ? "choice is-disabled" : "choice" },
            h("input", {
              type: "radio", name: `variant-${app.id}`, value: variant.id, checked: draft.variant === variant.id, disabled: draft.busy,
              dataset: { focus: `variant-${variant.id}` }, on: { change: () => chooseVariant(draft, variant.id) }
            }),
            h("span", { class: "choice-body" },
              h("strong", null, VARIANT_NAMES[variant.id] || variant.id, app.variant === variant.id ? h("span", { class: "muted", text: "（建議）" }) : null),
              h("small", { text: str(variant.label) }),
              variant.valid === false && variant.problem ? h("small", { class: "hint-error", text: str(variant.problem) }) : null))))),
        h("p", { class: "muted", text: "冷備份最穩妥但會停止資料庫；整個執行個體模式讓資料庫保持執行並保留角色與所有資料庫；單一資料庫只適合執行個體中只有這個應用資料庫、也不需要其他角色的應用。已安裝的應用改變方式後，舊備份在新設定下無法還原。" }))) : null;
    const notes = [noteList(app.warnings, "草稿注意事項"), noteList(app.notes, "草稿說明")].filter(Boolean);
    const skipped = list(app.skipped).filter(isObject);
    const hints = list(app.hints).filter(isString);
    const notesCard = h("section", { class: "card", "aria-labelledby": "draft-notes" },
      h("div", { class: "card-head" }, h("h3", { id: "draft-notes", text: "審查提醒" })),
      h("div", { class: "card-body" },
        app.valid === false && app.problem ? errorNotice(new HelperError(`${str(app.problem)}${app.field ? `（欄位 ${str(app.field)}）` : ""}`)) : null,
        notes.length ? notes : h("p", { class: "muted", text: "沒有需要注意的項目。" }),
        skipped.length ? [h("h4", { class: "subheading", text: "沒有列入的項目" }), h("ul", { class: "path-list" }, skipped.map(item => h("li", null,
          h("span", { class: "mono path", text: item.path ? `~/${str(item.path)}` : str(item.name) }),
          h("span", { class: "secondary", text: str(item.reason) }))))] : null,
        hints.length ? [h("h4", { class: "subheading", text: "建議" }), h("ul", { class: "bullet-list" }, hints.map(item => h("li", { text: item })))] : null));
    const editor = h("textarea", {
      id: "catalog-editor", class: "mono editor", rows: 22, spellcheck: "false", autocomplete: "off", autocapitalize: "off", wrap: "off",
      "aria-describedby": "catalog-parse", dataset: { focus: "catalog-editor" }, disabled: draft.busy,
      on: { input: event => {
        draft.text = event.target.value;
        replaceSection("catalog-parse", draftParseLine(draft));
        replaceSection("catalog-tools", draftTools(draft));
        replaceSection("catalog-review", draftReview(draft));
        replaceSection("catalog-footer", draftFooter(draft));
        scheduleDraftPreview(draft.id);
      } }
    });
    editor.value = draft.text;
    const editorCard = h("section", { class: "card", "aria-labelledby": "draft-editor" },
      h("div", { class: "card-head" }, h("h3", { id: "draft-editor", text: "應用設定（JSON）" })),
      h("div", { class: "card-body" },
        h("label", { class: "field-label", htmlFor: "catalog-editor", text: `${id}.json` }), editor,
        h("div", { id: "catalog-parse" }, draftParseLine(draft)),
        h("div", { id: "catalog-tools", class: "button-group" }, draftTools(draft))));
    return [back, head, state.catalog.notice ? infoNotice(state.catalog.notice, "ok", "check-circle-outline") : null,
      summary, variantCard,
      h("div", { class: "grid two" },
        h("section", { class: "card", "aria-labelledby": "draft-review" },
          h("div", { class: "card-head" }, h("h3", { id: "draft-review", text: "這份設定會備份什麼" })),
          h("div", { id: "catalog-review", class: "card-body" }, draftReview(draft))),
        notesCard),
      editorCard,
      h("section", { class: "card", "aria-labelledby": "draft-feedback" },
        h("div", { class: "card-head" }, h("h3", { id: "draft-feedback", text: "檢查與差異" })),
        h("div", { id: "catalog-feedback", class: "card-body" }, draftFeedback(draft))),
      draft.error ? errorNotice(draft.error) : null,
      h("div", { id: "catalog-footer", class: "form-footer button-group cleanup-footer" }, draftFooter(draft))];
  }

  function draftTools(draft) {
    const installed = isObject(draft.app?.installed) ? draft.app.installed : null;
    const edited = draft.text !== draft.pristine;
    return [
      edited ? chip("已編輯", "info") : chip("草稿原文", "neutral"),
      button("預覽變更", () => previewDraft(draft.id), { icon: "eye-outline", focus: "catalog-preview", disabled: draft.busy }),
      edited ? button("還原為草稿", () => {
        Object.assign(draft, { text: draft.pristine, preview: null, previewFor: null });
        render();
        previewDraft(draft.id);
      }, { icon: "refresh", focus: "catalog-revert", disabled: draft.busy }) : null,
      installed && isObject(installed.entry)
        ? button("載入已安裝的設定", () => loadInstalled(draft), { icon: "file-document-outline", focus: "catalog-load-installed", disabled: draft.busy }) : null
    ];
  }

  function installDraft(id) {
    const draft = state.catalog.drafts.get(id);
    const preview = draft && draft.previewFor === draft.text ? draft.preview : null;
    if (!draft || !preview?.valid || draft.busy) return;
    const parsed = parseEntry(draft.text);
    if (parsed.error) return;
    const changes = list(preview.changes);
    confirmDialog({
      title: preview.current ? `取代「${id}」的應用設定？` : `安裝「${id}」的應用設定？`,
      body: [
        h("p", { text: preview.current
          ? "會以新的內容取代目前安裝的設定；舊的設定保留在 apps-history（每個應用最近 10 份），安裝後立即重新載入確認。"
          : "會安裝這份應用設定（root 擁有、權限 0644）並立即重新載入確認；之後這個應用會出現在備份頁，可以建立備份。" }),
        metadata([["檔案", `/etc/woowtech-cockpit/backup/apps/${id}.json`, "mono"],
          preview.current ? ["變更", `${changes.length} 項`] : null,
          ["這個應用的備份", `${Number(preview.backups) || 0} 份`]]),
        list(preview.compat).length ? [h("h4", { text: "對既有備份的影響" }), h("ul", { class: "bullet-list warning-list" }, list(preview.compat).filter(isString).map(item => h("li", { text: item })))] : null,
        list(preview.warnings).length ? [h("h4", { text: "提醒" }), h("ul", { class: "bullet-list" }, list(preview.warnings).filter(isString).map(item => h("li", { text: item })))] : null,
        h("p", { class: "muted", text: "這項變更會記錄在系統日誌。安裝只寫入應用設定檔，不會建立部署範本，也不會變更服務或資料。" })
      ],
      acknowledge: "我已審查上面的內容、差異與影響",
      confirmLabel: preview.current ? "取代設定" : "安裝設定",
      action: async () => {
        draft.busy = true;
        draft.error = null;
        try {
          const data = await call("catalog-install", { entry: parsed.entry, confirm: true, expected_sha256: preview.expected_sha256 ?? null });
          requireShape(data.installed === true && isString(data.sha256), "安裝結果");
          state.catalog.notice = `已${preview.current ? "取代" : "安裝"}「${id}」的應用設定（SHA-256 ${data.sha256.slice(0, 12)}…）。`;
          announce(state.catalog.notice);
          Object.assign(draft, { pristine: draft.text, preview: null, previewFor: null });
          loadStatus({ quiet: true });
          scanOwner({ quiet: true });
        } catch (error) {
          if (error.details?.reason === "entry-changed") {
            throw new HelperError("目前安裝的設定在預覽之後被變更了。請重新預覽，確認差異後再安裝。", { code: error.code });
          }
          throw error;
        } finally {
          draft.busy = false;
          render();
        }
      }
    });
  }

  async function removeEntry(id) {
    const catalog = state.catalog;
    if (catalog.busy) return;
    catalog.busy = true;
    state.actionError = null;
    render();
    let preview;
    try {
      preview = await call("catalog-remove", { id });
      requireShape(preview.preview === true && "expected_sha256" in preview, "移除預覽");
    } catch (error) {
      state.actionError = unsupported(error) ? new HelperError(UNSUPPORTED, { code: error.code }) : error;
      return;
    } finally {
      catalog.busy = false;
      render();
    }
    const entry = isObject(preview.current?.entry) ? preview.current.entry : {};
    confirmDialog({
      title: `移除「${id}」的應用設定？`,
      body: [
        h("p", { text: "移除後，這個應用不會再出現在備份頁，也不能建立或還原它的備份，直到重新安裝它的應用設定。應用本身與它的服務、資料都不會被變更。" }),
        metadata([["檔案", `/etc/woowtech-cockpit/backup/apps/${id}.json`, "mono"], ["名稱", str(entry.name) || "—"], ["擁有者", str(entry.owner) || "—"],
          ["這個應用的備份", `${Number(preview.backups) || 0} 份（會保留）`]]),
        list(preview.warnings).length ? h("ul", { class: "bullet-list warning-list" }, list(preview.warnings).filter(isString).map(item => h("li", { text: item }))) : null,
        h("p", { class: "muted", text: "被移除的設定會保留在 apps-history（每個應用最近 10 份），這項變更會記錄在系統日誌。" })
      ],
      acknowledge: "我了解移除後無法再備份或還原這個應用，直到重新安裝它的應用設定",
      confirmLabel: "移除設定", danger: true,
      action: async () => {
        const data = await call("catalog-remove", { id, confirm: true, expected_sha256: preview.expected_sha256 ?? null });
        requireShape(data.removed === true, "移除結果");
        catalog.notice = `已移除「${id}」的應用設定；${Number(data.backups) || 0} 份備份仍保留。`;
        announce(catalog.notice);
        catalog.drafts.delete(id);
        loadStatus({ quiet: true });
        if (catalog.scan) scanOwner({ quiet: true });
        render();
      }
    });
  }

  // ------------------------------------------------------------------ activity

  function viewActivity() {
    const head = viewTitle("活動紀錄", "最近 50 筆備份、還原與驗證作業。作業在背景執行，可隨時回來查看。", [
      button("更新紀錄", () => loadJobs(), { icon: "refresh", focus: "activity-refresh", disabled: state.loading.has("jobs") })]);
    if (!state.jobs) return [head, pendingCard("jobs", "正在載入活動紀錄…")];
    if (!state.jobs.length) return [head, h("section", { class: "card" }, emptyState("clipboard-text-outline", "尚無活動紀錄", "建立備份或還原後，作業會顯示在這裡。"))];
    const rows = state.jobs.map(job => {
      const params = isObject(job.params) ? job.params : {};
      const summary = [
        list(params.apps).length ? list(params.apps).map(id => appName(str(id))).join("、") : null,
        isString(params.backup_id) ? `備份 ${params.backup_id}` : null
      ].filter(Boolean).join(" · ");
      return h("tr", null,
        h("th", { scope: "row", "data-label": "時間" }, link(date(job.created), ["jobs", job.id], {
          class: "row-title", dataset: { focus: `job-${job.id}` }, "aria-label": `查看 ${date(job.created)} 的${jobTitle(job.type)}`
        }), h("span", { class: "secondary mono", text: job.id })),
        h("td", { "data-label": "作業", text: `${JOB_TYPES[job.type]}` }),
        h("td", { "data-label": "狀態" }, jobStateChip(job.state)),
        h("td", { "data-label": "內容", text: summary || "—" }),
        h("td", { "data-label": "結果", text: isObject(job.error) ? str(job.error.message) : ACTIVE.has(job.state) ? `${clamp(Number(job.progress?.percent) || 0, 0, 100)}% · ${str(job.progress?.message)}` : JOB_STATES[job.state] || "" }));
    });
    return [head, h("section", { class: "card list-card" }, h("table", { class: "data jobs-table" },
      h("caption", { class: "sr-only", text: "活動紀錄" }),
      h("thead", null, h("tr", null, ["時間", "作業", "狀態", "內容", "結果"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows)))];
  }

  // ------------------------------------------------------------------ backup actions

  async function channelPrefix() {
    let token = cockpit.transport?.csrf_token;
    if (!isString(token) || !token) {
      await new Promise(resolve => {
        const timer = setTimeout(resolve, 5000);
        try { cockpit.transport.wait(() => { clearTimeout(timer); resolve(); }); } catch { clearTimeout(timer); resolve(); }
      });
      token = cockpit.transport?.csrf_token;
    }
    if (!isString(token) || !token) throw new HelperError("無法取得下載授權，請重新整理頁面後再試。", { code: "no-csrf" });
    return new URL(cockpit.transport.uri(`channel/${token}`)).pathname;
  }

  function encodeQuery(value) {
    const data = new TextEncoder().encode(JSON.stringify(value));
    let binary = "";
    for (let index = 0; index < data.length; index += 0x8000) binary += String.fromCharCode(...data.subarray(index, index + 0x8000));
    return window.btoa(binary);
  }

  const contentDisposition = name => "attachment; filename*=UTF-8''" +
    encodeURIComponent(name).replace(/['()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

  async function downloadBackup(backup) {
    const busyKey = `download:${backup.id}`;
    if (state.busy.has(busyKey)) return;
    state.busy.add(busyKey);
    state.actionError = null;
    render();
    try {
      const info = await call("download-info", { backup_id: backup.id });
      requireShape(isString(info.path) && info.path.startsWith("/") && isString(info.filename) && info.filename && isNumber(info.size), "下載資訊");
      await frameDownload(info.path, info.filename);
      announce(`已開始下載 ${info.filename}（${bytes(info.size)}）。若瀏覽器沒有開始下載，請再試一次。`);
    } catch (error) {
      state.actionError = error;
    } finally {
      state.busy.delete(busyKey);
      render();
    }
  }

  // A stored backup and an unencrypted copy download the same way: Cockpit's external fsread1 channel (CONTRACT §11).
  async function frameDownload(path, filename) {
    const prefix = await channelPrefix();
    const query = encodeQuery({
      payload: "fsread1", binary: "raw", path, superuser: "require", max_read_size: -1,
      external: { "content-disposition": contentDisposition(filename), "content-type": "application/octet-stream" }
    });
    startFrameDownload(`${prefix}?${query}`, filename);
  }

  function startFrameDownload(url, filename) {
    const container = $("downloads");
    const frame = h("iframe", { title: `下載 ${filename}`, tabIndex: -1, "aria-hidden": "true" });
    // A completed download never renders a document; a load with text means an error page.
    frame.addEventListener("load", () => {
      let message = "";
      try { message = str(frame.contentDocument?.body?.textContent).trim().slice(0, 200); } catch { /* not readable */ }
      if (message) {
        state.actionError = new HelperError(`下載 ${filename} 沒有開始：${message}`, { code: "download-failed" });
        render();
      }
    });
    frame.src = url;
    container.append(frame);
    while (container.children.length > 4) container.firstElementChild.remove();
  }

  function verifyBackup(backup) {
    if (activeJob()) {
      state.actionError = new HelperError("已有作業正在進行，請等它完成後再驗證。", { code: "busy", details: { job_id: activeJob().id } });
      render();
      return;
    }
    const start = async key => {
      if (!state.verifyRequest || state.verifyRequest.backupId !== backup.id) state.verifyRequest = { backupId: backup.id, id: requestId() };
      const request = { backup_id: backup.id, request_id: state.verifyRequest.id };
      if (key) request.key = key;
      const data = await call("verify-start", request);
      requireShape(isString(data.job_id) && JOB_ID_RE.test(data.job_id), "作業資訊");
      state.verifyRequest = null;
      announce("已開始驗證作業。");
      watchJob(data.job_id);
      go(["jobs", data.job_id]);
      loadStatus({ quiet: true });
    };
    if (!backup.key_available) {
      keyDialog({
        title: "輸入緊急金鑰以驗證", allowSave: false, confirmLabel: "開始驗證",
        description: `這份備份以金鑰 ${str(backup.key_id) || "（未知）"} 加密。金鑰只交給這次驗證作業使用，作業結束後即刪除。`,
        action: ({ key }) => start(key)
      });
      return;
    }
    start(null).catch(error => { state.actionError = error; render(); });
  }

  function deleteBackup(backup) {
    const warnings = [];
    if (backup.type === "safety") warnings.push(h("p", { class: "notice-inline", text: "這是還原前自動備份。刪除後，就無法用它回復到那次還原之前的狀態。" }));
    if (!backup.key_available) warnings.push(h("p", { class: "muted", text: "這份備份的金鑰不在這台設備上。" }));
    confirmDialog({
      title: "刪除備份？",
      body: [h("p", { text: "刪除後無法復原。若需要保留，請先下載備份檔。" }), metadata([
        ["備份", backupTitle(backup)], ["備份 ID", backup.id, "mono"], ["應用", appsText(backup)], ["大小", bytes(backup.size)],
        backup.note ? ["備註", backup.note] : null]), ...warnings],
      confirmLabel: "刪除備份", danger: true,
      action: async () => {
        await call("delete", { backup_id: backup.id });
        if (state.backups) state.backups = state.backups.filter(item => item.id !== backup.id);
        if (state.detail?.id === backup.id) state.detail = null;
        announce(`已刪除 ${backupTitle(backup)}。`);
        const route = currentRoute();
        if ((route.page === "backups" && route.arg === backup.id) || (route.page === "restore" && route.arg === backup.id)) go(["backups"]);
        else if (route.page === "restore" && state.wizard?.backupId === backup.id) {
          state.wizard = null;
          go(["backups"]);
        }
        loadBackups();
        loadStatus({ quiet: true });
      }
    });
  }

  // ------------------------------------------------------------------ dialogs

  let confirmState = null;
  let keyDialogState = null;

  function setDialogError(prefix, error) {
    const box = $(`${prefix}-error`);
    const message = isString(error) ? error : str(error?.message);
    box.hidden = !message;
    text($(`${prefix}-error-message`), message);
    box.querySelector(".dialog-error-actions")?.remove();
    // A busy refusal links to the blocking job, as errorNotice does elsewhere (review finding F12).
    const jobId = error?.details?.job_id;
    if (error?.code === "busy" && isString(jobId) && JOB_ID_RE.test(jobId)) {
      box.append(h("div", { class: "button-group dialog-error-actions" }, link("查看進行中的作業", ["jobs", jobId], {
        class: "button small", dataset: { focus: "dialog-busy-job" },
        on: { click: () => { const dialog = box.closest("dialog"); if (dialog?.open) dialog.close(); } }
      })));
    }
  }

  // `acknowledge`: the text of a checkbox the confirm button waits for (an explicit decision, e.g. plain text).
  function confirmDialog({ title, body, confirmLabel = "確認", cancelLabel = "取消", danger = false, acknowledge = null, action }) {
    const dialog = $("confirm-dialog");
    if (dialog.open) return;
    confirmState = { action, busy: false, trigger: document.activeElement, confirmLabel, acknowledge: Boolean(acknowledge) };
    text($("confirm-title"), title);
    const ack = acknowledge ? h("label", { class: "choice confirm-choice dialog-ack" },
      h("input", {
        type: "checkbox", id: "confirm-ack", dataset: { focus: "confirm-ack" },
        on: { change: () => { if (!confirmState?.busy) $("confirm-ok").disabled = !$("confirm-ack").checked; } }
      }),
      h("span", { class: "choice-body" }, h("strong", { text: acknowledge }))) : null;
    fill($("confirm-body"), ...body, ack);
    setDialogError("confirm", "");
    text($("confirm-status"), "");
    text($("confirm-ok"), confirmLabel);
    text($("confirm-cancel"), cancelLabel);
    $("confirm-ok").classList.toggle("danger", danger);
    $("confirm-ok").classList.toggle("primary", !danger);
    $("confirm-ok").disabled = Boolean(acknowledge);
    $("confirm-cancel").disabled = false;
    dialog.showModal();
    $("confirm-cancel").focus();
  }

  async function runConfirm() {
    const current = confirmState;
    if (!current || current.busy) return;
    if (current.acknowledge && !$("confirm-ack")?.checked) return;
    current.busy = true;
    $("confirm-ok").disabled = true;
    $("confirm-cancel").disabled = true;
    if ($("confirm-ack")) $("confirm-ack").disabled = true;
    setDialogError("confirm", "");
    text($("confirm-status"), "處理中，請稍候…");
    try {
      await current.action();
      current.done = true;
      $("confirm-dialog").close();
    } catch (error) {
      setDialogError("confirm", error?.message ? error : "操作失敗，請重試。");
      text($("confirm-status"), "操作未完成；不會自動重試。");
    } finally {
      current.busy = false;
      if (!current.done) {
        $("confirm-ok").disabled = current.acknowledge && !$("confirm-ack")?.checked;
        $("confirm-cancel").disabled = false;
        if ($("confirm-ack")) $("confirm-ack").disabled = false;
      }
    }
  }

  function keyDialog({ title, description, allowSave, confirmLabel = "繼續", action }) {
    const dialog = $("key-dialog");
    if (dialog.open) return;
    keyDialogState = { action, busy: false, trigger: document.activeElement };
    text($("key-dialog-title"), title);
    text($("key-dialog-description"), description);
    $("key-dialog-text").value = "";
    $("key-dialog-file").value = "";
    $("key-dialog-save").checked = false;
    $("key-dialog-save-wrap").hidden = !allowSave;
    setDialogError("key-dialog", "");
    text($("key-dialog-status"), "");
    text($("key-dialog-ok"), confirmLabel);
    ["key-dialog-ok", "key-dialog-cancel", "key-dialog-text", "key-dialog-file-button", "key-dialog-save"].forEach(id => { $(id).disabled = false; });
    dialog.showModal();
    $("key-dialog-text").focus();
  }

  async function runKeyDialog() {
    const current = keyDialogState;
    if (!current || current.busy) return;
    const parsed = extractSecret($("key-dialog-text").value);
    if (parsed.error) {
      setDialogError("key-dialog", parsed.error);
      $("key-dialog-text").focus();
      return;
    }
    current.busy = true;
    const controls = ["key-dialog-ok", "key-dialog-cancel", "key-dialog-text", "key-dialog-file-button", "key-dialog-save"];
    controls.forEach(id => { $(id).disabled = true; });
    setDialogError("key-dialog", "");
    text($("key-dialog-status"), "正在驗證金鑰…");
    try {
      await current.action({ key: parsed.key, save: !$("key-dialog-save-wrap").hidden && $("key-dialog-save").checked });
      current.done = true;
      $("key-dialog-text").value = "";
      $("key-dialog").close();
    } catch (error) {
      setDialogError("key-dialog", error.message || "無法使用這把金鑰，請確認後重試。");
      text($("key-dialog-status"), "");
    } finally {
      current.busy = false;
      if (!current.done) {
        controls.forEach(id => { $(id).disabled = false; });
        $("key-dialog-text").focus();
      }
    }
  }

  // ------------------------------------------------------------------ permission & lifecycle

  function permissionChanged() {
    if (state.permission?.allowed === true && state.accessDenied) {
      state.accessDenied = false;
      state.pageError = null;
      render();
      loadStatus().then(() => ensureData(currentRoute(), true));
    }
  }

  function poll() {
    if (!visible() || state.accessDenied || state.disconnected || state.helperMissing || state.pageError) return;
    if ($("confirm-dialog").open || $("key-dialog").open) return;
    if (Date.now() - Math.max(state.statusAt, state.statusTried) >= STATUS_POLL_MS) {
      loadStatus({ quiet: true });
      const route = currentRoute();
      if (["overview", "backups"].includes(route.page)) loadBackups();
    }
  }

  function wireStaticControls() {
    // Review F5: track IME composition so a background refresh never rebuilds the field being composed in.
    document.addEventListener("compositionstart", () => { state.composing = true; }, true);
    document.addEventListener("compositionend", () => {
      state.composing = false;
      setTimeout(() => { if (state.viewStale && !editingInView()) render(); }, 0);
    }, true);
    $("view").addEventListener("focusout", () => {
      setTimeout(() => { if (state.viewStale && !state.composing && !editingInView()) render(); }, 0);
    });
    $("refresh").addEventListener("click", () => {
      state.pageError = null;
      loadStatus().then(() => ensureData(currentRoute(), true));
    });
    $("retry").addEventListener("click", () => {
      if (state.disconnected) {
        window.location.reload();
        return;
      }
      state.pageError = null;
      state.helperMissing = false;
      render();
      loadStatus().then(() => ensureData(currentRoute(), true));
    });
    $("confirm-ok").addEventListener("click", runConfirm);
    $("confirm-cancel").addEventListener("click", () => { if (!confirmState?.busy) $("confirm-dialog").close(); });
    $("key-dialog-ok").addEventListener("click", runKeyDialog);
    $("key-dialog-cancel").addEventListener("click", () => { if (!keyDialogState?.busy) $("key-dialog").close(); });
    $("key-dialog-text").addEventListener("keydown", event => {
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) runKeyDialog();
    });
    $("key-dialog-file-button").addEventListener("click", () => $("key-dialog-file").click());
    $("key-dialog-file").addEventListener("change", async event => {
      const parsed = await readKeyFile(event.target.files?.[0] || null);
      event.target.value = "";
      if (parsed.error) setDialogError("key-dialog", parsed.error);
      else {
        $("key-dialog-text").value = parsed.key;
        setDialogError("key-dialog", "");
      }
    });
    for (const [id, getState] of [["confirm-dialog", () => confirmState], ["key-dialog", () => keyDialogState]]) {
      $(id).addEventListener("cancel", event => { if (getState()?.busy) event.preventDefault(); });
      $(id).addEventListener("close", () => {
        const current = getState();
        if (id === "key-dialog") {
          $("key-dialog-text").value = "";
          keyDialogState = null;
        } else confirmState = null;
        const trigger = current?.trigger;
        if (trigger?.isConnected && !trigger.disabled) trigger.focus({ preventScroll: true });
        else if (trigger?.dataset?.focus) document.querySelector(`[data-focus="${CSS.escape(trigger.dataset.focus)}"]`)?.focus({ preventScroll: true });
        else $("view-heading")?.focus({ preventScroll: true });
      });
    }
    // An open download menu closes on a click elsewhere or Escape, and stays inside the viewport when it resizes.
    document.addEventListener("click", event => {
      if (state.menu && !event.target?.closest?.(".menu-group")) closeMenu();
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && state.menu && !document.querySelector("dialog[open]")) closeMenu(true);
    });
    window.addEventListener("resize", restoreMenu);
    window.addEventListener("beforeunload", event => {
      if (activeUpload()) {
        event.preventDefault();
        event.returnValue = "";
      }
    });
  }

  function start() {
    if (!cockpit?.spawn || !cockpit?.channel || !cockpit?.location || !cockpit?.transport) {
      text($("page-error-message"), "無法載入 Cockpit 連線元件，請從 Cockpit 的「備份與還原」選單開啟此頁。");
      $("page-error").hidden = false;
      $("retry").hidden = true;
      fill($("view"));
      $("view").setAttribute("aria-busy", "false");
      return;
    }
    wireStaticControls();
    try {
      state.permission = cockpit.permission({ admin: true });
      state.permission.addEventListener("changed", permissionChanged);
    } catch {
      // spawn still reports access-denied; the page then shows the admin-required state.
    }
    try {
      cockpit.user?.().then(user => { state.user = isObject(user) ? user : null; renderBanners(); }, () => {});
    } catch { /* optional */ }
    cockpit.addEventListener("locationchanged", onRouteChange);
    cockpit.addEventListener("visibilitychange", poll);
    document.addEventListener("visibilitychange", poll);
    const timer = setInterval(poll, 5000);
    window.addEventListener("pagehide", () => {
      clearInterval(timer);
      stopWatch();
      state.permission?.removeEventListener?.("changed", permissionChanged);
      state.permission?.close?.();
    });
    const route = currentRoute();
    state.lastPage = `${route.page}/${route.arg || ""}`;
    render();
    loadStatus().then(() => ensureData(currentRoute()));
  }

  start();
})();
