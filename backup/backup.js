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
 * Icons: Material Design Icons path data (Pictogrammers, Apache-2.0), built with DOM APIs.
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
    document.documentElement.classList.toggle('pf-v6-theme-dark',
      preference === 'dark' || (preference === 'auto' && system.matches));
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
  const READS = new Set(["status", "list", "jobs", "job-status", "inspect", "key-kit", "download-info"]);
  const TIMEOUTS = {
    inspect: 300000, "upload-begin": 120000, "upload-finish": 900000, "upload-abort": 120000, "key-import": 120000,
    "backup-start": 120000, "restore-start": 120000, "verify-start": 120000, "key-init": 120000, delete: 120000
  };
  // upload-finish hashes the whole file before it answers: allow 20 MB/s plus two minutes, at least 15 minutes.
  const finishTimeout = size => Math.max(TIMEOUTS["upload-finish"], 120000 + Math.ceil((Number(size) || 0) / (20 * 1000 * 1000)) * 1000);
  const UPLOADING = new Set(["begin", "sending", "finishing"]);
  // An upload whose check timed out is still on the device, and the device keeps checking it (review finding HD-08):
  // it stays the active upload, so another restore never replaces it and leaving the page asks first.
  const UPLOAD_PENDING = new Set([...UPLOADING, "unconfirmed"]);
  const WRONG_KEY = "這把金鑰無法解開這份備份（金鑰 ID 不符）。請確認是建立這份備份的設備所產生的緊急金鑰。";
  const VERIFY_FAILED = "這份備份上次驗證未通過。還原時會先完整驗證整份備份，驗證不通過就不會變更任何資料，但這份備份很可能無法使用。";
  const ROUTES = new Set(["overview", "backups", "create", "restore", "jobs", "keys", "activity"]);
  const NAV_FOR = { overview: "overview", backups: "backups", create: "overview", restore: "restore", jobs: "activity", keys: "keys", activity: "activity" };

  const TYPE_LABELS = { manual: "手動", safety: "還原前備份", uploaded: "上傳" };
  const JOB_TYPES = { backup: "備份", restore: "還原", verify: "驗證" };
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

  // ------------------------------------------------------------------ state

  const state = {
    status: null, statusAt: 0, statusTried: 0, statusError: null, backups: null, backupsAt: 0, jobs: null, jobsAt: 0,
    loading: new Set(), accessDenied: false, helperMissing: false, disconnected: false,
    permission: null, permissionRetry: false, user: null, pageError: null, actionError: null,
    jobCache: new Map(), watch: { id: null, timer: null, busy: false, failures: 0 },
    wizard: null, detail: null, busy: new Set(), initialRouteHandled: false, lastPage: null,
    create: { selected: null, includeImages: false, note: "", requestId: null, signature: "", busy: false, error: null },
    keys: { kit: null, busy: false, error: null, confirmChecked: false, importText: "", importBusy: false, importError: null, imported: null },
    list: { query: "", type: "all" },
    verifyRequest: null, openDetails: new Set(), composing: false, viewStale: false, pendingWizard: null,
    jobUi: { id: null, root: null, nodes: null, cancelBusy: false, cancelError: null }
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
    if (["overview", "backups"].includes(route.page) && (!state.backups || stale(state.backupsAt, 10000))) loadBackups();
    if (route.page === "jobs" && route.arg && JOB_ID_RE.test(route.arg) && !state.backups) loadBackups();
    if (route.page === "activity" && (!state.jobs || stale(state.jobsAt, 5000))) loadJobs();
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
    const label = `${JOB_TYPES[job.type]}作業${JOB_STATES[job.state] || job.state}`;
    announce(`${label}。`);
    loadStatus({ quiet: true });
    if (job.type !== "verify" || state.backups) loadBackups();
    if (state.jobs) loadJobs();
  }

  function jobChanged(id) {
    renderBanners();
    const route = currentRoute();
    if (route.page === "jobs" && route.arg === id && state.jobUi.id === id) {
      const job = state.jobCache.get(id)?.job;
      const label = job && ACTIVE.has(job.state) ? job.phases.find(item => item.id === job.phase)?.label : null;
      if (label && state.jobUi.announced !== `${job.state}:${label}`) {
        state.jobUi.announced = `${job.state}:${label}`;
        announce(`${JOB_TYPES[job.type]}作業：${label}`);
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

  const EDITABLE = 'input:not([type]), input[type="text"], input[type="search"], textarea';

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
      const message = key
        ? "尚未確認已保存緊急金鑰。沒有緊急金鑰，就無法在其他設備或重新安裝後還原備份。"
        : "尚未建立加密金鑰。建立第一份備份前，請先建立金鑰並保存緊急金鑰。";
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
        h("p", null, h("strong", { text: `${JOB_TYPES[job.type]}作業進行中` }), ` · ${phase || JOB_STATES[job.state]} · ${percent}%`),
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

  function verifiedText(backup) {
    if (!isObject(backup.verified)) return "尚未驗證";
    return backup.verified.ok ? `已驗證 · ${date(backup.verified.at)}` : `驗證未通過 · ${date(backup.verified.at)}`;
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
    const stats = h("div", { class: "grid stats" },
      h("section", { class: "card stat", "aria-label": "本機儲存空間" }, tile("harddisk"),
        h("div", { class: "stat-main" }, h("p", { class: "stat-label", text: "本機儲存空間" }),
          h("p", { class: "stat-value", text: `${bytes(storage.free_bytes)} 可用` }),
          h("p", { class: "secondary", text: `共 ${bytes(storage.total_bytes)} · 備份 ${Number(storage.backup_count) || 0} 份，佔用 ${bytes(storage.backups_bytes)}` }),
          meter, storage.path ? h("p", { class: "secondary mono", text: storage.path }) : null)),
      h("section", { class: "card stat", "aria-label": "加密金鑰" }, tile("key-outline"),
        h("div", { class: "stat-main" }, h("p", { class: "stat-label", text: "加密金鑰" }),
          h("p", { class: "stat-value", text: key ? (key.kit_confirmed ? "已保存緊急金鑰" : "待確認保存") : "尚未建立" }),
          h("p", { class: "secondary", text: key ? `金鑰 ID ${str(key.key_id)}` : "建立備份前需要先設定" }),
          link(key ? "管理金鑰" : "設定加密金鑰", ["keys"], { class: "text-link", dataset: { focus: "stat-keys" } }))),
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
          h("div", { class: "item-side" }, typeChip(backup.type), keyChip(backup)))))
        : h("section", { class: "card" }, emptyState("database-outline", "還沒有備份", "建立第一份備份後，會顯示在這裡。", apps.length ? [
          link("建立備份", ["create"], { class: "button primary", dataset: { focus: "overview-first-backup" } })] : [])));

    const host = status.host;
    const hostLine = h("p", { class: "host-line muted" }, icon("server-network"),
      h("span", { text: [host.hostname && `設備 ${host.hostname}`, host.os, host.arch, host.podman && `Podman ${host.podman}`,
        status.version && `備份元件 ${status.version}`].filter(Boolean).map(str).join(" · ") }));
    return [head, stats, appSection, backupSection, hostLine];
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
      link([icon("tray-arrow-up"), h("span", { text: "上傳備份檔" })], ["restore"], { class: "button", dataset: { focus: "list-upload" } }),
      link([icon("plus"), h("span", { text: "建立備份" })], ["create"], { class: "button primary", dataset: { focus: "list-create" } })]);
    if (!state.backups) return [head, pendingCard("backups", "正在載入備份清單…")];
    if (!state.backups.length) {
      return [head, h("section", { class: "card" }, emptyState("database-outline", "還沒有備份",
        "建立第一份備份，或上傳從其他設備下載的 .woowbackup 備份檔。", [
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
      h("thead", null, h("tr", null, ["備份", "類型", "應用", "大小", "金鑰與驗證", "操作"].map(label => h("th", { scope: "col", text: label })))),
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
        backup.include_images ? h("span", { class: "secondary", text: "含容器映像" }) : null),
      h("td", { "data-label": "金鑰與驗證" }, keyChip(backup), h("span", { class: "secondary", text: verifiedText(backup) })),
      h("td", { "data-label": "操作" }, backupActions(backup, true)));
  }

  function backupActions(backup, compact) {
    const active = activeJob();
    const inUse = active && active.params?.backup_id === backup.id;
    const title = backupTitle(backup);
    const downloading = state.busy.has(`download:${backup.id}`);
    return h("div", { class: compact ? "row-actions" : "button-group" },
      button(downloading ? "準備下載…" : "下載", () => downloadBackup(backup), {
        small: compact, icon: "tray-arrow-down", disabled: downloading, label: `下載 ${title}`, focus: `download-${backup.id}`
      }),
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

  // ------------------------------------------------------------------ backup detail

  function viewDetail(id) {
    const back = backLink("返回備份列表", ["backups"]);
    if (!BACKUP_ID_RE.test(id)) return [back, viewTitle("備份詳情"), notFound("找不到這份備份", "網址中的備份 ID 格式不正確。")];
    if (!state.backups) return [back, viewTitle("備份詳情"), pendingCard("backups", "正在載入備份資料…")];
    const backup = state.backups.find(item => item.id === id);
    if (!backup) return [back, viewTitle("備份詳情"), notFound("找不到這份備份", "它可能已被刪除，或不是這台設備上的備份。")];
    const head = viewTitle(backupTitle(backup), backup.note || "沒有備註。");
    const info = h("section", { class: "card", "aria-labelledby": "detail-info" },
      h("div", { class: "card-head" }, h("h3", { id: "detail-info", text: "備份資訊" }), typeChip(backup.type)),
      h("div", { class: "card-body" }, metadata([
        ["備份 ID", backup.id, "mono"],
        ["類型", TYPE_LABELS[backup.type] || backup.type],
        ["建立時間", date(backup.created)],
        backup.uploaded_at ? ["上傳時間", date(backup.uploaded_at)] : null,
        ["來源設備", backup.source?.hostname || "—"],
        ["大小", bytes(backup.size)],
        ["容器映像", backup.include_images ? "已包含" : "未包含（還原時需已有或可下載相同映像）"],
        ["下載檔名", backup.filename || "—", "mono"],
        ["SHA-256", backup.sha256 || "—", "mono"],
        ["金鑰", h("span", null, keyChip(backup), " ", h("span", { class: "mono", text: str(backup.key_id) }))],
        ["驗證", verifiedText(backup)]
      ]), h("div", { class: "card-actions" }, backupActions(backup, false))));
    const apps = h("section", { class: "card", "aria-labelledby": "detail-apps" },
      h("div", { class: "card-head" }, h("h3", { id: "detail-apps", text: "包含的應用" })),
      list(backup.apps).length
        ? h("ul", { class: "item-list" }, list(backup.apps).map(app => h("li", { class: "item-row" }, tile("package-variant-closed", true),
          h("div", { class: "item-main" }, h("strong", { class: "item-title", text: str(app?.name || app?.id) }), h("span", { class: "secondary mono", text: str(app?.id) })))))
        : h("div", { class: "card-body" }, h("p", { class: "muted", text: backup.inspected === false
          ? "這份上傳的備份尚未檢查內容。檢視內容或開始還原時，會先解密並讀取它包含的應用。"
          : "沒有應用資料。" })));
    return [back, head, h("div", { class: "detail-grid" }, info, h("div", { class: "stack" }, apps, contentCard(backup)))];
  }

  function contentCard(backup) {
    const detail = state.detail?.id === backup.id ? state.detail : null;
    const body = [];
    if (detail?.busy) body.push(h("p", { class: "muted", role: "status", text: "正在解密並讀取備份內容…" }));
    else if (detail?.data) body.push(...manifestSummary(detail.data.manifest));
    else {
      body.push(h("p", { class: "muted", text: backup.key_available
        ? "解密備份的目錄資訊，查看應用、資料庫、資料卷與映像。這不會變更任何資料。"
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
      ["備註", str(manifest.note) || "—"]
    ]);
    const apps = list(manifest.apps).filter(isObject).map(app => h("article", { class: "app-content" },
      h("h4", { text: `${str(app.name || app.id)}` }), appContents(app)));
    return [general, ...apps];
  }

  function appContents(app) {
    const owner = isObject(app.owner) ? app.owner : {};
    const images = list(app.images).filter(isObject);
    const databases = list(app.postgres).filter(isObject);
    const volumes = list(app.volumes).filter(isObject);
    return metadata([
      ["應用 ID", str(app.id), "mono"],
      ["擁有者", owner.name ? `${str(owner.name)}（UID ${str(owner.uid)}）` : "—"],
      ["資料庫", databases.length ? databases.map(db => `PostgreSQL ${str(db.major)} · ${str(db.database)}`).join("、") : "無"],
      ["資料卷", volumes.length ? volumes.map(volume => str(volume.name)).join("、") : "無"],
      ["容器映像", images.length ? images.map(image => `${str(image.ref)}（${image.included ? "已包含" : "未包含"}）`).join("、") : "無"],
      ["應用機密與設定", `${Number(app.secrets_count) || 0} 個應用機密 · ${Number(app.config_files_count) || 0} 個設定檔`]
    ]);
  }

  // ------------------------------------------------------------------ create backup

  const selectable = app => app.deployed === true && !["not-deployed", "error"].includes(app.state);

  function viewCreate() {
    const head = viewTitle("建立備份", "選擇要備份的應用。備份會加密後保存在這台設備，完成後可下載成單一檔案。");
    const back = backLink("返回總覽", ["overview"]);
    const status = state.status;
    if (!status) return [back, head, state.statusError ? errorNotice(state.statusError, { retry: () => loadStatus() }) : loadingCard("正在載入應用…")];
    const apps = status.apps;
    if (!apps.length) return [back, head, emptyCatalog()];
    const create = state.create;
    if (create.selected === null) create.selected = new Set(apps.filter(selectable).map(app => app.id));
    for (const id of [...create.selected]) if (!apps.some(app => app.id === id && selectable(app))) create.selected.delete(id);
    const active = activeJob();
    const blockers = [];
    if (!status.key) {
      blockers.push(infoNotice("尚未建立加密金鑰。所有備份都會用這台設備的金鑰加密，請先完成金鑰設定。", "warn", "key-outline",
        link("設定加密金鑰", ["keys"], { class: "button small", dataset: { focus: "create-keys" } })));
    }
    if (active) {
      blockers.push(infoNotice(`目前有${JOB_TYPES[active.type]}作業正在進行，需等它完成後才能建立新的備份。`, "info", "progress-clock",
        link("查看進度", ["jobs", active.id], { class: "button small", dataset: { focus: "create-active-job" } })));
    }
    const noteInvalid = CONTROL_RE.test(create.note);
    const canSubmit = !create.busy && create.selected.size > 0 && Boolean(status.key) && !active && !noteInvalid;
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
      h("div", { class: "form-section" }, h("h3", { text: "備份期間" }),
        h("p", { class: "muted", text: "為了取得一致的資料，備份時會暫停應用的寫入服務（資料庫保持運作以便匯出），匯出完成後立即自動恢復。暫停時間通常為數秒到數分鐘，取決於資料量。" })),
      ...blockers,
      create.error ? errorNotice(create.error) : null,
      h("div", { class: "form-footer button-group" },
        link("取消", ["overview"], { class: "button", dataset: { focus: "create-cancel" } }),
        h("button", { type: "submit", class: "btn primary", disabled: !canSubmit, dataset: { focus: "create-submit" } },
          icon("database-outline"), h("span", { text: create.busy ? "正在開始…" : "開始備份" })))),
    h("aside", { class: "card side-card", "aria-labelledby": "create-side" },
      h("h3", { id: "create-side", text: "這份備份包含什麼？" }),
      h("ul", { class: "bullet-list" },
        ["PostgreSQL 資料庫（以 pg_dump 匯出，還原前會檢查）", "應用的資料卷", "應用機密（Podman secrets）與設定檔", "Quadlet 服務定義",
          "容器映像（僅在勾選時）"].map(item => h("li", { text: item }))),
      h("p", { class: "muted", text: status.key ? `使用這台設備的金鑰（${str(status.key.key_id)}）加密，完成後會完整驗證才列出。` : "使用這台設備的金鑰加密，完成後會完整驗證才列出。" }),
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
    if (submit && state.status) {
      submit.disabled = state.create.busy || state.create.selected?.size === 0 || !state.status.key || Boolean(activeJob()) || CONTROL_RE.test(note);
    }
  }

  async function startBackup() {
    const create = state.create;
    const status = state.status;
    if (create.busy || !status?.key || activeJob() || !create.selected?.size || CONTROL_RE.test(create.note)) return;
    const apps = status.apps.filter(app => create.selected.has(app.id)).map(app => app.id);
    const note = create.note.trim();
    const signature = JSON.stringify([apps, create.includeImages, note]);
    // Retries of the same intent reuse the request id so the helper deduplicates them.
    if (!create.requestId || create.signature !== signature) {
      create.requestId = requestId();
      create.signature = signature;
    }
    create.busy = true;
    create.error = null;
    render();
    try {
      const data = await call("backup-start", { apps, include_images: create.includeImages, note, request_id: create.requestId });
      requireShape(isString(data.job_id) && JOB_ID_RE.test(data.job_id), "作業資訊");
      create.requestId = null;
      create.signature = "";
      create.note = "";
      announce(data.deduplicated ? "這個備份要求先前已送出，正在顯示同一個作業。" : "已開始備份作業。");
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
      allowNoSafety: Boolean(pending?.allowNoSafety), confirmedNoSafety: false, preselect: pending ? list(pending.apps) : null
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
      : "上傳在這台或其他設備下載的 .woowbackup 備份檔，檢查相容性後再還原。");
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
      id: "restore-file", accept: ".woowbackup", label: "選擇檔案：備份檔（.woowbackup）", fileName: file?.name, disabled: wizard.busy,
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
    h("p", { class: "dropzone-label", text: "把備份檔（.woowbackup）拖放到這裡，或選擇檔案" }),
    picker,
    h("p", { id: "restore-file-hint", class: "hint", text: "檔案會先上傳到這台設備的私有暫存區；上傳本身不會變更任何應用。" }));
    const nameWarning = file && !/\.woowbackup$/i.test(file.name)
      ? infoNotice("檔名不是 .woowbackup。仍可上傳，系統會檢查檔案格式；若不是備份檔會被拒絕。", "warn", "alert-outline") : null;
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
    wizard.fileError = file && !file.size ? "這個檔案是空的，請選擇有效的 .woowbackup 備份檔。" : null;
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
    return cleaned || "backup.woowbackup";
  }

  async function startUpload(wizard) {
    const file = wizard.file;
    if (!file || wizard.busy) return;
    if (!file.size) {
      wizard.fileError = "這個檔案是空的，請選擇有效的 .woowbackup 備份檔。";
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
        inspect: data, backup: data.backup, step: "preflight", confirmed: false, confirmedNoSafety: false, keyText: "",
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
    return [
      h("h3", { class: "step-title", text: "預檢結果" }),
      h("p", { class: "muted", text: "以下檢查不會變更任何資料。選擇要還原的應用；未通過檢查的應用無法選擇。" }),
      wizard.notice ? infoNotice(wizard.notice, "warn", "alert-outline") : null,
      verifiedFailed ? infoNotice(VERIFY_FAILED, "warn", "alert-outline") : null,
      h("div", { class: "preflight-summary" }, metadata([
        ["備份", `${backupTitle(wizard.backup || { type: manifest.type, created: manifest.created })}`],
        ["備份 ID", str(manifest.backup_id), "mono"],
        ["來源設備", [manifest.source?.hostname, manifest.source?.os, manifest.source?.arch].filter(Boolean).map(str).join(" · ") || "—"],
        ["內容大小", bytes(manifest.total_size)],
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
    const canStart = wizard.confirmed && (!noSafety || wizard.confirmedNoSafety) && apps.length > 0 && !wizard.busy && !active;
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
            ? "原位還原：會停止服務，並以備份內容覆寫資料庫、資料卷、應用機密與設定檔。"
            : "全新部署：會在這台設備建立服務、資料卷與資料庫。" })),
        h("div", { class: "item-side" }, chip(MODES[app.mode] || str(app.mode), app.mode === "inplace" ? "warn" : "info"))))),
      h("h4", { class: "subheading", text: "停機時間" }),
      h("p", { text: `還原期間，上列應用會停止服務，直到資料還原、啟動與健康檢查完成。這份備份內容約 ${bytes(manifest.total_size)}；備份當時暫停寫入約 ${duration(downtime)}，還原通常需要更久。` }),
      h("h4", { class: "subheading", text: "還原前備份與自動回復" }),
      safetyText ? h("p", { text: safetyText }) : null,
      fresh.length
        ? h("p", { text: `${names(fresh)} 是全新部署；若還原失敗，系統會移除這次新建立的服務、資料卷與資料庫。` })
        : null,
      warnings.length ? [h("h4", { class: "subheading", text: "注意事項" }), checkList(warnings, "注意事項")] : null,
      verifiedFailed ? infoNotice(VERIFY_FAILED, "warn", "alert-outline") : null,
      wizard.key && !wizard.keySaved ? h("p", { class: "muted", text: "你輸入的緊急金鑰只會交給這次還原作業使用，作業結束後即刪除，不會保存在這台設備。" }) : null,
      active ? infoNotice(`目前有${JOB_TYPES[active.type]}作業正在進行，需等它完成後才能開始還原。`, "info", "progress-clock",
        link("查看進度", ["jobs", active.id], { class: "button small", dataset: { focus: "confirm-active-job" } })) : null,
      noSafety ? h("label", { class: "choice confirm-choice" },
        h("input", {
          type: "checkbox", id: "confirm-no-safety", checked: wizard.confirmedNoSafety, disabled: wizard.busy, dataset: { focus: "confirm-no-safety" },
          on: { change: event => { wizard.confirmedNoSafety = event.target.checked; render(); } }
        }),
        h("span", { class: "choice-body" }, h("strong", { text: "我了解這次還原可能沒有還原前備份，失敗時無法自動回復" }),
          h("small", { text: "只有在應用已無法運作（例如資料庫無法啟動）、又沒有可用的還原前備份時才這樣做。資料庫無法連線時，"
            + "也無法確認執行個體中是否還有其他資料庫；還原會重建整個資料庫資料卷。" }))) : null,
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
    const signature = JSON.stringify([wizard.backupId, apps, Boolean(wizard.key), noSafety]);
    if (!wizard.requestId || wizard.signature !== signature) {
      wizard.requestId = requestId();
      wizard.signature = signature;
    }
    const request = { backup_id: wizard.backupId, apps, request_id: wizard.requestId, confirm: true };
    if (wizard.key) request.key = wizard.key;
    if (noSafety) request.allow_no_safety = true;
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
    text(nodes.title, `${JOB_TYPES[job.type]}作業`);
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
      ["作業類型", JOB_TYPES[job.type]],
      list(params.apps).length ? ["應用", list(params.apps).map(id => appName(str(id))).join("、")] : null,
      backupId ? ["備份", link(backupId, ["backups", backupId], { class: "mono", dataset: { focus: "job-param-backup" } })] : null,
      job.type === "backup" ? ["容器映像", params.include_images ? "包含" : "不包含"] : null,
      job.type === "backup" && params.note ? ["備註", str(params.note)] : null,
      params.key_provided ? ["金鑰", "使用輸入的緊急金鑰（作業結束後即刪除）"] : null,
      params.allow_no_safety ? ["還原前備份", "無法建立時直接還原（你已確認；失敗時無法自動回復）"] : null
    ]);
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
    const body = [];
    const actions = [];
    let title = "作業結束";
    let tone = "neutral";
    let glyph = "information-outline";
    if (job.state === "succeeded") {
      tone = "ok";
      glyph = "check-circle";
      title = { backup: "備份完成", restore: "還原完成", verify: "驗證完成" }[job.type];
    } else if (job.state === "rolled-back") {
      tone = "warn";
      glyph = "backup-restore";
      title = "還原失敗，已自動回復";
    } else if (job.state === "failed") {
      tone = "fail";
      glyph = "close-circle-outline";
      title = `${JOB_TYPES[job.type]}失敗`;
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
      body.push(h("p", { text: "備份已建立，並以這台設備的金鑰完整解密驗證後才列出。" }), metadata([
        ["備份", createdId ? link(createdId, ["backups", createdId], { class: "mono", dataset: { focus: "result-backup" } }) : "—"],
        ["大小", bytes(result.size)],
        ["應用寫入暫停", duration(result.downtime_seconds)],
        ["應用", list(result.apps).map(id => appName(str(id))).join("、") || "—"]
      ]));
      const backup = createdId ? state.backups?.find(item => item.id === createdId) || { id: createdId, type: "manual", created: job.finished } : null;
      if (backup) {
        actions.push(button("下載備份", () => downloadBackup(backup), { primary: true, icon: "tray-arrow-down", focus: "result-download" }),
          link("查看備份", ["backups", createdId], { class: "button", dataset: { focus: "result-open" } }));
      }
    } else if (job.type === "verify" && job.state === "succeeded" && result) {
      body.push(h("p", { text: result.ok
        ? "備份檔已完整解密，每個項目的大小與 SHA-256 都與目錄一致。"
        : "驗證未通過：備份檔內容與目錄不一致，請勿使用這份備份還原。" }), metadata([
        ["項目數", str(result.entries)], ["資料量", bytes(result.bytes)]]));
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
      // What the restore could not keep, e.g. setuid bits or file capabilities in a volume (review finding HD-09).
      const notes = list(result.warnings).filter(isString).slice(0, 50);
      if (notes.length) body.push(h("h4", { class: "subheading", text: "注意事項" }),
        checkList(notes.map((message, index) => ({ id: `warning-${index}`, status: "warn", message })), "還原注意事項"));
      const verification = list(result.verification).filter(isObject);
      if (verification.length) body.push(h("h4", { class: "subheading", text: "資料核對（備份時與還原後）" }), verificationTable(verification));
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

  function verificationTable(entries) {
    const rows = [];
    for (const entry of entries) {
      const before = isObject(entry.before) ? entry.before : {};
      const after = isObject(entry.after) ? entry.after : {};
      const fields = [];
      for (const id of [...new Set([...Object.keys(before), ...Object.keys(after)])]) {
        if (isObject(before[id]) || isObject(after[id])) {
          const left = isObject(before[id]) ? before[id] : {};
          const right = isObject(after[id]) ? after[id] : {};
          for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])]) fields.push([`${id}.${key}`, left[key], right[key]]);
        } else fields.push([id, before[id], after[id]]);
      }
      const verdict = entry.match === true ? chip("資料一致", "ok", "check-circle-outline")
        : entry.match === false ? chip("資料不一致", "fail", "close-circle-outline") : chip("未比對", "neutral");
      fields.forEach(([label, left, right], index) => {
        const same = JSON.stringify(left) === JSON.stringify(right);
        rows.push(h("tr", null,
          h("th", { scope: "row", "data-label": "應用" }, index === 0 ? [h("span", { text: appName(str(entry.app)) }), " ", verdict] : h("span", { class: "muted", text: appName(str(entry.app)) })),
          h("td", { "data-label": "項目", class: "mono", text: label }),
          h("td", { "data-label": "備份時", class: "mono", text: formatValue(left) }),
          h("td", { "data-label": "還原後", class: "mono", text: formatValue(right) }),
          h("td", { "data-label": "比對" }, same ? chip("相同", "ok") : chip("不同", "fail"))));
      });
      if (!fields.length) {
        rows.push(h("tr", null, h("th", { scope: "row", "data-label": "應用" }, h("span", { text: appName(str(entry.app)) }), " ", verdict),
          h("td", { "data-label": "項目", colSpan: 4, text: "沒有可比對的資料。" })));
      }
    }
    return h("table", { class: "data compare" },
      h("caption", { class: "sr-only", text: "備份時與還原後的資料核對" }),
      h("thead", null, h("tr", null, ["應用", "項目", "備份時", "還原後", "比對"].map(label => h("th", { scope: "col", text: label })))),
      h("tbody", null, rows));
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

  function viewKeys() {
    const head = viewTitle("加密金鑰", "所有備份都以這台設備的金鑰加密。請保存緊急金鑰，才能在其他設備或重新安裝後還原。");
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
    return [head, deviceCard, h("div", { class: "grid two" }, importedCard, importCard)];
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
          class: "row-title", dataset: { focus: `job-${job.id}` }, "aria-label": `查看 ${date(job.created)} 的${JOB_TYPES[job.type]}作業`
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
      const prefix = await channelPrefix();
      const query = encodeQuery({
        payload: "fsread1", binary: "raw", path: info.path, superuser: "require", max_read_size: -1,
        external: { "content-disposition": contentDisposition(info.filename), "content-type": "application/octet-stream" }
      });
      startFrameDownload(`${prefix}?${query}`, info.filename);
      announce(`已開始下載 ${info.filename}（${bytes(info.size)}）。若瀏覽器沒有開始下載，請再試一次。`);
    } catch (error) {
      state.actionError = error;
    } finally {
      state.busy.delete(busyKey);
      render();
    }
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

  function confirmDialog({ title, body, confirmLabel = "確認", cancelLabel = "取消", danger = false, action }) {
    const dialog = $("confirm-dialog");
    if (dialog.open) return;
    confirmState = { action, busy: false, trigger: document.activeElement, confirmLabel };
    text($("confirm-title"), title);
    fill($("confirm-body"), ...body);
    setDialogError("confirm", "");
    text($("confirm-status"), "");
    text($("confirm-ok"), confirmLabel);
    text($("confirm-cancel"), cancelLabel);
    $("confirm-ok").classList.toggle("danger", danger);
    $("confirm-ok").classList.toggle("primary", !danger);
    $("confirm-ok").disabled = false;
    $("confirm-cancel").disabled = false;
    dialog.showModal();
    $("confirm-cancel").focus();
  }

  async function runConfirm() {
    const current = confirmState;
    if (!current || current.busy) return;
    current.busy = true;
    $("confirm-ok").disabled = true;
    $("confirm-cancel").disabled = true;
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
        $("confirm-ok").disabled = false;
        $("confirm-cancel").disabled = false;
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
