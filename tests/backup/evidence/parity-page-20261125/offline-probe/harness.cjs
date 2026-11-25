// Offline probe of the page lane with jsdom (NOT the acceptance run: no layout, no real browser). It loads backup/index.html, the fixture engine of
// tests/backup-ui.mjs (its top-level builders and installCockpitFixture, taken from the test file's text) and backup/backup.js, and lets a scenario click.
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { JSDOM } = require('/home/woowtechopenclaw/Woow_cloudflare_tunnel_webgui/frontend/node_modules/jsdom');
const REPO = process.env.PAGE_REPO || '/tmp/parity-page-20261125';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function loadBuilders() {
  const src = fs.readFileSync(path.join(REPO, 'tests/backup-ui.mjs'), 'utf8');
  const cut = src.indexOf('\ntry {\n');
  let prefix = src.slice(0, cut).replace(/^import .*$/mg, '').replace(/import\.meta\.url/g, "'file:///x/tests/backup-ui.mjs'");
  prefix = prefix.replace(/^const server = createServer\([\s\S]*?\n\}\);\n/m, 'const server = {};\n');
  const exportsList = ['fixture', 'haFixture', 'v2Fixture', 'v2Check', 'v2Issue', 'v2ChainRecord', 'haScripts', 'haCheck', 'installCockpitFixture', 'HA_V2', 'HA_ID', 'HA_PLAIN', 'HA_KEY',
    'V2_PAUSES', 'V2_N8N_KEY', 'V2_ODOO_MODULES', 'B_V2', 'B_V2_SAFETY', 'keyOf', 'haMeta', 'v2Meta', 'convertedMeta', 'haInspect', 'phasesAt', 'haImportView', 'B_HA', 'KEY_ID', 'J_HA_RUN'];
  const body = `${prefix}\n;({ ${exportsList.join(', ')} })`;
  const context = vm.createContext({ assert: require('node:assert/strict'), createHash: require('node:crypto').createHash, mkdir() {}, readFile() {}, createServer: () => ({}),
    dirname: path.dirname, extname: path.extname, join: path.join, resolve: path.resolve, sep: path.sep, fileURLToPath: require('node:url').fileURLToPath,
    test: async () => {}, chromium: {}, process, console, Buffer, URL, structuredClone, setTimeout, clearTimeout, Date, Math, JSON, Object, Array, Set, Map, Promise, Error, RegExp, String, Number, Symbol });
  return vm.runInContext(body, context, { filename: 'backup-ui-prefix.js' });
}

async function open(builders, data, { poll = 80, hash = '#/backups', timeoutScale = 1, timeouts = false } = {}) {
  let page = fs.readFileSync(path.join(REPO, 'backup/index.html'), 'utf8').replace(/<script[^>]*><\/script>/g, '').replace(/<link[^>]*>/g, '');
  const errors = [];
  const dom = new JSDOM(page, { url: `http://localhost/cockpit/woowtechbackup/index.html${hash}`, runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window;
  w.addEventListener('error', event => errors.push(`error: ${event.message}`));
  w.addEventListener('unhandledrejection', event => errors.push(`rejection: ${event.reason && event.reason.stack || event.reason}`));
  // what jsdom lacks
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.CSS = { escape: text => String(text).replace(/["\\]/g, '\\$&') };
  w.structuredClone = value => JSON.parse(JSON.stringify(value));
  w.scrollTo = () => {};
  w.Element.prototype.scrollIntoView = () => {};
  w.HTMLDialogElement.prototype.showModal = function showModal() { this.setAttribute('open', ''); };
  w.HTMLDialogElement.prototype.close = function close() { this.removeAttribute('open'); this.dispatchEvent(new w.Event('close')); };
  Object.defineProperty(w.HTMLDialogElement.prototype, 'open', { get() { return this.hasAttribute('open'); }, set(value) { value ? this.setAttribute('open', '') : this.removeAttribute('open'); } });
  if (!w.crypto || !w.crypto.randomUUID) w.crypto = { randomUUID: () => require('node:crypto').randomUUID(), getRandomValues: array => require('node:crypto').randomFillSync(array) };
  w.__fixture = JSON.parse(JSON.stringify({ csrf: 'probe', ...data }));
  w.eval(`(${builders.installCockpitFixture.toString()})();`);
  const js = fs.readFileSync(path.join(REPO, 'backup/backup.js'), 'utf8').replace('const JOB_POLL_MS = 1500;', `const JOB_POLL_MS = ${poll};`)
    .replace('const HA_START_PAUSE_MS = 3000;', 'const HA_START_PAUSE_MS = 30;').replace('"ha-import-start": 120000', `"ha-import-start": ${timeouts ? 400 : 120000}`);
  w.eval(js);
  const document = w.document;
  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const api = {
    w, document, errors, $, $$, sleep,
    text: selector => ($(selector) ? $(selector).textContent : null),
    click: element => { if (typeof element === 'string') element = $(element); if (!element) throw new Error('no element to click'); if (element.disabled) throw new Error(`click on a disabled element ${element.outerHTML.slice(0, 80)}`); element.click(); },
    tick: (element, value = true) => { if (typeof element === 'string') element = $(element); if (element.disabled) throw new Error('tick on a disabled element'); element.checked = value; element.dispatchEvent(new w.Event('change', { bubbles: true })); },
    fill: (element, value) => { if (typeof element === 'string') element = $(element); element.value = value; element.dispatchEvent(new w.Event('input', { bubbles: true })); },
    until: async (condition, what, ms = 20000) => {
      const started = Date.now();
      for (;;) {
        let ok = false;
        try { ok = condition(); } catch { ok = false; }
        if (ok) return;
        if (Date.now() - started > ms * timeoutScale) throw new Error(`timeout waiting for ${what}\n--- view ---\n${$('#view') ? $('#view').textContent.slice(0, 1500) : 'no view'}\nerrors: ${errors.join(' | ')}`);
        await sleep(30);
      }
    },
    calls: command => w.testcalls.filter(call => call.argv[1] === command).map(call => (call.stdin ? JSON.parse(call.stdin) : {})),
    fixtureErrors: () => JSON.parse(JSON.stringify(w.fixtureErrors)),
    close: () => w.close(),
  };
  await api.until(() => $('#view-heading'), 'the page to start');
  return api;
}

module.exports = { loadBuilders, open, sleep };
