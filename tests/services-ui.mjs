import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chromium } from 'playwright-core';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const helper = '/usr/local/libexec/woowtech-cockpit-services';
const scopes = [
  { id: 'system', label: '本機系統', owner: 'root', uid: 0 },
  { id: 'user:alice', label: 'Alice 的服務', owner: 'alice', uid: 1042 },
  { id: 'user:bob', label: 'Bob 的服務', owner: 'bob', uid: 2087 },
];
const hostileLog = '2026-11-12 service output\n<img src="/xss-probe" onerror="window.__xss=true">\n' +
  '<svg onload="window.__xss=true"></svg><script>window.__xss=true</script> & literal text';

function fixture(overrides = {}) {
  const unit = (name, extra = {}) => ({
    id: `${name}.service`, name, description: `Fixture ${name}`, active: 'active', sub: 'running',
    enabled: 'enabled', kind: 'local', can_start: true, can_stop: true, protected: false, containers: [], ...extra,
  });
  const services = [
    unit('n8n', { description: 'Stopped workflow Quadlet', active: 'inactive', sub: 'dead',
      enabled: 'generated', kind: 'quadlet' }),
    unit('cockpit', { kind: 'system', protected: true, can_start: false, can_stop: false }),
    ...Array.from({ length: 43 }, (_, i) => unit(`worker-${String(i).padStart(3, '0')}`)),
  ];
  const containers = [
    { id: 'a'.repeat(64), name: 'worker-container', image: 'registry.example.test/fixture/worker:1',
      state: 'running', status: 'Up 2 hours', ports: '127.0.0.1:8080 → 80/tcp', unit: 'worker-000.service' },
    { id: 'b'.repeat(64), name: 'standalone', image: 'registry.example.test/fixture/tools:1',
      state: 'exited', status: 'Exited (0)', ports: '', unit: null },
  ];
  services[2].containers = ['worker-container'];
  return {
    allowed: true, scopes, default_scope: 'user:alice', logs: hostileLog, failures: [],
    inventories: Object.fromEntries(scopes.map(scope => [scope.id, {
      scope: scope.id, owner: scope.owner, services: structuredClone(services), containers: structuredClone(containers),
      warnings: [], captured_at: '2026-11-12T02:00:00Z',
    }])), ...overrides,
  };
}

// Served in place of base1/cockpit.js. Each browser context injects its own data;
// this transport records argv and simulates stdout, never launching a process.
function installCockpitFixture() {
  const data = window.__fixture;
  const permission = Object.assign(new EventTarget(), { allowed: data.allowed, close() {} });
  window.testcalls = [];
  window.testjumps = [];
  window.fixtureErrors = [];
  data.hold = [];
  data.waiting = [];
  data.setAllowed = allowed => {
    permission.allowed = allowed;
    permission.dispatchEvent(new Event('changed'));
  };
  data.release = command => {
    data.hold = data.hold.filter(value => value !== command);
    const waiting = data.waiting.filter(item => item.command === command);
    data.waiting = data.waiting.filter(item => item.command !== command);
    waiting.forEach(item => item.resolve());
  };
  const cockpit = Object.assign(new EventTarget(), {
    hidden: false,
    permission: () => permission,
    jump: target => window.testjumps.push(target),
    spawn(argv, options) {
      window.testcalls.push({ argv: [...argv], options: { ...options } });
      const [, command, scope, id, verb] = argv;
      let stream = () => {};
      let closed = false;
      const process = new Promise((resolve, reject) => {
        setTimeout(async () => {
          const emit = payload => {
            const output = JSON.stringify(payload);
            const middle = Math.floor(output.length / 2);
            stream(output.slice(0, middle));
            stream(output.slice(middle));
          };
          try {
            if (data.hold.includes(command)) await new Promise(resolve => data.waiting.push({ command, resolve }));
            if (closed) return;
            if (!permission.allowed) {
              throw Object.assign(new Error('Administrative access denied'), { problem: 'access-denied' });
            }
            const failed = data.failures.findIndex(item => item.command === command);
            if (failed >= 0) {
              const failure = data.failures.splice(failed, 1)[0];
              if (failure.problem) throw Object.assign(new Error(failure.message), { problem: failure.problem });
              emit({ error: failure.message });
              throw Object.assign(new Error('Process exited with code 1'), { exit_status: 1 });
            }
            let result;
            const inventory = data.inventories[scope];
            const unit = inventory?.services.find(item => item.id === id);
            if (command === 'scopes') result = { scopes: data.scopes, default_scope: data.default_scope };
            else if (command === 'inventory' && inventory) result = inventory;
            else if (command === 'details' && unit) result = {
              unit: { id, description: unit.description, active: unit.active, sub: unit.sub, enabled: unit.enabled,
                can_start: unit.can_start, can_stop: unit.can_stop,
                metrics: { MainPID: '321', MemoryCurrent: '67108864', CPUUsageNSec: '1250000000', TasksCurrent: '18446744073709551615',
                  Requires: 'postgres.service <b>literal</b>', Restart: 'always' }, result: 'success',
                source: unit.kind === 'quadlet' ? `/home/${inventory.owner}/.config/containers/systemd/n8n.container` : '',
                fragment: `/run/user/${data.scopes.find(item => item.id === scope).uid}/systemd/generator/${id}` },
              logs: data.logs,
            };
            else if (command === 'logs' && unit) result = { logs: data.logs };
            else if (command === 'action' && unit && ['start', 'stop', 'restart'].includes(verb) && !unit.protected) {
              unit.active = verb === 'stop' ? 'inactive' : 'active';
              unit.sub = verb === 'stop' ? 'dead' : 'running';
              result = { ok: true, unit: id, action: verb, active: unit.active, sub: unit.sub };
            } else {
              window.fixtureErrors.push(`Unexpected helper call: ${JSON.stringify(argv)}`);
              throw new Error('Unexpected fixture command');
            }
            emit(result);
            resolve(''); // Streamed bytes are consumed, including when the process rejects.
          } catch (error) { reject(error); }
        }, 0);
      });
      process.stream = callback => { stream = callback; return process; };
      process.close = () => { closed = true; };
      return process;
    },
  });
  window.cockpit = cockpit;
}

const mockCockpit = `(${installCockpitFixture.toString()})();`;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.ttf': 'font/ttf',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const headers = { 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'" };
  if (pathname === '/cockpit/base1/cockpit.js') {
    res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript' }).end(mockCockpit);
    return;
  }
  if (pathname === '/favicon.ico') { res.writeHead(204).end(); return; }
  const mount = [['/cockpit/woowtechservices/', 'services'], ['/static/', 'branding']]
    .find(([prefix]) => pathname.startsWith(prefix));
  if (!mount) { res.writeHead(404).end(); return; }
  const directory = resolve(root, mount[1]);
  const path = resolve(directory, decodeURIComponent(pathname.slice(mount[0].length)));
  if (!path.startsWith(directory + sep)) { res.writeHead(403).end(); return; }
  try {
    const data = await readFile(path);
    res.writeHead(200, { ...headers, 'Content-Type': types[extname(path)] || 'application/octet-stream' }).end(data);
  } catch { res.writeHead(404).end(); }
});

let browser;
let base;
const rows = page => page.locator('#services-body tr');
const service = (page, id) => rows(page).filter({ has: page.locator(`[data-field="id"]`, { hasText: id }) });
const calls = (page, command) => page.evaluate(command => window.testcalls.filter(call => call.argv[1] === command), command);
const enabled = (page, selector) => page.locator(`${selector}:enabled`).waitFor();
async function ready(page, scope = 'user:alice') {
  await page.waitForFunction(scope => document.querySelector('#scope').value === scope &&
    document.querySelector('#inventory-content').getAttribute('aria-busy') === 'false' &&
    !document.querySelector('#search').disabled, scope);
  assert.equal(await page.locator('#page-error').isVisible(), false, await page.locator('#error-message').textContent());
}
async function check(name, data, body) {
  await test(name, async () => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    try {
      const errors = [];
      await context.route('**/*', route => {
        if (new URL(route.request().url()).origin === base) return route.continue();
        errors.push(`External request: ${route.request().url()}`);
        return route.abort();
      });
      await context.addInitScript(data => { window.__fixture = data; }, data);
      const page = await context.newPage();
      page.setDefaultTimeout(5000);
      page.on('pageerror', error => errors.push(error.message));
      page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`); });
      await page.goto(`${base}/cockpit/woowtechservices/index.html`);
      await body(page);
      assert.deepEqual(await page.evaluate(() => window.fixtureErrors), []);
      assert.deepEqual(errors, [], 'No script errors, missing assets, or external requests');
      for (const call of await page.evaluate(() => window.testcalls)) {
        assert.equal(call.argv[0], helper, 'Only the fixed CLI helper may be called');
        assert.equal(call.options.superuser, 'require', 'Every helper call requires administrative access');
      }
    } finally { await context.close(); }
  });
}

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });
  await check('disconnected transport offers a fresh page connection without replaying actions', fixture(), async page => {
    await ready(page);
    await page.evaluate(() => window.__fixture.failures.push({command:'inventory', problem:'disconnected', message:'Transport closed'}));
    await page.locator('#refresh').click();
    await page.locator('#page-error').waitFor({state:'visible'});
    assert.equal(await page.locator('#retry').textContent(), '重新連線');
    const navigation = page.waitForEvent('framenavigated', f => f === page.mainFrame());
    await page.locator('#retry').click();
    await navigation;
    await ready(page);
    assert.equal((await calls(page, 'action')).length, 0);
  });

  await check('denied access reveals no inventory; permission changed reloads automatically', fixture({ allowed: false }), async page => {
    await page.locator('#access-note').waitFor();
    await enabled(page, '#retry');
    assert.equal((await calls(page, 'inventory')).length, 0);
    assert.equal(await rows(page).count(), 0);
    assert.equal(await page.locator('#scope').isDisabled(), true);
    await page.evaluate(() => window.__fixture.setAllowed(true));
    await ready(page);
    assert.equal(await page.locator('#access-note').isVisible(), false);
    assert.deepEqual((await calls(page, 'inventory')).map(call => call.argv.slice(1)), [['inventory', 'user:alice']]);
    assert.equal((await calls(page, 'action')).length, 0);
  });

  await check('search retains stopped Quadlets without containers and paginates 40 rows', fixture(), async page => {
    await ready(page);
    await page.locator('#clear-filters').click();
    assert.equal(await rows(page).count(), 40);
    const first = await rows(page).evaluateAll(rows => rows.map(row => row.dataset.unit));
    assert.equal(await page.locator('#previous-page').isDisabled(), true);
    await page.locator('#next-page').click();
    const last = await rows(page).evaluateAll(rows => rows.map(row => row.dataset.unit));
    assert.equal(last.length, 5);
    assert.equal(new Set([...first, ...last]).size, 45, 'Pagination must not drop or repeat services');
    assert.equal(await page.locator('#next-page').isDisabled(), true);
    await page.locator('#previous-page').click();
    assert.deepEqual(await rows(page).evaluateAll(rows => rows.map(row => row.dataset.unit)), first);
    await page.locator('#search').fill(' N8N.SERVICE ');
    await page.locator('#state-filter').selectOption('inactive');
    await page.locator('#kind-filter').selectOption('quadlet');
    assert.equal(await rows(page).count(), 1);
    const stopped = service(page, 'n8n.service');
    assert.match(await stopped.textContent(), /generated/);
    assert.match(await stopped.locator('[data-field="sub"]').textContent(), /inactive/);
    assert.equal(await stopped.locator('[data-action="start"]').isEnabled(), true);
    assert.equal(await stopped.locator('[data-action="stop"]').isDisabled(), true);
    assert.equal(await stopped.locator('[data-field="containers"]').textContent(), '—');
    assert.equal((await calls(page, 'action')).length, 0);
  });

  await check('scoped confirmation reads current state; cancel never mutates; confirm acts once', fixture(), async page => {
    await ready(page);
    for (const scope of [scopes[1], scopes[0]]) {
      await page.locator('#scope').selectOption(scope.id);
      await ready(page, scope.id);
      await page.locator('#clear-filters').click();
      await page.locator('#search').fill('n8n.service');
      const before = (await calls(page, 'action')).length;
      await page.evaluate(() => window.__fixture.hold.push('details'));
      await service(page, 'n8n.service').locator('[data-action="start"]').click();
      await page.waitForFunction(() => window.__fixture.waiting.some(item => item.command === 'details'));
      assert.equal(await page.locator('#confirm-action').isDisabled(), true);
      assert.equal(await page.locator('#confirm-unit').textContent(), 'n8n.service');
      assert.match(await page.locator('#confirm-scope').textContent(), new RegExp(`${scope.owner}.*UID ${scope.uid}`));
      assert.equal(await page.locator('#scope').isDisabled(), true);
      assert.equal((await calls(page, 'action')).length, before);
      await page.evaluate(() => window.__fixture.release('details'));
      await enabled(page, '#confirm-action');
      assert.deepEqual((await calls(page, 'details')).at(-1).argv.slice(1), ['details', scope.id, 'n8n.service']);
      await page.locator('#cancel-action').click();
      await page.locator('#action-dialog').waitFor({ state: 'hidden' });
      assert.equal((await calls(page, 'action')).length, before);
      await service(page, 'n8n.service').locator('[data-action="start"]').click();
      await enabled(page, '#confirm-action');
      await page.locator('#confirm-action').click();
      await page.locator('#action-dialog').waitFor({ state: 'hidden' });
      await ready(page, scope.id);
      const mutations = await calls(page, 'action');
      assert.equal(mutations.length, before + 1);
      assert.deepEqual(mutations.at(-1).argv.slice(1), ['action', scope.id, 'n8n.service', 'start']);
      assert.match(await service(page, 'n8n.service').locator('[data-field="sub"]').textContent(), /^active \/ running$/);
    }
  });

  const backendError = 'Fixture backend: operation refused <unsafe-output>';
  await check('JSON stdout survives process rejection; failed actions require fresh confirmation',
    fixture({ failures: [{ command: 'inventory', message: backendError }] }), async page => {
      await page.locator('#page-error').waitFor();
      assert.match(await page.locator('#error-message').textContent(), /Fixture backend: operation refused <unsafe-output>/);
      await page.locator('#retry').click();
      await ready(page);
      await page.evaluate(message => window.__fixture.failures.push({ command: 'action', message }), backendError);
      await service(page, 'n8n.service').locator('[data-action="start"]').click();
      await enabled(page, '#confirm-action');
      await page.locator('#confirm-action').click();
      await page.locator('#confirm-error').waitFor();
      await enabled(page, '#cancel-action');
      assert.match(await page.locator('#confirm-error-message').textContent(), /Fixture backend: operation refused <unsafe-output>/);
      assert.equal(await page.locator('#confirm-error-message unsafe-output').count(), 0);
      assert.equal(await page.locator('#confirm-action').isDisabled(), true);
      assert.equal((await calls(page, 'action')).length, 1);
      await page.locator('#retry-confirm').click();
      await enabled(page, '#confirm-action');
      assert.equal((await calls(page, 'action')).length, 1, 'Rechecking state must not replay the failed mutation');
      await page.locator('#cancel-action').click();
      await page.locator('#action-dialog').waitFor({ state: 'hidden' });
      assert.equal((await calls(page, 'action')).length, 1);
    });

  await check('protected manager actions stay disabled in rows and details', fixture(), async page => {
    await ready(page);
    await page.locator('#scope').selectOption('system');
    await ready(page, 'system');
    const protectedRow = service(page, 'cockpit.service');
    for (const verb of ['start', 'stop', 'restart']) assert.equal(await protectedRow.locator(`[data-action="${verb}"]`).isDisabled(), true);
    await protectedRow.locator('[data-open-details]').click();
    await enabled(page, '#refresh-logs');
    for (const verb of ['start', 'stop', 'restart']) assert.equal(await page.locator(`#details-actions [data-action="${verb}"]`).isDisabled(), true);
    assert.equal((await calls(page, 'action')).length, 0);
  });

  await check('details and refreshed journal render HTML literally without creating elements', fixture(), async page => {
    await ready(page);
    await service(page, 'n8n.service').locator('[data-open-details]').click();
    await enabled(page, '#refresh-logs');
    assert.equal(await page.locator('#logs').textContent(), hostileLog);
    assert.equal(await page.locator('#logs *').count(), 0);
    const field = label => page.locator('#details-fields dt').getByText(label, { exact: true }).locator('xpath=following-sibling::dd[1]');
    assert.equal(await field('主程序 PID').textContent(), '321');
    assert.equal(await field('目前記憶體').textContent(), '64.0 MiB');
    assert.equal(await field('累計 CPU 時間').textContent(), '1.25 秒');
    assert.equal(await field('目前工作數').textContent(), '未提供');
    assert.equal(await field('必要相依').textContent(), 'postgres.service <b>literal</b>');
    assert.equal(await page.locator('#details-fields b').count(), 0);
    const refreshed = `${hostileLog}\nnew journal entry <b>still literal</b>`;
    await page.evaluate(logs => { window.__fixture.logs = logs; }, refreshed);
    await page.locator('#refresh-logs').click();
    await page.waitForFunction(logs => document.querySelector('#logs').textContent === logs, refreshed);
    assert.equal(await page.locator('#logs *').count(), 0);
    assert.equal(await page.evaluate(() => Boolean(window.__xss)), false);
    assert.deepEqual((await calls(page, 'logs')).map(call => call.argv.slice(1)), [['logs', 'user:alice', 'n8n.service']]);
  });

  await check('Podman links use the selected owner UID from header, container, and details', fixture(), async page => {
    await ready(page);
    for (const scope of [scopes[1], scopes[2], scopes[0]]) {
      await page.locator('#scope').selectOption(scope.id);
      await ready(page, scope.id);
      await page.locator('#native-podman').click();
      await page.locator('#containers-tab').click();
      await page.locator('#containers-body [data-open-podman]').first().click();
      await page.locator('#containers-body [data-open-details]').click();
      await enabled(page, '#refresh-logs');
      assert.equal(await page.locator('#details-native-services').isVisible(), scope.id === 'system');
      await page.locator('#details-native-podman').click();
      assert.deepEqual(await page.evaluate(() => window.testjumps.slice(-3)), Array(3).fill(`/podman#/?owner=${scope.uid}`));
      await page.locator('#close-details').click();
      await page.locator('#details').waitFor({ state: 'hidden' });
      await page.locator('#services-tab').click();
    }
    assert.equal((await calls(page, 'action')).length, 0);
  });

  const longData = fixture({ logs: hostileLog + '\n' + 'journal-value-'.repeat(80) });
  for (const inventory of Object.values(longData.inventories)) {
    inventory.services[0].description = 'unbroken-service-description-'.repeat(20);
    inventory.containers[0].image = `registry.example.test/${'long-image-segment-'.repeat(30)}:latest`;
  }
  await check('1440/390/360px layouts keep inventories and dialogs inside the viewport', longData, async page => {
    await ready(page);
    const fits = async label => {
      const size = await page.evaluate(async () => {
        await document.fonts.ready;
        const dialog = document.querySelector('dialog[open]');
        const rect = dialog?.getBoundingClientRect();
        return { viewport: innerWidth, document: document.documentElement.scrollWidth,
          body: document.body.scrollWidth, dialog: dialog ? { left: rect.left, right: rect.right,
            scroll: dialog.scrollWidth, client: dialog.clientWidth } : null };
      });
      assert(size.document <= size.viewport && size.body <= size.viewport, `${label}: page overflow ${JSON.stringify(size)}`);
      if (size.dialog) assert(size.dialog.left >= 0 && size.dialog.right <= size.viewport &&
        size.dialog.scroll <= size.dialog.client + 1, `${label}: dialog overflow ${JSON.stringify(size)}`);
    };
    for (const width of [1440, 390, 360]) {
      await page.setViewportSize({ width, height: 900 });
      await page.locator('#services-tab').click();
      await page.locator('#search').fill('n8n.service');
      await fits(`${width}px service list`);
      await service(page, 'n8n.service').locator('[data-open-details]').click();
      await enabled(page, '#refresh-logs');
      await fits(`${width}px details and logs`);
      await page.locator('#close-details').click();
      await page.locator('#details').waitFor({ state: 'hidden' });
      await service(page, 'n8n.service').locator('[data-action="start"]').click();
      await enabled(page, '#confirm-action');
      await fits(`${width}px confirmation`);
      await page.locator('#cancel-action').click();
      await page.locator('#action-dialog').waitFor({ state: 'hidden' });
      await page.locator('#containers-tab').click();
      await fits(`${width}px containers`);
    }
  });
} finally {
  try { await browser?.close(); }
  finally { if (server.listening) await new Promise(resolve => server.close(resolve)); }
}
