#!/usr/bin/env node
// Lab check: log in to a device's Cockpit over HTTPS as devadmin, turn on administrative access
// and prove it by running `id -u` with superuser: "require" (must print 0).
//   node tests/e2e/lab/cockpit-login.mjs <a|b>
// The password is read from ~/.woowbk-lab/secrets/devadmin.pass and never printed or captured:
// screenshots are taken only before a password is typed or after the fields are gone.
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const ports = { a: 19091, b: 19092 };
const dev = (process.argv[2] || '').replace(/^(woowbk-)?dev-/, '');
if (!ports[dev]) {
  console.error('usage: cockpit-login.mjs <a|b>');
  process.exit(2);
}
const lab = process.env.WOOWBK_LAB_HOME || join(homedir(), '.woowbk-lab');
const password = readFileSync(join(lab, 'secrets', 'devadmin.pass'), 'utf8').trim();
const evidence = join(lab, 'evidence', 'lab');
mkdirSync(evidence, { recursive: true, mode: 0o700 });
const bundled = join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome');
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || (existsSync(bundled) ? bundled : undefined);
const base = `https://127.0.0.1:${ports[dev]}`;

async function frameAt(page, marker) {
  const iframe = page.locator(`iframe[src*="${marker}"]`);
  await iframe.waitFor({ state: 'attached', timeout: 30000 });
  const frame = await (await iframe.elementHandle()).contentFrame();
  await frame.waitForURL(`**${marker}**`);
  return frame;
}

const result = { device: `woowbk-dev-${dev}`, url: base, steps: [] };
const step = (name, detail = '') => { result.steps.push(detail ? `${name}: ${detail}` : name); };
const browser = await chromium.launch({ executablePath });
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US', viewport: { width: 1280, height: 860 } });
  const page = await context.newPage();
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').waitFor({ timeout: 30000 });
  await page.screenshot({ path: join(evidence, `cockpit-${dev}-login.png`) });
  step('login page', await page.title());
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(password);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 45000 });
  const overview = await frameAt(page, '/system/index.html');
  await overview.locator('.system-information').waitFor({ timeout: 30000 });
  step('logged in', page.url());

  const indicator = page.getByRole('button', { name: /^(Limited access|Administrative access|受限存取|管理員存取模式)$/ });
  await indicator.waitFor({ timeout: 30000 });
  step('superuser indicator before', (await indicator.textContent()).trim());
  if (/Limited|受限/.test(await indicator.textContent())) {
    await indicator.click();
    await page.locator('#switch-to-admin-access-password').waitFor({ timeout: 30000 });
    await page.locator('#switch-to-admin-access-password').fill(password);
    await page.getByRole('button', { name: /^(Authenticate|認證)$/ }).click();
    await page.locator('#switch-to-admin-access-password').waitFor({ state: 'detached', timeout: 30000 });
  }
  await page.getByRole('button', { name: /^(Administrative access|管理員存取模式)$/ }).waitFor({ timeout: 30000 });
  step('superuser indicator after', 'Administrative access');

  const uid = await overview.evaluate(async () => await window.cockpit.spawn(['id', '-u'], { superuser: 'require', err: 'message' }));
  step('cockpit.spawn id -u (superuser: require)', uid.trim());
  const host = await overview.evaluate(async () => await window.cockpit.spawn(['hostname'], { err: 'message' }));
  step('hostname', host.trim());
  const version = await overview.evaluate(async () => await window.cockpit.spawn(['dpkg-query', '-W', '-f=${Version}', 'cockpit-ws'], { err: 'message' }));
  step('cockpit-ws', version.trim());
  await page.screenshot({ path: join(evidence, `cockpit-${dev}-admin.png`) });
  if (uid.trim() !== '0') throw new Error(`administrative access did not yield root (uid ${uid.trim()})`);
  if (host.trim() !== `woowbk-dev-${dev}`) throw new Error(`unexpected hostname ${host.trim()}`);
  result.ok = true;
} catch (error) {
  result.ok = false;
  result.error = String(error && error.message || error).split('\n')[0];
} finally {
  await browser.close();
}
console.log(JSON.stringify(result, null, 2));
process.exit(result.ok ? 0 : 1);
