#!/usr/bin/env node
// Local visual evidence only: never stores cookies, passwords or page text.
import { chromium } from 'playwright-core';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

if (process.argv.includes('--help')) {
  console.log('Set COCKPIT_URL, COCKPIT_USER and COCKPIT_PASSWORD. Optional: COCKPIT_INSECURE=1, COCKPIT_ELEVATE=1, COCKPIT_PODMAN_OWNER, COCKPIT_CAPTURE_DIR, PLAYWRIGHT_CHROMIUM_EXECUTABLE. See docs/testing.md.');
  process.exit(0);
}
const password = process.env.COCKPIT_PASSWORD;
const user = process.env.COCKPIT_USER;
if (!password || !user || !process.env.COCKPIT_URL) throw new Error('COCKPIT_URL, COCKPIT_USER and COCKPIT_PASSWORD are required');
const origin = new URL(process.env.COCKPIT_URL);
if (origin.protocol !== 'https:' || origin.username || origin.password) throw new Error('Use an HTTPS origin with no embedded credentials');
const base = origin.origin;
const output = resolve(process.env.COCKPIT_CAPTURE_DIR || '.local/screenshots');
await mkdir(output, { recursive: true, mode: 0o700 });
const results = [];
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });

async function frameAt(page, marker) {
  const iframe = page.locator(`iframe[src*="${marker}"]`);
  await iframe.waitFor({ state: 'attached', timeout: 30000 });
  const frame = await (await iframe.elementHandle()).contentFrame();
  await frame.waitForURL(`**${marker}**`);
  return frame;
}
async function surfaces(frame) {
  return frame.evaluate(async () => {
    await document.fonts.ready;
    const elements = [...document.querySelectorAll('body,#main,#content,#nav-system,#hosts-sel,#topnav,.pf-v6-c-page,.pf-v6-c-page__main-container,.pf-v6-c-page__main-section')]
      .filter(el => el.getBoundingClientRect().width > 0);
    return {
      width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
      blue: getComputedStyle(document.documentElement).getPropertyValue('--ww-blue').trim().toLowerCase(),
      whiteCanvas: elements.every(el => getComputedStyle(el).backgroundColor === 'rgb(255, 255, 255)' && getComputedStyle(el).backgroundImage === 'none'),
      cardRadius: [...document.querySelectorAll('.pf-v6-c-card')].every(el => getComputedStyle(el).borderRadius === '20px'),
    };
  });
}
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: process.env.COCKPIT_INSECURE === '1',
    viewport: { width: 1440, height: 900 }, locale: 'zh-TW', colorScheme: 'light' });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('Network.enable');
  await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
  async function shot(name) {
    await page.evaluate(() => document.fonts.ready);
    await page.mouse.move(0, 0);
    await page.screenshot({ path: join(output, name + '.png'), animations: 'disabled' });
  }
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.locator('#login-user-input').waitFor();
  await shot('00-login');
  await page.setViewportSize({ width: 390, height: 844 });
  await shot('14-mobile-login');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('#login-user-input').fill(user);
  await page.locator('#login-password-input').fill(password);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 30000 });
  const overview = await frameAt(page, '/system/index.html');
  await overview.locator('.system-information').waitFor();
  if (process.env.COCKPIT_ELEVATE === '1') {
    const elevate = overview.getByRole('button', { name: /打開管理員存取權限|Turn on administrative access/ });
    if (await elevate.isVisible()) {
      await elevate.click();
      await overview.locator('#switch-to-admin-access-password').waitFor();
      await shot('admin-auth-prompt'); // Capture BEFORE filling any password.
      await overview.locator('#switch-to-admin-access-password').fill(password);
      await overview.getByRole('button', { name: /^(認證|Authenticate)$/ }).click();
      await page.getByRole('button', { name: /^(管理員存取模式|Administrative access)$/ }).waitFor();
    } else {
      results.push({ name: 'admin-auth-prompt', status: 'not-captured', reason: 'No elevation prompt available in this session' });
    }
  } else {
    results.push({ name: 'admin-auth-prompt', status: 'not-captured', reason: 'Elevation not requested' });
  }
  delete process.env.COCKPIT_PASSWORD;
  const routes = [
    ['01-overview', '/system', '/system/index.html', '.system-information'],
    ['02-logs', '/system/logs', '/system/logs.html', 'body'],
    ['03-storage', '/storage', '/storage/index.html', '.pf-v6-c-card'],
    ['04-network', '/network', '/network/index.html', '.pf-v6-c-card'],
    ['05-podman', '/podman', '/podman/index.html', '#containers-images'],
    ['06-accounts', '/users', '/users/index.html', '#accounts-list'],
    ['07-services', '/system/services', '/system/services.html', '#services-list tbody tr'],
    ['08-applications', '/apps', '/apps/index.html', 'body'],
    ['09-updates', '/updates', '/updates/index.html', 'body'],
    ['10-terminal', '/system/terminal', '/system/terminal.html', '.xterm-screen'],
    ['11-hardware', '/system/hwinfo', '/system/hwinfo.html', '.pf-v6-c-card'],
    ['12-metrics', '/metrics', '/metrics/index.html', '#current-metrics-card-cpu'],
  ];
  for (const [name, route, marker, ready] of routes) {
    try {
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.goto(base + route, { waitUntil: 'domcontentloaded' });
      const frame = await frameAt(page, marker);
      await frame.locator(ready).first().waitFor({ timeout: 30000 });
      await frame.waitForFunction(() => document.body.innerText.trim().length > 15 || document.querySelector('.xterm-screen'));
      if (name === '05-podman' && process.env.COCKPIT_PODMAN_OWNER) {
        const owner = frame.locator('#containers-containers-owner');
        await owner.waitFor();
        await frame.waitForFunction(wanted => [...document.querySelectorAll('#containers-containers-owner option')].some(o => o.textContent.trim() === wanted), process.env.COCKPIT_PODMAN_OWNER);
        await owner.selectOption({ label: process.env.COCKPIT_PODMAN_OWNER });
      }
      await page.waitForTimeout(1200);
      const state = await surfaces(frame);
      const ok = state.whiteCanvas && state.cardRadius && state.blue === '#6183fc' && state.scrollWidth <= state.width;
      results.push({ name, status: ok ? 'passed' : 'failed', ...state, backendVerified: false });
      await shot(name);
      if (name === '01-overview') {
        for (const width of [1024, 390]) {
          await page.setViewportSize({ width, height: 900 });
          const narrow = await surfaces(frame);
          results.push({ name: `overview-${width}`, status: narrow.scrollWidth <= narrow.width && narrow.whiteCanvas ? 'passed' : 'failed', ...narrow });
        }
        const height = await frame.locator('main.pf-v6-c-page__main').evaluate(el => el.scrollHeight);
        const chrome = await page.evaluate(() => innerHeight - document.querySelector('iframe[src*="system/index.html"]').getBoundingClientRect().height);
        await page.setViewportSize({ width: 390, height: Math.ceil(height + chrome + 24) });
        await shot('15-mobile-overview');
      }
      if (name === '05-podman') {
        const show = frame.getByText(/^(Show images|顯示映像)$/);
        if (await show.isVisible()) await show.click();
        await page.waitForTimeout(300);
        await shot('13-podman-images');
      }
      console.log(`${name}: ${ok ? 'PASS' : 'FAIL'}`);
    } catch (error) {
      // Do not include locator dumps, URLs, account names or page text in summary.
      results.push({ name, status: 'failed', errorType: error.name });
      console.log(`${name}: FAIL (${error.name})`);
    }
  }
} finally {
  delete process.env.COCKPIT_PASSWORD;
  await browser.close();
  await writeFile(join(output, 'verification.json'), JSON.stringify({ capturedAt: new Date().toISOString(), results }, null, 2) + '\n', { mode: 0o600 });
}
if (results.some(row => row.status === 'failed')) process.exitCode = 1;
console.log(`Saved local evidence to ${output}. Review before sharing; screenshots contain host information.`);
