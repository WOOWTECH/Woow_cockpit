// Run against the deployed gateway or public HTTPS origin. Set COCKPIT_PASSWORD
// to additionally exercise a real login and WebSocket. Never log credentials.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const base = process.env.COCKPIT_URL || 'http://127.0.0.1:29091';
const dir = await mkdtemp(join(tmpdir(), 'woow-pwa-'));
const context = await chromium.launchPersistentContext(dir, {
  executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined,
  headless: true, locale: 'zh-TW', viewport: { width: 390, height: 844 },
});
try {
  const page = context.pages()[0];
  const sockets = [];
  page.on('websocket', socket => sockets.push(socket));
  await page.goto(base, { waitUntil: 'networkidle' });
  assert(await page.evaluate(() => isSecureContext), 'PWA must use a secure context');
  const cdp = await context.newCDPSession(page);
  const manifest = await cdp.send('Page.getAppManifest');
  assert(manifest.url.endsWith('/woow-pwa/manifest.webmanifest'));
  assert.deepEqual(manifest.errors, []);
  const installability = await cdp.send('Page.getInstallabilityErrors');
  assert.deepEqual(installability.installabilityErrors, []);
  if (process.env.COCKPIT_PASSWORD) {
    await page.locator('#login-user-input').fill(process.env.COCKPIT_USER || 'admin');
    await page.locator('#login-password-input').fill(process.env.COCKPIT_PASSWORD);
    await page.locator('#login-button').click();
    await page.waitForURL('**/system', { timeout: 25000 });
    await page.waitForTimeout(2000);
    assert(sockets.some(socket => !socket.isClosed()), 'Cockpit WebSocket must stay connected');
    assert.equal(await page.locator('link[rel=manifest]').getAttribute('href'), '/woow-pwa/manifest.webmanifest');
    assert(!(await page.locator('body').innerText()).includes('已離線'));
  }
  console.log('PWA manifest, installability' + (process.env.COCKPIT_PASSWORD ? ', login and WebSocket' : '') + ': passed');
} finally {
  await context.close();
  await rm(dir, { recursive: true, force: true });
}
