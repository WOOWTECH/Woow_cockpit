// Optional live installation check. Uses and removes an isolated browser profile.
// For a real desktop window: xvfb-run -a env PWA_HEADFUL=1 node .../install-test.mjs
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const base = process.env.COCKPIT_URL || 'http://127.0.0.1:29091';
const manifestId = new URL('/', base).href;
const profile = await mkdtemp(join(tmpdir(), 'woow-pwa-install-'));
let context;
let browserCDP;
let installed = false;
try {
  context = await chromium.launchPersistentContext(profile, {
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined,
    headless: process.env.PWA_HEADFUL !== '1',
  });
  const page = context.pages()[0];
  await page.goto(base, { waitUntil: 'networkidle' });
  const pageCDP = await context.newCDPSession(page);
  const manifest = await pageCDP.send('Page.getAppManifest');
  assert.deepEqual(manifest.errors, []);
  assert.equal(JSON.parse(manifest.data).display, 'standalone');
  browserCDP = await context.browser().newBrowserCDPSession();
  await pageCDP.send('PWA.install', { manifestId });
  installed = true;
  // The automation install API does not select the browser's "open in window"
  // preference. Select it explicitly, just as a desktop user can during install.
  await browserCDP.send('PWA.changeAppUserSettings', { manifestId, displayMode: 'standalone' });
  await browserCDP.send('PWA.launch', { manifestId });
  let app;
  const deadline = Date.now() + 15000;
  while (!app && Date.now() < deadline) {
    for (const candidate of context.pages()) {
      if (!candidate.url().startsWith(manifestId)) continue;
      if (await candidate.evaluate(() => matchMedia('(display-mode: standalone)').matches)) {
        app = candidate;
        break;
      }
    }
    if (!app) await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert(app, 'Installation must launch a standalone app window');
  await app.waitForLoadState('networkidle');
  assert(await app.evaluate(() => isSecureContext));
  assert(await app.locator('#login-button').isVisible());
  if (process.env.COCKPIT_PASSWORD) {
    await app.locator('#login-user-input').fill(process.env.COCKPIT_USER || 'admin');
    await app.locator('#login-password-input').fill(process.env.COCKPIT_PASSWORD);
    await app.locator('#login-button').click();
    await app.waitForURL('**/system', { timeout: 25000 });
    assert(await app.evaluate(() => matchMedia('(display-mode: standalone)').matches));
  }
  console.log('PWA install, standalone launch' + (process.env.COCKPIT_PASSWORD ? ' and app login' : '') + ': passed');
} finally {
  try {
    if (installed) await browserCDP.send('PWA.uninstall', { manifestId });
  } finally {
    await context?.close();
    await rm(profile, { recursive: true, force: true });
  }
}
