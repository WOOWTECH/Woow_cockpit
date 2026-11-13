// Live checks use an isolated browser context. Passwords are environment-only.
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';

const base = process.env.COCKPIT_URL || 'https://cockpit-openclaw.woowtech.io';
assert(process.env.COCKPIT_PASSWORD && process.env.PI_WEB_PASSWORD, 'Set both login passwords');
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });
try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'zh-TW' });
  const page = await context.newPage();
  await page.goto(base);
  await page.locator('#login-user-input').fill(process.env.COCKPIT_USER || 'admin');
  await page.locator('#login-password-input').fill(process.env.COCKPIT_PASSWORD);
  await page.locator('#login-button').click();
  await page.waitForURL('**/system', { timeout: 25000 });
  await page.goto(`${base}/woowpiweb`);
  // Resolve by the actual package URL to work with different shell frame names.
  let hostFrame;
  const deadline = Date.now() + 15000;
  while (!hostFrame && Date.now() < deadline) {
    hostFrame = page.frames().find(f => f.url().includes('/woowpiweb/index.html'));
    if (!hostFrame) await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert(hostFrame, 'Pi Web package must be available');
  await hostFrame.locator('#pi').waitFor({ state: 'visible', timeout: 10000 });
  assert.equal(await hostFrame.locator('#pi').getAttribute('src'), `${base}/pi-web/`);
  const pi = await (await hostFrame.locator('#pi').elementHandle()).contentFrame();
  await pi.locator('#web-login-password').waitFor({ timeout: 15000 });
  await pi.locator('#web-login-password').fill(process.env.PI_WEB_PASSWORD);
  await pi.locator('form button[type=submit]').click();
  await pi.waitForFunction(() => !document.getElementById('web-login-password'), null, { timeout: 20000 });
  assert(pi.url().startsWith(base + '/'), 'Pi must remain on the HTTPS Cockpit origin');
  await pi.locator('textarea').waitFor({ state: 'visible', timeout: 15000 });
  const nativePreference = await pi.evaluate(() => localStorage.getItem('pi-theme'));
  await page.evaluate(() => localStorage.setItem('shell:style', 'dark'));
  await pi.waitForFunction(() => document.documentElement.dataset.theme === 'dark', null, { timeout: 10000 });
  await page.evaluate(() => localStorage.setItem('shell:style', 'light'));
  await pi.waitForFunction(() => document.documentElement.dataset.theme === 'light', null, { timeout: 10000 });
  assert.equal(await pi.evaluate(() => localStorage.getItem('pi-theme')), nativePreference);
  assert.equal(await pi.evaluate(() => document.documentElement.style.getPropertyValue('--accent')), '#6183fc');
  assert.equal(await pi.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  assert.deepEqual(await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).map(r => r.scope)), []);
  if (process.env.PI_WEB_CHAT_TEST === '1') {
    const marker = `CF_PI_${Date.now()}`;
    let sessionId, createError;
    const streams = [];
    page.on('response', async response => {
      const url = new URL(response.url());
      if (url.pathname === '/api/agent/new' && response.request().method() === 'POST') {
        const data = await response.json();
        if (data.success && data.sessionId) sessionId = data.sessionId;
        else createError = data.error || 'Agent creation failed';
      }
      if (/\/api\/agent\/[^/]+\/events$/.test(url.pathname) && response.status() === 200) streams.push(url.pathname);
    });
    await page.setViewportSize({ width: 1280, height: 900 });
    const showSidebar = pi.getByRole('button', { name: '顯示側邊欄', exact: true });
    if (await showSidebar.isVisible()) await showSidebar.click();
    await pi.getByRole('button', { name: '新增', exact: true }).click();
    await pi.locator('textarea').fill(`Reply with exactly ${marker}. Do not use any tools.`);
    await pi.getByRole('button', { name: '傳送', exact: true }).click();
    const deadline = Date.now() + 90000;
    let replied = false;
    while (!replied && Date.now() < deadline) {
      if (createError) throw Error(createError);
      if (sessionId) {
        const data = await pi.evaluate(async id => {
          const response = await fetch(`/api/sessions/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10000) });
          return response.json();
        }, sessionId);
        const assistantText = [];
        function visit(value) {
          if (!value || typeof value !== 'object') return;
          if (value.role === 'assistant') assistantText.push(JSON.stringify(value.content));
          for (const child of Object.values(value)) visit(child);
        }
        visit(data.context?.messages);
        replied = assistantText.some(text => text?.includes(marker));
      }
      if (!replied) await new Promise(resolve => setTimeout(resolve, 1000));
    }
    assert(replied, 'A newly-created session must contain a real assistant response');
    assert(streams.some(path => path.includes(sessionId)), 'The session event stream must connect');
    assert(await pi.locator('body').innerText().then(text => text.includes(marker)), 'The reply must also render in Pi Web');
    await page.setViewportSize({ width: 390, height: 844 });
    console.log('PASS new Pi session, real assistant reply and event stream');
  }
  if (process.env.PI_WEB_SCREENSHOT) await page.screenshot({ path: process.env.PI_WEB_SCREENSHOT });
  console.log('PASS public Pi Web iframe, independent login, themes and mobile layout');
} finally {
  await browser.close();
}
