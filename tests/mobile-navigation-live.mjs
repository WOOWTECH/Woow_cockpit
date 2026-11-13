// Opt-in against a configured Cockpit host; never stores credentials or state.
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
const url = process.env.COCKPIT_URL, user = process.env.COCKPIT_USER, password = process.env.COCKPIT_PASSWORD;
if (!url || !user || !password) throw Error('Set COCKPIT_URL, COCKPIT_USER and COCKPIT_PASSWORD.');
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  const page = await browser.newPage({ locale: 'zh-TW', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(url);
  await page.locator('#login-user-input').fill(user);
  await page.locator('#login-password-input').fill(password);
  await page.locator('#login-button').click();
  await page.locator('#woow-mobile-tools').waitFor({ timeout: 30000 });
  const selectors = ['#nav-system-item', '#woow-mobile-tools', '#host-toggle', '#toggle-docs', '#toggle-menu'];
  for (const width of [320, 360, 390, 430, 767]) {
    await page.setViewportSize({ width, height: 844 });
    const boxes = await Promise.all(selectors.map(selector => page.locator(selector).boundingBox()));
    for (const [index, box] of boxes.entries()) {
      assert.ok(box && box.width >= 44 && box.x >= 0 && box.x + box.width <= width + 1);
      if (index) assert.ok(box.x >= boxes[index - 1].x + boxes[index - 1].width - 1);
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#woow-mobile-tools').click();
  await page.locator('#nav-system.interact').waitFor();
  assert.equal(await page.locator('#woow-mobile-tools').getAttribute('aria-expanded'), 'true');
  const tools = page.locator('#host-apps section[data-woow-nav-group="tools"]');
  const system = page.locator('#host-apps section[data-woow-nav-group="system"]');
  await tools.locator('a').first().waitFor({ state: 'visible' });
  assert.equal(await system.isVisible(), false);
  const search = page.locator('#host-apps .search input');
  await search.fill('Pi Web');
  await page.getByRole('link', { name: 'Pi Web', exact: true }).waitFor({ state: 'visible' });
  await page.locator('#nav-system-item').click();
  assert.equal(await page.locator('#woow-mobile-tools').getAttribute('aria-expanded'), 'false');
  await system.locator('a').first().waitFor({ state: 'visible' });
  assert.equal(await search.inputValue(), '');
  assert.equal(await tools.isVisible(), false);
  await search.fill('系統日誌');
  await page.getByRole('link', { name: '系統日誌', exact: true }).waitFor({ state: 'visible' });
  await page.locator('#woow-mobile-tools').click();
  await tools.locator('a').first().waitFor({ state: 'visible' });
  assert.equal(await search.inputValue(), '');
  assert.equal(await system.isVisible(), false);
  await page.locator('#nav-system-item').click();
  await page.locator('#nav-system-item').click();
  await page.locator('#woow-mobile-tools').focus();
  await page.keyboard.press('Enter');
  await page.locator('#nav-system.interact').waitFor();
  assert.equal(await page.locator('#woow-mobile-tools').getAttribute('aria-expanded'), 'true');
  await page.keyboard.press('Enter');
  await page.locator('#nav-system.interact').waitFor({ state: 'hidden' });
  for (const selector of ['#host-toggle', '#toggle-docs', '#toggle-menu']) {
    await page.locator(selector).click();
    assert.equal(await page.locator(selector).getAttribute('aria-expanded'), 'true');
    await page.locator(selector).click();
  }
  await page.setViewportSize({ width: 1000, height: 844 });
  assert.equal(await page.locator('#woow-mobile-tools').isVisible(), false);
  assert.equal(await system.isVisible(), true);
  assert.equal(await tools.isVisible(), true);
  assert.deepEqual(errors, []);
  console.log('PASS: mobile navigation layout, tools, menu controls and desktop');
} finally {
  await browser.close();
}
