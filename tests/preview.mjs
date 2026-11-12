import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, extname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { chromium } from 'playwright-core';

const staging = await mkdtemp(join(tmpdir(), 'woow-cockpit-'));
let browser;
let server;
try {
  await mkdir(join(staging, 'var/lib/dpkg'), { recursive: true });
  await writeFile(join(staging, 'var/lib/dpkg/status'), 'Package: cockpit-bridge\nStatus: install ok installed\nVersion: 362-1\n\n');
  execFileSync('python3', ['scripts/manage.py', '--root', staging, 'install'], { stdio: 'pipe' });
  const web = join(staging, 'usr/local/share/cockpit/woowtechpreview');
  const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ttf': 'font/ttf' };
  server = createServer(async (req, res) => {
    const path = resolve(web, '.' + new URL(req.url, 'http://localhost').pathname);
    if (!path.startsWith(web + '/')) { res.writeHead(403).end(); return; }
    try {
      const data = await readFile(path);
      res.writeHead(200, { 'Content-Type': types[extname(path)] || 'application/octet-stream',
        'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'" });
      res.end(data);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise(ok => server.listen(0, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  for (const width of [1440, 1024, 390, 360]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(base + '/index.html');
    await page.locator('figure img').evaluateAll(images => images.forEach(img => { img.loading = 'eager'; }));
    await page.waitForFunction(() => document.querySelectorAll('.missing-shot').length === 17);
    const state = await page.evaluate(async () => {
      await document.fonts.ready;
      return {
        width: innerWidth, scroll: document.documentElement.scrollWidth,
        white: getComputedStyle(document.body).backgroundColor,
        brokenVisible: [...document.querySelectorAll('figure img')].filter(img => !img.naturalWidth && img.getClientRects().length).length,
        brokenLinks: [...document.querySelectorAll('.open')].filter(el => el.getClientRects().length).length,
        logo: document.querySelector('.top img').naturalWidth,
        icons: document.querySelectorAll('[data-mdi] svg').length,
      };
    });
    assert.equal(state.brokenVisible, 0);
    assert.equal(state.brokenLinks, 0);
    assert(state.scroll <= state.width);
    assert.equal(state.white, 'rgb(255, 255, 255)');
    assert(state.logo > 0 && state.icons > 0);
    console.log(`PASS gallery ${width}px: missing captures handled, assets loaded, white canvas, no overflow`);
  }
  // A locally generated capture must replace the empty state and keep its link.
  await mkdir(join(web, 'screenshots'));
  await page.screenshot({ path: join(web, 'screenshots/00-login.png') });
  await page.goto(base + '/index.html');
  await page.locator('figure img').evaluateAll(images => images.forEach(img => { img.loading = 'eager'; }));
  await page.waitForFunction(() => document.querySelectorAll('.missing-shot').length === 16);
  assert(await page.locator('figure').first().locator('img').evaluate(img => img.naturalWidth > 0));
  assert(await page.locator('figure').first().locator('.open').isVisible());
  console.log('PASS gallery: local capture visible and full-image link works');
  await page.goto(base + '/layout-review.html');
  await page.locator('figure img').evaluateAll(images => images.forEach(img => { img.loading = 'eager'; }));
  await page.waitForFunction(() => document.querySelectorAll('.missing-shot').length === document.querySelectorAll('figure').length);
  assert.equal(await page.locator('figure img').evaluateAll(images => images.filter(img => img.getClientRects().length && !img.naturalWidth).length), 0);
  assert.deepEqual(errors, []);
  console.log('PASS historical layout review: missing captures handled, no JavaScript errors');
} finally {
  await browser?.close();
  if (server) await new Promise(ok => server.close(ok));
  await rm(staging, { recursive: true, force: true });
}
