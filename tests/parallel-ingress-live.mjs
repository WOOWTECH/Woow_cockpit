// Opt-in acceptance against an installed entrance. Credentials stay in the environment.
// Reads existing management data; does not change schedules or stop applications.
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
const base=process.env.COCKPIT_URL;
assert(base && process.env.COCKPIT_PASSWORD,'Set COCKPIT_URL and COCKPIT_PASSWORD');
const browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined});
const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'zh-TW'});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
async function open(route){
 await page.goto(`${base}/${route}`);
 for(let i=0;i<150;i++){
  const f=page.frames().find(f=>f.url().includes(`/${route}/index.html`));
  if(f){await f.locator('body').waitFor();return f}
  await page.waitForTimeout(100);
 }
 throw Error(`Missing package frame: ${route}`);
}
async function mobileThemes(frame){
 await page.setViewportSize({width:390,height:844});
 for(const theme of ['dark','light']){
  await page.evaluate(t=>localStorage.setItem('shell:style',t),theme);
  await page.waitForTimeout(400);
  assert(await frame.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile page must not overflow');
 }
 await page.setViewportSize({width:1440,height:1000});
}
try{
 await page.goto(base);
 await page.locator('#login-user-input').fill(process.env.COCKPIT_USER || 'admin');
 await page.locator('#login-password-input').fill(process.env.COCKPIT_PASSWORD);
 await page.locator('#login-button').click();
 await page.waitForURL('**/system',{timeout:30000});
 let f=await open('system');
 const elevate=f.getByRole('button',{name:/打開管理員存取權限|Turn on administrative access/});
 if(await elevate.isVisible()){
  await elevate.click();
  await f.locator('#switch-to-admin-access-password').fill(process.env.COCKPIT_ADMIN_PASSWORD || process.env.COCKPIT_PASSWORD);
  await f.getByRole('button',{name:/^(認證|Authenticate)$/}).click();
 }
 await page.getByRole('button',{name:/^(管理員存取模式|Administrative access)$/}).waitFor();
 f=await open('woowtechbackup');
 await f.waitForFunction(()=>document.querySelector('#view')?.getAttribute('aria-busy')==='false',null,{timeout:120000});
 assert.equal(await f.locator('#page-error').isVisible(),false);
 await f.evaluate(()=>location.hash='#/schedule');
 await f.getByText('自動建立排程備份',{exact:true}).waitFor({timeout:30000});
 await f.getByText('保留最新幾份排程備份',{exact:true}).waitFor();
 await mobileThemes(f);
 console.log('PASS backup status, actual schedule controls and mobile themes');
 f=await open('woowtechapps');
 await f.locator('#cards > *').first().waitFor({timeout:120000});
 assert.equal(await f.locator('#error').isVisible(),false);
 const apps=await f.locator('#cards > *').count();
 await mobileThemes(f);
 console.log(`PASS application inventory: ${apps} cards`);
 f=await open('woowtechservices');
 await f.waitForFunction(()=>/^\d+$/.test(document.querySelector('#service-count')?.textContent||''),null,{timeout:120000});
 assert.equal(await f.locator('#page-error').isVisible(),false);
 console.log(`PASS service inventory: ${await f.locator('#service-count').innerText()} services / ${await f.locator('#container-count').innerText()} containers`);
 await mobileThemes(f);
 for(const route of ['woowtechpreview']){
  f=await open(route);await f.getByRole('heading',{name:'畫面參考',exact:true}).waitFor();
  await f.waitForFunction(()=>[...document.images].every(i=>i.complete&&i.naturalWidth>0));
  assert.equal(await f.locator('.missing-shot').count(),17);
  await mobileThemes(f);
 }
 const manifest=await page.evaluate(async()=>{
  const response=await fetch('/woow-pwa/manifest.webmanifest');if(!response.ok)throw Error('manifest unavailable');return response.json();
 });
 assert.equal(manifest.display,'standalone');
 assert(manifest.icons.some(icon=>icon.sizes==='512x512'));
 assert.deepEqual(errors,[]);
 console.log('PASS complete reference page, PWA manifest and no uncaught page errors');
}finally{await browser.close()}
