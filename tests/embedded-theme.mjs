import assert from 'node:assert/strict';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright-core';
const listen=s=>new Promise(r=>s.listen(0,'127.0.0.1',()=>r(s.address().port)));
let wrapper=await readFile('pi-web-integration/package/app.js','utf8');
const cockpit=http.createServer((req,res)=>{
 if(req.url==='/cockpit/login'){res.writeHead(req.headers.cookie?.includes('cockpit=valid')?200:401).end();return;}
 if(req.url==='/wrapper.js'){res.writeHead(200,{'content-type':'text/javascript'}).end(wrapper);return;}
 res.writeHead(200,{'content-type':'text/html'}).end('<html><body><iframe id="pi"></iframe><div id="secure-required" hidden></div><div id="unavailable" hidden></div><script src="/wrapper.js"></script></body></html>');
});
const pi=http.createServer((req,res)=>{
 if(req.url==='/api/web-auth'){res.writeHead(200,{'content-type':'application/json'}).end('{"enabled":true}');return;}
 res.writeHead(200,{'content-type':'text/html'}).end('<html data-theme="light"><head><title>Pi test</title></head><body>Pi test</body></html>');
});
const cp=await listen(cockpit), pp=await listen(pi), probe=http.createServer(),gp=await listen(probe);await new Promise(r=>probe.close(r));
wrapper=wrapper.replaceAll('__GATEWAY_HOST__','127.0.0.1').replaceAll('__VPN_HOST__','').replaceAll('__GATEWAY_PORT__',String(gp));
const child=spawn(process.execPath,['pi-web-integration/gateway.mjs'],{env:{...process.env,PI_GATEWAY_BIND:'127.0.0.1',PI_GATEWAY_HOST:'127.0.0.1',PI_GATEWAY_PORT:String(gp),PI_GATEWAY_COCKPIT_PORT:String(cp),PI_GATEWAY_UPSTREAM_PORT:String(pp)},stdio:['ignore','pipe','pipe']});
let browser;
try {
 await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('exit',code=>reject(Error(`gateway exited ${code}`)));setTimeout(()=>reject(Error('gateway startup timeout')),5000).unref()});
 browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||undefined});
 const context=await browser.newContext({colorScheme:'light'});await context.addCookies([{name:'cockpit',value:'valid',domain:'127.0.0.1',path:'/'}]);
 const page=await context.newPage();await page.goto(`http://127.0.0.1:${cp}/`);
 const piFrame=await (await page.locator('#pi').elementHandle()).contentFrame();await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='light');
 await piFrame.evaluate(()=>localStorage.setItem('pi-theme','rose'));
 const control=await context.newPage();await control.goto(`http://127.0.0.1:${cp}/`);
 await control.evaluate(()=>localStorage.setItem('shell:style','dark'));
 await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='dark'&&document.documentElement.classList.contains('dark'));
 assert.equal(await piFrame.evaluate(()=>localStorage.getItem('pi-theme')),'rose');
 // A sibling iframe on an untrusted origin cannot change the embedded theme.
 await page.evaluate(port=>{const f=document.createElement('iframe');f.id='attacker';f.src=`http://127.0.0.1:${port}/attacker`;document.body.append(f)},pp);
 const attacker=await (await page.locator('#attacker').elementHandle()).contentFrame();await attacker.waitForLoadState('load');
 await attacker.evaluate(()=>window.parent.frames[0].postMessage({type:'woow-cockpit-theme',theme:'light'},'*'));
 await page.waitForTimeout(100);assert.equal(await piFrame.evaluate(()=>document.documentElement.dataset.theme),'dark');

 assert.equal(await piFrame.evaluate(()=>document.documentElement.style.getPropertyValue('--accent')),'#6183fc');
 await piFrame.evaluate(()=>{document.documentElement.dataset.theme='light';document.documentElement.classList.remove('dark')});
 await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='dark'&&document.documentElement.classList.contains('dark'));
 await control.evaluate(()=>localStorage.setItem('shell:style','light'));
 await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='light'&&!document.documentElement.classList.contains('dark'));
 await control.evaluate(()=>localStorage.setItem('shell:style','auto'));
 await page.emulateMedia({colorScheme:'dark'});await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
 await page.emulateMedia({colorScheme:'light'});await piFrame.waitForFunction(()=>document.documentElement.dataset.theme==='light');
 console.log('PASS Pi iframe follows Cockpit light, dark, auto and preserves native preference');
}finally{if(browser)await browser.close();child.kill('SIGTERM');await Promise.all([new Promise(r=>cockpit.close(r)),new Promise(r=>pi.close(r))]);}
