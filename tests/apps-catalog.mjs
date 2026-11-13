import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright-core';
const root=process.env.APPS_TEST_ROOT||process.cwd();
const server=createServer(async(req,res)=>{const name=new URL(req.url,'http://localhost').pathname;try{let file;if(name==='/base1/cockpit.js'){res.writeHead(200,{'content-type':'text/javascript'});res.end('');return;}else if(name==='/static/branding.css'){res.writeHead(200,{'content-type':'text/css'});res.end('');return;}else file=name.split('/').pop()||'index.html';if(!['index.html','apps.css','apps.js','stacks.js','theme.js'].includes(file))throw Error('missing');const data=await readFile(`${root}/apps-catalog/${file}`);res.writeHead(200,{'content-type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html','content-security-policy':"default-src 'self'; style-src 'self'; script-src 'self'"});res.end(data);}catch{res.writeHead(404).end();}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE||undefined});try{const context=await browser.newContext({viewport:{width:390,height:800}});const p=await context.newPage();await p.addInitScript(()=>{const unit=(id,active='active')=>({id,name:id.replace('.service',''),description:id,active,sub:'running',kind:'quadlet',can_start:true,can_stop:true,protected:false});window.calls=[];window.savedLinks={};window.open=(...args)=>window.calls.push(['open',...args]);const units=[unit('n8n.service'),unit('n8n-postgres.service'),unit('pi-web.service'),unit('custom-app.service','inactive')];window.cockpit={jump:p=>window.calls.push(['jump',p]),spawn(argv){window.calls.push(argv);let stream=()=>{};const promise=new Promise(resolve=>setTimeout(()=>{const [,cmd,scope,id,act]=argv;let x;if(cmd==='scopes')x={scopes:[{id:'user:test',owner:'test'}]};if(cmd==='inventory')x={scope:'user:test',owner:'test',services:units,containers:[{name:'standalone',unit:null,state:'running',ports:''}],warnings:[]};if(cmd==='app-links-get')x=window.savedLinks[scope+'/'+id]||{internal:'',external:''};if(cmd==='app-links-set'){x={internal:argv[4],external:argv[5]};window.savedLinks[scope+'/'+id]=x;}if(cmd==='logs')x={logs:'<img src=x onerror=alert(1)> log'};if(cmd==='details')x={unit:{...units.find(u=>u.id===id),metrics:{After:id==='n8n.service'?'n8n-postgres.service':'',Requires:id==='n8n.service'?'n8n-postgres.service':'',RequiredBy:id==='n8n-postgres.service'?'n8n.service':'',BoundBy:'',ConsistsOf:''}}};if(cmd==='action'){units.find(u=>u.id===id).active=act==='stop'?'inactive':'active';x={ok:true};}stream(JSON.stringify(x));resolve('');},5));promise.stream=fn=>{stream=fn};promise.close=()=>{};return promise;}}});p.on('dialog',dialog=>dialog.accept());await p.goto(`http://127.0.0.1:${server.address().port}/woowtechapps/index.html`);await p.getByRole('heading',{name:'n8n'}).waitFor();
// Cockpit changes shell:style from a separate browsing context.
const themeController=await p.context().newPage();
await themeController.goto(`http://127.0.0.1:${server.address().port}/woowtechapps/index.html`);
const bodyBackground=()=>p.locator('body').evaluate(el=>getComputedStyle(el).backgroundColor);
const lightBackground=await bodyBackground();
await themeController.evaluate(()=>localStorage.setItem('shell:style','dark'));
await p.waitForFunction(()=>document.documentElement.classList.contains('pf-v6-theme-dark'));
assert.notEqual(await bodyBackground(),lightBackground);
assert.equal(await p.locator('.icon').first().evaluate(e=>getComputedStyle(e).color),'rgb(97, 131, 252)');
assert.equal(await p.locator('.icon').first().evaluate(e=>getComputedStyle(e).backgroundColor),'rgb(27, 33, 49)');
const iconContrast=await p.locator('.icon').first().evaluate(e=>{const css=getComputedStyle(e);const luminance=c=>{const a=c.match(/\d+/g).slice(0,3).map(Number).map(x=>x/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4);return .2126*a[0]+.7152*a[1]+.0722*a[2]};const a=luminance(css.color),b=luminance(css.backgroundColor);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05)});
assert(iconContrast>=4.5,`Brand blue needs sufficient contrast: ${iconContrast}`);

await themeController.evaluate(()=>localStorage.setItem('shell:style','light'));
await p.waitForFunction(()=>!document.documentElement.classList.contains('pf-v6-theme-dark'));
assert.equal(await bodyBackground(),lightBackground);
await themeController.evaluate(()=>localStorage.setItem('shell:style','auto'));
await p.emulateMedia({colorScheme:'dark'});
await p.waitForFunction(()=>document.documentElement.classList.contains('pf-v6-theme-dark'));
await p.emulateMedia({colorScheme:'light'});
await p.waitForFunction(()=>!document.documentElement.classList.contains('pf-v6-theme-dark'));
await themeController.close();assert.equal(await p.locator('#cards .card').count(),2);assert.equal(await p.locator('#other-cards .card').count(),2);assert.equal(await p.locator('#other-section').getAttribute('open'),null);assert.equal(await p.getByRole('heading',{name:'n8n-postgres'}).count(),0);assert.match(await p.getByRole('button',{name:/n8n/}).locator('.icon').getAttribute('title'), /n8n/);
await p.getByRole('button',{name:/n8n/}).click();assert.equal(await p.getByText('主要服務').count(),0);
assert.equal(await p.getByRole('button',{name:'返回應用軟體列表',exact:true}).locator('svg[aria-hidden=true]').count(),1);
assert.equal(await p.locator('#list-header').isVisible(),false);assert.equal(await p.locator('#status').isVisible(),false);
for(const w of [320,390,768,1440]){await p.setViewportSize({width:w,height:800});assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}

assert.equal(await p.getByRole('button',{name:'開啟對外連結'}).count(),0);
await p.getByRole('button',{name:'設定',exact:true}).click();
await p.locator('#external-url:enabled').waitFor();
await p.locator('#internal-url').fill('http://192.168.2.46:15678/');
await p.locator('#external-url').fill('http://invalid.example');
await p.getByRole('button',{name:'儲存連結'}).click();
await p.getByText('請輸入有效的區網網址，以及 HTTPS 格式的對外網址。').waitFor();
await p.locator('#external-url').fill('https://workflow.example.com/');
await p.getByRole('button',{name:'儲存連結'}).click();await p.getByText('連結已儲存。').waitFor();
await p.getByRole('button',{name:'資訊',exact:true}).click();
await p.getByRole('button',{name:'開啟對外連結'}).click();
await p.getByRole('button',{name:'開啟區網連結'}).click();
assert(await p.evaluate(()=>window.calls.some(c=>c[0]==='open'&&c[1]==='https://workflow.example.com/')));
assert(await p.evaluate(()=>window.calls.some(c=>c[0]==='open'&&c[1]==='http://192.168.2.46:15678/')));
await p.getByRole('button',{name:'設定',exact:true}).click();await p.locator('#external-url').fill('');await p.getByRole('button',{name:'儲存連結'}).click();await p.getByText('連結已儲存。').waitFor();
await p.getByRole('button',{name:'資訊',exact:true}).click();assert.equal(await p.getByRole('button',{name:'開啟對外連結'}).count(),0);await p.getByRole('button',{name:'停止整組',exact:true}).click();await p.waitForFunction(()=>window.calls.some(c=>c[1]==='action'&&c[4]==='stop'));await p.waitForFunction(()=>window.calls.some(c=>c[1]==='action'&&c[3]==='n8n-postgres.service'&&c[4]==='stop'));await p.getByRole('button',{name:'設定',exact:true}).click();assert.equal(await p.locator('#detail details').getAttribute('open'),null);await p.locator('#detail summary').click();await p.getByText('n8n-postgres.service').first().waitFor();await p.getByRole('button',{name:'日誌',exact:true}).click();await p.locator('pre').getByText('<img src=x onerror=alert(1)> log',{exact:true}).waitFor();assert.equal(await p.locator('pre img').count(),0);await p.locator('#log-service').selectOption('n8n-postgres.service');await p.waitForFunction(()=>window.calls.some(c=>c[1]==='logs'&&c[3]==='n8n-postgres.service'));assert.equal(await p.locator('pre img').count(),0);await p.getByRole('button',{name:'返回應用軟體'}).click();assert.equal(await p.locator('#list-header').isVisible(),true);assert.equal(await p.locator('#status').isVisible(),true);await p.locator('#other-section summary').click();await p.getByRole('button',{name:/standalone/}).click();await p.getByRole('button',{name:'設定',exact:true}).click();await p.getByRole('button',{name:'開啟容器管理'}).click();assert(await p.evaluate(()=>window.calls.some(c=>c[0]==='jump'&&c[1]==='/podman')));await p.getByRole('button',{name:'返回應用軟體'}).click();await p.getByRole('button',{name:/Pi Agent/}).click();await p.getByRole('button',{name:'開啟區網連結'}).click();assert(await p.evaluate(()=>window.calls.some(c=>c[0]==='jump'&&c[1]==='/woowpiweb')));for(const w of [320,390,768,1440]){await p.setViewportSize({width:w,height:800});assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}console.log('PASS Cockpit theme switching and apps grouping, controls, logs, Pi link, and responsive layout');}finally{await browser.close();await new Promise(r=>server.close(r));}
