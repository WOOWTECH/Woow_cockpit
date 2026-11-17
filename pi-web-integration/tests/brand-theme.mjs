import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
const close=server=>new Promise(resolve=>server.close(resolve));
const profiles={
 woowtech:{light:{primary:'#6183fc',hover:'#6183fc',on_primary:'#111a3a'},dark:{primary:'#6183fc',hover:'#6183fc',on_primary:'#111a3a'}},
 apporo:{light:{primary:'#8B6B24',hover:'#765B1F',on_primary:'#FFFFFF'},dark:{primary:'#C49E53',hover:'#D1AF70',on_primary:'#1C1B1F'}},
};

for(const [brand,colors] of Object.entries(profiles))test(`${brand} Pi bridge follows the installed palette without changing auth or standalone preference`,async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'cockpit-brand-'));
 const file=path.join(dir,'brand.json');
 await writeFile(file,JSON.stringify({schema:1,id:brand,colors}));
 const cockpit=http.createServer((req,res)=>res.writeHead(req.headers.cookie==='cockpit=valid'?200:401).end());
 const pi=http.createServer((req,res)=>res.writeHead(200,{'content-type':'application/json'}).end('{"enabled":true}'));
 const cp=await listen(cockpit),pp=await listen(pi),probe=http.createServer(),port=await listen(probe);await close(probe);
 const child=spawn(process.execPath,['pi-web-integration/gateway.mjs'],{env:{...process.env,PI_GATEWAY_BRAND_FILE:file,PI_GATEWAY_BIND:'127.0.0.1',PI_GATEWAY_HOST:'127.0.0.1',PI_GATEWAY_PORT:String(port),PI_GATEWAY_COCKPIT_PORT:String(cp),PI_GATEWAY_UPSTREAM_PORT:String(pp)},stdio:['ignore','pipe','pipe']});
 try{
  await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('Gateway exited before listening')})]);
  const url=`http://127.0.0.1:${port}/__woow_cockpit_theme.js`;
  assert.equal((await fetch(url)).status,401);
  const response=await fetch(url,{headers:{cookie:'cockpit=valid'}});
  assert.equal(response.status,200);
  const script=await response.text();
  assert.doesNotMatch(script,/localStorage/);
  const styles=new Map(),classes=new Set(),listeners={};
  const parent={postMessage(){}};
  const root={dataset:{theme:'light'},style:{setProperty:(key,value)=>styles.set(key,value)},classList:{contains:key=>classes.has(key),toggle:(key,on)=>on?classes.add(key):classes.delete(key)}};
  const window={parent,addEventListener:(name,fn)=>{listeners[name]=fn;}};
  vm.runInNewContext(script,{window,document:{documentElement:root},MutationObserver:class{observe(){}}});
  for(const mode of ['dark','light']){
   listeners.message({origin:`http://127.0.0.1:${cp}`,source:parent,data:{type:'woow-cockpit-theme',theme:mode}});
   assert.equal(root.dataset.theme,mode);
   assert.equal(styles.get('--accent'),colors[mode].primary);
   assert.equal(styles.get('--accent-hover'),colors[mode].hover);
   assert.equal(styles.get('--accent-contrast'),colors[mode].on_primary);
  }
  listeners.message({origin:'https://evil.example',source:parent,data:{type:'woow-cockpit-theme',theme:'dark'}});
  assert.equal(root.dataset.theme,'light');
  listeners.message({origin:`http://127.0.0.1:${cp}`,source:{},data:{type:'woow-cockpit-theme',theme:'dark'}});
  assert.equal(root.dataset.theme,'light');
 }finally{child.kill();await Promise.all([close(cockpit),close(pi),rm(dir,{recursive:true,force:true})]);}
});

test('explicit missing or malformed brand configuration stops startup instead of serving another brand',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'cockpit-brand-invalid-'));
 try{
  for(const data of [null,'{}',JSON.stringify({schema:1,id:'apporo',colors:{light:{primary:'url(https://invalid.example)'}}})]){
   const file=path.join(dir,`${Math.random()}.json`);
   if(data!==null)await writeFile(file,data);
   const child=spawn(process.execPath,['pi-web-integration/gateway.mjs'],{env:{...process.env,PI_GATEWAY_BRAND_FILE:file},stdio:'ignore'});
   const [code]=await once(child,'exit');assert.notEqual(code,0);
  }
 }finally{await rm(dir,{recursive:true,force:true});}
});
