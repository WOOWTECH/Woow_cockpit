// Browser installation of the generated PWA, served from an isolated local
// fixture. Production Cockpit authentication is covered by gateway tests.
import {createServer} from 'node:http';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,extname} from 'node:path';
import {spawn} from 'node:child_process';
const temp=await mkdtemp(join(tmpdir(),'cockpit-pwa-brand-'));
function run(command,args,env={}){return new Promise((ok,fail)=>{
 const child=spawn(command,args,{env:{...process.env,...env},stdio:'inherit'});
 child.once('error',fail);child.once('exit',code=>code===0?ok():fail(Error(`PWA test exited ${code}`)));
});}
try{
 for(const brand of ['woowtech','apporo']){
  const output=join(temp,brand);
  await run('python3',['pwa-gateway/render.py','--brand',brand,'--output',output]);
  const manifest=JSON.parse(await readFile(join(output,'assets/manifest.webmanifest'),'utf8'));
  const server=createServer(async(req,res)=>{
   const path=new URL(req.url,'http://localhost').pathname;
   if(path==='/'){
    res.writeHead(200,{'content-type':'text/html; charset=utf-8'}).end(`<!doctype html><html lang="zh-Hant"><head><meta name="viewport" content="width=device-width"><title>${manifest.name}</title><link rel="manifest" href="/woow-pwa/manifest.webmanifest"><meta name="theme-color" content="${manifest.theme_color}"><link rel="apple-touch-icon" href="/woow-pwa/icon-192.png"></head><body><h1>${manifest.name}</h1><p>PWA installation fixture</p><button id="login-button">登入</button></body></html>`);return;
   }
   if(!path.startsWith('/woow-pwa/')){res.writeHead(404).end();return;}
   const base=resolve(output,'assets'),file=resolve(base,path.slice('/woow-pwa/'.length));
   if(!file.startsWith(base+'/')){res.writeHead(403).end();return;}
   try{res.writeHead(200,{'content-type':extname(file)==='.png'?'image/png':'application/manifest+json'}).end(await readFile(file));}
   catch{res.writeHead(404).end();}
  });
  await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
  try{
   const env={COCKPIT_URL:`http://127.0.0.1:${server.address().port}`,COCKPIT_PASSWORD:''};
   await run(process.execPath,['pwa-gateway/test.mjs'],env);
   await run(process.execPath,['pwa-gateway/install-test.mjs'],env);
   console.log(`PASS ${brand} PWA manifest, icon retrieval, browser install and standalone launch (fixture)`);
  }finally{await new Promise(ok=>server.close(ok));}
 }
}finally{await rm(temp,{recursive:true,force:true});}
