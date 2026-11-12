import {test} from 'node:test';import assert from 'node:assert/strict';import http from 'node:http';import https from 'node:https';import tls from 'node:tls';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawn,spawnSync} from 'node:child_process';

test('gateway requires both protections, strips Cockpit credentials and validates requests',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pi-gateway-test-'));
 const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem');
 const gen=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});assert.equal(gen.status,0);
 let enabled=true,lastCookie='';
 const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
 const cockpit=https.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(cert)},(req,res)=>{res.writeHead(req.url==='/cockpit/login'&&req.headers.cookie==='cockpit=valid'?200:401).end()});
 const pi=http.createServer((req,res)=>{if(req.url==='/api/web-auth'){res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({enabled}));return;}lastCookie=req.headers.cookie||'';res.writeHead(200,{'Set-Cookie':['cockpit=hostile; Path=/','pi_web_session=abc; Path=/']}).end('ok')});
 pi.on('upgrade',(req,socket)=>{lastCookie=req.headers.cookie||'';socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');socket.pipe(socket)});
 const cp=await listen(cockpit),pp=await listen(pi);const probe=http.createServer();const gp=await listen(probe);await new Promise(resolve=>probe.close(resolve));
 const child=spawn(process.execPath,[path.resolve('pi-web-integration/gateway.mjs')],{env:{...process.env,PI_GATEWAY_BIND:'127.0.0.1',PI_GATEWAY_HOST:'127.0.0.1',PI_GATEWAY_PORT:String(gp),PI_GATEWAY_KEY:key,PI_GATEWAY_CERT:cert,PI_GATEWAY_COCKPIT_CA:cert,PI_GATEWAY_COCKPIT_PORT:String(cp),PI_GATEWAY_UPSTREAM_PORT:String(pp)},stdio:['ignore','pipe','pipe']});
 const request=(headers={},method='GET')=>new Promise((resolve,reject)=>{const q=https.request({hostname:'127.0.0.1',port:gp,path:'/resource',method,rejectUnauthorized:false,headers:{host:`127.0.0.1:${gp}`,...headers}},r=>{r.resume();r.on('end',()=>resolve({status:r.statusCode,headers:r.headers}))});q.on('error',reject);q.end()});
 try{
  await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('exit',code=>reject(Error(`gateway exited ${code}`)));setTimeout(()=>reject(Error('gateway startup timed out')),5000).unref()});
  assert.equal((await request()).status,401);assert.equal((await request({cookie:'cockpit=wrong'})).status,401);
  assert.equal((await request({cookie:'cockpit=valid',origin:'https://evil.example'},'POST')).status,403);
  assert.equal((await request({cookie:'cockpit=valid',host:'evil.example'})).status,403);
  let r=await request({cookie:'cockpit=valid; pi_web_session=abc'});assert.equal(r.status,200);assert.equal(lastCookie,'pi_web_session=abc');assert.deepEqual(r.headers['set-cookie'],['pi_web_session=abc; Path=/']);
  enabled=false;assert.equal((await request({cookie:'cockpit=valid'})).status,503);enabled=true;
  let handshake=await new Promise((resolve,reject)=>{const s=tls.connect({host:'127.0.0.1',port:gp,rejectUnauthorized:false},()=>s.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${gp}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nOrigin: https://127.0.0.1:${gp}\r\nCookie: cockpit=valid; pi_web_session=abc\r\n\r\n`));s.once('data',d=>{resolve(String(d));s.destroy()});s.on('error',reject)});
  assert.match(handshake,/^HTTP\/1\.1 101 /);assert.equal(lastCookie,'pi_web_session=abc');
 }finally{child.kill('SIGTERM');await Promise.all([new Promise(r=>cockpit.close(r)),new Promise(r=>pi.close(r))]);fs.rmSync(dir,{recursive:true,force:true})}
});
