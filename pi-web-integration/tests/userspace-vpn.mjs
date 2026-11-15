import assert from 'node:assert/strict';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';

const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
const cockpit=http.createServer((req,res)=>res.writeHead(req.headers.cookie==='cockpit=valid'?200:401).end());
let piEnabled=true;
const pi=http.createServer((req,res)=>{
 if(req.url==='/api/web-auth')res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({enabled:piEnabled}));
 else res.writeHead(200,{'content-type':'text/plain'}).end('native Pi');
});
const cp=await listen(cockpit),pp=await listen(pi),probe=http.createServer(),gp=await listen(probe);
await new Promise(resolve=>probe.close(resolve));
const authority=`100.64.0.2:${gp}`;
const env={...process.env,PI_GATEWAY_BIND:'127.0.0.1',PI_GATEWAY_HOST:'100.64.0.2',PI_GATEWAY_PORT:String(gp),PI_GATEWAY_COCKPIT_PORT:String(cp),PI_GATEWAY_UPSTREAM_PORT:String(pp),PI_GATEWAY_COCKPIT_BROWSER_PORT:'9090'};
async function rejected(extra){
 const child=spawn(process.execPath,['pi-web-integration/gateway.mjs'],{env:{...env,...extra},stdio:'ignore'});
 assert.notEqual((await once(child,'exit'))[0],0);
}
function request(headers={},method='GET'){
 return new Promise((resolve,reject)=>{
  const req=http.request({host:'127.0.0.1',port:gp,path:'/',method,headers:{Host:authority,Cookie:'cockpit=valid',...headers}},res=>{res.resume();res.on('end',()=>{if(res.statusCode===200)assert.equal(res.headers['content-security-policy'],'frame-ancestors http://100.64.0.2:9090');resolve(res.statusCode);});});
  req.on('error',reject);req.end();
 });
}
let child;
try{
 await rejected({PI_GATEWAY_LOOPBACK_FORWARD:'0'});
 await rejected({PI_GATEWAY_LOOPBACK_FORWARD:'1',PI_GATEWAY_BIND:'0.0.0.0'});
 await rejected({PI_GATEWAY_LOOPBACK_FORWARD:'1',PI_GATEWAY_HOST:'999.64.0.2'});
 child=spawn(process.execPath,['pi-web-integration/gateway.mjs'],{env:{...env,PI_GATEWAY_LOOPBACK_FORWARD:'1'},stdio:['ignore','pipe','pipe']});
 await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('gateway exited before listening');})]);
 assert.equal(await request(),200);
 assert.equal(await request({Cookie:''}),401);
 assert.equal(await request({Cookie:'cockpit=invalid'}),401);
 assert.equal(await request({Host:`127.0.0.1:${gp}`}),403);
 assert.equal(await request({Host:'attacker.example','X-Forwarded-Host':authority}),403);
 assert.equal(await request({Origin:'http://attacker.example'}),403);
 assert.equal(await request({},'POST'),403);
 assert.equal(await request({Origin:`http://${authority}`},'POST'),200);
 piEnabled=false;assert.equal(await request(),503);
 console.log('PASS userspace VPN: explicit loopback forwarding preserves exact authority, Cockpit session, Origin and Pi login guards');
}finally{
 if(child){child.kill('SIGTERM');await once(child,'exit');}
 await Promise.all([new Promise(resolve=>cockpit.close(resolve)),new Promise(resolve=>pi.close(resolve))]);
}
