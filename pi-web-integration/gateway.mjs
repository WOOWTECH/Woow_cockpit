#!/usr/bin/env node
// LAN gateway for one Pi Web instance. Cockpit session AND Pi Web auth required.
import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import { Transform } from 'node:stream';

const required = key => { const value=process.env[key]; if(!value) throw Error(`Missing ${key}`); return value; };
const bind=required('PI_GATEWAY_BIND'), host=required('PI_GATEWAY_HOST'), port=Number(required('PI_GATEWAY_PORT'));
const cockpitPort=Number(process.env.PI_GATEWAY_COCKPIT_PORT||9090), piPort=Number(process.env.PI_GATEWAY_UPSTREAM_PORT||30141);
if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)||bind!==host||!Number.isInteger(port)||port<1024||port>65535) throw Error('Invalid listen configuration');
if(![cockpitPort,piPort].every(value=>Number.isInteger(value)&&value>=1&&value<=65535)) throw Error('Invalid backend port');
const authority=`${host}:${port}`, expectedOrigin=`https://${authority}`, cockpitOrigin=`https://${host}:9090`;
const tls={key:fs.readFileSync(required('PI_GATEWAY_KEY')),cert:fs.readFileSync(required('PI_GATEWAY_CERT')),minVersion:'TLSv1.2'};
const cockpitCA=fs.readFileSync(required('PI_GATEWAY_COCKPIT_CA'));
const maxBytes=128*1024*1024;
function cookies(header){
 const result={};for(const pair of String(header||'').split(';')){const i=pair.indexOf('=');if(i<1)continue;const k=pair.slice(0,i).trim();if(k==='cockpit'||k==='pi_web_session'){if(Object.hasOwn(result,k))return null;result[k]=pair.slice(i+1).trim();}}return result;
}
function validRequest(req){
 if(req.headers.host!==authority)return false;
 const origin=req.headers.origin;
 if(origin&&origin!==expectedOrigin)return false;
 if(!['GET','HEAD','OPTIONS'].includes(req.method)&&origin!==expectedOrigin)return false;
 if(req.headers['sec-fetch-site']==='cross-site')return false;
 return true;
}
function authorized(cookie){return new Promise(resolve=>{
 if(!cookie||!/^[A-Za-z0-9._~%+\/-]+=*$/.test(cookie)||cookie.length>8192)return resolve(false);
 const request=https.request({hostname:'127.0.0.1',port:cockpitPort,path:'/cockpit/login',method:'GET',ca:cockpitCA,headers:{cookie:`cockpit=${cookie}`},timeout:4000},res=>{res.resume();resolve(res.statusCode===200)});
 request.on('error',()=>resolve(false));request.on('timeout',()=>request.destroy());request.end();
});}
// Fail closed if Pi Web password protection is disabled or cannot be checked.
function piAuthEnabled(){return new Promise(resolve=>{
 let bytes=0,data='';const request=http.get({hostname:'127.0.0.1',port:piPort,path:'/api/web-auth',headers:{host:`127.0.0.1:${piPort}`},timeout:3000},res=>{
  res.on('data',chunk=>{bytes+=chunk.length;if(bytes>4096)request.destroy();else data+=chunk});
  res.on('end',()=>{try{resolve(res.statusCode===200&&JSON.parse(data).enabled===true)}catch{resolve(false)}});
 });request.on('error',()=>resolve(false));request.on('timeout',()=>request.destroy());
});}
function outgoing(req, jar){
 const headers={...req.headers,host:authority,'x-forwarded-host':authority,'x-forwarded-proto':'https'};
 delete headers['x-forwarded-for'];delete headers['x-real-ip'];delete headers['proxy-authorization'];
 delete headers.cookie;if(jar.pi_web_session)headers.cookie=`pi_web_session=${jar.pi_web_session}`;
 return headers;
}
function outputHeaders(headers){
 const copy={...headers};delete copy['x-powered-by'];
 // Do not let the upstream set or replace a Cockpit authentication cookie.
 // Browser cookies are scoped by host, not port.
 if(copy['set-cookie']) {
  const permitted=copy['set-cookie'].filter(value=>/^pi_web_session=/.test(value));
  if(permitted.length)copy['set-cookie']=permitted;else delete copy['set-cookie'];
 }
 // Limit embedded parents to the authenticated Cockpit origin; standalone remains allowed.
 const original=copy['content-security-policy'];copy['content-security-policy']=original?`${original}; frame-ancestors ${cockpitOrigin}`:`frame-ancestors ${cockpitOrigin}`;
 copy['cache-control']='no-store';return copy;
}
const server=https.createServer(tls,async(req,res)=>{
 if(!validRequest(req)){res.writeHead(403).end('Forbidden');return;}
 const jar=cookies(req.headers.cookie);
 if(!jar||!await authorized(jar.cockpit)){res.writeHead(401,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}).end('請先登入 Cockpit，然後重新載入此頁。');return;}
 if(!await piAuthEnabled()){res.writeHead(503,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}).end('Pi Web 無法連線，或尚未啟用獨立登入。');return;}
 const n=Number(req.headers['content-length']||0);if(!Number.isFinite(n)||n>maxBytes){res.writeHead(413).end('Payload too large');return;}
 let sent=false;const target=http.request({hostname:'127.0.0.1',port:piPort,path:req.url,method:req.method,headers:outgoing(req,jar)},up=>{
  sent=true;res.writeHead(up.statusCode,outputHeaders(up.headers));up.pipe(res);
  // A long SSE stream must stop after the authenticated Cockpit session is gone.
  const timer=setInterval(async()=>{if(!await authorized(jar.cockpit)||!await piAuthEnabled()){up.destroy();res.destroy()}},15000);timer.unref();res.on('close',()=>clearInterval(timer));
 });
 target.on('error',()=>{if(!sent)res.writeHead(502,{'content-type':'text/plain; charset=utf-8'}).end('Pi Web 目前無法連線。');else res.destroy()});
 let total=0;const limit=new Transform({transform(chunk,encoding,done){total+=chunk.length;done(total>maxBytes?Error('Payload too large'):null,chunk)}});
 limit.on('error',()=>{target.destroy();if(!res.headersSent)res.writeHead(413).end('Payload too large');else res.destroy()});req.pipe(limit).pipe(target);
});
// For WebSockets the browser must supply this gateway's Origin; both the
// Cockpit session and Pi Web's own upstream authorization still apply.
server.on('upgrade',async(req,socket,head)=>{
 const reject=code=>socket.end(`HTTP/1.1 ${code} Rejected\r\nConnection: close\r\n\r\n`);
 if(!validRequest(req)||req.headers.origin!==expectedOrigin){reject(403);return;}
 const jar=cookies(req.headers.cookie);
 if(!jar||!await authorized(jar.cockpit)){reject(401);return;}
 if(!await piAuthEnabled()){reject(503);return;}
 const target=http.request({hostname:'127.0.0.1',port:piPort,path:req.url,method:'GET',headers:outgoing(req,jar)});
 target.on('upgrade',(response,upstream,uphead)=>{
  let wire=`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n`;
  for(let i=0;i<response.rawHeaders.length;i+=2){const key=response.rawHeaders[i],value=response.rawHeaders[i+1];if(key.toLowerCase()==='set-cookie'&&!/^pi_web_session=/.test(value))continue;wire+=`${key}: ${value}\r\n`;}
  socket.write(wire+'\r\n');if(uphead.length)socket.write(uphead);if(head.length)upstream.write(head);socket.pipe(upstream).pipe(socket);
  const timer=setInterval(async()=>{if(!await authorized(jar.cockpit)||!await piAuthEnabled()){socket.destroy();upstream.destroy()}},15000);timer.unref();socket.on('close',()=>clearInterval(timer));upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy());
 });
 target.on('response',response=>{response.resume();reject(response.statusCode||502)});
 target.on('error',()=>socket.destroy());socket.on('error',()=>target.destroy());target.end();
});
server.headersTimeout=15000;server.requestTimeout=120000;server.maxHeadersCount=100;
server.listen(port,bind,()=>console.log(`Pi Web gateway listening on ${authority}`));
