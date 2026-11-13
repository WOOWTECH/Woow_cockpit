import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code=fs.readFileSync('pi-web-integration/package/app.js','utf8')
 .replaceAll('__GATEWAY_HOST__','192.168.2.46')
 .replaceAll('__VPN_HOST__','100.112.140.82')
 .replaceAll('__GATEWAY_PORT__','19094');
function render(host,protocol,publicOrigin=''){
 const elements=Object.fromEntries(['pi','unavailable','secure-required','secure-link'].map(id=>[id,{hidden:false}]));
 const messages=[];elements.pi.addEventListener=()=>{};elements.pi.contentWindow={postMessage:(...args)=>messages.push(args)};
 const root={classList:{toggle(){}},style:{}};
 const window={location:{hostname:host,protocol,port:'9090',origin:`${protocol}//${host}`},matchMedia:()=>({matches:false,addEventListener(){}}),addEventListener(){}};
 vm.runInNewContext(code.replaceAll('__PUBLIC_ORIGIN__',publicOrigin),{window,document:{getElementById:id=>elements[id],documentElement:root},localStorage:{getItem:()=>null}});
 elements.messages=messages;
 return elements;
}
test('embedded Pi Web selects only configured HTTP LAN or VPN hosts',()=>{
 for(const host of ['192.168.2.46','100.112.140.82']){
  const e=render(host,'http:');assert.equal(e.pi.src,`http://${host}:19094/`);assert.equal(e.messages[0][1],`http://${host}:19094`);assert.equal(e.messages[0][0].theme,'light');
 }
 const https=render('100.112.140.82','https:');assert.equal(https.pi.hidden,true);assert.equal(https['secure-required'].hidden,false);assert.equal(https['secure-link'].href,'http://100.112.140.82:9090/');
 const bad=render('example.com','https:');assert.equal(bad.pi.hidden,true);assert.equal(bad.unavailable.hidden,false);
});

test('configured Cloudflare HTTPS origin opens Pi Web on the same origin',()=>{
 const e=render('cockpit.example.test','https:','https://cockpit.example.test');
 assert.equal(e.pi.src,'https://cockpit.example.test/pi-web/');
 assert.equal(e.messages[0][1],'https://cockpit.example.test');
 assert.equal(e.messages[0][0].theme,'light');
 const bad=render('other.example.test','https:','https://cockpit.example.test');
 assert.equal(bad.pi.hidden,true);
 assert.equal(bad.unavailable.hidden,false);
});

test('Pi Web is registered in the Cockpit tools section',()=>{
 const manifest=JSON.parse(fs.readFileSync('pi-web-integration/package/manifest.json','utf8'));
 assert.equal(manifest.tools.index.label,'Pi Web');
 assert.equal(manifest.menu,undefined);
});
