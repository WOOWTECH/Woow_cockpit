import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const code=fs.readFileSync('pi-web-integration/package/app.js','utf8')
 .replaceAll('__GATEWAY_HOST__','192.168.2.46')
 .replaceAll('__VPN_HOST__','100.112.140.82')
 .replaceAll('__GATEWAY_PORT__','19094');
function render(host,protocol){
 const elements=Object.fromEntries(['pi','direct','notice','unavailable','secure-required','secure-link'].map(id=>[id,{hidden:false}]));
 vm.runInNewContext(code,{window:{location:{hostname:host,protocol,port:'9090'}},document:{getElementById:id=>elements[id]}});
 return elements;
}
test('embedded Pi Web selects only configured HTTP LAN or VPN hosts',()=>{
 for(const host of ['192.168.2.46','100.112.140.82']){
  const e=render(host,'http:');assert.equal(e.pi.src,`http://${host}:19094/`);assert.equal(e.direct.href,e.pi.src);
 }
 const https=render('100.112.140.82','https:');assert.equal(https.pi.hidden,true);assert.equal(https['secure-required'].hidden,false);assert.equal(https['secure-link'].href,'http://100.112.140.82:9090/');
 const bad=render('example.com','https:');assert.equal(bad.pi.hidden,true);assert.equal(bad.unavailable.hidden,false);
});
