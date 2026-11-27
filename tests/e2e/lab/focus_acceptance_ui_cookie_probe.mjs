#!/usr/bin/env node
// Read-only diagnostic login/frame/scan. Never invokes the HA wizard.
import { readFileSync, readdirSync, writeFileSync, lstatSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseSetCookie, digest, coverage, observedValues, provedPublicTombstone } from './focus_acceptance_ui_cookies.mjs';
if (process.argv.slice(2).join(' ') !== '--run') {
  console.log('Cookie probe prepared; no browser or device started');
  process.exit(process.argv.length === 2 ? 0 : 2);
}
const config = JSON.parse(readFileSync(0, 'utf8'));
if (!/^https:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(config.base)) throw new Error('invalid private origin');
const rows = [], pending = new Set(), versions = new Set();
let phase = 'initial', observationErrors = 0, browser, context, frame, finishing;
let initialJar = [], liveJar = [], rootVerified = false, failure = null;
let primarySourceVerified=false, primarySource, nativeCapability;
const result = {scope:'cookie-observer-readonly', acceptance_passed:false,
  proves_old_page4_cookie_absence:false, old_page4_result_unchanged:true};
function observe(response) {
  const url = new URL(response.url());
  if (url.origin !== config.base) return;
  const rootGet = phase === 'initial' && url.pathname === '/' && !url.search
    && response.request().method() === 'GET' && response.status() === 200;
  const work = response.headerValues('set-cookie').then(headers => {
    for (const header of headers) {
      const row = parseSetCookie(header);
      // Also scan the exact first-pair value used by the old page observer.
      const first = header.split(';', 1)[0];
      row.legacyValue = first.slice(first.indexOf('=')+1);
      rows.push({...row, rootGet});
    }
  }).catch(() => { observationErrors++; }).finally(() => pending.delete(work));
  pending.add(work);
}
async function drain() {
  const end = Date.now()+10000;
  while (pending.size) {
    if (Date.now()>end) throw new Error('cookie observation deadline');
    await Promise.race([Promise.all([...pending]), new Promise((_,reject) => {
      const t=setTimeout(() => reject(new Error('cookie observation deadline')),10000); t.unref();
    })]);
  }
}
function occurrences(data, needle) {
  let n=0, at=0;
  while ((at=data.indexOf(needle,at))>=0) { n++; at+=needle.length; }
  return n;
}
async function finish() {
  if (finishing) return finishing;
  finishing = (async () => {
    try {
      if (!context || !frame || !rootVerified) throw new Error('root handshake unavailable');
      context.off('response', observe); await drain();
      liveJar = await context.cookies();
      const cov = coverage(rows, initialJar, liveJar, observationErrors);
      const sourceVersion = versions.size===1 ? [...versions][0] : 'unknown';
      const authObserved = liveJar.some(c => c.name==='cockpit' && rows.some(r => r.name===c.name && r.value===c.value && !r.rootGet));
      const proof = {source_version:sourceVersion, administrative_root_verified:rootVerified,
        authenticated_cookie_observed:authObserved, primary_source_hashes_verified:primarySourceVerified,
        native_package_version:nativeCapability?.package_version,native_ws_binary_sha256:nativeCapability?.binary_sha256};
      const publicRows=rows.filter(r => provedPublicTombstone(r,liveJar,proof));
      const publicHashes = new Set(publicRows.map(r => digest(r.value)));
      const metadata = cov.metadata.map((r,i) => ({...r, classification:rows[i] && provedPublicTombstone(rows[i],liveJar,proof)
        ? 'proved-public-protocol-tombstone' : r.classification}));
      writeFileSync(join(config.evidence,'cookie-metadata.json'), JSON.stringify({
        phase:'before-per-value-scan',cookie_metadata:metadata,observations_complete:cov.observations_complete,
        administrative_root_verified:rootVerified,source_version:sourceVersion,native_cockpit_capability:nativeCapability,
        primary_source_hashes_verified:primarySourceVerified,primary_source_commit:primarySource.commit,
        primary_sources:primarySource.files.map(s=>({url:s.url,sha256:s.sha256})),
      },null,2)+'\n', {mode:0o600,flag:'wx'});
      const values = observedValues(rows, liveJar, initialJar);
      if (!values.length || values.some(v => !v)) throw new Error('missing cookie value');
      const report = await frame.evaluate(async ({script, values, registered, since}) => {
        const p=window.cockpit.spawn(['python3','-B','-I','-c',script], {superuser:'require',err:'ignore'});
        p.input(JSON.stringify({values,registered,since})); return JSON.parse(await p);
      }, {script:config.scan, values, registered:config.registered, since:config.since});
      let files=0, registeredHostHits=0;
      const host={};
      for (const value of values) host[digest(value)]={hits:0,categories:{}};
      for (const entry of readdirSync(config.evidence,{withFileTypes:true})) {
        if (!entry.isFile()) throw new Error('unexpected evidence path');
        const data=readFileSync(join(config.evidence,entry.name));files++;
        for (const value of config.registered) {
          const needles=[...new Set([value,JSON.stringify(value).slice(1,-1)])].filter(Boolean).map(v=>Buffer.from(v));
          registeredHostHits+=needles.reduce((n,needle)=>n+occurrences(data,needle),0);
        }
        for (const value of values) {
          const needles=[...new Set([value,JSON.stringify(value).slice(1,-1)])].map(v=>Buffer.from(v));
          const hits=needles.reduce((n,needle)=>n+occurrences(data,needle),0);
          if (hits) {
            const entry=host[digest(value)];entry.hits+=hits;
            const category=entry.categories.private_probe_evidence ||= {hits:0,matched_files:0};
            category.hits+=hits;category.matched_files++;
          }
        }
      }
      const finalJar=await context.cookies();
      const jarStable=finalJar.length===liveJar.length && finalJar.every(c=>liveJar.some(x=>x.name===c.name && x.value===c.value && x.domain===c.domain && x.path===c.path));
      const lateMetadata=coverage(rows,initialJar,finalJar,observationErrors).metadata
        .filter(c=>!metadata.some(old=>old.name===c.name && old.sha256===c.sha256));
      const matchedValues=values.map(value => {
        const hash=digest(value);
        if (!report.values[hash]) throw new Error('per-value scan missing');
        const names=[...new Set([...rows.filter(r=>r.value===value || r.legacyValue===value),
          ...initialJar.filter(r=>r.value===value),...liveJar.filter(r=>r.value===value)].map(r=>r.name))].sort();
        return {names,sha256:hash,length:Buffer.byteLength(value),
          classification:publicHashes.has(hash)?'proved-public-protocol-tombstone':'credential-zero-hits-required',
          device:report.values[hash],host:host[hash]};
      });
      const credentialsZero=matchedValues.every(v=>v.classification==='proved-public-protocol-tombstone'
        || (v.device.hits===0 && v.host.hits===0));
      Object.assign(result,{administrative_root_verified:rootVerified,source_version:sourceVersion,
        primary_source_hashes_verified:primarySourceVerified,primary_source_commit:primarySource?.commit,
        native_cockpit_capability:nativeCapability,
        cookie_metadata:metadata,match_counts:matchedValues,observations_complete:cov.observations_complete && jarStable,
        unscanned_late_jar_metadata:lateMetadata,
        public_tombstone_proofs:publicRows.map(r=>({name:r.name,sha256:digest(r.value),
          initial_https_root_get_200:true,source_version:sourceVersion,http_only:true,secure:true,
          same_site_strict:true,root_path:true,live_jar_member:false,
          source_auth_sha256:'d3ad1a818ec7b7d2270f6c36f8364f96ffe34a42018800381a78ee68100b43e7',
          source_handler_sha256:'7c6551f0a993da62ff1aecbd5382fc4087f9f6d327fe53055e3d0a931c0e9cca'})),
        authenticated_cookie_observed:authObserved,live_jar_stable_during_scan:jarStable,
        strict_credential_zero_hits:credentialsZero && jarStable,registered_credentials_zero_hits:report.registered_values_hits===0 && registeredHostHits===0,
        all_observed_values_zero_hits:jarStable && report.all_values_hits===0 && matchedValues.every(v=>v.host.hits===0),
        scanned:report.scanned,archive_index_sidecars:report.archive_index_sidecars_scanned,
        actual_archive_index_sidecars_expected:report.actual_archive_index_sidecars_expected,
        regular_json_roots:report.regular_json_roots_scanned,host_files:files});
      if (!cov.observations_complete || !jarStable || !authObserved || !credentialsZero || report.registered_values_hits || registeredHostHits)
        failure ||= 'cookie-coverage-or-credential-match';
    } catch { failure ||= 'bounded-observer-or-scan-error'; }
    if (browser) {try {await browser.close();} catch {failure ||= 'browser-close-error';}}
    Object.assign(result,{failure_kind:failure,diagnostic_completed:!failure});
    writeFileSync(join(config.evidence,'result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600,flag:'wx'});
  })();
  return finishing;
}
process.once('SIGTERM',()=>{failure='probe-timeout';finish().finally(()=>process.exit(124));});
const deadline=setTimeout(()=>process.kill(process.pid,'SIGTERM'),6*60*1000);deadline.unref();
try {
  primarySource=JSON.parse(readFileSync(new URL('./focus_acceptance_ui_cookie_source.json',import.meta.url),'utf8'));
  if (primarySource.commit!=='ca0d360e3a858a7eb189edde15cf7b976018404b' || primarySource.version!=='362' || primarySource.files.length!==2)
    throw new Error('source proof pin mismatch');
  for (const source of primarySource.files) {
    if (!['cockpitauth.c','cockpithandlers.c'].includes(source.name)
        || source.url!==`https://raw.githubusercontent.com/cockpit-project/cockpit/${primarySource.commit}/src/ws/${source.name}`)
      throw new Error('source proof URL mismatch');
    const path=join(primarySource.cache_directory,source.name);
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()
        || createHash('sha256').update(readFileSync(path)).digest('hex')!==source.sha256)
      throw new Error('source proof bytes mismatch');
  }
  primarySourceVerified=true;
  const {chromium}=await import(pathToFileURL(config.playwright).href);
  browser=await chromium.launch({executablePath:config.chromium,args:['--disable-background-networking','--disable-component-update']});
  context=await browser.newContext({ignoreHTTPSErrors:true,locale:'en-US'});
  context.on('response',observe);
  const page=await context.newPage();page.setDefaultTimeout(30000);
  page.on('websocket',ws=>ws.on('framereceived',event=>{
    if (typeof event.payload!=='string' || !event.payload.startsWith('\n')) return;
    try {const v=JSON.parse(event.payload.slice(1));if(v.command==='init' && /^\d+(?:\.\d+)*$/.test(v.system?.version||'')) versions.add(v.system.version);} catch {}
  }));
  await page.goto(config.base,{waitUntil:'domcontentloaded'});await drain();
  initialJar=await context.cookies();phase='login';
  await page.locator('#login-user-input').fill('devadmin');
  await page.locator('#login-password-input').fill(config.password);
  await page.locator('#login-button').click();await page.waitForURL('**/system',{timeout:60000});
  const indicator=page.getByRole('button',{name:/^(Limited access|Administrative access|受限存取|受限制的存取|管理員存取模式|管理員存取)$/});
  await indicator.waitFor();
  if (/Limited|受限/.test(await indicator.textContent())) {
    await indicator.click();await page.locator('#switch-to-admin-access-password').fill(config.password);
    await page.getByRole('button',{name:/^(Authenticate|認證|驗證)$/}).click();
    await page.locator('#switch-to-admin-access-password').waitFor({state:'detached'});
  }
  await page.goto(config.base+'/woowtechbackup#/backups',{waitUntil:'domcontentloaded'});
  const iframe=page.locator('iframe[src*="woowtechbackup"]');await iframe.waitFor({state:'attached'});
  frame=await (await iframe.elementHandle()).contentFrame();
  await frame.locator('[data-focus="list-upload"]').waitFor();
  const capability=await frame.evaluate(async()=>{
    const uid=await window.cockpit.spawn(['id','-u'],{superuser:'require',err:'ignore'});
    const host=await window.cockpit.spawn(['hostname'],{err:'ignore'});
    const native=await window.cockpit.spawn(['python3','-B','-I','-c',
      'import hashlib,json,subprocess; from pathlib import Path; p=Path("/usr/lib/cockpit/cockpit-ws"); assert p.is_file() and not p.is_symlink(); v=subprocess.run(["dpkg-query","-W","--showformat=${Version}","cockpit-ws"],capture_output=True,check=True,timeout=15).stdout.decode().strip(); print(json.dumps({"package_version":v,"binary_sha256":hashlib.sha256(p.read_bytes()).hexdigest()}))'],
      {superuser:'require',err:'ignore'});
    return {root:uid.trim()==='0' && host.trim()==='woowbk-dev-d',native:JSON.parse(native)};
  });
  if (!/^[0-9][A-Za-z0-9.+:~_-]{0,80}$/.test(capability.native.package_version)
      || !/^[0-9a-f]{64}$/.test(capability.native.binary_sha256)) throw new Error('invalid native capability metadata');
  rootVerified=capability.root;nativeCapability=capability.native;
} catch {failure='bounded-login-or-frame-error';}
finally {await finish();clearTimeout(deadline);}
console.log(result.diagnostic_completed?'Cookie observer diagnostic PASS (new probe only)':'Cookie observer diagnostic FAIL; fixed metadata retained');
process.exit(result.diagnostic_completed?0:1);
