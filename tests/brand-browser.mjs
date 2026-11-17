// Installed, isolated roots: shared real UI code + the existing fake Cockpit
// transports. No host service actions or live credentials are used here.
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn} from 'node:child_process';

const work=await mkdtemp(join(tmpdir(),'cockpit-dual-brand-'));
const evidence=process.env.BRAND_SCREENSHOTS ? resolve(process.env.BRAND_SCREENSHOTS) : null;
async function run(command,args,env={}){
 return new Promise((done,reject)=>{
  const child=spawn(command,args,{env:{...process.env,...env},stdio:'inherit'});
  child.once('error',reject);
  child.once('exit',code=>code===0?done():reject(Error(`${command} ${args.join(' ')} exited ${code}`)));
 });
}
try{
 for(const brand of ['woowtech','apporo']){
  const root=join(work,brand),ui=join(work,`${brand}-ui`);
  await mkdir(join(root,'var/lib/dpkg'),{recursive:true});
  await writeFile(join(root,'var/lib/dpkg/status'),'Package: cockpit-bridge\nStatus: install ok installed\nVersion: 362-1\n\n');
  await run('python3',['scripts/manage.py','--root',root,'install','--brand',brand,'--service-owner','tester']);
  await run('python3',['scripts/manage.py','--root',root,'verify']);
  const profile=JSON.parse(await readFile(join(root,'etc/cockpit/branding/brand.json'),'utf8'));
  assert.equal(profile.id,brand);
  await mkdir(ui);
  for(const [name,target] of Object.entries({
   branding:'etc/cockpit/branding',
   'apps-catalog':'usr/local/share/cockpit/woowtechapps',
   services:'usr/local/share/cockpit/woowtechservices',
   backup:'usr/local/share/cockpit/woowtechbackup',
  }))await symlink(join(root,target),join(ui,name),'dir');
  const env={BRAND_UI_ROOT:ui,UI_BRAND:brand};
  if(evidence){
   env.APPS_UI_SCREENSHOTS=join(evidence,brand,'applications');
   env.BACKUP_UI_SCREENSHOTS=join(evidence,brand,'backup');
  }
  console.log(`Testing installed ${brand} application controls, services and backup UI`);
  for(const file of ['apps-catalog.mjs','services-ui.mjs','backup-ui.mjs'])await run(process.execPath,[`tests/${file}`],env);
  await run(process.execPath,['tests/embedded-theme.mjs'],{PI_GATEWAY_BRAND_FILE:join(root,'etc/cockpit/branding/brand.json')});
 }
 // The two variants must call the very same privileged helpers.
 for(const relative of ['usr/local/libexec/woowtech-cockpit-services','usr/local/libexec/woowtech-cockpit-backup']){
  assert.deepEqual(await readFile(join(work,'woowtech',relative)),await readFile(join(work,'apporo',relative)));
 }
 console.log('PASS both installed brands: same helpers, application controls, service ownership, backup/restore UI and responsive themes');
}finally{await rm(work,{recursive:true,force:true});}
