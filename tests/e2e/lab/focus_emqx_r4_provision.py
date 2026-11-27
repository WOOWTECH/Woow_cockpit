#!/usr/bin/env python3
"""Plan only unless a NEW exact provisioning lease authorizes create/prove/smoke/cleanup of one fresh fixture.

No path to installer/upgrader, current dev-d, host Podman, original app data or real host credentials exists here.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_profile as profile

LABEL = 'io.woowtech.r4.fixture'
STATE = Path('/tmp/parity-focus-20261127')
PACKAGE_ROOT = Path('/home/woowtechopenclaw/Woow_podman_emqx')
PLAN = {'kind':'prepared-package-fixture','native_executed':False,'base':artifact.BASE,'images':artifact.IMAGES,
    'network':'none','outer_ports':0,'outer_memory_mib':2304,'outer_cpus':2,'outer_pids':2048,
    'host_memory_floor_mib':3000,'disk_floor_gib':16,'retain_disk_gib':13,'staging_mib':512,
    'runtime_wall_seconds':2100,'cleanup_seconds':300,'device_pattern':'woowbk-r4-package-<12 lowercase hex>',
    'volumes':['<device>-home','<device>-varlib','<device>-containers'],
    'requires':'reviewed lease binds source SHA, generated candidate/manifest SHA and all three verified OCI archive SHAs',
    'installer_or_upgrader':False,'dev_d_commands':0}

BOOTSTRAP = '''import os,pathlib,sys,tarfile
root=pathlib.Path('/var/lib/woowtech-backup/r4-payload')
assert not root.exists();root.mkdir(mode=0o700)
count=0;total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for m in archive:
  p=pathlib.PurePosixPath(m.name);count+=1;total+=m.size
  assert m.isfile() and not p.is_absolute() and '..' not in p.parts and count<=512 and 0<=m.size<=536870912 and total<=536870912
  dest=root.joinpath(*p.parts);dest.parent.mkdir(parents=True,exist_ok=True)
  with dest.open('xb') as out:
   src=archive.extractfile(m)
   while True:
    chunk=src.read(1048576)
    if not chunk:break
    out.write(chunk)
for path in [root,*root.rglob('*')]:
 assert not path.is_symlink();os.chown(path,1031,1031);path.chmod(0o700 if path.is_dir() else 0o600)
print('fixture_payload_staged')
'''


def valid_device(device):
    if not isinstance(device,str) or not re.fullmatch(r'woowbk-r4-package-[0-9a-f]{12}',device):
        raise ValueError('fresh_owned_device_name_required')
    return device


def volumes(device):
    valid_device(device)
    return {device+'-home':'/home',device+'-varlib':'/var/lib/woowtech-backup',device+'-containers':'/var/lib/containers'}


def validate_lease(doc, commit, *, cleanup=False, now=None):
    now=now or datetime.datetime.now(datetime.timezone.utc)
    until=datetime.datetime.fromisoformat(doc['expires'])
    required=300 if cleanup else 2400
    if (until.tzinfo is None or (until-now).total_seconds()<required or doc.get('source_commit')!=commit
        or doc.get('case') not in ('EMQX-R4-package-fixture:'+x for x in artifact.CASES)
        or doc.get('base_image')!=artifact.BASE or doc.get('image_configs')!=artifact.IMAGES
        or doc.get('inputs')!='controlled-generated-only' or doc.get('installer_or_upgrader') is not False
        or doc.get('package_smoke') is not True):
        raise ValueError('new_exact_provisioning_lease_required')
    valid_device(doc['device'])
    if not cleanup:
        for key in ('data_sha256','manifest_sha256'):
            if not artifact.HASH.fullmatch(doc.get(key,'')): raise ValueError('artifact_hash_lease_required')
        if set(doc.get('image_archives',{}))!=set(artifact.IMAGES): raise ValueError('all_image_archive_bindings_required')
        if not all(artifact.HASH.fullmatch(x) for x in doc['image_archives'].values()): raise ValueError('image_archive_hash')
    return doc['device']


def resource_floor(path, *, initial=False):
    memory=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    if memory<3000*1024 or shutil.disk_usage(path).free<(16 if initial else 13)*1024**3:
        raise ValueError('fresh_package_resource_floor')


def persist(path, doc):
    fd,name=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent);temporary=Path(name)
    with os.fdopen(fd,'w') as out:
        json.dump(doc,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
    temporary.chmod(0o600);os.replace(temporary,path)


class Controller:
    """Only isolated labpodman; exact owned device/three volumes are the only mutation/exec targets."""
    def __init__(self, device, *, run=subprocess.run):
        self.device=valid_device(device);self.run=run;self.lp=Path.home()/'.woowbk-lab/bin/labpodman'
        self.deadline=time.monotonic()+2100

    def call(self,*args,input=None,stdin=None,check=True,timeout=60,cleanup=False):
        args=list(args);verb=args[0]
        allowed=False
        if verb=='run':
            allowed=(args==self.create_args())
        elif verb in ('exec','rm','container'):
            # Exact positional target, never a matching unrelated string anywhere in argv.
            if verb=='exec':allowed=len(args)>3 and args[1]=='-i' and args[2]==self.device
            elif verb=='rm':allowed=args==['rm','--force','--volumes',self.device]
            else:allowed=args[:2] in (['container','exists'],['container','inspect']) and args[-1]==self.device
        elif verb=='volume':
            names=volumes(self.device)
            if args[1]=='create':allowed=args==['volume','create','--label',LABEL+'='+self.device,args[-1]] and args[-1] in names
            elif args[1]=='rm':allowed=args==['volume','rm',args[-1]] and args[-1] in names
            elif args[1] in ('inspect','exists'):allowed=args[-1] in names
            elif args[1]=='ls':allowed=True
        elif verb=='image':allowed=(args[:2]==['image','inspect'] and args[2]==artifact.BASE) or args[:2]==['image','ls']
        elif verb in ('ps','info'):allowed=True
        if not allowed:raise ValueError('foreign_or_unreviewed_outer_operation')
        mutating=verb in ('run','exec') or args[:2]==['volume','create']
        if mutating and not cleanup:resource_floor(STATE)
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('fixture_wall_budget')
        result=self.run([str(self.lp),*args],input=input,stdin=stdin,capture_output=True,
                        timeout=min(timeout,max(1,remaining)))
        if len(result.stdout)+len(result.stderr)>8*1024**2:raise ValueError('fixed_output_budget')
        if check and result.returncode:raise ValueError('isolated_fixture_command_failed')
        return result

    def create_args(self):
        args=['run','--detach','--name',self.device,'--hostname',self.device,'--label',LABEL+'='+self.device,
            '--pull=never','--image-volume=ignore','--network','none','--systemd=always','--privileged',
            '--device','/dev/fuse','--memory','2304m','--memory-swap','2304m','--cpus','2','--pids-limit','2048']
        for name,target in volumes(self.device).items():args+=['--volume',name+':'+target]
        return args+[artifact.BASE]

    def inventory(self):
        return [sorted(self.call(*args).stdout.decode().splitlines()) for args in
          [('ps','-a','--format','{{.ID}}'),('volume','ls','--format','{{.Name}}'),
           ('image','ls','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}')]]

    def verify_device(self, *, cleanup=False):
        line=self.call('container','inspect','--format',
            '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{.Image}} {{index .Config.Labels "'+LABEL+'"}}',
            self.device,cleanup=cleanup).stdout.decode().strip()
        parts=line.split()
        if (len(parts)!=5 or parts[1:3]!=['none','{}'] or parts[3].removeprefix('sha256:')!=artifact.BASE[7:]
            or parts[4]!=self.device or (not cleanup and parts[0]!='true')):raise ValueError('owned_device_proof')
        actual=self.call('container','inspect','--format','{{range .Mounts}}{{.Type}}:{{.Name}}:{{.Destination}};{{end}}',
                         self.device,cleanup=cleanup).stdout.decode().strip()
        rows=actual.rstrip(';').split(';')
        owned={'volume:'+k+':'+v for k,v in volumes(self.device).items()}
        tmpfs={'tmpfs::'+p for p in ('/run','/run/lock','/tmp')}
        if not owned<=set(rows) or set(rows)-owned-tmpfs:
            raise ValueError('all_outer_mounts_must_be_owned')

    def execute(self,*args,input=None,stdin=None,timeout=120):
        self.verify_device()
        return self.call('exec','-i',self.device,*args,input=input,stdin=stdin,timeout=timeout)

    def cleanup(self,receipt):
        """Name + prior-absence/intent receipt + exact label. No prune, guessed name or baseline deletion."""
        self.deadline=time.monotonic()+300
        if receipt.get('device')!=self.device or receipt.get('absent_before') is not True:
            raise ValueError('owned_creation_receipt_required')
        present=self.call('container','exists',self.device,check=False,cleanup=True).returncode
        if present==0:
            if not receipt.get('device_create_intended'):raise ValueError('no_owned_device_intent')
            self.verify_device(cleanup=True)
            self.call('rm','--force','--volumes',self.device,cleanup=True)
        elif present!=1:raise ValueError('device_absence_unproven')
        for name in volumes(self.device):
            code=self.call('volume','exists',name,check=False,cleanup=True).returncode
            if code==0:
                if name not in receipt.get('volume_create_intended',[]):raise ValueError('no_owned_volume_intent')
                label=self.call('volume','inspect','--format','{{index .Labels "'+LABEL+'"}}',name,cleanup=True).stdout.decode().strip()
                if label!=self.device:raise ValueError('foreign_volume_label')
                self.call('volume','rm',name,cleanup=True)
            elif code!=1:raise ValueError('volume_absence_unproven')
        if self.call('container','exists',self.device,check=False,cleanup=True).returncode!=1:
            raise ValueError('container_cleanup_unproven')
        for name in volumes(self.device):
            if self.call('volume','exists',name,check=False,cleanup=True).returncode!=1:raise ValueError('volume_cleanup_unproven')


def verified_inputs(args, lease):
    case=lease['case'].split(':',1)[1]
    doc=artifact.verify_candidate(args.artifact/'candidate.tar',args.artifact/'candidate.json',case=case,
        source_commit=lease['artifact_source_commit'],data_sha=lease['data_sha256'],manifest_sha=lease['manifest_sha256'])
    images={}
    for role,identity in artifact.IMAGES.items():
        path=args.images/(role+'.oci.tar');images[role]=artifact.verify_oci(path,identity)
        if images[role]['archive_sha256']!=lease['image_archives'][role]:raise ValueError('image_archive_lease_binding')
    return doc,images


def build_payload(path,args,lease,images):
    manifest=json.loads((ROOT/'snippets/focus-emqx-r4/package-provision-source.json').read_text())
    if manifest['commit']!=profile.PACKAGE_COMMIT or manifest['files']!=profile.PACKAGE_FILES:
        raise ValueError('shared_package_profile_source_binding')
    members=[]
    for relative,expected in manifest['files'].items():
        data=subprocess.check_output(['git','-C',str(PACKAGE_ROOT),'show',manifest['commit']+':'+relative])
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('reviewed_package_blob_mismatch')
        members.append(('package/'+relative,io.BytesIO(data),len(data),None))
    files=[(args.artifact/'candidate.tar','candidate.tar',lease['data_sha256']),
           (args.artifact/'candidate.json','candidate.json',lease['manifest_sha256'])]
    files +=[(args.images/(role+'.oci.tar'),role+'.oci.tar',facts['archive_sha256']) for role,facts in images.items()]
    files +=[(HERE/('focus_emqx_r4_'+name+'.py'),'focus_emqx_r4_'+name+'.py',None)
              for name in ('inner','artifact','fixtures','client_guard','package','profile')]
    files +=[(p,'woowbackup/'+p.name,None) for p in sorted((ROOT/'backup-engine/woowbackup').glob('*.py'))]
    context={'device':lease['device'],'case':lease['case'].split(':',1)[1],
        'artifact_source_commit':lease['artifact_source_commit'],'data_sha256':lease['data_sha256'],
        'manifest_sha256':lease['manifest_sha256'],'package_files':manifest['files']}
    body=json.dumps(context,sort_keys=True).encode();members.append(('context.json',io.BytesIO(body),len(body),None))
    opened=[]
    try:
        for source,name,expected in files:
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW);stream=os.fdopen(fd,'rb');opened.append(stream)
            members.append((name,stream,os.fstat(fd).st_size,expected))
        if sum(x[2]+1024 for x in members)>artifact.MAX_STAGE:raise ValueError('combined_staging_budget')
        with path.open('xb') as output,tarfile.open(fileobj=output,mode='w|') as archive:
            for name,source,size,expected in members:
                class HashReader:
                    def __init__(self):self.hash=hashlib.sha256()
                    def read(self,n):
                        data=source.read(n);self.hash.update(data);return data
                reader=HashReader();item=tarfile.TarInfo(name);item.size=size;item.mode=0o600
                archive.addfile(item,reader)
                if expected and reader.hash.hexdigest()!=expected:raise ValueError('input_changed_before_transfer')
        if path.stat().st_size>artifact.MAX_STAGE:raise ValueError('combined_staging_budget')
    finally:
        for stream in opened:stream.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    parser.add_argument('--cleanup',action='store_true');parser.add_argument('--lease',type=Path)
    parser.add_argument('--artifact',type=Path);parser.add_argument('--images',type=Path)
    args=parser.parse_args(argv)
    if not args.run:print(json.dumps(PLAN,sort_keys=True));return 0
    if not args.lease or args.lease.is_symlink():raise ValueError('new_lease_required')
    import dev_d_guard
    commit=dev_d_guard.head(ROOT)
    if not dev_d_guard.clean_tree(ROOT)[0]:raise ValueError('commit_ready_source_first')
    lease=json.loads(args.lease.read_text());device=validate_lease(lease,commit,cleanup=args.cleanup)
    path=STATE/('emqx-r4-package-'+device.removeprefix('woowbk-r4-package-')+'.recovery.json')
    if args.cleanup:
        if sha_file_receipt(path)!=lease.get('receipt_sha256'):raise ValueError('recovery_receipt_lease_binding')
        receipt=json.loads(path.read_text());controller=Controller(device)
        fd,_=dev_d_guard.acquire(timeout=15)
        try:
            finish_cleanup(controller,receipt);persist(path,receipt)
            print(json.dumps({'cleanup_complete':True,'device':device}));return 0
        finally:os.close(fd)
    if path.exists() or not args.artifact or not args.images:raise ValueError('fresh_receipt_and_inputs_required')
    resource_floor(STATE,initial=True);doc,images=verified_inputs(args,lease)
    # Snapshot and hash every transferred byte BEFORE any volume or device creation.
    with tempfile.TemporaryDirectory(prefix='emqx-r4-package-stage-',dir=STATE) as directory:
        payload=Path(directory)/'payload.tar';build_payload(payload,args,lease,images)
        controller=Controller(device);receipt={'device':device,'source_commit':commit,'phase':'preflight',
            'volume_create_intended':[],'device_create_intended':False,'absent_before':False,'cleanup_complete':False,
            'payload_sha256':artifact.sha_file(payload,artifact.MAX_STAGE),'artifact_sha256':lease['data_sha256']}
        fd,_=dev_d_guard.acquire(timeout=15)
        before=None;result={'capture_completed':False};cleanup_ok=False
        try:
            validate_lease(lease,commit);resource_floor(STATE,initial=True)
            if controller.call('info','--format','{{.Host.Security.Rootless}}').stdout.strip()!=b'true':raise ValueError('isolated_rootless_store_required')
            identity=controller.call('image','inspect',artifact.BASE,'--format','{{.Id}}').stdout.decode().strip()
            if identity.removeprefix('sha256:')!=artifact.BASE[7:]:raise ValueError('base_image_mismatch')
            if controller.call('container','exists',device,check=False).returncode!=1:raise ValueError('device_name_not_fresh')
            for name in volumes(device):
                if controller.call('volume','exists',name,check=False).returncode!=1:raise ValueError('volume_name_not_fresh')
            before=controller.inventory();receipt['absent_before']=True
            receipt['before_inventory_sha256']=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest()
            persist(path,receipt)
            for name in volumes(device):
                receipt['volume_create_intended'].append(name);persist(path,receipt)
                controller.call('volume','create','--label',LABEL+'='+device,name)
            receipt['device_create_intended']=True;receipt['phase']='device_create';persist(path,receipt)
            controller.call(*controller.create_args(),timeout=120)
            # Only the fresh device's own account/systemd/subuid database can be changed here.
            controller.execute('/usr/local/sbin/woowbk-provision','--appowner-uid','1031',
                               input=b'r4-owned-disposable-login\n',timeout=180)
            controller.execute('systemctl','restart','user@1031.service',timeout=60)
            with payload.open('rb') as incoming:
                controller.execute('python3','-B','-I','-c',BOOTSTRAP,stdin=incoming,timeout=180)
            receipt['phase']='inner_prove_and_smoke';persist(path,receipt)
            process=controller.execute('/usr/local/bin/woowbk-owner','python3','-B','-I',
                '/var/lib/woowtech-backup/r4-payload/focus_emqx_r4_inner.py',timeout=1500)
            result=json.loads(process.stdout.strip().splitlines()[-1])
            if not result.get('capture_completed'):raise ValueError('fixture_proof_failed')
            receipt['result']=result
        except Exception as error:
            result={'capture_completed':False,'phase':receipt['phase'],'reason':type(error).__name__}
            receipt['result']=result
        finally:
            try:
                try:
                    if receipt['absent_before']:
                        finish_cleanup(controller,receipt);cleanup_ok=True
                except Exception as error:receipt['cleanup_error']=type(error).__name__
                receipt['cleanup_complete']=cleanup_ok;persist(path,receipt)
            finally:os.close(fd)
        print(json.dumps({'device':device,'source_commit':commit,'result':result,'cleanup_complete':cleanup_ok,
            'installer_or_upgrader_executed':False,'dev_d_commands':0,'receipt':str(path)},sort_keys=True))
        return 0 if result.get('capture_completed') and cleanup_ok else 1


def sha_file_receipt(path):
    return artifact.sha_file(path,256*1024)


def finish_cleanup(controller,receipt):
    controller.cleanup(receipt)
    current=hashlib.sha256(json.dumps(controller.inventory(),sort_keys=True).encode()).hexdigest()
    if current!=receipt['before_inventory_sha256']:raise ValueError('outer_original_inventory_changed')
    receipt['cleanup_complete']=True


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'capture_completed':False,'reason':type(error).__name__}));raise SystemExit(1)
