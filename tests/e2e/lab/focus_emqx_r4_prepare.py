#!/usr/bin/env python3
"""Preparation-only by default. Future producer/cache exports require NEW exact coordinator leases.

Uses only the isolated dev-d owner wrapper, never host Podman, package scripts or a new device.
"""
import argparse
import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
STATE=Path('/tmp/parity-focus-20261127')
sys.path.insert(0,str(HERE))
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_profile as profile

PLAN={'prepared_only':True,'native_executed':False,'device':'woowbk-dev-d','profile_sha256':profile.receipt()['sha256'],
      'images':artifact.IMAGES,'phases':['producer','images'],'requires':'new exact source/profile/case/cache-export lease',
      'brokers_max':2,'each_memory_mib':768,'each_cpus':0.5,'each_pids':256,'wall_seconds':900,
      'artifact_or_archives_mib_max':512,'host_memory_floor_mib':1200,'device_headroom_mib':1900,
      'disk_reserve_gib':13,'ports':0,'network':'none','pull_load_tag_install_or_upgrade':False}

BOOTSTRAP='''import io,json,pathlib,re,subprocess,sys,tarfile
context=json.loads(sys.argv[1]);token=context['payload_token']
assert re.fullmatch('[0-9a-f]{12}',token)
root=pathlib.Path.home()/('woowbk-r4-prepare-'+token);root.mkdir(mode=0o700)
raw=sys.stdin.buffer.read(16777217);assert len(raw)<=16777216
with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
 for m in archive:
  p=pathlib.PurePosixPath(m.name)
  assert m.isfile() and not p.is_absolute() and '..' not in p.parts and m.size<=4194304
  out=root.joinpath(*p.parts);out.parent.mkdir(parents=True,exist_ok=True)
  with out.open('xb') as stream:stream.write(archive.extractfile(m).read())
(root/'context.json').write_text(json.dumps(context,sort_keys=True));(root/'context.json').chmod(0o600)
name='producer_runtime' if context['phase']=='producer' else 'cached_images'
p=subprocess.run([sys.executable,'-B','-I',str(root/('focus_emqx_r4_'+name+'.py'))],capture_output=True,timeout=870)
sys.stdout.buffer.write(p.stdout);sys.exit(p.returncode)
'''

READ_ONE='''import pathlib,re,sys
root=pathlib.Path(sys.argv[1]);name=sys.argv[2];maximum=int(sys.argv[3])
assert root.parent==pathlib.Path.home() and re.fullmatch('woowbk-r4-prepare-[0-9a-f]{12}',root.name) and not root.is_symlink()
assert name in ('candidate.tar','candidate.json','broker.oci.tar','entrance.oci.tar','client.oci.tar','images.json')
p=root/'artifact'/name;assert not p.parent.is_symlink() and not p.is_symlink() and p.is_file() and p.stat().st_size<=maximum
with p.open('rb') as stream:
 total=0
 while True:
  body=stream.read(1048576)
  if not body:break
  total+=len(body);assert total<=maximum;sys.stdout.buffer.write(body)
'''

CLEAN_PAYLOAD='''import json,pathlib,re,shutil,subprocess,sys
context=json.loads(sys.argv[1]);root=pathlib.Path.home()/('woowbk-r4-prepare-'+context['payload_token'])
assert re.fullmatch('woowbk-r4-prepare-[0-9a-f]{12}',root.name) and not root.is_symlink()
assert not (root/'context.json').is_symlink() and json.loads((root/'context.json').read_text())==context
if context['phase']=='producer' and (root/'job.json').exists():
 assert not (root/'job.json').is_symlink()
 job=json.loads((root/'job.json').read_text());assert job['source_commit']==context['source_commit']
 assert re.fullmatch('j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',job['job_id'])
 prefix='woowbk-'+job['job_id']+'-'
 for args in (['ps','-a','--format','{{.Names}}'],['volume','ls','--format','{{.Name}}'],['network','ls','--format','{{.Name}}']):
  p=subprocess.run(['podman',*args],capture_output=True,timeout=60);assert p.returncode==0
  assert not any(x.startswith(prefix) for x in p.stdout.decode().splitlines())
shutil.rmtree(root);print('owned_preparation_payload_removed')
'''


def validate_lease(doc,commit,*,cleanup=False,now=None):
    now=now or datetime.datetime.now(datetime.timezone.utc)
    expiry=datetime.datetime.fromisoformat(doc['expires']);phase=doc.get('phase');case=doc.get('generated_case')
    expected='EMQX-R4-package-producer:'+str(case) if phase=='producer' else 'EMQX-R4-cached-image-export'
    if (expiry.tzinfo is None or (expiry-now).total_seconds()<(300 if cleanup else 1200)
            or phase not in ('producer','images') or (phase=='producer' and case not in artifact.CASES)
            or (phase=='images' and case is not None) or doc.get('case')!=expected
            or doc.get('source_commit')!=commit or doc.get('device')!='woowbk-dev-d'
            or doc.get('profile_sha256')!=profile.receipt()['sha256'] or doc.get('image_configs')!=artifact.IMAGES
            or doc.get('package_commands') is not False or doc.get('inputs')!='controlled-generated-only'
            or doc.get('artifact_export') is not True or bool(doc.get('cleanup_only'))!=cleanup
            or not re.fullmatch('[0-9a-f]{12}',doc.get('payload_token',''))):
        raise ValueError('new_exact_preparation_lease_required')
    output=Path(doc['output_dir'])
    stem='producer-'+case if phase=='producer' else 'images'
    if output.parent!=STATE or output.name!='emqx-r4-prepared-'+stem+'-'+doc['payload_token']:
        raise ValueError('exact_owned_output_directory_required')
    return {'kind':'emqx-r4-owned-preparation','phase':phase,'case':case,'source_commit':commit,
            'profile_sha256':profile.receipt()['sha256'],'payload_token':doc['payload_token']}


def bundle():
    data=[]
    for name in ('artifact','profile','fixtures','runtime','producer_runtime','cached_images'):
        path=HERE/('focus_emqx_r4_'+name+'.py');data.append((path.name,path.read_bytes()))
    data += [('woowbackup/'+p.name,p.read_bytes()) for p in sorted((ROOT/'backup-engine/woowbackup').glob('*.py'))]
    package_root='/home/woowtechopenclaw/Woow_podman_emqx'
    for name,expected in profile.PACKAGE_FILES.items():
        body=subprocess.check_output(['git','-C',package_root,'show',profile.PACKAGE_COMMIT+':'+name],timeout=60)
        if profile.sha(body)!=expected:raise ValueError('immutable_package_blob_mismatch')
        data.append(('package/'+name,body))
    result=io.BytesIO()
    with tarfile.open(fileobj=result,mode='w') as archive:
        for name,body in data:
            if len(body)>4*1024**2:raise ValueError('source_member_budget')
            item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o600;archive.addfile(item,io.BytesIO(body))
    if result.tell()>16*1024**2:raise ValueError('source_bundle_budget')
    return result.getvalue()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    parser.add_argument('--cleanup',action='store_true');parser.add_argument('--lease',type=Path)
    args=parser.parse_args(argv)
    if not args.run:print(json.dumps(PLAN,sort_keys=True));return 0
    if not args.lease or args.lease.is_symlink():raise ValueError('new_lease_required')
    import dev_d_guard
    commit=dev_d_guard.head(ROOT)
    if not dev_d_guard.clean_tree(ROOT)[0]:raise ValueError('commit_preparation_code_first')
    lease=json.loads(args.lease.read_text());context=validate_lease(lease,commit,cleanup=args.cleanup)
    output=Path(lease['output_dir']);device_root='/home/appowner/woowbk-r4-prepare-'+context['payload_token']
    owner=HERE/'owner.sh';dev_d_guard.verify_isolation(owner)
    if args.cleanup:
        if artifact.sha_file(output/'result.json',1024**2)!=lease.get('result_sha256'):raise ValueError('cleanup_result_lease_binding')
        original=json.loads((output/'result.json').read_text())
        if original['context']!=context:raise ValueError('cleanup_context_binding')
    else:
        available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        if available<1200*1024 or shutil.disk_usage(STATE).free<13*1024**3+artifact.MAX_STAGE:raise ValueError('preparation_resource_floor')
        payload=bundle()
        if output.exists() or output.is_symlink():raise ValueError('fresh_owned_output_required')
        output.mkdir(mode=0o700)
    command=['bash',str(owner),'d','python3','-B','-I','-c']
    fd,_=dev_d_guard.acquire(timeout=15)
    work_deadline=time.monotonic()+(0 if args.cleanup else 900)
    def bounded_run(*parts,cleanup=False,**kwargs):
        remaining=work_deadline+(300 if cleanup else 0)-time.monotonic()
        if remaining<=0:raise TimeoutError('preparation_wall_budget')
        kwargs['timeout']=min(kwargs.get('timeout',120),remaining)
        return subprocess.run(*parts,**kwargs)
    doc={'ok':False,'context':context,'device_payload':device_root,'payload_removed':False,'package_commands':False}
    try:
        validate_lease(lease,commit,cleanup=args.cleanup);dev_d_guard.verify_isolation(owner)
        if args.cleanup:
            process=bounded_run([*command,CLEAN_PAYLOAD,json.dumps(context,sort_keys=True)],capture_output=True,timeout=240,cleanup=True)
            if process.returncode or process.stdout.strip()!=b'owned_preparation_payload_removed':raise ValueError('owned_payload_cleanup_unproven')
            original['payload_removed']=True;(output/'result.json').write_text(json.dumps(original,sort_keys=True)+'\n')
            print(json.dumps({'ok':True,'payload_removed':True}));return 0
        process=bounded_run([*command,BOOTSTRAP,json.dumps(context,sort_keys=True)],input=payload,capture_output=True,timeout=900)
        rows=process.stdout.strip().splitlines();native=json.loads(rows[-1]) if rows else {'ok':False,'reason':'no_fixed_result'}
        doc['native']=native
        if process.returncode or not native.get('ok'):raise ValueError('preparation_native_failed')
        if context['phase']=='producer':
            files={'candidate.tar':artifact.MAX_DATA,'candidate.json':256*1024}
        else:files={**{role+'.oci.tar':artifact.MAX_STAGE for role in artifact.IMAGES},'images.json':256*1024}
        used=0
        for name,maximum in files.items():
            path=output/(name+'.partial')
            with path.open('xb') as stream:
                result=bounded_run([*command,READ_ONE,device_root,name,str(maximum)],stdout=stream,stderr=subprocess.PIPE,timeout=180)
            used+=path.stat().st_size
            if result.returncode or used>artifact.MAX_STAGE:raise ValueError('bounded_transfer_failed')
            path.chmod(0o600);path.rename(output/name)
        if context['phase']=='producer':
            artifact.verify_candidate(output/'candidate.tar',output/'candidate.json',case=context['case'],source_commit=commit,
                data_sha=native['artifact_hashes']['data_sha256'],manifest_sha=native['artifact_hashes']['manifest_sha256'])
        else:
            for role,identity in artifact.IMAGES.items():
                facts=artifact.verify_oci(output/(role+'.oci.tar'),identity)
                if facts['archive_sha256']!=native['archives'][role]:raise ValueError('archive_transfer_hash_mismatch')
            if artifact.sha_file(output/'images.json',256*1024)!=native['provenance_sha256']:raise ValueError('image_provenance_transfer_hash')
        process=bounded_run([*command,CLEAN_PAYLOAD,json.dumps(context,sort_keys=True)],capture_output=True,timeout=240,cleanup=True)
        if process.returncode or process.stdout.strip()!=b'owned_preparation_payload_removed':raise ValueError('owned_payload_cleanup_unproven')
        doc.update(ok=True,payload_removed=True)
    except Exception as error:doc['reason']=type(error).__name__
    finally:
        try:
            dev_d_guard.verify_isolation(owner,run=lambda *parts,**kwargs:bounded_run(*parts,cleanup=True,**kwargs))
        except Exception as error:
            doc.update(ok=False,final_isolation_error=type(error).__name__)
            if args.cleanup:
                original['cleanup_isolation_final_error']=type(error).__name__
                (output/'result.json').write_text(json.dumps(original,sort_keys=True)+'\n')
            raise
        finally:
            os.close(fd)
            if not args.cleanup:
                (output/'result.json').write_text(json.dumps(doc,sort_keys=True)+'\n');(output/'result.json').chmod(0o600)
    print(json.dumps(doc,sort_keys=True));return 0 if doc['ok'] else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:print(json.dumps({'ok':False,'reason':type(error).__name__}));raise SystemExit(1)
