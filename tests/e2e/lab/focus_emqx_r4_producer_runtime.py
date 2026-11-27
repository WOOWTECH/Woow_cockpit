#!/usr/bin/python3
"""Future leased producer: fresh synthetic source -> actual package target -> actual product candidate.

No existing candidate/volume input, application selection, package execution, image pull or device provisioning.
"""
import io
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import sys
import tarfile
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_profile as profile
import focus_emqx_r4_runtime as rt
from woowbackup import ha_emqx as emqx, tempctr
from woowbackup.errors import BackupError


class PackageRunner(rt.Runner):
    """Adds only three exact files from this job's own profile volume to the existing fixture guard."""
    def __init__(self):self.profile_bindings={};self.profile_volume=None

    def validate(self,args):
        checked=list(args)
        if checked[0]=='run':
            for i,value in enumerate(checked):
                if value=='--volume':
                    source=checked[i+1].split(':',1)[0]
                    if source in self.profile_bindings:
                        target=self.profile_bindings[source]
                        if checked[i+1]!=source+':'+target+':ro':raise ValueError('exact_readonly_profile_mount_required')
                        # Guard the same owned source volume/target; actual argv keeps the verified file bind.
                        checked[i+1]=self.profile_volume+':'+target+':ro'
        super().validate(checked)


def package_mounts(tmp,runner,package,ids):
    if ids!=(1000,1000):raise ValueError('exact_image_user_required')
    tmp.volume('package-files')
    paths={'base.hocon':'/opt/emqx/etc/base.hocon','acl.conf':'/opt/emqx/etc/acl.conf',
           'bootstrap.csv':'/opt/emqx/etc/woow-mqtt-bootstrap.csv'}
    bodies={'base.hocon':package['config/base.hocon'],'acl.conf':package['config/acl.conf'],
            'bootstrap.csv':profile.secret_values()['woow-emqx-mqtt-bootstrap']}
    def write(out):
        with tarfile.open(fileobj=out,mode='w|') as archive:
            root=tarfile.TarInfo('.');root.type=tarfile.DIRTYPE;root.uid=root.gid=1000;root.mode=0o755;archive.addfile(root)
            for name,data in bodies.items():
                item=tarfile.TarInfo(name);item.uid=item.gid=1000;item.mode=0o400 if name=='bootstrap.csv' else 0o444
                item.size=len(data);archive.addfile(item,io.BytesIO(data))
    tmp.volume_import('package-files',write)
    volume=tmp.name('package-files')
    mount=runner.podman('volume','inspect','--format','{{.Mountpoint}}',volume).stdout.decode().strip()
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+/volumes/'+re.escape(volume)+r'/_data',mount):
        raise ValueError('owned_profile_volume_path_required')
    runner.profile_volume=volume;runner.profile_bindings={mount+'/'+name:target for name,target in paths.items()}
    return [(source,target,'ro') for source,target in runner.profile_bindings.items()]


def target_record(tmp):
    read=rt.exec_read(tmp,'emqx-ha')
    result=emqx.readback_record(emqx.boot_form(read),emqx.table_receipts(read));artifact.check_record(result)
    return result


def assert_package_target(tmp):
    config=emqx.boot_form(rt.exec_read(tmp,'emqx-ha'))
    rt.check('package_dashboard_backend_from_first_boot',config['dashboard']['listeners']['http']['bind']=='0.0.0.0:18093')
    rt.check('package_ws_entrance_from_first_boot',config['listeners']['ws']['entrance']['bind']=='127.0.0.1:8093')
    rt.check('actual_package_bootstrap_path',config['authentication'][0]['bootstrap_file']=='/opt/emqx/etc/woow-mqtt-bootstrap.csv')
    rt.check('actual_target_account_works',rt.mqtt_probe(tmp,'emqx-ha','r4_target','r4-owned-target-password')==0)


def main(context):
    case_id=context['case']
    if case_id not in artifact.CASES or context['profile_sha256']!=profile.receipt()['sha256']:
        raise ValueError('exact_package_profile_case_required')
    rt.JOB=time.strftime('j%Y%m%dT%H%M%SZ-',time.gmtime())+secrets.token_hex(4)
    (ROOT/'job.json').write_text(json.dumps({'job_id':rt.JOB,'source_commit':context['source_commit']}))
    resource.setrlimit(resource.RLIMIT_FSIZE,(artifact.MAX_DATA,artifact.MAX_DATA))
    def alarm(_s,_f):raise TimeoutError('producer_wall_budget')
    signal.signal(signal.SIGALRM,alarm);signal.alarm(840)
    rt.check('appowner_only',os.getuid()==1019 and Path.home()==Path('/home/appowner') and ROOT.parent==Path.home())
    rt.check('device_headroom',int(Path('/sys/fs/cgroup/memory.max').read_text())-int(Path('/sys/fs/cgroup/memory.current').read_text())>=1900*1024**2)
    rt.check('disk_floor',shutil.disk_usage(ROOT).free>=13*1024**3+artifact.MAX_STAGE)
    runner=PackageRunner()
    rt.check('nested_rootless',runner.podman('info','--format','{{.Host.Security.Rootless}}').stdout.strip()==b'true')
    rt.check('exact_image',runner.podman('image','inspect',artifact.IMAGES['broker'],'--format','{{.Id}}').stdout.decode().strip().removeprefix('sha256:')==artifact.IMAGES['broker'][7:])
    before=rt.inventory(runner);package=profile.package_bytes(ROOT/'package')
    fixture=ROOT/'fixture';fixture.mkdir(mode=0o755)
    for name,body in rt.fx.files().items():
        path=fixture/name;path.write_bytes(body);path.chmod(0o644)
    (fixture/'dead-update.json').write_text(json.dumps(rt.fx.dead_row_update()))
    mount=[(str(fixture),'/fixture','ro')];staging=ROOT/'staging';staging.mkdir(mode=0o700)
    work=SimpleNamespace(runner=lambda _:runner,guard=rt.Budget(),abort=None,checkpoint=lambda:None,log=lambda _:None)
    app=SimpleNamespace(id='emqx')
    with tempctr.TempObjects(runner,rt.JOB,memory='768m',pids=256,cpus='0.5') as tmp:
        ids=tmp.user_ids('ids',artifact.IMAGES['broker'],'emqx')
        tmp.volume('emqx-xfer');tmp.volume_import('emqx-xfer',lambda out:emqx._folder_tar(out,'out',*ids))
        def boot(data,log,env,files):
            tmp.run('emqx-ha',artifact.IMAGES['broker'],[],detach=True,read_only_root=True,env=env,
                volumes=[(tmp.name(data),emqx.DATA_TARGET,None),(tmp.name(log),emqx.LOG_TARGET,None),
                         (tmp.name('emqx-xfer'),'/work',None)]+files)
            emqx.wait_ready(tmp,'emqx-ha',checkpoint=work.checkpoint)
            rt.check('source_or_target_ticker_paused',emqx.quiesce_system_ticker(tmp,'emqx-ha') is not None)
        rt.STAGE='fresh_synthetic_source'
        rt.seed(tmp,'source',rt.fx.config(case_id),rt.fx.SOURCE_ACL,ids);tmp.volume('source-log')
        boot('source','source-log',{'EMQX_NODE__NAME':rt.fx.NODE,'ERL_AFLAGS':'+S 1:1',
                                  'EMQX_DASHBOARD__DEFAULT_PASSWORD':rt.fx.DUMMY_PASSWORD},mount)
        if case_id=='dead_row':
            rt.check('plain_row_initially_logs_in',rt.mqtt_probe(tmp,'emqx-ha')==0)
            emqx.ctl(tmp,'emqx-ha',['conf','load','--replace','/fixture/dead-update.json'])
            rt.check('ordinary_algorithm_change_leaves_dead_row',rt.mqtt_probe(tmp,'emqx-ha')!=0)
        else:
            rt.check('fresh_source_login',rt.mqtt_probe(tmp,'emqx-ha',None,None)==0 if case_id=='noauth' else rt.mqtt_probe(tmp,'emqx-ha')==0)
        readings=rt.read_source(tmp);raw=emqx.read_effective_config(rt.exec_read(tmp,'emqx-ha'))
        output=emqx.ctl(tmp,'emqx-ha',['data','export','--root-keys',','.join(x for x in emqx.DATA_ROOTS if x in raw),
            '--table-sets',','.join(emqx.TABLE_SETS),'--dir','/work/out'],timeout=180).stdout
        found=emqx.EXPORT_RE.search(output or b'');rt.check('real_vendor_export',found is not None)
        export=emqx.take_export(work,tmp,found.group(1).decode(),staging)
        tmp.stop('emqx-ha',timeout=60);tmp.remove('emqx-ha')
        rt.STAGE='fresh_package_target'
        rt.seed(tmp,'device',{},rt.fx.TARGET_ACL,ids);tmp.volume('device-log')
        files=package_mounts(tmp,runner,package,ids)+mount
        boot('device','device-log',dict(profile.ENV),files);assert_package_target(tmp)
        original=target_record(tmp)
        target=SimpleNamespace(container=tmp.name('emqx-ha'),data_volume=tmp.name('device'),log_volume=tmp.name('device-log'),
            image=artifact.IMAGES['broker'],env=dict(profile.ENV),files=files,secrets=[],publish=[],other_publish=[],tunnels=[])
        rt.STAGE='product_candidate_from_actual_package_target'
        notes={};seeded,counts,_,_=emqx.candidate_from_target(work,app,tmp,target,staging,export,ids,readings=readings,notes=notes)
        rt.check('vendor_counts_match',not emqx.check_counts(readings['counts'],seeded,counts))
        sink=rt.lines(tmp,target,readings,notes)
        found={item.id:item for item in sink.found};case=rt.fx.BY_ID[case_id]
        for name in case.confirms:rt.check('confirm_'+name,name in found and found[name].level=='confirm')
        for name in case.notices:rt.check('notice_'+name,name in found and found[name].level=='notice')
        keys=[item.key('emqx') for item in sink.found if item.level=='confirm']
        if keys:
            try:rt.lines(tmp,target,readings,notes,[])
            except BackupError as error:rt.check('no_ack_refuses',error.code=='confirmation-required')
            else:rt.check('no_ack_refuses',False)
            rt.lines(tmp,target,readings,notes,keys);rt.check('exact_ack_accepted')
        emqx.write_marker(tmp);record=emqx.candidate_readback(tmp,notes=notes);artifact.check_record(record)
        rt.check('complete_candidate_receipt')
        tmp.stop('emqx-new',timeout=60);runner.podman('start',tmp.name('emqx-new'));emqx.wait_ready(tmp,'emqx-new',checkpoint=work.checkpoint)
        rt.check('restart_ticker_paused',emqx.quiesce_system_ticker(tmp,'emqx-new') is not None)
        rt.check('full_roots_and_tables_stable_after_restart',not emqx.compare_readback(record,emqx.candidate_readback(tmp)))
        if case_id=='noauth':rt.check('anonymous_still_enabled',rt.mqtt_probe(tmp,'emqx-new',None,None)==0)
        elif case_id=='dead_row':rt.check('dead_row_still_dead',rt.mqtt_probe(tmp,'emqx-new')!=0)
        else:rt.check('source_account_still_works',rt.mqtt_probe(tmp,'emqx-new')==0)
        rt.verify(tmp,record)
        rt.check('package_target_config_and_tables_unchanged',not emqx.compare_readback(original,target_record(tmp)))
        rt.STAGE='owned_candidate_artifact_export'
        owned_files=[p for p in ROOT.rglob('*') if p.is_file()]
        if any(p.is_symlink() for p in owned_files) or sum(p.stat().st_size for p in owned_files)>artifact.MAX_STAGE-artifact.MAX_DATA:
            raise ValueError('combined_source_staging_artifact_budget')
        hashes=artifact.export_candidate(tmp,ROOT/'artifact',case=case_id,source_commit=context['source_commit'],
            record=record,target_record=original)
        rt.check('actual_profile_material_and_artifact_verified')
    rt.STAGE='cleanup'
    rt.check('tempobjects_empty',not tmp.containers and not tmp.volumes and not tmp.networks)
    after=rt.inventory(runner);rt.check('durable_images_volumes_unchanged',after[1:]==before[1:])
    return {'ok':True,'case':case_id,'job_id':rt.JOB,'checks':rt.CHECKS,'profile_sha256':profile.receipt()['sha256'],
            'source_commit':context['source_commit'],'artifact_hashes':hashes,'scope':'fresh generated package-target candidate; package smoke not executed',
            'unrelated_container_churn':after[0]!=before[0]}


if __name__=='__main__':
    try:result=main(json.loads((ROOT/'context.json').read_text()))
    except Exception as error:result={'ok':False,'stage':rt.STAGE,'reason':type(error).__name__,'checks':rt.CHECKS,'job_id':rt.JOB}
    print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['ok'] else 1)
