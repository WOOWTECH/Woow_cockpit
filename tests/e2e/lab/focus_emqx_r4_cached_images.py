#!/usr/bin/python3
"""Future separately leased cache-only OCI export. No pull/load/tag, container, service or secret operations."""
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import focus_emqx_r4_artifact as artifact

REFS={role:(artifact.CLIENT_REF if role=='client' else identity) for role,identity in artifact.IMAGES.items()}
CLIENT_REPO_DIGEST='docker.io/library/eclipse-mosquitto@'+artifact.CLIENT_REF.split('@')[1]
STAGE='startup'
ROLE=None
POD_ERROR=None


def save_args(role,directory):
    if role not in REFS:raise ValueError('only_reviewed_cached_images')
    return ['image','save','--format','oci-archive','--output',str(Path(directory)/(role+'.oci.tar')),REFS[role]]


def cached_record(raw,role):
    doc=json.loads(raw)
    if (doc['id'].removeprefix('sha256:')!=artifact.IMAGES[role][7:] or doc['os']!='linux' or doc['arch']!='amd64'
            or not re.fullmatch('sha256:[0-9a-f]{64}',doc['manifest']) or not 0<int(doc['size'])<=artifact.MAX_STAGE):
        raise ValueError('exact_cached_config_platform_required')
    if role=='broker' and doc['manifest']!='sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937':
        raise ValueError('reviewed_broker_manifest_required')
    if role=='client' and not {CLIENT_REPO_DIGEST,artifact.CLIENT_REF}.intersection(doc['repo_digests'] or []):
        raise ValueError('unchanged_client_reference_must_resolve_in_source_cache')
    return doc


def inspect_cached(pod,role):
    if role not in REFS:raise ValueError('only_reviewed_cached_images')
    # Podman's Go field is ID; the JSON response object's Id spelling is not a template field.
    template='{"id":{{json .ID}},"manifest":{{json .Digest}},"os":{{json .Os}},"arch":{{json .Architecture}},"size":{{.Size}},"repo_digests":{{json .RepoDigests}}}'
    return cached_record(pod('image','inspect',REFS[role],'--format',template),role)


def main():
    global STAGE,ROLE,POD_ERROR
    resource.setrlimit(resource.RLIMIT_FSIZE,(artifact.MAX_STAGE,artifact.MAX_STAGE))
    def alarm(_s,_f):raise TimeoutError('cache_export_wall_budget')
    signal.signal(signal.SIGALRM,alarm);signal.alarm(840)
    STAGE='owner_guard'
    if os.getuid()!=1019 or ROOT.parent!=Path.home() or Path.home()!=Path('/home/appowner'):
        raise ValueError('existing_isolated_device_owner_required')
    STAGE='headroom_guard'
    if int(Path('/sys/fs/cgroup/memory.max').read_text())-int(Path('/sys/fs/cgroup/memory.current').read_text())<1900*1024**2:
        raise ValueError('fresh_device_headroom_required')
    def pod(*args,timeout=60):
        global POD_ERROR
        result=subprocess.run(['podman',*args],capture_output=True,timeout=timeout)
        if result.returncode or len(result.stdout)+len(result.stderr)>1024**2:
            POD_ERROR={'returncode':result.returncode,'stderr':result.stderr[:2048].decode(errors='replace')}
            raise ValueError('bounded_cached_image_operation_failed')
        return result.stdout
    STAGE='rootless_guard'
    if pod('info','--format','{{.Host.Security.Rootless}}').strip()!=b'true':raise ValueError('rootless_required')
    def inventory():return sorted(pod('image','ls','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}').decode().splitlines())
    STAGE='inventory_before'
    before=inventory();directory=ROOT/'artifact';directory.mkdir(mode=0o700)
    STAGE='source_budget'
    source_bytes=sum(p.stat().st_size for p in ROOT.rglob('*') if p.is_file())
    records={};used=0
    for role in REFS:
        ROLE=role;STAGE='inspect_before'
        cached=inspect_cached(pod,role)
        STAGE='archive_budget'
        remaining=artifact.MAX_STAGE-used-source_bytes-256*1024
        if remaining<=0:raise ValueError('combined_source_image_archive_budget')
        if shutil.disk_usage(ROOT).free<13*1024**3+remaining:raise ValueError('fresh_archive_disk_floor')
        resource.setrlimit(resource.RLIMIT_FSIZE,(remaining,artifact.MAX_STAGE))
        STAGE='save'
        pod(*save_args(role,directory),timeout=240)
        resource.setrlimit(resource.RLIMIT_FSIZE,(artifact.MAX_STAGE,artifact.MAX_STAGE))
        STAGE='archive_validate'
        path=directory/(role+'.oci.tar');path.chmod(0o600);facts=artifact.verify_oci(path,artifact.IMAGES[role])
        used+=path.stat().st_size
        if used>artifact.MAX_STAGE:raise ValueError('combined_image_archive_budget')
        STAGE='inspect_after'
        if cached!=inspect_cached(pod,role):
            raise ValueError('source_image_metadata_changed')
        records[role]={'source_reference':REFS[role],'cached':cached,'archive':facts}
    ROLE=None;STAGE='inventory_after'
    if inventory()!=before:raise ValueError('cached_image_catalog_changed')
    STAGE='provenance'
    provenance={'kind':'emqx-r4-cached-image-archives','version':1,'source_device':'woowbk-dev-d',
        'source_commit':json.loads((ROOT/'context.json').read_text())['source_commit'],
        'images':records,'bytes':used,'pull_load_tag_or_container_operations':False,
        'client_literal_identity_after_load':'must be independently proven inside fresh fixture; never inferred from this receipt'}
    receipt=directory/'images.json';receipt.write_text(json.dumps(provenance,sort_keys=True)+'\n');receipt.chmod(0o600)
    return {'ok':True,'source_commit':provenance['source_commit'],'image_catalog_unchanged':True,
        'archives':{role:record['archive']['archive_sha256'] for role,record in records.items()},
        'provenance_sha256':artifact.sha_file(receipt,256*1024),'bytes':used,'container_or_device_mutation':False}


def failed_result(error):
    """Future failures retain bounded private diagnostics; stdout has fixed stage/type only."""
    private={'stage':STAGE,'role':ROLE,'type':type(error).__name__,'message':str(error)[:1024],
             'pod_error':POD_ERROR}
    saved=False
    try:
        body=(json.dumps(private,ensure_ascii=False,sort_keys=True)+'\n').encode()
        if len(body)>16384:raise ValueError('private_diagnostic_budget')
        fd=os.open(ROOT/'cache-error.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body)
        saved=True
    except (OSError,ValueError):pass
    return {'ok':False,'reason':type(error).__name__,'stage':STAGE,'role':ROLE,'private_diagnostic_saved':saved}


def execute():
    try:return main()
    except Exception as error:return failed_result(error)


if __name__=='__main__':
    result=execute()
    print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['ok'] else 1)
