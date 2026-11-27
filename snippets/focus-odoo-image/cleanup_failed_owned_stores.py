#!/usr/bin/env python3
"""Lease-only cleanup of exact failed r3/r4 preparation leaves after the successful release was retained.

Preserve original/r2 exports and every protected failed quarantine. No original images/volumes/fixtures touched.
"""
import fcntl
import json
from pathlib import Path
import subprocess

ROOTS = ('/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r3',
         '/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r4')
BODY = r'''
import json,os,pathlib,pwd,shutil,subprocess,sys
root=pathlib.Path(ROOT_VALUE)
assert root.parent==pathlib.Path('/var/lib') and str(root) in ROOT_LIST
assert root.is_dir() and not root.is_symlink() and root.stat().st_uid==0 and root.stat().st_mode&0o777==0o755
assert shutil.disk_usage(root).free>=17*1024**3
assert int(pathlib.Path('/sys/fs/cgroup/memory.max').read_text())-int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())>=512*1024**2
assert pathlib.Path('/mnt').is_dir() and not any(pathlib.Path('/mnt').iterdir())
subprocess.run(['/usr/bin/mount','--bind',str(root),'/mnt'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
assert pathlib.Path('/mnt').stat().st_ino==root.stat().st_ino
sys.path.insert(0,str(root/'code/backup-engine'))
from woowbackup import pg16_bundle as bundle,podman
from woowbackup.errors import BackupError
def guard():
 if shutil.disk_usage(root).free<13*1024**3:return BackupError('insufficient-space','proof-reserve-reached')
expected='sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
with bundle._directory(root,trusted=True) as dfd,bundle._file(dfd,'quarantined-verification-view.tar',trusted=True) as stream:
 bundle.validate_archive(stream,'amd64',expected,abort=guard)
path=root/'preparation-store';uid=pwd.getpwnam('appowner').pw_uid
assert path.is_dir() and not path.is_symlink() and path.stat().st_uid==uid and path.stat().st_mode&0o777==0o700
assert not (root/'owner-store').exists()
runtime='/mnt/preparation-store'
flags=['--root',str(path/'graph'),'--runroot',runtime+'/run','--storage-driver','vfs',
       '--events-backend','file','--tmpdir',runtime+'/tmp','--cgroup-manager','cgroupfs']
class IsolatedOwner(podman.OwnerRunner):
 def prefix(self):
  return ['XDG_RUNTIME_DIR='+runtime+'/run' if v.startswith('XDG_RUNTIME_DIR=') else v for v in super().prefix()]
owner=IsolatedOwner('appowner')
for args in (('ps','-a','--format','{{.Names}}'),('volume','ls','--format','{{.Name}}'),('image','ls','--format','{{.ID}}')):
 assert owner.run([podman.PODMAN,*flags,*args],timeout=60,max_output=65536,abort=guard).stdout.strip()==b''
owner.run([podman.PODMAN,*flags,'system','migrate'],timeout=120,max_output=65536,abort=guard)
assert shutil.rmtree.avoids_symlink_attacks
mounts=[line.split()[4] for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()]
assert not any(m==p or m.startswith(p+'/') for m in mounts for p in (str(path),runtime))
shutil.rmtree(path)
assert (root/'quarantined-verification-view.tar').is_file()
source=podman.OwnerRunner('appowner')
fmt='{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}","tags":{{json .RepoTags}},"digests":{{json .RepoDigests}}}'
identity=json.loads(source.podman('image','inspect','--format',fmt,expected,timeout=60,max_output=65536).stdout)
assert identity['id'].removeprefix('sha256:')==expected[7:] and identity['architecture']=='amd64' and identity['os']=='linux'
assert identity['tags']==['docker.io/library/postgres:16.15-alpine3.24'] and identity['digests']==SOURCE_DIGESTS
print(json.dumps({'status':'owned-failed-store-removed','removed':str(path),'protected_quarantine_retained':True,
 'containers_before':0,'volumes_before':0,'images_before':0,'source_unchanged':True,'pulls':0,
 'free_bytes_after':shutil.disk_usage(root).free},sort_keys=True))
'''

if __name__ == '__main__':
    folder = Path(__file__).parent
    receipt = json.loads((folder / 'retained-release.json').read_text())
    assert receipt['status'] == 'retained-and-hash-verified'
    result = json.loads((folder / 'woowbk-odoo-pg16-proof-20261127-od23-r5-result.json').read_text())
    assert result['status'] == 'passed' and receipt['manifest_sha256'] == result['manifest_sha256']
    reports = []
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for root in ROOTS:
            body = BODY.replace('ROOT_VALUE', repr(root)).replace('ROOT_LIST', repr(ROOTS))
            body = body.replace('SOURCE_DIGESTS', repr(result['source_repo_digests']))
            run = subprocess.run([str(Path.home() / '.woowbk-lab/bin/labpodman'), 'exec', '-i', 'woowbk-dev-d',
                                  'unshare', '--mount', '--propagation', 'private', 'python3', '-I', '-'],
                                 input=body.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
            assert run.returncode == 0, 'fixed-owned-store-cleanup-refused'
            reports.append(json.loads(run.stdout))
        with (folder / 'failed-owned-store-cleanup.json').open('x') as output:
            output.write(json.dumps({'status': 'passed', 'stores': reports}, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'stores_removed': len(reports), 'protected_artifacts_retained': True,
                      'source_unchanged': True, 'pulls': 0}, sort_keys=True))
