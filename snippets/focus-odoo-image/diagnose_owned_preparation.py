#!/usr/bin/env python3
"""Lease-only bounded replay: reverify protected r3 bytes, then retry its exact NEW owned preparation load once."""
import fcntl
import json
from pathlib import Path
import subprocess

BODY = r'''
import json,pathlib,pwd,shutil,sys
root=pathlib.Path('/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r3')
assert root.stat().st_uid==0 and root.stat().st_mode&0o777==0o755
assert shutil.disk_usage(root).free>=17*1024**3
assert int(pathlib.Path('/sys/fs/cgroup/memory.max').read_text())-int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())>=512*1024**2
sys.path.insert(0,str(root/'code/backup-engine'))
from woowbackup import pg16_bundle as bundle,podman
from woowbackup.errors import BackupError
def guard():
 if shutil.disk_usage(root).free<13*1024**3:return BackupError('insufficient-space','proof-reserve-reached')
expected='sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
path=root/'preparation-store'
assert path.stat().st_uid==pwd.getpwnam('appowner').pw_uid and path.stat().st_mode&0o777==0o700 and not path.is_symlink()
flags=['--root',str(path/'graph'),'--runroot',str(path/'run'),'--storage-driver','vfs',
       '--events-backend','file','--tmpdir',str(path/'tmp'),'--cgroup-manager','cgroupfs']
owner=podman.OwnerRunner('appowner')
with (root/'quarantined-verification-view.tar').open('rb') as stream:
 bundle.validate_archive(stream,'amd64',expected,abort=guard)
 result=owner.run([podman.PODMAN,*flags,'load'],input=stream,timeout=900,max_output=65536,abort=guard,check=False)
raw=result.stderr.lower()
known={'stdin-reopen-denied':b'/proc/self/fd/0' in raw and b'permission denied' in raw,
 'rootless-permission':b'operation not permitted' in raw,'tar-header':b'invalid tar header' in raw,
 'directory-missing':b'no such file or directory' in raw,'stdin-copy':b'copying stdin' in raw,
 'rootless-mount':b'mount' in raw and b'permission' in raw,'graphroot':b'graphroot' in raw,
 'read-only-fs':b'read-only file system' in raw,'policy-signature':b'signature' in raw,
 'invalid-argument':b'invalid argument' in raw,'manifest-type':b'manifest' in raw,
 'invalid-tar':b'invalid tar' in raw,'unrecognized-image':b'unrecognized image format' in raw}
print(json.dumps({'status':'replayed','returncode':result.returncode,'fixed_reason':podman.reason_of(result),
 'diagnostic_codes':[key for key,value in known.items() if value],
 'config_and_all_layers_reverified_before_load':True,'pulls':0},sort_keys=True))
'''

if __name__ == '__main__':
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    assert int(memory['MemAvailable'].split()[0]) >= 1200 * 1024
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([str(Path.home() / '.woowbk-lab/bin/labpodman'), 'exec', '-i',
                                 'woowbk-dev-d', 'python3', '-I', '-'], input=BODY.encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1000)
        assert result.returncode == 0
        report = json.loads(result.stdout)
        with Path(__file__).with_name('dev-d-r3-preparation-diagnosis.json').open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True))
