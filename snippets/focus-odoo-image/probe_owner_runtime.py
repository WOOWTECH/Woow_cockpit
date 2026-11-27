#!/usr/bin/env python3
"""Lease-only metadata probe of the otherwise empty owned r4 preparation store. No load/pull/source command."""
import fcntl
import json
from pathlib import Path
import subprocess

BODY = r'''
import json,pathlib,pwd,re,select,subprocess,sys
root=pathlib.Path('/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r4');owned=root/'preparation-store'
sys.path.insert(0,str(root/'code/backup-engine'))
from woowbackup import podman
owner=podman.OwnerRunner('appowner')
assert owned.stat().st_uid==owner.uid and owned.stat().st_mode&0o777==0o700 and not owned.is_symlink()
assert pathlib.Path('/mnt').is_dir() and not any(pathlib.Path('/mnt').iterdir())
subprocess.run(['/usr/bin/mount','--bind',str(root),'/mnt'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
assert pathlib.Path('/mnt').stat().st_ino==root.stat().st_ino
runtime='/mnt/preparation-store'
base_prefix=owner.prefix()
owner.prefix=lambda: ['XDG_RUNTIME_DIR='+runtime+'/run' if value.startswith('XDG_RUNTIME_DIR=') else value
                       for value in base_prefix]
flags=['--root',str(owned/'graph'),'--runroot',runtime+'/run','--storage-driver','vfs',
       '--events-backend','file','--tmpdir',runtime+'/tmp','--cgroup-manager','cgroupfs']
result=owner.run([podman.PODMAN,*flags,'image','ls','--format','{{.ID}}'],check=False,timeout=60,max_output=65536)
raw=result.stderr.lower()
vocab='error stat lstat mkdir cannot not file exists absolute directory argument flag option invalid path supported incompatible already db default state network log logging vfs overlay used empty lock failed driver store create creating access open opening initialize initializing init initialization backend system config read reading write writing format permission refused function short ids must requires uid gid database bolt sqlite storage no found home graph event events user session exit status too many files free libpod podman load when root runroot tmpdir static tmp temporary volume manager cgroupfs dbus re-exec reexec read-only symlink symbolic link unknown shorthand provided defined unexpected decoding parsing parse unsupported duplicate multiple conflict conflicting mismatch redirection illegal unrecognized in both the a an for to at and as be is or with set setting changed specified expected restricted blocked rejected gated denied run command arguments maximum minimum has have was empty rootless accessing equivalent points resolved evaluated resolve links clean cleaned longer than characters proc cwd'.split()
print(json.dumps({'status':'metadata-probed','returncode':result.returncode,'stderr_bytes':len(raw),
   'fixed_reason':podman.reason_of(result),'fixed_diagnostic_codes':[word for word in vocab
      if re.search(rb'(?<![a-z])'+re.escape(word.encode())+rb'(?![a-z])',raw)],
   'exact_runroot_length_error':raw.strip()==b'error: the specified runroot is longer than 50 characters',
   'source_commands':0,'loads':0,'pulls':0},sort_keys=True))
'''

if __name__ == '__main__':
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([str(Path.home() / '.woowbk-lab/bin/labpodman'), 'exec', '-i',
                                 'woowbk-dev-d', 'unshare', '--mount', '--propagation', 'private', 'python3', '-I', '-'], input=BODY.encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
        assert result.returncode == 0
        print(json.dumps(json.loads(result.stdout), sort_keys=True))
