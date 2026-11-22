"""Explicit SSH coordinator for authorized .54 only; password stays in askpass env."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

SSH = ['ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/tmp/ha-test-54-known-hosts',
       '-o', 'ConnectTimeout=10', '-o', 'NumberOfPasswordPrompts=1', 'root@192.168.2.54']
REPO = Path(__file__).resolve().parents[3]
STATE = Path('/tmp/arm54-service-state.json')
EVIDENCE = REPO / 'tests/e2e/lab/evidence/arm54-service-20261122'


def remote(code, *, timeout=300):
    return subprocess.run(SSH + ['python3 -'], input=code.encode(), capture_output=True, timeout=timeout)


def init():
    code = '''import json,os,pathlib,shutil,subprocess,tempfile,time
os.umask(0o077)
assert shutil.disk_usage('/var/tmp').free >= 12*1024**3+2*1024**3
root=pathlib.Path(tempfile.mkdtemp(prefix='woow-arm54-ha-20261122-',dir='/var/tmp'))
for name in ('source','store','run','tmp','config','build'):
 (root/name).mkdir(mode=0o700)
(root/'empty-auth.json').write_text('{"auths":{}}')
def read(args): return subprocess.check_output(args,timeout=45).decode().splitlines()
baseline={'containers':read(['podman','ps','-a','--no-trunc','--format','{{.ID}} {{.Names}} {{.Image}} {{.State}} {{.Ports}}']),
 'images':read(['podman','images','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}']),
 'volumes':read(['podman','volume','ls','--format','{{.Name}}']),
 'networks':read(['podman','network','ls','--format','{{.Name}}']),
 'store':read(['podman','info','--format','{{.Store.GraphRoot}} {{.Store.RunRoot}}'])}
(root/'baseline.json').write_text(json.dumps(baseline))
print(json.dumps({'workspace':str(root),'baseline':baseline,'started_epoch':time.time(),'free_bytes':shutil.disk_usage(root).free}))
'''
    result = remote(code)
    assert result.returncode == 0, 'remote-init-failed'
    STATE.write_bytes(result.stdout)
    STATE.chmod(0o600)
    (EVIDENCE / 'before.json').write_bytes(result.stdout)
    print(result.stdout.decode())


def upload():
    state = json.loads(STATE.read_text())
    bundle = Path('/tmp/arm54-service-source.tar.gz')
    files = [p for p in (REPO / 'backup-engine').rglob('*')
             if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc']
    files += list((REPO / 'tests/e2e/lab').glob('arm54_*native*.py'))
    files += [REPO / 'tests/e2e/lab/arm54_owned_runtime.py', EVIDENCE / 'package.Containerfile', EVIDENCE / 'arm-platform-inputs.json']
    with tarfile.open(bundle, 'w:gz') as tar:
        for path in files:
            tar.add(path, arcname=str(path.relative_to(REPO)))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (EVIDENCE / 'source-hashes.json').write_text(json.dumps({'base':'3fe2ff3','bundle_sha256':digest,
        'files':{str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}},indent=2)+'\n')
    result = subprocess.run(['scp', *SSH[1:-1], str(bundle), 'root@192.168.2.54:' + state['workspace'] + '/source/bundle.tar.gz'], capture_output=True, timeout=90)
    assert result.returncode == 0, 'upload-failed'
    code = '''import hashlib,os,pathlib,tarfile
root=pathlib.Path(ROOT); os.umask(0o077)
assert hashlib.sha256((root/'source/bundle.tar.gz').read_bytes()).hexdigest()==DIGEST
with tarfile.open(root/'source/bundle.tar.gz') as tar:
 for m in tar:
  assert m.isfile() and m.size <= 4*1024**2 and not pathlib.PurePosixPath(m.name).is_absolute() and '..' not in pathlib.PurePosixPath(m.name).parts
  p=root/'source'/m.name; p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  with p.open('xb') as out: out.write(tar.extractfile(m).read())
print('source-bundle-sha256-and-extract: OK')
'''.replace('ROOT', repr(state['workspace'])).replace('DIGEST', repr(digest))
    result = remote(code)
    assert result.returncode == 0, 'source-extract-failed'
    print(result.stdout.decode())


def run(script, output):
    root = json.loads(STATE.read_text())['workspace']
    source = (REPO / 'tests/e2e/lab' / script).read_text()
    # Executed exact source is retained next to each result.
    (EVIDENCE / (output + '.source.txt')).write_text(source)
    prefix = 'import sys\nsys.argv=["' + script + '",' + repr(root) + ']\n'
    result = remote(prefix + source, timeout=600)
    (EVIDENCE / (output + '.json')).write_bytes(result.stdout)
    (EVIDENCE / (output + '.exit.json')).write_text(json.dumps({'ssh_exit':result.returncode})+'\n')
    print(result.stdout.decode())
    if result.returncode:
        print('REMOTE_FAILED',result.returncode)  # never publish arbitrary traceback/private locals
    return result.returncode


if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('mode',choices=('init','upload','run'))
    p.add_argument('--script'); p.add_argument('--output'); a=p.parse_args()
    if a.mode=='init': init()
    elif a.mode=='upload': upload()
    else: raise SystemExit(run(a.script,a.output))
