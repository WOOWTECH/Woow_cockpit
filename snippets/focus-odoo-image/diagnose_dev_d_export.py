#!/usr/bin/env python3
"""Read-only diagnosis of the preserved first Docker export. Fixed counts/statuses/hashes only; no engine load."""
import fcntl
import json
from pathlib import Path
import subprocess

LAB = Path.home() / '.woowbk-lab/bin/labpodman'
BODY = r'''
import collections,hashlib,json,pathlib,sys,tarfile
root=pathlib.Path('/var/lib/woowbk-odoo-pg16-proof-20261127-od23')
sys.path.insert(0,str(root/'code/backup-engine'))
from woowbackup import pg16_bundle as bundle
expected='sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
positions={}; kinds={}; metadata={}; aliases=[]
with (root/'original.docker.tar').open('rb') as f:
 while True:
  header=f.read(512)
  if header==bytes(512): break
  info=tarfile.TarInfo.frombuf(header,'utf-8','strict'); start=f.tell()
  assert len(kinds)<4096 and info.size>=0 and info.name not in kinds
  kinds[info.name]=info.type.hex()
  if info.isfile(): positions[info.name]=(start,info.size)
  elif info.issym(): aliases.append(info.name)
  else: assert info.isdir()
  if info.name in ('manifest.json',expected[7:]+'.json'):
   assert info.size<=bundle.MAX_JSON and info.isfile()
   metadata[info.name]=f.read(info.size)
  f.seek(start+((info.size+511)//512)*512)
 manifest=bundle._json(metadata['manifest.json']); configraw=metadata[expected[7:]+'.json']
 assert len(manifest)==1 and manifest[0]['RepoTags']==['docker.io/library/postgres:16.15-alpine3.24']
 assert 'sha256:'+hashlib.sha256(configraw).hexdigest()==expected
 config=bundle._json(configraw); layers=manifest[0]['Layers']; diff_ids=config['rootfs']['diff_ids']
 assert config['architecture']=='amd64' and config['os']=='linux' and config['rootfs']['type']=='layers'
 assert len(layers)==len(diff_ids)==11 and all(name in positions for name in layers)
 assert not set(aliases)&set(layers)
 bundle._verify_layers(f,layers,positions,diff_ids,None)
 f.seek(0)
 try: bundle.validate_archive(f,'amd64',expected)
 except bundle.BundleError as error:
  assert str(error)=='Unsafe Docker archive member.'
 else: raise AssertionError()
report={'status':'diagnosed','reason':'source-archive-header-refused','validator_reason':'unsafe-docker-member',
 'reason_is_fixed_whitelisted_constant':True,'config_id':expected,'config_sha256_verified':True,
 'ordered_uncompressed_layer_sha256_verified':len(layers),'manifest_layer_files_regular':True,
 'redundant_symlink_aliases':len(aliases),'aliases_referenced_by_manifest':0,
 'type_counts_hex':dict(collections.Counter(kinds.values())),
 'first_failed_artifact_preserved':True,'source_store_mutations':0,'loads':0,'pulls':0}
print(json.dumps(report,sort_keys=True))
'''

if __name__ == '__main__':
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run = subprocess.run([str(LAB), 'exec', '-i', 'woowbk-dev-d', 'python3', '-I', '-'],
                             input=BODY.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
        if run.returncode:
            raise SystemExit('fixed-export-diagnosis-failed')
        report = json.loads(run.stdout)
        destination = Path(__file__).with_name('dev-d-first-export-diagnosis.json')
        with destination.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True))
