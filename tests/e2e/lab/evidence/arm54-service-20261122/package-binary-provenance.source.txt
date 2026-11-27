import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner
r=Runner();built=json.loads((ROOT/'build-result.json').read_text())['image_id']
source='ghcr.io/juanfont/headscale:v0.29.4@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f'
records=[]
for name,image in (('upstream',source),('package',built)):
    container=ROOT.name+'-binary-'+name;dest=ROOT/('binary-'+name)
    try:
        info=json.loads(r.podman('image','inspect',image).stdout)[0]
        assert info['Architecture']=='arm64'
        r.podman('create','--name',container,'--network=none','--memory=64m','--image-volume=ignore',image)
        r.podman('cp',container+':/ko-app/headscale',str(dest))
        assert dest.stat().st_size<128*1024**2
        records.append({'role':name,'image_id':info['Id'],'architecture':info['Architecture'],
                        'binary_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'binary_bytes':dest.stat().st_size})
    finally:
        r.podman('rm','-f',container,check=False);dest.unlink(missing_ok=True)
assert records[0]['binary_sha256']==records[1]['binary_sha256']
print(json.dumps({'upstream_binary_identical':True,'images':records,'commands':r.commands,'free_bytes_samples':r.free}))
