import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner,report
from woowbackup import tempctr,hacommon,ha_headscale
from types import SimpleNamespace
r=Runner(); image=json.loads(r.podman('image','inspect','localhost/woow-headscale:0.29.4-arm54-local').stdout)[0]
t=tempctr.TempObjects(r,'j20261122T130000Z-a54b0003',memory='256m',pids=128,cpus='0.5')
try:
    out=t.run('net',image['Id'],['-c','cat /proc/net/dev; cat /proc/net/route; readlink /proc/self/ns/net'],entrypoint='sh',remove=False,check=False)
    info=json.loads(r.podman('inspect',t.name('net')).stdout)[0]
    labels=hacommon.image_labels(SimpleNamespace(runner=lambda app:r),SimpleNamespace(id='headscale'),image['Id'])
    assert ha_headscale.VERSIONS.blocker('0.1.3',hacommon.semver(labels.get('org.opencontainers.image.version'))) is None
    result={'probe_exit':out.returncode,'net_namespace_probe':out.stdout.decode(),'network_mode':info['HostConfig']['NetworkMode'],
            'port_bindings':info['HostConfig'].get('PortBindings'),'labels':labels,'image_id':image['Id'],
            'image_arch':image['Architecture'],'image_bytes':image['Size'],'kind':'native-local-package-build','product_version':'0.29.4'}
    assert result['network_mode']=='none' and not result['port_bindings']
    result['status']='passed'
    report(ROOT/'build-result.json',result)
    print(json.dumps(result))
finally: assert not t.cleanup()
