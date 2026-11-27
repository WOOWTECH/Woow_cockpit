import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner
r=Runner();name='woowbk-j20261122T123000Z-a54c0003-source'
if r.podman('container','exists',name,check=False).returncode==0:
    p=r.podman('exec',name,'bash','-c','timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/8080"',check=False,timeout=5)
    q=r.podman('exec',name,'/client-bin/tailscale','--socket=/client-state/tailscaled.sock','status','--json',check=False,timeout=5)
    state=json.loads(q.stdout).get('BackendState') if q.returncode==0 else 'unavailable'
    print(json.dumps({'source_exists':True,'localhost_tcp_exit':p.returncode,'tailscale_backend':state}))
else:
    print(json.dumps({'source_exists':False}))
