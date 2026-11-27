import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner
r=Runner();p=r.podman('unshare','cat','/proc/self/uid_map',check=False)
# Command reads only a public proc mapping; static diagnostic contains no app values.
print(json.dumps({'command':['unshare','cat','/proc/self/uid_map'],'exit':p.returncode,
                 'public_transport_error':p.stderr.decode()[:1500],
                 'actual_host_uid_map':Path('/proc/self/uid_map').read_text(),
                 'actual_host_gid_map':Path('/proc/self/gid_map').read_text()}))
