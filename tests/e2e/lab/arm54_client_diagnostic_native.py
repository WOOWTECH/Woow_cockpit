"""Only fixed predicates over our generated private daemon logs; no log text output."""
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);assert root.parent==Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')
results=[]
for log in root.glob('trial-*/client-state/daemon.log'):
    with log.open('rb') as handle: data=handle.read(1024*1024).lower()
    words=('proxyconnect','http_proxy','https_proxy','lookup arm54.invalid','network is unreachable',
           'connection refused','certificate signed by unknown authority','no route to host',
           'invalid auth','key is invalid','client is too new','permission denied')
    results.append({'trial':log.parents[1].name,'predicates':{w:w.encode() in data for w in words}})
print(json.dumps(results))
