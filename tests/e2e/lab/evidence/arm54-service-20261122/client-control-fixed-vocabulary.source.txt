"""Fixed vocabulary diagnostics only; no raw log strings or credential values."""
import json,re,sys
from pathlib import Path
root=Path(sys.argv[1]);assert root.parent==Path('/var/tmp') and root.name.startswith('woow-arm54-ha-20261122-')
allowed=set('error failed fetch fetching control key get post register login login-server auth authkey auth-key file read open no such directory permission denied x509 certificate signed unknown authority verify tls handshake http https status code 400 401 403 404 500 unsupported protocol invalid missing expired timeout waiting timed out context deadline exceeded lookup resolve network unreachable connection refused reset client server default proxy unexpected response needs update new old version force-reauth requires changing settings flags flag provided defined already state socket cannot connect local tailscaled tailscale controlplane.tailscale.com login.tailscale.com 127.0.0.1 arm54.invalid'.split())
logs=sorted(root.glob('trial-*/client-state/daemon.log'),key=lambda p:p.stat().st_mtime)
result=[]
for log in logs[-1:]:
    with log.open('rb') as h: text=h.read(1024*1024).decode('utf-8','replace').lower()
    lines=[line for line in text.splitlines() if ('control:' in line or 'received error:' in line or 'fetch control key' in line)]
    for line in lines[-12:]:
        result.append([token for token in re.findall(r'[a-z0-9_.-]+',line) if token in allowed])
print(json.dumps({'fixed_vocabulary_control_diagnostics':result}))
