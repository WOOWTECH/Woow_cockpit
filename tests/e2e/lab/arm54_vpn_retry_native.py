"""Single-variable retry in retained network-none fixture: official network-up test knob."""
import sys,json,time
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner,report
r=Runner(); trial=Path(json.loads((ROOT/'probe-result.json').read_text())['fixture']); state=trial/'client-state'
name='woowbk-j20261122T123000Z-a54c0003-source'
r.podman('exec',name,'sh','-c','for p in /proc/[0-9]*/comm; do read c < "$p"; if [ "$c" = tailscaled ]; then q=${p%/comm}; kill "${q##*/}"; fi; done')
time.sleep(1);(state/'tailscaled.sock').unlink(missing_ok=True)
r.podman('exec','--detach','--env','SSL_CERT_FILE=/etc/headscale/server.crt','--env','TS_DEBUG_LOG_DISABLE=true',
 '--env','TS_ASSUME_NETWORK_UP_FOR_TEST=true',
 '--env','HTTP_PROXY=','--env','HTTPS_PROXY=','--env','ALL_PROXY=','--env','http_proxy=','--env','https_proxy=','--env','all_proxy=','--env','NO_PROXY=*','--env','no_proxy=*',name,'sh','-c',
 'exec /client-bin/tailscaled --tun=userspace-networking --state=/client-state/tailscaled.state --socket=/client-state/tailscaled.sock > /client-state/daemon-retry.log 2>&1')
for i in range(40):
 if (state/'tailscaled.sock').exists():break
 time.sleep(.25)
p=r.podman('exec',name,'/client-bin/tailscale','--socket=/client-state/tailscaled.sock','up','--login-server=https://127.0.0.1:8080','--auth-key=file:/client-state/authkey','--accept-dns=false','--timeout=30s',timeout=40,check=False)
(state/'retry.stderr').write_bytes(p.stderr);(state/'retry.stdout').write_bytes(p.stdout)
status=json.loads(r.podman('exec',name,'/client-bin/tailscale','--socket=/client-state/tailscaled.sock','status','--json',check=False).stdout)
log=(state/'daemon-retry.log').read_bytes()[:1024*1024].lower()
a={'up_exit':p.returncode,'backend':status.get('BackendState'),'identity':{'id':status.get('Self',{}).get('ID'),'ips':status.get('Self',{}).get('TailscaleIPs')},'predicates':{x:x.encode() in log for x in ['x509','unknown authority','registerreq','machineauthorized=true','network is unreachable','unsupported','401 unauthorized','paused=true','paused=false']},'commands':r.commands,'free_bytes_samples':r.free}
report(ROOT/'retry-result.json',a);print(json.dumps(a));sys.exit(0 if p.returncode==0 and a['backend']=='Running' else 1)
