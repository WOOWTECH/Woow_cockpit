"""Fixed public synthetic NC loop in one pinned CLIENT; no source/broker IO.

Applet inventory and actual option/listener/repeated-connection behavior share
one no-network sidecar. These primitives do NOT attest HTTP fixture delivery.
"""
import re
import secrets

from emqx_adapter_owner import OwnerProvision,LabOwnerRunner
from emqx_adapter_mqtt import CLIENT
from emqx_native_runtime import IMAGE
from emqx_owned_client import owned_client

RECEIPT=b'CLIENT NC PRIMITIVES PASSED\n'
REQUIRED=('nc','sh','timeout','cmp')  # No head/cat/mkfifo or assumed applets used.
LIMIT=65536
BEGIN=b'NCPRIMITIVE-APPLETS-BEGIN\n'
END=b'NCPRIMITIVE-APPLETS-END\n'
PASS=b'NCPRIMITIVE-BEHAVIOR-PASSED\n'
BEHAVIOR=('listener','health','empty','repeat_one','repeat_two','requests','responses')
PHASES=frozenset(('realm','input','owner','run','applets','timeout','cleanup',
    *('missing_'+name for name in REQUIRED),*BEHAVIOR))
TMPFS='/work:rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=1000,gid=1000'

# All script/HTTP bytes are compiled public synthetic inputs. No args, source
# fields, host mounts, secret environment or arbitrary executable are accepted.
SCRIPT=r'''umask 077
applets=$(/bin/busybox --list) || exit 1
printf 'NCPRIMITIVE-APPLETS-BEGIN\n%s\nNCPRIMITIVE-APPLETS-END\n' "$applets"
for applet in nc sh timeout cmp; do
 case "
$applets
" in *"
$applet
"*) ;; *) printf 'NCPRIMITIVE-REFUSED:missing_%s\n' "$applet"; exit 1;; esac
done
# noexec tmpfs is intentional: the fixed interpreter reads this private script.
printf '%s' '' > /work/empty
/bin/busybox sh -c 'printf "%s\n" "$1" > /work/probe.sh' sh '
phase=listener
loop=
finish() {
 code=$?
 trap - EXIT
 if [ -n "$loop" ]; then kill "$loop" 2>/dev/null || :; wait "$loop" 2>/dev/null || :; fi
 if [ "$code" -ne 0 ]; then printf "NCPRIMITIVE-REFUSED:%s\n" "$phase"; fi
 exit "$code"
}
trap finish EXIT
printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" > /work/response
for n in 2 3; do printf "GET /public-probe/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$n" > /work/send.$n; done
listen_loop() {
 for n in 1 2 3; do
  /bin/busybox nc -l -p 19089 -s 127.0.0.1 -w 2 < /work/response > /work/request.$n 2>/work/listen.err || return 1
  [ ! -s /work/listen.err ] || return 1
  printf done > /work/done.$n
 done
}
listen_loop > /work/loop.out 2>/work/loop.err &
loop=$!
ready() {
 attempt=0
 while [ "$attempt" -lt 20000 ]; do
  while read -r sl local remote state rest; do
   if [ "$local" = "0100007F:4A91" ] && [ "$state" = "0A" ]; then return 0; fi
  done < /proc/net/tcp
  kill -0 "$loop" 2>/dev/null || return 1
  attempt=$((attempt+1))
 done
 return 1
}
done_connection() {
 attempt=0
 while [ "$attempt" -lt 20000 ]; do
  [ -f "/work/done.$1" ] && return 0
  kill -0 "$loop" 2>/dev/null || return 1
  attempt=$((attempt+1))
 done
 return 1
}
ready || exit 1
phase=health
/bin/busybox nc -w 2 127.0.0.1 19089 < /work/empty > /work/received.1 2>/work/client.err || exit 1
[ ! -s /work/client.err ] || exit 1
done_connection 1 || exit 1
phase=empty
[ ! -s /work/request.1 ] || exit 1
for n in 2 3; do
 if [ "$n" = 2 ]; then phase=repeat_one; else phase=repeat_two; fi
 ready || exit 1
 /bin/busybox nc -w 2 127.0.0.1 19089 < /work/send.$n > /work/received.$n 2>/work/client.err || exit 1
 [ ! -s /work/client.err ] || exit 1
 done_connection "$n" || exit 1
done
phase=requests
for n in 2 3; do /bin/busybox cmp -s /work/send.$n /work/request.$n || exit 1; done
phase=responses
for n in 1 2 3; do /bin/busybox cmp -s /work/response /work/received.$n || exit 1; done
wait "$loop" || exit 1
loop=
printf "NCPRIMITIVE-BEHAVIOR-PASSED\n"
' || exit 1
exec /bin/busybox timeout 18 /bin/busybox sh /work/probe.sh
'''


class ClientNCRefused(ValueError):
    def __init__(self,phase):
        super().__init__('client-nc-refused');self.phase=phase if phase in PHASES else 'run'


def _validate(result):
    if (type(result.returncode) is not int or type(result.stdout) is not bytes
            or not 0<len(result.stdout)<=LIMIT or type(result.stderr) is not bytes or result.stderr):raise ClientNCRefused('run')
    raw=result.stdout
    if not raw.isascii() or not raw.startswith(BEGIN):raise ClientNCRefused('applets')
    inventory,separator,tail=raw[len(BEGIN):].partition(END)
    if not separator or not inventory.endswith(b'\n'):raise ClientNCRefused('applets')
    applets=inventory[:-1].split(b'\n')
    if (not 1<=len(applets)<=1024 or len(set(applets))!=len(applets)
            or any(re.fullmatch(rb'[A-Za-z0-9_.\[\]-]{1,64}',name) is None for name in applets)):raise ClientNCRefused('applets')
    missing=next((name for name in REQUIRED if name.encode() not in applets),None)
    if missing:
        phase='missing_'+missing
        if result.returncode!=0 and tail==b'NCPRIMITIVE-REFUSED:'+phase.encode()+b'\n':raise ClientNCRefused(phase)
        raise ClientNCRefused('applets')
    if result.returncode==0 and tail==PASS:return
    if result.returncode!=0:
        for phase in BEHAVIOR:
            if tail==b'NCPRIMITIVE-REFUSED:'+phase.encode()+b'\n':raise ClientNCRefused(phase)
        if result.returncode==124 and not tail:raise ClientNCRefused('timeout')
    raise ClientNCRefused('run')


def run_client_nc_primitives():
    phase='owner'
    try:
        provision=OwnerProvision(IMAGE.removeprefix('sha256:'))
        if (type(provision) is not OwnerProvision or type(provision.runner) is not LabOwnerRunner
                or provision.runner.owner!='appowner' or provision.file_capability is not None or provision.created):raise ValueError()
        name=provision.fixture.prefix+'-mqtt-'+secrets.token_hex(6)
        with owned_client(provision.runner,name) as args:
            phase='run'
            result=provision.runner.podman('run','--rm',*args,'--pull=never','--read-only','--network=none',
                '--image-volume=ignore','--log-driver=none','--memory=32m','--cpus=0.25','--pids-limit=16',
                '--timeout=20','--stop-timeout=1','--user=1000:1000','--tmpfs',TMPFS,
                '--entrypoint=/bin/busybox',CLIENT,'sh','-c',SCRIPT,timeout=25,max_output=LIMIT,check=False)
            _validate(result);phase='cleanup'
        return RECEIPT
    except ClientNCRefused:raise
    except BaseException:raise ClientNCRefused(phase) from None
