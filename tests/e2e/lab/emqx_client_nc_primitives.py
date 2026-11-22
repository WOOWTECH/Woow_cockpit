"""Fixed public synthetic NC loop in one pinned CLIENT; no source/broker IO.

Applet inventory and actual option/listener/repeated-connection behavior share
one no-network sidecar. These primitives do NOT attest HTTP fixture delivery.
"""
import re
import secrets
import subprocess

from emqx_adapter_owner import OwnerProvision,LabOwnerRunner
from emqx_adapter_mqtt import CLIENT
from emqx_native_runtime import IMAGE
from emqx_owned_client import owned_client

RECEIPT=b'CLIENT NC PRIMITIVES PASSED\n'
REQUIRED=('nc','sh','timeout','cmp','mkdir')  # No head/cat/mkfifo or assumed applets used.
LIMIT=65536
BEGIN=b'NCPRIMITIVE-APPLETS-BEGIN\n'
END=b'NCPRIMITIVE-APPLETS-END\n'
PASS=b'NCPRIMITIVE-BEHAVIOR-PASSED\n'
SETUP=('inventory','script_setup','script_exec')
LAUNCH_CODES=frozenset((125,126,127,137))
LAUNCH_125_PHASES=frozenset(('launch_tmpfs_uid_gid','launch_tmpfs_option',
    'launch_tmpfs_permission','launch_user_mapping','launch_resource','launch_option','launch_oci'))
BEHAVIOR=('listener','health','empty','repeat_one','repeat_two','requests','responses')
PHASES=frozenset(('realm','input','owner','run','applets','timeout','cleanup','runner','stderr','output','exit_other',
    *('launch_'+str(code) for code in LAUNCH_CODES),*LAUNCH_125_PHASES,*SETUP,
    *('missing_'+name for name in REQUIRED),*BEHAVIOR))
# Rootless Podman rejects tmpfs uid/gid options. Only this fresh sidecar sees
# the sticky scratch root; all work happens in its atomically created 0700 child.
TMPFS='/work:rw,noexec,nosuid,nodev,size=1048576,mode=1777'

# All script/HTTP bytes are compiled public synthetic inputs. No args, source
# fields, host mounts, secret environment or arbitrary executable are accepted.
SCRIPT=r'''umask 077
setup_refused() { printf 'NCPRIMITIVE-REFUSED:%s\n' "$1"; exit 1; }
applets=$(/bin/busybox --list) || setup_refused inventory
printf 'NCPRIMITIVE-APPLETS-BEGIN\n%s\nNCPRIMITIVE-APPLETS-END\n' "$applets"
for applet in nc sh timeout cmp mkdir; do
 case "
$applets
" in *"
$applet
"*) ;; *) printf 'NCPRIMITIVE-REFUSED:missing_%s\n' "$applet"; exit 1;; esac
done
/bin/busybox mkdir -m 700 /work/private || setup_refused script_setup
# noexec tmpfs is intentional: the fixed interpreter reads this private script.
printf '%s' '' > /work/private/empty || setup_refused script_setup
/bin/busybox sh -c 'printf "%s\n" "$1" > /work/private/probe.sh' sh '
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
printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" > /work/private/response
for n in 2 3; do printf "GET /public-probe/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$n" > /work/private/send.$n; done
listen_loop() {
 for n in 1 2 3; do
  /bin/busybox nc -l -p 19089 -s 127.0.0.1 -w 2 < /work/private/response > /work/private/request.$n 2>/work/private/listen.err || return 1
  [ ! -s /work/private/listen.err ] || return 1
  printf done > /work/private/done.$n
 done
}
listen_loop > /work/private/loop.out 2>/work/private/loop.err &
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
  [ -f "/work/private/done.$1" ] && return 0
  kill -0 "$loop" 2>/dev/null || return 1
  attempt=$((attempt+1))
 done
 return 1
}
ready || exit 1
phase=health
/bin/busybox nc -w 2 127.0.0.1 19089 < /work/private/empty > /work/private/received.1 2>/work/private/client.err || exit 1
[ ! -s /work/private/client.err ] || exit 1
done_connection 1 || exit 1
phase=empty
[ ! -s /work/private/request.1 ] || exit 1
for n in 2 3; do
 if [ "$n" = 2 ]; then phase=repeat_one; else phase=repeat_two; fi
 ready || exit 1
 /bin/busybox nc -w 2 127.0.0.1 19089 < /work/private/send.$n > /work/private/received.$n 2>/work/private/client.err || exit 1
 [ ! -s /work/private/client.err ] || exit 1
 done_connection "$n" || exit 1
done
phase=requests
for n in 2 3; do /bin/busybox cmp -s /work/private/send.$n /work/private/request.$n || exit 1; done
phase=responses
for n in 1 2 3; do /bin/busybox cmp -s /work/private/response /work/private/received.$n || exit 1; done
wait "$loop" || exit 1
loop=
printf "NCPRIMITIVE-BEHAVIOR-PASSED\n"
' || setup_refused script_setup
# Preserve a fixed exec failure if the timeout/interpreter cannot be invoked.
/bin/busybox timeout 18 /bin/busybox sh /work/private/probe.sh
code=$?
case "$code" in 126|127) setup_refused script_exec;; esac
exit "$code"
'''


class ClientNCRefused(ValueError):
    def __init__(self,phase):
        super().__init__('client-nc-refused');self.phase=phase if phase in PHASES else 'run'


def _launch_125_phase(stderr):
    """Lossy classification of bounded PRIVATE launch stderr, never a receipt.

    Only compiled public error phrases and compiled tmpfs options are tested;
    no captures, path extraction, raw text, exception hints or fallback output.
    This changes refusal diagnostics only, never authorizes a launch/retry.
    """
    if type(stderr) is not bytes or not stderr or len(stderr)>LIMIT:return 'launch_125'
    raw=stderr.lower()
    invalid_mount=any(phrase in raw for phrase in
        (b'invalid mount option',b'invalid tmpfs option',b'invalid tmpfs mount option',
         b'unsupported mount option',b'unsupported tmpfs option'))
    if invalid_mount and any(option in raw for option in (b'uid=1000',b'gid=1000')):
        return 'launch_tmpfs_uid_gid'
    if invalid_mount and b'tmpfs' in raw:return 'launch_tmpfs_option'
    if b'tmpfs' in raw and any(phrase in raw for phrase in (b'operation not permitted',b'permission denied')):
        return 'launch_tmpfs_permission'
    if any(phrase in raw for phrase in (b'not enough ids available',b'insufficient uids or gids',
                                       b'cannot set uid',b'cannot set gid',b'invalid uid mapping',b'invalid gid mapping')):
        return 'launch_user_mapping'
    if any(phrase in raw for phrase in (b'cannot allocate memory',b'pids limit exceeded',b'too many open files')):
        return 'launch_resource'
    if any(phrase in raw for phrase in (b'unknown flag:',b'unknown shorthand flag:',b'flag provided but not defined:')):
        return 'launch_option'
    if b'oci runtime' in raw:return 'launch_oci'
    return 'launch_125'


def _validate(result):
    # Only compiled exit classes and framed phases escape. Never copy/parse
    # stderr content outside the bounded 125 classifier, and never accept a
    # success carrying any stderr bytes.
    if (type(result.returncode) is not int or type(result.stdout) is not bytes
            or len(result.stdout)>LIMIT or type(result.stderr) is not bytes
            or len(result.stderr)>LIMIT):raise ClientNCRefused('output')
    raw=result.stdout
    if not raw:
        if result.returncode==125:raise ClientNCRefused(_launch_125_phase(result.stderr))
        if result.returncode in LAUNCH_CODES:raise ClientNCRefused('launch_'+str(result.returncode))
        if result.returncode==124:raise ClientNCRefused('timeout')
        if result.stderr:raise ClientNCRefused('stderr')
        raise ClientNCRefused('exit_other' if result.returncode else 'output')
    if raw==b'NCPRIMITIVE-REFUSED:inventory\n' and result.returncode!=0:
        raise ClientNCRefused('inventory')
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
    if result.returncode!=0:
        for phase in (*SETUP,*BEHAVIOR):
            if tail==b'NCPRIMITIVE-REFUSED:'+phase.encode()+b'\n':raise ClientNCRefused(phase)
        if result.returncode==124 and not tail:raise ClientNCRefused('timeout')
    if result.stderr:raise ClientNCRefused('stderr')
    if result.returncode==0 and tail==PASS:return
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
            try:result=provision.runner.podman('run','--rm',*args,'--pull=never','--read-only','--network=none',
                '--image-volume=ignore','--log-driver=none','--memory=32m','--cpus=0.25','--pids-limit=16',
                '--timeout=20','--stop-timeout=1','--user=1000:1000','--tmpfs',TMPFS,
                '--entrypoint=/bin/busybox',CLIENT,'sh','-c',SCRIPT,timeout=25,max_output=LIMIT,check=False)
            except (TimeoutError,subprocess.TimeoutExpired):raise ClientNCRefused('timeout') from None
            except Exception:raise ClientNCRefused('runner') from None
            _validate(result);phase='cleanup'
        return RECEIPT
    except ClientNCRefused:raise
    except BaseException:raise ClientNCRefused(phase) from None
