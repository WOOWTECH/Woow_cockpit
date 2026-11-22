"""Fixed pinned CLIENT BusyBox applet inventory; no broker/source/delivery IO."""
import re
import secrets

from emqx_adapter_owner import OwnerProvision,LabOwnerRunner
from emqx_adapter_mqtt import CLIENT
from emqx_native_runtime import IMAGE
from emqx_owned_client import owned_client

RECEIPT=b'CLIENT SINK CAPABILITIES PASSED\n'
PHASES=frozenset(('realm','input','owner','run','applets','missing_nc','missing_httpd','missing_timeout','missing_sh','cleanup'))
LIMIT=65536
REQUIRED=('nc','httpd','timeout','sh')


class ClientSinkRefused(ValueError):
    def __init__(self,phase):
        super().__init__('client-sink-refused')
        self.phase=phase if phase in PHASES else 'input'


def run_client_sink_capabilities():
    """One no-network, read-only, named pinned CLIENT invocation, then cleanup.

    Constructor only: OwnerProvision.create and all source credential/frame IO
    are forbidden here. Exact applet names attest only compiled applet presence,
    not listen flags, HTTP behavior, source coverage, delivery or restore success.
    No host mount, env, additional executable or image is accepted.
    """
    phase='owner'
    try:
        provision=OwnerProvision(IMAGE.removeprefix('sha256:'))
        if (type(provision) is not OwnerProvision or type(provision.runner) is not LabOwnerRunner
                or provision.runner.owner!='appowner' or provision.file_capability is not None
                or provision.created):raise ValueError()
        runner=provision.runner
        name=provision.fixture.prefix+'-mqtt-'+secrets.token_hex(6)
        with owned_client(runner,name) as args:
            phase='run'
            result=runner.podman('run','--rm',*args,'--pull=never','--read-only','--network=none',
                '--image-volume=ignore','--log-driver=none','--memory=32m','--cpus=0.25',
                '--pids-limit=16','--timeout=15','--stop-timeout=1','--user=1000:1000',
                '--entrypoint=/bin/busybox',CLIENT,'--list',timeout=20,max_output=LIMIT,check=False)
            if (type(result.returncode) is not int or result.returncode!=0
                    or type(result.stdout) is not bytes or not 0<len(result.stdout)<=LIMIT
                    or type(result.stderr) is not bytes or result.stderr!=b''):raise ValueError()
            phase='applets'
            raw=result.stdout
            if not raw.isascii() or not raw.endswith(b'\n'):raise ValueError()
            applets=raw[:-1].split(b'\n')
            if (not 1<=len(applets)<=1024 or len(set(applets))!=len(applets)
                    or any(re.fullmatch(rb'[A-Za-z0-9_.\[\]-]{1,64}',name) is None for name in applets)):raise ValueError()
            for name in REQUIRED:
                if name.encode('ascii') not in applets:raise ClientSinkRefused('missing_'+name)
            phase='cleanup'
        return RECEIPT  # Only after nonce/CID cleanup/absence proof returned normally.
    except ClientSinkRefused:raise
    except BaseException:raise ClientSinkRefused(phase) from None
