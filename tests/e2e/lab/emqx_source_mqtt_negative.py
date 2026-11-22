"""Owned B1 negative CONNECT probes; no publish, broker creation or evidence.

Requires private API-observed ban expiry, not guessed original seed metadata.
Does not prove archive-final Mnesia truth or active ACL chain behavior.
"""
from datetime import datetime
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time

from emqx_adapter_owner import OwnerProvision, LabOwnerRunner
from emqx_adapter_mqtt import CLIENT
from emqx_owner_fixture_files import _record
from emqx_post_restore_values import _runtime_identity
from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import RuntimeRegistry
from emqx_runtime_workflow import CombinedRegistry
from emqx_real_owner_workflow import SourceClients, _ram_client_parent
from emqx_source_api_validator import SourceAPIResult

BANNED = b'b1-banned-client'


class NegativeMQTTResult:
    def __init__(self, observed, anonymous): self._observed,self._anonymous=observed,anonymous
    def __repr__(self): return '<EMQX private negative CONNECT observation>'
    def scan(self,payload): self._observed.scan(payload)
    def private_facts(self):
        return {'anonymous_connack':self._anonymous,'banned_connack':138,
                'scope':'authentication-and-ban-only-not-active-acl'}


def _ban_deadline(observed):
    document=observed.private_documents()['banned']
    if type(document) is not dict or type(document.get('data')) is not list: raise ValueError()
    rows=[r for r in document['data'] if r.get('as')=='clientid' and r.get('who')==BANNED.decode()]
    if len(rows)!=1: raise ValueError()
    until=rows[0]['until']
    if until=='infinity': return float('inf')
    # Pinned API formats epoch seconds as RFC3339; do not guess units or accept
    # missing/opaque/numeric/string dates from a different producer contract.
    if type(until) is not str or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)',until) is None:
        raise ValueError()
    parsed=datetime.fromisoformat(until.replace('Z','+00:00'))
    if parsed.tzinfo is None: raise ValueError()
    return parsed.timestamp()


def _probe(provision,cid,runtime,*,username=None,password=None):
    r=provision.runner
    name=provision.fixture.prefix+'-negative-'+secrets.token_hex(6)
    owned=False
    with tempfile.TemporaryDirectory(prefix=name+'-',dir=_ram_client_parent()) as directory:
        root=Path(directory);root.chmod(0o700)
        info=root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError()
        config=b'-i '+(BANNED if username is not None else name.encode())+b'\n-t b1/retained/#\n'
        if username is not None: config+=b'-u '+username+b'\n-P '+password+b'\n'
        fd=os.open(root/'mosquitto_sub',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as handle:
            os.fchmod(handle.fileno(),0o600);handle.write(config);handle.flush()
            st=os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600: raise ValueError()
        try:
            if r.podman('container','exists',name,timeout=5,max_output=4096,check=False).returncode!=1: raise ValueError()
            owned=True
            result=r.podman('run','--rm','--name',name,'--pull=never','--log-driver=none','--image-volume=ignore',
                '--network=container:'+cid,'--userns=keep-id:uid=1000,gid=1000','--user=1000:1000',
                '--memory=64m','--cpus=0.25','--pids-limit=32','--timeout=15','--stop-timeout=1',
                '-e','HOME=/work','-e','XDG_CONFIG_HOME=/work','-v',str(root)+':/work:ro',
                '--entrypoint=mosquitto_sub',CLIENT,'-h','127.0.0.1','-p','1883','-V','mqttv5',
                '-q','1','-E','-W','5','-d',timeout=20,max_output=65536,check=False)
            if (type(result.returncode) is not int or any(type(x) is not bytes or len(x)>65536 for x in (result.stdout,result.stderr))): raise ValueError()
            output=result.stdout+b'\n'+result.stderr
            runtime.register_bundle({'runtime-login-token':[x for x in (result.stdout,result.stderr) if x]})
            reasons=re.findall(rb'received CONNACK \(([0-9]{1,3})\)',output)
            expected=(138,) if username is not None else (134,135)
            if len(reasons)!=1 or int(reasons[0]) not in expected or result.returncode!=int(reasons[0]): raise ValueError()
            return int(reasons[0])
        finally:
            if owned:
                removed=absent=False
                try: removed=r.podman('rm','--force','--ignore',name,timeout=5,max_output=4096,check=False).returncode==0
                finally: absent=r.podman('container','exists',name,timeout=5,max_output=4096,check=False).returncode==1
                if not removed or not absent: raise ValueError()


def validate_source_mqtt_negative(*,provision,expected_container_id,clients,source_api,quiesce):
    """2 explicit MQTTv5 refusals through exact current CID; no default auth.

    source_api is an actual validate_source_api result with complete prior runtime.
    Gateway credentials must ALREADY be registered; no new source coverage claim.
    Caller supplies actual exclusion. Ban expiry must cover the120s cooperative
    operation budget (native runner call<=20s; late finish refuses). RAM config
    directory700/file600, fixed tmpfs, all owned container/file cleanup mandatory.
    Old file capability is issuance/lifetime proof ONLY and never rebound.
    """
    try:
        if (type(provision) is not OwnerProvision or not isinstance(provision.runner,LabOwnerRunner)
                or provision.runner.owner!='appowner' or type(clients) is not SourceClients
                or type(source_api) is not SourceAPIResult or type(expected_container_id) is not str
                or re.fullmatch('[0-9a-f]{64}',expected_container_id) is None or not callable(quiesce)): raise ValueError()
        root=source_api._prior
        from emqx_post_restore_values import PostRestoreValues
        for _ in range(4):
            if type(root) is PostRestoreValues:root=root._previous
        if type(root) is not CombinedRegistry or type(root._runtime) is not RuntimeRegistry or source_api._runtime is not root._runtime: raise ValueError()
        runtime=root._runtime;source_api.scan(b'')
        user,password=(clients.fields['gateway_user'],clients.fields['gateway_password'])
        if (user!=b'b1-gateway' or any(type(v) is not bytes or re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',v) is None for v in (user,password))
                or user not in runtime._values or password not in runtime._values): raise ValueError()
        expiry=_ban_deadline(source_api)
        runtime.register_bundle({'runtime-login-input':[BANNED]})
        record,owner=_record(provision.file_capability)
        if owner is not provision:raise ValueError()
        old=record['cid'];deadline=time.monotonic()+120
        def timely():
            if time.monotonic()>=deadline or expiry<=time.time()+120:raise ValueError()
        with quiesce():
            timely();before=_runtime_identity(provision,expected_container_id)
            if before[3].get('NetworkMode')!='none':raise ValueError()
            anonymous=_probe(provision,expected_container_id,runtime);timely()
            _probe(provision,expected_container_id,runtime,username=user,password=password);timely()
            if _runtime_identity(provision,expected_container_id)!=before or record['cid']!=old:raise ValueError()
        if _record(provision.file_capability)[1] is not provision or record['cid']!=old:raise ValueError()
        timely();source_api.scan(b'')
        return NegativeMQTTResult(source_api,anonymous)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('source-negative-cancelled') from None
    except Exception:raise PrivateFailure('source-negative-refused') from None
