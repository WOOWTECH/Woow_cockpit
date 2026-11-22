"""Private real-HA same-fixture foundation, intentionally NOT a lab/host CLI.

Fixed encrypted source frames only. No synthetic backup producer, FreshTarget,
external target credentials or public HA import. Runtime remains gated on the
issued-fixture composite observer, full observed target capture and product gates.
Only an authorized sole lab owner may eventually invoke this internal operation.
"""
from contextlib import contextmanager
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import tempfile
import time
from types import SimpleNamespace

from emqx_adapter_owner import OwnerProvision, LabOwnerRunner
from emqx_adapter_fixture import Fixture
from emqx_arm_source_owner import validate_source_capture, _exact
from emqx_captured_candidate import build_captured_candidate
from emqx_fresh_owner_workflow import staged_owner_frame
from emqx_native_runtime import IMAGE
from emqx_owner_preflight import owner_preflight
from emqx_owner_source_capture import capture_owner_source
from emqx_owner_target import owner_target_readers, MAX_WIRE
from emqx_private_boundary import PrivateFailure
from emqx_private_owner_driver import curl_login_transport
from woowbackup import catalog, flows
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.paths import Paths

PHASES = frozenset(('profile','observer_dependency','realm','frame','provision',
    'ready','source','target','preflight','build','package','restore',
    'rollback','restart','cleanup','client_frame','no_live','mqtt','post_capture','post_capture_identity','payload_history','build_adapter'))
from emqx_candidate_stage import STAGES as BUILD_STAGES, KINDS as BUILD_KINDS
from emqx_captured_candidate import CandidatePhaseRefused
PHASES=PHASES | frozenset('build_'+s+'_'+k for s in BUILD_STAGES for k in BUILD_KINDS)
SOURCE_MODES = ('--source-vendor-acl-sql-aliases','--x86-source-vendor-acl-sql-aliases')


class RealOwnerRefused(PrivateFailure):
    def __init__(self, phase):
        self.phase = phase if phase in PHASES else 'profile'
        super().__init__('private-real-owner-refused')


def _composite_observer_factory():
    from emqx_target_fixture_policy import issued_fixture_observer
    if not callable(issued_fixture_observer): raise ImportError()
    return issued_fixture_observer


def _logical_raw(fixture):
    raw = copy.deepcopy(fixture.catalog())
    raw['id'] = 'emqx'
    return raw


def private_catalog(fixture, paths):
    """Only logical ID changes; all issued resource declarations stay identical."""
    if type(fixture) is not Fixture or fixture.image_id != IMAGE.removeprefix('sha256:'):
        raise ValueError()
    # Validate the ACTUAL fixture namespace first. Public catalog installation
    # still rejects fixture config paths under logical id emqx; do not weaken it.
    original = catalog.validate_entry(fixture.catalog(),paths=paths)
    raw = _logical_raw(fixture)
    digest = hashlib.sha256(json.dumps(raw,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    app = replace(original,id='emqx',raw=raw,sha256=digest)
    return catalog.Catalog({'emqx':app})


def _assert_binding(provision, app):
    from emqx_owner_fixture_files import _record
    if type(provision) is not OwnerProvision or type(provision.runner) is not LabOwnerRunner:
        raise ValueError()
    record, owner = _record(provision.file_capability)
    if owner is not provision or record['fixture'] is not provision.fixture:
        raise ValueError()
    f = provision.fixture
    expected = private_catalog(f,Paths(base=Path(provision.runner.home)/'private-catalog-only'))['emqx']
    if (app != expected or type(app) is not catalog.App or app.raw != _logical_raw(f)
            or app.id != 'emqx' or app.owner != provision.runner.owner
            or app.units != (f.unit,) or app.writer_units != (f.unit,)
            or {v['name'] for v in app.volumes} != set(f.volumes)
            or {s['name'] for s in app.secrets} != {f.secret,f.dashboard_secret}
            or app.postgres or app.data_dirs):
        raise ValueError()
    return record


def bound_target(provision, app):
    _assert_binding(provision,app)
    f, r = provision.fixture, provision.runner
    base = r.home+'/.config/'+f.prefix
    return SimpleNamespace(container=f.prefix,image=IMAGE,
        data_volume=f.volumes[0],log_volume=f.volumes[1],
        env={'EMQX_NODE__NAME':'emqx@127.0.0.1'},
        files=[(base+'/base.hocon','/opt/emqx/etc/base.hocon','ro'),
               (base+'/acl.conf','/opt/emqx/etc/lab-acl.conf','ro')],
        secrets=[f.secret+',type=mount,target=/opt/emqx/etc/lab-bootstrap.csv,uid=1000,gid=1000,mode=0400',
                 f.dashboard_secret+',type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'])


class PrivateReporter:
    """Flow callbacks deliberately retain no private product diagnostics."""
    cancellable = False
    def phase(self,*a,**k): pass
    skip = complete = fail = mark = add_phase = log = set_partial = progress = phase
    def set_cancellable(self,flag): self.cancellable=flag;return False
    def cancel_requested(self): return False


class CandidateBudget:
    def __init__(self): self.used=0
    def budget(self): return 2*1024**3-self.used
    def wrote(self,size):
        if type(size) is not int or size<0: raise ValueError()
        self.used+=size
        if self.budget()<0: raise ValueError()


def flow_context(provision,root,job):
    """Product FlowContext restricted to a private Paths clone and this fixture."""
    paths=Paths(base=Path(root)/'engine')
    private=private_catalog(provision.fixture,paths)
    app=private['emqx']
    _assert_binding(provision,app)
    deps=flows.default_deps(paths)
    deps.load_catalog=lambda:private
    deps.encrypt_by_default=lambda:False
    deps.sweep_temp=None
    deps.audit=lambda _line:None
    state={'armed':False,'injected':False}
    marker='.config/'+provision.fixture.prefix+'/fail-once'
    def factory(app_,**kwargs):
        _assert_binding(provision,app_)
        imported_hook=kwargs.pop('imported_hook',None)
        def imported():
            if imported_hook is not None: imported_hook()
            if state['armed'] and not state['injected']:
                provision.runner.write_file(marker,b'fail once\n',0o600)
                state['injected']=True
        return QuadletPostgresAdapter(app_,provision.runner,imported_hook=imported,**kwargs)
    deps.adapter_factory=factory
    return flows.FlowContext(paths,job,deps,PrivateReporter()),app,state


def _inspect(provision):
    from emqx_semantic_readers import _pairs
    r,f=provision.runner,provision.fixture
    response=r.podman('container','inspect',f.prefix,timeout=5,max_output=65536)
    raw=response.stdout
    if response.returncode or type(raw) is not bytes or not 0<len(raw)<=65536: raise ValueError()
    rows=json.loads(raw,object_pairs_hook=_pairs)
    if type(rows) is not list or len(rows)!=1: raise ValueError()
    f.validate_inspection(rows[0])
    if rows[0]['HostConfig'].get('LogConfig',{}).get('Type') != 'none': raise ValueError()
    return rows[0]


def _ready(provision):
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        _inspect(provision)
        response=provision.runner.podman('exec',provision.fixture.prefix,'emqx','ctl','status',
            timeout=10,max_output=65536,check=False)
        if response.returncode==0 and b'is started' in response.stdout:return
        time.sleep(1)
    raise ValueError()


@contextmanager
def fixture_quiescence(provision):
    """Limited same-fixture no-client/ticker exclusion; no completeness assertion."""
    from woowbackup.ha_emqx import SUSPEND_SYS_EXPR,TICKER_STATUS_EXPR
    r,f=provision.runner,provision.fixture
    before=_inspect(provision)
    def evaluate(expr):
        response=r.podman('exec',f.prefix,'emqx','eval',expr,timeout=15,max_output=65536)
        if response.returncode or type(response.stdout) is not bytes or len(response.stdout)>65536:
            raise ValueError()
        return response.stdout.strip()
    def stable():
        after=_inspect(provision)
        if before['Id']!=after['Id']: raise ValueError()
        if evaluate('[] = emqx_cm:all_channels(), io:format("OWNERNOCLIENTS").')!=b'OWNERNOCLIENTSok':
            raise ValueError()
    stable()
    match=re.fullmatch(rb'WOOWSYS:(<[0-9]+\.[0-9]+\.[0-9]+>):suspended\s*(?:ok\s*)?',
                      evaluate(SUSPEND_SYS_EXPR))
    if match is None: raise ValueError()
    expression=TICKER_STATUS_EXPR.replace('{pid}',match[1].decode('ascii'))
    if evaluate(expression)!=b'ticker_unchanged': raise ValueError()
    try: yield
    finally:
        stable()
        if evaluate(expression)!=b'ticker_unchanged': raise ValueError()


def _package_same_target(ctx,app,provision,volumes,root):
    _assert_binding(provision,app)
    if type(volumes) is not dict or set(volumes)!=set(provision.fixture.volumes):raise ValueError()
    staging=Path(root)/'package';staging.mkdir(mode=0o700)
    ctx.storage.ensure_layout()
    app_dir=staging/'apps'/app.id;app_dir.mkdir(mode=0o700,parents=True)
    manifest,entries=ctx.adapter(app).import_manifest(app_dir,volumes=volumes)
    result=flows._package(ctx,[app],staging,include_images=False,
        note='private EMQX owner candidate',backup_type='manual',key=None,
        phases=False,manifest_apps=[manifest],entries=entries,downtime=0)
    return result['backup_id']


def _restore_and_rollback(ctx,app,provision,backup_id,state,*,clients=None,session=None):
    """Product restore, destructive one-shot startup failure, automatic rollback.

    Live callers supply source clients and require MQTT checks plus supplemental
    capture after every last client activity. File-policy authorization does not
    prove source Mnesia ACL behavior. Never report commercial acceptance.
    """
    _assert_binding(provision,app)
    post_registry=session.registry if session is not None else None
    request={'backup_id':backup_id,'apps':['emqx'],'accept_unauthenticated':True}
    outcome=flows.run_restore(ctx,request)
    if outcome.get('rolled_back') or not outcome.get('changed'):raise ValueError()
    _ready(provision)
    if clients is not None:validate_source_mqtt(provision,clients)
    if session is not None:post_registry=_post_activity_capture(provision,post_registry)
    r,f=provision.runner,provision.fixture
    directory='.config/systemd/user/'+f.unit+'.d'
    dropin=directory+'/woowbk-real-owner-fail-once.conf'
    marker='.config/'+f.prefix+'/fail-once'
    directory_created=dropin_created=False
    try:
        if r.stat_files([directory,dropin,marker])[directory]['type']!='missing':raise ValueError()
        if any(r.stat_files([path])[path]['type']!='missing' for path in (dropin,marker)):raise ValueError()
        r.run(['/usr/bin/mkdir','-m','0700','--',r.home+'/'+directory]);directory_created=True
        command=('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/'+marker+
            '; then rm -f %h/'+marker+'; exit 1; fi\'\n').encode()
        r.write_file(dropin,command,0o600);dropin_created=True
        r.systemctl('daemon-reload')
        state['armed']=True
        try:
            flows.run_restore(ctx,request)
        except flows.RolledBack as error:
            if error.result.get('rolled_back') is not True or not state['injected']:raise ValueError()
        else:raise ValueError()
        _ready(provision)
        if clients is not None:validate_source_mqtt(provision,clients)
        if session is not None:post_registry=_post_activity_capture(provision,post_registry)
        if r.stat_files([marker])[marker]['type']!='missing':raise ValueError()
    finally:
        state['armed']=False
        if dropin_created:r.remove_file(dropin)
        if state['injected']:r.remove_file(marker)
        if directory_created:r.run(['/usr/bin/rmdir','--',r.home+'/'+directory])
        if dropin_created:r.systemctl('daemon-reload')
    r.systemctl('restart','--',f.unit,timeout=180)
    _ready(provision)
    if clients is not None:validate_source_mqtt(provision,clients)
    if session is not None:post_registry=_post_activity_capture(provision,post_registry)
    return post_registry


def _post_activity_capture(provision,prior_registry):
    """Capture values through independently reverified current issued runtime.

    The value-only collector proves current CID/pins inside the exclusion lease;
    it neither rebinds the original file capability nor issues a build capability.
    """
    from emqx_owner_fixture_files import _record
    from emqx_post_restore_values import collect_post_restore_values
    record,owner=_record(provision.file_capability)
    current=_inspect(provision)
    cid=current.get('Id')
    if (owner is not provision or type(cid) is not str or re.fullmatch('[0-9a-f]{64}',cid) is None
            or record['cid'] is None):
        raise RealOwnerRefused('post_capture_identity')
    try:
        return collect_post_restore_values(prior_registry=prior_registry,provision=provision,
            expected_container_id=cid,quiesce=lambda:fixture_quiescence(provision))
    except BaseException:
        raise RealOwnerRefused('post_capture') from None


def _full_restore_budget():
    # Fixed actual cgroup counters, not a caller acknowledgement. No memory tuning.
    current=Path('/sys/fs/cgroup/memory.current').read_text().strip()
    maximum=Path('/sys/fs/cgroup/memory.max').read_text().strip()
    if (not current.isascii() or not maximum.isascii() or not current.isdecimal()
            or not maximum.isdecimal() or int(maximum)-int(current)<1800*1024**2):
        raise ValueError()


CLIENT_MAGIC=b'WOOWREALCLIENT1:'
CLIENT_MODES={SOURCE_MODES[0]:b'A',SOURCE_MODES[1]:b'B'}
CLIENT_FIELDS=('sensor_user','sensor_password','gateway_user','gateway_password',
               'third_user','third_password','retained_topic1','retained_payload1',
               'retained_topic2','retained_payload2')


class SourceClients:
    __slots__=('fields',)
    def __init__(self,fields):self.fields=fields
    def __repr__(self):return '<SourceClients private>'


def read_source_clients(stream,source_mode):
    """Fixed prefix BEFORE the unchanged key/ciphertext frame; no trailing data.

    magic, fixed profile byte, then ten uint16 lengths + bytes in CLIENT_FIELDS
    order. Six single-line ASCII Mosquitto auth fields <=128B; two fixed-prefix
    topics <=128B and two binary payloads <=4096B. No paths, argv or env inputs.
    EOF/finish is enforced by the subsequent staged_owner_frame over this stream.
    """
    if source_mode not in CLIENT_MODES:raise ValueError()
    if _exact(stream,len(CLIENT_MAGIC))!=CLIENT_MAGIC:raise ValueError()
    if _exact(stream,1)!=CLIENT_MODES[source_mode]:raise ValueError()
    fields={}
    for index,name in enumerate(CLIENT_FIELDS):
        size=struct.unpack('!H',_exact(stream,2))[0]
        bound=4096 if name.startswith('retained_payload') else 128
        if not 1<=size<=bound:raise ValueError()
        raw=_exact(stream,size)
        if index<6 and re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',raw) is None:raise ValueError()
        if name.startswith('retained_topic') and re.fullmatch(rb'b1/retained/[A-Za-z0-9_/-]{1,110}',raw) is None:
            raise ValueError()
        fields[name]=raw
    if fields['sensor_user']!=b'b1-sensor' or fields['gateway_user']!=b'b1-gateway':raise ValueError()
    if len({fields[name] for name in ('sensor_user','gateway_user','third_user')})!=3 or fields['third_user']==b'lab':raise ValueError()
    if fields['retained_topic1']==fields['retained_topic2']:raise ValueError()
    wrong=secrets.token_hex(24).encode()
    while wrong in tuple(fields.values()):wrong=secrets.token_hex(24).encode()
    fields['negative_password']=wrong
    return SourceClients(fields)


def _target_base():
    return (b'node.name="emqx@127.0.0.1"\nnode.data_dir="/opt/emqx/data"\n'
        +b'node.cookie="'+secrets.token_hex(24).encode()+b'"\n'
        +b'cluster.discovery_strategy=manual\ncluster.proto_dist=inet_tcp\nrpc.protocol=tcp\n'
        +b'dashboard.default_username="owner"\n'
        +b'dashboard.listeners.http.bind="127.0.0.1:18083"\n'
        +b'listeners.tcp.default.bind="127.0.0.1:1883"\n'
        +b'listeners.ssl.default.enable=false\nlisteners.ws.default.enable=false\nlisteners.wss.default.enable=false\n'
        +b'authentication=[{mechanism=password_based,backend=built_in_database,'
         b'user_id_type=username,enable=true,password_hash_algorithm={name=sha256,salt_position=suffix},'
         b'bootstrap_file="/opt/emqx/etc/lab-bootstrap.csv",bootstrap_type=plain}]\n'
         b'authorization={no_match=deny,deny_action=ignore,sources=[{type=file,enable=true,'
         b'path="/opt/emqx/etc/lab-acl.conf"}]}\n')


def _target_acl():
    """Explicit isolated target FILE policy, not source Mnesia ACL semantics.

    Keep target-only lab/# behavior and deny-by-default. Authorize only the
    source fixture's already-known gateway retained read and sensor deny probe.
    The issued file observer must collect every literal before build.
    """
    return (b'{allow, {username, "lab"}, all, ["lab/#"]}.\n'
            b'{allow, {username, "b1-gateway"}, subscribe, ["b1/retained/#"]}.\n'
            b'{deny, {username, "b1-sensor"}, subscribe, ["b1/secret/#"]}.\n'
            b'{deny, all}.\n')


def _opt_in_private_unit(provision):
    """Only this issued, not-yet-started fixture unit; no global fixture edits.

    Hooke's fixed CreateCommand parser must also support --image-volume=ignore;
    until then its unchanged provenance gate intentionally refuses live use.
    """
    from emqx_owner_fixture_files import _record
    if _record(provision.file_capability)[1] is not provision:raise ValueError()
    f,r=provision.fixture,provision.runner
    path='.config/containers/systemd/'+f.prefix+'.container'
    original=f.container_unit().encode()
    if r.read_file(path,max_bytes=65536)!=original:raise ValueError()
    line=b'PodmanArgs=--memory=768m --cpus=1 --pids-limit=512\n'
    if original.count(line)!=1:raise ValueError()
    updated=original.replace(line,line[:-1]+b' --log-driver=none --image-volume=ignore\n')
    r.write_file(path,updated,0o600)
    if r.read_file(path,max_bytes=65536)!=updated:raise ValueError()
    r.systemctl('daemon-reload')


def _ram_client_parent():
    # Original client passwords are never staged to a disk-backed temp directory.
    with open('/proc/self/mountinfo','rb') as source:
        raw=source.read(1024**2+1)
    if len(raw)>1024**2:raise ValueError()
    mounts=[]
    for line in raw.splitlines():
        left,separator,right=line.partition(b' - ')
        fields=left.split()
        if len(fields)>4 and fields[4]==b'/dev/shm':
            mounts.append(right.split()[0] if separator and right.split() else b'')
    if mounts!=[b'tmpfs'] or Path('/dev/shm').is_symlink():raise ValueError()
    return Path('/dev/shm')


def _register_client_inputs(session,clients,evidence):
    """Add real MQTT login inputs to the already observed complete runtime only.

    Does not claim new source/target coverage. Re-scan identical private receipt
    after registration, before MQTT IO or candidate build. No pretty/JSON replay.
    """
    from emqx_runtime_workflow import PrivateSession,CombinedRegistry
    from emqx_runtime_credentials import RuntimeRegistry
    import stat
    if (type(session) is not PrivateSession or type(session.registry) is not CombinedRegistry
            or type(session.registry._runtime) is not RuntimeRegistry or type(clients) is not SourceClients):
        raise ValueError()
    runtime=session.registry._runtime
    runtime.summary()  # still requires actual complete target, never an empty ack
    runtime.register_bundle({'runtime-login-input':[
        clients.fields[name] for name in (*CLIENT_FIELDS[:6],'negative_password')]})
    fd=os.open(evidence,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=65536):raise ValueError()
        raw=source.read(65537)
        after=os.fstat(source.fileno())
        if (len(raw)!=info.st_size or source.read(1)!=b'' or any(getattr(info,key)!=getattr(after,key)
                for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))):raise ValueError()
    session.registry.scan(raw)
    from emqx_runtime_workflow import SOURCE_CATEGORIES
    source_counts=session.registry._source.summary()
    actual=runtime.summary()
    coverage={name:source_counts[name] for name in SOURCE_CATEGORIES}
    for name in ('mqtt-auth','api-keys','connectors','tls','target-bootstrap'):coverage[name]=actual[name]
    coverage['target-bootstrap']+=actual.get('runtime-login-input',0)+actual.get('runtime-login-token',0)
    session.coverage=coverage  # re-derived actual summary, never hand-filled counts


def _mqtt_private(provision,clients,role,*,topic,retained=False,wrong_password=None):
    """Bounded pinned Mosquitto subscription only, never publish source payloads.

    Uses private config, retained bit/topic/hex-payload formatting per official
    mosquitto_sub manual (https://mosquitto.org/man/mosquitto_sub-1.html).
    Raw output never leaves this trusted caller.
    """
    from emqx_adapter_mqtt import CLIENT
    r,f=provision.runner,provision.fixture
    user=clients.fields[role+'_user'];password=wrong_password or clients.fields[role+'_password']
    if re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',user) is None or re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',password) is None:
        raise ValueError()
    topic_raw=topic.encode('ascii')
    if topic not in ('b1/retained/#','b1/secret/#') and re.fullmatch(rb'b1/retained/[A-Za-z0-9_/-]{1,110}',topic_raw) is None:
        raise ValueError()
    client=f.prefix+'-mqtt-'+secrets.token_hex(6)
    owned=False
    with tempfile.TemporaryDirectory(prefix=client+'-',dir=_ram_client_parent()) as directory:
        root=Path(directory);root.chmod(0o700)
        fd=os.open(root/'mosquitto_sub',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as config:
            os.fchmod(config.fileno(),0o600);config.write(b'-u '+user+b'\n-P '+password+b'\n-t '+topic_raw+b'\n')
        try:
            if r.podman('container','exists',client,check=False,timeout=10,max_output=4096).returncode!=1:
                raise ValueError()
            owned=True
            command=['run','--rm','--name',client,'--pull=never','--log-driver=none','--image-volume=ignore',
                '--network=container:'+f.prefix,'--userns=keep-id:uid=1000,gid=1000','--user=1000:1000',
                '--memory=64m','--cpus=0.25','--pids-limit=32','--timeout=15','--stop-timeout=1',
                '-e','HOME=/work','-e','XDG_CONFIG_HOME=/work','-v',str(root)+':/work:ro',
                '--entrypoint=mosquitto_sub',CLIENT,'-h','127.0.0.1','-p','1883','-V','mqttv5',
                '-q','1','-i',client]
            command += ['-C','1','-W','5','-F','%r:%t:%x'] if retained else ['-E','-W','5','-d']
            result=r.podman(*command,timeout=20,check=False,max_output=65536)
            if (type(result.returncode) is not int or any(type(x) is not bytes or len(x)>65536
                    for x in (result.stdout,result.stderr))):raise ValueError()
            return result
        finally:
            if owned:
                removed=absent=False
                try:removed=r.podman('rm','--force','--ignore',client,check=False,timeout=10,max_output=4096).returncode==0
                finally:
                    absent=r.podman('container','exists',client,check=False,timeout=10,max_output=4096).returncode==1
                if not removed or not absent:raise ValueError()


def _reason(output,kind):
    pattern=rb'received CONNACK \(([0-9]{1,3})\)' if kind=='connack' else rb'Subscribed[^\n]*:\s*([0-9]{1,3})\b'
    found=re.findall(pattern,output)
    if len(found)!=1:raise ValueError()
    return int(found[0])


def validate_source_mqtt(provision,clients):
    """Explicit source CONNACK, gateway allow, sensor deny and two retained bytes.

    B1 public fixture roles/topics with the COMPILED TARGET FILE ACL: gateway
    retained reads allowed, sensor secret subscriptions denied. This does not
    prove source Mnesia ACL chain behavior. No guessed publish permission.
    Timeout/transport errors never establish protocol authorization or denial.
    """
    if type(clients) is not SourceClients:raise ValueError()
    for role in ('sensor','gateway','third'):
        result=_mqtt_private(provision,clients,role,topic='b1/retained/#')
        output=result.stdout+b'\n'+result.stderr
        if result.returncode not in (0,135) or _reason(output,'connack')!=0:raise ValueError()
        if role=='gateway' and (result.returncode!=0 or _reason(output,'suback') not in (0,1)):
            raise ValueError()
    denied=_mqtt_private(provision,clients,'sensor',topic='b1/secret/#')
    output=denied.stdout+b'\n'+denied.stderr
    if denied.returncode not in (0,135) or _reason(output,'connack')!=0 or _reason(output,'suback')!=135:raise ValueError()
    refused=_mqtt_private(provision,clients,'gateway',topic='b1/retained/#',
        wrong_password=clients.fields['negative_password'])
    if refused.returncode not in (134,135) or _reason(refused.stdout+b'\n'+refused.stderr,'connack') not in (134,135):
        raise ValueError()
    for index in (1,2):
        topic=clients.fields['retained_topic'+str(index)]
        payload=clients.fields['retained_payload'+str(index)]
        result=_mqtt_private(provision,clients,'gateway',topic=topic.decode('ascii'),retained=True)
        if result.returncode or result.stdout!=b'1:'+topic+b':'+payload.hex().encode()+b'\n':raise ValueError()


def final_private_receipt(registry):
    """Return only exact scanned text after all three post-operation captures."""
    from emqx_post_restore_values import PostRestoreValues
    from emqx_private_evidence import names_receipt, SOURCE_NAMES
    if type(registry) is not PostRestoreValues or len(registry._generations) != 3:
        raise RealOwnerRefused('post_capture')
    raw=names_receipt('restore','passed',SOURCE_NAMES)
    registry.scan(raw)
    return raw


def _payload_history(source_mode,source,key,spool,profile,clients):
    """Independently bind original producer expectations to authenticated history.

    Runs before any target mutation. Historical consensus does not replay
    deletion/expiry or prove final presence; later actual retained MQTT must pass.
    """
    from emqx_retained_history import collect_original_retained_payloads,RetainedHistory
    expected=tuple((clients.fields['retained_topic'+str(i)],clients.fields['retained_payload'+str(i)])
                   for i in (1,2))
    if type(key) is not str:raise RealOwnerRefused('payload_history')
    result=collect_original_retained_payloads(source_mode=source_mode,password=key,
        topics=tuple(t for t,_ in expected),spool_directory=spool,source_path=source)
    if (type(result) is not RetainedHistory or result.source_sha256!=profile.sha256
            or result.final_state is not False or result.private_pairs()!=expected):
        raise RealOwnerRefused('payload_history')
    return result


def run_real_framed_owner(stream,*,private_parent,source_mode,no_live=True):
    """Internal fixed-frame operation; NO CLI/host mode or restore right added.

    Default no_live validates only the fixed client prefix and ciphertext frame.
    It authenticates no HA plaintext and performs no provision/client/restore IO.
    Explicit live invocation is reserved to main's authorized held owner wrapper;
    it does not waive any actual source, issued observer, logging or product gate.
    """
    phase='profile'
    provision=None
    create_attempted=False
    try:
        if source_mode not in SOURCE_MODES or type(no_live) is not bool:raise ValueError()
        phase='observer_dependency'
        observer_factory=_composite_observer_factory()
        phase='realm'
        provision=OwnerProvision(IMAGE.removeprefix('sha256:'))
        r,f=provision.runner,provision.fixture
        _full_restore_budget()
        phase='client_frame'
        clients=read_source_clients(stream,source_mode)
        phase='frame'
        with staged_owner_frame(stream,runner=r,private_parent=private_parent,
                source_mode=source_mode) as (source,key,spool,profile,root):
            if no_live:
                return {'scope':'sha-bound-ciphertext-and-client-frame-only','runtime':'not-run',
                        'source_authentication':'not-performed','restore':'not-performed'}
            phase='payload_history'
            retained_history=_payload_history(source_mode,source,key,spool,profile,clients)
            phase='provision'
            # All bootstrap inputs belong solely to THIS invocation/fixture.
            dashboard=secrets.token_hex(24).encode()
            bootstrap=('user_id,password,is_superuser\nlab,'+secrets.token_hex(24)+',false\n').encode()
            base=_target_base()
            acl=_target_acl()
            create_attempted=True
            provision.create(base,acl,bootstrap,dashboard)
            _opt_in_private_unit(provision)
            r.systemctl('start','--',f.unit,timeout=180)
            phase='ready';_ready(provision)
            job='j'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(4)
            ctx,app,state=flow_context(provision,root,job)
            target=bound_target(provision,app)
            candidate=root/'candidate';candidate.mkdir(mode=0o700)
            evidence=root/'evidence';evidence.mkdir(mode=0o700)
            phase='source'
            with capture_owner_source(source,password=key,expected_sha256=profile.sha256,
                    spool_directory=spool,required_encryption='v3',fixture_profile=profile.fixture_profile,
                    file_dependency_profile=profile.file_dependency_profile,product_image=IMAGE) as (captured,binding):
                validate_source_capture(captured,binding,profile)
                def evaluate(expr):
                    result=r.podman('exec',f.prefix,'emqx','eval',expr,timeout=30,max_output=MAX_WIRE,check=False)
                    if result.returncode or type(result.stdout) is not bytes or len(result.stdout)>MAX_WIRE:
                        raise ValueError()
                    return result.stdout
                phase='target'
                with owner_target_readers(private_eval=evaluate,
                        quiesce=lambda:fixture_quiescence(provision),
                        vendor_observer=observer_factory(provision)) as readers:
                    phase='preflight'
                    session=owner_preflight(captured=captured,target_readers=readers,
                        target_generation=readers.generation,
                        private_transport=curl_login_transport(runner=r,broker=f.prefix,
                            login_url='http://127.0.0.1:18083/api/v5/login'),
                        username=b'owner',password=dashboard,evidence_directory=evidence,
                        evidence_name='owner-preflight.txt')
                    _register_client_inputs(session,clients,evidence/'owner-preflight.txt')
                    phase='build'
                    work=SimpleNamespace(runner=lambda _app:r,guard=CandidateBudget(),abort=None,
                        checkpoint=ctx.checkpoint,phase=ctx.phase,log=ctx.log)
                    phase='build_adapter'
                    adapter=ctx.adapter(app)
                    phase='build'
                    try:
                        volumes=build_captured_candidate(work,app,adapter,target,source,candidate,job,
                            captured=captured,private_binding=binding,session=session,expected_sha256=profile.sha256)
                    except CandidatePhaseRefused as error:
                        # The held readers intentionally mask body exceptions;
                        # retain only fixed diagnostics before unwinding them.
                        phase='build_'+error.stage+'_'+error.kind
                        raise
                phase='package'
                backup_id=_package_same_target(ctx,app,provision,volumes,root)
                phase='restore'
                post_registry=_restore_and_rollback(ctx,app,provision,backup_id,state,clients=clients,session=session)
                post_registry.scan(b'')  # retain/check the complete supplemental chain through phase end
            phase='cleanup'
        receipt=final_private_receipt(post_registry)
        phase='payload_history';retained_history.scan(receipt)
        return {'evidence_bytes':receipt,'scope':'private-same-target-product-flow', 'client_validation':'source-login-target-file-acl-retained-after-restore-rollback-restart',
                'source_mnesia_acl_behavior':'not-assessed-target-file-authorizer',
                'source_final_state':'not-assessed','commercial_acceptance':'not-assessed'}
    except RealOwnerRefused:
        raise
    except CandidatePhaseRefused as error:
        raise RealOwnerRefused('build_'+error.stage+'_'+error.kind) from None
    except BaseException:
        raise RealOwnerRefused(phase) from None
    finally:
        if provision is not None and create_attempted:
            try:provision.cleanup()
            except BaseException:raise RealOwnerRefused('cleanup') from None
