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
import tempfile
import time
from types import SimpleNamespace

from emqx_adapter_owner import OwnerProvision, LabOwnerRunner
from emqx_adapter_fixture import Fixture
from emqx_arm_source_owner import validate_source_capture
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
    'rollback','restart','cleanup'))
SOURCE_MODES = ('--source-vendor-acl-sql-aliases','--x86-source-vendor-acl-sql-aliases')


class RealOwnerRefused(PrivateFailure):
    def __init__(self, phase):
        self.phase = phase if phase in PHASES else 'profile'
        super().__init__('private-real-owner-refused')


def _composite_observer_factory():
    """Fixed dependency, never a caller-injected observer or boolean waiver.

    Hooke API needed: fixture_vendor_observer(provision=actual_owner_provision)
    -> held callback(generation, private_values), compatible with the actual
    owner_target_readers policy. It MUST validate the issued FixtureFiles token,
    use its same runner/container, register full vendor+custom values and recheck.
    Missing API refuses BEFORE creating any runtime resource.
    """
    from emqx_target_vendor_policy import fixture_vendor_observer
    if not callable(fixture_vendor_observer): raise ImportError()
    return fixture_vendor_observer


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


def _restore_and_rollback(ctx,app,provision,backup_id,state):
    """Product restore, destructive one-shot startup failure, automatic rollback.

    This foundation checks flow outcomes/readiness, not source MQTT contents or
    retained-message equivalence. Never report commercial acceptance from it.
    """
    _assert_binding(provision,app)
    request={'backup_id':backup_id,'apps':['emqx'],'accept_unauthenticated':True}
    outcome=flows.run_restore(ctx,request)
    if outcome.get('rolled_back') or not outcome.get('changed'):raise ValueError()
    _ready(provision)
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
        if r.stat_files([marker])[marker]['type']!='missing':raise ValueError()
    finally:
        state['armed']=False
        if dropin_created:r.remove_file(dropin)
        if state['injected']:r.remove_file(marker)
        if directory_created:r.run(['/usr/bin/rmdir','--',r.home+'/'+directory])
        if dropin_created:r.systemctl('daemon-reload')
    r.systemctl('restart','--',f.unit,timeout=180)
    _ready(provision)


def _full_restore_budget():
    # Fixed actual cgroup counters, not a caller acknowledgement. No memory tuning.
    current=Path('/sys/fs/cgroup/memory.current').read_text().strip()
    maximum=Path('/sys/fs/cgroup/memory.max').read_text().strip()
    if (not current.isascii() or not maximum.isascii() or not current.isdecimal()
            or not maximum.isdecimal() or int(maximum)-int(current)<1800*1024**2):
        raise ValueError()


def run_real_framed_owner(stream,*,private_parent,source_mode):
    """Internal fixed-frame operation; NO CLI/host mode or restore right added.

    The policy dependency is currently missing and fails closed before mutation.
    Future source client credentials require a separate bounded RAM-only fixed
    field frame; none are borrowed from another target or inferred from a hash.
    """
    phase='profile'
    provision=None
    create_attempted=False
    try:
        if source_mode not in SOURCE_MODES:raise ValueError()
        phase='observer_dependency'
        observer_factory=_composite_observer_factory()
        phase='realm'
        provision=OwnerProvision(IMAGE.removeprefix('sha256:'))
        r,f=provision.runner,provision.fixture
        _full_restore_budget()
        phase='frame'
        with staged_owner_frame(stream,runner=r,private_parent=private_parent,
                source_mode=source_mode) as (source,key,spool,profile,root):
            phase='provision'
            # All bootstrap inputs belong solely to THIS invocation/fixture.
            dashboard=secrets.token_hex(24).encode()
            bootstrap=('user_id,password,is_superuser\nlab,'+secrets.token_hex(24)+',false\n').encode()
            base=(b'dashboard.default_username="owner"\n'
                  b'dashboard.listeners.http.bind="127.0.0.1:18083"\n'
                  b'listeners.tcp.default.bind="127.0.0.1:1883"\n'
                  b'authentication=[{mechanism=password_based,backend=built_in_database,'
                  b'user_id_type=username,enable=true,password_hash_algorithm={name=sha256,salt_position=suffix},'
                  b'bootstrap_file="/opt/emqx/etc/lab-bootstrap.csv",bootstrap_type=plain}]\n'
                  b'authorization={no_match=deny,deny_action=ignore,sources=[{type=file,enable=true,'
                  b'path="/opt/emqx/etc/lab-acl.conf"}]}\n')
            acl=b'{allow, {username, "lab"}, all, ["lab/#"]}.\n{deny, all}.\n'
            create_attempted=True
            provision.create(base,acl,bootstrap,dashboard)
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
                        vendor_observer=observer_factory(provision=provision)) as readers:
                    phase='preflight'
                    session=owner_preflight(captured=captured,target_readers=readers,
                        target_generation=readers.generation,
                        private_transport=curl_login_transport(runner=r,broker=f.prefix,
                            login_url='http://127.0.0.1:18083/api/v5/login'),
                        username=b'owner',password=dashboard,evidence_directory=evidence,
                        evidence_name='owner-preflight.json')
                    phase='build'
                    work=SimpleNamespace(runner=lambda _app:r,guard=CandidateBudget(),abort=None,
                        checkpoint=ctx.checkpoint,phase=ctx.phase,log=ctx.log)
                    volumes=build_captured_candidate(work,app,ctx.adapter(app),target,source,candidate,job,
                        captured=captured,private_binding=binding,session=session,expected_sha256=profile.sha256)
                phase='package'
                backup_id=_package_same_target(ctx,app,provision,volumes,root)
                phase='restore'
                _restore_and_rollback(ctx,app,provision,backup_id,state)
            phase='cleanup'
        return {'scope':'private-same-target-product-flow', 'client_validation':'not-implemented',
                'source_final_state':'not-assessed','commercial_acceptance':'not-assessed'}
    except BaseException:
        raise RealOwnerRefused(phase) from None
    finally:
        if provision is not None and create_attempted:
            try:provision.cleanup()
            except BaseException:raise RealOwnerRefused('cleanup') from None
