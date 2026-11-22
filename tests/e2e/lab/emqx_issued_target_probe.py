"""Actual issued-fixture target-only probe; no source, login, build or restore.

Only the existing isolated owner may call this. Exact private evidence is returned
AFTER lease exit and scoped cleanup. Five target categories are not HA acceptance.
"""
import secrets
from contextlib import contextmanager
from emqx_adapter_owner import OwnerProvision
from emqx_native_runtime import IMAGE
from emqx_private_boundary import PrivateFailure
from emqx_real_owner_workflow import (_target_base, _target_acl, _opt_in_private_unit,
    _ready, fixture_quiescence, _full_restore_budget)
from emqx_target_fixture_policy import issued_fixture_observer
from emqx_owner_target import owner_target_readers, MAX_WIRE, OwnerCaptureRefused, CONSUMER_PHASES
from emqx_owner_fixture_files import FixtureFilesFailure, STAGES as FILE_STAGES, REASONS as FILE_REASONS
from emqx_preflight_stage import STAGES as TRACE_STAGES, native_refusal_stage
from emqx_runtime_credentials import RuntimeRegistry, TARGET_CATEGORIES
from emqx_target_snapshots import register_target_snapshots

TARGET_RECEIPT = '階段：目標擷取；結果：通過；涵蓋：訊息認證、介面金鑰、連接器憑證、傳輸憑證、目標初始憑證'.encode()
PHASES = (frozenset(('realm','budget','provision','start','quiescence','target','register','scan','cleanup'))
    | frozenset('files_'+s+'_'+r for s in FILE_STAGES for r in FILE_REASONS)
    | frozenset('target_'+s for s in CONSUMER_PHASES)
    | frozenset(s for s in TRACE_STAGES if s.startswith('native_')))
class IssuedProbeRefused(PrivateFailure):
    def __init__(self, phase):
        self.phase=phase if phase in PHASES else 'realm'
        super().__init__('private-issued-target-probe-refused')

def run_issued_target_probe():
    phase='realm'; provision=None; attempted=False; result=None
    try:
        provision=OwnerProvision(IMAGE.removeprefix('sha256:'))
        phase='budget'; _full_restore_budget()
        phase='provision'; attempted=True
        provision.create(_target_base(),_target_acl(),
            b'user_id,password,is_superuser\nlab,'+secrets.token_hex(24).encode()+b',false\n',
            secrets.token_hex(24).encode())
        _opt_in_private_unit(provision)
        phase='start'
        provision.runner.systemctl('start','--',provision.fixture.unit,timeout=180)
        _ready(provision)
        def evaluate(expression):
            nonlocal phase
            response=provision.runner.podman('exec',provision.fixture.prefix,'emqx','eval',expression,
                timeout=30,max_output=MAX_WIRE,check=False)
            if response.returncode or type(response.stdout) is not bytes or len(response.stdout)>MAX_WIRE:
                raise ValueError()
            fixed=native_refusal_stage(response.stdout)
            if fixed is not None:
                phase=fixed
                raise ValueError()
            return response.stdout
        @contextmanager
        def observed(**kwargs):
            nonlocal phase
            try:
                with issued_fixture_observer(provision)(**kwargs) as observation:
                    yield observation
            except FixtureFilesFailure as failure:
                phase='files_'+failure.stage+'_'+failure.reason
                raise
        @contextmanager
        def quiesced():
            nonlocal phase
            phase='quiescence'
            with fixture_quiescence(provision):
                phase='target'
                yield
        phase='target'
        with owner_target_readers(private_eval=evaluate,
                quiesce=quiesced,
                vendor_observer=observed) as readers:
            phase='register'; runtime=RuntimeRegistry()
            counts=register_target_snapshots(runtime,readers)
            if set(counts)!=TARGET_CATEGORIES:raise ValueError()
            phase='scan'
            runtime.scan(TARGET_RECEIPT)
            readers.persisted_values.scan(TARGET_RECEIPT)
            result=TARGET_RECEIPT
    except OwnerCaptureRefused as failure:
        raise IssuedProbeRefused('target_'+failure.phase) from None
    except BaseException:
        raise IssuedProbeRefused(phase) from None
    finally:
        if attempted:
            try:provision.cleanup()
            except BaseException:raise IssuedProbeRefused('cleanup') from None
    return result
