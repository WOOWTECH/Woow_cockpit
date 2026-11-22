"""Actual issued-fixture target-only probe; no source, login, build or restore.

Only the existing isolated owner may call this. Exact private evidence is returned
AFTER lease exit and scoped cleanup. Five target categories are not HA acceptance.
"""
import secrets
from emqx_adapter_owner import OwnerProvision
from emqx_native_runtime import IMAGE
from emqx_private_boundary import PrivateFailure
from emqx_real_owner_workflow import (_target_base, _target_acl, _opt_in_private_unit,
    _ready, fixture_quiescence, _full_restore_budget)
from emqx_target_fixture_policy import issued_fixture_observer
from emqx_owner_target import owner_target_readers, MAX_WIRE
from emqx_runtime_credentials import RuntimeRegistry, TARGET_CATEGORIES
from emqx_target_snapshots import register_target_snapshots

TARGET_RECEIPT = '階段：目標擷取；結果：通過；涵蓋：訊息認證、介面金鑰、連接器憑證、傳輸憑證、目標初始憑證'.encode()
PHASES = frozenset(('realm','budget','provision','start','target','register','scan','cleanup'))
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
            response=provision.runner.podman('exec',provision.fixture.prefix,'emqx','eval',expression,
                timeout=30,max_output=MAX_WIRE,check=False)
            if response.returncode or type(response.stdout) is not bytes or len(response.stdout)>MAX_WIRE:
                raise ValueError()
            return response.stdout
        phase='target'
        with owner_target_readers(private_eval=evaluate,
                quiesce=lambda:fixture_quiescence(provision),
                vendor_observer=issued_fixture_observer(provision)) as readers:
            phase='register'; runtime=RuntimeRegistry()
            counts=register_target_snapshots(runtime,readers)
            if set(counts)!=TARGET_CATEGORIES:raise ValueError()
            phase='scan'
            runtime.scan(TARGET_RECEIPT)
            readers.persisted_values.scan(TARGET_RECEIPT)
            result=TARGET_RECEIPT
    except BaseException:
        raise IssuedProbeRefused(phase) from None
    finally:
        if attempted:
            try:provision.cleanup()
            except BaseException:raise IssuedProbeRefused('cleanup') from None
    return result
