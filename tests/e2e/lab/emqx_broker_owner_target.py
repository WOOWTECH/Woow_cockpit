"""Fresh synthetic native owner-target mode; invoked only by locked owner wrapper."""
from contextlib import contextmanager
import json
import base64
from pathlib import Path
import os
import re

from emqx_owner_target import broker_target_readers,OwnerCaptureRefused
from emqx_runtime_live import checked, podman
from emqx_runtime_credentials import RuntimeRegistry
from emqx_target_snapshots import register_target_snapshots
from emqx_private_boundary import PrivateFailure


NATIVE_STAGES = frozenset(('typed_setup','effective_config','provider_state','native_inventory',
    'native_tables','table_storage','table_fragments','table_type','table_lock',
    'schema_metadata','table_size','table_schema','table_fold','table_row_terms',
    'schema_terms','ticker_state','table_receipts','stable_config','stable_provider',
    'serialize_config','serialize_provider','encode_reply'))
NATIVE_REASONS = frozenset(('undef','badmatch','bad_argument','function_clause',
    'no_exists','bad_type','not_active','node_not_running','no_transaction','system_limit',
    'storage_null_copies','storage_null_nonempty','storage_external','storage_unknown','storage_unsupported',
    'fragments_unsupported','table_type_unsupported','table_row_limit',
    'table_count_mismatch','table_receipt_changed','config_changed','provider_changed',
    'ticker_not_suspended','ticker_changed','schema_record_invalid','unsupported_pid','unsupported_reference','unsupported_port','unsupported_function','unsupported_bitstring','unsupported_term','native_refused'))



FUNCTION_PATHS = frozenset(('log_console_time_offset','log_file_time_offset','log_other',
    'dashboard','node','authentication','authorization','listeners','other_config',
    'ssl_default_user_lookup_fun','wss_default_user_lookup_fun'))
FUNCTION_ENV_KINDS = frozenset(('empty','binary','atom','integer','float','tuple','list',
    'map','function','pid','reference','port','other','multiple'))


def fixed_function_diagnostic(encoded):
    """Public BEAM identities only; catalogue is fixed trusted source, not input."""
    try:
        if len(encoded) > 1024:
            return None
        raw = base64.b64decode(encoded,validate=True)
        if base64.b64encode(raw) != encoded:
            return None
        def pairs(items):
            result = dict(items)
            if len(result) != len(items):
                raise ValueError()
            return result
        item = json.loads(raw,object_pairs_hook=pairs)
        if (type(item) is not dict or set(item) != {'module','name','arity','md5','type','path','env_kind','profile','descriptor_sha256'}
                or item['type'] not in ('local','external','unknown')
                or item['path'] not in FUNCTION_PATHS or item['env_kind'] not in FUNCTION_ENV_KINDS
                or item['profile'] not in ('public_code','unverified','secret_wrap_identity_or_env','secret_loader_refused')):
            return None
        descriptor = item['descriptor_sha256']
        if descriptor != 'not-emitted' and (type(descriptor) is not str or
                not re.fullmatch(r'[0-9A-F]{64}',descriptor) or item['type'] != 'external' or item['env_kind'] != 'empty'):
            return None
        identity = (item['module'],item['name'],item['arity'],item['md5'])
        if identity == ('unknown','unknown','unknown','unknown'):
            return item if item['profile'] != 'public_code' else None
        catalog = json.loads(Path(__file__).with_name('emqx_public_function_catalog.json').read_text())
        module = next((m for m in catalog if m['module'] == item['module'] and m['md5'] == item['md5']),None)
        if module is None or type(item['arity']) is not int or not 0 <= item['arity'] <= 255:
            return None
        symbols = module['locals'] if item['type'] == 'local' else module['exports']
        if not any(n == item['name'] and (a >= item['arity'] if item['type'] == 'local' else a == item['arity'])
                   for n,a in symbols):
            return None
        if item['profile'] == 'unverified':
            return None
        if item['profile'] == 'secret_wrap_identity_or_env' and (item['module'],item['name']) != ('emqx_secret','-wrap/1-fun-0-'):
            return None
        if item['profile'] == 'secret_loader_refused' and (item['module'],item['name']) != ('emqx_secret','-wrap_load/1-fun-0-'):
            return None
        return item
    except (ValueError,TypeError,KeyError,OSError):
        return None


def fixed_native_diagnostic(wire):
    """Only fixed stage/reason enums; never accept a table/abort/value token."""
    if type(wire) is not bytes or len(wire) > 1536:
        return None
    function = None
    if wire.startswith(b'WOOWFUN:'):
        framed = re.fullmatch(rb'WOOWFUN:([A-Za-z0-9+/=]+):END\n(WOOWTARGETFAIL:[a-z_]+:[a-z_]+:ENDok)\s*',wire)
        if not framed:
            return None
        function = fixed_function_diagnostic(framed[1])
        if function is None:
            return None
        wire = framed[2]
    if len(wire) > 160:
        return None
    match = re.fullmatch(rb'WOOWTARGETFAIL:([a-z_]+):([a-z_]+):ENDok', wire.strip())
    if not match:
        return None
    stage, reason = (part.decode('ascii') for part in match.groups())
    result = {'native_fixed_stage': stage if stage in NATIVE_STAGES else 'native_tables',
              'native_fixed_reason': reason if reason in NATIVE_REASONS else 'native_refused'}
    if function is not None:
        if stage != 'serialize_config' or reason != 'unsupported_function':
            return None
        result['native_config_function'] = function
    return result


@contextmanager
def fresh_target_quiescence(*, broker, owned_container_id, clients, checks):
    """Only this invocation's fresh fixture; never production/system services.

    Suspension ends when the workload's finally removes this exact broker. It
    does not freeze expiry/other background tasks; stable native receipts are
    additionally required and are not a universal writer exclusion barrier.
    """
    from woowbackup.ha_emqx import SUSPEND_SYS_EXPR, TICKER_STATUS_EXPR
    from emqx_runtime_live import IMAGE
    if (type(broker) is not str or type(owned_container_id) is not str
            or not re.fullmatch(r'woowbk-emqx-workload-[0-9a-f]{12}', broker)
            or not re.fullmatch(r'[0-9a-f]{64}', owned_container_id)):
        raise RuntimeError('fresh-target-identity-required')
    def identity():
        info = json.loads(checked('inspect', broker))[0]
        if (info['Id'] != owned_container_id or not info['State']['Running']
                or info['Image'].removeprefix('sha256:') != IMAGE
                or info['HostConfig']['NetworkMode'] != 'none'
                or info['HostConfig'].get('PortBindings') not in (None, {})
                or info['HostConfig']['LogConfig']['Type'] != 'none'
                or any(m['Type'] == 'volume' for m in info['Mounts'])):
            raise RuntimeError('fresh-target-identity-changed')
    def empty_clients():
        if clients:
            raise RuntimeError('fixture-writer-not-quiesced')
        raw = checked('exec', broker, 'emqx', 'eval',
            '[] = emqx_cm:all_channels(), io:format("OWNERNOCLIENTS").')
        if raw.strip() != b'OWNERNOCLIENTSok':
            raise RuntimeError('target-clients-not-empty')
    identity()
    empty_clients()
    checks['no_clients_before_capture'] = True
    wire = checked('exec', broker, 'emqx', 'eval', SUSPEND_SYS_EXPR)
    match = re.fullmatch(rb'WOOWSYS:(<[0-9]+\.[0-9]+\.[0-9]+>):suspended\s*(?:ok\s*)?', wire)
    if not match:
        raise RuntimeError('fresh-target-ticker-suspend-refused')
    pid = match[1].decode('ascii')  # Private identity only, never a report field.
    def ticker_status():
        identity()
        raw = checked('exec', broker, 'emqx', 'eval', TICKER_STATUS_EXPR.replace('{pid}', pid))
        if raw.strip() != b'ticker_unchanged':
            raise RuntimeError('fresh-target-ticker-changed')
    ticker_status()
    checks['fresh_ticker_identity_suspended_before'] = True
    try:
        yield
    finally:
        ticker_status()
        checks['fresh_ticker_identity_suspended_after'] = True
        empty_clients()
        checks['no_clients_after_capture'] = True


def run_owner_target(root, broker, clients, report, *, owned_container_id):
    checks = report['checks']
    def quiesce():
        return fresh_target_quiescence(broker=broker, owned_container_id=owned_container_id,
                                       clients=clients, checks=checks)
    def private_checked(*args):
        result = podman(*args)
        report['native_transport'] = 'passed' if result.returncode == 0 else 'failed'
        wire = result.stdout.strip()
        diagnostic_fields = fixed_native_diagnostic(wire)
        if diagnostic_fields is not None:
            report.update(diagnostic_fields)
        if result.returncode:
            diagnostic = result.stdout + result.stderr
            for marker, code in ((b'unsafe', 'unsafe_variable'), (b'unbound', 'unbound_variable'),
                    (b'syntax', 'expression_syntax'), (b'illegal_guard', 'illegal_guard'),
                    (b'badarg', 'bad_argument'), (b'undef', 'undefined_api'),
                    (b'timeout', 'transport_timeout')):
                if marker in diagnostic.lower():
                    report['native_fixed_reason'] = code
                    break
            else:
                report['native_fixed_reason'] = 'transport_refused'
            raise RuntimeError('owner-target-private-eval-refused')
        return result.stdout
    try:
        with broker_target_readers(broker=broker, checked=private_checked, quiesce=quiesce) as readers:
            checks['actual_native_expression_and_projection'] = True
            runtime = RuntimeRegistry()
            counts = register_target_snapshots(runtime, readers)
            assert set(counts) == {'mqtt-auth','api-keys','connectors','tls','target-bootstrap'}
            checks['all_five_target_categories_registered'] = True
            assert 'emqx_admin' in readers.persisted_values.tables
            checks['native_full_inventory_not_two_table_subset'] = True
            class FullScan:
                def scan(self, payload):
                    runtime.scan(payload)
                    readers.persisted_values.scan(payload)
            scan = FullScan()
            # Target-only evidence: no fake source registry/counts, no numeric JSON.
            raw = (json.dumps({'階段':'目標擷取','結果':'passed',
                '涵蓋':['MQTT認證','API金鑰','連接器憑證','TLS憑證','目標初始憑證']},
                ensure_ascii=False,sort_keys=True)+'\n').encode()
            scan.scan(raw)
            evidence = root / 'owner-target-evidence.json'
            fd = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw)
            assert evidence.read_bytes() == raw
            checks['actual_exact_names_only_target_evidence_scanned'] = True
            report['target_completeness'] = 'synthetic-stable-observed'
            report['quiescence_scope'] = 'clients-and-system-ticker'
            report['other_background_writers'] = 'not-excluded'
            # Keep diagnostics independent from raw configs/rows/counts. No source or
            # restore/startup/restart/MQTT acceptance is asserted by this mode.
    except OwnerCaptureRefused as failure:
        report['consumer_fixed_stage']=failure.phase
        report['consumer_fixed_reason']=failure.reason
        if failure.reference is not None:
            report['consumer_fixed_reference']=failure.reference
        raise


def parse_fixed_expression(root, broker_name, report):
    """Native parse of fixed PUBLIC source before any broker starts."""
    from pathlib import Path
    from emqx_runtime_live import IMAGE
    here = Path(__file__).parent
    for filename in ('emqx_owner_target.expr', 'emqx_owner_target_parse.escript'):
        (root / filename).write_bytes((here / filename).read_bytes())
        (root / filename).chmod(0o600)
    name = broker_name + '-parse'
    try:
        result = podman('run','--rm','--name',name,'--pull=never','--network=none',
            '--log-driver=none','--image-volume=ignore','--userns=keep-id:uid=1000,gid=1000',
            '--memory=128m','--pids-limit=32','-v',str(root)+':/work:ro',
            '--entrypoint=/opt/emqx/erts-14.2.5.11/bin/escript','sha256:'+IMAGE,
            '/work/emqx_owner_target_parse.escript','/work/emqx_owner_target.expr')
        if result.returncode or result.stdout != b'OWNERPARSEOK':
            # This diagnostic is only from public code parsing, not broker data.
            if result.stdout.startswith(b'OWNERPARSEFAIL:') and len(result.stdout) <= 256:
                report['fixed_source_parse'] = result.stdout.decode('utf-8')
            raise RuntimeError('fixed-expression-parse-refused')
        report['checks']['native_fixed_expression_parsed'] = True
    finally:
        cleanup = podman('rm','-f','--ignore','--volumes',name)
        assert cleanup.returncode == 0 and podman('container','exists',name).returncode == 1
