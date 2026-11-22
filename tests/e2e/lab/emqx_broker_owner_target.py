"""Fresh synthetic native owner-target mode; invoked only by locked owner wrapper."""
from contextlib import contextmanager
import json
import os
import re

from emqx_owner_target import broker_target_readers
from emqx_runtime_live import checked, podman
from emqx_runtime_credentials import RuntimeRegistry
from emqx_target_snapshots import register_target_snapshots
from emqx_private_boundary import PrivateFailure


NATIVE_STAGES = frozenset(('typed_setup','effective_config','provider_state','native_inventory',
    'native_tables','table_storage','table_fragments','table_type','table_lock',
    'schema_metadata','table_size','table_schema','table_fold','table_row_terms',
    'schema_terms','serialize_config','serialize_provider','encode_reply'))
NATIVE_REASONS = frozenset(('undef','badmatch','bad_argument','function_clause',
    'no_exists','bad_type','not_active','node_not_running','no_transaction','system_limit',
    'storage_null_copies','storage_external','storage_unknown','storage_unsupported',
    'fragments_unsupported','table_type_unsupported','table_row_limit',
    'unsupported_term','native_refused'))


def fixed_native_diagnostic(wire):
    """Only fixed stage/reason enums; never accept a table/abort/value token."""
    if type(wire) is not bytes or len(wire) > 160:
        return None
    match = re.fullmatch(rb'WOOWTARGETFAIL:([a-z_]+):([a-z_]+):ENDok', wire.strip())
    if not match:
        return None
    stage, reason = (part.decode('ascii') for part in match.groups())
    return {'native_fixed_stage': stage if stage in NATIVE_STAGES else 'native_tables',
            'native_fixed_reason': reason if reason in NATIVE_REASONS else 'native_refused'}


def run_owner_target(root, broker, clients, report):
    checks = report['checks']
    def empty_clients():
        assert not clients  # This mode never starts any MQTT client or ticker.
        raw = checked('exec', broker, 'emqx', 'eval',
            '[] = emqx_cm:all_channels(), io:format("OWNERNOCLIENTS").')
        assert raw.strip() == b'OWNERNOCLIENTSok'
    @contextmanager
    def quiesce():
        empty_clients()
        checks['no_clients_before_capture'] = True
        try:
            yield
        finally:
            empty_clients()
            checks['no_clients_after_capture'] = True
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
        report['target_completeness'] = 'synthetic-live-observed'
        # Keep diagnostics independent from raw configs/rows/counts. No source or
        # restore/startup/restart/MQTT acceptance is asserted by this mode.


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
