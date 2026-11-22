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
        match = re.fullmatch(rb'WOOWTARGETFAIL:([a-z_]+):([a-z_]+):ENDok', wire)
        if match:
            # All text is fixed producer diagnostic enums, not native values.
            report['native_fixed_stage'] = match[1].decode()
            report['native_fixed_reason'] = match[2].decode()
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
            # Only names already present in the fixed source, never arbitrary
            # server text, may refine an unbound/unsafe variable diagnostic.
            variables = set(re.findall(rb'\b[A-Z][A-Za-z0-9_]*\b', args[-1].encode()))
            for variable in variables:
                if b"'" + variable + b"'" in diagnostic:
                    report['native_fixed_variable'] = variable.decode()
                    break
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
