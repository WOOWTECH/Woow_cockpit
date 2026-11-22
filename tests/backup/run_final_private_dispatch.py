"""Execute the explicit R2 local selection; skips/expected failures are NOT passes.

No discovery, -k filtering, lab entrypoints or remote transports. The selected
methods themselves use real parsers/files/crypto with simulated service runtimes.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = '3fe2ff3'
GROUPS = [
    ('tests.backup.test_ha_omnigent_candidate.CandidateFlowTests',
     'Private dispatch and public guard; synthetic PG/schema/owner transport', [
         'test_full_synthetic_backup_candidate',
         'test_candidate_requires_ddl_quiescence',
         'test_private_entry_rejects_truthy_quiescence_and_mixed_apps',
         'test_unregistered_quadlet_secret_refuses_before_conversion',
         'test_request_fields_cannot_enable_public_conversion']),
    ('tests.backup.test_ha_omnigent_install.InstallTests',
     'Real Python flow/adapter methods; FakeOwner, HTTP, PG/snapshot and encryption fixtures', [
         'test_install_requires_registered_candidate_before_touch',
         'test_corrupt_registry_refuses_before_owner_commands',
         'test_other_app_origin_refuses_before_owner_commands',
         'test_registered_but_missing_secret_prevents_packaging',
         'test_failed_safety_export_restarts_writers_without_candidate_import']),
    ('test_emqx_real_candidate.RealCallerTests',
     'Real local source/decrypt/parser/builder/package; fake broker/runtime/TempObjects', [
         'test_actual_binding_builder_and_packager_use_source_identity',
         'test_builder_completes_its_own_source_stream_after_preflight',
         'test_public_conversion_stays_blocked_after_private_candidate_build',
         'test_invalid_sources_refused_before_temp_objects',
         'test_target_label_and_pin_are_required',
         'test_real_builder_failure_cleans_roles_without_packaging',
         'test_cleanup_failure_refuses_result',
         'test_source_change_during_build_refuses_result_after_cleanup',
         'test_wrong_app_and_malformed_digest_refused_before_transport',
         'test_private_staging_required_before_transport',
         'test_volume_path_escape_and_alias_refused_before_transport',
         'test_exclusive_work_directory_ignores_preexisting_output_links',
         'test_temp_factory_failure_removes_private_directory',
         'test_invalid_job_refused_before_transport',
         'test_packaging_failure_and_cancellation_remove_partial_files',
         'test_private_cleanup_error_is_fixed_field_and_does_not_return_result']),
    ('test_ha_real_fixture.FixtureGateTests',
     'Real generated local archives, file I/O, parser and v3 crypto; no service transport', [
         'test_private_copy_and_actual_source_binding',
         'test_real_v3_decrypt_stream_and_binding',
         'test_late_v3_authentication_failure_is_not_a_prefix_read_pass',
         'test_truncated_v3_member_refused_before_binding',
         'test_gzip_trailer_corruption_refuses_source_binding',
         'test_changed_source_refused']),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []
        self.passed_ids = []
        self.subtests = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passed_ids.append(test.id())
        super().addSuccess(test)

    def addSubTest(self, test, subtest, err):
        self.subtests.append({'parent': test.id(), 'id': subtest.id(), 'passed': err is None})
        super().addSubTest(test, subtest, err)


def main():
    os.chdir(ROOT)
    # Missing crypto must fail import/execution, never be counted as a skip.
    os.environ['WOOWBK_REQUIRE_HA_CRYPTO'] = '1'
    import nacl
    import cryptography
    selected = [{'id': cls + '.' + method, 'coverage': coverage}
                for cls, coverage, methods in GROUPS for method in methods]
    expected = [case['id'] for case in selected]
    if len(set(expected)) != len(expected):
        raise RuntimeError('duplicate selected method')
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(expected)
    loaded = list(flatten(suite))
    if loader.errors or [test.id() for test in loaded] != expected:
        raise RuntimeError('selection must load exactly the named real methods')
    # Bind modules loaded by these methods; also check them again after execution.
    sources = {Path(__file__).resolve()}
    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT) and path.suffix == '.py' and path.is_file():
                sources.add(path)
    before = {str(path.relative_to(ROOT)): sha(path) for path in sorted(sources)}
    output = io.StringIO()
    started = time.monotonic()
    result = unittest.TextTestRunner(stream=output, verbosity=2,
                                    resultclass=RecordedResult).run(suite)
    after = {path: sha(ROOT / path) for path in before}
    success = (result.wasSuccessful() and result.testsRun == len(expected)
               and result.executed_ids == expected and result.passed_ids == expected
               and not result.skipped and not result.expectedFailures
               and not result.unexpectedSuccesses and before == after)
    dest = ROOT / 'tests/backup/evidence/final-private-dispatch-20261122'
    dest.mkdir(parents=True, exist_ok=True)
    # Keep the raw captured output hash while normalizing unittest status whitespace.
    raw = output.getvalue()
    log = dest / 'unittest.txt'
    log.write_text('\n'.join(line.rstrip() for line in raw.splitlines()) + '\n')
    base = subprocess.check_output(['git', 'rev-parse', BASE], text=True).strip()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    report = {
        'schema': 1, 'base_commit': base, 'checkout_head_during_run': head,
        'scope': 'R2 focused local changed-caller/private-dispatch/source-completion regression',
        'commercial_acceptance': False, 'real_service_acceptance': False,
        'command': 'PYTHONDONTWRITEBYTECODE=1 WOOWBK_REQUIRE_HA_CRYPTO=1 PYTHONPATH=backup-engine:tests/e2e/lab:. python3 tests/backup/run_final_private_dispatch.py',
        'selected_methods': selected, 'executed_methods': result.executed_ids,
        'passed_methods': result.passed_ids, 'subtests': result.subtests,
        'tests_run': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'skipped': len(result.skipped),
        'expected_failures': len(result.expectedFailures),
        'unexpected_successes': len(result.unexpectedSuccesses),
        'elapsed_seconds': time.monotonic() - started, 'passed': success,
        'source_sha256_before': before, 'source_sha256_after': after,
        'source_binding_limit': 'Observed repo Python modules loaded before execution; not a full transitive/runtime/image closure. Mocked modules are hashed but are not live service evidence.',
        'python': sys.version.split()[0], 'pynacl': nacl.__version__,
        'cryptography': cryptography.__version__,
        'log': str(log.relative_to(ROOT)), 'log_sha256': sha(log),
        'raw_captured_output_sha256': hashlib.sha256(raw.encode()).hexdigest(),
        'log_normalization': 'Trailing whitespace removed only; no test result or traceback filtered.',
        'restrictions': {'lab_access': False, 'target_54_access': False,
                         'hermes_review': False, 'old_full_suite': False},
        'next_real_check': 'No real acceptance claimed. Banach owns ARM cleanup lifecycle. Real EMQX cold-source build/package remains a separately owner-scheduled check; do not repeat old service suites solely for these local assertion changes.',
    }
    (dest / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(raw, end='')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
