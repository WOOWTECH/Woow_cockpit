import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

import ha_real_fixture as gate
from tests.backup import hafixtures as hx


class FixtureGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def fixture(self, app='headscale', *, version=None, outer_version=None,
                state='stopped', arch='amd64', missing=None, extra=(), slug=None):
        version = version or ('0.1.3' if app == 'headscale' else '5.9.1')
        suffix = 'woow-' + app
        slug = slug or 'abcdef01_' + suffix
        addon = {'system': {'slug': suffix}, 'user': {'image': 'test/' + arch + '-addon-' + suffix,
                 'options': {'password': 'DO-NOT-PRINT-SECRET'}}, 'version': version, 'state': state}
        names = (['data/db.sqlite', 'data/noise_private.key', 'config/config.yaml'] if app == 'headscale'
                 else ['data/emqx/node.name', 'data/emqx/data/configs/cluster.hocon',
                       'data/emqx/data/mnesia/emqx@127.0.0.1/schema.DAT'])
        entries = [{'name': 'addon.json', 'data': json.dumps(addon).encode()}]
        entries += [{'name': n, 'data': b'DO-NOT-PRINT-SECRET'} for n in names if n != missing]
        entries += list(extra)
        doc = hx.ha_doc((slug,))
        doc['addons'][0]['version'] = outer_version or version
        path = self.root / 'backup.tar'
        path.write_bytes(hx.outer_bytes([(slug + '.tar.gz', hx.tar_bytes(entries, compress=True))], doc))
        return path

    def check(self, path, app='headscale', **kwargs):
        return gate.preflight(path, app, '0.29.4' if app == 'headscale' else '5.8.9', **kwargs)

    def test_both_contracts_and_arches(self):
        for app in ('emqx', 'headscale'):
            for arch in ('amd64', 'aarch64'):
                with self.subTest(app=app, arch=arch):
                    result = self.check(self.fixture(app, arch=arch), app)
                    self.assertFalse(result['restore_allowed'])
                    self.assertEqual(result['semantic_validation'], 'pending')
                    self.assertEqual(result['source_arch'], arch)
                    self.assertNotIn('DO-NOT-PRINT', json.dumps(result))

    def test_reject_hot_unknown_state(self):
        for state in ('started', '', 'unknown'):
            with self.subTest(state=state), self.assertRaisesRegex(gate.Refused, 'cold-backup-required'):
                self.check(self.fixture(state=state))

    def test_unknown_version(self):
        with self.assertRaisesRegex(gate.Refused, 'unsupported-version'):
            self.check(self.fixture(version='99.0.0'))

    def test_target_version_mismatch(self):
        with self.assertRaisesRegex(gate.Refused, 'unsupported-version'):
            gate.preflight(self.fixture(), 'headscale', '0.29.3')

    def test_outer_inner_mismatch(self):
        with self.assertRaisesRegex(gate.Refused, 'metadata-version-mismatch'):
            self.check(self.fixture(outer_version='0.1.2'))

    def test_missing_required(self):
        for name in ('data/db.sqlite', 'data/noise_private.key', 'config/config.yaml'):
            with self.subTest(name=name), self.assertRaisesRegex(gate.Refused, 'missing-required-member'):
                self.check(self.fixture(missing=name))

    def test_no_mnesia(self):
        path = self.fixture('emqx', missing='data/emqx/data/mnesia/emqx@127.0.0.1/schema.DAT')
        with self.assertRaisesRegex(gate.Refused, 'missing-or-ambiguous-mnesia'):
            self.check(path, 'emqx')

    def test_multiple_mnesia(self):
        path = self.fixture('emqx', extra=({'name': 'data/emqx/data/mnesia/emqx@other/schema.DAT', 'data': b'x'},))
        with self.assertRaisesRegex(gate.Refused, 'missing-or-ambiguous-mnesia'):
            self.check(path, 'emqx')

    def test_unknown_architecture(self):
        with self.assertRaisesRegex(gate.Refused, 'unknown-source-architecture'):
            self.check(self.fixture(arch='mystery'))

    def test_symlink_required(self):
        path = self.fixture(missing='data/noise_private.key', extra=(
            {'name': 'data/noise_private.key', 'type': 'symlink', 'linkname': 'db.sqlite'},))
        with self.assertRaisesRegex(gate.Refused, 'unsupported-entry'):
            self.check(path)

    def test_traversal_refused_without_echo(self):
        path = self.fixture(extra=({'name': '../DO-NOT-PRINT-SECRET', 'data': b'x'},))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(gate.main([str(path), '--app', 'headscale', '--target-version', '0.29.4']), 2)
        self.assertNotIn('DO-NOT-PRINT', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['reason'], 'archive-or-io-error')

    def test_source_symlink(self):
        link = self.root / 'link'
        link.symlink_to(self.fixture())
        with self.assertRaises(Exception):
            self.check(link)

    def test_private_copy_and_actual_source_binding(self):
        path = self.fixture(slug='fedcba98_woow-headscale')
        dest = self.root / 'prepared'
        result = self.check(path, prepare=dest)
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o700)
        for name in ('source.tar', 'preflight.json'):
            self.assertEqual(os.stat(dest / name).st_mode & 0o777, 0o600)
        self.assertEqual((dest / 'source.tar').read_bytes(), path.read_bytes())
        with gate.source_binding(dest / 'source.tar', 'headscale', '0.29.4', result['sha256']) as binding:
            self.assertEqual(binding['addon_member']('woow-headscale'), 'fedcba98_woow-headscale')
            self.assertEqual(binding['addon_info']('woow-headscale').version, '0.1.3')
            with binding['open']('fedcba98_woow-headscale') as stream:
                self.assertTrue(stream.read(512))
            with self.assertRaises(gate.Refused):
                binding['addon_member']('woow-emqx')
        with self.assertRaisesRegex(gate.Refused, 'digest-mismatch'):
            with gate.source_binding(path, 'headscale', '0.29.4', '0' * 64):
                self.fail('must not yield')

    def test_no_overwrite(self):
        dest = self.root / 'prepared'
        dest.mkdir()
        (dest / 'marker').write_text('keep')
        with self.assertRaises(FileExistsError):
            self.check(self.fixture(), prepare=dest)
        self.assertEqual((dest / 'marker').read_text(), 'keep')

    def test_failed_prepare_cleanup(self):
        dest = self.root / 'prepared'
        with patch.object(gate.os, 'fsync', side_effect=OSError('private-error')):
            with self.assertRaises(OSError):
                self.check(self.fixture(), prepare=dest)
        self.assertFalse(dest.exists())

    def test_metadata_only_never_prepares(self):
        dest = self.root / 'prepared'
        with self.assertRaisesRegex(gate.Refused, 'metadata-only-cannot-prepare'):
            self.check(self.fixture(), metadata_only=True, prepare=dest)
        self.assertFalse(dest.exists())

    def test_encryption_refused_before_opening(self):
        from dataclasses import replace
        from woowbackup import habackup
        with habackup.open_backup(self.fixture()) as opened:
            opened.layout = replace(opened.layout, members=tuple(
                replace(m, encryption='v3') for m in opened.layout.members))
            with patch.object(opened, 'open_addon', side_effect=AssertionError('no decryption')):
                with self.assertRaisesRegex(gate.Refused, 'encrypted-fixture-unsupported'):
                    gate.inspect_open(opened, 'headscale', '0.29.4')
                summary, _, _ = gate.inspect_open(opened, 'headscale', '0.29.4', metadata_only=True)
                self.assertEqual(summary['encryption'], 'v3')

    def encrypted_fixture(self, *, state='stopped'):
        import tarfile
        path = self.fixture('emqx', state=state)
        with tarfile.open(path) as tar:
            member = next(m for m in tar if m.name.endswith('.tar.gz'))
            payload = tar.extractfile(member).read()
            doc = json.load(tar.extractfile('./backup.json'))
        doc['protected'] = True
        path.write_bytes(hx.outer_bytes([(member.name, hx.v3_encrypt(payload))], doc))
        return path

    def test_real_v3_decrypt_stream_and_binding(self):
        path = self.encrypted_fixture()
        keys = gate.read_private_keys(io.BytesIO((hx.PASSWORD + '\n').encode()))
        report = self.check(path, 'emqx', keys=keys)
        self.assertEqual(report['source_state'], 'stopped')
        self.assertEqual(report['encryption'], 'v3')
        self.assertFalse(report['restore_allowed'])
        self.assertNotIn(hx.PASSWORD, json.dumps(report))
        with gate.source_binding(path, 'emqx', '5.8.9', report['sha256'], keys=keys) as bindings:
            slug = bindings['addon_member']('woow-emqx')
            with bindings['open'](slug) as stream:
                self.assertTrue(stream.read(1))

    def test_v3_wrong_key_and_hot_state_still_refused(self):
        path = self.encrypted_fixture()
        with self.assertRaises(Exception):
            self.check(path, 'emqx', keys=gate.hasecuretar.Keys(hx.WRONG_PASSWORD))
        path = self.encrypted_fixture(state='started')
        with self.assertRaisesRegex(gate.Refused, 'cold-backup-required'):
            self.check(path, 'emqx', keys=gate.hasecuretar.Keys(hx.PASSWORD))

    def test_private_key_input_bounded_and_invalid_refused(self):
        for value in (b'', b'x'*1025, b'\xff', b'one\ntwo'):
            with self.subTest(size=len(value)), self.assertRaises(gate.Refused):
                gate.read_private_keys(io.BytesIO(value))
        stream = io.BytesIO(b'x'*2000)
        with self.assertRaises(gate.Refused):
            gate.read_private_keys(stream)
        self.assertEqual(stream.tell(), 1025)

    def cli_command(self, path, *args):
        return [sys.executable, str(Path(gate.__file__).resolve()), str(path),
                '--app', 'emqx', '--target-version', '5.8.9', *args]

    def assert_cli_output(self, result, expected):
        # Boolean assertions keep even unexpected secret output out of test logs.
        output = result.stdout + result.stderr
        for secret in (hx.PASSWORD.encode(), hx.WRONG_PASSWORD.encode(),
                       b'DO-NOT-PRINT-SECRET', str(self.root).encode()):
            self.assertFalse(secret in output, 'CLI exposed a private marker')
        self.assertTrue(result.stderr == b'', 'CLI emitted unexpected stderr')
        self.assertTrue(result.stdout == (json.dumps(expected, sort_keys=True) + '\n').encode(),
                        'CLI output differs from the sanitized contract')

    def test_v3_cli_private_key_failures(self):
        path = self.encrypted_fixture()
        original = path.read_bytes()
        cases = (
            ('missing-option', (), b'', 'encrypted-fixture-unsupported'),
            ('empty-stdin', ('--key-stdin',), b'', 'invalid-private-key-input'),
            ('wrong-key', ('--key-stdin',), hx.WRONG_PASSWORD.encode(), 'archive-or-io-error'),
            ('oversize', ('--key-stdin',), b'DO-NOT-PRINT-SECRET' + b'x' * 1025,
             'invalid-private-key-input'),
            ('non-ascii', ('--key-stdin',), b'DO-NOT-PRINT-SECRET\xff', 'invalid-private-key-input'),
            ('multiline', ('--key-stdin',), b'DO-NOT-PRINT-SECRET\nsecond', 'invalid-private-key-input'),
        )
        for name, args, value, reason in cases:
            with self.subTest(case=name):
                dest = self.root / name
                result = subprocess.run(self.cli_command(path, *args, '--prepare', str(dest)),
                                        input=value, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assert_cli_output(result, {'status': 'refused', 'reason': reason,
                                                'restore_allowed': False})
                self.assertFalse(dest.exists())
                self.assertTrue(path.read_bytes() == original, 'CLI changed the source')
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_v3_cli_valid_key_control(self):
        path = self.encrypted_fixture()
        expected = self.check(path, 'emqx', keys=gate.hasecuretar.Keys(hx.PASSWORD))
        result = subprocess.run(self.cli_command(path, '--key-stdin'),
                                input=(hx.PASSWORD + '\n').encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assert_cli_output(result, expected)
        self.assertFalse(expected['restore_allowed'])
        self.assertEqual(expected['encryption'], 'v3')
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_v3_cli_oversize_refuses_without_waiting_for_eof(self):
        path = self.encrypted_fixture()
        dest = self.root / 'prepared'
        process = subprocess.Popen(self.cli_command(path, '--key-stdin', '--prepare', str(dest)),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Keep the pipe open: reading beyond the 1025-byte bound would hang.
            process.stdin.write(b'DO-NOT-PRINT-SECRET'.ljust(1025, b'x'))
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=10), 2)
            stdout, stderr = process.communicate(timeout=10)
            self.assert_cli_output(subprocess.CompletedProcess(process.args, process.returncode,
                                                               stdout, stderr),
                                   {'status': 'refused', 'reason': 'invalid-private-key-input',
                                    'restore_allowed': False})
            self.assertFalse(dest.exists())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def test_changed_source_refused(self):
        path = self.fixture()
        real_stamp = gate.stamp
        calls = 0

        def changed(fd):
            nonlocal calls
            calls += 1
            value = real_stamp(fd)
            return value if calls == 1 else (*value[:-1], value[-1] + 1)

        with patch.object(gate, 'stamp', side_effect=changed):
            with self.assertRaisesRegex(gate.Refused, 'source-changed'):
                self.check(path, prepare=self.root / 'prepared')
        self.assertFalse((self.root / 'prepared').exists())

    def test_wrong_addon_and_duplicate_members(self):
        with self.assertRaisesRegex(gate.Refused, 'missing-or-ambiguous-addon'):
            self.check(self.fixture('emqx'))
        path = self.fixture(extra=({'name': 'data/db.sqlite', 'data': b'x'},))
        with self.assertRaises(Exception):
            self.check(path)

    def test_truncated_archive(self):
        path = self.fixture()
        path.write_bytes(path.read_bytes()[:1000])
        with self.assertRaises(Exception):
            self.check(path)

    def test_size_limit(self):
        with patch.object(gate, 'MAX_ARCHIVE', 1):
            with self.assertRaisesRegex(gate.Refused, 'archive-too-large'):
                self.check(self.fixture())


if __name__ == '__main__':
    unittest.main()
