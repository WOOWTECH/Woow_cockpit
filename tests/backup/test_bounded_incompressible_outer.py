"""Safety checks of the incompressible >8GiB outer-archive probe; the real run is a separate opt-in invocation."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import bounded_incompressible_outer as probe
from .test_archive_v2 import small_inner
from woowbackup import archive

MIB, GIB = probe.MIB, probe.GIB


class PlanTests(unittest.TestCase):
    def test_bound_covers_model_and_requirement_adds_reserve(self):
        for mib in (128, 8193):
            size = mib * MIB
            plan = probe.plan(size, 10 ** 13)
            self.assertGreaterEqual(plan['archive_bound_bytes'], plan['expected_archive_bytes_model'])
            self.assertEqual(plan['required_free_bytes'], probe.RESERVE + probe.MARGIN
                             + plan['archive_bound_bytes'] + probe.WINDOW_PEAK)
            self.assertEqual(plan['shortfall_bytes'], 0)
        self.assertTrue(probe.plan(8193 * MIB, 0)['outer_over_8gib_expected'])
        self.assertFalse(probe.plan(128 * MIB, 0)['outer_over_8gib_expected'])

    def run_main(self, argv, free):
        output = io.StringIO()
        with mock.patch('sys.argv', ['probe', *argv]), \
             mock.patch.object(probe.SpaceGuard, 'free', return_value=free), \
             mock.patch.object(probe.resource, 'setrlimit') as limits, \
             mock.patch.object(probe.common, 'encryption_dependencies') as deps, \
             contextlib.redirect_stdout(output):
            code = probe.main()
        return code, json.loads(output.getvalue()), limits, deps

    def test_insufficient_space_generates_nothing_and_states_shortfall(self):
        with tempfile.TemporaryDirectory() as root:
            required = probe.plan(8193 * MIB, 0)['required_free_bytes']
            code, report, limits, deps = self.run_main(['--scratch-parent', root], required - 1)
            self.assertEqual(code, probe.EXIT_NO_SPACE)
            self.assertEqual(report['status'], 'insufficient-space')
            self.assertEqual(report['shortfall_bytes'], 1)
            self.assertEqual(report['generated_bytes'], 0)
            self.assertEqual(report['commercial_acceptance'], 'not-complete')
            limits.assert_not_called()
            deps.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_plan_only_generates_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            code, report, _, deps = self.run_main(['--plan-only', '--scratch-parent', root], 10 ** 13)
            self.assertEqual((code, report['status'], report['shortfall_bytes']), (0, 'plan-only', 0))
            deps.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_cli_bounds(self):
        for mib in ('127', '8194'):
            with mock.patch('sys.argv', ['probe', '--mib', mib]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    probe.main()
            self.assertEqual(caught.exception.code, 2)


class HeaderTests(unittest.TestCase):
    def member(self, raw, size):
        return mock.Mock(offset=len(raw), size=size)

    def test_pax_size_record_above_8gib(self):
        size = 8 * GIB + 12345
        raw = archive.README.encode() * 400 + archive._outer_header('apps/x.tar.zst.age', size, 0, pax=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'h.bin'
            path.write_bytes(raw)
            view = probe.outer_member_header(path, self.member(raw, size))
        self.assertEqual((view['pax_size_record'], view['ustar_size_field']), (size, 0))
        self.assertTrue(view['size_above_ustar_limit'])

    def test_plain_ustar_header_for_small_member(self):
        raw = bytes(2 * archive.BLOCK) + archive._outer_header('apps/x.tar.zst.age', 4096, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'h.bin'
            path.write_bytes(raw)
            view = probe.outer_member_header(path, self.member(raw, 4096))
            self.assertEqual((view['pax_header'], view['ustar_size_field']), (False, 4096))
            with self.assertRaisesRegex(RuntimeError, 'size differs'):
                probe.outer_member_header(path, self.member(raw, 4097))

    def test_large_member_without_pax_is_rejected(self):
        raw = bytes(2 * archive.BLOCK) + archive._outer_header('apps/x.tar.zst.age', 4096, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'h.bin'
            path.write_bytes(raw)
            with mock.patch.object(probe.archive, 'USTAR_SIZE_MAX', 4095):
                with self.assertRaisesRegex(RuntimeError, 'without PAX size'):
                    probe.outer_member_header(path, self.member(raw, 4096))


class JsonSlotTests(unittest.TestCase):
    def test_member_sha_rewrite_keeps_slot_and_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source = folder / 'payload.bin'
            source.write_bytes(b'abc' * 1000)
            inner = small_inner(probe.APP, None, {probe.ENTRY: b''}, encryption='none')
            manifest = {k: v for k, v in inner.items() if k not in ('app', 'backup_apps')}
            manifest['apps'] = [inner['app']]
            dest = folder / 'plain.tar'
            entry = archive.Entry(probe.ENTRY, source, source.stat().st_size,
                                  hashlib.sha256(source.read_bytes()).hexdigest())
            archive.write_archive(dest, None, manifest, [entry], None, tmp_dir=folder)
            offset, raw = probe.json_slot(dest)
            changed = probe.rewrite_member_sha(raw, 'f' * 64)
            self.assertEqual(len(changed), len(raw))
            self.assertEqual(json.loads(changed)['apps'][0]['sha256'], 'f' * 64)
            self.assertEqual(json.loads(probe.rewrite_member_sha(changed, json.loads(raw)['apps'][0]['sha256'])),
                             json.loads(raw))
            self.assertEqual(dest.read_bytes()[offset:offset + len(raw)], raw)


if __name__ == '__main__':
    unittest.main()
