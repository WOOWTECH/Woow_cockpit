"""Offline tests of the LiteLLM product-flow driver (litellm_full_flow.py): the dev-d lock rule, the tree rule, the
embedded device programs, what the lab derivation of the app image changes, and that no secret travels in argv.
Nothing here touches a device, Podman or a secret file."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('litellm_full_flow', HERE / 'litellm_full_flow.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = load()


class DriverRules(unittest.TestCase):
    def test_lock_waits_while_emqx_main_asks_for_the_next_turn(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            waiting.write_text('x')
            clock = iter(range(0, 100000, 5))
            with self.assertRaises(flow.Failed):
                flow.acquire(lock, waiting, timeout=20, sleep=lambda _s: None, clock=lambda: next(clock))
            waiting.unlink()
            fd, waited = flow.acquire(lock, waiting, timeout=20, sleep=lambda _s: None, clock=lambda: 0)
            os.close(fd)
            self.assertEqual(waited, 0)

    def test_lock_is_a_kernel_queued_wait_that_gives_way_to_emqx_main(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            lock, waiting = Path(directory) / 'lock', Path(directory) / 'waiting'
            calls, released = [], []
            answers = iter([False, False, True, True])

            def block(fd, seconds):
                calls.append(seconds)
                held = next(answers)
                if held and len(calls) == 3:
                    waiting.write_text('x')  # emqx-main asks for the next turn while this driver got the lock
                return held

            def sleep(_s):
                released.append(True)
                waiting.unlink(missing_ok=True)

            with mock.patch.object(fcntl, 'flock', side_effect=lambda fd, op: None):
                fd, waited = flow.acquire(lock, waiting, timeout=100, sleep=sleep, clock=lambda: 0, tick=30,
                                          block=block)
            os.close(fd)
            self.assertEqual((calls, len(released), waited), ([30, 30, 30, 30], 1, 0))
            self.assertIs(flow.acquire.__kwdefaults__['block'], flow._block)

    def test_a_real_kernel_queued_wait_times_out_and_then_holds(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'lock'
            other = os.open(lock, os.O_RDWR | os.O_CREAT, 0o664)
            fcntl.flock(other, fcntl.LOCK_EX)
            fd = os.open(lock, os.O_RDWR)
            try:
                self.assertFalse(flow._block(fd, 1))
                fcntl.flock(other, fcntl.LOCK_UN)
                self.assertTrue(flow._block(fd, 1))
            finally:
                os.close(fd)
                os.close(other)

    def test_only_evidence_may_differ_from_the_commit(self):
        out = ' M tests/e2e/lab/evidence/litellm-product-20261123/attempt-01.json\n?? tests/backup/evidence/x.json\n'
        with mock.patch.object(flow.subprocess, 'run', return_value=mock.Mock(stdout=out)):
            self.assertEqual(flow.clean_tree(), (True, []))
        with mock.patch.object(flow.subprocess, 'run', return_value=mock.Mock(stdout=' M backup-engine/x.py\n')):
            self.assertEqual(flow.clean_tree(), (False, ['backup-engine/x.py']))

    def test_programs_compile_and_never_print_values(self):
        flow.self_check()
        for program in (flow.PROBE, flow.DECRYPT):
            self.assertNotIn('print(secret', program)
            self.assertNotIn('print(master', program)
        self.assertIn('"secret_sha256"', flow.PROBE)
        self.assertIn('hashlib.sha256(v.encode()).hexdigest()', flow.PROBE)

    def test_the_lab_app_derivation_only_changes_the_user_and_prisma_owner(self):
        lines = [line for line in flow.DERIVE.splitlines() if line]
        self.assertEqual(lines[0], f'FROM {flow.APP_BASE}')
        self.assertEqual([line.split()[0] for line in lines], ['FROM', 'USER', 'RUN', 'USER', 'LABEL'])
        self.assertIn('chown -R 1000:0 /app/.venv/lib/python3.13/site-packages/prisma', flow.DERIVE)

    def test_secrets_reach_the_device_on_stdin_only(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs.get('input')))
            return mock.Mock(returncode=0, stdout=b'{}\n', stderr=b'')

        with mock.patch.object(flow.drv, 'run', side_effect=run):
            flow.drv.device_python(flow.PROBE, {'keys': {'ha': 'sk-secret-value-123'}}, as_owner=True)
        argv, data = calls[0]
        self.assertNotIn('sk-secret-value-123', ' '.join(argv))
        self.assertIn(b'sk-secret-value-123', data)

    def test_optional_phases_stop_at_the_hold_budget(self):
        run = flow.Run(mock.Mock(), mock.Mock())
        run.lock_started = flow.time.monotonic()
        self.assertTrue(run.optional('autorb'))
        run.lock_started = flow.time.monotonic() - flow.OPTIONAL_BUDGET - 1
        self.assertFalse(run.optional('restart'))


if __name__ == '__main__':
    unittest.main()
