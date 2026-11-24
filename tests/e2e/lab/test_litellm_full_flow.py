"""Offline tests of the LiteLLM product-flow driver (litellm_full_flow.py): the dev-d lock rule, the tree rule, the
embedded device programs, what the lab derivation of the app image changes, that no secret travels in argv, that the
catalog entry is the engine's own draft (asked here, not copied), and the container and digest comparisons. Nothing here
touches a device, Podman or a secret file."""
import copy
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))        # tests.backup (its __init__ puts this tree's engine first)


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

    def test_the_key_users_stub_is_a_valid_catalog_app_the_product_names(self):
        # The stub only has a catalog entry and a Quadlet file: the engine's own validator accepts the entry, the
        # product's key_users text rule names it, it is not one of LiteLLM's own apps, and it holds no secret.
        import types
        from woowbackup import catalog, ha_litellm
        from woowbackup.paths import Paths

        def lookup(name):
            if name != 'appowner':
                raise KeyError(name)
            return types.SimpleNamespace(pw_name=name, pw_uid=1001, pw_gid=1001, pw_dir='/home/appowner')

        with tempfile.TemporaryDirectory() as base:
            app = catalog.validate_entry(flow.STUB_ENTRY, paths=Paths(base=Path(base)), user_lookup=lookup)
        self.assertEqual((app.id, app.owner), (flow.STUB_ID, 'appowner'))
        self.assertEqual(flow.STUB_ENTRY['quadlet']['files'], [flow.STUB_FILE])
        self.assertTrue(ha_litellm._uses_litellm_text(flow.STUB_QUADLET))
        self.assertFalse(flow.STUB_ID == ha_litellm.APP_ID or flow.STUB_ID.startswith(f'{ha_litellm.APP_ID}-mcp'))
        self.assertNotIn('[Install]', flow.STUB_QUADLET)  # never started: no unit is enabled
        self.assertFalse(any(word in flow.STUB_QUADLET.upper() for word in ('KEY=', 'TOKEN', 'PASSWORD', 'SECRET')))

    def test_the_containers_are_compared_both_ways(self):
        base = ['hermes-agent', 'omnigent-server', 'woow-emqx']
        self.assertEqual(flow.container_changes(base, base), ([], []))
        self.assertEqual(flow.container_changes(base, base + ['litellm']), ([], ['litellm']), 'a new one is seen')
        self.assertEqual(flow.container_changes(base, base[1:]), (['hermes-agent'], []), 'one that vanished is seen')
        # dev-d's headscale in one snapshot or the other (attempts 07, 08, negative-01): a difference ...
        self.assertEqual(flow.container_changes(base + ['headscale'], base), (['headscale'], []))
        self.assertEqual(flow.container_changes(base, base + ['headscale']), ([], ['headscale']))
        # ... left out only when its unit's own restart counter grew during the run
        for before, after, apart in ((1363, 1500, {'headscale'}), (0, 0, set()), (5, 4, set()), (None, 3, set()),
                                     (3, None, set())):
            with self.subTest(before=before, after=after):
                self.assertEqual(flow.restarting({'headscale': before}, {'headscale': after}), apart)
        self.assertEqual(flow.container_changes(base, base + ['headscale'], {'headscale'}), ([], []))
        self.assertEqual(flow.restarting({}, {}), set())
        self.assertEqual(flow.RESTART_UNITS, {'headscale': 'headscale.service'})

    def test_the_restart_counter_is_only_read(self):
        calls = []

        def owner(*argv, **_kwargs):
            calls.append(argv)
            return mock.Mock(stdout=b'1363\n', returncode=0)

        with mock.patch.object(flow.drv, 'owner', side_effect=owner):
            self.assertEqual(flow.restart_counts(), {'headscale': 1363})
        self.assertEqual(calls, [('systemctl', '--user', 'show', '-p', 'NRestarts', '--value', 'headscale.service')])
        with mock.patch.object(flow.drv, 'owner', return_value=mock.Mock(stdout=b'', returncode=1)):
            self.assertEqual(flow.restart_counts(), {'headscale': None})

    def test_the_digest_result_is_read_from_the_jobs_own_shape(self):
        # flows.digest_entry / verification_entry: one entry per app with its checks
        result = {'verification': [{'app': 'other', 'checks': [{'id': 'x', 'match': True}]},
                                   {'app': 'litellm', 'match': None, 'before': {}, 'after': {},
                                    'checks': [{'id': 'db-main', 'match': None, 'note': 'n'}]}]}
        self.assertEqual(flow.digest_checks(result), {'db-main': None})
        self.assertEqual(flow.digest_checks({'verification': []}), {})
        self.assertEqual(flow.digest_checks({}), {})

    def test_optional_phases_stop_at_the_hold_budget(self):
        run = flow.Run(mock.Mock(), mock.Mock())
        run.lock_started = flow.time.monotonic()
        self.assertTrue(run.optional('autorb'))
        run.lock_started = flow.time.monotonic() - flow.OPTIONAL_BUDGET - 1
        self.assertFalse(run.optional('restart'))


class TheProductsOwnDraft(unittest.TestCase):
    """The run installs what the engine proposes, unedited: the expectations are the engine's answer for the package's
    Quadlet files (tests.backup.test_suggest.LiteLLMPackageTests), for a fresh device and for one with the production
    shape installed."""

    def setUp(self):
        from tests.backup import test_suggest
        self.package = test_suggest.LiteLLMPackageTests('test_the_import_accepts_the_new_draft_as_it_is')
        self.package.setUp()
        self.addCleanup(self.package.doCleanups)
        self.fresh = self.package.draft()

    def test_the_fresh_draft_is_the_expected_entry(self):
        self.assertEqual(flow.fresh_draft_problems(self.fresh), [])
        self.assertEqual(self.package.import_target(self.fresh['entry']).pg_id, 'main', 'and the import takes it')

    def test_what_attempt_10_edited_would_be_seen(self):
        cold = next(v for v in self.fresh['variants'] if v['id'] == 'cold')
        app = {**self.fresh, 'variant': 'cold', 'entry': cold['entry']}
        self.assertEqual(flow.fresh_draft_problems(app), ['postgres', 'variant', 'verify', 'volumes'])
        for key, value in (('verify', []), ('config_files', flow.DRAFT_CONFIGS[:1]),
                           ('health', [{**flow.DRAFT_HEALTH[0], 'url': 'http://127.0.0.1:4000/health/liveliness'}]),
                           ('health', [{**flow.DRAFT_HEALTH[0], 'timeout_seconds': 300}])):
            with self.subTest(key=key, value=value):
                app = copy.deepcopy(self.fresh)
                app['entry'][key] = value
                self.assertEqual(flow.fresh_draft_problems(app), [key])
        self.assertIn('valid', flow.fresh_draft_problems({**self.fresh, 'valid': False}))
        self.assertIn('installed', flow.fresh_draft_problems({**self.fresh, 'installed': {'same': True}}))

    def test_the_production_shape_gets_exactly_two_changes_and_then_none(self):
        old = flow.production_like(self.fresh['entry'])
        self.assertEqual((old['verify'], [h['timeout_seconds'] for h in old['health']]), ([], [300]))
        self.assertEqual(self.fresh['entry']['verify'], [flow.DIGEST], 'a copy was changed')
        app = self.package.draft(installed=[old])
        self.assertEqual(flow.installed_draft_problems(app), [])
        self.assertEqual((app['entry']['verify'], app['entry']['health']), ([flow.DIGEST], flow.DRAFT_HEALTH))
        self.assertEqual(flow.installed_draft_problems(self.fresh), ['changes', 'drift', 'health-timeout note',
                                                                     'import-mode note'])
        self.assertTrue(self.package.draft(installed=[app['entry']])['installed']['same'])
        self.assertEqual(self.package.import_target(app['entry']).pg_id, 'main')

    def test_the_run_never_edits_the_draft(self):
        # The driver hands catalog-install the answer itself: no assignment to the proposed entry's keys is left.
        source = (HERE / 'litellm_full_flow.py').read_text(encoding='utf-8')
        setup = source[source.index('    def setup(self):'):source.index('    def draft(self, name):')]
        self.assertIn("self.install_entry(app['entry'], 'the proposed draft, unedited')", setup)
        for edit in ("entry['verify']", "entry['health']", "entry['config_files']", "entry['postgres']"):
            self.assertNotIn(f'{edit} =', setup)


if __name__ == '__main__':
    unittest.main()
