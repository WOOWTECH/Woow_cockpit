"""Local stateful cleanup regressions; no Podman process, device or lab access."""
import unittest

from woowbackup import tempctr
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from tests.backup.test_ha_tempctr import FakeRunner, JOB


class StatefulCleanupRunner(FakeRunner):
    """Track simulated objects independently of TempObjects' retry lists."""

    def __init__(self):
        super().__init__()
        self.objects = {kind: set() for kind in ('container', 'volume', 'network')}
        self.failures = {}
        self.unknown = set()
        self.removals = []

    def podman(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'run':
            self.objects['container'].add(args[args.index('--name') + 1])
        elif args[:2] in (('volume', 'create'), ('network', 'create')):
            self.objects[args[0]].add(args[-1])
        elif args[0] == 'rm' or args[:2] in (('volume', 'rm'), ('network', 'rm')):
            kind = 'container' if args[0] == 'rm' else args[0]
            key = (kind, args[-1])
            self.removals.append(key)
            outcome = self.failures.get(key)
            if outcome == 'exception':
                raise BackupError('job-failed', 'simulated transport failure')
            if outcome == 'exit125':
                return Result(125, b'', b'simulated storage busy')
            self.objects[kind].discard(args[-1])
        elif len(args) > 1 and args[1] == 'exists':
            key = (args[0], args[-1])
            if key in self.unknown:
                raise BackupError('job-failed', 'simulated unavailable inventory')
            return Result(0 if args[-1] in self.objects[args[0]] else 1, b'', b'')
        else:
            raise AssertionError('Unexpected simulated command: ' + repr(args))
        return Result(0, b'', b'')


class CleanupDependencyTests(unittest.TestCase):
    def prepare(self):
        runner = StatefulCleanupRunner()
        tmp = tempctr.TempObjects(runner, JOB)
        # Names intentionally overlap across kinds; tracking must stay typed.
        for role in ('first', 'second'):
            tmp.volume(role)
            tmp.network(role)
            tmp.run(role, 'unused-local-fixture:1', detach=True)
        return runner, tmp

    def test_partial_cleanup_retries_only_survivors_in_dependency_order(self):
        runner, tmp = self.prepare()
        survivors = [(kind, tmp.name('first')) for kind in runner.objects]
        runner.failures = {key: 'exit125' for key in survivors}
        self.assertEqual(tmp.cleanup(), [name for _, name in survivors])
        for kind in runner.objects:
            self.assertEqual(runner.objects[kind], {tmp.name('first')})
            self.assertEqual(getattr(tmp, kind + 's'), [tmp.name('first')])
        runner.failures.clear()
        runner.removals.clear()
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(runner.removals, survivors)  # container, volume, network
        self.assertTrue(all(not objects for objects in runner.objects.values()))
        runner.removals.clear()
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual(runner.removals, [])  # idempotent; no successful object retried

    def test_transport_failure_and_unknown_inventory_remain_retryable(self):
        for failure in ('exception', 'exit125'):
            with self.subTest(failure=failure):
                runner, tmp = self.prepare()
                keys = [(kind, tmp.name(role)) for kind in runner.objects
                        for role in ('first', 'second')]
                runner.failures = dict.fromkeys(keys, failure)
                runner.unknown = set(keys)
                self.assertEqual(len(tmp.cleanup()), 6)
                self.assertEqual(len(tmp.cleanup()), 6)
                for kind in runner.objects:
                    self.assertEqual(getattr(tmp, kind + 's'),
                                     [tmp.name('first'), tmp.name('second')])
                runner.failures.clear()
                runner.unknown.clear()
                runner.removals.clear()
                self.assertEqual(tmp.cleanup(), [])
                self.assertEqual(runner.removals, [(kind, tmp.name(role))
                                 for kind in runner.objects for role in ('second', 'first')])
                self.assertTrue(all(not objects for objects in runner.objects.values()))

    def test_failed_remove_with_confirmed_absence_does_not_leave_phantom(self):
        runner, tmp = self.prepare()
        for kind in runner.objects:
            runner.objects[kind].remove(tmp.name('first'))  # independently gone
            runner.failures[(kind, tmp.name('first'))] = 'exit125'
        self.assertEqual(tmp.cleanup(), [])
        self.assertEqual((tmp.containers, tmp.volumes, tmp.networks), ([], [], []))
        self.assertTrue(all(not objects for objects in runner.objects.values()))

    def test_explicit_transport_failure_keeps_objects_until_successful_retry(self):
        for kind, method in (('container', 'remove'), ('volume', 'remove_volume')):
            with self.subTest(kind=kind):
                runner, tmp = self.prepare()
                name = tmp.name('first')
                key = (kind, name)
                runner.failures[key] = 'exception'
                runner.unknown.add(key)
                with self.assertRaises(BackupError) as caught:
                    getattr(tmp, method)('first')
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertIn(name, getattr(tmp, kind + 's'))
                self.assertEqual(tmp.cleanup(), [name])
                runner.failures.clear()
                runner.unknown.clear()
                runner.removals.clear()
                self.assertEqual(tmp.cleanup(), [])
                self.assertEqual(runner.removals, [key])
                self.assertTrue(all(not objects for objects in runner.objects.values()))

    def test_context_exit_preserves_primary_failure_and_later_retry(self):
        runner, tmp = self.prepare()
        original = BackupError('wrong-key', 'synthetic primary import failure')
        runner.failures[('network', tmp.name('first'))] = 'exception'
        with self.assertRaises(BackupError) as caught:
            with tmp:
                raise original
        self.assertIs(caught.exception, original)
        self.assertEqual((tmp.containers, tmp.volumes, tmp.networks),
                         ([], [], [tmp.name('first')]))
        runner.failures.clear()
        self.assertEqual(tmp.cleanup(), [])
        self.assertTrue(all(not objects for objects in runner.objects.values()))


if __name__ == '__main__':
    unittest.main()
