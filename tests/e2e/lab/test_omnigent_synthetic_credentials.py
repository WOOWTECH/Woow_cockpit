"""Fixture transport tests for harness ownership/partial-provision cleanup only."""
import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import omnigent_synthetic_credentials as probe


class ProvisionSafetyTests(unittest.TestCase):
    def invoke(self, pod):
        metadata = [SimpleNamespace(stdout=b'true none {}'),
                    SimpleNamespace(stdout=b'1000000000 4294967296')]
        with patch.object(probe, 'pod', side_effect=pod), \
             patch.object(probe.subprocess, 'run', side_effect=metadata), \
             patch('sys.argv', ['probe', '--run']), contextlib.redirect_stdout(io.StringIO()):
            probe.main()

    def test_existing_or_unknown_namespace_stops_before_mutation(self):
        for code in (0, 125):
            calls = []
            def pod(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('image','inspect'):
                    return SimpleNamespace(stdout=args[2].encode(), returncode=0)
                if args[1] == 'exists':
                    return SimpleNamespace(stdout=b'', returncode=code)
                self.fail('mutation before namespace proved empty')
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'namespace'):
                self.invoke(pod)
            self.assertFalse(any(c[0] in ('run','rm') or c[1] in ('create','rm') for c in calls))

    def test_partial_create_or_start_is_cleaned_after_prior_absence_proof(self):
        for fail in ('secret', 'run'):
            objects = {'secret':set(), 'volume':set(), 'container':set()}
            def pod(*args, **kwargs):
                if args[:2] == ('image','inspect'):
                    return SimpleNamespace(stdout=args[2].encode(), returncode=0)
                if len(args)>1 and args[1] == 'exists':
                    return SimpleNamespace(stdout=b'', returncode=0 if args[2] in objects[args[0]] else 1)
                if len(args)>1 and args[1] == 'create':
                    objects[args[0]].add(args[2])
                    if args[0] == fail:
                        raise RuntimeError('partial provisioning')
                elif args[0] == 'run':
                    objects['container'].add(args[args.index('--name')+1])
                    raise RuntimeError('partial provisioning')
                elif args[0] == 'rm':
                    objects['container'].discard(args[-1])
                elif len(args)>1 and args[1] == 'rm':
                    objects[args[0]].discard(args[-1])
                else:
                    self.fail('unexpected command')
                return SimpleNamespace(stdout=b'', stderr=b'', returncode=0)
            with self.subTest(fail=fail), self.assertRaisesRegex(RuntimeError, 'partial provisioning'):
                self.invoke(pod)
            self.assertTrue(all(not names for names in objects.values()))


if __name__ == '__main__':
    unittest.main()
