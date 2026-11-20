import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('events', Path(__file__).with_name('b1_credential_events.py'))
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)


class CredentialEventsTests(unittest.TestCase):
    def setUp(self):
        self.log = []
        self.login = {'sequence': 0, 'kind': 'login', 'issue_refresh': True,
                      'token': 'test-access-a', 'refresh_token': 'test-refresh-a'}
        self.end = {'sequence': 1, 'kind': 'end'}

    def test_registers_all_rotations_once_and_redacts(self):
        stream = [self.login,
                  {'sequence': 1, 'kind': 'refresh', 'access_token': 'test-access-b',
                   'refresh_token': 'test-refresh-b'},
                  {'sequence': 2, 'kind': 'refresh', 'access_token': 'test-access-c'},
                  {'sequence': 3, 'kind': 'end'}]
        self.assertEqual(events.register_runner_events(stream, lambda k, v: self.log.append((k, v))), 5)
        evidence = ' '.join(v for _, v in self.log)
        for name, value in self.log:
            evidence = evidence.replace(value, '<' + name + '>')
        self.assertNotIn('test-access', evidence)
        self.assertNotIn('test-refresh', evidence)
        self.assertEqual(len(self.log), 5)

    def test_missing_or_invalid_events_fail_before_any_registration(self):
        variants = [[], [self.login], [dict(self.login, refresh_token=None), self.end],
                    [dict(self.login, issue_refresh=False), self.end],
                    [self.login, {'sequence': 2, 'kind': 'end'}],
                    [self.login, {'sequence': 1, 'kind': 'refresh', 'access_token': 'test-access-b',
                                  'refresh_token': None}, {'sequence': 2, 'kind': 'end'}],
                    [self.login, self.end, {'sequence': 2, 'kind': 'refresh', 'access_token': 'test-access-b'}]]
        for stream in variants:
            with self.subTest(stream=stream):
                with self.assertRaises(events.CredentialCoverageError) as caught:
                    events.register_runner_events(stream, lambda k, v: self.log.append((k, v)))
                self.assertNotIn('test-access', str(caught.exception))
                self.assertNotIn('test-refresh', str(caught.exception))
                self.assertEqual(self.log, [])

    def test_duplicate_credentials_are_registered_once(self):
        stream = [self.login, {'sequence': 1, 'kind': 'refresh', 'access_token': 'test-access-a'},
                  {'sequence': 2, 'kind': 'end'}]
        self.assertEqual(events.register_runner_events(stream, lambda k, v: self.log.append((k, v))), 2)


if __name__ == '__main__':
    unittest.main()
