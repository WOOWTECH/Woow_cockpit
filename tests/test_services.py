"""Service-manager contracts; every external command is intercepted."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch


SPEC = importlib.util.spec_from_file_location(
    'service_manager', Path(__file__).parents[1] / 'services/service-manager.py')
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


def unit_output(name='n8n.service', **changes):
    fields = dict(Id=name, Description='Workflow service', LoadState='loaded',
                  ActiveState='active', SubState='running', UnitFileState='enabled',
                  FragmentPath='/etc/systemd/system/' + name, SourcePath='',
                  CanStart='yes', CanStop='yes', Result='success')
    fields.update(changes)
    return '\n'.join(f'{key}={value}' for key, value in fields.items()) + '\n'


class ServiceManagerContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lock_dir = Path(self.temp.name) / 'locks'
        self.replace(manager, 'LOCK_DIR', self.lock_dir)
        self.process = self.replace(manager.subprocess, 'run', side_effect=AssertionError(
            'Unexpected external command: supply a mocked response'))
        self.euid = self.replace(manager.os, 'geteuid', return_value=0)
        self.account = SimpleNamespace(pw_name='alice', pw_uid=1042, pw_gid=1042,
                                       pw_dir='/home/alice')
        self.lookup = self.replace(manager.pwd, 'getpwnam', return_value=self.account)
        self.config = Mock(spec=Path)
        self.config.is_symlink.return_value = False
        self.config.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100644)
        self.config.read_text.return_value = json.dumps({'owners': ['alice']})
        self.replace(manager, 'CONFIG', self.config)
        self.runtime = MagicMock(spec=Path)
        self.runtime.is_dir.return_value = True
        (self.runtime / 'bus').exists.return_value = True
        self.replace(manager, 'Path', return_value=self.runtime)

    def replace(self, target, name, *args, **kwargs):
        replacement = patch.object(target, name, *args, **kwargs)
        result = replacement.start()
        self.addCleanup(replacement.stop)
        return result

    def outputs(self, replies):
        """Route fixed executable/verb tokens, failing closed on unknown commands."""
        def execute(argv, **kwargs):
            for token, reply in replies.items():
                if token in argv:
                    if isinstance(reply, Exception):
                        raise reply
                    if isinstance(reply, subprocess.CompletedProcess):
                        return reply
                    return subprocess.CompletedProcess(argv, 0, reply, '')
            self.fail(f'Unexpected external command: {argv!r}')
        self.process.reset_mock()
        self.process.side_effect = execute

    def commands(self, token):
        return [call.args[0] for call in self.process.call_args_list if token in call.args[0]]

    def test_entry_requires_root_and_rejects_unknown_commands_scopes_and_verbs(self):
        self.euid.return_value = 1042
        with self.assertRaises(manager.ServiceError):
            manager.main(['scopes'])
        self.config.read_text.assert_not_called()
        self.process.assert_not_called()

        self.euid.return_value = 0
        requests = [[], ['shell', 'system'], ['inventory', 'system', 'extra']]
        requests += [['inventory', scope] for scope in
                     ('', 'root', 'user:root', 'user:mallory', 'user:alice;id')]
        requests += [['action', 'system', 'n8n.service', verb] for verb in
                     ('enable', 'disable', 'daemon-reload', 'kill', 'restart;id', '--help')]
        for argv in requests:
            with self.subTest(argv=argv), self.assertRaises(manager.ServiceError):
                manager.main(argv)
        self.process.assert_not_called()
        self.assertFalse(self.lock_dir.exists())

    def test_malicious_names_and_bare_templates_fail_before_any_command(self):
        bad_names = ('../n8n.service', '/etc/n8n.service', '--help.service',
                     'n8n.service;id', '$(id).service', 'n8n*.service',
                     'n8n.service\n', 'n8n\x00.service', 'n8n.socket',
                     'x' * 300 + '.service', '', None, 'worker@.service')
        for name in bad_names:
            for command in ('details', 'logs', 'action'):
                argv = [command, 'system', name] + (['start'] if command == 'action' else [])
                with self.subTest(name=name, command=command), self.assertRaises(manager.ServiceError):
                    manager.main(argv)
        self.process.assert_not_called()

    def test_protected_units_aliases_and_unsupported_actions_cannot_mutate(self):
        protected = ('cockpit.service', 'dbus.service', 'systemd-logind.service',
                     'cockpit-session@42.service', 'cockpit-wsinstance-https.service',
                     'user@1042.service')
        for canonical in protected:
            for requested in (canonical, 'innocent-alias.service'):
                for verb in ('start', 'stop', 'restart'):
                    with self.subTest(unit=canonical, requested=requested, verb=verb):
                        self.outputs({'show': unit_output(canonical)})
                        with self.assertRaises(manager.ServiceError):
                            manager.main(['action', 'system', requested, verb])
                        self.assertTrue(self.commands('show'))
                        self.assertFalse(self.commands(verb))
        for verb, capabilities in (('start', {'CanStart': 'no'}), ('stop', {'CanStop': 'no'}),
                                   ('restart', {'CanStart': 'no'}), ('restart', {'CanStop': 'no'})):
            with self.subTest(verb=verb, capabilities=capabilities):
                self.outputs({'show': unit_output(**capabilities)})
                with self.assertRaises(manager.ServiceError):
                    manager.main(['action', 'system', 'n8n.service', verb])
                self.assertFalse(self.commands(verb))
        self.assertFalse(self.lock_dir.exists())

    def test_config_ownership_permissions_and_owners_control_available_scopes(self):
        for uid, mode, symlink in ((1042, 0o100644, False), (0, 0o100664, False),
                                   (0, 0o100646, False), (0, 0o100644, True)):
            with self.subTest(uid=uid, mode=oct(mode), symlink=symlink):
                self.config.stat.return_value = SimpleNamespace(st_uid=uid, st_mode=mode)
                self.config.is_symlink.return_value = symlink
                with self.assertRaises(manager.ServiceError):
                    manager.main(['scopes'])
        self.config.read_text.assert_not_called()
        self.config.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100600)
        self.config.is_symlink.return_value = False
        invalid = ([], {'owners': 'alice'}, {'owners': ['root']}, {'owners': ['alice;id']},
                   {'owners': [None]}, {'owners': ['alice'] * 33})
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(manager.ServiceError):
                self.config.read_text.return_value = json.dumps(config)
                manager.main(['scopes'])
        self.config.read_text.return_value = json.dumps({'owners': ['alice']})
        for uid in (0, None):
            with self.subTest(owner_uid=uid):
                self.account.pw_uid = uid
                self.lookup.side_effect = KeyError('alice') if uid is None else None
                with self.assertRaises(manager.ServiceError):
                    manager.main(['scopes'])
        self.account.pw_uid = 1042
        self.lookup.side_effect = None
        self.config.read_text.return_value = json.dumps({'owners': ['alice', 'alice'],
                                                        'command': '/tmp/untrusted'})
        result = manager.main(['scopes'])
        self.assertEqual([(s['id'], s['uid']) for s in result['scopes']],
                         [('system', 0), ('user:alice', 1042)])
        self.assertEqual(result['default_scope'], 'user:alice')
        self.config.read_text.return_value = '{}'
        result = manager.main(['scopes'])
        self.assertEqual([s['id'] for s in result['scopes']], ['system'])
        self.assertEqual(result['default_scope'], 'system')
        self.process.assert_not_called()

    def test_user_commands_have_fixed_runuser_argv_and_clean_environment(self):
        self.outputs({'show': unit_output(), '/usr/bin/podman': '[]'})
        hostile = {'PATH': '/tmp/attacker', 'LD_PRELOAD': '/tmp/evil.so',
                   'PYTHONPATH': '/tmp/python', 'API_TOKEN': 'secret',
                   'XDG_RUNTIME_DIR': '/run/user/0', 'DBUS_SESSION_BUS_ADDRESS': 'evil'}
        with patch.dict(os.environ, hostile, clear=True):
            scope = manager.Scope('user:alice', {'owners': ['alice']})
            manager.unit_details(scope, 'n8n.service')
            manager.container_inventory(scope)
        prefix = ['/usr/sbin/runuser', '-u', 'alice', '--', '/usr/bin/env',
                  'XDG_RUNTIME_DIR=/run/user/1042',
                  'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1042/bus']
        show = self.commands('show')[0]
        self.assertEqual(show[:len(prefix) + 3], prefix + ['/usr/bin/systemctl', '--user', 'show'])
        self.assertEqual(show[show.index('--', len(prefix)) + 1:], ['n8n.service'])
        self.assertEqual(self.commands('/usr/bin/podman'),
                         [prefix + ['/usr/bin/podman', 'ps', '--all', '--format=json']])
        for call in self.process.call_args_list:
            env = call.kwargs['env']
            self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL', 'SYSTEMD_COLORS', 'SYSTEMD_PAGER'})
            self.assertEqual(env['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
            self.assertEqual(env['SYSTEMD_PAGER'], 'cat')
            self.assertFalse(call.kwargs.get('shell', False))
            self.assertGreater(call.kwargs['timeout'], 0)
        for directory, bus in ((False, True), (True, False)):
            with self.subTest(directory=directory, bus=bus):
                self.runtime.is_dir.return_value = directory
                (self.runtime / 'bus').exists.return_value = bus
                self.process.reset_mock()
                with self.assertRaises(manager.ServiceError):
                    manager.main(['inventory', 'user:alice'])
                self.process.assert_not_called()

    def test_logs_select_system_or_owner_journal_and_bound_output(self):
        for scope in ('system', 'user:alice'):
            with self.subTest(scope=scope):
                self.outputs({'show': unit_output(), '/usr/bin/journalctl': 'x' * 110000 + 'tail'})
                result = manager.main(['logs', scope, 'n8n.service'])
                command, = self.commands('/usr/bin/journalctl')
                self.assertIn('--lines=100', command)
                self.assertIn('--no-pager', command)
                if scope == 'system':
                    self.assertIn('--unit=n8n.service', command)
                    self.assertFalse(any(arg.startswith(('--user-unit=', '_UID=')) for arg in command))
                else:
                    self.assertEqual(command[:4], ['/usr/sbin/runuser', '-u', 'alice', '--'])
                    self.assertIn('--user', command)
                    self.assertIn('--unit=n8n.service', command)
                self.assertLessEqual(len(result['logs']), 100000)
                self.assertTrue(result['logs'].endswith('tail'))

    def test_successful_command_with_failed_unit_is_not_reported_as_success(self):
        before = dict(line.split('=', 1) for line in unit_output().splitlines())
        after = dict(before, ActiveState='failed', SubState='failed', Result='exit-code')
        self.replace(manager, 'unit_details', side_effect=[before, after])
        self.outputs({'stop': '', '/usr/bin/logger': ''})
        with self.assertRaisesRegex(manager.ServiceError, '失敗狀態'):
            manager.main(['action', 'system', 'n8n.service', 'stop'])
        self.assertEqual(len(self.commands('stop')), 1)

    def test_inventory_preserves_stopped_generated_units_skips_templates_and_filters_secrets(self):
        secret = 'DO-NOT-EXPOSE-THIS-TOKEN'
        self.outputs({
            'list-units': json.dumps([{'unit': 'cockpit.service'}, {'unit': 'backup@daily.service'}]),
            'list-unit-files': json.dumps([{'unit_file': name} for name in
                                          ('foo@.service', 'n8n.service', 'stopped.service',
                                           'n8n.socket', '../bad.service')]),
            'show': '\n'.join((unit_output('cockpit.service'), unit_output('backup@daily.service'),
                               unit_output('stopped.service', ActiveState='inactive', SubState='dead',
                                           UnitFileState='disabled'),
                               unit_output('n8n.service', ActiveState='inactive', SubState='dead',
                                           UnitFileState='generated', SourcePath='/etc/containers/systemd/n8n.container',
                                           FragmentPath='/run/systemd/generator/n8n.service', Environment=secret))),
            '/usr/bin/podman': json.dumps([
                {'Id': 'abc123', 'Names': ['workflow'], 'Image': 'example/n8n:1', 'State': 'exited',
                 'Status': 'Exited', 'Labels': {'PODMAN_SYSTEMD_UNIT': 'n8n.service', 'password': secret},
                 'Env': [secret], 'Command': [secret], 'Mounts': [{'Source': secret}],
                 'Ports': [{'host_ip': '127.0.0.1', 'host_port': 5678, 'container_port': 5678, 'protocol': 'tcp'}]},
                {'Id': 'def456', 'Names': 'unmanaged', 'Labels': {'PODMAN_SYSTEMD_UNIT': 'bad;id.service'}}]),
        })
        result = manager.main(['inventory', 'system'])
        services = {row['id']: row for row in result['services']}
        self.assertEqual(set(services), {'cockpit.service', 'backup@daily.service', 'n8n.service', 'stopped.service'})
        self.assertEqual((services['n8n.service']['kind'], services['n8n.service']['enabled'],
                          services['n8n.service']['active']), ('quadlet', 'generated', 'inactive'))
        self.assertEqual(services['stopped.service']['active'], 'inactive')
        self.assertTrue(services['backup@daily.service']['can_start'])
        self.assertTrue(services['cockpit.service']['protected'])
        self.assertFalse(services['cockpit.service']['can_start'])
        self.assertFalse(services['cockpit.service']['can_stop'])
        self.assertEqual(services['n8n.service']['containers'], ['workflow'])
        containers = {row['name']: row for row in result['containers']}
        self.assertEqual(containers['workflow']['unit'], 'n8n.service')
        self.assertEqual(containers['workflow']['state'], 'exited')
        self.assertIn('5678', containers['workflow']['ports'])
        self.assertIsNone(containers['unmanaged']['unit'])
        for row in result['containers']:
            self.assertEqual(set(row), {'id', 'name', 'image', 'state', 'status', 'unit', 'ports'})
        self.assertNotIn(secret, json.dumps(result))
        show, = self.commands('show')
        self.assertNotIn('foo@.service', show)
        self.assertNotIn('../bad.service', show)
        self.assertNotIn('n8n.socket', show)
        self.assertIn('n8n.service', show)
        self.assertIn('--all', self.commands('list-units')[0])
        self.assertIn('--all', self.commands('/usr/bin/podman')[0])

    def test_aliases_use_canonical_units_for_details_logs_and_actions(self):
        for operation in ('details', 'logs', 'action'):
            with self.subTest(operation=operation):
                self.outputs({'show': unit_output(), '/usr/bin/journalctl': 'canonical journal',
                              '/usr/bin/logger': '', 'restart': ''})
                argv = [operation, 'system', 'workflow-alias.service']
                result = manager.main(argv + (['restart'] if operation == 'action' else []))
                if operation == 'action':
                    self.assertTrue(result['ok'])
                    self.assertEqual(result['unit'], 'n8n.service')
                    self.assertEqual(result['active'], 'active')
                    self.assertEqual(self.commands('restart'),
                                     [['/usr/bin/systemctl', 'restart', '--', 'n8n.service']])
                else:
                    if operation == 'details':
                        self.assertEqual(result['unit']['id'], 'n8n.service')
                    journal, = self.commands('/usr/bin/journalctl')
                    self.assertIn('--unit=n8n.service', journal)
                    self.assertNotIn('--unit=workflow-alias.service', journal)
                    self.assertEqual(result['logs'], 'canonical journal')

    def test_failed_timed_out_or_locked_actions_never_report_success_or_retry(self):
        failures = (subprocess.CompletedProcess([], 1, '', 'systemctl refused action'),
                    subprocess.TimeoutExpired('systemctl', 45), FileNotFoundError(2, 'tool missing'))
        for failure in failures:
            with self.subTest(failure=repr(failure)):
                self.outputs({'show': unit_output(), '/usr/bin/logger': '', 'restart': failure})
                with self.assertRaises(manager.ServiceError) as error:
                    manager.main(['action', 'system', 'n8n.service', 'restart'])
                self.assertTrue(str(error.exception))
                self.assertEqual(len(self.commands('restart')), 1)
                audit = ' '.join(' '.join(cmd) for cmd in self.commands('/usr/bin/logger'))
                self.assertIn('result=unconfirmed', audit)
                self.assertNotIn('result=active', audit)
                self.assertNotIn('systemctl refused action', audit)
        self.outputs({'show': unit_output()})
        with patch.object(manager.fcntl, 'flock', side_effect=BlockingIOError):
            with self.assertRaises(manager.ServiceError):
                manager.main(['action', 'system', 'n8n.service', 'restart'])
        self.assertFalse(self.commands('restart'))
        # Failure must release the lock so a later explicit request can succeed.
        self.outputs({'show': unit_output(), '/usr/bin/logger': '', 'restart': ''})
        self.assertTrue(manager.main(['action', 'system', 'n8n.service', 'restart'])['ok'])

    def test_inventory_warns_for_podman_failure_but_rejects_partial_or_missing_units(self):
        replies = {'list-units': '[{"unit":"n8n.service"}]', 'list-unit-files': '[]',
                   'show': unit_output()}
        for failure in (subprocess.CompletedProcess([], 125, '', 'podman unavailable'),
                        subprocess.TimeoutExpired('podman', 20), 'invalid JSON'):
            with self.subTest(podman=repr(failure)):
                self.outputs({**replies, '/usr/bin/podman': failure})
                result = manager.main(['inventory', 'system'])
                self.assertEqual([row['id'] for row in result['services']], ['n8n.service'])
                self.assertEqual(result['containers'], [])
                self.assertTrue(result['warnings'])
        for show in (subprocess.CompletedProcess([], 1, unit_output(), 'partial show failure'),
                     unit_output(LoadState='not-found'), unit_output(LoadState='error'), ''):
            with self.subTest(show=repr(show)):
                self.outputs({**replies, 'show': show})
                with self.assertRaises(manager.ServiceError):
                    manager.main(['inventory', 'system'])
                self.assertFalse(self.commands('/usr/bin/podman'))


if __name__ == '__main__':
    unittest.main()
