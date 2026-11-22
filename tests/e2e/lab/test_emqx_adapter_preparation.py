"""Generated consumer/process tests only. No lab, Podman or production commands."""
import ast
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_adapter_mqtt as transport
import emqx_adapter_owner as owner
from woowbackup.podman import Result

BROKER = 'woowbk-emqxlab-aabb0011'


class MQTTTests(unittest.TestCase):
    def invoke(self, *, program='mosquitto_pub', payload='generated-marker',
               username='lab', failure=None, cleanup_failure=False, collision=False, clear=False, returncode=0,
               await_suback=False):
        self.calls = []
        self.root = None
        def podman(*args, **kwargs):
            self.calls.append((args, kwargs))
            if args[:2] == ('container', 'exists'):
                return Result(0 if collision else 1, b'', b'')
            if args[0] == 'rm':
                return Result(1 if cleanup_failure else 0, b'', b'')
            self.assertEqual(args[0], 'run')
            self.assertEqual(kwargs, {'check': False, 'timeout': 20, 'max_output': 65536})
            self.assertNotIn('generated-private-credential', repr((args, kwargs)))
            self.assertNotIn('-P', args)
            self.assertNotIn('-u', args)
            self.assertNotIn(username, args)
            self.assertIn('--log-driver=none', args)
            self.assertIn('--image-volume=ignore', args)
            self.assertIn('--pull=never', args)
            self.assertIn('--network=container:' + BROKER, args)
            self.assertIn('--userns=keep-id:uid=1000,gid=1000', args)
            name = args[args.index('--name') + 1]
            self.assertEqual(args[args.index('-i') + 1], name)
            self.assertRegex(name, '^' + BROKER + '-mqtt-[0-9a-f]{12}$')
            self.name = name
            mount = args[args.index('-v') + 1]
            self.assertTrue(mount.endswith(':/work:ro'))
            self.root = Path(mount[:-len(':/work:ro')])
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
            for command in ('mosquitto_pub', 'mosquitto_sub'):
                config = self.root / command
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertEqual(config.read_text(), '-u ' + username + '\n-P generated-private-credential\n')
            if failure:
                raise failure
            return Result(returncode, b'generated-output', b'')
        runner = SimpleNamespace(podman=podman)
        return transport.mqtt(runner, BROKER, program, 'lab/generated', payload,
                              username=username, credential='generated-private-credential', clear=clear,
                              await_suback=await_suback)

    def test_subscription_ack_mode_keeps_credentials_private_and_cleans_client(self):
        self.invoke(program='mosquitto_sub', payload=None, await_suback=True)
        args = next(args for args, _ in self.calls if args[0] == 'run')
        self.assertIn('-E', args)
        self.assertNotIn('-C', args)
        self.assert_cleaned()
        with patch.object(transport.tempfile, 'TemporaryDirectory') as create:
            with self.assertRaises(RuntimeError):
                transport.mqtt(None, BROKER, 'mosquitto_pub', 'lab/test', 'marker',
                    username='lab', credential='generated-private', await_suback=True)
            create.assert_not_called()

    def test_driver_denial_requires_actual_suback_not_timeout_or_success(self):
        import re
        tree = ast.parse(Path(__file__).with_name('emqx_adapter_driver.py').read_text())
        nested = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                      and n.name == 'denied_subscription')
        module = ast.fix_missing_locations(ast.Module(body=[nested], type_ignores=[]))
        for output, accepted in ((b'timed out: Not authorized', False),
                                 (b'received SUBACK\nSubscribed (mid: 1): 0', False),
                                 (b'received SUBACK\nSubscribed (mid: 1): 135', True)):
            calls = []
            def mqtt(*args, **kwargs):
                calls.append((args, kwargs))
                return Result(1, output, b'')
            namespace = {'mqtt':mqtt, 're':re}
            exec(compile(module, '<driver-suback-boundary>', 'exec'), namespace)
            if accepted:
                namespace['denied_subscription']()
            else:
                with self.assertRaises(RuntimeError):
                    namespace['denied_subscription']()
            self.assertTrue(calls[0][1]['await_suback'])

    def assert_cleaned(self):
        self.assertFalse(self.root.exists())
        self.assertEqual(self.calls[-2][0], ('rm', '--force', '--ignore', self.name))
        self.assertEqual(self.calls[-1][0], ('container', 'exists', self.name))

    def test_normal_source_auth_subscribe_retained_clear_and_denied_transport(self):
        names = set()
        for program, payload, username, clear in (
                ('mosquitto_pub', 'generated-marker', 'lab', False),
                ('mosquitto_pub', 'source-authenticated', 'source-only', False),
                ('mosquitto_sub', None, 'lab', False),
                ('mosquitto_pub', None, 'lab', True),
                ('mosquitto_pub', 'should-not-publish', 'lab', False)):
            self.invoke(program=program, payload=payload, username=username, clear=clear)
            args = next(args for args, _ in self.calls if args[0] == 'run')
            if clear:
                self.assertIn('-n', args)
                self.assertNotIn('-m', args)
            elif program == 'mosquitto_sub':
                self.assertIn('-C', args)
                self.assertIn('-W', args)
            else:
                self.assertEqual(args[args.index('-m')+1], payload)
            self.assert_cleaned()
            names.add(self.name)
        self.assertEqual(len(names), 5)

    def test_failure_timeout_cancellation_and_cleanup_failure_remove_private_files(self):
        for failure in (RuntimeError('generated-failure'), subprocess.TimeoutExpired('generated',20), KeyboardInterrupt()):
            with self.assertRaises(type(failure)):
                self.invoke(failure=failure)
            self.assert_cleaned()
        with self.assertRaisesRegex(RuntimeError, '^private-mqtt-cleanup-refused$'):
            self.invoke(cleanup_failure=True)
        self.assertFalse(self.root.exists())

    def test_nonzero_client_result_remains_private_and_cleanup_still_runs(self):
        result = self.invoke(returncode=135)
        self.assertEqual(result.returncode, 135)
        self.assertEqual(result.stdout, b'generated-output')
        self.assert_cleaned()

    def test_collision_preserved_and_credential_newline_refused_before_files(self):
        with self.assertRaisesRegex(RuntimeError, '^private-mqtt-name-refused$'):
            self.invoke(collision=True)
        self.assertEqual(len(self.calls), 1)
        with patch.object(transport.tempfile, 'TemporaryDirectory') as create:
            with self.assertRaises(RuntimeError):
                transport.mqtt(None, BROKER, 'mosquitto_pub', 'lab/test', 'marker',
                               username='lab', credential='private\n-o /arbitrary')
            create.assert_not_called()

    def test_driver_routes_clear_and_all_mqtt_operations_through_private_transport(self):
        tree = ast.parse(Path(__file__).with_name('emqx_adapter_driver.py').read_text())
        nested = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'mqtt')
        caller = []
        namespace = {'private_mqtt': lambda *a, **k: caller.append((a,k)),
                     'runner': object(), 'f': SimpleNamespace(prefix=BROKER), 'password': 'generated-normal'}
        module = ast.fix_missing_locations(ast.Module(body=[nested], type_ignores=[]))
        exec(compile(module, '<generated-driver-consumer>', 'exec'), namespace)
        namespace['mqtt']('mosquitto_pub', 'lab/from-ha', clear=True)
        namespace['mqtt']('mosquitto_pub', 'lab/source-login', 'marker',
                          username='source-only', credential='generated-source')
        self.assertTrue(caller[0][1]['clear'])
        self.assertEqual(caller[1][1]['credential'], 'generated-source')
        self.assertEqual(caller[1][1]['username'], 'source-only')
        # A second ad-hoc mosquitto container would bypass the transport.
        direct = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and n.func.attr == 'podman'
                  and any(isinstance(a, ast.Constant) and a.value == 'run' for a in n.args)]
        self.assertEqual(direct, [])


class OwnerTests(unittest.TestCase):
    def test_current_owner_uses_original_runner_environment_and_product_adapter(self):
        user = SimpleNamespace(pw_uid=1019, pw_gid=1019, pw_dir='/home/appowner', pw_name='appowner')
        with patch.object(owner.pwd, 'getpwnam', return_value=user), \
             patch.object(owner.pwd, 'getpwuid', return_value=user), \
             patch.object(owner.socket, 'gethostname', return_value='woowbk-dev-d'), \
             patch.object(owner.os, 'getuid', return_value=1019), \
             patch.object(owner.os, 'geteuid', return_value=1019), \
             patch.object(owner.os, 'getgid', return_value=1019), \
             patch.object(owner.os, 'getegid', return_value=1019):
            runner = owner.LabOwnerRunner()
        self.assertEqual(runner.prefix()[:2], ['/usr/bin/env','-i'])
        self.assertIn('HOME=/home/appowner', runner.prefix())
        self.assertIn('XDG_RUNTIME_DIR=/run/user/1019', runner.prefix())
        with patch.object(runner, '_runner', return_value=Result(0,b'',b'')) as execute:
            runner.podman('container','exists',BROKER)
        self.assertNotIn('/usr/sbin/runuser', execute.call_args.args[0])
        self.assertEqual(execute.call_args.kwargs['cwd'], '/home/appowner')
        fixture = owner.Fixture(BROKER, 'appowner', '3f60addfad2b'+'0'*52)
        app = SimpleNamespace(raw=fixture.catalog(), owner='appowner', adapter='quadlet-postgres')
        factory = owner.adapter_factory(fixture, runner)
        from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
        actual = factory(app, log=lambda _:None)
        self.assertIsInstance(actual, QuadletPostgresAdapter)
        app.raw = {}
        with self.assertRaises(RuntimeError):
            factory(app, log=lambda _:None)
        self.assertIs(owner.OwnerProvision.create, owner.Provision.create)
        self.assertIs(owner.OwnerProvision.cleanup, owner.Provision.cleanup)

    def test_wrong_host_and_root_refuse(self):
        user = SimpleNamespace(pw_uid=1019,pw_gid=1019,pw_dir='/home/appowner')
        with patch.object(owner.pwd,'getpwnam',return_value=user), \
             patch.object(owner.socket,'gethostname',return_value='not-dev-d'):
            with self.assertRaisesRegex(RuntimeError,'wrong-lab-owner'):
                owner.LabOwnerRunner()
        with patch.object(owner.pwd,'getpwnam',return_value=user), \
             patch.object(owner.socket,'gethostname',return_value='woowbk-dev-d'), \
             patch.object(owner.os,'getuid',return_value=0):
            with self.assertRaisesRegex(RuntimeError,'wrong-lab-owner'):
                owner.LabOwnerRunner()
