"""Generated owned-file/process-boundary tests; no native, lab or production IO."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_adapter_owner as owner
from emqx_adapter_provision import Provision
import emqx_owner_fixture_files as m
from emqx_private_boundary import PrivateFailure, Registry, SOURCES
from emqx_semantic_readers import Values

BASE = b'dashboard.default_password = "generated-config-secret"\n'
ACL = b'{allow,{username,"generated-user"},all,["lab/#"]}.\n{deny,all}.\n'
CSV = b'user_id,password,is_superuser\ngenerated-user,"generated,password",false\n'


def binary(value):
    return {'type': 'binary', 'value': base64.b64encode(value).decode()}


class GeneratedRunner:
    owner = 'appowner'

    def __init__(self, root):
        self.home = str(root)
        self.calls = []
        self.secrets = {}
        self.volumes = set()
        (root / '.config/containers/systemd').mkdir(parents=True)

    def run(self, args):
        self.calls.append(args)
        if args[0] == '/usr/bin/mkdir':
            Path(args[-1]).mkdir()
        elif args[0] == '/usr/bin/rmdir':
            Path(args[-1]).rmdir()
        else:
            raise AssertionError(args)

    def write_file(self, name, value, mode):
        path = Path(self.home) / name
        path.write_bytes(value)
        path.chmod(mode)

    def remove_file(self, name):
        (Path(self.home) / name).unlink()

    def stat_files(self, paths):
        return {p: {'type': 'file' if (Path(self.home) / p).exists() else 'missing'} for p in paths}

    def systemctl(self, *args, **kwargs):
        self.calls.append(('systemctl', args))

    def podman(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        out, code = b'', 0
        if args[:2] == ('image', 'inspect'):
            out = json.dumps([{'Id': m.IMAGE, 'Config': {'Labels': {'org.opencontainers.image.version': '5.8.9'}}}]).encode()
        elif args[:2] == ('volume', 'exists'):
            code = 0 if args[2] in self.volumes else 1
        elif args[:2] == ('volume', 'create'):
            self.volumes.add(args[2])
        elif args[:2] == ('secret', 'ls'):
            out = '\n'.join(self.secrets).encode()
        elif args[:2] == ('secret', 'create'):
            self.secrets[args[2]] = ('d' * 25, kwargs['input'])
        elif args[:2] == ('secret', 'inspect'):
            assert args[2] == '--showsecret'
            assert kwargs == {'timeout': 5, 'max_output': 2*m.LIMIT}
            sid, data = self.secrets[args[3]]
            out = json.dumps([{'ID': sid, 'Spec': {'Name': args[3]}, 'SecretData': data.decode()}]).encode()
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=out, stderr=b'', returncode=code)


class FixtureFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='generated-fixture-files-')
        self.addCleanup(self.tmp.cleanup)
        self.runner = GeneratedRunner(Path(self.tmp.name))
        with patch.object(owner, 'LabOwnerRunner', return_value=self.runner):
            self.provision = owner.OwnerProvision(m.IMAGE.removeprefix('sha256:'))
        self.f = self.provision.create(BASE, ACL, CSV, b'generated-dashboard-secret')
        self.cap = self.provision.file_capability
        self.addCleanup(m.revoke, self.cap)
        self.values = Values()
        self.cid = 'a' * 64
        self.doc = [{'Id': self.cid, 'Name': '/' + self.f.prefix, 'Image': m.IMAGE,
            'State': {'Running': True}, 'HostConfig': {'NetworkMode': 'none',
                'PortBindings': {}, 'Memory': 768*1024*1024, 'NanoCpus': 1000000000, 'PidsLimit': 512},
            'Config': {'Env': ['EMQX_NODE__NAME=emqx@127.0.0.1'],
                       'Secrets': [{'Name': self.f.secret, 'ID': 'd'*25}]},
            'Mounts': [
                {'Type': 'volume', 'Name': name, 'Destination': destination, 'RW': True}
                for name, destination in zip(self.f.volumes, ('/opt/emqx/data', '/opt/emqx/log'))] + [
                {'Type': 'bind', 'Destination': m.BASE, 'RW': False,
                 'Source': self.runner.home + '/.config/' + self.f.prefix + '/base.hocon'},
                {'Type': 'bind', 'Destination': m.ACL, 'RW': False,
                 'Source': self.runner.home + '/.config/' + self.f.prefix + '/acl.conf'},
                {'Type': 'bind', 'Destination': m.BOOTSTRAP, 'RW': False,
                 'Source': '/generated/podman/secret/mount'}]}]
        self.files = {'contract': m.CONTRACT, 'complete': True, 'files': []}
        for path, raw in sorted(((m.BASE, BASE), (m.ACL, ACL), (m.BOOTSTRAP, CSV))):
            terms = ([binary(b'generated-config-secret'), binary(b'dashboard.default_password')]
                     if path == m.BASE else [{'type': 'tuple', 'value': [
                         {'type': 'atom', 'value': 'allow'}, {'type': 'list', 'value': [
                             {'type': 'integer', 'value': c} for c in b'generated-user']}]}]
                     if path == m.ACL else [])
            self.files['files'].append({'path': path, 'bytes': len(raw),
                'identity': [1, 0, 100, len(raw), 10, 10, stat.S_IFREG | 0o400, 1, 1000, 1000],
                'content_b64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
                'terms': terms})
        self.events = []

    def inspect(self):
        self.events.append('inspect')
        return json.dumps(self.doc).encode()

    def evaluate(self, expression):
        self.events.append('eval')
        self.assertEqual(expression, m.public_expression())
        self.assertNotIn('\n', expression)
        for secret in (b'generated-config-secret', b'generated,password', b'generated-user'):
            self.assertNotIn(secret.decode(), expression)
        return b'WOOWFIXTURE:' + base64.b64encode(json.dumps(self.files).encode()) + b':ENDok\n'

    def observe(self, token=None, **changes):
        kwargs = dict(private_eval=self.evaluate, private_inspect=self.inspect, private_values=self.values)
        kwargs.update(changes)
        return m.observe_fixture_files(self.cap if token is None else token, **kwargs)

    def refuse(self, **changes):
        before = self.values.values
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaisesRegex(PrivateFailure, '^private-fixture-files-refused$'):
                self.observe(**changes)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(before, self.values.values)

    def test_real_create_callsite_issues_file_and_secret_bound_capability(self):
        self.assertIsInstance(self.cap, m.FixtureFiles)
        self.assertEqual(repr(self.cap), '<FixtureFiles private>')
        self.assertIs(self.provision.fixture, self.f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            receipts = self.observe()
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(self.events, ['inspect', 'eval', 'inspect'])
        self.assertEqual({r['path'] for r in receipts}, set(m.PATHS))
        for marker in (BASE, ACL, CSV, b'generated-config-secret', b'generated-user',
                       b'generated,password', b'is_superuser', b'false'):
            self.assertIn(marker, self.values.values)
        self.assertTrue(all(r['container_id'] == self.cid for r in receipts))
        registry = Registry()
        for source in SOURCES:
            registry.register(source, self.values.values if source == 'tls' else
                              [b'generated-backup-key'] if source == 'backup-key' else [])
        registry.seal()
        for marker in (b'generated,password', b'generated-user', b'generated-config-secret'):
            with self.assertRaises(PrivateFailure):
                registry.scan(marker)

    def test_failed_parent_creation_cannot_issue_or_reuse_capability(self):
        with patch.object(owner, 'LabOwnerRunner', return_value=self.runner):
            other = owner.OwnerProvision(m.IMAGE.removeprefix('sha256:'))
        with patch.object(Provision, 'create', side_effect=RuntimeError('generated failure')), \
             patch.object(m, '_issue') as issue:
            with self.assertRaises(RuntimeError):
                other.create(BASE, ACL, CSV, b'generated-dashboard-secret')
            issue.assert_not_called()
        self.assertIsNone(other.file_capability)
        with self.assertRaisesRegex(RuntimeError, 'fixture-files-already-issued'):
            self.provision.create(BASE, ACL, CSV, b'generated-dashboard-secret')

    def test_issuance_requires_actual_new_files_and_exact_creation_bytes(self):
        with patch.object(owner, 'LabOwnerRunner', return_value=self.runner):
            other = owner.OwnerProvision(m.IMAGE.removeprefix('sha256:'))
        with self.assertRaises(PrivateFailure):
            m._issue(other, BASE, ACL, CSV)
        write = self.runner.write_file
        def corrupt(name, data, mode):
            write(name, b'changed creation bytes' if name.endswith('/acl.conf') else data, mode)
        with patch.object(self.runner, 'write_file', side_effect=corrupt):
            with self.assertRaises(PrivateFailure):
                other.create(BASE, ACL, CSV, b'generated-dashboard-secret')
        self.assertIsNone(other.file_capability)

    def test_cleanup_revokes_before_resource_cleanup_even_on_failure(self):
        def failed_cleanup(provision):
            self.assertIsNone(provision.file_capability)
            self.assertNotIn(self.cap, m._RECORDS)
            raise RuntimeError('generated-cleanup-failure')
        with patch.object(Provision, 'cleanup', failed_cleanup):
            with self.assertRaises(RuntimeError):
                self.provision.cleanup()
        self.refuse()
        self.assertEqual(self.events, [])

    def test_handmade_or_mixed_owner_capability_refuses(self):
        for token in ({'complete': True}, m.FixtureFiles(), True):
            self.refuse(token=token)
        original = self.provision.fixture
        self.provision.fixture = copy.copy(original)
        self.refuse()
        self.provision.fixture = original
        self.assertEqual(self.events, [])

    def test_missing_changed_replaced_or_symlink_source_refuses(self):
        path = Path(self.runner.home) / '.config' / self.f.prefix / 'acl.conf'
        path.unlink()
        self.refuse()
        path.write_bytes(ACL)
        self.refuse()  # Same bytes, different original inode.
        path.unlink()
        path.symlink_to('/etc/passwd')
        self.refuse()
        self.assertNotIn('eval', self.events)

    def test_changed_source_content_refuses(self):
        path = Path(self.runner.home) / '.config' / self.f.prefix / 'base.hocon'
        path.write_bytes(b'different=1')
        self.refuse()
        self.assertNotIn('eval', self.events)

    def test_secret_id_bytes_or_missing_secret_refuses(self):
        for value in (('e'*25, CSV), ('d'*25, CSV+b'changed')):
            self.runner.secrets[self.f.secret] = value
            self.refuse()
        self.runner.secrets.pop(self.f.secret)
        self.refuse()
        self.assertNotIn('eval', self.events)

    def test_mount_path_source_readonly_and_secret_identity_are_mandatory(self):
        original = copy.deepcopy(self.doc)
        changes = [lambda d: d['Mounts'][2].update(Source='/host/arbitrary'),
            lambda d: d['Mounts'][3].update(RW=True),
            lambda d: d['Mounts'].pop(),
            lambda d: d['Mounts'].append({'Type': 'bind', 'Destination': '/opt/emqx/etc', 'RW': False}),
            lambda d: d['Mounts'][2].update(Destination='/opt/emqx/etc/emqx.conf'),
            lambda d: d['Config']['Secrets'][0].update(ID='e'*25),
            lambda d: d['Config'].pop('Secrets'),
            lambda d: d['HostConfig'].update(NetworkMode='host'),
            lambda d: d['Config']['Env'].append('EMQX_NODE__NAME=other@127.0.0.1'),
            lambda d: d.update(Image='sha256:'+'0'*64)]
        for change in changes:
            self.doc = copy.deepcopy(original)
            change(self.doc[0])
            self.refuse()
        self.refuse(private_inspect=lambda: True)
        self.assertNotIn('eval', self.events)

    def test_same_container_binding_survives_digest_spelling_but_not_recreation(self):
        self.observe()
        self.doc[0]['Image'] = m.IMAGE.removeprefix('sha256:')
        self.observe()
        self.doc[0]['Id'] = 'b'*64
        self.refuse()

    def test_source_or_mount_change_during_callback_refuses_atomically(self):
        def evaluate(expr):
            result = self.evaluate(expr)
            self.doc[0]['Mounts'][3]['Source'] += '-changed'
            return result
        self.refuse(private_eval=evaluate)

    def test_revocation_during_callback_refuses_atomically(self):
        def evaluate(expr):
            result = self.evaluate(expr)
            m.revoke(self.cap)
            return result
        self.refuse(private_eval=evaluate)

    def test_bad_complete_stream_bytes_terms_and_timeout_refuse(self):
        original = copy.deepcopy(self.files)
        mutations = [lambda d: d.update(complete=False), lambda d: d['files'].pop(),
            lambda d: d['files'][0].update(sha256='0'*64),
            lambda d: d['files'][0].update(terms=[]),
            lambda d: d['files'][-1]['identity'].__setitem__(7, 2)]
        for mutate in mutations:
            self.files = copy.deepcopy(original)
            mutate(self.files)
            self.refuse()
        self.refuse(private_eval=lambda expr: b'error-private-details')
        self.refuse(private_eval=lambda expr: b'x'*(m.MAX_WIRE+1))
        def timeout(expr):
            raise TimeoutError('generated private diagnostic')
        self.refuse(private_eval=timeout)
        def cancelled(expr):
            raise KeyboardInterrupt('generated private diagnostic')
        self.refuse(private_eval=cancelled)

    def test_complete_but_different_native_bytes_refuse(self):
        item = self.files['files'][-1]
        raw = CSV.replace(b'generated,password', b'different,password')
        item.update(bytes=len(raw), content_b64=base64.b64encode(raw).decode(),
                    sha256=hashlib.sha256(raw).hexdigest())
        item['identity'][3] = len(raw)
        self.refuse()

    def test_source_changes_during_eval_refuse(self):
        def evaluate(expr):
            result = self.evaluate(expr)
            path = Path(self.runner.home) / '.config' / self.f.prefix / 'acl.conf'
            path.write_bytes(b'{deny,all}.\n')
            return result
        self.refuse(private_eval=evaluate)

    def test_strict_csv_preserves_quoted_password_and_refuses_unsupported(self):
        values = Values()
        m._csv(CSV, values)
        self.assertIn(b'generated,password', values.values)
        for raw in (b'username,password,is_superuser\na,b,false\n',
                    b'user_id,password,is_superuser\na,b,false,extra\n',
                    b'user_id,password,is_superuser\na,b,False\n',
                    b'user_id,password,is_superuser\na,b,false\na,c,true\n',
                    b'user_id,password,is_superuser\na,"unterminated,false\n',
                    b'user_id,password,is_superuser\na,,false\n'):
            with self.assertRaises(Exception):
                m._csv(raw, Values())

    def test_fixed_native_source_keeps_full_parse_and_single_line(self):
        expression = m.public_expression()
        for path in m.PATHS:
            self.assertIn(path, expression)
        for required in ('erl_parse:parse_term', 'hocon_token:scan', 'hocon_token:parse',
                         'Syntax=Leaves(Tree,0)', 'Typed(Syntax,0)', 'Typed(Doc,0)', 'eof=file:read(F,1)',
                         'file:read(F,65537)', 'DirIDs=', 'throw(reference)'):
            self.assertIn(required, expression)
        self.assertNotIn('os:getenv', expression)
        self.assertNotIn('\n', expression)


if __name__ == '__main__':
    unittest.main()
