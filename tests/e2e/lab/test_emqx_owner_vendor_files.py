"""Generated contracts/filesystem tests only. No native runtime or lab access."""
import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

import emqx_owner_vendor_files as v
from emqx_private_boundary import PrivateFailure, Registry, SOURCES
from emqx_semantic_readers import Values


class VendorFilesTests(unittest.TestCase):
    def setUp(self):
        self.paths = list(v.PATHS)
        self.values = Values()
        self.cid = 'a' * 64
        self.broker = 'woowbk-emqx-fresh-012345abcdef'
        self.inspect = [{'Id': self.cid, 'Name': '/' + self.broker, 'Image': v.IMAGE,
            'State': {'Running': True}, 'Config': {'Env': ['EMQX_ETC_DIR=/opt/emqx/etc']},
            'HostConfig': {'NetworkMode': 'none', 'PortBindings': {}, 'LogConfig': {'Type': 'none'}},
            'Mounts': [{'Type': 'bind', 'Destination': '/opt/emqx/etc/emqx.conf',
                        'Source': '/private/generated.conf', 'RW': False},
                       {'Type': 'volume', 'Destination': '/opt/emqx/data', 'Name': 'owned-data'}]}]
        self.image = {'contract': v.CONTRACT, 'complete': True, 'files': []}
        for path in sorted(self.paths):
            acl = path.endswith('acl.conf')
            raw = (b'user_id,password,is_superuser\n' if path == v.BOOTSTRAP else
                   b'{allow, all}.\n' if acl else (
                b'-----BEGIN ' + (b'PRIVATE KEY' if path.endswith('key.pem') else b'CERTIFICATE') +
                b'-----\nZ2VuZXJhdGVkLWRlci1ieXRlcw==\n-----END ' +
                (b'PRIVATE KEY' if path.endswith('key.pem') else b'CERTIFICATE') + b'-----\n'))
            self.image['files'].append({'path': path, 'bytes': len(raw),
                'identity': [1, 0, 123, len(raw), 10, 10, stat.S_IFREG | 0o644, 1, 0, 0],
                'content_b64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
                'terms': [{'type': 'tuple', 'value': [{'type': 'atom', 'value': 'allow'},
                    {'type': 'atom', 'value': 'all'}]}] if acl else []})
        self.actual = copy.deepcopy(self.image)
        for item in self.actual['files']:
            item['identity'][2] = 456  # Overlay identity need not equal image inode.
        self.events = []
        self.directories = []

    def native(self, directory, script, *, output):
        self.events.append('image')
        self.directories.append(directory)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / script).stat().st_mode), 0o600)
        code = (directory / script).read_text()
        self.assertNotIn('generated-der-bytes', code)
        self.assertNotIn('PRIVATE KEY-----', code)
        self.assertIn('file:read(F,65537)', code)
        self.assertIn('eof=file:read(F,1)', code)
        self.assertIn('file:read_file_info(F', code)
        self.assertIn('DirIDs=', code)
        output.write(json.dumps(self.image).encode())
        return 0

    def inspect_callback(self):
        self.events.append('inspect')
        return json.dumps(self.inspect).encode()

    def eval_callback(self, expression):
        self.events.append('eval')
        self.assertEqual(expression, v.public_expression(self.paths))
        return b'WOOWVENDOR:' + base64.b64encode(json.dumps(self.actual).encode()) + b':ENDok\n'

    def observe(self, **changes):
        kwargs = dict(private_eval=self.eval_callback, private_inspect=self.inspect_callback,
            broker=self.broker, owned_container_id=self.cid, private_values=self.values)
        kwargs.update(changes)
        with patch.object(v, 'run_native', self.native):
            return v.observe_vendor_files(self.paths, **kwargs)

    def refuse(self, **changes):
        before = self.values.values
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            with self.assertRaisesRegex(PrivateFailure, '^private-vendor-files-refused$'):
                self.observe(**changes)
        self.assertEqual(stream.getvalue(), '')
        self.assertEqual(self.values.values, before)
        self.assertTrue(all(not d.exists() for d in self.directories))

    def test_full_contract_registers_acl_and_all_pem_encodings_privately(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.observe()
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(repr(result), '<VendorFiles private>')
        self.assertEqual(self.events, ['inspect', 'image', 'eval', 'inspect'])
        self.assertEqual(len(result.receipts), len(v.PATHS))
        for item in self.image['files']:
            self.assertIn(base64.b64decode(item['content_b64']), self.values.values)
        for value in (b'allow', b'all', b'generated-der-bytes', b'Z2VuZXJhdGVkLWRlci1ieXRlcw=='):
            self.assertIn(value, self.values.values)
        self.assertTrue(all(not d.exists() for d in self.directories))

    def test_values_feed_actual_existing_evidence_scanner(self):
        self.observe()
        registry = Registry()
        for source in sorted(SOURCES):
            registry.register(source, self.values.values if source == 'tls' else
                              [b'generated-test-backup-key'] if source == 'backup-key' else [])
        registry.seal()
        for marker in (b'generated-der-bytes', b'Z2VuZXJhdGVkLWRlci1ieXRlcw==', b'{allow, all}.'):
            with self.assertRaises(PrivateFailure):
                registry.scan(marker)

    def bootstrap_only(self):
        self.paths = ['${EMQX_ETC_DIR}/auth-built-in-db-bootstrap.csv']
        self.image['files'] = [x for x in self.image['files'] if x['path'] == v.BOOTSTRAP]
        self.actual['files'] = [x for x in self.actual['files'] if x['path'] == v.BOOTSTRAP]

    def set_bootstrap_content(self, document, raw):
        item = next(x for x in document['files'] if x['path'] == v.BOOTSTRAP)
        item.update(bytes=len(raw), content_b64=base64.b64encode(raw).decode(),
                    sha256=hashlib.sha256(raw).hexdigest())
        item['identity'][3] = len(raw)

    def test_observed_header_only_vendor_csv_registers_exact_bytes_and_all_cells(self):
        self.bootstrap_only()
        raw = b'user_id,password,is_superuser\n'
        self.assertEqual(len(raw), 30)
        result = self.observe()
        self.assertEqual(self.values.values, tuple(sorted((raw, b'user_id', b'password', b'is_superuser'))))
        self.assertEqual(result.receipts[0]['csv_rows'], 0)
        self.assertEqual(result.receipts[0]['bytes'], 30)
        self.assertEqual(result.receipts[0]['path'], v.BOOTSTRAP)
        self.assertEqual(result.receipts[0]['sha256'], hashlib.sha256(raw).hexdigest())
        registry = Registry()
        for source in SOURCES:
            registry.register(source, self.values.values if source == 'tls' else
                              [b'generated-test-key'] if source == 'backup-key' else [])
        registry.seal()
        for marker in (raw, b'user_id', b'password', b'is_superuser'):
            with self.assertRaises(PrivateFailure):
                registry.scan(marker)

    def test_vendor_csv_data_rows_register_decoded_cells_including_plain_password(self):
        self.bootstrap_only()
        raw = b'user_id,password,is_superuser\nfixture-user,"generated,password",false\n'
        self.set_bootstrap_content(self.image, raw)
        self.set_bootstrap_content(self.actual, raw)
        result = self.observe()
        self.assertEqual(result.receipts[0]['csv_rows'], 1)
        self.assertIn(b'generated,password', self.values.values)
        self.assertIn(b'fixture-user', self.values.values)
        self.assertIn(b'false', self.values.values)

    def test_csv_missing_empty_bad_header_or_different_actual_cells_refuse(self):
        self.bootstrap_only()
        original = copy.deepcopy(self.actual)
        for raw in (b'', b'username,password,is_superuser\n',
                    b'user_id,password,is_superuser\nfixture-user,pw,false\n'):
            self.actual = copy.deepcopy(original)
            self.set_bootstrap_content(self.actual, raw)
            self.refuse()
        self.actual = copy.deepcopy(original)
        self.actual['files'] = []
        self.refuse()

    def test_shared_csv_collector_enforces_file_and_row_bounds(self):
        header = b'user_id,password,is_superuser\n'
        rows = b''.join(('user%d,generated-password,false\n' % i).encode() for i in range(256))
        self.assertEqual(v.collect_bootstrap_csv(header + rows, Values()), 256)
        for raw in (header + rows + b'extra-user,pw,false\n', b'x'*(v.LIMIT+1), b''):
            with self.assertRaises(ValueError):
                v.collect_bootstrap_csv(raw, Values(), allow_header_only=True)
        with self.assertRaises(ValueError):
            v.collect_bootstrap_csv(header, Values())

    def test_vendor_csv_covering_mount_and_unknown_alias_refuse_before_native(self):
        self.bootstrap_only()
        self.inspect[0]['Mounts'].append({'Type': 'bind', 'Destination': v.BOOTSTRAP})
        self.refuse()
        self.assertNotIn('image', self.events)
        self.inspect[0]['Mounts'].pop()
        self.paths = ['/opt/emqx/etc/lab-bootstrap.csv']
        self.refuse()
        self.assertNotIn('image', self.events)

    def test_single_alias_observes_only_requested_fixed_file(self):
        self.paths = ['${EMQX_ETC_DIR}/acl.conf']
        self.image['files'] = self.image['files'][:1]
        self.actual['files'] = self.actual['files'][:1]
        result = self.observe()
        self.assertEqual([r['path'] for r in result.receipts], [v.PATHS[0]])

    def test_aliases_are_exact_and_public_expression_contains_no_host_expansion(self):
        for path in v.PATHS:
            alias = path.replace('/opt/emqx/etc', '${EMQX_ETC_DIR}')
            self.assertEqual(v.public_expression([alias]), v.public_expression([path]))
        self.assertNotIn('os:getenv', v.public_expression(self.paths))
        self.assertNotIn('\n', v.public_expression(self.paths))
        self.assertNotIn('\r', v.public_expression(self.paths))
        self.assertIn('file:read(F,65537)', v.public_expression(self.paths))

    def test_unknown_paths_refuse_before_any_callback(self):
        for references in ([], ['/etc/passwd'], ['${HOME}/acl.conf'],
                           ['/opt/emqx/etc/../etc/acl.conf'], ['${EMQX_ETC_DIR}/certs/unknown.pem']):
            self.paths = references
            self.refuse()
            self.assertEqual(self.events, [])

    def test_covering_mounts_refuse_but_sibling_config_is_allowed(self):
        original = copy.deepcopy(self.inspect)
        for destination in ('/', '/opt', '/opt/emqx', '/opt/emqx/etc',
                            '/opt/emqx/etc/acl.conf', '/opt/emqx/etc/certs',
                            '/opt/emqx/etc/certs/key.pem'):
            self.inspect = copy.deepcopy(original)
            self.inspect[0]['Mounts'].append({'Type': 'bind', 'Destination': destination})
            self.refuse()
        self.assertNotIn('image', self.events)

    def test_inspect_accepts_only_two_exact_pinned_image_spellings(self):
        for image in (v.IMAGE, v.IMAGE.removeprefix('sha256:')):
            with self.subTest(image=image):
                self.inspect[0]['Image'] = image
                result = self.observe()
                self.assertEqual(len(result.receipts), len(v.PATHS))
                self.assertTrue(all(r['image'] == v.IMAGE for r in result.receipts))
        for image in ('0'*64, 'sha256:'+'0'*64, 'sha512:'+v.IMAGE.removeprefix('sha256:'),
                      'sha256:'+v.IMAGE, v.IMAGE.upper(), None, True, [v.IMAGE]):
            with self.subTest(image=image):
                self.inspect[0]['Image'] = image
                self.refuse()

    def test_equivalent_inspect_spelling_change_preserves_identity(self):
        def evaluate(expression):
            result = self.eval_callback(expression)
            self.inspect[0]['Image'] = v.IMAGE.removeprefix('sha256:')
            return result
        self.assertEqual(len(self.observe(private_eval=evaluate).receipts), len(v.PATHS))

    def test_invalid_provenance_refuses(self):
        original = copy.deepcopy(self.inspect)
        mutations = [lambda d: d.update(Id='b'*64), lambda d: d.update(Image='sha256:'+'0'*64),
            lambda d: d['State'].update(Running=False),
            lambda d: d['Config'].update(Env=['EMQX_ETC_DIR=/host']),
            lambda d: d['HostConfig'].update(NetworkMode='host'),
            lambda d: d.update(Mounts=[{'Type': 'bind', 'Destination': '/opt/../opt/emqx/etc'}])]
        for mutate in mutations:
            self.inspect = copy.deepcopy(original)
            mutate(self.inspect[0])
            self.refuse()
        self.refuse(private_inspect=lambda: True)

    def test_changed_provenance_after_file_read_refuses(self):
        def evaluate(expression):
            result = self.eval_callback(expression)
            self.inspect[0]['Mounts'][1]['Name'] = 'different-volume'
            return result
        self.refuse(private_eval=evaluate)

    def test_changed_bytes_even_with_self_consistent_hash_refuses(self):
        item = self.actual['files'][0]
        raw = b'{deny, all}. \n'
        item.update(bytes=len(raw), content_b64=base64.b64encode(raw).decode(),
                    sha256=hashlib.sha256(raw).hexdigest())
        item['identity'][3] = len(raw)
        self.refuse()

    def test_incomplete_duplicate_missing_bad_identity_or_hash_refuse(self):
        original = copy.deepcopy(self.actual)
        mutations = [lambda d: d.update(complete=False), lambda d: d['files'].pop(),
            lambda d: d['files'].__setitem__(1, d['files'][0]),
            lambda d: d['files'][0].update(sha256='0'*64),
            lambda d: d['files'][0]['identity'].__setitem__(7, 2),
            lambda d: d['files'][0]['identity'].__setitem__(6, stat.S_IFLNK | 0o777),
            lambda d: d['files'][0].update(bytes=v.LIMIT+1),
            lambda d: d['files'][0].update(terms=[])]
        for mutate in mutations:
            self.actual = copy.deepcopy(original)
            mutate(self.actual)
            self.refuse()

    def test_native_failure_cleans_private_directory(self):
        def failed(directory, script, *, output):
            self.directories.append(directory)
            output.write(b'private partial output')
            raise TimeoutError('must not escape')
        self.native = failed
        self.refuse()
        self.assertNotIn('eval', self.events)

    def test_wire_bound_and_framing_refuse(self):
        for raw in (b'x'*(v.MAX_WIRE+1), b'WOOWVENDOR:@@:ENDok', b'private error', b''):
            self.refuse(private_eval=lambda expression: raw)

    def test_no_boolean_owner_or_arbitrary_broker(self):
        self.refuse(owned_container_id=True)
        self.refuse(broker='production')
        self.refuse(private_values=object())
        self.assertEqual(self.events, [])

    def test_invalid_pem_and_acl_term_refuse_before_registration(self):
        original = copy.deepcopy(self.image)
        for acl in (False, True):
            docs = copy.deepcopy(original)
            suffix = 'acl.conf' if acl else '.pem'
            item = next(x for x in docs['files'] if x['path'].endswith(suffix))
            if acl:
                item['terms'] = [{'type': 'unsupported', 'value': 'private'}]
            else:
                raw = b'invalid pem'
                item.update(bytes=len(raw), content_b64=base64.b64encode(raw).decode(),
                            sha256=hashlib.sha256(raw).hexdigest())
                item['identity'][3] = len(raw)
            self.image = copy.deepcopy(docs)
            self.actual = copy.deepcopy(docs)
            self.refuse()


if __name__ == '__main__':
    unittest.main()
