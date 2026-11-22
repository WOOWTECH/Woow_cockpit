"""Code-only policy and native-envelope fixtures; never contacts dev-d."""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from emqx_owner_target import owner_target_readers
from test_emqx_owner_target import Atom, reply_document, typed

ROOT = Path(__file__).parent


class OwnerStorageTests(unittest.TestCase):
    def test_fixed_source_exact_pairs_and_pre_fold_gate(self):
        source = (ROOT / 'emqx_owner_target.expr').read_text()
        policy = source.split('StoragePolicy = fun(Storage) ->', 1)[1].split('StorageReceipt =', 1)[0]
        for pair in ('{ext,rocksdb_copies,mnesia_rocksdb}',
                     '{ext,null_copies,mria_mnesia_null_storage}'):
            self.assertIn(pair + ' -> ok;', policy)
        self.assertIn('{ext,_,_} -> error(storage_external)', policy)
        self.assertLess(source.index('StoragePolicy(Storage),'), source.index('mnesia:foldl('))
        self.assertEqual(source.count('mnesia:foldl('), 2)
        self.assertIn('StorageReceipt(StorageBefore,Count,N,N2,CountAfter)', source)
        self.assertIn('{0,0,0,0} -> ok; _ -> error(storage_null_nonempty)', source)
        self.assertIn('DefsAfter = [{T,mnesia:table_info(T,all)} || T <- All]', source)

    def test_execute_exact_fixed_source_policy_in_erlang(self):
        # Exercise the exact policy in the pinned native runtime even when the
        # host has no Erlang; absence of a host binary is not a passing skip.
        from emqx_native_runtime import run_native
        with tempfile.TemporaryDirectory(prefix='emqx-public-storage-policy-') as directory:
            root=Path(directory)
            for name in ('emqx_owner_storage_fixture.escript','emqx_owner_target.expr'):
                (root/name).write_bytes((ROOT/name).read_bytes())
                (root/name).chmod(0o600)
            with tempfile.TemporaryFile() as output:
                code=run_native(root,'emqx_owner_storage_fixture.escript',
                    args=('/input/emqx_owner_target.expr',),output=output)
                output.seek(0)
                self.assertEqual((code,output.read(128)),(0,b'OWNERSTORAGEFIXTUREOK'))

    def test_native_envelope_consumer_preserves_external_metadata(self):
        # Synthetic structured native reply, not execution of storage backends.
        @contextmanager
        def quiesce():
            yield
        def evaluate(expression):
            import re
            nonce = re.search(r'generation => <<"([0-9a-f]{32})">>', expression)[1]
            doc = reply_document(nonce)
            for definition in doc['schema_metadata']['value']:
                name, metadata = definition['value']
                if name['value'] == 'emqx_app':
                    metadata['value'].append(typed((Atom('native_backend'),
                        (Atom('ext'), Atom('null_copies'), Atom('mria_mnesia_null_storage')))))
                if name['value'] == 'schema':
                    metadata['value'].append(typed((Atom('backend_types'), [
                        (Atom('rocksdb_copies'), Atom('mnesia_rocksdb')),
                        (Atom('null_copies'), Atom('mria_mnesia_null_storage'))])))
            return b'WOOWTARGET:' + base64.b64encode(json.dumps(doc).encode()) + b':ENDok'
        with owner_target_readers(private_eval=evaluate, quiesce=quiesce) as readers:
            self.assertEqual(len(readers), 5)
            # Metadata enters the private persisted-value superset, not public evidence.
            values = readers.persisted_values
            from emqx_private_boundary import PrivateFailure
            for token in (b'mnesia_rocksdb', b'mria_mnesia_null_storage'):
                with self.assertRaises(PrivateFailure):
                    values.scan(token)

    def test_wrapper_uses_existing_readonly_validated_lock_fds(self):
        wrapper = (ROOT / 'run_emqx_owner_target.sh').read_text()
        for fd, name in ((9, 'main_lock'), (8, 'volume_lock')):
            self.assertIn(f'exec {fd}<"${name}"', wrapper)
            self.assertNotIn(f'exec {fd}>', wrapper)
            self.assertIn(f'! -L "${name}"', wrapper)
            self.assertIn(f'/proc/self/fd/{fd} -ef "${name}"', wrapper)
            self.assertIn(f'"$(stat -Lc %h /proc/self/fd/{fd})" = 1', wrapper)
