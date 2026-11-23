"""Internal LiteLLM cluster reader candidate: real tar parser and the product PgSink, synthetic data only."""
import io
import json
import tarfile
import unittest

from woowbackup import ha_litellm_candidate as candidate, ha_odoo
from woowbackup.errors import BackupError
from . import hafixtures

SALT = b'abcdefghijklmnop0123456789_-ABCD'
SECRETS = {'master_key': b'sk-master-synthetic-0001\n', 'salt_key': SALT + b'\n',
           'pg_password': b'pg-synthetic-0002', 'ui_password': b'ui-synthetic-0003'}


def member(*, slug='woow-litellm', secrets=None, extra=(), pg_version=b'18\n'):
    addon_info = {'system': {'slug': slug, 'name': 'LiteLLM'}, 'version': '0.1.15',
                  'user': {'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64'}}
    entries = [{'name': 'addon.json', 'data': json.dumps(addon_info).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/postgres/PG_VERSION', 'data': pg_version},
               {'name': 'data/postgres/global', 'type': 'dir'},
               {'name': 'data/postgres/global/pg_control', 'data': b'control'},
               {'name': 'data/postgres/pg_hba.conf', 'data': b'host all all 0.0.0.0/0 trust\n'},
               {'name': 'data/postgres/postgresql.conf', 'data': b"shared_preload_libraries = 'evil'\n"},
               {'name': 'data/postgres/postmaster.pid', 'data': b'123\n'},
               {'name': 'data/postgres/standby.signal', 'data': b''},
               {'name': 'data/woow', 'type': 'dir'},
               {'name': 'data/woow/state.json', 'data': b'{"litellm_version": "1.104.0"}'},
               {'name': 'data/secrets', 'type': 'dir', 'mode': 0o700}]
    for name, value in (SECRETS if secrets is None else secrets).items():
        entries.append({'name': f'data/secrets/{name}', 'data': value, 'mode': 0o600})
    entries.extend(extra)
    return io.BytesIO(hafixtures.tar_bytes(entries))


class Recorder:
    def __init__(self):
        self.added = []

    def add(self, rel, entry, data=None):
        self.added.append((rel, entry.kind, data))


class ClusterMemberTests(unittest.TestCase):
    def test_streams_cluster_and_returns_private_secrets(self):
        sink = Recorder()
        src = candidate.cluster_member(member(), sink)
        self.assertEqual((src.addon_version, src.pg_version), ('0.1.15', '18'))
        self.assertEqual(src.pg_files, 6)
        rels = [rel for rel, _kind, _data in sink.added]
        self.assertIn('.', rels)
        self.assertIn('global/pg_control', rels)
        self.assertEqual(dict((r, d) for r, _k, d in sink.added)['PG_VERSION'], b'18\n')
        self.assertFalse(any(r.startswith('woow') or 'secrets' in r for r in rels))
        self.assertEqual(src.secrets.value('salt_key'), SALT)
        self.assertEqual(src.secrets.value('master_key'), b'sk-master-synthetic-0001')
        self.assertEqual(src.secrets.names(), tuple(sorted(candidate.SECRET_NAMES)))
        text = repr(src) + str(src)
        for value in SECRETS.values():
            self.assertNotIn(value.strip().decode(), text)

    def test_product_pgsink_replaces_configuration_and_drops_runtime_files(self):
        out = io.BytesIO()
        sink = ha_odoo.PgSink(out, 70, 70)
        candidate.cluster_member(member(), sink)
        sink.close()
        out.seek(0)
        with tarfile.open(fileobj=out, mode='r:') as tar:
            names = {m.name: m for m in tar.getmembers()}
            self.assertNotIn('postmaster.pid', names)
            self.assertNotIn('standby.signal', names)
            self.assertEqual(tar.extractfile(names['pg_hba.conf']).read(), ha_odoo.PG_HBA)
            self.assertEqual(tar.extractfile(names['postgresql.conf']).read(), ha_odoo.PG_CONF)
            self.assertTrue(all(m.uid == 70 and m.gid == 70 for m in names.values()))
            self.assertTrue(all(m.mode in (0o700, 0o600) for m in names.values()))

    def test_missing_or_malformed_secrets_refuse(self):
        cases = [dict(SECRETS, salt_key=b'short'), {k: v for k, v in SECRETS.items() if k != 'pg_password'},
                 dict(SECRETS, ui_password=b'   \n'), dict(SECRETS, master_key=b'x' * 2000)]
        for secrets in cases:
            with self.subTest(names=sorted(secrets)):
                with self.assertRaises(BackupError) as caught:
                    candidate.cluster_member(member(secrets=secrets), Recorder())
                self.assertEqual(caught.exception.code, 'incompatible')
                for value in SECRETS.values():
                    self.assertNotIn(value.strip().decode(), str(caught.exception))

    def test_secret_that_is_not_a_regular_file_refuses(self):
        secrets = {k: v for k, v in SECRETS.items() if k != 'salt_key'}
        extra = [{'name': 'data/secrets/salt_key', 'type': 'symlink', 'linkname': '../../etc/passwd'}]
        with self.assertRaises(BackupError):
            candidate.cluster_member(member(secrets=secrets, extra=extra), Recorder())

    def test_other_addon_refuses(self):
        with self.assertRaises(BackupError) as caught:
            candidate.cluster_member(member(slug='woow-hermes'), Recorder())
        self.assertEqual(caught.exception.code, 'incompatible')

    def test_unparseable_pg_version_is_none(self):
        src = candidate.cluster_member(member(pg_version=b'eighteen'), Recorder())
        self.assertIsNone(src.pg_version)

    def test_public_conversion_still_refuses(self):
        with self.assertRaises(BackupError) as caught:
            candidate.convert(None, type('App', (), {'id': 'litellm'})(), False, None)
        self.assertEqual(caught.exception.message, candidate.GUARD)


if __name__ == '__main__':
    unittest.main()
