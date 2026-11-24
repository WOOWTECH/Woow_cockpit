"""The real batch 1 backups (made 2026-11-19 by Supervisor 2026.11.0 on the RPi5 (aarch64) and an x86-64 HA;
never committed): every member reads strictly, and each importer's pass and its sandboxed SQLite reads find what the
add-ons were given (counts from the lab's evidence summary). No container runs here: the broker and database steps are
covered by the fakes and the lab. Set WOOWBK_HA_B1_FIXTURES to the folder holding arm/ and x86/ and WOOWBK_HA_B1_KEY to
the backups' key (never printed). Team E2."""
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import ha_emqx, ha_headscale, ha_hermes, ha_omnigent, habackup, hacommon, hasecuretar, hasqlite, jobs

ROOT = os.environ.get('WOOWBK_HA_B1_FIXTURES')
KEY = os.environ.get('WOOWBK_HA_B1_KEY')
ARM = ('woow-omnigent', 'woow-emqx', 'woow-headscale')
X86 = ('woow-omnigent', 'woow-hermes', 'woow-emqx', 'woow-headscale')
BACKUPS = {  # name: (machine, encrypted, compressed, add-on suffixes)
    'woow-b1-arm-enc': ('arm', True, True, ARM), 'woow-b1-arm-plain': ('arm', False, True, ARM),
    'woow-b1-arm-enc-uncompressed': ('arm', True, False, ARM),
    'woow-b1-arm-emqx-stopped-enc': ('arm', True, True, ('woow-emqx',)),
    'woow-b1-x86-enc': ('x86', True, True, X86), 'woow-b1-x86-plain': ('x86', False, True, X86),
    'woow-b1-x86-enc-uncompressed': ('x86', True, False, X86),
    'woow-b1-x86-emqx-stopped-enc': ('x86', True, True, ('woow-emqx',)),
}
LIVE_CONFIG = {'prefixes.v4': '100.64.0.0/10', 'prefixes.v6': 'fd7a:115c:a1e0::/48',
               'dns.extra_records_path': '/var/lib/headscale/extra_records.json', 'server_url': 'https://x.example'}


@unittest.skipUnless(ROOT, 'set WOOWBK_HA_B1_FIXTURES (and WOOWBK_HA_B1_KEY) to read the real batch 1 HA backups')
class RealBatch1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.staging = Path(self.tmp.name)

    def path(self, name):
        machine = BACKUPS[name][0]
        return Path(ROOT) / machine / name / f'{name}.tar'

    def keys(self, name):
        if not BACKUPS[name][1]:
            return None
        if not KEY:
            self.skipTest('needs WOOWBK_HA_B1_KEY')
        return hasecuretar.Keys(KEY)

    def member(self, backup, name, suffix):
        found = [m for m in backup.layout.members if m.role == 'addon' and m.slug.split('_', 1)[-1] == suffix]
        self.assertEqual(len(found), 1, suffix)
        return backup.open_member(found[0].name, self.keys(name))

    def test_every_backup_is_described_and_its_add_ons_are_importable(self):
        for name, (machine, encrypted, compressed, suffixes) in BACKUPS.items():
            with self.subTest(name=name), habackup.open_backup(self.path(name)) as backup:
                doc = backup.layout.doc
                self.assertEqual(doc['compressed'], compressed)
                addons = {m.slug.split('_', 1)[-1]: m for m in backup.layout.members if m.role == 'addon'}
                self.assertEqual(sorted(addons), sorted(suffixes))
                self.assertTrue(all(m.encrypted == encrypted for m in addons.values()))
                for suffix, member in addons.items():
                    with backup.open_member(member.name, self.keys(name)) as stream:
                        info = habackup.read_addon_info(stream)
                    self.assertEqual(info.slug, suffix)
                    self.assertEqual(info.arch, 'aarch64' if machine == 'arm' else 'amd64')
                    if suffix == 'woow-emqx':
                        self.assertEqual(info.state, 'stopped' if 'stopped' in name else 'started', 'hot or cold')

    def test_omnigent_artifacts_and_cluster(self):
        for name in ('woow-b1-arm-enc', 'woow-b1-x86-enc'):
            with self.subTest(name=name), habackup.open_backup(self.path(name)) as backup:
                report = habackup.Report()
                with self.member(backup, name, 'woow-omnigent') as stream:
                    src = ha_omnigent.scan_member(stream, report)
                self.assertTrue(report.complete)
                self.assertEqual((src.addon.version, src.pg_version, src.cookie, src.addon_artifacts),
                                 ('0.1.23', '16', True, 0))
                self.assertIsNone(ha_omnigent.VERSIONS.blocker(src.addon.version, '0.21.0'))
                bundles = [k for k in src.keys if '/' in k]
                blobs = [k for k in src.keys if '/' not in k and k != ha_omnigent.COOKIE]
                self.assertTrue(bundles and len(blobs) == 1, (len(bundles), len(blobs)))
                self.assertTrue(all(ha_omnigent.key_ok(k) for k in src.keys))
                self.assertFalse([k for k in src.keys if k.startswith('.cache')])
                self.assertEqual(report.secret_files, 1, 'options.json is never read')

    def test_hermes_tree_and_databases(self):
        name = 'woow-b1-x86-enc'
        before = dict(jobs._MASK_COUNTS)
        with habackup.open_backup(self.path(name)) as backup:
            report = habackup.Report()
            with self.member(backup, name, 'woow-hermes') as stream:
                src = ha_hermes.scan_member(stream, report, self.staging, ha_hermes._Count(), machine=0x3E)
        for value, count in list(jobs._MASK_COUNTS.items()):  # the .env values masked by the pass (never printed)
            for _ in range(count - before.get(value, 0)):
                self.addCleanup(jobs.unmask_secret, value)
        self.assertTrue(report.complete)
        self.assertEqual(report.secret_files, 5, 'options.json and the four generated secrets are never read')
        self.assertEqual(src.image_version, '0.1.14')
        self.assertEqual((src.config_version, src.skills, src.cron_jobs), (51, 64, 1))
        self.assertIn('config.yaml：9c1a67eb-woow-hermes', src.ha_urls)
        for skipped in ('gateway.lock', 'gateway_state.json', 'kanban.db-shm', '.woow-image-version'):
            self.assertIn(skipped, src.skipped)
        self.assertEqual(src.foreign, [])
        self.assertEqual((src.counts['symlinks'], src.counts['hardlinks']), (0, 0))
        answers = hasqlite.run([{'db': n, 'check': 'quick', **({'counts': ['sessions', 'messages'],
                                                                 'queries': ['hermes.schema_version'], 'hermes_fts': True}
                                                                if n == 'state.db' else {})}
                                for n in sorted(src.dbs) if not n.endswith(ha_hermes.SIDECARS)],
                               dict(src.dbs), self.staging / 'sqlite')
        blockers, warnings, details = ha_hermes.analyse(src, {k: v for k, v in answers.items() if k is not None},
                                                        addon_version='0.1.14', release='0.22.5',
                                                        digest=ha_hermes.BASE_DIGESTS['0.22.5'])
        self.assertEqual(blockers, [])
        self.assertEqual((details['sessions'], details['messages'], details['schema_version']), (5, 15, 32))
        self.assertTrue(any('9c1a67eb-woow-hermes' in w for w in warnings))

    def test_emqx_files_hot_and_cold(self):
        for name in ('woow-b1-arm-enc', 'woow-b1-arm-emqx-stopped-enc', 'woow-b1-x86-enc', 'woow-b1-x86-emqx-stopped-enc'):
            with self.subTest(name=name), habackup.open_backup(self.path(name)) as backup:
                report = habackup.Report()
                buffer = io.BytesIO()
                tar = tarfile.open(fileobj=buffer, mode='w|', format=tarfile.PAX_FORMAT)
                sink = ha_emqx._Sink(tar, None)
                with self.member(backup, name, 'woow-emqx') as stream:
                    src = ha_emqx.scan_member(stream, report, sink)
                tar.close()
                self.assertTrue(report.complete)
                node, blocker = ha_emqx.node_name(src)
                self.assertEqual((node, blocker), ('emqx@127.0.0.1', None))
                self.assertIsNone(ha_emqx.VERSIONS.blocker(src.addon.version, '5.8.9'))
                self.assertEqual(bool(ha_emqx.hint_for(src.addon)), 'stopped' not in name)
                with tarfile.open(fileobj=io.BytesIO(buffer.getvalue())) as staged:
                    names = set(staged.getnames())
                self.assertIn('mnesia/emqx@127.0.0.1/emqx_authn_mnesia.DCD', names)
                self.assertIn('mnesia/emqx@127.0.0.1/schema.DAT', names)
                self.assertIn('configs/cluster.hocon', names)
                self.assertFalse([n for n in names if 'cookie' in n or n.startswith(('configs/vm.', 'configs/app.'))
                                  or n.endswith('.bak') or n.startswith(('trace', 'patches', 'backup'))])
                self.assertEqual(report.secret_files, 2, 'options.json and node.cookie are never read')

    def test_headscale_databases_also_when_only_the_wal_holds_them(self):
        for name in ('woow-b1-arm-enc', 'woow-b1-x86-enc'):
            with self.subTest(name=name), habackup.open_backup(self.path(name)) as backup:
                staging = self.staging / name
                staging.mkdir()
                report = habackup.Report()
                with self.member(backup, name, 'woow-headscale') as stream:
                    src = ha_headscale.scan_member(stream, report, staging)
                self.addCleanup(jobs.unmask_secret, src.noise)
                self.assertTrue(report.complete)
                self.assertEqual(report.secret_files, 3, 'options.json and the Headplane key and cookie')
                self.assertTrue(src.noise.startswith('privkey:'))
                self.assertEqual(src.records_count, 1)
                self.assertEqual(src.wal is not None, name.startswith('woow-b1-arm'), 'the RPi5 left a -wal')
                live = staging / 'live.sqlite'
                live.write_bytes(_live_db())
                files = {'ha.sqlite': src.db, **({'ha.sqlite-wal': src.wal} if src.wal else {}), 'live.sqlite': live}
                out = staging / 'out'
                out.mkdir()
                answers = hasqlite.run(ha_headscale._specs(replace=True), files, staging / 'sqlite',
                                       outputs=('ha.sqlite',), out_dir=out)
                blockers, warnings, details = ha_headscale.analyse(src, answers['ha.sqlite'], addon_version='0.1.3',
                                                                   version='0.29.4', ha_config=src.config,
                                                                   config=LIVE_CONFIG)
                self.assertEqual(blockers, [])
                self.assertEqual((details['users'], details['nodes'], details['pre_auth_keys'], details['db_version']),
                                 (3, 2, 2, 'v0.29.4'))
                self.assertGreaterEqual(details['api_keys'], 1)
                self.assertEqual(answers['ha.sqlite']['replaced']['prefixes'], ['live-key'])
                conn = __import__('sqlite3').connect(answers[None]['ha.sqlite'])
                try:
                    self.assertEqual(conn.execute('SELECT count(*) FROM users').fetchone()[0], 3)
                    self.assertEqual(conn.execute('SELECT prefix FROM api_keys').fetchall(), [('live-key',)])
                    self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                finally:
                    conn.close()
                self.assertFalse(os.path.exists(str(answers[None]['ha.sqlite']) + '-wal'))
                self.assertEqual(hacommon.network(src.config.get('prefixes.v4')),
                                 hacommon.network(LIVE_CONFIG['prefixes.v4']))


def _live_db():
    """A live-like Headscale database with one API key (the importer only reads its api_keys rows)."""
    import sqlite3
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'live.sqlite'
        conn = sqlite3.connect(path)
        conn.executescript("CREATE TABLE api_keys(id integer PRIMARY KEY AUTOINCREMENT, prefix text, hash blob, "
                           "expiration datetime, last_seen datetime, created_at datetime);"
                           "INSERT INTO api_keys(prefix, hash, created_at) VALUES ('live-key', x'01', '2026-11-19');")
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
