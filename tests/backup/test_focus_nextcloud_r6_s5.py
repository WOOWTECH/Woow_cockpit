"""Offline tests of the S5-A builder. NOT native SSE or import acceptance.

The tiny cluster/key bytes below are structural unit inputs, never released as an S5 fixture. Runtime proof still
requires the actual OCC/WebDAV/cipher/key/PG gates. The product library is THIS repository's backup-engine (put on the
path by tests/backup/__init__.py), never the host's installed /usr/local copy.
"""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'e2e/lab'))
import focus_nextcloud_r6_s5 as s5
from woowbackup import habackup, ha_nextcloud, ha_odoo, tempctr

REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO/'backup-engine'
LIBRARIES = lambda: (habackup, ha_nextcloud, ha_odoo)   # noqa: E731 - the repository's own engine
MASTER = 'master_0123abcd'


def no_product(*args, **kwargs):
    raise AssertionError('offline tests never import the installed product library')


def key_bytes(seed):
    """A key file in the native layout (Security/Crypto.php:100): hex ciphertext|hex iv|hex hmac|3. Not key material."""
    h = hashlib.sha256(seed.encode()).hexdigest()
    return (h*2+'|'+h[:32]+'|'+h+'|3').encode()


def header_block(fields=None, pad=b'-'):
    fields = dict(s5.HEADER) if fields is None else fields
    raw = ('HBEGIN:'+''.join(k+':'+v+':' for k, v in fields.items())+'HEND').encode()
    return raw+pad*(s5.HEADER_SIZE-len(raw))


def symfony_help(command, contract=None):
    """What Symfony's JsonDescriptor prints for `help --format=json <command>`, built from a contract row."""
    row = s5.OCC_CONTRACT[command] if contract is None else contract
    options = {name: {'name': '--'+name, 'shortcut': o[0], 'accept_value': o[1], 'is_value_required': o[2],
                      'is_multiple': o[3], 'description': 'text', 'default': o[4]} for name, o in row['options'].items()}
    for name, shortcut in (('help', '-h'), ('quiet', '-q'), ('verbose', '-v|-vv|-vvv'), ('version', '-V'),
                           ('ansi', ''), ('no-ansi', ''), ('no-interaction', '-n'), ('no-warnings', '')):
        options[name] = {'name': '--'+name, 'shortcut': shortcut, 'accept_value': False, 'is_value_required': False,
                         'is_multiple': False, 'description': 'console', 'default': False}
    arguments = {name: {'name': name, 'is_required': a[0], 'is_array': a[1], 'description': 'text',
                        'default': [] if a[1] else None} for name, a in row['arguments'].items()}
    return {'name': command, 'hidden': False, 'usage': [command], 'description': row['description'], 'help': 'x',
            'definition': {'arguments': arguments or [], 'options': options}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)/'owned'; self.work.mkdir(mode=0o700)
        patcher = patch.object(s5, 'product', no_product); patcher.start(); self.addCleanup(patcher.stop)

    def write(self, name, raw):
        p = self.work/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw); p.chmod(0o600)
        return p


class LibraryTests(unittest.TestCase):
    def test_the_product_is_this_repositorys_engine_never_the_host_install(self):
        for module in (habackup, ha_nextcloud, ha_odoo):
            self.assertTrue(Path(module.__file__).resolve().is_relative_to(ENGINE), module.__file__)
        self.assertNotIn(s5.PRODUCT_LIB, sys.path)
        needle = "sys.path.insert(0, '" + '/usr'
        self.assertNotIn(needle, Path(__file__).read_text())


class PackagingTests(Base):
    def setUp(self):
        super().setUp()
        for path in ('html/config', 'html/custom_apps', 'pg', 'data'):
            (self.work/path).mkdir(parents=True)
        self.write('pg/PG_VERSION', b'16\n')
        self.write('pg/base/1/123', b'structural unit input only')
        self.write('html/config/config.php', b'''<?php
$CONFIG = array ('instanceid' => 'ocs5structural', 'passwordsalt' => 'unit-salt',
'secret' => 'unit-secret', 'version' => '35.0.1.1', 'installed' => true,
'dbtype' => 'pgsql', 'dbtableprefix' => 'oc_', 'dbname' => 'nextcloud',
'datadirectory' => '/share/nextcloud');
''')
        self.write('data/.ncdata', b'# Nextcloud data directory')
        # A >1MiB file exercises repeated bounded reads through the actual writer.
        self.write('data/s5owner/files/s5-binary.bin', header_block()+b'x'*(3*s5.MIB+7))
        self.write('data/files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey', key_bytes('unit'))
        self.proof = {'webdav_before': True, 'webdav_after_restart': True, 'plaintext_before_encryption': True,
                      'master_key_mode': True, 'pg_shutdown': True, 'cipher_and_keys': {}}
        for name in ('s5owner/files/s5-binary.bin', 'files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey'):
            p = self.work/'data'/name
            self.proof['cipher_and_keys'][name] = {'bytes': p.stat().st_size, 'sha256': s5.digest(p)}

    def build(self, proof=None):
        return s5.build_fixture(self.work, self.proof if proof is None else proof, libraries=LIBRARIES)

    def test_real_stream_packaging_strict_parser_and_truthful_provenance(self):
        sizes = []; read = s5.HashedReader.read
        def bounded(reader, size): sizes.append(size); return read(reader, size)
        with patch.object(s5.HashedReader, 'read', bounded):
            result = self.build()
        self.assertEqual(result['status'], 'passed'); self.assertFalse(result['haos_export'])
        self.assertFalse(result['s5_import_acceptance']); self.assertLessEqual(max(sizes), s5.MIB)
        path = Path(result['archive']); self.assertEqual(s5.digest(path), result['sha256'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()),
                         ['generated-s5-source.tar', 'provenance.private.json'])
        provenance = json.loads((path.parent/'provenance.private.json').read_text())
        self.assertEqual(provenance['actual_components']['images'], s5.IMAGES)
        self.assertEqual(provenance['native_proof'], self.proof)
        with tarfile.open(path) as tar:
            self.assertEqual([m.name for m in tar], [s5.SLUG+'.tar', 'share.tar', './backup.json'])
            doc = json.load(tar.extractfile('./backup.json'))
        self.assertFalse(doc['protected']); self.assertFalse(doc['extra']['haos_export'])
        self.assertTrue(doc['extra']['generated_test_fixture'])
        with habackup.open_backup(path) as opened:
            with opened.open_member('share.tar') as stream:
                report = habackup.Report(); names = {}
                for entry in habackup.iter_entries(stream, habackup.Select(), report):
                    if entry.kind == 'file':
                        h = hashlib.sha256()
                        for raw in iter(lambda: entry.read(65536), b''): h.update(raw)
                        names[entry.name] = h.hexdigest()
                self.assertTrue(report.complete)
                for name, row in self.proof['cipher_and_keys'].items():
                    self.assertEqual(names['nextcloud/'+name], row['sha256'])
        self.assertNotIn(s5.PRODUCT_LIB, sys.path)

    def test_link_hardlink_and_special_file_refused_without_following(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                p = self.work/'data/unsafe'
                if kind == 'symlink': p.symlink_to('/etc/passwd')
                elif kind == 'hardlink': os.link(self.work/'data/.ncdata', p)
                else: os.mkfifo(p)
                try:
                    with self.assertRaisesRegex(ValueError, 'source-link-or-special'): s5.tree(self.work/'data')
                finally: p.unlink()

    def test_missing_or_changed_actual_key_binding_refuses(self):
        for fault in ('missing', 'digest', 'length', 'runtime-proof', 'no-plaintext-before', 'no-master-key-mode'):
            with self.subTest(fault=fault):
                proof = copy.deepcopy(self.proof)
                row = proof['cipher_and_keys']['files_encryption/OC_DEFAULT_MODULE/master_unit.privateKey']
                if fault == 'missing':
                    proof['cipher_and_keys']['missing/key'] = row
                elif fault == 'digest': row['sha256'] = '0'*64
                elif fault == 'length': row['bytes'] += 1
                elif fault == 'runtime-proof': proof['webdav_after_restart'] = False
                elif fault == 'no-plaintext-before': del proof['plaintext_before_encryption']
                else: proof['master_key_mode'] = False
                with self.assertRaises(ValueError): self.build(proof)
                (self.work/'artifact').rmdir()

    def test_config_outside_share_refuses_in_actual_product_layout_scan(self):
        p = self.work/'html/config/config.php'
        p.write_bytes(p.read_bytes().replace(b'/share/nextcloud', b'/elsewhere/nextcloud'))
        with self.assertRaisesRegex(ValueError, 'native-config-layout'):
            self.build()

    def test_wrong_pg_major_and_live_pid_refuse(self):
        for fault in ('major', 'pid'):
            with self.subTest(fault=fault):
                self.write('pg/PG_VERSION', b'15\n' if fault == 'major' else b'16\n')
                if fault == 'pid': self.write('pg/postmaster.pid', b'123\n')
                with self.assertRaises(ValueError): self.build()
                (self.work/'artifact').rmdir()

    def test_output_is_exclusive_and_cold_file_change_refuses(self):
        artifact = self.work/'artifact'; artifact.mkdir()
        self.write('artifact/keep', b'previous-failed-attempt')
        with self.assertRaises(FileExistsError): self.build()
        self.assertEqual((artifact/'keep').read_bytes(), b'previous-failed-attempt')
        rows = s5.tree(self.work/'data')
        self.write('data/.ncdata', b'changed')
        class NoWriter:
            def add_member(self, *args): raise AssertionError('changed source must refuse before writing')
        with self.assertRaisesRegex(ValueError, 'cold-source-changed'):
            s5.pack_tree(NoWriter(), self.work/'data', 'nextcloud', rows, lambda: None)

    def test_stream_reader_refuses_unbounded_reads(self):
        import io
        reader = s5.HashedReader(io.BytesIO(b'test'), lambda: None)
        for size in (-1, s5.MIB+1):
            with self.assertRaisesRegex(ValueError, 'stream-read-bound'): reader.read(size)


class EngineBindingTests(unittest.TestCase):
    """Gap 1: the installed engine must equal the engine of a named commit, computed from git objects."""

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(REPO), *args])

    def test_manifest_is_every_engine_file_of_the_named_commit_from_git(self):
        manifest = s5.engine_manifest(REPO)
        names = [n for n in self.git('ls-tree', '-r', '--name-only', '--full-tree', s5.ENGINE_COMMIT, '--',
                                     'backup-engine/woowbackup').decode().splitlines()]
        self.assertEqual(sorted(n for n in manifest if n.startswith('lib/woowbackup/')),
                         sorted('lib/woowbackup/'+n[len('backup-engine/woowbackup/'):] for n in names))
        self.assertEqual(len(manifest), len(names)+2)
        for name, path in (('helper', 'backup-engine/woowtech-cockpit-backup'), ('lib/VERSION', 'VERSION'),
                           ('lib/woowbackup/ha_nextcloud.py', 'backup-engine/woowbackup/ha_nextcloud.py'),
                           ('lib/woowbackup/adapters/base.py', 'backup-engine/woowbackup/adapters/base.py')):
            self.assertEqual(manifest[name], hashlib.sha256(self.git('show', s5.ENGINE_COMMIT+':'+path)).hexdigest())

    def test_installed_engine_must_be_exactly_the_manifest(self):
        manifest = s5.engine_manifest(REPO)
        self.assertEqual(s5.engine_differs(dict(manifest), manifest), [])
        changed = dict(manifest, **{'lib/woowbackup/cli.py': '0'*64})
        extra = dict(manifest, **{'lib/woowbackup/extra.py': '1'*64})
        missing = {k: v for k, v in manifest.items() if k != 'helper'}
        self.assertEqual(s5.engine_differs(changed, manifest), ['lib/woowbackup/cli.py'])
        self.assertEqual(s5.engine_differs(extra, manifest), ['lib/woowbackup/extra.py'])
        self.assertEqual(s5.engine_differs(missing, manifest), ['helper'])

    def test_stale_upload_bindings_are_gone(self):
        source = Path(s5.__file__).read_text()
        for stale in ('PRIOR_SHA', 'HELPER_SHA', 'VERSION_SHA', 'transaction.json', '24d1dc3d14bfc94e', 'meta_program',
                      'cb23acdb', '539c32a6', '29ddb46f'):
            self.assertNotIn(stale, source)

    def test_device_engine_program_reads_the_installed_paths_as_named(self):
        program = s5.ENGINE_PROGRAM
        compile(program, 'engine-program', 'exec')
        for needle in ("'/usr/local/lib/woowtech-cockpit-backup'", "'/usr/local/libexec/woowtech-cockpit-backup'",
                       "'lib/VERSION'", "'helper'", "!='__pycache__'", 'O_NOFOLLOW'):
            self.assertIn(needle, program)


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.code = Path(s5.__file__).read_text()
        self.engine = {'helper': 'a'*64, 'lib/VERSION': 'b'*64}
        self.now = 1_900_000_000.0
        start = datetime.datetime.fromtimestamp(self.now-60, datetime.timezone.utc)
        end = datetime.datetime.fromtimestamp(self.now+45*60, datetime.timezone.utc)
        self.lease = {'lane': 'nextcloud-r6', 'device': 'woowbk-dev-e', 'phases': [s5.PHASE], 'source_commit': 'c'*40,
                      'builder_sha256': s5.sha(self.code.encode()), 'engine_commit': s5.ENGINE_COMMIT,
                      'engine_manifest_sha256': s5.manifest_hash(self.engine),
                      'occ_contract_sha256': s5.manifest_hash(s5.OCC_CONTRACT),
                      'proof_root': '/var/lib/woowbk-nextcloud-s5-0123456789abcdef',
                      'not_before_utc': start.isoformat().replace('+00:00', 'Z'),
                      'expires_utc': end.isoformat().replace('+00:00', 'Z'),
                      'reserve_bytes': s5.RESERVE, 'memory_cap_bytes': s5.DEVICE_CAP, 'images': dict(s5.IMAGES),
                      'component_caps': dict(s5.CAPS), 'disk_caps': dict(s5.DISK_CAPS),
                      'minimum_start_free_bytes': s5.START_FREE, 'additional_disk_cap_bytes': s5.OWNED_CAP,
                      'fixture_cap_bytes': s5.FIXTURE_CAP, 'cleanup_grace_seconds': s5.CLEANUP_GRACE,
                      'target_wake': False, 'target_source_install': False, 'target_restore': False,
                      'image_operations': []}
        from focus_nextcloud_r6_plan import lease_check
        self.lease_check = lambda lease, commit, phase: lease_check(
            lease, commit, phase, now=datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc))

    def admit(self, lease, now=None):
        return s5.admit_lease(lease, 'c'*40, self.code, self.engine, lease_check=self.lease_check,
                              now=self.now if now is None else now)

    def test_exact_lease_is_admitted_and_every_bound_field_matters(self):
        self.assertEqual(self.admit(self.lease), self.now+45*60)
        for field, value in (('builder_sha256', '0'*64), ('engine_commit', '0'*40), ('engine_manifest_sha256', '0'*64),
                             ('occ_contract_sha256', '0'*64), ('disk_caps', dict(s5.DISK_CAPS, data=32*s5.MIB)),
                             ('component_caps', {}), ('images', {}), ('minimum_start_free_bytes', 1),
                             ('additional_disk_cap_bytes', 1), ('fixture_cap_bytes', 1), ('cleanup_grace_seconds', 1),
                             ('target_wake', True), ('target_restore', None), ('image_operations', ['pull'])):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'lease-builder-contract'):
                    self.admit(dict(self.lease, **{field: value}))
        with self.assertRaisesRegex(ValueError, 'lease-root'):
            self.admit(dict(self.lease, proof_root='/var/lib/woowbk-nextcloud-s5-../x'))
        with self.assertRaisesRegex(ValueError, 'lease-headroom'):
            self.admit(self.lease, now=self.now+16*60)

    def test_template_binds_this_checkout(self):
        template = s5.lease_template(REPO)
        for field in ('builder_sha256', 'engine_commit', 'occ_contract_sha256', 'images', 'component_caps', 'disk_caps',
                      'minimum_start_free_bytes', 'additional_disk_cap_bytes', 'fixture_cap_bytes',
                      'cleanup_grace_seconds', 'target_wake', 'target_source_install', 'target_restore',
                      'image_operations', 'reserve_bytes', 'memory_cap_bytes', 'phases', 'lane', 'device'):
            self.assertEqual(template[field], self.lease[field], field)
        self.assertEqual(template['engine_manifest_sha256'], s5.manifest_hash(s5.engine_manifest(REPO)))
        self.assertTrue(template['proof_root'].startswith('REQUIRES_'))

    def test_blocking_lock_then_the_lease_must_still_have_thirty_minutes(self):
        """Gap 4: flock waits (LOCK_EX without LOCK_NB); after the wait the headroom is checked before any device step."""
        flags = []; deadline = self.admit(self.lease)
        def flock(fd, flag): flags.append(flag); self.now += 20*60   # someone else held the lock for 20 minutes
        with tempfile.TemporaryDirectory() as tmp, patch.object(s5, 'LOCK', str(Path(tmp)/'lock')), \
                patch.object(s5.fcntl, 'flock', flock), patch.dict(os.environ, {'HEAVY_FREE': str(Path(tmp)/'lock')}), \
                patch.object(s5, 'checkout', lambda repo: ('c'*40, True)), \
                patch.object(s5, 'engine_manifest', lambda repo: self.engine), \
                patch.object(s5.time, 'time', lambda: self.now), \
                patch.object(s5, 'run_locked', side_effect=AssertionError('no device step after a late lock')):
            lease = Path(tmp)/'lease.json'; lease.write_text(json.dumps(self.lease))
            import focus_nextcloud_r6_plan as plan
            with patch.object(plan, 'lease_check', self.lease_check):
                with self.assertRaisesRegex(ValueError, 'lease-headroom-after-lock'):
                    s5.main(['--run', '--lease', str(lease)])
        self.assertEqual(flags, [s5.fcntl.LOCK_EX])
        self.assertEqual(deadline, self.now-20*60+45*60)

    def test_lock_wait_shorter_than_the_slack_proceeds(self):
        deadline = self.admit(self.lease)
        s5.locked_admission(self.lease, 'c'*40, deadline, lease_check=self.lease_check, now=self.now+10*60)


class OccContractTests(unittest.TestCase):
    """Gap 3: a difference from the reviewed occ help stops the run."""

    def native(self, replies):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        work = Path(tmp.name)/'owned'; work.mkdir()
        native = s5.Native({'proof_root': str(work.parent), 'deadline': 4e9, 'nonce': '0'*16, 'action': 'unit',
                            'start_free': 30*s5.GIB})
        native.work = work; calls = []
        def call(argv, data=None, timeout=180, allowed=(0,), cleanup=False):
            calls.append((list(argv), data)); key = tuple(argv[7:]) if argv[:2] == ['podman', 'exec'] else tuple(argv)
            code, out = replies(key)
            if code not in allowed: raise ValueError('fixed-s5-native-command-refused')
            return code, out
        native.call = call
        return native, calls

    def test_reviewed_help_of_every_command_passes(self):
        native, calls = self.native(lambda key: (0, json.dumps(symfony_help(key[2])).encode()))
        for command in s5.OCC_CONTRACT:
            native.occ_help(command)
        self.assertEqual(set(native.help_hashes), set(s5.OCC_CONTRACT))
        self.assertTrue(all(argv[:6] == ['podman', 'exec', '-u', 'www-data', 'woowbk-s5-'+'0'*16+'-nc', 'php']
                            and data is None for argv, data in calls))

    def test_any_semantic_difference_stops_for_review_and_keeps_what_was_found(self):
        faults = {
            'extra-required-argument': lambda r: r['arguments'].update(force=[True, False]),
            'option-now-requires-a-value': lambda r: r['options']['details'].__setitem__(2, True),
            'new-option': lambda r: r['options'].update(yes=['-y', False, False, False, False]),
            'missing-output-option': lambda r: r['options'].pop('output'),
            'other-default': lambda r: r['options']['output'].__setitem__(4, 'json'),
            'other-description': lambda r: r.update(description='Get a config value'),
        }
        for name, fault in faults.items():
            with self.subTest(fault=name):
                row = copy.deepcopy(s5.OCC_CONTRACT['config:app:get']); fault(row)
                native, _ = self.native(lambda key, row=row: (0, json.dumps(symfony_help('config:app:get', row)).encode()))
                with self.assertRaisesRegex(ValueError, 'occ-help-differs-stop-for-review'):
                    native.occ_help('config:app:get')
                found = json.loads((native.work/'occ-help-differs-config-app-get.private.json').read_text())
                self.assertEqual(found['expected']['name'], 'config:app:get')
        native, _ = self.native(lambda key: (0, b'Nextcloud is not installed\n'))
        with self.assertRaisesRegex(ValueError, 'occ-help-unreadable'):
            native.occ_help('status')

    def test_contract_carries_the_verified_v35_facts(self):
        c = s5.OCC_CONTRACT
        self.assertEqual(c['encryption:enable-master-key']['description'],
                         'Enable the master key. Only available for fresh installations with no existing encrypted '
                         'data! There is also no way to disable it again.')
        self.assertEqual(c['encryption:enable-master-key']['options'], {})
        self.assertEqual(c['status']['options']['exit-code'], ['-e', False, False, False, False])
        self.assertEqual(c['app:enable']['arguments'], {'app-id': [True, True]})
        self.assertEqual(s5.OCC_AFTER_APP, ('encryption:enable-master-key',))
        self.assertEqual(s5.contract()['occ_contract_sha256'], s5.manifest_hash(c))


class EncryptionFlowTests(unittest.TestCase):
    """Gap 2b: native master-key procedure; masterKeyId only after the first encrypted write."""

    def native(self, overrides=None):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        work = Path(tmp.name)/'owned'; work.mkdir()
        native = s5.Native({'proof_root': str(work.parent), 'deadline': 4e9, 'nonce': '0'*16, 'action': 'unit',
                            'start_free': 30*s5.GIB})
        native.work = work; self.calls = calls = []
        state = {'enabled': False, 'app': False}
        replies = {
            ('app:enable', 'encryption'): (0, b'encryption 2.21.0 enabled\n'),
            ('app:list', '--output=json'): None,
            ('encryption:list-modules', '--output=json'):
                (0, b'{"OC_DEFAULT_MODULE":{"displayName":"Default encryption module","default":true}}\n'),
            ('encryption:set-default-module', 'OC_DEFAULT_MODULE'):
                (0, b'"OC_DEFAULT_MODULE"" is already the default module\n'),
            ('config:app:get', 'encryption', 'useMasterKey'): (1, b''),
            ('encryption:enable',): (0, b'Encryption enabled\n\nDefault module: OC_DEFAULT_MODULE\n'),
            ('encryption:enable-master-key',): (0, b'Master key already enabled\n'),
            ('config:app:get', 'core', 'encryption_enabled', '--details', '--output=json'):
                (0, b'{"app":"core","key":"encryption_enabled","value":"1","type":"boolean"}\n'),
            ('config:app:get', 'encryption', 'masterKeyId'): (0, (MASTER+'\n').encode()),
            ('list', '--raw'): None, ('encryption:status', '--output=json'): None,
        }
        replies.update(overrides or {})
        def call(argv, data=None, timeout=180, allowed=(0,), cleanup=False):
            key = tuple(argv[7:]); calls.append((key, data))
            if key[:2] == ('help', '--format=json'):
                code, out = 0, json.dumps(symfony_help(key[2])).encode()
            elif replies[key] is not None:
                code, out = replies[key]
            elif key == ('list', '--raw'):
                names = list(s5.OCC_BEFORE_APP)+(list(s5.OCC_AFTER_APP) if state['app'] else [])
                code, out = 0, ''.join(n+'   text\n' for n in names).encode()
            elif key == ('app:list', '--output=json'):
                code, out = 0, json.dumps({'enabled': {'encryption': '2.21.0'}, 'disabled': {}} if state['app']
                                          else {'enabled': {}, 'disabled': {'encryption': '2.21.0'}}).encode()
            else:
                code, out = 0, json.dumps({'enabled': state['enabled'],
                                           'defaultModule': 'OC_DEFAULT_MODULE' if state['app'] else ''}).encode()
            if key == ('app:enable', 'encryption'): state['app'] = True
            if key == ('encryption:enable',): state['enabled'] = True
            if code not in allowed: raise ValueError('fixed-s5-native-command-refused')
            return code, out
        native.call = call
        return native

    def test_native_procedure_in_order_without_reading_the_master_key_id(self):
        native = self.native()
        native.enable_encryption()
        keys = [k for k, _ in self.calls if k[:1] != ('help',)]
        self.assertNotIn(('config:app:get', 'encryption', 'masterKeyId'), keys)
        self.assertLess(keys.index(('encryption:set-default-module', 'OC_DEFAULT_MODULE')),
                        keys.index(('encryption:enable',)))
        self.assertLess(keys.index(('encryption:enable',)), keys.index(('encryption:enable-master-key',)))
        self.assertTrue(all(data is None for _, data in self.calls))          # never a typed "yes"
        self.assertEqual(native.facts['use_master_key'], 'unset-default-true')
        self.assertEqual(native.facts['core_encryption_enabled'], {'value': '1', 'type': 'boolean'})
        self.assertEqual(native.master_key_id(), MASTER)

    def test_other_native_outputs_stop(self):
        cases = {
            'master-key-procedure-differs-stop-for-review': {('encryption:enable-master-key',): (1, b'aborted.\n')},
            'master-key-not-the-default': {('config:app:get', 'encryption', 'useMasterKey'): (0, b'0\n')},
            'encryption-enable-output': {('encryption:enable',): (1, b'No default module is set\n')},
            'set-default-module-output': {('encryption:set-default-module', 'OC_DEFAULT_MODULE'):
                                          (0, b'Set default module to "OTHER"\n')},
            'app-enable-output': {('app:enable', 'encryption'): (0, b'encryption already enabled\n')},
        }
        for reason, override in cases.items():
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason+'|native-command-refused'):
                    self.native(override).enable_encryption()
        native = self.native({('config:app:get', 'encryption', 'useMasterKey'): (0, b'true\n')})
        native.enable_encryption(); self.assertEqual(native.facts['use_master_key'], 'true')
        native = self.native({('encryption:set-default-module', 'OC_DEFAULT_MODULE'):
                              (0, b'Set default module to "OC_DEFAULT_MODULE"\n')})
        native.enable_encryption()
        for value in (b'master_\n', b'master_0123abcz\n', b'recoveryKey_0123abcd\n'):
            with self.subTest(value=value):
                native = self.native({('config:app:get', 'encryption', 'masterKeyId'): (0, value)})
                with self.assertRaisesRegex(ValueError, 'master-key-id'): native.master_key_id()


class WatchTests(unittest.TestCase):
    """Gap 4: a breach stops at once; failed or slow probes only after three in a row."""

    def native(self, sizes):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        native = s5.Native({'proof_root': tmp.name, 'deadline': 4e9, 'nonce': '0'*16, 'action': 'build',
                            'start_free': 30*s5.GIB})
        native.basic_probe = lambda: (30*s5.GIB, 900*s5.MIB)
        replies = iter(sizes)
        def owned():
            reply = next(replies)
            if isinstance(reply, BaseException): raise reply
            return reply
        native.owned_sizes = owned
        return native

    def sample(self, native):
        native.next_basic = native.next_disk = 0.0
        native.check()

    def test_slow_or_failed_du_stops_only_after_three_in_a_row(self):
        slow = subprocess.TimeoutExpired(['du'], 15)
        native = self.native([slow, slow, {'owned': 1}, slow, ValueError('fixed-s5-du-probe-unreadable'), slow])
        for _ in range(5):
            self.sample(native)
        self.assertEqual(native.probe_failures, 4)
        with self.assertRaisesRegex(ValueError, 'watch-disk-probe-failed-3-in-a-row-TimeoutExpired'):
            self.sample(native)

    def test_breaches_stop_at_once(self):
        for sizes, reason in (({'owned': s5.OWNED_CAP+1}, 'owned-disk-cap'),
                              ({'owned': 1, 'data': s5.DISK_CAPS['data']+1}, 'component-disk-cap-data'),
                              ({'owned': 1, 'html': s5.DISK_CAPS['html']+1}, 'component-disk-cap-html')):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, 'watch-'+reason):
                    self.sample(self.native([sizes]))
        for probe, reason in (((s5.FLOOR-1, 1), 'reserve'), ((30*s5.GIB, s5.MEMORY_WATCH+1), 'memory'),
                              ((30*s5.GIB-s5.OWNED_CAP-1, 1), 'combined-disk')):
            with self.subTest(reason=reason):
                native = self.native([{'owned': 1}]); native.basic_probe = lambda probe=probe: probe
                with self.assertRaisesRegex(ValueError, 'watch-'+reason): self.sample(native)
        native = self.native([{'owned': 1}]); native.deadline = 0
        with self.assertRaisesRegex(ValueError, 'watch-expired'): self.sample(native)

    def test_failed_basic_probes_also_need_three_in_a_row(self):
        native = self.native([{'owned': 1}]*5)
        def broken(): raise OSError(5, 'unreadable')
        native.basic_probe = broken
        self.sample(native); self.sample(native)
        with self.assertRaisesRegex(ValueError, 'watch-basic-probe-failed-3-in-a-row-OSError'): self.sample(native)

    def test_du_reply_is_parsed_strictly(self):
        native = self.native([])
        paths = [native.work/'html', native.work/'data']
        with patch.object(s5, 'bounded', return_value=(0, ('10\t%s\n20\t%s\n' % tuple(paths)).encode())):
            self.assertEqual(native.du(paths, apparent=True), [10, 20])
        for code, out in ((1, ('10\t%s\n20\t%s\n' % tuple(paths)).encode()), (0, b'10\t/elsewhere\n20\tx\n'),
                          (0, ('10\t%s\n' % paths[0]).encode())):
            with patch.object(s5, 'bounded', return_value=(code, out)):
                with self.assertRaisesRegex(ValueError, 'du-probe-unreadable'): native.du(paths)


class CipherClassificationTests(Base):
    """Gap 2c and 7: share keys only (no fileKey), the native header, a plaintext file written before encryption."""

    def setUp(self):
        super().setUp()
        known = s5.plaintexts()
        self.before = {n: {'bytes': len(v), 'sha256': s5.sha(v)} for n, v in known['before'].items()}
        self.encrypted = {n: {'bytes': len(v), 'sha256': s5.sha(v)} for n, v in known['encrypted'].items()}
        for name, value in known['before'].items():
            self.write('data/s5owner/files/'+name, value)
        self.write('data/s5owner/files/Readme.md', b'skeleton file copied by the installer\n')
        for name, value in known['encrypted'].items():   # structural stand-in: header + more bytes than the plaintext
            self.write('data/s5owner/files/'+name, header_block()+hashlib.sha512(value).digest()*(len(value)//64+2))
            self.write('data/s5owner/files_encryption/keys/files/'+name+'/OC_DEFAULT_MODULE/'+MASTER+'.shareKey',
                       key_bytes(name))
        for suffix in ('publicKey', 'privateKey'):
            self.write('data/files_encryption/OC_DEFAULT_MODULE/'+MASTER+'.'+suffix, key_bytes(suffix))
            self.write('data/files_encryption/OC_DEFAULT_MODULE/pubShare_89abcdef.'+suffix, key_bytes('p'+suffix))
        self.write('data/.ncdata', b'# Nextcloud data directory\n')
        self.write('data/appdata_ocs5/js/core.js', b'not a user file')

    def classify(self, master=MASTER):
        return s5.classify_source(self.work/'data', self.before, self.encrypted, master)

    def test_master_key_mode_source_is_classified_and_bound(self):
        result = self.classify()
        self.assertEqual(result['encrypted'], ['s5owner/files/s5-binary.bin', 's5owner/files/s5-utf8.txt'])
        self.assertEqual(result['plaintext'], ['s5owner/files/Readme.md', 's5owner/files/s5-before-encryption.txt'])
        self.assertEqual(result['public_share_keys'], 2)
        self.assertEqual(len(result['keys']), 6)
        self.assertEqual(set(result['cipher_and_keys']),
                         set(result['keys']) | set(result['encrypted']) | {'s5owner/files/s5-before-encryption.txt'})
        text = json.dumps(result)
        for raw in (key_bytes('publicKey'), key_bytes('s5-binary.bin')):
            self.assertNotIn(raw.decode(), text)                     # hashes only, never key bytes

    def test_departures_from_the_verified_layout_refuse(self):
        share = 'data/s5owner/files_encryption/keys/files/s5-binary.bin/OC_DEFAULT_MODULE/'
        faults = {
            'legacy-file-key': ('key-storage-not-master-key-mode', lambda: self.write(share+'fileKey', key_bytes('f'))),
            'user-share-key': ('key-storage-not-master-key-mode',
                               lambda: self.write(share+'s5owner.shareKey', key_bytes('u'))),
            'missing-share-key': ('key-storage-not-master-key-mode',
                                  lambda: (self.work/(share+MASTER+'.shareKey')).unlink()),
            'user-key-pair': ('key-storage-not-master-key-mode', lambda: self.write(
                'data/s5owner/files_encryption/OC_DEFAULT_MODULE/s5owner.publicKey', key_bytes('k'))),
            'recovery-key': ('key-storage-not-master-key-mode', lambda: self.write(
                'data/files_encryption/OC_DEFAULT_MODULE/recoveryKey_01234567.publicKey', key_bytes('r'))),
            'key-not-native': ('key-file-not-native-layout', lambda: self.write(share+MASTER+'.shareKey', b'-----BEGIN')),
            'other-cipher': ('native-header-not-the-installed-module', lambda: self.write(
                'data/s5owner/files/s5-utf8.txt', header_block(dict(s5.HEADER, cipher='AES-128-CFB'))+b'x'*64)),
            'bad-padding': ('native-header-layout', lambda: self.write(
                'data/s5owner/files/s5-utf8.txt', header_block(pad=b'=')+b'x'*64)),
            'short-header': ('native-header-layout',
                             lambda: self.write('data/s5owner/files/s5-utf8.txt', b'HBEGIN:x:HEND')),
            'plaintext-encrypted': ('plaintext-before-encryption', lambda: self.write(
                'data/s5owner/files/s5-before-encryption.txt', header_block()+b'x'*64)),
            'plaintext-changed': ('plaintext-before-encryption', lambda: self.write(
                'data/s5owner/files/s5-before-encryption.txt', b'other bytes')),
            'skeleton-encrypted': ('unexpected-encrypted-files', lambda: self.write(
                'data/s5owner/files/Readme.md', header_block()+b'x'*64)),
            'ciphertext-is-plaintext': ('native-ciphertext', lambda: self.write(
                'data/s5owner/files/s5-binary.bin', s5.plaintexts()['encrypted']['s5-binary.bin'])),
        }
        for name, (reason, fault) in faults.items():
            with self.subTest(fault=name):
                saved = {p: p.read_bytes() for p in (self.work/'data').rglob('*') if p.is_file()}
                fault()
                try:
                    with self.assertRaisesRegex(ValueError, reason): self.classify()
                finally:
                    for p in [p for p in (self.work/'data').rglob('*') if p.is_file() and p not in saved]: p.unlink()
                    for p, raw in saved.items(): p.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'master-key-id'): self.classify('master_x')

    def test_data_cap_allows_the_installers_skeleton(self):
        self.assertGreaterEqual(s5.DISK_CAPS['data'], 35_234_605*2)   # example-files stable35, with margin
        self.write('data/s5owner/files/Templates/big.odp', b'0'*(40*s5.MIB))
        self.classify()


class OwnedCleanupTests(Base):
    """Gap 5: diagnostics first, then the containers, then ONLY this run's own leaves."""

    def populate(self, records=True):
        for name in ('html/config/config.php', 'pg/PG_VERSION', 'data/s5owner/files/a.bin', 'artifact/share.tar'):
            self.write(name, b'x')
        self.write('credentials.private.json', b'{"password":"generated"}')
        records = ('failure.private.json', 'fixed-result.json') if records else ()
        for name in ('command-0001.json', 'nc-identity.json')+records:
            self.write(name, b'{}')

    def test_discard_removes_exactly_the_owned_leaves_and_keeps_records(self):
        self.populate()
        removed = s5.discard_owned(self.work, s5.OWNED_LEAVES)
        self.assertEqual(removed, list(s5.OWNED_LEAVES))
        self.assertEqual(sorted(p.name for p in self.work.iterdir()),
                         ['command-0001.json', 'failure.private.json', 'fixed-result.json', 'nc-identity.json'])
        self.assertEqual(s5.discard_owned(self.work, s5.OWNED_LEAVES), [])

    def test_discard_never_follows_links_or_takes_foreign_names(self):
        outside = Path(self.tmp.name)/'outside'; outside.mkdir(); (outside/'keep').write_bytes(b'k')
        (self.work/'data').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'discard-owned-file'):
            s5.discard_owned(self.work, ('data',))
        self.assertEqual((outside/'keep').read_bytes(), b'k')
        (self.work/'data').unlink(); (self.work/'html').mkdir(); (self.work/'html/link').symlink_to(outside)
        self.assertEqual(s5.discard_owned(self.work, ('html',)), ['html'])
        self.assertEqual((outside/'keep').read_bytes(), b'k')
        for name in ('command-0001.json', '..', 'owned', '/etc'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'discard-name-not-owned'):
                    s5.discard_owned(self.work, (name,))

    def supervisor(self, fail_at=None, cleanup_fails=False):
        order = []; work = self.work; test = self
        class FakeNative:
            stage = 'unit'; watch_failure = None; probe_failures = 0; lowest = 1; peak = 1
            def execute(self):
                order.append('execute'); test.populate(records=False)
                if fail_at: raise ValueError('fixed-s5-'+fail_at)
                return {'status': 'passed'}
            def save_logs(self):
                order.append('save-logs:failure-record-present=%s' % (work/'failure.private.json').exists())
            def cleanup(self):
                order.append('cleanup')
                if cleanup_fails: raise ValueError('fixed-s5-cleanup-container-ownership')
            def unshare(self, action, cleanup=False, **extra):
                order.append('unshare:%s:%s' % (action, cleanup))
                return {'status': 'owned-discarded', 'removed': s5.discard_owned(work, s5.OWNED_LEAVES)}
        return FakeNative(), order

    def test_failed_build_discards_after_diagnostics_and_containers(self):
        native, order = self.supervisor(fail_at='webdav-put')
        with patch('builtins.print'):
            failure = s5.supervise(native, self.work)
        self.assertIsNotNone(failure)
        self.assertEqual(order, ['execute', 'save-logs:failure-record-present=True', 'cleanup', 'unshare:discard:True'])
        self.assertFalse(any((self.work/n).exists() for n in s5.OWNED_LEAVES))
        fixed = json.loads((self.work/'fixed-result.json').read_text())
        self.assertEqual(fixed['status'], 'failed'); self.assertEqual(fixed['owned_source_discarded']['removed'][0], 'html')

    def test_nothing_is_discarded_while_owned_containers_may_remain_or_on_success(self):
        native, order = self.supervisor(fail_at='webdav-put', cleanup_fails=True)
        with patch('builtins.print'):
            s5.supervise(native, self.work)
        self.assertNotIn('unshare:discard:True', order)
        self.assertTrue((self.work/'credentials.private.json').exists())
        self.assertTrue((self.work/'cleanup-failure.private.json').exists())
        for leaf in s5.OWNED_LEAVES:
            s5.discard_owned(self.work, (leaf,))
        for name in ('failure.private.json', 'fixed-result.json', 'cleanup-failure.private.json'):
            (self.work/name).unlink()
        native, order = self.supervisor()
        with patch('builtins.print'):
            self.assertIsNone(s5.supervise(native, self.work))
        self.assertEqual(order, ['execute', 'cleanup'])

    def test_cleanup_actions_have_the_grace_and_others_do_not(self):
        source = Path(s5.__file__).read_text(); root = '/var/lib/woowbk-nextcloud-s5-'+'0'*16
        q = {'proof_root': root, 'nonce': '0'*16, 'builder_source': source, 'builder_sha256': s5.sha(source.encode()),
             'deadline': 1000.0}
        umask = os.umask(0o022); os.umask(umask); self.addCleanup(os.umask, umask)   # internal_main sets 0o077
        with patch.object(s5.time, 'time', return_value=1300.0):
            for action in ('build', 'prepare', 'cipher', 'package'):
                with self.subTest(action=action):
                    with self.assertRaisesRegex(ValueError, 'native-expired'): s5.internal_main(dict(q, action=action))
            for action in ('discard', 'remove-source'):     # within the grace: reaches the work-dir check
                with self.subTest(action=action):
                    with self.assertRaisesRegex(ValueError, 'owned-work'): s5.internal_main(dict(q, action=action))


class OwnershipTests(Base):
    """Gap 2a: www-data owns the owned html and data dirs before the first start; no :U."""

    def test_prepare_gives_only_empty_owned_dirs_mode_0750(self):
        for name in ('html', 'pg', 'data'): (self.work/name).mkdir(mode=0o700)
        result = s5.prepare_owned(self.work, os.getuid(), os.getgid(), owner=os.getuid())
        self.assertEqual(result['www_data'], [os.getuid(), os.getgid()])
        self.assertEqual({n: (self.work/n).stat().st_mode & 0o777 for n in ('html', 'pg', 'data')},
                         {'html': 0o750, 'pg': 0o700, 'data': 0o750})
        self.write('data/.ncdata', b'x')
        with self.assertRaisesRegex(ValueError, 'prepare-owned-empty-dir'):
            s5.prepare_owned(self.work, os.getuid(), os.getgid(), owner=os.getuid())
        for uid in (0, 70000, '33'):
            with self.assertRaisesRegex(ValueError, 'prepare-ids'):
                s5.prepare_owned(self.work, uid, 33, owner=os.getuid())

    def test_source_containers_never_use_U_and_mount_only_owned_dirs(self):
        native = s5.Native({'proof_root': '/var/lib/woowbk-nextcloud-s5-'+'0'*16, 'deadline': 4e9, 'nonce': '0'*16,
                            'action': 'unit', 'start_free': 30*s5.GIB})
        work = '/var/lib/woowbk-nextcloud-s5-'+'0'*16+'/owned'
        args = {role: native.source_args(role) for role in ('pg', 'redis', 'nc')}
        volumes = {role: [a[i+1] for i, x in enumerate(a) if x == '-v'] for role, a in args.items()}
        self.assertEqual(volumes, {'pg': [work+'/pg:/var/lib/postgresql/data'], 'redis': [],
                                   'nc': [work+'/html:/var/www/html', work+'/data:/share/nextcloud']})
        self.assertFalse(any(':U' in a or a.endswith(',U') for row in args.values() for a in row))
        self.assertIn('--env=NEXTCLOUD_DATA_DIR=/share/nextcloud', args['nc'])
        self.assertFalse(any('PASSWORD=' in a for row in args.values() for a in row))   # secrets only

    def test_cpu_limit_only_when_the_controller_is_delegated(self):
        native = s5.Native({'proof_root': str(self.work.parent), 'deadline': 4e9, 'nonce': '0'*16, 'action': 'unit',
                            'start_free': 30*s5.GIB})
        controllers = self.work/'cgroup.controllers'
        for text, expected in (('cpuset cpu io memory pids\n', ['--cpus=1']), ('cpuset io memory pids\n', [])):
            with self.subTest(text=text):
                controllers.write_text(text)
                self.assertEqual(native.cpu_limit(str(controllers)), expected)
        self.assertEqual(native.cpu_limit(str(self.work/'absent-{uid}')), [])
        self.assertIs(native.facts['cpu_controller_delegated'], False)
        self.assertEqual(s5.CONTROLLERS, tempctr.CONTROLLERS)   # the product's own rule and path


class RenderedProgramTests(unittest.TestCase):
    def test_rendered_native_program_compiles_fits_argv_and_does_not_run_host_cli(self):
        source = Path(s5.__file__).read_text()
        rendered = s5.native_program(source)
        compile(rendered, 'actual-rendered-s5-program', 'exec')
        self.assertLess(len(rendered.encode()), 120*1024)   # one argv string (MAX_ARG_STRLEN is 128 KiB)
        # The actual module body is library-only in the device program. No I/O.
        with patch.object(sys, 'argv', ['-c', '--run']), patch.object(s5.subprocess, 'Popen', side_effect=AssertionError):
            namespace = {'__name__': 's5_native_scope'}
            exec(compile(source, 'actual-s5-library', 'exec'), namespace)
        self.assertEqual(namespace['IMAGES'], s5.IMAGES)

    def test_script_runs_isolated_like_the_launch_command(self):
        """python3 -B -I (the heavy.sh command) puts no script directory on the path; the offline modes only read git."""
        out = subprocess.run([sys.executable, '-B', '-I', str(Path(s5.__file__)), '--lease-template'], cwd=REPO,
                             capture_output=True, timeout=120, check=True)
        template = json.loads(out.stdout)
        self.assertEqual(template['engine_commit'], s5.ENGINE_COMMIT)
        self.assertEqual(template['builder_sha256'], s5.sha(Path(s5.__file__).read_bytes()))
        self.assertIn("sys.path.insert(0, str(here.parent))", Path(s5.__file__).read_text())

    def test_offline_entry_points_print_without_device_access(self):
        with patch.object(s5.subprocess, 'Popen', side_effect=AssertionError('no process')), \
                patch('builtins.print') as shown:
            self.assertEqual(s5.main([]), 0)
        self.assertEqual(json.loads(shown.call_args[0][0])['engine_commit'], s5.ENGINE_COMMIT)


if __name__ == '__main__': unittest.main()
