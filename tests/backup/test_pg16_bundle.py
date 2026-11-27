"""OD-23 release sidecar tests. Synthetic image archives only; never invokes Podman or pulls images."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest import mock

from woowbackup import ha_odoo, pg16_bundle as bundle, podman
from woowbackup.errors import BackupError

SPEC = importlib.util.spec_from_file_location('package_odoo_pg16', Path(__file__).resolve().parents[2]
                                           / 'scripts/package_odoo_pg16.py')
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)
packager.bundle = bundle


def image_archive(path, *, arch='amd64', tag=bundle.TAG, extra=(), multi=False, config_name=None,
                  layer=b'layer payload', compressed=False, second_layer=None, reverse_layers=False, rootfs=None):
    entries = [('layer/layer.tar', gzip.compress(layer) if compressed else layer)]
    diff_ids = ['sha256:' + hashlib.sha256(b'layer payload').hexdigest()]
    if second_layer is not None:
        entries.append(('second/layer.tar', second_layer))
        diff_ids.append('sha256:' + hashlib.sha256(second_layer).hexdigest())
    config = json.dumps({'architecture': arch, 'os': 'linux',
                         'rootfs': {'type': 'layers', 'diff_ids': diff_ids} if rootfs is None else rootfs}).encode()
    image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
    name = config_name or image_id[7:] + '.json'
    manifest = [{'Config': name, 'RepoTags': [tag], 'Layers': [n for n, _data in entries][::(-1 if reverse_layers else 1)]}]
    if multi:
        manifest *= 2
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for member, data in [(name, config), *entries,
                             ('manifest.json', json.dumps(manifest).encode()), *extra]:
            info = tarfile.TarInfo(member) if isinstance(member, str) else member
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return image_id


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.archive = self.base / 'export.tar'
        self.image_id = image_archive(self.archive)
        self.output = self.base / 'release'
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o755)
        # Test fixtures emulate root ownership below a private trust anchor; production always checks to /.
        self.enterContext(mock.patch.object(bundle, 'ROOT_UID', os.getuid()))
        self.enterContext(mock.patch.object(bundle, 'TRUST_ANCHOR', self.root))
        self.enterContext(mock.patch.object(bundle, 'INSTALLED_ROOT', self.root / bundle.INSTALL_REL))
        self.enterContext(mock.patch.object(bundle.platform, 'machine', return_value='x86_64'))

    def package(self):
        self.report = packager.package(self.archive, 'amd64', self.image_id, self.output)
        return self.report['manifest_sha256']

    def install(self):
        pin = self.package()
        self.installed = bundle.install_bundle(self.output, pin, self.root)
        return pin

    def repin(self, **updates):
        path = self.output / 'manifest.json'
        record = json.loads(path.read_bytes())
        record.update(updates)
        path.write_bytes(json.dumps(record).encode())
        return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseTests(BundleCase):
    def test_package_install_and_verify_same_generation_without_loading(self):
        pin = self.install()
        generation = Path(self.installed['path'])
        self.assertEqual(bundle.install_bundle(self.output, pin, self.root), self.installed)
        with bundle.installed_bundle() as (record, raw, stream):
            self.assertEqual(record['ref'], ha_odoo.PG16_PINNED)
            self.assertEqual(record['image_id'], self.image_id)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
            self.assertEqual(stream.tell(), 0)
            self.assertGreater(stream.fileno(), 0)
        self.assertEqual((generation.parent / 'active.sha256').read_text().strip(), pin)
        for name in ('manifest.json', bundle.ARCHIVE):
            self.assertEqual((generation / name).stat().st_mode & 0o777, 0o644)

    def test_missing_bundle_is_optional(self):
        with bundle.installed_bundle() as value:
            self.assertIsNone(value)
        self.root.chmod(0o775)
        with bundle.installed_bundle() as value:
            self.assertIsNone(value)

    def test_arm64_artifact_matches_config_and_not_amd64(self):
        image_id = image_archive(self.archive, arch='arm64')
        report = packager.package(self.archive, 'arm64', image_id, self.output)
        with bundle.open_bundle(self.output, report['manifest_sha256'], arch='arm64'):
            pass
        with self.assertRaises(bundle.BundleError):
            with bundle.open_bundle(self.output, report['manifest_sha256'], arch='amd64'):
                pass

    def test_manifest_needs_independent_sha_and_exact_contract(self):
        pin = self.package()
        for bad in (None, '', 'A' * 64, '0' * 64):
            with self.subTest(pin=bad), self.assertRaises(bundle.BundleError):
                with bundle.open_bundle(self.output, bad):
                    pass
        raw = (self.output / 'manifest.json').read_bytes()
        for updates in ({'ref': 'docker.io/library/postgres:latest'}, {'archive': '../elsewhere.tar'},
                        {'archive_size': True}, {'archive_size': bundle.MAX_ARCHIVE + 1},
                        {'architecture': 'arm/v7'}, {'schema': True}, {'unexpected': True}):
            (self.output / 'manifest.json').write_bytes(raw)
            with self.subTest(updates=updates), self.assertRaises(bundle.BundleError):
                with bundle.open_bundle(self.output, self.repin(**updates)):
                    pass
        self.assertEqual(len(pin), 64)

    def test_duplicate_and_oversized_manifest_rejected(self):
        self.package()
        for raw in (b'{"schema":1,"schema":1}', b'x' * (bundle.MAX_JSON + 1)):
            (self.output / 'manifest.json').write_bytes(raw)
            with self.assertRaises(bundle.BundleError):
                with bundle.open_bundle(self.output, hashlib.sha256(raw).hexdigest()):
                    pass

    def test_archive_hash_and_size_are_both_verified(self):
        pin = self.package()
        target = self.output / bundle.ARCHIVE
        raw = target.read_bytes()
        target.write_bytes(b'x' + raw[1:])
        with self.assertRaisesRegex(bundle.BundleError, 'SHA256'):
            with bundle.open_bundle(self.output, pin):
                pass
        target.write_bytes(raw[:-1])
        with self.assertRaisesRegex(bundle.BundleError, 'size'):
            with bundle.open_bundle(self.output, pin):
                pass

    def test_correct_config_with_wrong_exported_layer_is_rejected(self):
        image_archive(self.archive, layer=b'altered rootfs content')
        with self.assertRaisesRegex(bundle.BundleError, 'rootfs digest'):
            packager.package(self.archive, 'amd64', self.image_id, self.output)

    def test_gzip_export_uses_the_uncompressed_config_diff_id(self):
        image_archive(self.archive, compressed=True)
        self.package()
        with bundle.open_bundle(self.output, self.report['manifest_sha256']):
            pass

    def test_expanded_layer_budget_is_enforced(self):
        image_archive(self.archive, compressed=True)
        with self.archive.open('rb') as stream, mock.patch.object(bundle, 'MAX_ARCHIVE', 2):
            with self.assertRaisesRegex(bundle.BundleError, 'Expanded'):
                bundle.validate_archive(stream, 'amd64', self.image_id)

    def test_rootfs_diff_ids_must_exist_have_correct_count_and_valid_digests(self):
        for rootfs in ({}, {'type': 'layers'}, {'type': 'layers', 'diff_ids': []},
                       {'type': 'layers', 'diff_ids': ['sha256:not-hex']},
                       {'type': 'layers', 'diff_ids': ['sha256:' + '0' * 64]},
                       {'type': 'layers', 'diff_ids': ['sha256:' + '0' * 64] * 2}):
            image_id = image_archive(self.archive, rootfs=rootfs)
            with self.subTest(rootfs=rootfs), self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', image_id, self.output)

    def test_each_layer_hash_must_match_config_order(self):
        image_id = image_archive(self.archive, second_layer=b'second rootfs layer')
        packager.package(self.archive, 'amd64', image_id, self.output)
        image_archive(self.archive, second_layer=b'second rootfs layer', reverse_layers=True)
        with self.assertRaisesRegex(bundle.BundleError, 'rootfs digest'):
            packager.package(self.archive, 'amd64', image_id, self.base / 'wrong-order')

    def test_layer_hashing_preserves_abort_and_rejects_invalid_gzip(self):
        stop = BackupError('insufficient-space', 'stop')
        original = bundle._verify_layers
        def abort_layer(stream, layers, positions, diff_ids, abort):
            return original(stream, layers, positions, diff_ids, lambda: stop)
        with self.archive.open('rb') as stream, mock.patch.object(bundle, '_verify_layers', abort_layer):
            with self.assertRaises(BackupError) as caught:
                bundle.validate_archive(stream, 'amd64', self.image_id)
        self.assertIs(caught.exception, stop)
        image_archive(self.archive, layer=b'\x1f\x8bbad gzip data')
        with self.assertRaisesRegex(bundle.BundleError, 'compressed Docker image layer'):
            packager.package(self.archive, 'amd64', self.image_id, self.output)

    def test_wrong_config_id_arch_ref_multiimage_and_malformed_archive_rejected(self):
        for options in ({'tag': 'evil.invalid/postgres:16'}, {'multi': True}, {'arch': 'arm64'},
                        {'config_name': 'wrong.json'}):
            image_archive(self.archive, **options)
            with self.subTest(options=options), self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', self.image_id, self.output)
            self.assertFalse(self.output.exists())
        self.archive.write_bytes(b'invalid tar')
        with self.assertRaises(bundle.BundleError):
            packager.package(self.archive, 'amd64', self.image_id, self.output)
        self.assertFalse(list(self.base.glob('.pg16-package-*')))

    def test_no_path_traversal_duplicate_members_links_or_extended_headers(self):
        entries = []
        for name in ('../evil', '/absolute', 'layer/../evil', 'a//b', 'manifest.json'):
            entries.append((name, b'bad'))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_SPARSE):
            info = tarfile.TarInfo('bad-link-or-extension')
            info.type, info.linkname = kind, '../evil'
            entries.append((info, b''))
        for entry in entries:
            image_archive(self.archive, extra=[entry])
            with self.subTest(name=str(entry[0])), self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', self.image_id, self.output)
        self.assertFalse((self.base.parent / 'evil').exists())

    def test_unrelated_images_and_repository_tags_refused(self):
        for extra in ([('other-config.json', b'{}')],
                      [('repositories', b'{"evil.invalid/postgres":{"latest":"layer"}}')]):
            image_archive(self.archive, extra=extra)
            with self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', self.image_id, self.output)

    def test_legacy_layer_metadata_and_matching_repositories_allowed(self):
        image_archive(self.archive, extra=[('layer/json', b'{}'), ('layer/VERSION', b'1.0'),
                                          ('repositories', json.dumps({bundle.TAG.rsplit(':', 1)[0]:
                                                                      {'16.15-alpine': 'layer'}}).encode())])
        self.package()

    def test_truncated_and_concatenated_archives_rejected(self):
        raw = self.archive.read_bytes()
        for malformed in (raw[:1025], raw + b'nonzero trailing content'):
            self.archive.write_bytes(malformed)
            with self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', self.image_id, self.output)

    def test_source_symlink_hardlink_and_fifo_refused(self):
        self.package()
        target = self.output / bundle.ARCHIVE
        target.unlink()
        for kind in ('symlink', 'hardlink', 'fifo'):
            if kind == 'symlink':
                target.symlink_to(self.archive)
            elif kind == 'hardlink':
                os.link(self.archive, target)
            else:
                os.mkfifo(target)
            with self.subTest(kind=kind), self.assertRaises((OSError, bundle.BundleError)):
                with bundle.open_bundle(self.output, self.report['manifest_sha256']):
                    pass
            target.unlink()

    def test_installed_files_and_ancestors_must_be_root_trusted(self):
        self.install()
        generation = Path(self.installed['path'])
        for target in (generation / bundle.ARCHIVE, generation / 'manifest.json', generation.parent / 'active.sha256',
                       generation, generation.parent, self.root / 'usr'):
            original = target.stat().st_mode & 0o777
            target.chmod(original | 0o020)
            with self.subTest(path=target), self.assertRaises(bundle.BundleError):
                with bundle.installed_bundle():
                    pass
            target.chmod(original)
        with mock.patch.object(bundle, 'ROOT_UID', os.getuid() + 1), self.assertRaises(bundle.BundleError):
            with bundle.installed_bundle():
                pass

    def test_symlink_generation_and_selected_path_cannot_escape(self):
        self.install()
        generation = Path(self.installed['path'])
        active = generation.parent / 'active.sha256'
        active.write_text('../escape\n')
        with self.assertRaises(bundle.BundleError):
            with bundle.installed_bundle():
                pass
        active.write_text(generation.name + '\n')
        other = generation.with_name('moved')
        generation.rename(other)
        generation.symlink_to(other, target_is_directory=True)
        with self.assertRaises(OSError):
            with bundle.installed_bundle():
                pass

    def test_failed_copy_keeps_previous_selection_and_cleans_stage(self):
        pin = self.install()
        # A second valid manifest generation (different whitespace) must not become active on ENOSPC.
        raw = (self.output / 'manifest.json').read_bytes() + b'\n'
        (self.output / 'manifest.json').write_bytes(raw)
        new_pin = hashlib.sha256(raw).hexdigest()
        original = bundle.copy_hash
        def fail_copy(source, output=None, **options):
            if output is not None:
                output.write(b'partial')
                raise OSError(28, 'No space left on device')
            return original(source, **options)
        with mock.patch.object(bundle, 'copy_hash', fail_copy), self.assertRaises(OSError):
            bundle.install_bundle(self.output, new_pin, self.root)
        active_dir = Path(self.installed['path']).parent
        self.assertEqual((active_dir / 'active.sha256').read_text().strip(), pin)
        self.assertFalse(list(active_dir.glob('.stage-*')))
        self.assertFalse((active_dir / new_pin).exists())

    def test_verification_honors_job_cancel_before_read(self):
        pin = self.package()
        stop = BackupError('job-failed', 'stop')
        with self.assertRaises(BackupError) as caught:
            with bundle.open_bundle(self.output, pin, abort=lambda: stop):
                pass
        self.assertIs(caught.exception, stop)

    def test_install_abort_preserves_previous_selection(self):
        pin = self.install()
        selected = Path(self.installed['path']).parent / 'active.sha256'
        stop = BackupError('insufficient-space', 'proof-reserve-reached')
        with self.assertRaises(BackupError) as caught:
            bundle.install_bundle(self.output, pin, self.root, abort=lambda: stop)
        self.assertIs(caught.exception, stop)
        self.assertEqual(selected.read_text().strip(), pin)

    def test_200mib_stream_copy_never_requests_or_retains_the_whole_artifact(self):
        class Source:
            remaining, reads = 200 * 1024**2, []
            def read(self, size=-1):
                if not 0 < size <= bundle.CHUNK:
                    raise AssertionError('Unbounded artifact read')
                self.reads.append(size)
                count = min(self.remaining, size)
                self.remaining -= count
                return b'x' * count
        class Sink:
            count, maximum = 0, 0
            def write(self, data):
                self.count += len(data)
                self.maximum = max(self.maximum, len(data))
        source, sink = Source(), Sink()
        _sha, total = bundle.copy_hash(source, sink)
        self.assertEqual(total, 200 * 1024**2)
        self.assertEqual(sink.count, total)
        self.assertEqual(sink.maximum, bundle.CHUNK)
        self.assertEqual(len(source.reads), 201)


class RuntimeTests(BundleCase):
    def setUp(self):
        super().setUp()
        self.app = types.SimpleNamespace(id='odoo', name='Odoo', owner='odoo-owner')
        self.calls, self.loaded = [], False
        self.runner = types.SimpleNamespace(podman=self.podman)
        self.work = types.SimpleNamespace(runner=mock.Mock(return_value=self.runner), log=mock.Mock(), abort=lambda: None)

    def podman(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == 'load':
            stream = kwargs['input']
            self.assertEqual(stream.tell(), 0)
            self.assertGreater(os.fstat(stream.fileno()).st_size, 0)
            self.assertNotIn('--input', args)
            while stream.read(4096):
                pass
            self.loaded = True
            return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        self.assertEqual(args[:2], ('image', 'inspect'))
        bundled_present = args[-1] == self.image_id and self.loaded
        value = f'{self.image_id} amd64 linux\n'.encode() if bundled_present else b''
        return types.SimpleNamespace(returncode=0 if bundled_present else 1, stdout=value, stderr=b'')

    def test_offline_load_goes_to_app_owner_before_pull_and_returns_config_id(self):
        self.install()
        with mock.patch.object(ha_odoo.hatarget, 'ensure_image') as pull:
            self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), self.image_id)
            self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), self.image_id)
        pull.assert_not_called()
        self.assertEqual(sum(args[0] == 'load' for args, _kwargs in self.calls), 1)
        self.assertTrue(all(call.args == (self.app,) for call in self.work.runner.call_args_list))
        load = next(kwargs for args, kwargs in self.calls if args[0] == 'load')
        self.assertEqual(load['abort'], self.work.abort)
        self.assertLessEqual(load['max_output'], 64 * 1024)

    def test_existing_local_image_takes_priority_without_bundle_io(self):
        with mock.patch.object(ha_odoo.hatarget, 'image_present', return_value=True), \
                mock.patch.object(bundle, 'installed_bundle') as shipped:
            self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), ha_odoo.PG16_IMAGES[0])
        shipped.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_existing_pinned_pull_also_takes_priority_without_bundle_io(self):
        with mock.patch.object(ha_odoo.hatarget, 'image_present', side_effect=lambda _w, _a, ref: ref == ha_odoo.PG16_PINNED), \
                mock.patch.object(bundle, 'installed_bundle') as shipped:
            self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), ha_odoo.PG16_PINNED)
        shipped.assert_not_called()

    def test_podman_inspect_accepts_full_hex_without_sha256_prefix(self):
        self.install()
        real = self.podman
        def bare_id(*args, **kwargs):
            result = real(*args, **kwargs)
            if self.loaded and args[0] == 'image':
                result.stdout = result.stdout.removeprefix(b'sha256:')
            return result
        self.runner.podman = bare_id
        self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), self.image_id)

    def test_real_owner_runner_passes_verified_descriptor_through_runuser_without_root_load(self):
        self.install()
        commands = []
        def execute(argv, **kwargs):
            commands.append(argv)
            self.assertEqual(argv[:4], [podman.RUNUSER, '-u', self.app.owner, '--'])
            self.assertEqual(kwargs['cwd'], '/home/odoo-owner')
            args = argv[argv.index(podman.PODMAN) + 1:]
            return self.podman(*args, **kwargs)
        account = types.SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_dir='/home/odoo-owner')
        owner = podman.OwnerRunner(self.app.owner, runner=execute, user_lookup=lambda _name: account)
        self.work.runner = mock.Mock(return_value=owner)
        self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), self.image_id)
        self.assertEqual(sum(command[command.index(podman.PODMAN) + 1] == 'load' for command in commands), 1)

    def test_absent_bundle_keeps_pinned_online_retry_contract(self):
        with mock.patch.object(ha_odoo.hatarget, 'ensure_image') as ensure:
            self.assertEqual(ha_odoo.pick_pg16(self.work, self.app), ha_odoo.PG16_PINNED)
        ensure.assert_called_once_with(self.work, self.app, ha_odoo.PG16_PINNED)
        self.assertFalse(any(args[0] == 'load' for args, _ in self.calls))

    def test_tampered_bundle_stops_before_load_or_pull(self):
        self.install()
        (Path(self.installed['path']) / bundle.ARCHIVE).write_bytes(b'changed')
        with mock.patch.object(ha_odoo.hatarget, 'ensure_image') as pull, self.assertRaises(BackupError) as caught:
            ha_odoo.pick_pg16(self.work, self.app)
        self.assertEqual(caught.exception.code, 'incompatible')
        pull.assert_not_called()
        self.assertFalse(any(args[0] == 'load' for args, _ in self.calls))

    def test_successful_load_must_be_followed_by_exact_config_arch_inspection(self):
        self.install()
        real = self.podman
        def wrong(*args, **kwargs):
            result = real(*args, **kwargs)
            if self.loaded and args[0] == 'image':
                result.stdout = f'{self.image_id} arm64 linux\n'.encode()
            return result
        self.runner.podman = wrong
        with self.assertRaises(BackupError) as caught:
            ha_odoo.pick_pg16(self.work, self.app)
        self.assertEqual(caught.exception.code, 'incompatible')

    def test_job_wide_load_failure_is_preserved(self):
        self.install()
        real = self.podman
        stop = BackupError('insufficient-space', 'stop')
        def no_space(*args, **kwargs):
            if args[0] == 'load':
                raise stop
            return real(*args, **kwargs)
        self.runner.podman = no_space
        with self.assertRaises(BackupError) as caught:
            ha_odoo.pick_pg16(self.work, self.app)
        self.assertIs(caught.exception, stop)
