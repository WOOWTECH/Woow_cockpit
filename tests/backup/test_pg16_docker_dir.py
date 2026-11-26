"""Docker directory transport preserves original Docker config bytes without legacy archive links."""
import gzip
import hashlib
import json
import os
from pathlib import Path

from .test_pg16_bundle import BundleCase, bundle, packager


def docker_directory(path, *, bad_layer=False):
    path.mkdir()
    data = b'original layer bytes'
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {
        'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(data).hexdigest()]}}).encode()
    def blob(raw, media):
        sha = hashlib.sha256(raw).hexdigest()
        (path / sha).write_bytes(raw)
        return {'digest': 'sha256:' + sha, 'size': len(raw), 'mediaType': media}
    config_desc = blob(config, 'application/vnd.docker.container.image.v1+json')
    layer = blob(gzip.compress(b'wrong' if bad_layer else data),
                 'application/vnd.docker.image.rootfs.diff.tar.gzip')
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                'config': config_desc, 'layers': [layer]}
    (path / 'manifest.json').write_text(json.dumps(manifest))
    (path / 'version').write_text('Directory Transport Version: 1.1\n')
    return config_desc['digest']


class DockerDirectoryTests(BundleCase):
    def setUp(self):
        super().setUp()
        self.directory = self.base / 'directory'
        self.image_id = docker_directory(self.directory)

    def test_real_packager_preserves_pinned_docker_config_and_layers(self):
        report = packager.package(self.directory, 'amd64', self.image_id, self.output, input_format='docker-dir')
        with bundle.open_bundle(self.output, report['manifest_sha256']) as (record, raw, stream):
            self.assertEqual(record['image_id'], self.image_id)
            bundle.validate_archive(stream, 'amd64', self.image_id)

    def test_links_hardlinks_extra_files_and_multiimage_are_refused(self):
        config = self.directory / self.image_id[7:]
        original = config.read_bytes()
        for attack in ('symlink', 'hardlink', 'extra', 'multi'):
            with self.subTest(attack=attack):
                if attack == 'symlink':
                    config.unlink()
                    config.symlink_to(self.archive)
                elif attack == 'hardlink':
                    os.link(config, self.base / 'alias')
                elif attack == 'extra':
                    (self.directory / 'unrelated').write_text('extra')
                else:
                    manifest = self.directory / 'manifest.json'
                    saved = manifest.read_bytes()
                    manifest.write_text(json.dumps([json.loads(saved)] * 2))
                with self.assertRaises((bundle.BundleError, OSError)):
                    packager.package(self.directory, 'amd64', self.image_id, self.output, input_format='docker-dir')
                self.assertFalse(self.output.exists())
                if attack == 'symlink':
                    config.unlink()
                    config.write_bytes(original)
                elif attack == 'hardlink':
                    (self.base / 'alias').unlink()
                elif attack == 'extra':
                    (self.directory / 'unrelated').unlink()
                else:
                    manifest.write_bytes(saved)

    def test_config_digest_descriptor_and_uncompressed_layer_digest_are_all_mandatory(self):
        config = self.directory / self.image_id[7:]
        config.write_bytes(b'wrong config')
        with self.assertRaises(bundle.BundleError):
            packager.package(self.directory, 'amd64', self.image_id, self.output, input_format='docker-dir')
        import shutil
        shutil.rmtree(self.directory)
        self.image_id = docker_directory(self.directory, bad_layer=True)
        with self.assertRaisesRegex(bundle.BundleError, 'rootfs digest'):
            packager.package(self.directory, 'amd64', self.image_id, self.output, input_format='docker-dir')

    def test_wrong_pin_and_reserve_abort_cannot_publish(self):
        with self.assertRaises(bundle.BundleError):
            packager.package(self.directory, 'amd64', 'sha256:' + '0' * 64, self.output, input_format='docker-dir')
        stop = RuntimeError('reserve reached')
        with self.assertRaises(RuntimeError) as caught:
            packager.package(self.directory, 'amd64', self.image_id, self.output,
                             input_format='docker-dir', abort=lambda: stop)
        self.assertIs(caught.exception, stop)
        self.assertFalse(self.output.exists())
