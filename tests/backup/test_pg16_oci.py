"""Strict OCI export packaging regressions; synthetic blobs only, no engine commands."""
import gzip
import hashlib
import io
import json
import tarfile

from .test_pg16_bundle import BundleCase, bundle, packager


def oci_archive(path, *, tag=bundle.TAG, bad_layer=False, extra=(), multi=False, wrong_descriptor=False):
    layer = b'ordered uncompressed layer'
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {
        'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
    blobs = {}
    def blob(raw, media):
        digest = hashlib.sha256(raw).hexdigest()
        blobs['blobs/sha256/' + digest] = raw
        return {'digest': 'sha256:' + digest, 'size': len(raw), 'mediaType': media}
    config_desc = blob(config, 'application/vnd.oci.image.config.v1+json')
    layer_desc = blob(gzip.compress(b'wrong bytes' if bad_layer else layer),
                      'application/vnd.oci.image.layer.v1.tar+gzip')
    if wrong_descriptor:
        layer_desc['size'] += 1
    manifest = blob(json.dumps({'schemaVersion': 2, 'config': config_desc, 'layers': [layer_desc]}).encode(),
                    'application/vnd.oci.image.manifest.v1+json')
    manifest['annotations'] = {'org.opencontainers.image.ref.name': tag}
    index = {'schemaVersion': 2, 'manifests': [manifest] * (2 if multi else 1)}
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in [('oci-layout', b'{"imageLayoutVersion":"1.0.0"}'),
                          ('index.json', json.dumps(index).encode()), *blobs.items(), *extra]:
            info = tarfile.TarInfo(name) if isinstance(name, str) else name
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return config_desc['digest']


class OciPackagingTests(BundleCase):
    def test_real_packager_explicit_oci_export_produces_link_free_verified_docker_bundle(self):
        image_id = oci_archive(self.archive)
        report = packager.package(self.archive, 'amd64', image_id, self.output, input_format='oci-archive')
        with bundle.open_bundle(self.output, report['manifest_sha256']) as (record, raw, stream):
            self.assertEqual(record['image_id'], image_id)
            bundle.validate_archive(stream, 'amd64', image_id)
        with tarfile.open(self.output / bundle.ARCHIVE) as tar:
            self.assertTrue(all(info.isfile() for info in tar))

    def test_oci_links_paths_wrong_ref_multiimage_and_descriptor_are_refused(self):
        link = tarfile.TarInfo('legacy/layer.tar')
        link.type, link.linkname = tarfile.SYMTYPE, '../layer.tar'
        for options in ({'extra': [(link, b'')]}, {'extra': [('../escape', b'')]},
                        {'tag': 'wrong.invalid/postgres:16'}, {'multi': True}, {'wrong_descriptor': True}):
            with self.subTest(options=list(options)):
                image_id = oci_archive(self.archive, **options)
                with self.assertRaises(bundle.BundleError):
                    packager.package(self.archive, 'amd64', image_id, self.output, input_format='oci-archive')
                self.assertFalse(self.output.exists())

    def test_oci_config_pin_and_each_layer_bytes_remain_mandatory(self):
        for wrong_config in (False, True):
            image_id = oci_archive(self.archive, bad_layer=not wrong_config)
            with self.assertRaises(bundle.BundleError):
                packager.package(self.archive, 'amd64', 'sha256:' + '0' * 64 if wrong_config else image_id,
                                 self.output, input_format='oci-archive')

    def test_default_docker_packaging_still_refuses_symlink_aliases(self):
        from .test_pg16_bundle import image_archive
        link = tarfile.TarInfo('legacy/layer.tar')
        link.type, link.linkname = tarfile.SYMTYPE, '../layer.tar'
        image_id = image_archive(self.archive, extra=[(link, b'')])
        with self.assertRaisesRegex(bundle.BundleError, 'Unsafe Docker archive member'):
            packager.package(self.archive, 'amd64', image_id, self.output)

    def test_converter_reads_bounded_chunks_and_honors_abort(self):
        image_id = oci_archive(self.archive)
        class Bounded(io.BytesIO):
            def read(self, size=-1):
                if not 0 <= size <= bundle.CHUNK:
                    raise AssertionError('unbounded read')
                return super().read(size)
        with Bounded(self.archive.read_bytes()) as source, io.BytesIO() as target:
            packager.oci.convert_archive(source, target, bundle, 'amd64', image_id)
        stop = RuntimeError('stop')
        with self.archive.open('rb') as source, io.BytesIO() as target, self.assertRaises(RuntimeError) as caught:
            packager.oci.convert_archive(source, target, bundle, 'amd64', image_id, abort=lambda: stop)
        self.assertIs(caught.exception, stop)

    def test_packaging_abort_never_publishes_partial_release(self):
        image_id = oci_archive(self.archive)
        stop = RuntimeError('reserve reached')
        with self.assertRaises(RuntimeError) as caught:
            packager.package(self.archive, 'amd64', image_id, self.output,
                             input_format='oci-archive', abort=lambda: stop)
        self.assertIs(caught.exception, stop)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.base.glob('.pg16-package-*')))
