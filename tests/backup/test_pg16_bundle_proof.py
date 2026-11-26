"""Offline tests of the lease-only archive tag normalization. No device/store/engine command runs."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import unittest
from unittest import mock

from woowbackup import pg16_bundle as bundle
from .test_pg16_bundle import BundleCase, image_archive

SPEC = importlib.util.spec_from_file_location('od23_dev_d_proof', Path(__file__).resolve().parents[2]
                                           / 'snippets/focus-odoo-image/dev_d_offline_proof.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class CanonicalArchiveTests(BundleCase):
    def setUp(self):
        super().setUp()
        self.image_id = image_archive(self.archive, tag=proof.SOURCE_TAG)
        self.enterContext(mock.patch.object(proof, 'EXPECTED', self.image_id))
        self.canonical = self.base / 'canonical.tar'

    def test_streamed_copy_changes_tag_and_preserves_source_config_and_layers(self):
        before = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        proof.canonical_archive(self.archive, self.canonical, bundle, lambda: None)
        with self.canonical.open('rb') as source:
            bundle.validate_archive(source, 'amd64', self.image_id)
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(), before)
        with tarfile.open(self.archive) as original, tarfile.open(self.canonical) as changed:
            for name in (self.image_id[7:] + '.json', 'layer/layer.tar'):
                self.assertEqual(original.extractfile(name).read(), changed.extractfile(name).read())

    def test_wrong_layer_bytes_are_rejected_before_packaging_or_load(self):
        image_archive(self.archive, tag=proof.SOURCE_TAG, layer=b'changed layer')
        with self.assertRaisesRegex(bundle.BundleError, 'rootfs digest'):
            proof.canonical_archive(self.archive, self.canonical, bundle, lambda: None)

    def test_multiple_images_wrong_source_tag_and_links_are_rejected(self):
        link = tarfile.TarInfo('link')
        link.type, link.linkname = tarfile.SYMTYPE, '../outside'
        for options in ({'multi': True}, {'tag': 'evil.invalid/postgres:16'}, {'extra': [(link, b'')]}):
            image_archive(self.archive, tag=options.pop('tag', proof.SOURCE_TAG), **options)
            with self.assertRaises((ValueError, AssertionError)):
                proof.canonical_archive(self.archive, self.canonical, bundle, lambda: None)
            self.canonical.unlink(missing_ok=True)

    def test_cancel_stops_copy_and_no_sidecar_is_selected(self):
        stop = RuntimeError('stop')
        with self.assertRaises(RuntimeError) as caught:
            proof.canonical_archive(self.archive, self.canonical, bundle, lambda: stop)
        self.assertIs(caught.exception, stop)

    def test_failure_reason_is_fixed_whitelist_and_never_raw_artifact_text(self):
        self.assertEqual(proof.failure_reason(ValueError('source-archive-header-refused')),
                         'source-archive-header-refused')
        self.assertEqual(proof.failure_reason(bundle.BundleError(bundle.ERROR_LAYER_DIGEST)),
                         'ordered-layer-digest-mismatch')
        self.assertEqual(proof.failure_reason(bundle.BundleError('private artifact contents')),
                         'unclassified-fixed-failure')


if __name__ == '__main__':
    unittest.main()
