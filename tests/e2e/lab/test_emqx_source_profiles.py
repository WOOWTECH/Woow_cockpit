"""Fixed public profile policy only; no archive/credential/container access."""
import unittest


class ProfileTests(unittest.TestCase):
    def test_profiles_bind_distinct_fixed_archive_mode_arch_and_budget_identity(self):
        from emqx_source_profiles import source_profile
        arm = source_profile('--source')
        x86 = source_profile('--x86-source')
        self.assertEqual(arm.sha256, 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664')
        self.assertEqual(arm.cold_receipt, (28, 57502))
        self.assertIsNone(arm.fixture_profile)
        self.assertEqual(arm.arch, 'aarch64')
        self.assertEqual(x86.sha256, '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9')
        self.assertIsNone(x86.cold_receipt)
        self.assertEqual(x86.fixture_profile, 'owner-x86-20261121')
        self.assertEqual(x86.arch, 'amd64')
        self.assertEqual(x86.archive.name, 'woow-b1-x86-emqx-stopped-enc.tar')
        self.assertEqual(x86.archive.parent.parent.name, 'x86')
        self.assertEqual((arm.frame_mode, x86.frame_mode), (b'S', b'X'))
        for mode, base, byte in (('--source-vendor-acl', arm, b'V'),
                                 ('--x86-source-vendor-acl', x86, b'W')):
            vendor = source_profile(mode)
            self.assertEqual(vendor.sha256, base.sha256)
            self.assertEqual(vendor.archive, base.archive)
            self.assertEqual(vendor.cold_receipt, base.cold_receipt)
            self.assertEqual(vendor.file_dependency_profile, 'owner-pinned-image-vendor-acl-v1')
            self.assertEqual(vendor.frame_mode, byte)
        with self.assertRaises(AttributeError):
            x86.sha256 = arm.sha256
        for unknown in ('', '--source=/tmp/other', '--x86-source=bad', 'owner-x86-20261121'):
            with self.assertRaises(ValueError):
                source_profile(unknown)
