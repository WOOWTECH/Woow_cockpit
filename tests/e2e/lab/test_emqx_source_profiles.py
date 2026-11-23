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
        for mode, base, byte in (('--source-vendor-acl-republish',arm,b'Y'),
                                 ('--x86-source-vendor-acl-republish',x86,b'Z')):
            contextual = source_profile(mode)
            self.assertEqual(contextual.sha256,base.sha256)
            self.assertEqual(contextual.archive,base.archive)
            self.assertEqual(contextual.cold_receipt,base.cold_receipt)
            self.assertEqual(contextual.fixture_profile,base.fixture_profile)
            self.assertEqual(contextual.frame_mode,byte)
            self.assertEqual(contextual.file_dependency_profile,
                             'owner-pinned-image-vendor-acl-republish-context-v1')
        for mode, base, byte in (('--source-vendor-acl-http-body',arm,b'H'),
                                 ('--x86-source-vendor-acl-http-body',x86,b'J')):
            http = source_profile(mode)
            self.assertEqual(http.sha256,base.sha256)
            self.assertEqual(http.archive,base.archive)
            self.assertEqual(http.cold_receipt,base.cold_receipt)
            self.assertEqual(http.fixture_profile,base.fixture_profile)
            self.assertEqual(http.frame_mode,byte)
            self.assertEqual(http.file_dependency_profile,
                             'owner-pinned-image-vendor-acl-http-body-context-v1')
        for mode, base, byte in (('--source-vendor-acl-sql-aliases',arm,b'A'),
                                 ('--x86-source-vendor-acl-sql-aliases',x86,b'B')):
            sql = source_profile(mode)
            self.assertEqual(sql.sha256,base.sha256)
            self.assertEqual(sql.archive,base.archive)
            self.assertEqual(sql.cold_receipt,base.cold_receipt)
            self.assertEqual(sql.fixture_profile,base.fixture_profile)
            self.assertEqual(sql.frame_mode,byte)
            self.assertEqual(sql.file_dependency_profile,
                             'owner-pinned-image-vendor-acl-sql-alias-context-v1')
        with self.assertRaises(AttributeError):
            x86.sha256 = arm.sha256
        for unknown in ('', '--source=/tmp/other', '--x86-source=bad', 'owner-x86-20261121'):
            with self.assertRaises(ValueError):
                source_profile(unknown)
