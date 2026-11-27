"""SecureTar v1/v2/v3 decryption (hasecuretar.py, team E1) against fixtures written by the real securetar library.

Byte-identical plaintext (fixtures.json records what securetar 2026.10.0 returns), wrong keys (v1/v2 heuristic, v3
exact, always before any plaintext), truncation, tampering, header/size consistency, v3 chunk and tag rules (test-side
writer, hafixtures.v3_encrypt) and the zh-TW errors for missing Ubuntu packages.
"""
import hashlib
import io
import sys
import unittest
from unittest import mock

from woowbackup import hasecuretar
from woowbackup.errors import BackupError

from . import hafixtures as hx

MiB = 1024 * 1024


def decrypt(data, password=hx.PASSWORD, *, keys=None, size=None, chunk=MiB):
    reader = hasecuretar.DecryptReader(io.BytesIO(data), len(data) if size is None else size,
                                       keys or hasecuretar.Keys(password))
    parts = []
    while True:
        part = reader.read(chunk)
        if not part:
            break
        parts.append(part)
    reader.finish()
    return b''.join(parts)


def code_of(callable_, *args, **kwargs):
    try:
        callable_(*args, **kwargs)
    except BackupError as error:
        return error.code, error
    raise AssertionError('no BackupError')


class SniffTests(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(hasecuretar.sniff(b'SecureTar\x03' + bytes(6) + b'x' * 30), 'v3')
        self.assertEqual(hasecuretar.sniff(b'SecureTar\x02' + bytes(6)), 'v2')
        self.assertEqual(hasecuretar.sniff(b'SecureTar\x04' + bytes(6)), 'unsupported')
        self.assertEqual(hasecuretar.sniff(b'SecureTar\x03' + b'\x01' + bytes(5)), 'unsupported')
        self.assertEqual(hasecuretar.sniff(b'\x1f\x8b\x08\x00rest'), 'gzip')
        self.assertEqual(hasecuretar.sniff(bytes(257) + b'ustar\x0000' + bytes(250)), 'tar')
        self.assertEqual(hasecuretar.sniff(bytes(512)), 'tar')
        self.assertEqual(hasecuretar.sniff(b'\x7f' * 512), 'unknown')

    def test_ciphertext_sizes(self):
        import struct
        head = lambda version, size: b'SecureTar' + bytes([version]) + bytes(6) + struct.pack('!Q8x', size)  # noqa: E731
        self.assertTrue(hasecuretar.ciphertext_ok('v2', 48 + 16, head(2, 0)))
        self.assertTrue(hasecuretar.ciphertext_ok('v2', 48 + 32, head(2, 16)))   # PKCS7 always pads
        self.assertFalse(hasecuretar.ciphertext_ok('v2', 48 + 16, head(2, 16)))
        self.assertTrue(hasecuretar.ciphertext_ok('v3', 136 + 17, head(3, 0)))
        self.assertTrue(hasecuretar.ciphertext_ok('v3', 136 + MiB + 17, head(3, MiB)))
        self.assertTrue(hasecuretar.ciphertext_ok('v3', 136 + MiB + 1 + 34, head(3, MiB + 1)))
        self.assertFalse(hasecuretar.ciphertext_ok('v3', 136 + MiB + 1 + 17, head(3, MiB + 1)))
        self.assertTrue(hasecuretar.ciphertext_ok('v1', 16 + 32, b''))
        self.assertFalse(hasecuretar.ciphertext_ok('v1', 16 + 33, b''))
        self.assertFalse(hasecuretar.ciphertext_ok('v1', 16, b''))
        # KEY-07: shorter than its header says is cut off; KEY-13: what a longer one holds after that is not read.
        for kind, version, size, exact in (('v2', 2, 100, 48 + 112), ('v3', 3, 100, 136 + 117)):
            for extra, good in ((-1, False), (0, True), (1, True), (MiB, True)):
                with self.subTest(kind=kind, extra=extra):
                    self.assertIs(hasecuretar.ciphertext_ok(kind, exact + extra, head(version, size)), good)
        for size in (2 ** 63, 2 ** 64 - 1):
            self.assertFalse(hasecuretar.ciphertext_ok('v2', 10 ** 12, head(2, size)))
            self.assertFalse(hasecuretar.ciphertext_ok('v3', 10 ** 12, head(3, size)))
        self.assertFalse(hasecuretar.ciphertext_ok('v3', 10 ** 12, head(3, 0)[:31]))


class KeysTests(unittest.TestCase):
    def test_invalid_keys_and_privacy(self):
        for bad in ('', None, 5, 'x' * 5000, 'a\x00b', '\ud800abc'):
            with self.subTest(bad=repr(bad)[:20]):
                code, error = code_of(hasecuretar.Keys, bad)
                self.assertEqual(code, 'invalid-request')
        keys = hasecuretar.Keys(hx.PASSWORD)
        self.assertNotIn(hx.PASSWORD, repr(keys))
        self.assertFalse(hasattr(keys, '__dict__'), 'no attribute dump can show the key')

    def test_key_required_without_keys(self):
        data, _info = hx.member_bytes(hx.fixture('v3_gzip.tar'), f'{hx.ODOO}.tar.gz')
        code, error = code_of(hasecuretar.DecryptReader, io.BytesIO(data), len(data), None, name='x')
        self.assertEqual(code, 'key-required')
        self.assertIn('HA 備份金鑰', error.message)


@hx.needs_crypto
class RealLibraryFixtureTests(unittest.TestCase):
    """Every encrypted member of every fixture: the plaintext securetar 2026.10.0 returns, byte for byte."""

    def test_plaintext_is_byte_identical_to_securetar(self):
        checked = {'v1': 0, 'v2': 0, 'v3': 0}
        for name, fixture in hx.META['fixtures'].items():
            keys = hasecuretar.Keys(hx.PASSWORD)  # one Keys per backup, like the jobs
            for member, info in fixture['members'].items():
                if info['encryption'] == 'none':
                    continue
                data, _tarinfo = hx.member_bytes(hx.fixture(name), member)
                with self.subTest(fixture=name, member=member):
                    plaintext = decrypt(data, keys=keys, chunk=4096)
                    if info.get('library_truncates'):
                        # securetar 2026.10.0 drops the last read buffer of an unpadded v1 stream; this reader
                        # returns the whole tar (the entries are checked in test_ha_backup).
                        self.assertEqual(len(plaintext) % 10240, 0)
                        self.assertEqual(plaintext[-1024:], bytes(1024))
                    else:
                        self.assertEqual((hashlib.sha256(plaintext).hexdigest(), len(plaintext)),
                                         (info['plaintext_sha256'], info['plaintext_length']))
                    checked[info['encryption']] += 1
        self.assertEqual(checked, {'v1': 6, 'v2': 8, 'v3': 7})

    def test_wrong_key_before_any_plaintext(self):
        for name in ('v1_gzip.tar', 'v1_plain.tar', 'v2_gzip.tar', 'v2_2025_gzip.tar', 'v3_gzip.tar', 'v3_plain.tar'):
            for member, info in hx.fixture_members(name).items():
                data, _tarinfo = hx.member_bytes(hx.fixture(name), member)
                with self.subTest(fixture=name, member=member):
                    code, error = code_of(hasecuretar.DecryptReader, io.BytesIO(data), len(data),
                                          hasecuretar.Keys(hx.WRONG_PASSWORD))
                    self.assertEqual(code, 'wrong-key')
                    self.assertEqual(error.message, 'HA 備份金鑰不正確，請確認後再試一次。')
                    self.assertNotIn(hx.WRONG_PASSWORD, repr(error.details))

    def test_one_argon2id_per_backup(self):
        from nacl.pwhash import argon2id
        keys = hasecuretar.Keys(hx.PASSWORD)
        real = argon2id.kdf
        with mock.patch.object(argon2id, 'kdf', side_effect=real) as kdf:
            for member in hx.fixture_members('v3_gzip.tar'):
                data, _tarinfo = hx.member_bytes(hx.fixture('v3_gzip.tar'), member)
                decrypt(data, keys=keys)
        self.assertEqual(kdf.call_count, 1, 'every member of a backup shares the root salt')

    def test_truncated_members(self):
        for name, member in (('v3_gzip.tar', f'{hx.ODOO}.tar.gz'), ('v2_gzip.tar', f'{hx.ODOO}.tar.gz'),
                             ('v1_gzip.tar', f'{hx.ODOO}.tar.gz'), ('v3_plain.tar', 'supervisor.tar')):
            data, _tarinfo = hx.member_bytes(hx.fixture(name), member)
            with self.subTest(fixture=name, kind='size declared, data shorter'):
                code, _error = code_of(decrypt, data[:-1000], size=len(data))
                self.assertEqual(code, 'corrupt-archive')
            with self.subTest(fixture=name, kind='member itself shorter'):
                if name.startswith('v1'):
                    # v1 has no header, size or MAC: a whole block less still decrypts, and the gzip layer (CRC,
                    # ISIZE) is what refuses it.
                    from woowbackup import habackup
                    reader = hasecuretar.DecryptReader(io.BytesIO(data[:-16]), len(data) - 16,
                                                       hasecuretar.Keys(hx.PASSWORD))
                    code, _error = code_of(habackup._Gunzip(reader, legacy=True).finish)
                else:
                    code, _error = code_of(decrypt, data[:-16])
                self.assertEqual(code, 'corrupt-archive')
            with self.subTest(fixture=name, kind='header only'):
                code, _error = code_of(decrypt, data[:40])
                self.assertEqual(code, 'corrupt-archive')

    def test_damage_concerns_one_member(self):
        """KEY-05 to KEY-12: the error says so (its scope and its message), so that the other apps can go on."""
        data, _tarinfo = hx.member_bytes(hx.fixture('v3_gzip.tar'), f'{hx.ODOO}.tar.gz')
        legacy, _tarinfo = hx.member_bytes(hx.fixture('v1_gzip.tar'), f'{hx.ODOO}.tar.gz')
        cases = {'header cut': data[:10], 'metadata cut': data[:20], 'init cut': data[:100], 'cut': data[:-1],
                 'flipped': data[:200] + bytes([data[200] ^ 1]) + data[201:], 'legacy blocks': legacy[:-3],
                 'legacy salt only': legacy[:16], 'empty': b''}
        for label, raw in cases.items():
            with self.subTest(case=label):
                code, error = code_of(decrypt, raw)
                self.assertEqual((code, error.details['scope']), ('corrupt-archive', 'member'))
                self.assertEqual(error.message, hasecuretar.MEMBER_MESSAGE)
        code, error = code_of(decrypt, data[:9] + b'\x04' + data[10:])
        self.assertEqual((code, error.details['scope']), ('unsupported-format', 'member'))
        self.assertIn('請在 HA 重新備份後再匯入', hasecuretar.MEMBER_MESSAGE)
        self.assertNotIn('scope', hasecuretar.corrupt('x').details)
        self.assertEqual(hasecuretar.corrupt('x').message, hasecuretar.CORRUPT_MESSAGE)

    def test_bytes_after_the_content_are_never_read(self):
        """KEY-13: v2 and v3 say how long they are; the plaintext is the same and nothing behind it is touched."""
        for name, member in (('v2_gzip.tar', f'{hx.ODOO}.tar.gz'), ('v2_2025_gzip.tar', f'{hx.N8N}.tar.gz'),
                             ('v3_gzip.tar', f'{hx.ODOO}.tar.gz'), ('v3_plain.tar', 'supervisor.tar')):
            data, _tarinfo = hx.member_bytes(hx.fixture(name), member)
            whole = decrypt(data)
            for tail in (b'x', bytes(16), hashlib.sha256(b'noise').digest() * 100, data):
                with self.subTest(fixture=name, tail=len(tail)):
                    source = io.BytesIO(data + tail)
                    reader = hasecuretar.DecryptReader(source, len(data) + len(tail), hasecuretar.Keys(hx.PASSWORD))
                    self.assertEqual(b''.join(iter(lambda: reader.read(65536), b'')), whole)
                    reader.finish()
                    self.assertEqual(source.tell(), len(data))
            for cut in (1, 16, 17, 1000):  # the tail must not stand in for what is missing
                with self.subTest(fixture=name, cut=cut):
                    self.assertEqual(code_of(decrypt, data[:-cut] + b'x' * cut)[0], 'corrupt-archive')
        # Without a header (v1) there is no telling content from what follows it.
        legacy, _tarinfo = hx.member_bytes(hx.fixture('v1_gzip.tar'), f'{hx.ODOO}.tar.gz')
        self.assertEqual(code_of(decrypt, legacy + b'x')[0], 'corrupt-archive')

    def test_a_smaller_size_in_the_header_is_detected(self):
        """The header is not authenticated: saying less than there is must not cut the content silently."""
        for name in ('v2_gzip.tar', 'v3_gzip.tar'):
            data, _tarinfo = hx.member_bytes(hx.fixture(name), f'{hx.ODOO}.tar.gz')
            size = int.from_bytes(data[16:24], 'big')
            from woowbackup import habackup
            for less in (1, 16, 512, size - 1000):
                with self.subTest(fixture=name, less=less):
                    raw = data[:16] + (size - less).to_bytes(8, 'big') + data[24:]

                    def whole():
                        reader = hasecuretar.DecryptReader(io.BytesIO(raw), len(raw), hasecuretar.Keys(hx.PASSWORD))
                        habackup._Gunzip(reader).finish()
                        reader.finish()
                    self.assertEqual(code_of(whole)[0], 'corrupt-archive')

    def test_tampered_v3_is_detected(self):
        data, _tarinfo = hx.member_bytes(hx.fixture('v3_gzip.tar'), f'{hx.ODOO}.tar.gz')
        for offset in (136, len(data) // 2, len(data) - 1):
            tampered = bytearray(data)
            tampered[offset] ^= 0x01
            with self.subTest(offset=offset):
                code, error = code_of(decrypt, bytes(tampered))
                self.assertEqual(code, 'corrupt-archive')
                self.assertIn('authentication', error.details['reason'])
        tampered = bytearray(data)
        tampered[16 + 16 + 16 + 16] ^= 0x01  # the stored validation key
        self.assertEqual(code_of(decrypt, bytes(tampered))[0], 'wrong-key')
        tampered = bytearray(data)
        tampered[16] ^= 0x01  # plaintext size: no longer fits the member size
        self.assertEqual(code_of(decrypt, bytes(tampered))[0], 'corrupt-archive')

    def test_tampered_v2_padding_and_size(self):
        data, _tarinfo = hx.member_bytes(hx.fixture('v2_gzip.tar'), f'{hx.ODOO}.tar.gz')
        tampered = bytearray(data)
        tampered[-17] ^= 0x55  # the second to last block garbles the last block's padding
        code, error = code_of(decrypt, bytes(tampered))
        self.assertEqual(code, 'corrupt-archive')
        self.assertIn(error.details['reason'], ('invalid PKCS7 padding', 'plaintext size differs from the SecureTar header'))

    def test_what_cannot_be_whole_is_refused_when_it_is_opened(self):
        """KEY-06, KEY-07: before the key is used, not after most of it was handed out."""
        cases = []
        for name in ('v2_gzip.tar', 'v3_gzip.tar'):
            data, _tarinfo = hx.member_bytes(hx.fixture(name), f'{hx.ODOO}.tar.gz')
            cases += [(name, data[:-cut], 'member size does not match the SecureTar header') for cut in (1, 16, 17)]
        legacy, _tarinfo = hx.member_bytes(hx.fixture('v1_gzip.tar'), f'{hx.ODOO}.tar.gz')
        cases += [('v1', legacy[:-cut], 'legacy ciphertext is not a whole number of blocks') for cut in (1, 15)]
        cases += [('v1 salt', legacy[:16], 'legacy ciphertext is not a whole number of blocks')]
        for label, raw, reason in cases:
            keys = hasecuretar.Keys(hx.WRONG_PASSWORD)
            with self.subTest(case=label, size=len(raw)):
                code, error = code_of(hasecuretar.DecryptReader, io.BytesIO(raw), len(raw), keys)
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', reason))

    def test_a_source_that_ends_early(self):
        """KEY-08: cut off between two whole blocks, where nothing else shows it (v1 has no size and no padding)."""
        for name, member in (('v1_plain.tar', f'{hx.ODOO}.tar'), ('v1_gzip.tar', f'{hx.ODOO}.tar.gz'),
                             ('v2_gzip.tar', f'{hx.ODOO}.tar.gz')):
            data, _tarinfo = hx.member_bytes(hx.fixture(name), member)
            for cut in (16, 512):
                with self.subTest(fixture=name, cut=cut):
                    code, error = code_of(decrypt, data[:-cut], size=len(data))
                    self.assertEqual((code, error.details['reason']), ('corrupt-archive', 'truncated ciphertext'))

    def test_every_rule_of_v2_padding(self):
        """KEY-09, KEY-10: the padding is what PKCS7 says, whole, and leaves exactly what the header announces."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        salt, body = b's' * 16, hasecuretar.GZIP_MAGIC + bytes(1021)
        key = hasecuretar._sha256_rounds(hx.PASSWORD.encode())[:16]

        def member(last, size):
            encryptor = Cipher(algorithms.AES(key), modes.CBC(hasecuretar._sha256_rounds(key + salt)[:16])).encryptor()
            head = b'SecureTar\x02' + bytes(6) + size.to_bytes(8, 'big') + bytes(8) + salt
            return head + encryptor.update(body + last) + encryptor.finalize()
        self.assertEqual(decrypt(member(b'x' * 11 + b'\x05' * 5, 1035)), body + b'x' * 11)
        self.assertEqual(decrypt(member(b'\x10' * 16, 1024)), body)
        for label, last, size in (('one byte of five', b'x' * 15 + b'\x05', 1035), ('four of five', b'x' * 12 + b'\x05' * 4, 1035),
                                  ('zero', b'x' * 15 + b'\x00', 1039), ('seventeen', b'\x11' * 16, 1024)):
            with self.subTest(padding=label):
                code, error = code_of(decrypt, member(last, size))
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', 'invalid PKCS7 padding'))
        for size in (1034, 1036, 1024):
            with self.subTest(size=size):
                code, error = code_of(decrypt, member(b'x' * 11 + b'\x05' * 5, size))
                self.assertEqual((code, error.details['reason']),
                                 ('corrupt-archive', 'plaintext size differs from the SecureTar header'))

    def test_unsupported_version(self):
        data, _tarinfo = hx.member_bytes(hx.fixture('v3_gzip.tar'), 'supervisor.tar.gz')
        code, error = code_of(decrypt, data[:9] + b'\x04' + data[10:])
        self.assertEqual((code, error.details['version']), ('unsupported-format', 4))


@hx.needs_nacl
class V3StreamRuleTests(unittest.TestCase):
    """Chunk boundaries and tags with the test-side writer (real files of several MiB would be too large)."""

    @classmethod
    def setUpClass(cls):
        cls.salts = (b'r' * 16, b'v' * 16, b'd' * 16)
        cls.keys = hasecuretar.Keys(hx.PASSWORD)

    def make(self, plaintext, **kwargs):
        return hx.v3_encrypt(plaintext, salts=self.salts, **kwargs)

    def test_chunk_boundaries_round_trip(self):
        for size in (0, 1, MiB - 1, MiB, MiB + 1, 2 * MiB + 17):
            payload = hashlib.sha256(str(size).encode()).digest() * (size // 32 + 1)
            payload = payload[:size]
            with self.subTest(size=size):
                self.assertEqual(decrypt(self.make(payload), keys=self.keys, chunk=700_000), payload)

    def test_tag_and_chunk_rules(self):
        from nacl import bindings
        final = bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        message = bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        rekey = bindings.crypto_secretstream_xchacha20poly1305_TAG_REKEY
        payload = b'x' * (MiB + 10)
        cases = {
            'early final tag': self.make(payload, tags=[final, final]),
            'no final tag': self.make(payload, tags=[message, message]),
            'rekey tag': self.make(payload, tags=[rekey, final]),
            'short inner chunk': self.make(payload, chunks=[payload[:10], payload[10:]], declared_size=len(payload)),
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                code, error = code_of(decrypt, data, keys=self.keys)
                self.assertEqual(code, 'corrupt-archive', label)
        good = self.make(payload)
        self.assertEqual(decrypt(good, keys=self.keys), payload)
        reordered = good[:136] + good[136 + MiB + 17:] + good[136:136 + MiB + 17]
        self.assertEqual(code_of(decrypt, reordered, keys=self.keys)[0], 'corrupt-archive')

    def test_a_source_that_ends_between_two_chunks(self):
        """KEY-08, KEY-12: what came so far is authentic, but it is not everything."""
        payload = b'z' * (2 * MiB + 10)
        data = self.make(payload)
        for chunks in (0, 1, 2):
            with self.subTest(chunks=chunks):
                code, error = code_of(decrypt, data[:136 + chunks * (MiB + 17)], size=len(data), keys=self.keys)
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', 'truncated ciphertext'))

    def test_reads_are_bounded(self):
        reader = hasecuretar.DecryptReader(io.BytesIO(self.make(b'y' * (3 * MiB))), 3 * MiB + 3 * 17 + 136, self.keys)
        self.assertLessEqual(len(reader.read(10 * MiB)), MiB)
        reader.close()


class MissingPackageTests(unittest.TestCase):
    """The Ubuntu packages are imported only when a member of that kind is read; their absence names the package."""

    def blocked(self, *names):
        modules = {name: None for name in names}
        return mock.patch.dict(sys.modules, modules)

    def test_without_nacl(self):
        data, _tarinfo = hx.member_bytes(hx.fixture('v3_gzip.tar'), 'supervisor.tar.gz')
        with self.blocked('nacl', 'nacl.bindings', 'nacl.exceptions', 'nacl.pwhash', 'nacl.pwhash.argon2id'):
            code, error = code_of(decrypt, data)
        self.assertEqual(code, 'internal-error')
        self.assertEqual(error.message, '系統缺少 python3-nacl，無法解開 2026 年 3 月以後的 HA 加密備份。請重新執行安裝程式。')

    def test_without_cryptography(self):
        data, _tarinfo = hx.member_bytes(hx.fixture('v2_gzip.tar'), 'supervisor.tar.gz')
        names = [name for name in list(sys.modules) if name == 'cryptography' or name.startswith('cryptography.')]
        with self.blocked('cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
                          'cryptography.hazmat.primitives.ciphers', *names):
            code, error = code_of(decrypt, data)
        self.assertEqual(code, 'internal-error')
        self.assertIn('python3-cryptography', error.message)

    def test_plain_members_need_neither(self):
        from woowbackup import habackup
        with self.blocked('nacl', 'cryptography'), habackup.open_backup(hx.fixture('plain_gzip.tar')) as ha:
            with ha.open_member(f'{hx.ODOO}.tar.gz') as stream:
                self.assertTrue(list(habackup.iter_entries(stream)))


if __name__ == '__main__':
    unittest.main()
