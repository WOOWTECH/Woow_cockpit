"""Key management and emergency kit tests (team E1)."""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[2] / 'backup-engine'
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from woowbackup import keys  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.keys import KeyStore, key_id_for, normalize_secret  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

HAVE_AGE = bool(shutil.which('age') and shutil.which('age-keygen') and shutil.which('zstd'))
needs_age = unittest.skipUnless(HAVE_AGE, 'needs age, age-keygen and zstd (installed in CI / woowbk test runner)')

# A syntactically valid bech32 secret (checksum verified by age-keygen in the age-backed tests below).
CHARSET = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def assert_no_key_material(testcase, exc):
    """The message may *mention* the AGE-SECRET-KEY-1 prefix, but must never echo a key body."""
    text = exc.message + repr(exc.details)
    testcase.assertIsNone(re.search(r'AGE-SECRET-KEY-1[0-9A-Za-z]{8,}', text), text)
    testcase.assertIsNone(re.search(r'[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{20,}', text.upper()), text)


def fresh_secret():
    out = subprocess.run(['age-keygen'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    return next(line for line in out.decode().splitlines() if line.startswith('AGE-SECRET-KEY-1'))


class PureTests(unittest.TestCase):
    def assert_no_key_material(self, exc):
        assert_no_key_material(self, exc)

    def test_key_id_vector(self):
        recipient = 'age1clhpxav4304etj3dgzylaqx2srph77ay6da4qvjjqn3qyczfu3rqzjyk77'
        digest = hashlib.sha256(recipient.encode()).hexdigest()[:16].upper()
        expected = '-'.join(digest[i:i + 4] for i in range(0, 16, 4))
        self.assertEqual(key_id_for(recipient), expected)
        self.assertRegex(key_id_for(recipient), r'^[0-9A-F]{4}(-[0-9A-F]{4}){3}$')

    def test_normalize_secret_accepts_key_line_and_identity_file(self):
        key = 'AGE-SECRET-KEY-1' + (CHARSET * 2)[:58]
        self.assertEqual(normalize_secret(key), key)
        self.assertEqual(normalize_secret(f'  {key}  \r\n'), key)
        self.assertEqual(normalize_secret(key.lower()), key)
        self.assertEqual(normalize_secret(f'# created: x\n# public key: age1xyz\n{key}\n'), key)

    def test_normalize_secret_rejects(self):
        key = 'AGE-SECRET-KEY-1' + (CHARSET * 2)[:58]
        for bad in (None, '', 123, key + '\n' + key, key[:-1], key + 'Q', key.replace('Q', 'B', 1), 'hello',
                    key + '\x00', 'x' * 5000, f'{key}\nextra line', key.replace('AGE-SECRET-KEY-1', 'AGE-PLUGIN-X-1')):
            with self.subTest(bad=str(bad)[:30]):
                with self.assertRaises(BackupError) as ctx:
                    normalize_secret(bad)
                self.assertEqual(ctx.exception.code, 'invalid-request')
                self.assert_no_key_material(ctx.exception)

    def test_empty_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = KeyStore(Paths(base=Path(tmp)))
            self.assertIsNone(store.device_key())
            self.assertEqual(store.identities(), [])
            self.assertIsNone(store.find('ABCD-EF01-2345-6789'))
            self.assertIsNone(store.find('../../etc'))
            for call in (store.kit_text, store.kit_filename):
                with self.assertRaises(BackupError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, 'no-device-key')
            with self.assertRaises(BackupError) as ctx:
                store.confirm_kit('ABCD-EF01-2345-6789')
            self.assertEqual(ctx.exception.code, 'no-device-key')

    def test_temp_identity_rejects_bad_names_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = KeyStore(Paths(base=Path(tmp)))
            for name in ('../escape', 'a/b', '', '.hidden', 'x' * 200, None):
                with self.subTest(name=name):
                    with self.assertRaises(BackupError) as ctx:
                        with store.temp_identity('AGE-SECRET-KEY-1' + 'Q' * 58, name):
                            pass
                    self.assertEqual(ctx.exception.code, 'invalid-request')
            self.assertFalse((Path(tmp) / 'run').exists())


@needs_age
class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-keys-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.paths = Paths(base=self.base)
        self.store = KeyStore(self.paths)

    def recipient_of(self, path):
        with open(path, 'rb') as handle:
            return subprocess.run(['age-keygen', '-y'], stdin=handle, stdout=subprocess.PIPE,
                                  check=True).stdout.decode().strip()

    def test_ensure_device_key_creates_private_files(self):
        info, created = self.store.ensure_device_key()
        self.assertTrue(created)
        self.assertEqual(info.kind, 'device')
        self.assertRegex(info.key_id, r'^[0-9A-F]{4}(-[0-9A-F]{4}){3}$')
        self.assertEqual(info.key_id, key_id_for(info.recipient))
        self.assertEqual(Path(info.path), self.paths.keys / f'device-{info.key_id}.key')
        self.assertEqual(mode(self.paths.keys), 0o700)
        self.assertEqual(mode(info.path), 0o600)
        self.assertEqual(mode(self.paths.keys / 'keys.json'), 0o600)
        self.assertEqual(self.recipient_of(info.path), info.recipient)
        self.assertRegex(info.created, r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        self.assertFalse(info.kit_confirmed)
        content = Path(info.path).read_text()
        self.assertIn(f'# public key: {info.recipient}', content)
        self.assertEqual(len([line for line in content.splitlines() if line.startswith('AGE-SECRET-KEY-1')]), 1)
        again, created_again = self.store.ensure_device_key()
        self.assertFalse(created_again)
        self.assertEqual(again, info)
        self.assertEqual(KeyStore(self.paths).device_key(), info)
        self.assertEqual(info.as_dict(), {'key_id': info.key_id, 'kind': 'device', 'created': info.created,
                                          'kit_confirmed': False})

    def test_device_identity_decrypts_with_age(self):
        info, _ = self.store.ensure_device_key()
        cipher = subprocess.run(['age', '-r', info.recipient], input=b'hello', stdout=subprocess.PIPE,
                                check=True).stdout
        plain = subprocess.run(['age', '-d', '-i', str(info.path)], input=cipher, stdout=subprocess.PIPE,
                               check=True).stdout
        self.assertEqual(plain, b'hello')

    def test_secret_never_in_argv_or_environment(self):
        calls = []
        real_run = subprocess.run

        def spy(argv, *args, **kwargs):
            calls.append((list(argv), dict(kwargs.get('env') or {}), kwargs.get('input')))
            return real_run(argv, *args, **kwargs)

        secret = fresh_secret()  # generated by the test itself, outside the spy
        with mock.patch.object(keys.subprocess, 'run', side_effect=spy):
            info, _ = self.store.ensure_device_key()
            imported = self.store.import_key(secret)
            kit = self.store.kit_text()
            with self.store.temp_identity(secret, 'key-test') as path:
                self.assertTrue(path.exists())
        self.assertTrue(calls)
        secrets_seen = {secret, next(line for line in kit.splitlines() if line.startswith('AGE-SECRET-KEY-1'))}
        for argv, env, stdin in calls:
            blob = ' '.join(argv) + ' ' + ' '.join(f'{k}={v}' for k, v in env.items())
            self.assertNotIn('AGE-SECRET-KEY', blob)
            for value in secrets_seen:
                self.assertNotIn(value, blob)
            self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL'})
        self.assertTrue(any(argv[-1] == '-y' and stdin and secret.encode() in stdin for argv, _, stdin in calls),
                        'age-keygen -y received the secret on stdin')
        self.assertEqual(imported.kind, 'imported')
        self.assertNotEqual(imported.key_id, info.key_id)

    def test_import_identities_and_find(self):
        device, _ = self.store.ensure_device_key()
        secret = fresh_secret()
        imported = self.store.import_key(f'\n  {secret.lower()}  \n')
        self.assertEqual(imported.kind, 'imported')
        self.assertEqual(Path(imported.path).name, f'imported-{imported.key_id}.key')
        self.assertEqual(mode(imported.path), 0o600)
        self.assertEqual(self.recipient_of(imported.path), imported.recipient)
        self.assertEqual(self.store.import_key(secret), imported, 'importing twice is idempotent')
        device_secret = next(line for line in Path(device.path).read_text().splitlines()
                             if line.startswith('AGE-SECRET-KEY-1'))
        self.assertEqual(self.store.import_key(device_secret), device, 'device key is not duplicated')
        second = self.store.import_key(fresh_secret())
        ids = self.store.identities()
        self.assertEqual(ids[0], device, 'device key first')
        self.assertEqual({i.key_id for i in ids[1:]}, {imported.key_id, second.key_id})
        self.assertEqual(self.store.find(imported.key_id), imported)
        self.assertEqual(self.store.find(device.key_id), device)
        self.assertIsNone(self.store.find('0000-0000-0000-0000'))
        self.assertEqual(sorted(p.name for p in self.paths.keys.iterdir()),
                         sorted(['.lock', 'keys.json', f'device-{device.key_id}.key',
                                 f'imported-{imported.key_id}.key', f'imported-{second.key_id}.key']))

    def test_import_rejects_bad_keys_without_writing(self):
        self.store.ensure_device_key()
        before = sorted(p.name for p in self.paths.keys.iterdir())
        valid = fresh_secret()
        broken_checksum = valid[:-1] + ('Q' if valid[-1] != 'Q' else 'P')
        for bad in (broken_checksum, 'AGE-SECRET-KEY-1' + 'Q' * 58, valid + '\n' + fresh_secret(), 'not a key', ''):
            with self.subTest(bad=bad[:24]):
                with self.assertRaises(BackupError) as ctx:
                    self.store.import_key(bad)
                self.assertEqual(ctx.exception.code, 'invalid-request')
                assert_no_key_material(self, ctx.exception)
        self.assertEqual(sorted(p.name for p in self.paths.keys.iterdir()), before)

    def test_kit_text_and_confirmation(self):
        info, _ = self.store.ensure_device_key()
        kit = self.store.kit_text()
        secret_line = next(line for line in Path(info.path).read_text().splitlines()
                           if line.startswith('AGE-SECRET-KEY-1'))
        for needle in (info.key_id, info.created, secret_line, '金鑰 ID', '建立時間', '建立設備', '另一台設備',
                       '遺失', '永遠無法還原', '.woowbackup'):
            self.assertIn(needle, kit)
        hostname = os.uname().nodename
        self.assertIn(hostname, kit)
        self.assertRegex(self.store.kit_filename(), r'^woowtech-backup-key-[a-z0-9-]+-[0-9A-F-]{19}\.txt$')
        with self.assertRaises(BackupError) as ctx:
            self.store.confirm_kit('0000-0000-0000-0000')
        self.assertEqual(ctx.exception.code, 'invalid-request')
        with self.assertRaises(BackupError) as ctx:
            self.store.confirm_kit('not-an-id')
        self.assertEqual(ctx.exception.code, 'invalid-request')
        with self.assertRaises(BackupError) as ctx:
            self.store.confirm_kit(info.key_id + '\n')
        self.assertEqual(ctx.exception.code, 'invalid-request')
        self.assertIsNone(self.store.find(info.key_id + '\n'))
        confirmed = self.store.confirm_kit(info.key_id)
        self.assertTrue(confirmed.kit_confirmed)
        self.assertTrue(KeyStore(self.paths).device_key().kit_confirmed, 'persisted in keys.json')
        self.assertEqual(mode(self.paths.keys / 'keys.json'), 0o600)
        self.assertNotIn('AGE-SECRET-KEY', (self.paths.keys / 'keys.json').read_text())

    def test_temp_identity_lifecycle(self):
        secret = fresh_secret()
        with self.store.temp_identity(secret, 'key-j20261113T020000Z-a1b2c3d4') as path:
            self.assertEqual(path, self.paths.run / 'key-j20261113T020000Z-a1b2c3d4')
            self.assertEqual(mode(path), 0o600)
            self.assertEqual(mode(self.paths.run), 0o700)
            self.assertEqual(path.read_text().strip(), secret)
        self.assertFalse(path.exists())
        with self.assertRaises(RuntimeError):
            with self.store.temp_identity(secret, 'key-boom') as path:
                raise RuntimeError('job failed')
        self.assertFalse(path.exists(), 'deleted on exceptions too')
        stale = self.paths.run / 'key-stale'
        stale.write_text('old')
        with self.store.temp_identity(secret, 'key-stale') as path:
            self.assertEqual(path.read_text().strip(), secret)
        self.assertFalse(stale.exists())
        victim = self.base / 'victim'
        victim.write_text('do not touch')
        (self.paths.run / 'key-link').symlink_to(victim)
        with self.store.temp_identity(secret, 'key-link') as path:
            self.assertFalse(path.is_symlink())
        self.assertEqual(victim.read_text(), 'do not touch')
        with self.assertRaises(BackupError) as ctx:
            with self.store.temp_identity('AGE-SECRET-KEY-1' + 'Q' * 58, 'key-bad'):
                pass
        self.assertEqual(ctx.exception.code, 'invalid-request')
        self.assertFalse((self.paths.run / 'key-bad').exists())

    def test_recovers_without_keys_json_and_tightens_modes(self):
        info, _ = self.store.ensure_device_key()
        imported = self.store.import_key(fresh_secret())
        (self.paths.keys / 'keys.json').write_text('{broken json')
        self.assertEqual(self.store.device_key().key_id, info.key_id, 'key files are the source of truth')
        again, created = self.store.ensure_device_key()
        self.assertFalse(created, 'must adopt the existing key, never mint a replacement')
        self.assertEqual(again.key_id, info.key_id)
        (self.paths.keys / 'keys.json').unlink()
        os.chmod(imported.path, 0o644)
        self.assertEqual({i.key_id for i in self.store.identities()}, {info.key_id, imported.key_id})
        self.assertEqual(mode(imported.path), 0o600, 'loose permissions tightened')

    def test_symlinked_or_foreign_key_files_are_ignored(self):
        info, _ = self.store.ensure_device_key()
        outside = self.base / 'outside.key'
        outside.write_text(Path(info.path).read_text())
        fake_id = '0000-0000-0000-0000'
        (self.paths.keys / f'imported-{fake_id}.key').symlink_to(outside)
        (self.paths.keys / 'imported-garbage.key').write_text('x')
        (self.paths.keys / f'imported-{"1111-1111-1111-1111"}.key').write_text(Path(info.path).read_text())
        ids = self.store.identities()
        self.assertEqual([i.key_id for i in ids], [info.key_id], 'symlinks and mislabelled files never used')


if __name__ == '__main__':
    unittest.main()


def old_layout_kit(key_id, created, host, secret):
    """The emergency kit as engines before 2026-11-13 wrote it (prose without '#'): still accepted whole."""
    return '\n'.join([
        'woowtech Cockpit 備份緊急金鑰', '================================', '',
        '這是還原加密備份檔（.woowbackup）所需的金鑰。請立即把這個檔案保存到這台設備以外的安全位置，',
        '例如密碼管理器、加密隨身碟，或列印後上鎖保管。', '',
        f'金鑰 ID：{key_id}', f'建立時間：{created}（UTC）', f'建立設備：{host}', '',
        '緊急金鑰（請完整複製下一行，包含開頭的 AGE-SECRET-KEY-1）：', '', secret, '',
        '如何在另一台設備還原', '1. 在目標設備登入 Cockpit，以管理員身分開啟「備份與還原」頁面。',
        '2. 到「從檔案還原」，上傳你下載保存的 .woowbackup 備份檔。',
        '3. 頁面要求輸入金鑰時，貼上上方以 AGE-SECRET-KEY-1 開頭的整行金鑰。',
        '   若選擇在該設備保存金鑰，日後還原同一金鑰加密的備份時就不必再次輸入。',
        '4. 檢查預檢結果與受影響的應用，確認後開始還原。', '', '重要警告',
        '- 遺失這把金鑰後，以它加密的備份將永遠無法還原；任何人（包括 woowtech）都無法替你找回或重設。',
        '- 這台設備故障或重新安裝時，設備上保存的金鑰也會一起消失，屆時只能依靠這份緊急金鑰。',
        '- 任何同時取得這把金鑰與備份檔的人，都能讀取備份中的資料庫、檔案與應用機密。',
        '  請勿以電子郵件、聊天訊息或公開雲端分享傳送，也不要和備份檔存放在同一處。', ''])


@needs_age
class KitIdentityFileTests(unittest.TestCase):
    """The kit is an age identity file (`age -d -i kit.txt`), and key import accepts new and old kits whole."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        self.store = KeyStore(self.paths)
        self.info, _ = self.store.ensure_device_key()

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_line_but_the_key_is_a_comment(self):
        kit = self.store.kit_text()
        lines = kit.split('\n')
        self.assertEqual(lines[-1], '', 'ends with a newline')
        keys_ = [line for line in lines[:-1] if not line.startswith('#')]
        self.assertEqual(len(keys_), 1)
        self.assertRegex(keys_[0], r'^AGE-SECRET-KEY-1[0-9A-Z]{58}$')
        self.assertTrue(all(line == '#' or line.startswith('# ') for line in lines[:-1] if line != keys_[0]))
        self.assertIn(f'# public key: {self.info.recipient}', lines)
        self.assertEqual(lines[0], f'# {keys.KIT_TITLE}')

    def test_age_decrypts_with_the_kit_file(self):
        kit_file = Path(self.tmp.name) / 'woowtech-backup-key.txt'
        kit_file.write_text(self.store.kit_text(), encoding='utf-8')
        cipher = subprocess.run(['age', '-r', self.info.recipient], input=b'payload of a backup',
                                stdout=subprocess.PIPE, check=True).stdout
        plain = subprocess.run(['age', '-d', '-i', str(kit_file)], input=cipher, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True).stdout
        self.assertEqual(plain, b'payload of a backup')

    def test_import_accepts_new_and_old_kits_whole(self):
        kit = self.store.kit_text()
        secret = next(line for line in kit.splitlines() if line.startswith('AGE-SECRET-KEY-1'))
        self.assertEqual(normalize_secret(kit), secret)
        self.assertEqual(normalize_secret(kit.replace('\n', '\r\n')), secret)
        self.assertEqual(self.store.import_key(kit), self.info, 'the device key is not duplicated')
        other = fresh_secret()
        old = old_layout_kit('ABCD-EF01-2345-6789', '2026-11-01T00:00:00Z', 'dev-a', other)
        self.assertEqual(normalize_secret(old), other)
        self.assertEqual(normalize_secret('﻿' + old), other, 'a byte order mark from an editor')
        imported = self.store.import_key(old)
        self.assertEqual((imported.kind, imported.recipient), ('imported', keys.recipient_for_secret(other)))

    def test_old_layout_with_two_keys_or_without_one_is_refused(self):
        two = old_layout_kit('ABCD-EF01-2345-6789', 'x', 'dev-a', fresh_secret()) + fresh_secret() + '\n'
        none = old_layout_kit('ABCD-EF01-2345-6789', 'x', 'dev-a', 'not a key')
        prose = 'some notes\n' + fresh_secret() + '\n'  # not a kit: a key with extra text stays ambiguous
        for bad in (two, none, prose):
            with self.subTest(bad=bad[:20]), self.assertRaises(BackupError) as caught:
                normalize_secret(bad)
            assert_no_key_material(self, caught.exception)
