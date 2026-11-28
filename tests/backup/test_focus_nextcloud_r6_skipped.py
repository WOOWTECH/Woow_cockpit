"""Offline tests of the R6 skipped-entries case: the derivation builder (focus_nextcloud_r6_skipped_derive) and the case
driver (focus_nextcloud_r6_skipped). No lab, device, credential or host podman.

The fixtures are small generated HA-shaped backups encrypted with SecureTar v3 under a generated key (hafixtures'
test-only v3 writer, the share and add-on members of test_ha_nextcloud); the real 4.47 GB fixture is never opened. The
product is THIS repository's backup-engine (tests/backup/__init__.py): its reader (habackup, hasecuretar), its whole check
and conversion in test_ha_nextcloud's fake world, and its texts and keys (ha_nextcloud, haissues).
"""
import contextlib
import copy
import datetime
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import secrets as token_source
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / 'e2e/lab'
sys.path.insert(0, str(LAB))
import focus_nextcloud_r6 as r6   # noqa: E402
import focus_nextcloud_r6_case as case   # noqa: E402
import focus_nextcloud_r6_cold as cold   # noqa: E402
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_skipped as skipped   # noqa: E402
import focus_nextcloud_r6_skipped_derive as derive   # noqa: E402
import focus_nextcloud_r6_upload as upload   # noqa: E402
import focus_nextcloud_r6_wake as wake   # noqa: E402
from woowbackup import cli, flows, habackup, hasecuretar, haimport, haissues, hacommon, ha_nextcloud   # noqa: E402
from woowbackup.errors import BackupError   # noqa: E402

from tests.backup import hafixtures as hx   # noqa: E402
from tests.backup import test_ha_nextcloud as product_case   # noqa: E402  (its NextcloudCase: the product, fake world)

REPO = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
# A generated key for these tests only (never a real HA key); every member of one backup shares the root salt pair,
# like a real v3 backup (one Argon2id per backup).
PASSWORD = 'unit-' + token_source.token_hex(10)
ROOT_SALT, VALIDATION_SALT = os.urandom(16), os.urandom(16)
OUTSIDE_LINK = {'name': 'woowtechbot-image-test/link', 'type': 'symlink', 'linkname': 'big.bin'}   # outside the data dir


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def v3(plaintext, password=PASSWORD):
    return hx.v3_encrypt(plaintext, password, salts=(ROOT_SALT, VALIDATION_SALT, os.urandom(16)))


def supervisor_member():
    return gzip.compress(hx.tar_bytes([{'name': '.', 'type': 'dir'}]), mtime=0)


def original_backup(*, share=None, share_member=None, password=PASSWORD, doc=None, members=None):
    """A small encrypted HA-shaped Nextcloud backup like the original full-share fixture: the add-on, the share folder
    (Nextcloud's data directory with users' files, an updater folder, an Office cache, a symlink OUTSIDE the data
    directory), supervisor.tar.gz and backup.json (protected, compressed), every member SecureTar v3."""
    share = product_case.share_tar(extra=[OUTSIDE_LINK]) if share is None else share
    items = members if members is not None else [
        (f'{product_case.SLUG}.tar.gz', v3(product_case.addon_tar(), password)),
        ('share.tar.gz', share_member if share_member is not None else v3(share, password)),
        ('supervisor.tar.gz', v3(supervisor_member(), password))]
    return hx.outer_bytes(items, doc or hx.ha_doc(addons=(product_case.SLUG,), folders=('share',), protected=True))


def write(tmp, name, data):
    path = Path(tmp) / name
    path.write_bytes(data)
    return path


SALT, HEADER = bytes(range(16)), bytes(range(100, 124))


def derivation(path, *, password=PASSWORD, salt=SALT, header=HEADER, **kwargs):
    return derive.Derivation(path, password, derivation_salt=salt, stream_header=header, **kwargs)


def derived_bytes(path, **kwargs):
    d = derivation(path, **kwargs)
    d.prepare()
    stream = d.stream()
    data = stream.read()
    return d, stream, data


def outer_members(data):
    """[(name, TarInfo, data)] of an outer tar (test side, Python's tarfile)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        return [(m.name, m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()]


def member_plaintext(data, name='share.tar.gz', password=PASSWORD):
    """The decrypted (still compressed) plaintext of one member, through the product's own DecryptReader."""
    raw = dict((n, d) for n, _i, d in outer_members(data))[name]
    reader = hasecuretar.DecryptReader(io.BytesIO(raw), len(raw), hasecuretar.Keys(password), name=name)
    out = reader.read()
    reader.finish()
    return out


def member_tar(data, name='share.tar.gz', password=PASSWORD):
    """The inner tar of one member through the product's own member stream (decrypt and gunzip)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = write(tmp, 'b.tar', data)
        stream = habackup.open_member(path, name, password=password)
        try:
            out = stream.read()
            stream.finish()
        finally:
            stream.close()
    return out


# ====================================================================== the v3 writer

class V3WriterTests(unittest.TestCase):
    ROOT = None

    @classmethod
    def setUpClass(cls):
        from nacl.pwhash import argon2id
        cls.ROOT = argon2id.kdf(32, PASSWORD.encode(), ROOT_SALT, opslimit=8, memlimit=16 * MIB)
        cls.VKEY = hasecuretar._blake2b_subkey(cls.ROOT, VALIDATION_SALT)

    def encrypt(self, plaintext, pieces=None, header=HEADER):
        writer = derive.V3Writer(self.ROOT, len(plaintext), root_salt=ROOT_SALT, validation_salt=VALIDATION_SALT,
                                 validation_key=self.VKEY, derivation_salt=SALT, stream_header=header)
        out = [writer.header]
        for piece in pieces or [plaintext]:
            out.append(writer.write(piece))
        out.append(writer.close())
        return b''.join(out)

    def test_every_size_round_trips_through_the_products_reader_and_has_its_exact_size(self):
        for size in (0, 1, MIB - 1, MIB, MIB + 1, 2 * MIB + 17):
            with self.subTest(size=size):
                plain = os.urandom(size)
                pieces = [plain[i:i + 300001] for i in range(0, size, 300001)] or [b'']
                blob = self.encrypt(plain, pieces)
                self.assertEqual(len(blob), derive.member_size(size))
                self.assertEqual(hasecuretar.ciphertext_ok('v3', len(blob), blob[:48]), True)
                reader = hasecuretar.DecryptReader(io.BytesIO(blob), len(blob), hasecuretar.Keys(PASSWORD))
                self.assertEqual((reader.kind, reader.plaintext_size), ('v3', size))
                self.assertEqual(reader.read(), plain)
                reader.finish()

    def test_a_recorded_header_gives_the_stream_init_push_would_have_given(self):
        from nacl import bindings as b
        key = os.urandom(32)
        pushed = b.crypto_secretstream_xchacha20poly1305_state()
        header = b.crypto_secretstream_xchacha20poly1305_init_push(pushed, key)
        replayed = b.crypto_secretstream_xchacha20poly1305_state()
        b.crypto_secretstream_xchacha20poly1305_init_pull(replayed, header, key)
        for tag in (b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, b.crypto_secretstream_xchacha20poly1305_TAG_FINAL):
            message = os.urandom(1000)
            self.assertEqual(b.crypto_secretstream_xchacha20poly1305_push(replayed, message, None, tag),
                             b.crypto_secretstream_xchacha20poly1305_push(pushed, message, None, tag))

    def test_the_wrong_key_and_a_writer_fed_too_much_or_too_little_are_refused(self):
        blob = self.encrypt(b'x' * 100)
        with self.assertRaises(BackupError) as caught:
            hasecuretar.DecryptReader(io.BytesIO(blob), len(blob), hasecuretar.Keys(PASSWORD + 'x'))
        self.assertEqual(caught.exception.code, 'wrong-key')
        writer = derive.V3Writer(self.ROOT, 10, root_salt=ROOT_SALT, validation_salt=VALIDATION_SALT,
                                 validation_key=self.VKEY, derivation_salt=SALT, stream_header=HEADER)
        with self.assertRaisesRegex(ValueError, 'v3-writer-overflow'):
            writer.write(b'y' * 11)
        writer = derive.V3Writer(self.ROOT, 10, root_salt=ROOT_SALT, validation_salt=VALIDATION_SALT,
                                 validation_key=self.VKEY, derivation_salt=SALT, stream_header=HEADER)
        writer.write(b'y' * 9)
        with self.assertRaisesRegex(ValueError, 'v3-writer-short'):
            writer.close()


# ====================================================================== the derivation

class DerivationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.original = original_backup()
        self.path = write(self.tmp, 'original.tar', self.original)

    def test_the_derived_backup_is_the_original_plus_exactly_the_reviewed_entries(self):
        d, stream, data = derived_bytes(self.path, expected_sha=sha(self.original), expected_size=len(self.original))
        self.assertTrue(stream.ended and d.original_ok)
        self.assertEqual((len(data), stream.count, stream.sha256), (d.plan['derived_bytes'], len(data), sha(data)))
        self.assertEqual(len(data) % derive.RECORD, 0)
        before, after = outer_members(self.original), outer_members(data)
        self.assertEqual([n for n, _i, _d in after], [n for n, _i, _d in before])   # every entry, in its order
        for (name, info, raw), (_n, info2, raw2) in zip(before, after):
            if name != 'share.tar.gz':
                self.assertEqual(raw2, raw, name)
                self.assertEqual((info2.mtime, info2.mode, info2.pax_headers), (info.mtime, info.mode, info.pax_headers))
            else:
                self.assertEqual((info2.mtime, info2.pax_headers), (info.mtime, info.pax_headers))   # only size changed
                self.assertEqual(info2.size, d.plan['derived_member_bytes'])
        # the outer header regions of the unchanged members are byte for byte the original's
        offsets = {name: off for off, name, _t in hx.header_offsets(self.original)}
        offsets2 = {name: off for off, name, _t in hx.header_offsets(data)}
        self.assertEqual(offsets2[product_case.SLUG + '.tar.gz'], offsets[product_case.SLUG + '.tar.gz'])
        first = offsets[product_case.SLUG + '.tar.gz']
        self.assertEqual(data[:d.plan['share']['header_offset']], self.original[:d.plan['share']['header_offset']])
        self.assertLess(first, d.plan['share']['header_offset'])
        # the share plaintext: the reviewed gzip member, then the original's gzip stream byte for byte
        plain, plain2 = member_plaintext(self.original), member_plaintext(data)
        self.assertEqual(plain2, derive.PREFIX_GZIP + plain)
        # decompressed by the product's member stream: the reviewed entries, then the original inner tar byte for byte
        tar, tar2 = member_tar(self.original), member_tar(data)
        self.assertEqual(tar2, derive.ADDED_TAR + tar)
        names = [m.name for m in tarfile.open(fileobj=io.BytesIO(derive.ADDED_TAR + bytes(1024))).getmembers()]
        self.assertEqual(names, [derive.DATADIR + '/' + derive.FOLDER, derive.DATADIR + '/' + derive.CONTROL,
                                 derive.DATADIR + '/' + derive.HTACCESS, derive.DATADIR + '/' + derive.LINK])
        facts = d.facts(stream)
        self.assertEqual(facts['original'], {'name': 'original.tar', 'bytes': len(self.original), 'sha256': sha(self.original),
                                             'expected_sha256_matched': True})
        self.assertEqual(facts['derived'], {'bytes': len(data), 'sha256': sha(data)})
        share = next(m for m in facts['members'] if m['derived'])
        self.assertEqual((share['plaintext_sha256'], share['prefix_gzip']['sha256']), (sha(plain), sha(derive.PREFIX_GZIP)))
        self.assertEqual([r['name'] for r in facts['added']], [x['name'] for x in derive.ADDED])
        self.assertEqual(facts['expected_check'], {derive.SYMLINK_ID: {'items': [derive.SYMLINK_ITEM], 'key': derive.SYMLINK_KEY},
                                                   derive.HTACCESS_ID: {'items': [derive.HTACCESS_ITEM],
                                                                        'key': derive.HTACCESS_KEY}})
        self.assertNotIn(PASSWORD, json.dumps(facts))

    def test_the_stream_is_the_same_for_the_recorded_salt_and_header_and_another_header_is_another_valid_file(self):
        _d, _s, one = derived_bytes(self.path)
        _d, _s, two = derived_bytes(self.path)
        self.assertEqual(one, two)
        _d, _s, other = derived_bytes(self.path, header=bytes(24))
        self.assertNotEqual(other, one)
        self.assertEqual(len(other), len(one))
        self.assertEqual(member_tar(other), member_tar(one))

    def test_the_keys_are_the_products_own_for_exactly_these_names(self):
        self.assertEqual(derive.SYMLINK_KEY, haissues.Issue(derive.SYMLINK_ID, 'confirm', 'x', [derive.SYMLINK_ITEM])
                         .key('nextcloud'))
        self.assertEqual(derive.HTACCESS_KEY, haissues.Issue(derive.HTACCESS_ID, 'confirm', 'x',
                                                             haissues.Names([derive.HTACCESS_ITEM])).key('nextcloud'))
        self.assertEqual(ha_nextcloud.ISSUES[derive.SYMLINK_ID], 'confirm')
        self.assertEqual(ha_nextcloud.ISSUES[derive.HTACCESS_ID], 'confirm')
        self.assertEqual(derive.KEYS, tuple(sorted((derive.SYMLINK_KEY, derive.HTACCESS_KEY))))

    def test_the_wrong_key_is_refused_before_a_single_derived_byte(self):
        d = derivation(self.path, password=PASSWORD + '-wrong')
        with self.assertRaises(BackupError) as caught:
            d.prepare()
        self.assertEqual(caught.exception.code, 'wrong-key')
        self.assertIsNone(d.plan)
        with self.assertRaisesRegex(ValueError, 'prepare-once-stream-once'):
            d.stream()

    def test_another_original_than_the_bound_one_never_gets_its_last_bytes(self):
        d = derivation(self.path, expected_sha='0' * 64)
        d.prepare()
        stream = d.stream()
        got = []
        with self.assertRaisesRegex(ValueError, 'original-sha256'):
            for piece in stream.pieces():
                got.append(piece)
        self.assertLess(sum(map(len, got)), d.plan['derived_bytes'])
        self.assertFalse(d.original_ok)
        with self.assertRaisesRegex(ValueError, 'original-size'):
            derivation(self.path, expected_size=len(self.original) + 1).prepare()

    def test_a_file_that_changed_after_the_preflight_is_refused(self):
        d = derivation(self.path)
        d.prepare()
        os.utime(self.path, ns=(1, 1))
        with self.assertRaisesRegex(ValueError, 'original-changed'):
            d.stream().read()

    def test_only_a_v3_gzip_share_member_that_holds_exactly_its_announced_bytes(self):
        cases = {
            'plain backup': original_backup(members=[(f'{product_case.SLUG}.tar.gz', product_case.addon_tar()),
                                                     ('share.tar.gz', product_case.share_tar())],
                                            doc=hx.ha_doc(addons=(product_case.SLUG,), folders=('share',))),
            'no share member': original_backup(members=[(f'{product_case.SLUG}.tar.gz', v3(product_case.addon_tar()))],
                                               doc=hx.ha_doc(addons=(product_case.SLUG,), folders=(), protected=True)),
            'bytes after what the header announces': original_backup(
                share_member=v3(product_case.share_tar()) + b'trailing'),
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaisesRegex(ValueError, 'fixed-derive-'):
                derivation(write(self.tmp, 'case.tar', data)).prepare()
        twice = hx.outer_bytes([(f'{product_case.SLUG}.tar.gz', v3(product_case.addon_tar())),
                                ('share.tar.gz', v3(product_case.share_tar())), ('share.tar.gz', v3(product_case.share_tar()))],
                               hx.ha_doc(addons=(product_case.SLUG,), folders=('share',), protected=True))
        with self.assertRaisesRegex(ValueError, 'share-member'):
            derivation(write(self.tmp, 'twice.tar', twice)).prepare()
        member = v3(product_case.share_tar())
        pax_size = hx.outer_bytes([(f'{product_case.SLUG}.tar.gz', v3(product_case.addon_tar())), ('share.tar.gz', member)],
                                  hx.ha_doc(addons=(product_case.SLUG,), folders=('share',), protected=True),
                                  member_pax={'share.tar.gz': {'size': str(len(member))}})
        with self.assertRaisesRegex(ValueError, 'share-entry'):    # the one field rewritten must be the ustar field's
            derivation(write(self.tmp, 'pax-size.tar', pax_size)).prepare()
        tail = bytearray(self.original)
        tail[-1] = 1
        with self.assertRaisesRegex(ValueError, 'original-tail'):
            derivation(write(self.tmp, 'tail.tar', bytes(tail))).prepare()

    def test_the_outer_size_field_is_written_like_tarfile_writes_it(self):
        block = hx.raw_header('share.tar.gz', size=123)
        out = derive.sized(block, 4219423319 + 3000)
        self.assertTrue(habackup._checksum_ok(out))
        self.assertEqual(habackup._number(out[124:136]), 4219423319 + 3000)
        self.assertEqual(out[:124] + out[136:148] + out[156:], block[:124] + block[136:148] + block[156:])
        info = tarfile.TarInfo('share.tar.gz')
        info.size, info.mtime = 4219426319, 0
        self.assertEqual(derive.sized(info.tobuf(tarfile.USTAR_FORMAT)[:512], 4219426319), info.tobuf(tarfile.USTAR_FORMAT)[:512])
        with self.assertRaisesRegex(ValueError, 'outer-size-field'):
            derive.sized(block, 8 ** 11)


class VerifyTests(unittest.TestCase):
    """The plan's read-back of a derived stream with the product's readers (the same code the coordinator runs over the
    real fixture before any lease)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.original = original_backup()
        self.path = write(tmp.name, 'original.tar', self.original)

    def test_the_read_back_proves_every_reviewed_fact(self):
        d = derivation(self.path, expected_sha=sha(self.original), expected_size=len(self.original))
        d.prepare()
        facts, seen, checks = derive.verify(d, PASSWORD)
        self.assertEqual(checks, dict.fromkeys(checks, True), seen)
        share = seen['share']
        self.assertEqual((share['symlink_items'], share['htaccess_items']), ([derive.SYMLINK_ITEM], [derive.HTACCESS_ITEM]))
        self.assertEqual(share['keys'], {derive.SYMLINK_ID: derive.SYMLINK_KEY, derive.HTACCESS_ID: derive.HTACCESS_KEY})
        # the control file is one more file of the data directory, the left-out ones are not files of it
        plain = ha_nextcloud.scan_datadir(io.BytesIO(gzip.decompress(product_case.share_tar(extra=[OUTSIDE_LINK]))),
                                          habackup.Report(), derive.DATADIR, addon=False)
        self.assertEqual((share['files'], share['bytes']), (plain.files + 1, plain.bytes + len(derive.CONTROL_DATA)))
        self.assertEqual(facts['derived']['sha256'], sha(self.read_derived()))

    def read_derived(self):
        d = derivation(self.path)
        d.prepare()
        return d.stream().read()

    def test_a_share_member_that_already_left_something_out_is_named(self):
        share = product_case.share_tar(extra=[{'name': 'nextcloud/admin/files/site/.htaccess', 'data': b'Require all granted\n'}])
        path = write(Path(self.path).parent, 'other.tar', original_backup(share=share))
        d = derivation(path)
        d.prepare()
        _facts, seen, checks = derive.verify(d, PASSWORD)
        self.assertFalse(checks['exactly_the_reviewed_htaccess_left_out'])
        self.assertEqual(seen['share']['htaccess_items'], [derive.HTACCESS_ITEM, 'admin/files/site/.htaccess'])


# ====================================================================== the product's own check and conversion

class ProductRoundTripTests(product_case.NextcloudCase):
    """The product's real check and conversion (test_ha_nextcloud's fake world: the real habackup, hasecuretar,
    haimport, ha_nextcloud, haissues) of the original and of its derivative, with the HA key."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.original = original_backup()
        _d, _s, self.derived = derived_bytes(write(tmp.name, 'original.tar', self.original))

    def check_with_key(self, ha_id):
        return flows.run_verify(self.ctx(PASSWORD), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['nextcloud'],
                                                     'key_provided': True})['ha_check']['apps'][0]

    def convert_with_key(self, ha_id, acknowledged=None):
        params = {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['nextcloud'], 'odoo_database': None, 'test_mode': False,
                  'encrypt': True, 'key_provided': True}
        if acknowledged is not None:
            params['acknowledged'] = acknowledged
        return flows.run_backup(self.ctx(PASSWORD), params)

    def test_the_check_of_the_derivative_is_the_originals_with_exactly_the_two_reviewed_lines_more(self):
        row = self.check_with_key(self.upload(self.original))
        row2 = self.check_with_key(self.upload(self.derived))
        self.assertEqual([i for i in row['issues'] if i['level'] in ('stop', 'confirm')], [])   # like the real full share
        added = [i for i in row2['issues'] if i['level'] == 'confirm']
        self.assertEqual([(i['id'], i['items'], i['more'], i['key'], i['message']) for i in added], [
            (derive.SYMLINK_ID, [derive.SYMLINK_ITEM], 0, derive.SYMLINK_KEY, ha_nextcloud.MSG_SYMLINKS.format(count=1)),
            (derive.HTACCESS_ID, [derive.HTACCESS_ITEM], 0, derive.HTACCESS_KEY, ha_nextcloud.MSG_HTACCESS.format(count=1))])
        self.assertEqual([i for i in row2['issues'] if i['level'] != 'confirm'], row['issues'])   # every other line
        self.assertEqual(row2['warnings'], row['warnings'])
        before, after = row['nextcloud'], row2['nextcloud']
        self.assertEqual({k: (before.get(k), v) for k, v in after.items() if before.get(k) != v},
                         {'datadir_files': (before['datadir_files'], before['datadir_files'] + 1),
                          'datadir_bytes': (before['datadir_bytes'], before['datadir_bytes'] + len(derive.CONTROL_DATA))})
        self.assertEqual((row2['importable'], row2['ok'], row['ok']), (True, False, True))
        job = {'state': 'succeeded', 'result': {'ha_check': {'apps': [row2]}}}
        verdict = skipped.judge_check(job, skipped.expected_section(before))
        self.assertTrue(all(verdict[k] for k in ('base', 'lines', 'others', 'section', 'versions')), verdict)
        self.assertFalse(skipped.judge_check({'state': 'succeeded', 'result': {'ha_check': {'apps': [row]}}},
                                             skipped.expected_section(before))['lines'])

    def test_the_conversion_refuses_without_or_with_one_key_and_moves_everything_but_the_two_with_both(self):
        self.convert_with_key(self.upload(self.original))
        original_dir = product_case.members(self.world.dirs[product_case.DIRS[3]])
        self.world.dirs = {}
        derived_id = self.upload(self.derived)
        for keys, found, raised in ((None, [derive.SYMLINK_KEY], derive.SYMLINK_KEY),
                                    ([derive.SYMLINK_KEY], list(derive.KEYS), derive.HTACCESS_KEY)):
            with self.subTest(keys=keys), self.assertRaises(BackupError) as caught:
                self.convert_with_key(derived_id, None if keys is None else {'nextcloud': keys})
            self.assertEqual(caught.exception.code, 'confirmation-required')
            job = {'state': 'failed', 'error': caught.exception.as_dict(), 'result': caught.exception.result}
            ok, detail = skipped.judge_refusal(0, {'job_id': 'j1'}, job, {'a'}, {'a'}, found=found, raised=raised)
            self.assertTrue(ok, detail)
            self.assertEqual(self.world.dirs, {}, 'nothing is handed to the restore')
        with self.assertRaises(BackupError) as caught:      # the .htaccess key alone: the link line comes first
            self.convert_with_key(derived_id, {'nextcloud': [derive.HTACCESS_KEY]})
        self.assertEqual([i['key'] for i in caught.exception.as_dict()['details']['apps']['nextcloud']], [derive.SYMLINK_KEY])
        result = self.convert_with_key(derived_id, {'nextcloud': list(derive.KEYS)})
        ok, detail = skipped.judge_import_row({'result': result})
        self.assertTrue(ok, detail)
        registered = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual(sorted((c['id'], c['items']) for c in registered['confirmed']),
                         [(derive.HTACCESS_ID, [derive.HTACCESS_ITEM]), (derive.SYMLINK_ID, [derive.SYMLINK_ITEM])])
        data = product_case.members(self.world.dirs[product_case.DIRS[3]])
        self.assertEqual(sorted(set(data) - set(original_dir)),
                         ['./' + derive.FOLDER, './' + derive.CONTROL])           # the control file and its folder only
        self.assertEqual(set(original_dir) - set(data), set())
        for name, (info, content) in original_dir.items():
            info2, content2 = data[name]
            self.assertEqual((info2.type, info2.mode, info2.uid, info2.gid, info2.size, info2.linkname, content2),
                             (info.type, info.mode, info.uid, info.gid, info.size, info.linkname, content), name)
        control, body = data['./' + derive.CONTROL]
        self.assertEqual((body, control.mode, control.uid, control.gid), (derive.CONTROL_DATA, 0o644, 33, 33))
        self.assertEqual(data['./.htaccess'][1], ha_nextcloud.DATA_HTACCESS)
        self.assertFalse([n for n in data if (n.endswith('.htaccess') and n != './.htaccess') or 'control-link' in n])


# ====================================================================== the plan and its provenance

_SMALL = {}


def small_case():
    """One small generated original (named like the real fixture), the plan's provenance of it (written by the plan code
    itself) -- built once for the driver tests."""
    if not _SMALL:
        tmp = Path(tempfile.mkdtemp())
        data = original_backup()
        path = write(tmp, 'woow-b2-nextcloud-x86-enc-share-20261123.tar', data)
        provenance = tmp / 'private' / 'derivation-provenance.json'
        with patch.object(s5, 'checkout', lambda repo: ('c' * 40, True)), contextlib.redirect_stdout(io.StringIO()):
            rc = skipped.plan(provenance, fixture=path, fixture_sha=sha(data), fixture_bytes=len(data), password=PASSWORD)
        assert rc == 0, provenance.read_text()
        _SMALL.update(tmp=tmp, path=path, data=data, sha=sha(data), bytes=len(data), provenance=provenance)
    return _SMALL


def tearDownModule():
    if _SMALL:
        shutil.rmtree(_SMALL['tmp'], True)


def fixture_patches(small):
    """The driver bound to the small original instead of the real one (the real file is never opened here)."""
    return ((skipped, 'FIXTURE', small['path']), (skipped, 'FIXTURE_SHA', small['sha']),
            (skipped, 'FIXTURE_BYTES', small['bytes']), (r6, 'FIXTURE', small['path']), (r6, 'FIXTURE_SHA', small['sha']))


@contextlib.contextmanager
def bound_to(small):
    with contextlib.ExitStack() as stack:
        for target, name, value in fixture_patches(small):
            stack.enter_context(patch.object(target, name, value))
        stack.enter_context(patch.object(s5, 'checkout', lambda repo: ('c' * 40, True)))
        yield


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.small = small_case()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_plan(self, out, **changes):
        small = self.small
        kwargs = dict(fixture=small['path'], fixture_sha=small['sha'], fixture_bytes=small['bytes'], password=PASSWORD)
        kwargs.update(changes)
        text = io.StringIO()
        with patch.object(s5, 'checkout', lambda repo: ('c' * 40, True)), contextlib.redirect_stdout(text):
            rc = skipped.plan(out, **kwargs)
        return rc, text.getvalue()

    def test_the_plan_writes_a_private_provenance_once_and_it_makes_the_same_bytes_again(self):
        out = self.tmp / 'private' / 'provenance.json'
        rc, text = self.run_plan(out)
        self.assertEqual(rc, 0, text)
        self.assertEqual((stat.S_IMODE(out.stat().st_mode), stat.S_IMODE(out.parent.stat().st_mode)), (0o600, 0o700))
        for blob in (out.read_text(), text):
            self.assertNotIn(PASSWORD, blob)
        record = json.loads(out.read_text())
        self.assertEqual((record['device_access'], record['materialized'], record['status']), (False, False, 'passed'))
        with bound_to(self.small):
            prov = skipped.load_provenance(out)
        summary = json.loads(text)
        self.assertEqual((summary['derived'], summary['provenance_sha256'], summary['keys']),
                         ({'bytes': prov.derived_bytes, 'sha256': prov.derived_sha}, prov.sha256, list(derive.KEYS)))
        d = derive.Derivation(self.small['path'], PASSWORD, derivation_salt=prov.salt, stream_header=prov.header,
                              expected_sha=self.small['sha'], expected_size=self.small['bytes'])
        d.prepare()
        data = d.stream().read()
        self.assertEqual((len(data), sha(data), prov.ha_id), (prov.derived_bytes, prov.derived_sha, 'ha-' + sha(data)[:20]))
        with self.assertRaisesRegex(ValueError, 'provenance-exists'):
            self.run_plan(out)

    def test_a_failed_plan_is_recorded_and_never_admitted(self):
        for label, changes, reason in (('wrong key', {'password': PASSWORD + '-x'}, 'fixed-skipped-plan-wrong-key'),
                                       ('another original', {'fixture_sha': '0' * 64}, 'fixed-derive-original-sha256')):
            with self.subTest(case=label):
                out = self.tmp / label.replace(' ', '-') / 'p.json'
                rc, text = self.run_plan(out, **changes)
                self.assertEqual((rc, json.loads(out.read_text())['fixed_failure']), (1, reason))
                self.assertNotIn(PASSWORD, out.read_text() + text)
                with bound_to(self.small), self.assertRaisesRegex(ValueError, 'provenance-status'):
                    skipped.load_provenance(out)

    def test_a_provenance_that_is_not_exactly_the_plans_is_refused(self):
        good = json.loads(self.small['provenance'].read_text())
        share_index = next(i for i, m in enumerate(good['facts']['members']) if m['derived'])

        def changed(path, value):
            doc = copy.deepcopy(good)
            target = doc
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            return doc
        cases = [('provenance-status', changed(('status',), 'failed')),
                 ('provenance-status', changed(('checks', 'nothing_else_left_out'), False)),
                 ('provenance-builder', changed(('facts', 'builder_sha256'), '0' * 64)),
                 ('provenance-product-readers', changed(('facts', 'product_readers', 'habackup.py'), '0' * 64)),
                 ('provenance-original', changed(('facts', 'original', 'sha256'), '0' * 64)),
                 ('provenance-additions', changed(('facts', 'added'), good['facts']['added'][:3])),
                 ('provenance-share', changed(('facts', 'members', share_index, 'stream_header'), 'zz')),
                 ('provenance-derived', changed(('facts', 'derived', 'bytes'), good['facts']['derived']['bytes'] + 1))]
        for number, (reason, doc) in enumerate(cases):
            with self.subTest(reason=reason, number=number):
                path = self.tmp / ('case-%d.json' % number)
                path.write_text(json.dumps(doc))
                with bound_to(self.small), self.assertRaisesRegex(ValueError, reason):
                    skipped.load_provenance(path)
        linked = self.tmp / 'linked.json'
        os.link(self.small['provenance'], linked)
        self.addCleanup(linked.unlink)
        with bound_to(self.small), self.assertRaisesRegex(ValueError, 'provenance-file'):
            skipped.load_provenance(linked)


# ====================================================================== the device probe, run locally

class Answers(http.server.BaseHTTPRequestHandler):
    codes = {}

    def do_GET(self):   # noqa: N802 - http.server's name
        self.send_response(self.codes.get(self.path, 404))
        self.end_headers()

    def log_message(self, *args):
        pass


class DeviceProbeTests(unittest.TestCase):
    def data_dir(self, extra=()):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / '.htaccess').write_bytes(ha_nextcloud.DATA_HTACCESS)
        (root / 'admin/files').mkdir(parents=True)
        (root / 'admin/files/hello.txt').write_bytes(b'hello from HA')
        (root / derive.FOLDER).mkdir()
        (root / derive.CONTROL).write_bytes(derive.CONTROL_DATA)
        os.chmod(root / derive.CONTROL, 0o644)
        for kind in extra:
            if kind == 'htaccess':
                (root / derive.HTACCESS).write_bytes(derive.HTACCESS_DATA)
            elif kind == 'link':
                (root / derive.LINK).symlink_to(derive.LINK_TARGET)
            elif kind == 'link-elsewhere':
                (root / 'admin/files/up').symlink_to('../../../etc')
            elif kind == 'control-changed':
                (root / derive.CONTROL).write_bytes(b'changed')
            elif kind == 'no-folder':
                shutil.rmtree(root / derive.FOLDER)
            elif kind == 'protection-changed':
                (root / '.htaccess').write_bytes(b'Require all granted\n')
        return root

    def serve(self, code=403):
        handler = type('Handler', (Answers,), {'codes': {'/' + p: code for p in skipped.WEB_PATHS}})
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:%d' % server.server_address[1]

    def probe(self, root, base):
        program = skipped.programs({'EXEC': (), 'DATA_ROOT': str(root), 'BASE': base})['probe']
        p = subprocess.run([sys.executable, '-I', '-c', program], input=b'{}', capture_output=True, timeout=120)
        if p.returncode:
            raise ValueError(p.stderr.decode('utf-8', 'replace').strip().splitlines()[-1])
        return json.loads(p.stdout)

    def test_the_program_compiles_and_binds_the_real_container_paths(self):
        program = skipped.PROGRAMS['probe']
        compile(program, 'probe', 'exec')
        self.assertLess(len(program.encode()), 120 * 1024)
        self.assertIn("EXEC=('podman', 'exec', '-u', 'www-data', 'nextcloud-app')", program)
        self.assertIn("DATA_ROOT='/var/www/html/data'", program)
        self.assertIn("BASE='http://127.0.0.1:18081'", program)
        self.assertIn(f"FOLDER={derive.FOLDER!r}", program)

    def test_after_the_import_exactly_the_control_file_its_protection_and_no_left_out_entry(self):
        probe = self.probe(self.data_dir(), self.serve(403))
        verdict = skipped.judge_skipped(probe)
        self.assertEqual(verdict, dict.fromkeys(verdict, True), probe)
        self.assertEqual(probe['entries'][derive.CONTROL]['sha256'], sha(derive.CONTROL_DATA))
        self.assertNotIn(derive.CONTROL_DATA.decode(), json.dumps(probe))   # hashes only, never the bytes
        self.assertFalse(skipped.judge_before(probe))

    def test_every_left_out_or_changed_thing_is_caught(self):
        base = self.serve(403)
        for extra, verdict_name in ((('htaccess',), 'absent'), (('link',), 'absent'), (('link-elsewhere',), 'absent'),
                                    (('control-changed',), 'control'), (('protection-changed',), 'protection')):
            with self.subTest(extra=extra):
                probe = self.probe(self.data_dir(extra), base)
                self.assertFalse(skipped.judge_skipped(probe)[verdict_name], probe)
        probe = self.probe(self.data_dir(('link',)), base)
        self.assertEqual((probe['links']['count'], probe['entries'][derive.LINK]['type']), (1, 'symlink'))
        probe = self.probe(self.data_dir(('htaccess',)), base)
        self.assertEqual(probe['nested_htaccess'], {'count': 1, 'first': [derive.HTACCESS]})
        self.assertFalse(skipped.judge_skipped(self.probe(self.data_dir(), self.serve(200)))['web'])

    def test_before_the_import_the_folder_is_absent(self):
        probe = self.probe(self.data_dir(('no-folder',)), self.serve(404))
        self.assertTrue(skipped.judge_before(probe))
        self.assertEqual(set(probe['entries']), {'.htaccess'})
        self.assertFalse(skipped.judge_skipped(probe)['control'])


# ====================================================================== the verdicts

def link_issue():
    return haissues.Issue(derive.SYMLINK_ID, 'confirm', ha_nextcloud.MSG_SYMLINKS.format(count=1),
                          haissues.Names([derive.SYMLINK_ITEM]))


def htaccess_issue():
    return haissues.Issue(derive.HTACCESS_ID, 'confirm', ha_nextcloud.MSG_HTACCESS.format(count=1),
                          haissues.Names([derive.HTACCESS_ITEM]))


def settings_text(keys=('memcache.distributed', 'memcache.locking', 'redis')):
    return f'HA 的 Nextcloud 設定 {hacommon.names(keys)} 不會搬過來（以這台的設定為準）。'


SECTION = {'nextcloud_version': '35.0.1.1', 'pg_version': '16', 'users': 4, 'files': 381, 'shares': 3,
           'datadir': '/share/nextcloud', 'datadir_in_backup': True, 'datadir_files': 1500, 'datadir_bytes': 10 ** 8}


def check_job(issues=None, *, state='succeeded', section=None, **app):
    issues = [link_issue(), htaccess_issue(), *haissues.from_legacy(warnings=[settings_text()])] if issues is None else issues
    row = {'app_id': 'nextcloud', 'arch': 'amd64', 'version': '0.2.3', 'target_version': '35.0.1.1',
           'nextcloud': skipped.expected_section(SECTION) if section is None else section,
           **haissues.check_fields('nextcloud', issues)}
    row.update(app)
    return {'id': 'j20261129T100000Z-00000001', 'state': state, 'result': {'ha_check': {'apps': [row]}}}


def refusal_job(found, named, *, state='failed', code='confirmation-required', status='skipped', extra=()):
    error = haissues.confirmation_required({'nextcloud': named}, 'x')
    issues = list(found) + list(extra)
    return {'state': state, 'error': error.as_dict() if code == 'confirmation-required' else {'code': code},
            'result': {'results': [dict(haimport.convert_result('nextcloud', error, issues), status=status)]}}


class VerdictTests(unittest.TestCase):
    def test_the_section_is_the_originals_with_one_control_file_more(self):
        self.assertEqual(skipped.expected_section(SECTION), dict(SECTION, datadir_files=1501,
                                                                 datadir_bytes=10 ** 8 + len(derive.CONTROL_DATA)))
        self.assertEqual(skipped.expected_section({'users': 3}), {'users': 3})

    def test_exactly_the_two_lines_with_their_texts_and_keys_pass(self):
        verdict = skipped.judge_check(check_job(), skipped.expected_section(SECTION))
        self.assertTrue(all(verdict[k] for k in ('base', 'lines', 'others', 'section', 'versions')), verdict)

    def test_a_missing_extra_renamed_or_rekeyed_line_or_a_stop_refuses(self):
        section = skipped.expected_section(SECTION)
        other_link = haissues.Issue(derive.SYMLINK_ID, 'confirm', ha_nextcloud.MSG_SYMLINKS.format(count=2),
                                    [derive.SYMLINK_ITEM, 'nextcloud/admin/files/up'])
        cases = {'only the link': ([link_issue()], 'lines'), 'only the htaccess': ([htaccess_issue()], 'lines'),
                 'a third confirmation': ([link_issue(), htaccess_issue(),
                                           haissues.Issue('nextcloud.db-objects-skipped', 'confirm', 'x', ['f'])], 'lines'),
                 'another link too': ([other_link, htaccess_issue()], 'lines'),
                 'a stop': ([link_issue(), htaccess_issue(), haissues.Issue('nextcloud.db-objects', 'stop', 'x')], 'base'),
                 'file lists differ': ([link_issue(), htaccess_issue(), *haissues.from_legacy(warnings=[
                     ha_nextcloud.MSG_LISTS.format(count=1, names='admin')])], 'others')}
        for label, (issues, name) in cases.items():
            with self.subTest(case=label):
                self.assertFalse(skipped.judge_check(check_job(issues), section)[name])
        self.assertFalse(skipped.judge_check(check_job(section=SECTION), section)['section'])    # no control file
        self.assertFalse(skipped.judge_check(check_job(arch='unknown'), section)['versions'])
        self.assertFalse(skipped.judge_check(check_job(state='failed'), section)['base'])

    def test_the_refusals_must_stop_at_the_named_line_with_the_found_lines(self):
        ok, detail = skipped.judge_refusal(0, {'job_id': 'j1'}, refusal_job([link_issue()], [link_issue()]), {'a'}, {'a'},
                                           found=[derive.SYMLINK_KEY], raised=derive.SYMLINK_KEY)
        self.assertTrue(ok, detail)
        ok, detail = skipped.judge_refusal(0, {'job_id': 'j1'}, refusal_job([link_issue(), htaccess_issue()],
                                                                            [htaccess_issue()]), {'a'}, {'a'},
                                           found=list(derive.KEYS), raised=derive.HTACCESS_KEY)
        self.assertTrue(ok, detail)
        self.assertTrue(skipped.judge_refusal(1, {'error': {'code': 'confirmation-required'}}, None, {'a'}, {'a'},
                                              found=[], raised=derive.SYMLINK_KEY)[0])
        faults = {
            'another line named': (refusal_job([link_issue()], [htaccess_issue()]), [derive.SYMLINK_KEY], derive.SYMLINK_KEY,
                                   {'a'}),
            'converted': (refusal_job([link_issue()], [link_issue()], state='succeeded'), [derive.SYMLINK_KEY],
                          derive.SYMLINK_KEY, {'a'}),
            'other code': (refusal_job([link_issue()], [link_issue()], code='incompatible', status='failed'),
                           [derive.SYMLINK_KEY], derive.SYMLINK_KEY, {'a'}),
            'a stop': (refusal_job([link_issue()], [link_issue()], extra=[haissues.Issue('nextcloud.db-objects', 'stop', 'x')]),
                       [derive.SYMLINK_KEY], derive.SYMLINK_KEY, {'a'}),
            'backup added': (refusal_job([link_issue()], [link_issue()]), [derive.SYMLINK_KEY], derive.SYMLINK_KEY,
                             {'a', 'b'})}
        for label, (job, found, raised, after) in faults.items():
            with self.subTest(fault=label):
                self.assertFalse(skipped.judge_refusal(0, {'job_id': 'j1'}, job, {'a'}, after, found=found, raised=raised)[0])
        self.assertFalse(skipped.judge_refusal(1, {'error': {'code': 'invalid-request'}}, None, {'a'}, {'a'},
                                               found=[], raised=derive.SYMLINK_KEY)[0])

    def test_the_import_row_must_carry_both_acknowledged_lines(self):
        row = haimport.convert_result('nextcloud', None, [link_issue(), htaccess_issue()])
        self.assertTrue(skipped.judge_import_row({'result': {'results': [row]}})[0])
        for issues in ([link_issue()], [link_issue(), htaccess_issue(), haissues.Issue('nextcloud.db-objects', 'stop', 'x')]):
            row = haimport.convert_result('nextcloud', None, issues)
            self.assertFalse(skipped.judge_import_row({'result': {'results': [row]}})[0])

    def test_both_requests_carry_schema_fields_only_and_the_ha_key(self):
        for keys in (None, [derive.SYMLINK_KEY], list(derive.KEYS)):
            request = skipped.convert_request('ha-' + '1' * 20, ['nextcloud'], False, 'AAAA-BBBB', keys, 'focus-r1')
            cli.validate('ha-convert-start', request)
            self.assertEqual(request['key'], 'AAAA-BBBB')
            self.assertEqual('acknowledged' in request, keys is not None)
        self.assertEqual(skipped.Variant.convert_request('h', ['nextcloud'], False, 'k', ['x'], 'r'),
                         skipped.convert_request('h', ['nextcloud'], False, 'k', ['x'], 'r'))


# ====================================================================== bindings, lease and entry points

class ProductBindingTests(unittest.TestCase):
    def test_the_frozen_products_readers_are_the_bytes_these_tests_run(self):
        self.assertEqual(skipped.PRODUCT_COMMIT, 'b058df278d661cc6195cd40936ff6494036c63a1')
        for name, digest in derive.reader_hashes().items():
            frozen = subprocess.check_output(['git', '-C', str(REPO), 'show',
                                              f'{skipped.PRODUCT_COMMIT}:backup-engine/woowbackup/{name}'])
            self.assertEqual(sha(frozen), digest, name)
        self.assertEqual(derive.reader_hashes()['ha_nextcloud.py'], skipped.NC_SHA)


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.small = small_case()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(bound_to(self.small))
        self.prov = skipped.load_provenance(self.small['provenance'])
        self.template = skipped.lease_template(REPO, self.prov)
        self.rows = skipped.s5b.git_manifest(REPO)

    def lease(self, **changes):
        now = datetime.datetime.now(datetime.timezone.utc)
        lease = dict(self.template, not_before_utc=(now - datetime.timedelta(minutes=1)).isoformat(),
                     expires_utc=(now + datetime.timedelta(minutes=150)).isoformat())
        lease.update(changes)
        return lease

    def test_the_template_binds_this_checkout_the_plan_and_the_frozen_product(self):
        t = self.template
        self.assertEqual(sorted(t), sorted(skipped.LEASE_KEYS))
        self.assertEqual((t['source_commit'], t['product_commit'], t['phases'], t['provenance_sha256']),
                         ('c' * 40, skipped.PRODUCT_COMMIT, [skipped.PHASE], self.prov.sha256))
        self.assertEqual((t['derived_sha256'], t['derived_bytes'], t['fixture_sha256'], t['fixture_bytes']),
                         (self.prov.derived_sha, self.prov.derived_bytes, self.small['sha'], self.small['bytes']))
        self.assertEqual((t['confirmation_keys'], t['added_entries'], t['builder_sha256']),
                         (list(derive.KEYS), [x['name'] for x in derive.ADDED], derive.module_sha()))
        self.assertEqual((t['host_fixture_copy'], t['derived_materialized'], t['image_operations'], t['upload_route']),
                         (False, False, [], skipped.UPLOAD_ROUTE))
        self.assertIn('150', t['expires_utc'])

    def test_exactly_this_lease_is_admitted_and_every_field_matters(self):
        lease = self.lease()
        deadline = skipped.admit_lease(lease, 'c' * 40, REPO, self.rows, self.prov)
        self.assertGreater(deadline - datetime.datetime.now().timestamp(), skipped.HEADROOM)
        for key in skipped.LEASE_KEYS:
            if key in ('not_before_utc', 'expires_utc'):
                continue
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'fixed-'):
                skipped.admit_lease(self.lease(**{key: 'other'}), 'c' * 40, REPO, self.rows, self.prov)
        with self.assertRaisesRegex(ValueError, 'lease-fields'):
            skipped.admit_lease(dict(lease, extra=1), 'c' * 40, REPO, self.rows, self.prov)
        with self.assertRaisesRegex(ValueError, 'frozen-checkout-manifest'):
            skipped.admit_lease(lease, 'c' * 40, REPO, dict(self.rows, VERSION={'size': 1, 'sha256': '0' * 64}), self.prov)
        with self.assertRaisesRegex(ValueError, 'fixed-'):
            skipped.admit_lease(lease, 'd' * 40, REPO, self.rows, self.prov)

    def test_the_window_is_timezone_aware_current_and_leaves_headroom(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        for start, end in ((now - datetime.timedelta(minutes=1), now + datetime.timedelta(minutes=100)),
                           (now + datetime.timedelta(minutes=5), now + datetime.timedelta(minutes=200)),
                           (now - datetime.timedelta(minutes=200), now - datetime.timedelta(minutes=1))):
            with self.subTest(start=start, end=end), self.assertRaisesRegex(ValueError, 'fixed-'):
                skipped.admit_lease(self.lease(not_before_utc=start.isoformat(), expires_utc=end.isoformat()),
                                    'c' * 40, REPO, self.rows, self.prov)
        with self.assertRaisesRegex(ValueError, 'fixed-'):
            skipped.admit_lease(self.lease(not_before_utc=now.replace(tzinfo=None).isoformat()), 'c' * 40, REPO, self.rows,
                                self.prov)
        lease = self.lease()
        deadline = skipped.admit_lease(lease, 'c' * 40, REPO, self.rows, self.prov)
        with self.assertRaisesRegex(ValueError, 'lease-headroom-after-lock'):
            skipped.locked_admission(lease, 'c' * 40, deadline, now=deadline - skipped.HEADROOM + 60)

    def test_run_needs_the_heavy_seat(self):
        path = self.small['tmp'] / 'lease-heavy.json'
        path.write_text(json.dumps(self.lease()))
        with patch.object(skipped.s5b, 'frozen_manifest', lambda path: ({}, self.rows)), \
                patch.dict(os.environ, {'HEAVY_FREE': ''}), self.assertRaisesRegex(ValueError, 'heavy-seat-required'):
            skipped.main(['--run', '--lease', str(path), '--provenance', str(self.small['provenance'])])


class OfflineEntryTests(unittest.TestCase):
    def test_the_default_mode_touches_no_device_and_names_the_contract(self):
        out = io.StringIO()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')), \
                patch.object(subprocess, 'run', side_effect=AssertionError('no process')), contextlib.redirect_stdout(out):
            self.assertEqual(skipped.main([]), 0)
        contract = json.loads(out.getvalue())
        self.assertEqual((contract['mutations'], contract['derived_materialized'], contract['upload_route']),
                         (0, False, skipped.UPLOAD_ROUTE))
        self.assertEqual(contract['confirmations'], {derive.SYMLINK_ID: {'items': [derive.SYMLINK_ITEM], 'key': derive.SYMLINK_KEY},
                                                     derive.HTACCESS_ID: {'items': [derive.HTACCESS_ITEM],
                                                                          'key': derive.HTACCESS_KEY}})

    def test_the_script_runs_isolated_like_the_heavy_command_and_refuses_without_a_plan(self):
        script = str(LAB / 'focus_nextcloud_r6_skipped.py')
        p = subprocess.run([sys.executable, '-B', '-I', script], capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertEqual(json.loads(p.stdout)['phase'], skipped.PHASE)
        missing = Path(tempfile.mkdtemp()) / 'absent.json'
        self.addCleanup(shutil.rmtree, missing.parent, True)
        p = subprocess.run([sys.executable, '-B', '-I', script, '--lease-template', '--provenance', str(missing)],
                           capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'fixed-skipped-preflight-refused-no-mutation', p.stderr)


# ====================================================================== end to end against a fake dev-e

HA_KEY = PASSWORD   # the small original's generated key, as the lab's creds file would hold the real one
CREDS = {'HA_BACKUP_KEY': HA_KEY, 'B2_NC_X86_NOSHARE_USER_PW': 'noshare-user-pw-1', 'B2_NC_X86_NOSHARE_APP_PW': 'noshare-app-pw-12',
         'B2_NC_X86_SHARE_USER_PW': 'share-user-pw-123', 'B2_NC_X86_SHARE_APP_PW': 'share-app-pw-1234',
         'B2_NC_X86_SHARE_USER2_PW': 'share-user2-pw-12', 'B2_NC_X86_SHARE_LINK_PW': 'share-link-pw-123',
         'B2_NC_X86_SHARE_LINK_TOKEN': 'linktokenABCDEFG', 'B2_NC_X86_SHARE_USER': 'woow-import-share'}
FAKE_WRITER = r'''
import hashlib,json,os,sys
q=json.loads(sys.argv[1]);out=sys.argv[2];h=hashlib.sha256();n=0
with open(out,'wb') as f:
 while True:
  b=sys.stdin.buffer.read(65536)
  if not b:break
  n+=len(b);h.update(b);f.write(b)
st=os.stat(out);ok=n==q['size'] and h.hexdigest()==q['sha256']
print(json.dumps({'status':'passed' if ok else 'failed','bytes':n,'sha256':h.hexdigest(),
 'identity':{'dev':st.st_dev,'ino':st.st_ino},'metrics':{}}))
sys.exit(0 if ok else 2)
'''


def fake_facts(small):
    return {'fixture': str(small['path']), 'sha256': small['sha'], 'section': dict(SECTION),
            'user': 'woow-import-share', 'user_pw': 'B2_NC_X86_SHARE_USER_PW', 'app_pw': 'B2_NC_X86_SHARE_APP_PW',
            'user2': 'woow-import-share2', 'user2_pw': 'B2_NC_X86_SHARE_USER2_PW', 'user2_file': 'shared/a.txt',
            'link_pw': 'B2_NC_X86_SHARE_LINK_PW', 'link_token': 'B2_NC_X86_SHARE_LINK_TOKEN', 'link_file': 'a.txt',
            'user2_shared': 'a.txt',
            'files': {'a.txt': 'a' * 64, '匯入測試-share-20261123.txt': 'b' * 16}, 'digests': {'woow-import-share': 'd' * 64},
            'versioned': 'woow-versioned.txt', 'versions': 1, 'caldav': 'c.ics', 'caldav_uid': 'uid-c',
            'carddav': 'c.vcf', 'carddav_uid': 'uid-v'}


def proc(code, out=b''):
    return types.SimpleNamespace(returncode=code, stdout=out, stderr=b'')


class FakeDevE:
    """dev-e for one whole run: its helper, device programs, inventory, source transaction, owner commands and the upload
    file the (local) writer fills. `mode` breaks one thing: 'check-extra-confirm', 'htaccess-present',
    'converts-unacknowledged', 'source-restore-fails'."""
    BASE_USERS = ['admin', 'woowbk-lab-baseline']

    def __init__(self, engines, rows, prov, target, facts, mode='pass'):
        self.mode, self.rows, self.prov, self.target, self.facts = mode, rows, prov, target, facts
        self.prior_engine, self.product_engine = engines
        self.events, self.engine, self.nc = [], 'prior', 'original'
        self.backups = ['20261123T084036Z-5ebb7283', case.BASELINE]
        self.ha, self.uploads, self.jobs, self.count = set(), {'u' + '9' * 16 + '.done'}, {}, 0
        self.injected, self.converted, self.import_safety, self.nc_module, self.upload_id = False, None, None, None, None
        self.convert_requests = []

    def device(self, program, request=None, *, root=False, timeout=300):
        if program == s5.ENGINE_PROGRAM:
            if self.engine == 'stale':
                return dict(self.prior_engine, helper='3' * 64)
            return dict(self.product_engine if self.engine == 'product' else self.prior_engine)
        if program == s5.TARGET_STATE:
            rows = lambda names: [[n, 0o100600, 0, 0, 1, 1, 0, 0, i] for i, n in enumerate(sorted(names))]   # noqa: E731
            return {'archives': rows(f'{b}.{s}' for b in self.backups for s in ('json', 'tar')),
                    'ha-backups': rows(f'{h}.{s}' for h in self.ha for s in ('json', 'tar')), 'uploads': rows(self.uploads),
                    'jobs': rows(f'{j}.{s}' for j in self.jobs for s in ('json', 'log', 'lock'))}
        if program == case.QUIESCENT:
            return {'active_jobs': 0}
        if program == case.RESOURCE:
            return {'free': 30 * 1024 ** 3, 'memory': 1024 ** 3}
        if program == case.BASELINE_INSPECT:
            return {'status': 'passed', 'encrypted_manifest_opened': True}
        if program == wake.BASELINE_HASH:
            return [{'name': case.BASELINE + '.json', 'size': 655, 'sha256': 'a' * 64},
                    {'name': case.BASELINE + '.tar', 'size': 422031360, 'sha256': 'b' * 64}]
        if program == wake.unit_program():
            self.events.append('units-' + request['action'])
            return {'rows': [{'name': n} for n in wake.FILES]} if request['action'] == 'snapshot' else {'status': 'ok'}
        if program == wake.CONTROL:
            self.events.append('wake')
            return {'status': 'started'}
        if program == cold.CLAIM:
            return {'ActiveState': 'active', 'MainPID': '42', 'InvocationID': 'a' * 32}
        if program == cold.STOP:
            self.events.append('cold-stop')
            return {'status': 'stopped'}
        raise AssertionError('unexpected device program')

    def collect(self):
        return {'isolation': {'running': True, 'network': 'none', 'ports': {}, 'memory_limit': case.DEVICE_CAP},
                'root': {'memory_max': str(case.DEVICE_CAP), 'memory_current': 500 * 1024 ** 2,
                         'varlib_free_bytes': 30 * 1024 ** 3,
                         'catalog_sha256': '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6',
                         'installed_hashes': {'ha_nextcloud.py': self.engine}},
                'host_memory_available_mib': 3500, 'host_free_bytes': 30 * 1024 ** 3,
                'owner': {'units': {n: {'ActiveState': 'inactive', 'UnitFileState': 'generated'} for n in r6.INACTIVE_UNITS},
                          'quadlets': {'nextcloud-app.container': {'sha256': 'q' * 64}},
                          'images': [{'ref': r, 'present': True, 'identity': {'id': 'sha256:' + v, 'architecture': 'amd64',
                                                                             'os': 'linux'}} for r, v in case.ORIGINALS.items()]}}

    def transact(self, action, nonce, paths, manifest, expires):
        self.events.append('source-' + action)
        if action == 'install':
            assert manifest == self.rows
            self.engine = 'product'
            return {'status': 'installed'}
        if self.mode == 'source-restore-fails':
            raise RuntimeError('fixed-source-exact-prior-return-failed')
        self.engine = 'prior'
        return {'status': 'restored'}

    # ---------------------------------------------------------------- the helper
    def job(self, kind, state, result=None, error=None):
        self.count += 1
        job_id = 'j20261129T%06dZ-%08x' % (100000 + self.count, self.count)
        self.jobs[job_id] = {'id': job_id, 'type': kind, 'state': state, 'phase': 'done', 'progress': {'message': ''},
                             'result': result, 'error': error}
        return job_id

    def new_backup(self):
        self.count += 1
        backup_id = '20261129T%06dZ-%08x' % (100000 + self.count, self.count)
        self.backups.append(backup_id)
        return backup_id

    def check_row(self):
        issues = [link_issue(), htaccess_issue(), *haissues.from_legacy(warnings=[settings_text()])]
        if self.mode == 'check-extra-confirm':
            issues.append(haissues.Issue('nextcloud.db-objects-skipped', 'confirm', 'x', ['public.f']))
        return {'app_id': 'nextcloud', 'arch': 'amd64', 'version': '0.2.3', 'target_version': '35.0.1.1',
                'nextcloud': skipped.expected_section(self.facts['section']), **haissues.check_fields('nextcloud', issues)}

    def helper(self, command, request=None, *, timeout=1800):
        self.events.append(command)
        if command == 'jobs':
            return 0, {'jobs': [{'id': j['id'], 'state': j['state']} for j in self.jobs.values()]}
        if command == 'job-status':
            return 0, {'job': copy.deepcopy(self.jobs[request['job_id']]), 'log': []}
        if command == 'list':
            return 0, {'backups': [{'id': b, 'size': 10 ** 6} for b in self.backups]}
        if command == 'upload-begin':
            assert request == {'filename': skipped.UPLOAD_NAME, 'size': self.prov.derived_bytes}, request
            self.upload_id = 'u' + 'a' * 16
            return 0, {'upload_id': self.upload_id, 'path': f'/var/lib/woowtech-backup/uploads/{self.upload_id}.part',
                       'max_size': 10 ** 12}
        if command == 'upload-finish':
            assert request == {'upload_id': self.upload_id}
            data = self.target.read_bytes()
            record_id = 'ha-' + sha(data)[:20]
            self.ha.add(record_id)
            self.uploads.add(self.upload_id + '.done')
            return 0, {'ha_backup': {'id': record_id, 'sha256': sha(data), 'size': len(data),
                                     'importable_apps': [{'app_id': 'nextcloud', 'installed': True}]}}
        if command == 'ha-check-start':
            assert request.get('key') == HA_KEY
            return 0, {'job_id': self.job('verify', 'succeeded', {'ha_check': {'apps': [self.check_row()]}})}
        if command == 'ha-convert-start':
            cli.validate('ha-convert-start', request)
            assert request.get('key') == HA_KEY
            acknowledged = (request.get('acknowledged') or {}).get('nextcloud')
            self.convert_requests.append(acknowledged)
            if sorted(acknowledged or []) == list(derive.KEYS) or self.mode == 'converts-unacknowledged':
                backup = self.new_backup()
                self.converted = backup
                result = {'backup_id': backup, 'size': 10 ** 6, 'apps': ['nextcloud'], 'encrypted': True,
                          'ha_import': {'notes': ['Nextcloud 會標示資料是從備份還原的（新的資料指紋）。', 'Office 會改用這台的 Collabora。'],
                                        'reminders_by_app': {'nextcloud': ['請到「Woow Nextcloud MCP Server」確認連線資料。']}},
                          'results': [haimport.convert_result('nextcloud', None, [link_issue(), htaccess_issue()])]}
                return 0, {'job_id': self.job('backup', 'succeeded', result)}
            found, named = (([link_issue(), htaccess_issue()], [htaccess_issue()]) if acknowledged == [derive.SYMLINK_KEY]
                            else ([link_issue()], [link_issue()]))
            error = haissues.confirmation_required({'nextcloud': named}, 'x')
            result = {'results': [haimport.convert_result('nextcloud', error, found)]}
            return 0, {'job_id': self.job('backup', 'failed', result, error.as_dict())}
        if command == 'inspect':
            return 0, {'preflight': {'ok': True, 'checks': [], 'apps': [{'id': 'nextcloud', 'mode': 'inplace',
                                                                          'settings': {'state': 'same'}}]}, 'manifest': {}}
        if command == 'ha-delete':
            assert request == {'ha_backup_id': self.prov.ha_id, 'confirm': True}, request
            self.ha.discard(self.prov.ha_id)
            return 0, {}
        if command == 'restore-start':
            safety = self.new_backup()
            if self.injected:
                self.injected = False
                return 0, {'job_id': self.job('restore', 'rolled-back', {'rolled_back': True, 'safety_backup_id': safety})}
            if request['backup_id'] == self.converted:
                self.nc = 'imported'
                self.import_safety = self.import_safety or safety
            else:
                assert request['backup_id'] == self.import_safety
                self.nc = 'original'
            return 0, {'job_id': self.job('restore', 'succeeded', {'safety_backup_id': safety, 'health': [{'status': 'ok'}]})}
        if command == 'delete':
            self.backups.remove(request['backup_id'])
            return 0, {}
        if command in ('job-cancel', 'upload-abort'):
            return 0, {}
        raise AssertionError(command)

    # ---------------------------------------------------------------- appowner probes
    def probe(self):
        web = {p: 403 for p in skipped.WEB_PATHS}
        if self.nc != 'imported':
            return {'entries': {'.htaccess': {'type': 'file', 'mode': 0o644, 'uid': 33, 'gid': 33, 'size': 400,
                                              'sha256': 'e' * 64}},
                    'links': {'count': 0, 'first': []}, 'nested_htaccess': {'count': 0, 'first': []}, 'web': web}
        owner = {'uid': 33, 'gid': 33}
        entries = {'.htaccess': dict(owner, type='file', mode=0o644, size=len(ha_nextcloud.DATA_HTACCESS),
                                     sha256=sha(ha_nextcloud.DATA_HTACCESS)),
                   derive.FOLDER: dict(owner, type='dir', mode=0o755, size=0),
                   derive.CONTROL: dict(owner, type='file', mode=0o644, size=len(derive.CONTROL_DATA),
                                        sha256=sha(derive.CONTROL_DATA))}
        nested = {'count': 0, 'first': []}
        if self.mode == 'htaccess-present':
            entries[derive.HTACCESS] = dict(owner, type='file', mode=0o644, size=len(derive.HTACCESS_DATA),
                                            sha256=sha(derive.HTACCESS_DATA))
            nested = {'count': 1, 'first': [derive.HTACCESS]}
        return {'entries': entries, 'links': {'count': 0, 'first': []}, 'nested_htaccess': nested, 'web': web}

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        nc = self.nc_module
        if script == nc.ENGINE_HASHES:
            source_rows = self.rows if self.engine == 'product' else {}
            return {n[len('woowbackup/'):]: r['sha256'] for n, r in source_rows.items() if n.startswith('woowbackup/')}
        if script == nc.STATE:
            imported = self.nc == 'imported'
            return {'config_sha256': 'cfg-' + self.nc, 'users': ['woow-import-share'] if imported else self.BASE_USERS,
                    'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                    'db': {'storages': ['home::x'], 'users': 4 if imported else 2}, 'data_top': ['a', 'b'],
                    'units': {u: 'active' for u in nc.UNITS}, 'office': {'core.backgroundjobs_mode': 'cron'},
                    'fingerprint': 'fp-' + self.nc, 'filecache_rows': 10}
        if script == nc.CLIENT:
            if request['user'] == nc.BASE_USER:
                return {'ocs': {'password': [200, True], 'wrong': [401, False]}, 'fingerprint': [207, 'fp-original'],
                        'capabilities': [200, {'keys': ['config']}], 'discovery': [200, True]}
            assert request['user'] == self.facts['user'] and request['user_pw'] == CREDS['B2_NC_X86_SHARE_USER_PW']
            assert request['user2_pw'] == CREDS['B2_NC_X86_SHARE_USER2_PW'] and self.nc == 'imported'
            return {'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                    'user2_file': 'a' * 64,
                    'files': dict(self.facts['files']), 'digests': dict(self.facts['digests']),
                    'ocs': {'password': [200, True], 'app_password': [200, True], 'wrong': [401, False]},
                    'link': ['a' * 64, 401, 401], 'caldav': [200, True], 'carddav': [200, True],
                    'versions': {'dav': [207, 1], 'on_disk': '1'}, 'capabilities': [200, {'keys': ['config']}],
                    'fingerprint': [207, 'fp-imported'], 'discovery': [200, True],
                    'web': {'control': 200, 'picked': True, 'codes': [404, 403, 404, 403],
                            'htaccess': sha(ha_nextcloud.DATA_HTACCESS), 'htaccess_below': '0'},
                    'scan': {'folders': 3, 'files': 20, 'new': 0, 'updated': 0, 'removed': 0, 'errors': 0, 'rc': 0},
                    'setup': {'checks': 30, 'data_dir': 'success', 'not_success': []},
                    'storage': 'local::/var/www/html/data/', 'owners': 'oc_admin', 'lastcron': '1'}
        if script == nc.OFFICE:
            assert request['user'] == self.facts['user2'] and self.nc == 'imported'
            self.events.append('office-' + self.nc)
            return {'document': [True, True, True], 'copy': 201, 'direct': [200, True], 'page': [200, True, True],
                    'wopi_info': [200, True, True, True], 'wopi_file': [200, True], 'wopi_wrong_token': 403, 'relay': 0,
                    'loaded': [True, True, True], 'perm': 'perm: edit', 'text': [200, 40, 40, True], 'saved': True,
                    'saved_in_nextcloud': [True, True], 'deleted': 204, 'trash_deleted': [204], 'relay_gone': True}
        if script == nc.LEAKS:
            self.events.append('leak-scan')
            return {'scanned': 12, 'journal_bytes': 1000, 'names': len([v for v in request['secrets'].values() if v]),
                    'hits': 0, 'url_token_access_log_hits': 1 if request.get('url_tokens') else 0,
                    'url_token_hits_elsewhere': 0}
        if script == nc.drv.RUN_LIST:
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': []}
        if script == skipped.PROGRAMS['probe']:
            self.events.append('probe-' + self.nc)
            return self.probe()
        raise AssertionError('unexpected owner program')

    def owner(self, *argv, input=None, timeout=600, check=False):
        argv = [str(a) for a in argv]
        if argv[:2] == ['python3', '-I'] and argv[-2:] == ['nextcloud', 'read']:
            return proc(0, json.dumps({'users': ['woowbk-lab-baseline'], 'files': {'marker.txt': 'e' * 64}}).encode())
        if argv[:3] == ['podman', 'unshare', 'du']:
            return proc(0, f'{100 * 1024 ** 2}\t{argv[-1]}\n'.encode())
        if argv[0] == 'podman':
            return proc(0, b'')
        if argv[0] == 'test':
            return proc(1)
        if argv[0] == 'sh':
            self.injected = self.injected or argv[4].endswith(self.nc_module.FAIL_MARKER_REL)
            return proc(0)
        if argv[0] in ('mkdir', 'rm', 'rmdir', 'systemctl'):
            return proc(0)
        raise AssertionError(argv)

    def trace(self, body, request, ev, prefix, timeout):
        assert body is upload.VERIFY and request['expected_id'] == self.prov.ha_id
        data, st = self.target.read_bytes(), self.target.stat()
        return {'status': 'passed', 'ha_backup_id': self.prov.ha_id, 'bytes': len(data), 'sha256': sha(data),
                'identity': {'dev': st.st_dev, 'ino': st.st_ino}, 'sidecar_sha256': 'c' * 64, 'allocated_bytes': len(data)}


class EndToEndSimulationTests(unittest.TestCase):
    """The whole run -- main(), the read-only proofs, R6's cold-to-cold path and case body with this variant, the end
    checks -- against FakeDevE, with the REAL derivation of a small generated original streamed through the real upload
    loop into a local writer process. Every lab boundary is a fake; the guard refuses any host podman/labpodman."""
    CACHE = None

    def setUp(self):
        self.small = small_case()
        if EndToEndSimulationTests.CACHE is None:
            with bound_to(self.small):
                other_lane = dict(s5.engine_manifest(REPO, s5.ENGINE_COMMIT), **{'lib/woowbackup/cli.py': '1' * 64,
                                                                                 'helper': '2' * 64})
                prov = skipped.load_provenance(self.small['provenance'])
                EndToEndSimulationTests.CACHE = (skipped.lease_template(REPO, prov), skipped.s5b.git_manifest(REPO),
                                                 (other_lane, s5.engine_manifest(REPO, skipped.PRODUCT_COMMIT)), prov)

    def run_case(self, mode='pass'):
        template, rows, engines, prov = EndToEndSimulationTests.CACHE
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        lab = home / '.woowbk-lab'
        secrets_dir = lab / 'secrets'
        secrets_dir.mkdir(parents=True)
        (secrets_dir / 'ha-import-creds.env').write_text(''.join(f'{k}={v}\n' for k, v in CREDS.items()))
        (secrets_dir / 'b1-creds.env').write_text('')
        (secrets_dir / 'dev-e-markers.json').write_text(json.dumps({'nextcloud': 'marker-password-1'}))
        (secrets_dir / 'dev-e-kit.txt').write_text('# kit\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ\n')
        facts = fake_facts(self.small)
        facts_path = home / 'share-facts.json'
        facts_path.write_text(json.dumps(facts))
        target = home / 'device-upload.part'
        fake = FakeDevE(engines, rows, prov, target, facts, mode)
        now = datetime.datetime.now(datetime.timezone.utc)
        lease = dict(template, not_before_utc=(now - datetime.timedelta(minutes=1)).isoformat(),
                     expires_utc=(now + datetime.timedelta(minutes=150)).isoformat())
        lease_path = home / 'lease.json'
        lease_path.write_text(json.dumps(lease))
        original_load = r6.load_flow

        def load_flow(receipt=None):
            mod = original_load(receipt)
            mod.drv.helper, mod.drv.device_python, mod.drv.owner = fake.helper, fake.device_python, fake.owner
            mod.drv.root = lambda *a, **k: (_ for _ in ()).throw(AssertionError('no root command'))
            fake.nc_module = mod
            return mod
        with contextlib.ExitStack() as stack:
            stack.enter_context(bound_to(self.small))
            stack.enter_context(patch.object(Path, 'home', return_value=home))
            for target_module, name, value in (
                    (skipped, 'LAB', lab), (skipped, 'RECEIPT', lab / 'run/focus_nextcloud_r6_skipped.json'),
                    (skipped, 'CREDS', secrets_dir / 'ha-import-creds.env'), (skipped, 'LOCK', str(home / 'lock')),
                    (r6, 'LAB', lab), (r6, 'RECEIPT', lab / 'run/focus_nextcloud_r6.json'),
                    (skipped.s5b, 'RECEIPT', lab / 'run/focus_nextcloud_r6_s5b.json'),
                    (skipped, 'lease_template', lambda repo, prov: copy.deepcopy(template)),
                    (skipped.s5b, 'frozen_manifest', lambda path: ({}, rows)), (wake, 'device', fake.device),
                    (cold, 'device', fake.device), (case, 'collect', fake.collect), (case.source, 'transact', fake.transact),
                    (case, 'reload_units', lambda: fake.events.append('reload')), (r6, 'baseline_verify', lambda: True),
                    (r6, 'load_flow', load_flow), (skipped, 'trace', fake.trace),
                    (skipped, 'writer_command', lambda q: [sys.executable, '-I', '-c', FAKE_WRITER, json.dumps(q),
                                                           str(target)])):
                stack.enter_context(patch.object(target_module, name, value))
            stack.enter_context(patch.dict(os.environ, {'HEAVY_FREE': str(home / 'lock')}))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            rc = skipped.main(['--run', '--lease', str(lease_path), '--provenance', str(self.small['provenance']),
                               '--facts', str(facts_path)])
        records = sorted((lab / 'evidence').glob(skipped.AREA + '-run/*/fixed-result.json'))
        result = json.loads(records[-1].read_text())
        checks = json.loads(next((lab / 'evidence').glob(skipped.AREA + '/*/results.json')).read_text())
        return rc, fake, result, checks, home, out.getvalue()

    def assert_no_secret_in_any_record(self, home):
        needles = [v for k, v in CREDS.items() if not k.endswith('_USER')] + ['AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ',
                                                                             'marker-password-1', PASSWORD]
        for path in home.rglob('*'):
            if path.is_file() and 'secrets' not in path.parts and path.name not in ('lease.json', 'share-facts.json'):
                text = path.read_bytes()
                for needle in needles:
                    self.assertNotIn(needle.encode(), text, path)

    def test_a_passing_run_streams_checks_refuses_twice_imports_verifies_rolls_back_and_returns_cold(self):
        rc, fake, result, checks, home, out = self.run_case()
        self.assertEqual(checks['failed'], 0, [(c['check'], c['detail']) for c in checks['results'] if not c['ok']])
        self.assertEqual(rc, 0, result)
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['prior_engine_returned_exactly'] and result['owned_store_clean'])
        self.assertEqual((result['evidence_leak_scan']['hits'], result['evidence_leak_scan']['provenance_hits']), (0, 0))
        self.assertEqual(result['store_delta']['uploads']['added'], ['u' + 'a' * 16 + '.done'])
        # the device's upload file got exactly the derived bytes of the plan, made again from the original
        prov = EndToEndSimulationTests.CACHE[3]
        self.assertEqual((sha(fake.target.read_bytes()), fake.target.stat().st_size), (prov.derived_sha, prov.derived_bytes))
        self.assertEqual(fake.convert_requests, [None, [derive.SYMLINK_KEY], list(derive.KEYS)])
        e = fake.events
        order = ['source-install', 'wake', 'probe-original', 'upload-begin', 'upload-finish', 'ha-check-start',
                 'ha-convert-start', 'probe-imported', 'cold-stop', 'source-restore']
        self.assertEqual(sorted(e.index(x) for x in order), [e.index(x) for x in order])
        self.assertLess(max(i for i, x in enumerate(e) if x == 'leak-scan'), e.index('source-restore'))
        self.assertEqual((fake.engine, fake.nc, fake.ha), ('prior', 'original', set()))
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', case.BASELINE]))
        names = [c['check'] for c in checks['results']]
        # fullshare05's 118 fixed lines plus this case's 22: the frozen-product engine, the folder absent before, two
        # more upload lines, three more check lines, the two refusals, the converted row, four skipped-entry lines in
        # each of the three verifications -- what a real passing run prints
        self.assertEqual(checks['passed'], 140)
        self.assertEqual(fake.events.count('office-imported'), 3)
        for phase, count in (('check', 5), ('upload', 3), ('convert', 2)):
            self.assertEqual(sum(n.startswith(phase + ':') for n in names), count, phase)
        for phase in ('import', 'restart', 'auto rollback'):
            self.assertEqual(sum(n.startswith(phase + ': the two left-out entries') for n in names), 1, phase)
            self.assertEqual(sum(n.startswith(phase + ': the web server serves nothing of the derived folder') for n in names),
                             1, phase)
        scope = json.loads(next((home / '.woowbk-lab/evidence').glob(skipped.AREA + '/*/scope.json')).read_text())
        self.assertEqual((scope['derived']['materialized'], scope['derived']['sha256']), (False, prov.derived_sha))
        self.assert_no_secret_in_any_record(home)

    def test_an_unexpected_check_line_stops_before_any_conversion_and_dev_e_comes_back(self):
        rc, fake, result, checks, home, _out = self.run_case('check-extra-confirm')
        self.assertEqual(rc, 1)
        self.assertNotIn('ha-convert-start', fake.events)
        self.assertEqual((fake.engine, fake.ha), ('prior', set()))
        self.assertIn('check: exactly two lines to confirm: nextcloud.symlinks-skipped naming exactly the reviewed link and '
                      'nextcloud.htaccess-skipped naming exactly the reviewed .htaccess, the product\'s texts, each with the '
                      'key bound to that name', checks['failed_checks'])
        self.assert_no_secret_in_any_record(home)

    def test_a_left_out_entry_on_disk_fails_the_run_but_still_rolls_back_and_cleans_up(self):
        rc, fake, result, checks, _home, _out = self.run_case('htaccess-present')
        self.assertEqual(rc, 1)
        self.assertIn('restore-start', fake.events)
        self.assertEqual((fake.engine, fake.nc, fake.ha), ('prior', 'original', set()))
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', case.BASELINE]))
        self.assertTrue(any('the two left-out entries are not on disk' in c for c in checks['failed_checks']))

    def test_a_conversion_without_the_acknowledgement_that_succeeds_fails_the_run(self):
        rc, fake, result, checks, _home, _out = self.run_case('converts-unacknowledged')
        self.assertEqual(rc, 1)
        self.assertEqual(fake.convert_requests, [None])                 # the step stopped the case
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', case.BASELINE]))

    def test_an_engine_that_did_not_come_back_fails_the_run(self):
        rc, _fake, result, checks, _home, _out = self.run_case('source-restore-fails')
        self.assertEqual(checks['failed'], 0)                            # the case itself passed
        self.assertEqual((rc, result['prior_engine_returned_exactly']), (1, False))


if __name__ == '__main__':
    unittest.main()
