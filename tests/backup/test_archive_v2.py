"""Format 2 (`.tar`, CONTRACT section 5) with the real age/zstd/tar tools (team E1, format).

Covers: encrypted and unencrypted round trips, the outer tar read by plain tools (tar, Python tarfile, backup.json
without secrets), the manual decrypt the README documents (age/zstd/tar run as written), backup.json tampering against
the authenticated per-app manifests, truncated/extra/duplicate/missing/reordered outer members, hostile and oversize
inner tars, per-app partial restore that reads only the selected application archive, deep verification of nested
volume/image/directory/digest content, v1 still readable (with the same deep checks), and the parallel gzip writer.
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from woowbackup import archive, util
from woowbackup.deepcheck import DeepCheck
from woowbackup.errors import BackupError

from . import tarfixtures
from .test_archive import (APP, BACKUP_ID, CREATED, Workspace, demo_app, demo_manifest, demo_payloads, file_tree,
                           needs_age, stage, tool_children)

SECOND = 'second-app'
SECRET_VALUE = b's3cr3t-value\n'  # demo_payloads' database password


def second_app():
    app = json.loads(json.dumps(demo_app()).replace(f'apps/{APP}/', f'apps/{SECOND}/'))
    app.update(id=SECOND, name='第二個應用')
    return app


def second_payloads(big=4096):
    return {path.replace(f'apps/{APP}/', f'apps/{SECOND}/'): data for path, data in demo_payloads(big=big).items()}


def v2_manifest(key_id, apps=None, encryption='age-x25519'):
    manifest = demo_manifest(key_id, apps=apps if apps is not None else [demo_app(), second_app()])
    manifest.update(format=2, encryption=encryption)
    return manifest


def outer_members(path):
    """[(name, bytes)] of a v2 file read with Python's tarfile (an independent reader)."""
    with tarfile.open(path, mode='r:') as tar:
        return [(m.name, tar.extractfile(m).read()) for m in tar.getmembers()]


def build_outer(parts, *, trailer=b'', end=True, mtime=1762999200):
    """A hand-built outer tar from (name, bytes) regular members (or raw header bytes via ('<raw>', bytes))."""
    out = bytearray()
    for name, data in parts:
        if name == '<raw>':
            out += data
            continue
        out += archive._outer_header(name, len(data), mtime) + data + bytes((-len(data)) % 512)
    if end:
        out += bytes(1024) + bytes((-(len(out) + 1024)) % 10240)
    return bytes(out) + trailer


def doc_for(members, inner_manifests, encryption='age-x25519'):
    """backup.json for inner archive bytes `members` [(app id, bytes)] described by their inner manifests."""
    head = archive._head_view(inner_manifests[0])
    head['apps'] = [dict(archive.display_app(inner['app']), file=archive.inner_name(app_id, encryption),
                         size=len(data), sha256=hashlib.sha256(data).hexdigest())
                    for (app_id, data), inner in zip(members, inner_manifests)]
    return head


def pack_doc(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2).encode() + b'\n'


def seal_inner(tar_bytes, encryption, recipient=None):
    """Compress (and encrypt) arbitrary inner tar bytes like the engine: zstd | age -r, or gzip."""
    if encryption == 'none':
        return gzip.compress(tar_bytes, mtime=0)
    compressed = subprocess.run(['zstd', '-q', '-c', '-3'], input=tar_bytes, stdout=subprocess.PIPE,
                                check=True).stdout
    return subprocess.run(['age', '-e', '-r', recipient], input=compressed, stdout=subprocess.PIPE, check=True).stdout


def tar_of(members):
    """Inner tar bytes from [(TarInfo, data|None)]."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def reg(name, data, size=None):
    info = tarfile.TarInfo(name)
    info.size = len(data) if size is None else size
    info.mode = 0o600
    return info, data


def small_inner(app_id, key_id, files, *, encryption='age-x25519', backup_id=BACKUP_ID, backup_apps=None):
    """A schema-valid per-app manifest declaring `files` ({entry path: bytes}; secrets and config files only)."""
    secrets, configs = [], []
    for index, path in enumerate(files):
        category, name = path.split('/')[2], path.split('/')[3]
        if category == 'secrets':
            secrets.append({'name': name, 'entry': path})
        else:
            configs.append({'path': f'.config/{app_id}/f{index}.env', 'mode': '0600', 'entry': path})
    app = {'id': app_id, 'name': '示範', 'adapter': 'quadlet-postgres', 'adapter_version': 1,
           'catalog_sha256': 'a' * 64, 'owner': {'name': 'appowner', 'uid': 1001}, 'images': [], 'postgres': [],
           'volumes': [], 'secrets': secrets, 'config_files': configs, 'quadlet_files': [], 'verify_snapshot': {}}
    return {'format': 2, 'backup_id': backup_id, 'created': CREATED, 'type': 'manual', 'note': '',
            'key_id': key_id if encryption != 'none' else None, 'encryption': encryption,
            'tool': {'name': 'woowtech-cockpit-backup', 'version': 'test'},
            'source': {'hostname': 'attacker', 'machine_id_sha256': '', 'arch': 'x86_64', 'os': 'x', 'podman': 'x'},
            'consistency': {'method': 'writers-stopped', 'downtime_seconds': 0},
            'backup_apps': backup_apps or [app_id], 'app': app,
            'entries': [{'path': p, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()} for p, d in files.items()]}


def inner_tar(inner, files, *, extra=(), order=None):
    members = [reg('manifest.json', json.dumps(inner).encode())]
    members += [reg(path, files[path]) for path in (order or list(files))]
    members += list(extra)
    return tar_of(members)


class V2Workspace(Workspace):
    def write_v2(self, payloads=None, manifest=None, *, encrypted=True, name='b.tar', progress=None):
        if payloads is None:
            payloads = dict(demo_payloads(big=2 * 1024 * 1024))
            payloads.update(second_payloads())
        entries = stage(self.staging, payloads)
        if manifest is None:
            manifest = v2_manifest(self.key.key_id if encrypted else None,
                                   encryption='age-x25519' if encrypted else 'none')
        dest = self.out / name
        result = archive.write_archive(dest, None, manifest, entries, self.key.recipient if encrypted else None,
                                       tmp_dir=self.out, progress=progress)
        return dest, result, payloads


# ---------------------------------------------------------------------------- round trips

@needs_age
class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)

    def check_round_trip(self, encrypted):
        calls = []
        dest, result, payloads = self.ws.write_v2(encrypted=encrypted, progress=lambda d, t: calls.append((d, t)))
        total = sum(len(v) for v in payloads.values())
        self.assertEqual(result['size'], dest.stat().st_size)
        self.assertEqual(result['sha256'], util.sha256_file(dest))
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
        self.assertEqual(calls[-1], (total, total))
        self.assertEqual(sorted(p.name for p in self.ws.out.iterdir()), [dest.name], 'no temp or recipient files')
        encryption = 'age-x25519' if encrypted else 'none'
        self.assertEqual([(a['id'], a['file']) for a in result['apps']],
                         [(APP, archive.inner_name(APP, encryption)), (SECOND, archive.inner_name(SECOND, encryption))])

        header = archive.read_header(dest)
        self.assertEqual(header, {'format': 2, 'backup_id': BACKUP_ID, 'created': CREATED,
                                  'key_id': self.ws.key.key_id if encrypted else None, 'encryption': encryption,
                                  'compression': 'zstd' if encrypted else 'gzip'})
        self.assertEqual(archive.format_of(dest), 2)
        ids = self.ws.keys.identities() if encrypted else []
        manifest = archive.read_manifest(dest, ids)
        self.assertEqual(manifest['format'], 2)
        self.assertEqual(manifest['encryption'], encryption)
        self.assertEqual([a['id'] for a in manifest['apps']], [APP, SECOND])
        self.assertEqual(manifest['backup_apps'], [APP, SECOND])
        self.assertEqual([e['path'] for e in manifest['entries']], list(payloads))
        self.assertEqual(manifest['apps'][0]['verify_snapshot']['summary']['title'], '我的筆記')
        self.assertEqual(manifest['source']['machine_id_sha256'], '0' * 64, 'authenticated fields, not backup.json')

        seen = []
        verified = archive.verify_archive(dest, ids, progress=lambda d, t: seen.append((d, t)))
        self.assertEqual((verified['entries'], verified['bytes'], verified['format'], verified['encryption']),
                         (len(payloads), total, 2, encryption))
        self.assertEqual(seen[-1], (total, total))
        target = self.ws.dest()
        extracted = archive.extract_archive(dest, ids, target)
        self.assertEqual(extracted, manifest)
        tree = file_tree(target)
        for path, data in payloads.items():
            self.assertEqual(tree[path], ('file', 0o600, data), path)
        self.assertEqual({k for k, v in tree.items() if v[0] == 'file'}, set(payloads))
        self.assertEqual(tool_children(), [], 'age/zstd children reaped')
        return dest

    def test_encrypted_round_trip_two_apps(self):
        dest = self.check_round_trip(encrypted=True)
        self.assertNotIn(SECRET_VALUE, dest.read_bytes(), 'nothing secret in clear text')

    def test_unencrypted_round_trip_needs_no_key(self):
        dest = self.check_round_trip(encrypted=False)
        members = dict(outer_members(dest))
        inner = gzip.decompress(members[f'apps/{APP}.tar.gz'])  # any gzip reader
        with tarfile.open(fileobj=io.BytesIO(inner)) as tar:
            self.assertEqual(tar.getnames()[0], 'manifest.json')
            self.assertEqual(tar.extractfile(f'apps/{APP}/secrets/woowbk-demo-db-password').read(), SECRET_VALUE)
        work = self.ws.dest('gz')
        (work / 'a.tar.gz').write_bytes(members[f'apps/{APP}.tar.gz'])
        self.assertEqual(subprocess.run(['gzip', '-t', str(work / 'a.tar.gz')], capture_output=True).returncode, 0)
        readme = members['README.txt'].decode()
        self.assertIn('沒有加密', readme)
        self.assertIn('NOT encrypted', readme)

    def test_cancel_from_progress_leaves_nothing(self):
        def cancel(done, total):
            raise KeyboardInterrupt
        for encrypted in (True, False):
            with self.subTest(encrypted=encrypted):
                with self.assertRaises(KeyboardInterrupt):
                    self.ws.write_v2(encrypted=encrypted, progress=cancel, name=f'c{int(encrypted)}.tar')
                self.assertEqual(list(self.ws.out.iterdir()), [], 'temp archive and recipient file removed')
                self.assertEqual(tool_children(), [])
                shutil.rmtree(self.ws.staging)
                self.ws.staging.mkdir(mode=0o700)

    def test_writer_refuses_inconsistent_input(self):
        payloads = demo_payloads(big=16)
        entries = stage(self.ws.staging, payloads)
        manifest = v2_manifest(self.ws.key.key_id, apps=[demo_app()])
        cases = {
            'plain with a recipient': (dict(manifest, encryption='none', key_id=None), self.ws.key.recipient),
            'encrypted without a recipient': (manifest, None),
            'key id of another key': (dict(manifest, key_id='AAAA-BBBB-CCCC-DDDD'), self.ws.key.recipient),
            'entry of an app not in the backup': (v2_manifest(self.ws.key.key_id, apps=[second_app()]),
                                                  self.ws.key.recipient),
        }
        for name, (bad, recipient) in cases.items():
            with self.subTest(name):
                with self.assertRaises(BackupError):
                    archive.write_archive(self.ws.out / 'x.tar', None, bad, entries, recipient, tmp_dir=self.ws.out)
                self.assertEqual(list(self.ws.out.iterdir()), [])

    def test_large_member_switches_to_a_pax_size_slot(self):
        # The header slot is chosen from an upper bound before the data streams; with a bound over 8 GiB the slot
        # carries a PAX size record (lowered limit here so the test stays small).
        with mock.patch.object(archive, 'USTAR_SIZE_MAX', 1024):
            dest, result, payloads = self.ws.write_v2(encrypted=False)
        raw = dest.read_bytes()
        self.assertIn(b'././@PaxHeader', raw)
        with tarfile.open(dest) as tar:
            self.assertEqual([m.size for m in tar.getmembers()[2:]], [a['size'] for a in result['apps']])
        target = self.ws.dest()
        archive.extract_archive(dest, [], target)
        self.assertEqual((target / f'apps/{SECOND}/config/0').read_bytes(), payloads[f'apps/{SECOND}/config/0'])


# ---------------------------------------------------------------------------- the outer tar with plain tools

@needs_age
class OuterTarTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)

    def test_plain_tools_list_it_and_backup_json_has_no_secrets(self):
        dest, result, payloads = self.ws.write_v2()
        listing = subprocess.run(['tar', '-tvf', str(dest)], capture_output=True, text=True, check=True).stdout
        names = [line.split()[-1] for line in listing.splitlines()]
        self.assertEqual(names, ['backup.json', 'README.txt', f'apps/{APP}.tar.zst.age', f'apps/{SECOND}.tar.zst.age'])
        with tarfile.open(dest) as tar:
            for member in tar.getmembers():
                self.assertTrue(member.isreg())
                self.assertEqual((member.mode, member.uid, member.gid), (0o600, 0, 0))
            doc = json.loads(tar.extractfile('backup.json').read())
            readme = tar.extractfile('README.txt').read()
            sizes = {m.name: m.size for m in tar.getmembers()}
        self.assertEqual(set(doc), {'format', 'backup_id', 'created', 'type', 'note', 'tool', 'source', 'encryption',
                                    'compression', 'key_id', 'apps'})
        self.assertEqual((doc['format'], doc['encryption'], doc['key_id'], doc['compression']),
                         (2, 'age-x25519', self.ws.key.key_id, 'zstd'))
        self.assertEqual(set(doc['source']), {'hostname', 'arch', 'os', 'podman'})
        first = doc['apps'][0]
        self.assertEqual(first, {
            'id': APP, 'name': '示範筆記應用', 'adapter': 'quadlet-postgres', 'owner': 'appowner',
            'images': [{'ref': 'docker.io/library/postgres:16-alpine', 'included': True},
                       {'ref': 'localhost/woowbk-demo-app:1', 'included': False}],
            'databases': ['notes'], 'volumes': ['woowbk-demo-files'], 'data_dirs': [],
            'secrets': ['woowbk-demo-db-password', demo_app()['secrets'][1]['name']],
            'config_files': ['.config/woowbk-demo/app.env', '.local/share/woowbk-demo/empty.env'],
            'file': f'apps/{APP}.tar.zst.age', 'size': sizes[f'apps/{APP}.tar.zst.age'],
            'sha256': result['apps'][0]['sha256']})
        text = json.dumps(doc) + readme.decode()
        self.assertNotIn(self.ws.key.recipient, text, 'the public recipient never appears in the clear')
        self.assertNotIn('AGE-SECRET-KEY', text)
        for secret in (SECRET_VALUE.strip(), b'long-name-secret', 'TITLE=我的筆記'.encode()):
            self.assertNotIn(secret, json.dumps(doc, ensure_ascii=False).encode() + readme)

    def run_readme(self, dest, readme, kit=None):
        """Run the commands README.txt documents (first language block) in a fresh directory."""
        block = readme.split('-' * 70)[0]
        lines = [line.strip() for line in block.splitlines() if line.startswith('  ') and
                 line.strip().split(' ')[0] in ('tar', 'mkdir', 'age')]
        self.assertTrue(lines)
        work = self.ws.dest('manual')
        script = '\n'.join(line.replace('<backup-file>.tar', str(dest)).replace('<emergency-kit>.txt', str(kit))
                           for line in lines)
        subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=work, check=True,
                       env={'PATH': util.SAFE_PATH, 'LANG': 'C.UTF-8'})
        return work, lines

    def test_manual_decrypt_with_age_zstd_tar_as_the_readme_says(self):
        dest, _result, payloads = self.ws.write_v2()
        members = dict(outer_members(dest))
        kit = self.ws.base / 'woowtech-backup-key.txt'
        kit.write_text(self.ws.keys.kit_text())  # the emergency kit is an age identity file
        work, lines = self.run_readme(dest, members['README.txt'].decode(), kit)
        self.assertTrue(any(line.startswith('age -d -i <emergency-kit>.txt') for line in lines))
        for app_id in (APP, SECOND):
            inner = json.loads((work / app_id / 'manifest.json').read_text())
            self.assertEqual(inner['backup_id'], BACKUP_ID)
            self.assertEqual(inner['app']['id'], app_id)
            for entry in inner['entries']:
                data = (work / app_id / entry['path']).read_bytes()
                self.assertEqual(data, payloads[entry['path']])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])

    def test_manual_unpack_of_an_unencrypted_backup_needs_only_tar(self):
        dest, _result, payloads = self.ws.write_v2(encrypted=False)
        members = dict(outer_members(dest))
        work, lines = self.run_readme(dest, members['README.txt'].decode())
        self.assertIn(f'tar -xzf apps/{APP}.tar.gz -C {APP}', lines)
        for path, data in payloads.items():
            app_id = path.split('/')[1]
            self.assertEqual((work / app_id / path).read_bytes(), data)


# ---------------------------------------------------------------------------- backup.json is display only

def rewrite_doc(path, change):
    """Edit backup.json in place (same member size: padded with spaces) and return the new doc."""
    raw = bytearray(Path(path).read_bytes())
    size = int(raw[124:136].rstrip(b'\0 '), 8)
    doc = json.loads(raw[512:512 + size])
    change(doc)
    data = json.dumps(doc, ensure_ascii=False, indent=2).encode()
    assert len(data) + 1 <= size, 'the edited backup.json must fit its member'
    raw[512:512 + size] = data + b' ' * (size - len(data) - 1) + b'\n'
    Path(path).write_bytes(bytes(raw))
    return doc


@needs_age
class BackupJsonTamperTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)
        self.dest, _result, _payloads = self.ws.write_v2(name='orig.tar')
        self.ids = self.ws.keys.identities()

    def tampered(self, change):
        copy = self.ws.out / 'tampered.tar'
        shutil.copyfile(self.dest, copy)
        rewrite_doc(copy, change)
        return copy

    def test_any_difference_from_the_authenticated_manifests_is_corrupt(self):
        cases = {
            'note': lambda d: d.update(note='已被修改'),
            'type': lambda d: d.update(type='safety'),
            'created': lambda d: d.update(created='2026-11-12T02:00:00Z'),
            'backup id': lambda d: d.update(backup_id='20261113T020000Z-ffffffff'),
            'key id': lambda d: d.update(key_id='AAAA-BBBB-CCCC-DDDD'),
            'tool': lambda d: d['tool'].update(version='9999'),
            'hostname': lambda d: d['source'].update(hostname='elsewhere'),
            'app name': lambda d: d['apps'][0].update(name='別的應用'),
            'owner': lambda d: d['apps'][1].update(owner='someone'),
            'volumes': lambda d: d['apps'][0].update(volumes=['other-volume']),
            'secrets': lambda d: d['apps'][0].update(secrets=[]),
            'image included': lambda d: d['apps'][0]['images'][1].update(included=True),
            'databases': lambda d: d['apps'][0].update(databases=['postgres']),
        }
        for name, change in cases.items():
            with self.subTest(name):
                copy = self.tampered(change)
                header = archive.read_header(copy)  # display only: shown before a key is entered
                self.assertEqual(header['format'], 2)
                for call in (lambda: archive.read_manifest(copy, self.ids), lambda: archive.verify_archive(copy, self.ids)):
                    with self.assertRaises(BackupError) as caught:
                        call()
                    self.assertEqual(caught.exception.code, 'corrupt-archive', name)
                self.assertEqual(tool_children(), [])

    def test_structural_fields_are_checked_against_the_outer_tar(self):
        for name, change, code in (
                ('member size', lambda d: d['apps'][0].update(size=d['apps'][0]['size'] + 1), 'corrupt-archive'),
                ('member file', lambda d: d['apps'][0].update(file=f'apps/{SECOND}.tar.zst.age'), 'corrupt-archive'),
                ('app order', lambda d: d['apps'].reverse(), 'corrupt-archive'),
                ('format', lambda d: d.update(format=3), 'unsupported-format'),
                ('unknown key', lambda d: d.update(extra=1), 'corrupt-archive'),
                ('encryption', lambda d: d.update(encryption='aes'), 'unsupported-format')):
            with self.subTest(name):
                copy = self.tampered(change)
                with self.assertRaises(BackupError) as caught:
                    archive.read_header(copy)
                self.assertEqual(caught.exception.code, code)

    def test_member_checksum_is_checked_when_the_member_is_read_whole(self):
        copy = self.tampered(lambda d: d['apps'][1].update(sha256='0' * 64))
        archive.read_manifest(copy, self.ids)  # the manifest alone does not read the whole member
        with self.assertRaises(BackupError) as caught:
            archive.verify_archive(copy, self.ids)
        self.assertEqual((caught.exception.code, caught.exception.details.get('member')),
                         ('corrupt-archive', f'apps/{SECOND}.tar.zst.age'))
        target = self.ws.dest()
        archive.extract_archive(copy, self.ids, target, apps=[APP])  # the untouched app still restores
        with self.assertRaises(BackupError):
            archive.extract_archive(copy, self.ids, self.ws.dest('second'), apps=[SECOND])

    def test_claiming_no_encryption_does_not_bypass_anything(self):
        def plain(doc):
            doc.update(encryption='none', compression='gzip', key_id=None)
            for app in doc['apps']:
                app['file'] = app['file'].replace('.tar.zst.age', '.tar.gz')
        copy = self.tampered(plain)
        with self.assertRaises(BackupError) as caught:
            archive.read_header(copy)  # the member names no longer match backup.json
        self.assertEqual(caught.exception.code, 'corrupt-archive')


# ---------------------------------------------------------------------------- outer structure

@needs_age
class OuterStructureTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)
        self.dest, _result, _payloads = self.ws.write_v2(name='orig.tar')
        self.members = outer_members(self.dest)
        self.ids = self.ws.keys.identities()

    def code(self, data, call='verify'):
        path = self.ws.out / 'hostile.tar'
        path.write_bytes(data)
        try:
            if call == 'header':
                archive.read_header(path)
            else:
                archive.verify_archive(path, self.ids)
        except BackupError as error:
            return error.code
        finally:
            self.assertEqual(tool_children(), [])
        return None

    def test_rebuilt_original_is_accepted(self):
        self.assertIsNone(self.code(build_outer(self.members)))
        self.assertIsNone(self.code(build_outer(self.members, trailer=bytes(4096))), 'zero padding after the end')

    def test_truncation_at_many_offsets(self):
        data = self.dest.read_bytes()
        with tarfile.open(self.dest) as tar:
            last = tar.getmembers()[-1]
        end = last.offset_data + (last.size + 511) // 512 * 512  # where the end-of-archive marker starts
        offsets = sorted({300, 512, 513, 1024, 1536, 2048, 4096, len(data) // 3, len(data) // 2, end - 20000,
                          end - 1, end, end + 511, end + 512, end + 1023})
        for cut in offsets:
            with self.subTest(cut=cut):
                self.assertIn(self.code(data[:cut]), ('corrupt-archive', 'not-a-backup'))
        for cut in (end + 1024, end + 4096, len(data) - 1):
            with self.subTest(valid_cut=cut):
                self.assertIsNone(self.code(data[:cut]), 'only zero padding after the end marker was cut')

    def test_extra_duplicate_missing_and_reordered_members(self):
        doc, readme, first, second = self.members
        cases = {
            'extra member at the end': [doc, readme, first, second, ('notes.txt', b'hello')],
            'duplicate app member': [doc, readme, first, first, second],
            'missing app member': [doc, readme, first],
            'apps reordered': [doc, readme, second, first],
            'README missing': [doc, first, second],
            'README twice': [doc, readme, readme, first, second],
        }
        for name, parts in cases.items():
            with self.subTest(name):
                self.assertEqual(self.code(build_outer(parts)), 'corrupt-archive')
        self.assertEqual(self.code(build_outer([readme, doc, first, second]), 'header'), 'not-a-backup')

    def test_special_members_garbage_and_padding(self):
        doc, readme, first, second = self.members
        body = build_outer([doc, readme, first, second], end=False)

        def special(name, kind, linkname=''):
            info = tarfile.TarInfo(name)
            info.type, info.linkname, info.mode = kind, linkname, 0o777
            return info.tobuf(tarfile.PAX_FORMAT)

        for name, kind in (('apps/x', tarfile.SYMTYPE), ('apps', tarfile.DIRTYPE), ('apps/y', tarfile.LNKTYPE),
                           ('fifo', tarfile.FIFOTYPE)):
            with self.subTest(kind=kind):
                data = body + special(name, kind, 'backup.json' if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else '')
                self.assertEqual(self.code(data + bytes(10240)), 'corrupt-archive')
        gnu = tarfile.TarInfo('x' * 120)
        gnu.size = 0
        self.assertEqual(self.code(body + gnu.tobuf(tarfile.GNU_FORMAT) + bytes(10240)), 'corrupt-archive')
        glob = tarfile.TarInfo('pax_global_header')
        glob.type = tarfile.XGLTYPE
        self.assertEqual(self.code(body + glob.tobuf(tarfile.PAX_FORMAT) + bytes(10240)), 'corrupt-archive')
        self.assertEqual(self.code(build_outer(self.members, trailer=b'\x01')), 'corrupt-archive', 'data after the end')
        raw = bytearray(build_outer(self.members))
        size = int(raw[124:136].rstrip(b'\0 '), 8)
        if size % 512:
            raw[512 + size] = 0x41  # first byte of backup.json's padding
            self.assertEqual(self.code(bytes(raw), 'header'), 'corrupt-archive')

    def test_backup_json_limits_and_strict_json(self):
        doc, readme, first, second = self.members
        for name, data, code in (
                ('not json', b'{not json', 'corrupt-archive'),
                ('duplicate keys', b'{"format": 2, "format": 2}', 'corrupt-archive'),
                ('too large', b' ' * (archive.MAX_BACKUP_JSON + 1), 'limit-exceeded'),
                ('format 1', json.dumps({'format': 1}).encode(), 'unsupported-format')):
            with self.subTest(name):
                self.assertEqual(self.code(build_outer([('backup.json', data), readme, first, second]), 'header'), code)
        self.assertEqual(self.code(build_outer([doc, ('README.txt', b'\xff\xfe' * 10), first, second]), 'header'),
                         'corrupt-archive')
        self.assertEqual(self.code(build_outer([doc, ('README.txt', b'x' * (archive.MAX_README + 1)), first,
                                                second]), 'header'), 'limit-exceeded')

    def test_other_tar_files_are_not_backups(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            info = tarfile.TarInfo('photo.jpg')
            info.size = 3
            tar.addfile(info, io.BytesIO(b'jpg'))
        self.assertEqual(self.code(buf.getvalue(), 'header'), 'not-a-backup')
        self.assertEqual(self.code(b'backup.json\0' + bytes(100), 'header'), 'corrupt-archive')
        self.assertEqual(self.code(b'', 'header'), 'not-a-backup')


# ---------------------------------------------------------------------------- hostile inner archives

@needs_age
class InnerArchiveTests(unittest.TestCase):
    FILES = {f'apps/{APP}/secrets/db-password': b'hunter2-but-longer', f'apps/{APP}/config/0': b'TITLE=demo\n'}

    def setUp(self):
        self.ws = V2Workspace(self)
        self.ids = self.ws.keys.identities()

    def backup(self, tar_bytes, inner=None, encryption='age-x25519', member=None, doc_change=None):
        inner = inner or small_inner(APP, self.ws.key.key_id, self.FILES, encryption=encryption)
        data = member if member is not None else seal_inner(tar_bytes, encryption, self.ws.key.recipient)
        doc = doc_for([(APP, data)], [inner], encryption)
        if doc_change:
            doc_change(doc)
        path = self.ws.out / 'crafted.tar'
        path.write_bytes(build_outer([('backup.json', pack_doc(doc)), ('README.txt', b'readme\n'),
                                      (archive.inner_name(APP, encryption), data)]))
        return path

    def outcome(self, path, ids=None):
        target = self.ws.dest(f'x{len(list(self.ws.base.iterdir()))}')
        try:
            archive.extract_archive(path, self.ids if ids is None else ids, target)
        except BackupError as error:
            self.assertEqual(list(target.iterdir()), [], 'nothing left after a refused extraction')
            return error.code
        finally:
            self.assertEqual(tool_children(), [])
        return None

    def test_control_crafted_archive_is_accepted(self):
        for encryption in ('age-x25519', 'none'):
            with self.subTest(encryption):
                inner = small_inner(APP, self.ws.key.key_id, self.FILES, encryption=encryption)
                path = self.backup(inner_tar(inner, self.FILES), inner, encryption)
                self.assertIsNone(self.outcome(path))

    def test_hostile_inner_tars(self):
        inner = small_inner(APP, self.ws.key.key_id, self.FILES)
        secret, config = list(self.FILES)
        link = tarfile.TarInfo(secret)
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
        cases = {
            'manifest not first': (tar_of([reg(secret, self.FILES[secret]),
                                           reg('manifest.json', json.dumps(inner).encode()),
                                           reg(config, self.FILES[config])]), 'corrupt-archive'),
            'empty': (tar_of([]), 'corrupt-archive'),
            'extra member': (inner_tar(inner, self.FILES, extra=[reg(f'apps/{APP}/config/9', b'x')]), 'corrupt-archive'),
            'missing member': (tar_of([reg('manifest.json', json.dumps(inner).encode()),
                                       reg(secret, self.FILES[secret])]), 'corrupt-archive'),
            'wrong order': (inner_tar(inner, self.FILES, order=[config, secret]), 'corrupt-archive'),
            'symlink member': (tar_of([reg('manifest.json', json.dumps(inner).encode()), (link, None),
                                       reg(config, self.FILES[config])]), 'corrupt-archive'),
            'size lie': (tar_of([reg('manifest.json', json.dumps(inner).encode()),
                                 reg(secret, self.FILES[secret] + b'!'), reg(config, self.FILES[config])]),
                         'corrupt-archive'),
            'content differs': (tar_of([reg('manifest.json', json.dumps(inner).encode()),
                                        reg(secret, b'x' * len(self.FILES[secret])), reg(config, self.FILES[config])]),
                                'corrupt-archive'),
            'oversize manifest': (tar_of([reg('manifest.json', b' ' * (archive.MAX_MANIFEST + 1))]), 'limit-exceeded'),
        }
        for name, (data, code) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.outcome(self.backup(data, inner)), code)

    def test_inner_manifest_must_match_backup_json_and_the_member(self):
        good = small_inner(APP, self.ws.key.key_id, self.FILES)
        other_backup = small_inner(APP, self.ws.key.key_id, self.FILES, backup_id='20261113T020000Z-ffffffff')
        other_apps = small_inner(APP, self.ws.key.key_id, self.FILES, backup_apps=[APP, SECOND])
        # backup.json written for `good`, but the authenticated manifest inside says something else.
        for name, inner in (('another backup', other_backup), ('another app list', other_apps)):
            with self.subTest(name):
                data = seal_inner(inner_tar(inner, self.FILES), 'age-x25519', self.ws.key.recipient)
                doc = doc_for([(APP, data)], [good])
                path = self.ws.out / 'crafted.tar'
                path.write_bytes(build_outer([('backup.json', pack_doc(doc)), ('README.txt', b'r'),
                                              (f'apps/{APP}.tar.zst.age', data)]))
                self.assertEqual(self.outcome(path), 'corrupt-archive')
        # The inner archive of one app placed under another app's name.
        renamed = small_inner(SECOND, self.ws.key.key_id,
                              {p.replace(APP, SECOND): d for p, d in self.FILES.items()}, backup_apps=[APP, SECOND])
        files = {p.replace(APP, SECOND): d for p, d in self.FILES.items()}
        data = seal_inner(inner_tar(renamed, files), 'age-x25519', self.ws.key.recipient)
        doc = doc_for([(APP, data)], [renamed])
        doc['apps'][0].update(id=APP, file=f'apps/{APP}.tar.zst.age')
        path = self.ws.out / 'crafted.tar'
        path.write_bytes(build_outer([('backup.json', pack_doc(doc)), ('README.txt', b'r'),
                                      (f'apps/{APP}.tar.zst.age', data)]))
        self.assertEqual(self.outcome(path), 'corrupt-archive')

    def test_too_many_members_and_invalid_manifest(self):
        inner = small_inner(APP, self.ws.key.key_id, self.FILES)
        many = dict(inner, entries=inner['entries'] + [{'path': f'apps/{APP}/config/{i + 9}', 'size': 0,
                                                        'sha256': hashlib.sha256(b'').hexdigest()}
                                                       for i in range(archive.MAX_MEMBERS)])
        self.assertEqual(self.outcome(self.backup(tar_of([reg('manifest.json', json.dumps(many).encode())]), inner)),
                         'limit-exceeded')
        bad = small_inner(APP, self.ws.key.key_id, self.FILES)
        bad['app']['config_files'][0]['path'] = '.ssh/authorized_keys'
        # backup.json shows the harmless path; the authenticated manifest inside fails its own schema first.
        self.assertEqual(self.outcome(self.backup(inner_tar(bad, self.FILES), inner)), 'invalid-manifest')
        # A backup.json that itself names such a path is refused before anything is decrypted.
        self.assertEqual(self.outcome(self.backup(inner_tar(bad, self.FILES), bad)), 'corrupt-archive')
        traversal = small_inner(APP, self.ws.key.key_id, self.FILES)
        traversal['entries'][0]['path'] = f'apps/{APP}/secrets/../../../etc/passwd'
        self.assertEqual(self.outcome(self.backup(inner_tar(traversal, self.FILES), traversal)), 'invalid-manifest')

    def test_compression_and_encryption_tricks(self):
        inner = small_inner(APP, self.ws.key.key_id, self.FILES, encryption='none')
        tar_bytes = inner_tar(inner, self.FILES)
        one = gzip.compress(tar_bytes, mtime=0)
        for name, member in (('garbage after the gzip stream', one + b'garbage'),
                             ('two gzip members', gzip.compress(tar_bytes[:2048], mtime=0)
                              + gzip.compress(tar_bytes[2048:], mtime=0)),
                             ('truncated gzip', one[:-10]),
                             ('not gzip', b'\x00' * 200)):
            with self.subTest(name):
                self.assertEqual(self.outcome(self.backup(None, inner, 'none', member=member), ids=[]),
                                 'corrupt-archive')
        enc = small_inner(APP, self.ws.key.key_id, self.FILES)
        sealed = seal_inner(inner_tar(enc, self.FILES), 'age-x25519', self.ws.key.recipient)
        self.assertEqual(self.outcome(self.backup(None, enc, member=sealed + b'trailing')), 'corrupt-archive')
        other = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True).stdout
        recipient = [line.split(': ')[1] for line in other.splitlines() if line.startswith('# public key: ')][0]
        foreign_inner = small_inner(APP, archive.key_id_for(recipient), self.FILES)
        foreign = seal_inner(inner_tar(foreign_inner, self.FILES), 'age-x25519', recipient)
        self.assertEqual(self.outcome(self.backup(None, foreign_inner, member=foreign)), 'wrong-key')
        # backup.json names this device's key, but the archive was encrypted to another one: damaged, not wrong key.
        self.assertEqual(self.outcome(self.backup(None, enc, member=foreign)), 'corrupt-archive')
        self.assertEqual(self.outcome(self.backup(None, enc, member=sealed), ids=[]), 'key-required')


# ---------------------------------------------------------------------------- per-app partial restore

@needs_age
class PartialRestoreTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)
        self.dest, self.result, self.payloads = self.ws.write_v2()
        self.ids = self.ws.keys.identities()
        with tarfile.open(self.dest) as tar:
            member = tar.getmember(f'apps/{SECOND}.tar.zst.age')
            self.second = (member.offset_data, member.offset_data + member.size)

    def test_only_the_selected_application_archive_is_read(self):
        reads = []
        real = os.pread

        def spy(fd, size, offset):
            reads.append((offset, offset + size))
            return real(fd, size, offset)

        target = self.ws.dest()
        with mock.patch('os.pread', side_effect=spy):
            manifest = archive.extract_archive(self.dest, self.ids, target, apps=[APP])
        start, end = self.second
        self.assertFalse([r for r in reads if r[0] < end and r[1] > start], 'no byte of the other app was read')
        self.assertEqual([a['id'] for a in manifest['apps']], [APP])
        self.assertTrue(all(e['path'].startswith(f'apps/{APP}/') for e in manifest['entries']))
        self.assertEqual(sorted(os.listdir(target / 'apps')), [APP])
        for path, data in self.payloads.items():
            if path.startswith(f'apps/{APP}/'):
                self.assertEqual((target / path).read_bytes(), data)

    def test_damage_in_another_app_does_not_block_a_restore_of_this_one(self):
        raw = bytearray(self.dest.read_bytes())
        start, end = self.second
        raw[(start + end) // 2] ^= 0xFF
        self.dest.write_bytes(bytes(raw))
        archive.extract_archive(self.dest, self.ids, self.ws.dest('a'), apps=[APP])
        for call in (lambda: archive.verify_archive(self.dest, self.ids),
                     lambda: archive.extract_archive(self.dest, self.ids, self.ws.dest('b'), apps=[SECOND])):
            with self.assertRaises(BackupError) as caught:
                call()
            self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertEqual(tool_children(), [])

    def test_an_app_the_backup_does_not_hold(self):
        with self.assertRaises(BackupError) as caught:
            archive.extract_archive(self.dest, self.ids, self.ws.dest(), apps=['missing-app'])
        self.assertEqual(caught.exception.code, 'incompatible')
        manifest = archive.read_manifest(self.dest, self.ids, apps=[SECOND])
        self.assertEqual([a['id'] for a in manifest['apps']], [SECOND])


# ---------------------------------------------------------------------------- deep verification

def listing_line(kind, mode, uid, gid, size, digest, target, path):
    target_hex = target.encode().hex() if target else '-'
    return f'{kind} {mode} {uid} {gid} {size} {digest} {target_hex} {path.encode().hex()}\n'.encode()


def realistic_app(app_id='deep-app', *, volume=None, image=None, listing=None, dump=b'PGDMP' + b'\0' * 64,
                  secret=b'pw'):
    """An app section and its payloads whose nested content passes the restore checks (keyword args break it)."""
    base = f'apps/{app_id}'
    ref = 'docker.io/library/postgres:16-alpine'
    volume = volume if volume is not None else tarfixtures.volume_tar()
    image = image if image is not None else tarfixtures.oci_archive(ref)
    if listing is None:
        listing = (listing_line('d', '0755', 0, 0, 0, '-', '', 'files')
                   + listing_line('f', '0644', 0, 0, 4, hashlib.sha256(b'data').hexdigest(), '', 'files/a.bin'))
    files_summary = {'entries': 0, 'files': 0, 'dirs': 0, 'symlinks': 0, 'other': 0, 'bytes': 0}
    for line in listing.splitlines():
        fields = line.split()
        files_summary['entries'] += 1
        key = {b'f': 'files', b'd': 'dirs', b'l': 'symlinks'}.get(fields[0], 'other')
        files_summary[key] += 1
        if fields[0] == b'f':
            files_summary['bytes'] += int(fields[4])
    payloads = {f'{base}/images/0.oci.tar': image, f'{base}/postgres/main.dump': dump,
                f'{base}/volumes/files.tar': volume, f'{base}/secrets/pw': secret,
                f'{base}/verify/files.txt': listing}
    app = {'id': app_id, 'name': '深度檢查', 'adapter': 'quadlet-postgres', 'adapter_version': 1,
           'catalog_sha256': 'b' * 64, 'owner': {'name': 'appowner', 'uid': 1001},
           'images': [{'ref': ref, 'id': tarfixtures.image_id(ref), 'digest': '', 'arch': 'amd64',
                       'entry': f'{base}/images/0.oci.tar'}],
           'postgres': [{'id': 'main', 'database': 'notes', 'server_version': '16.4', 'major': 16,
                         'entry': f'{base}/postgres/main.dump'}],
           'volumes': [{'name': 'files', 'entry': f'{base}/volumes/files.tar'}],
           'secrets': [{'name': 'pw', 'entry': f'{base}/secrets/pw'}], 'config_files': [], 'quadlet_files': [],
           'verify_snapshot': {},
           'verify_digests': [{'id': 'files', 'type': 'files-digest', 'target': 'volume:files', 'exclude': [],
                               'summary': files_summary, 'digest': hashlib.sha256(listing).hexdigest(),
                               'entry': f'{base}/verify/files.txt'}]}
    return app, payloads


@needs_age
class DeepVerifyTests(unittest.TestCase):
    def setUp(self):
        self.ws = V2Workspace(self)

    def make(self, fmt=2, **broken):
        app, payloads = realistic_app(**broken)
        entries = stage(self.ws.staging, payloads)
        manifest = demo_manifest(self.ws.key.key_id, apps=[app])
        if fmt == 2:
            manifest.update(format=2, encryption='age-x25519')
        dest = self.ws.out / f'deep-{len(list(self.ws.out.iterdir()))}.{"tar" if fmt == 2 else "woowbackup"}'
        archive.write_archive(dest, None, manifest, entries, self.ws.key.recipient, tmp_dir=self.ws.out)
        shutil.rmtree(self.ws.staging)
        self.ws.staging.mkdir(mode=0o700)
        return dest

    def deep(self, dest):
        scratch = self.ws.dest(f'scratch{len(list(self.ws.base.iterdir()))}')
        check = DeepCheck()
        try:
            return archive.verify_archive(dest, self.ws.keys.identities(), deep=check, scratch_dir=scratch), check
        finally:
            self.assertEqual(list(scratch.iterdir()), [], 'each scratch copy is deleted after its check')

    def test_realistic_content_passes_in_both_formats(self):
        for fmt in (2, 1):
            with self.subTest(fmt=fmt):
                result, check = self.deep(self.make(fmt))
                self.assertEqual(result['format'], fmt)
                self.assertEqual(check.report(), [{'id': 'deep-app', 'name': '深度檢查', 'checked': {
                    'volumes': 1, 'dirs': 0, 'images': 1, 'digests': 1, 'globals': 0, 'dumps': 1, 'secrets': 1},
                    'header_only': ['dumps']}], 'a dump is only recognized by its header (review L8)')

    def test_a_local_read_error_is_not_a_defect_of_the_backup(self):
        # review F10: EIO/EMFILE while reading the scratch copy says nothing about the backup -- internal-error, so the
        # verify job records no `verified` (only corrupt-archive and the other archive defects do)
        import errno
        from woowbackup import nested
        dest = self.make(2)
        with mock.patch.object(nested, 'check_volume', side_effect=OSError(errno.EIO, 'Input/output error')):
            with self.assertRaises(BackupError) as caught:
                self.deep(dest)
        self.assertEqual(caught.exception.code, 'internal-error')
        with mock.patch.object(nested.tarfile, 'open', side_effect=OSError(errno.EMFILE, 'Too many open files')):
            with self.assertRaises(BackupError) as caught:
                self.deep(dest)
        self.assertEqual(caught.exception.code, 'internal-error')
        # tarfile's own "unexpected end of data" (no errno) is still a defect of the content
        with mock.patch.object(nested, 'check_volume', side_effect=OSError('unexpected end of data')):
            with self.assertRaises(BackupError) as caught:
                self.deep(dest)
        self.assertEqual(caught.exception.code, 'corrupt-archive')

    def test_content_a_restore_would_refuse_fails_the_verify(self):
        escape = tarfixtures.volume_tar([{'name': 'files/', 'kind': tarfile.DIRTYPE, 'mode': 0o755},
                                         {'name': 'files/evil', 'kind': tarfile.SYMTYPE, 'linkname': '../../../etc'}])
        bad_listing = b'not a listing line\n'
        cases = {
            'volume symlink leaving it': ({'volume': escape}, 'volumes'),
            'volume that is not a tar': ({'volume': b'volume-tar-bytes' * 100}, 'volumes'),
            'image of another ref': ({'image': tarfixtures.oci_archive('docker.io/library/redis:7')}, 'images'),
            'digest listing malformed': ({'listing': bad_listing}, 'digests'),
            'dump not pg_dump custom format': ({'dump': b'-- plain SQL\n'}, 'dumps'),
            'empty secret': ({'secret': b''}, 'secrets'),
        }
        for fmt in (2, 1):
            for name, (broken, check_kind) in cases.items():
                with self.subTest(fmt=fmt, case=name):
                    dest = self.make(fmt, **broken)
                    archive.verify_archive(dest, self.ws.keys.identities())  # the archive itself is intact
                    with self.assertRaises(BackupError) as caught:
                        self.deep(dest)
                    self.assertEqual(caught.exception.code, 'corrupt-archive')
                    self.assertEqual(caught.exception.details.get('check'), check_kind)
                    self.assertIn('這份備份無法還原', caught.exception.message)
                    self.assertEqual(tool_children(), [])

    def test_digest_summary_must_match_the_listing(self):
        app, payloads = realistic_app()
        app['verify_digests'][0]['summary']['files'] = 7
        entries = stage(self.ws.staging, payloads)
        manifest = demo_manifest(self.ws.key.key_id, apps=[app])
        manifest.update(format=2, encryption='age-x25519')
        dest = self.ws.out / 'summary.tar'
        archive.write_archive(dest, None, manifest, entries, self.ws.key.recipient, tmp_dir=self.ws.out)
        with self.assertRaises(BackupError) as caught:
            self.deep(dest)
        self.assertEqual(caught.exception.details.get('check'), 'digests')


# ---------------------------------------------------------------------------- v1 forever

@needs_age
class V1CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def test_v1_reads_through_the_same_api_with_app_selection(self):
        payloads = dict(demo_payloads(big=4096))
        payloads.update(second_payloads())
        manifest = demo_manifest(self.ws.key.key_id, apps=[demo_app(), second_app()])
        dest, _result, _entries = self.ws.write(payloads, manifest=manifest, name='old.woowbackup')
        ids = self.ws.keys.identities()
        self.assertEqual(archive.format_of(dest), 1)
        self.assertEqual(archive.read_header(dest)['format'], 1)
        self.assertEqual(archive.describe(dest)['format'], 1)
        self.assertEqual([a['id'] for a in archive.read_manifest(dest, ids)['apps']], [APP, SECOND])
        self.assertEqual(archive.verify_archive(dest, ids)['format'], 1)
        target = self.ws.dest()
        selected = archive.extract_archive(dest, ids, target, apps=[SECOND])
        self.assertEqual([a['id'] for a in selected['apps']], [SECOND])
        self.assertEqual(sorted(os.listdir(target / 'apps')), [SECOND], 'only the selected app is written')
        for path, data in payloads.items():
            if path.startswith(f'apps/{SECOND}/'):
                self.assertEqual((target / path).read_bytes(), data)
        with self.assertRaises(BackupError) as caught:
            archive.extract_archive(dest, ids, self.ws.dest('none'), apps=['missing-app'])
        self.assertEqual(caught.exception.code, 'incompatible')


# ---------------------------------------------------------------------------- the parallel gzip writer

class GzipWriterTests(unittest.TestCase):
    def test_parallel_blocks_make_one_standard_gzip_stream(self):
        data = (os.urandom(300_000) + b'compressible ' * 200_000) * 3 + b'tail'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'out.gz'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            digest = hashlib.sha256()
            try:
                writer = archive._GzipWriter(fd, digest, workers=3)
                for offset in range(0, len(data), 70_000):
                    writer.write(data[offset:offset + 70_000])
                writer.close()
            finally:
                os.close(fd)
            raw = path.read_bytes()
            self.assertGreater(len(data), 3 * archive.GZIP_BLOCK, 'several blocks were compressed in parallel')
            self.assertEqual(writer.total, len(raw))
            self.assertEqual(digest.hexdigest(), hashlib.sha256(raw).hexdigest())
            self.assertEqual(gzip.decompress(raw), data)
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            self.assertEqual(inflater.decompress(raw), data)
            self.assertTrue(inflater.eof and not inflater.unused_data, 'exactly one gzip member')
            result = subprocess.run(['gzip', '-t', str(path)], capture_output=True)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertLess(len(raw), len(data) * 0.6)


if __name__ == '__main__':
    unittest.main()
