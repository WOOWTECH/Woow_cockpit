"""Generate the small Home Assistant backup fixtures of tests/backup/test_ha_*.py with the REAL securetar library.

Never run by the tests (they only read the committed files). Run in a scratch virtualenv that has securetar, and the
older writers installed with `pip --no-deps --target` (see README.md here):

  PY=<venv>/bin/python; OUT=<empty scratch dir>
  $PY -I generate.py build-v1      --out $OUT --lib <dir with securetar 2024.11.0>   # v1 gzip + plain (Supervisor <= 2024.12)
  $PY -I generate.py build-v2-2025 --out $OUT --lib <dir with securetar 2025.12.0>   # v2 gzip (Supervisor 2025.12.3)
  $PY -I generate.py build         --out $OUT          # v3 gzip + plain, v2 gzip, unencrypted, download (securetar 2026.10.0)
  $PY -I generate.py record        --out $OUT                                        # fixtures.json (2026.10.0 reads)

Each fixture is a whole backup the way Supervisor writes it: a plain PAX outer tar with one inner tar per component
(`<repo>_odoo18ce`, `<repo>_woow-n8n`, the `share` folder, `supervisor`) and `./backup.json` LAST. The inner trees
copy the layout of real WOOWTECH add-on backups (addon.json, data/postgres, data/odoo/filestore, data/addons,
config/.n8n, options.json and odoo.conf with made-up secrets) with the owners a real backup has (postgres 100:102,
odoo 101:103). `record` reads every member back with securetar 2026.10.0 and writes fixtures.json: per member its
encryption, the sha256 and length of the plaintext the library returns (not for v1 uncompressed members, which that
library truncates) and the entries that were written, so the tests can check byte-identical decryption and the whole
read path. The password is made up for these fixtures only.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

PASSWORD = 'ABCD-EFGH-JKLM-NPQR-STUV-WXY2-3456'   # made-up HA-style key, fixtures only
WRONG_PASSWORD = 'ABCD-EFGH-JKLM-NPQR-STUV-WXY2-3457'
BUF_SIZE = 4 * 2 ** 20                             # supervisor/backups/const.py
ODOO = '5e12b5f3_odoo18ce'
N8N = '4b6d58cd_woow-n8n'
MTIME = 1794992487.25                              # float mtimes: tarfile writes PAX records like a real backup
SECRETS = ('fixture-admin-secret', 'fixture-db-secret', 'fixture-access-token', 'fixture-ingress-token',
           'fixture-env-secret', 'fixture-runner-token')


def blob(seed, size):
    out, counter = bytearray(), 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}:{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


def d(name, mode=0o755, uid=0, gid=0):
    return {'name': name, 'type': 'dir', 'mode': mode, 'uid': uid, 'gid': gid}


def f(name, data, mode=0o644, uid=0, gid=0):
    return {'name': name, 'type': 'file', 'data': data, 'mode': mode, 'uid': uid, 'gid': gid}


def link(name, target, uid=0, gid=0):
    return {'name': name, 'type': 'symlink', 'target': target, 'mode': 0o777, 'uid': uid, 'gid': gid}


def addon_json(slug, version, image, options):
    return json.dumps({
        'user': {'version': version, 'image': image, 'uuid': '0123456789abcdef0123456789abcdef',
                 'access_token': 'fixture-access-token', 'ingress_token': 'fixture-ingress-token',
                 'options': options, 'boot': 'auto', 'auto_update': False, 'protected': True},
        'system': {'slug': slug, 'name': {'odoo18ce': 'Woow Odoo 18', 'woow-n8n': 'Woow n8n'}[slug], 'version': version,
                   'arch': ['amd64', 'aarch64'], 'image': image.rsplit('-', 1)[0] + '-{arch}',
                   'repository': '5e12b5f3' if slug == 'odoo18ce' else '4b6d58cd'},
        'version': version, 'state': 'started'}).encode()


def odoo_tree():
    pg, odoo = (100, 102), (101, 103)
    manifest = (b"{'name': 'Woow Demo', 'version': '18.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3',\n"
                b" 'external_dependencies': {'python': []}}\n")
    return [
        d('.'),
        f('./addon.json', addon_json('odoo18ce', '0.4.12', 'ghcr.io/woowtech/woow-ha-odoo-amd64',
                                     {'admin_passwd': 'fixture-admin-secret', 'db_password': 'fixture-db-secret',
                                      'workers': 2})),
        d('data'),
        f('data/options.json', json.dumps({'admin_passwd': 'fixture-admin-secret',
                                           'db_password': 'fixture-db-secret'}).encode(), 0o600),
        f('data/odoo.conf', b'[options]\nadmin_passwd = fixture-admin-secret\ndb_password = fixture-db-secret\n', 0o600,
          *odoo),
        d('data/postgres', 0o700, *pg),
        f('data/postgres/PG_VERSION', b'16\n', 0o600, *pg),
        d('data/postgres/base', 0o700, *pg),
        d('data/postgres/base/1', 0o700, *pg),
        f('data/postgres/base/1/1259', blob('pg', 8192), 0o600, *pg),
        d('data/postgres/pg_tblspc', 0o700, *pg),
        d('data/odoo', 0o755, *odoo),
        d('data/odoo/filestore', 0o755, *odoo),
        d('data/odoo/filestore/odoo', 0o755, *odoo),
        d('data/odoo/filestore/odoo/ab', 0o755, *odoo),
        f('data/odoo/filestore/odoo/ab/abcdef0123456789', blob('attachment', 3000), 0o644, *odoo),
        d('data/addons', 0o755, *odoo),
        d('data/addons/woow_demo', 0o755, *odoo),
        f('data/addons/woow_demo/__manifest__.py', manifest, 0o644, *odoo),
        f('data/addons/woow_demo/__init__.py', b'', 0o644, *odoo),
        link('data/pgver.link', 'postgres/PG_VERSION'),
        d('config'),
    ]


def n8n_tree():
    return [
        d('.'),
        f('./addon.json', addon_json('woow-n8n', '2.43.6', 'ghcr.io/woowtech/woow-ha-n8n-amd64',
                                     {'N8N_LOG_LEVEL': 'info',
                                      'env_vars': [{'key': 'FIXTURE', 'value': 'fixture-env-secret'}]})),
        d('config'),
        d('config/.n8n'),
        f('config/.n8n/config', b'{"encryptionKey": "fixture-n8n-encryption-key"}', 0o600),
        f('config/.n8n/database.sqlite', b'SQLite format 3\x00' + bytes(4080)),
        d('config/.n8n/nodes'),
        f('config/.n8n/nodes/package.json', b'{"dependencies": {"n8n-nodes-fixture": "1.0.0"}}\n'),
        d('config/.n8n/nodes/node_modules'),
        d('config/.n8n/nodes/node_modules/n8n-nodes-fixture'),
        f('config/.n8n/nodes/node_modules/n8n-nodes-fixture/index.js', b'module.exports = {};\n'),
        d('config/.n8n/nodes/node_modules/.bin'),
        link('config/.n8n/nodes/node_modules/.bin/fixture', '../n8n-nodes-fixture/index.js'),
        link('config/.n8n/nodes/node_modules/escape', '../../../../data'),
        d('config/.cache'),
        f('config/.cache/blob.bin', blob('cache', 1000)),
        d('data'),
        f('data/options.json', b'{"N8N_LOG_LEVEL": "info"}', 0o600),
        f('data/n8n-runners-auth-token', b'fixture-runner-token' + b'0' * 44, 0o600),
    ]


def share_tree():
    return [
        d('.'),
        d('odoo_addons'),
        d('odoo_addons/woow_custom'),
        f('odoo_addons/woow_custom/__manifest__.py', b"{'name': 'Woow Custom', 'version': '18.0.2.0.0'}\n"),
    ]


def supervisor_tree():
    return [f('mounts.json', b'{"mounts": []}'), f('docker.json', b'{"registries": {}}')]


COMPONENTS = [(ODOO, odoo_tree), (N8N, n8n_tree), ('share', share_tree), ('supervisor', supervisor_tree)]
# Uncompressed inner tars are padded to 10 KiB records: those fixtures carry only the Odoo add-on and supervisor.
PLAIN_COMPONENTS = [(ODOO, odoo_tree), ('supervisor', supervisor_tree)]


def components(gzip):
    return COMPONENTS if gzip else PLAIN_COMPONENTS


def add_tree(tar, items):
    rows = []
    for item in items:
        info = tarfile.TarInfo(item['name'])
        info.mode, info.uid, info.gid, info.mtime = item['mode'], item['uid'], item['gid'], MTIME
        data = None
        if item['type'] == 'dir':
            info.type = tarfile.DIRTYPE
        elif item['type'] == 'symlink':
            info.type = tarfile.SYMTYPE
            info.linkname = item['target']
        else:
            data = item['data']
            info.size = len(data)
        tar.addfile(info, io.BytesIO(data) if data is not None else None)
        rows.append([item['name'], item['type'], item['mode'], item['uid'], item['gid'], len(data or b''),
                     hashlib.sha256(data).hexdigest() if data is not None else None, item.get('target')])
    return rows


def backup_json(slug, name, protected, compressed, supervisor_version, *, crypto=False):
    addons = [{'slug': ODOO, 'name': 'Woow Odoo 18', 'version': '0.4.12', 'size': 0.0}]
    if compressed:
        addons.append({'slug': N8N, 'name': 'Woow n8n', 'version': '2.43.6', 'size': 0.0})
    doc = {'slug': slug, 'version': 2, 'name': name, 'date': '2026-11-18T09:01:20.915956+00:00', 'type': 'partial',
           'supervisor_version': supervisor_version, 'extra': {}, 'homeassistant': None,
           'repositories': ['https://github.com/WOOWTECH/Woow_ha_odoo', 'https://github.com/WOOWTECH/Woow_ha_n8n'],
           'compressed': compressed, 'folders': ['share'] if compressed else [], 'addons': addons,
           'protected': protected}
    if crypto:
        doc['crypto'] = 'aes128'
    return json.dumps(doc).encode()


def read_all(reader):
    """securetar's decrypt stream must be read in sized chunks (a bare read() returns nothing)."""
    parts = []
    while chunk := reader.read(2 ** 20):
        parts.append(chunk)
    return b''.join(parts)


def add_backup_json(outer, raw):
    info = tarfile.TarInfo('./backup.json')
    info.size, info.mtime = len(raw), MTIME
    outer.addfile(info, io.BytesIO(raw))


def save_rows(out, name, writer, rows):
    (out / f'{name}.rows.json').write_text(json.dumps({'writer': writer, 'members': rows}, indent=1))


def build_new(out):
    import securetar
    from securetar import SecureTarArchive
    assert 'site-packages' in securetar.__file__, securetar.__file__
    plans = [('v3_gzip.tar', 3, True), ('v3_plain.tar', 3, False), ('v2_gzip.tar', 2, True),
             ('plain_gzip.tar', None, True)]
    for name, version, gzip in plans:
        kwargs = {} if version is None else {'create_version': version, 'password': PASSWORD}
        rows = {}
        with SecureTarArchive(out / name, 'w', bufsize=BUF_SIZE, **kwargs) as archive:
            for stem, tree in components(gzip):
                member = f'./{stem}.tar{".gz" if gzip else ""}'
                with archive.create_tar(member, gzip=gzip) as tar:
                    rows[member.removeprefix('./')] = add_tree(tar, tree())
            add_backup_json(archive.tar, backup_json(f'f1x7{version or 0}{"a" if gzip else "b"}00',
                                                     f'fixture {name[:-4]}', version is not None, gzip, '2026.11.0'))
        save_rows(out, name, f'securetar 2026.10.0 create_version={version}' if version else 'securetar 2026.10.0 '
                  'without password (Supervisor 2026.11.0, no encryption)', rows)
        print(name, (out / name).stat().st_size)
    # What Home Assistant's "download" button gives for a protected backup when the key is configured (Core
    # backup/util.py): the members Core knows decrypted, supervisor.tar.gz copied still encrypted, protected false.
    source = out / 'v3_gzip.tar'
    name = 'downloaded_gzip.tar'
    rows = json.loads((out / 'v3_gzip.tar.rows.json').read_text())['members']
    with SecureTarArchive(source, 'r', password=PASSWORD) as archive, tarfile.open(out / name, 'w') as dest:
        for member in archive.tar.getmembers():
            if member.name.endswith('backup.json'):
                doc = json.loads(archive.tar.extractfile(member).read())
                doc['protected'] = False
                doc['slug'] = 'f1x7d0wn'
                doc['name'] = 'fixture downloaded'
                add_backup_json(dest, json.dumps(doc).encode())
                continue
            info = tarfile.TarInfo(member.name)
            info.mtime = MTIME
            if member.name.startswith('supervisor'):
                data = archive.tar.extractfile(member).read()
            else:
                with archive.extract_tar(member) as reader:
                    data = read_all(reader)
            info.size = len(data)
            dest.addfile(info, io.BytesIO(data))
    save_rows(out, name, 'decrypted copy of v3_gzip.tar like Home Assistant Core 2026.7 downloads it', rows)
    print(name, (out / name).stat().st_size)


def record(out):
    import securetar
    from securetar import SecureTarArchive
    assert 'site-packages' in securetar.__file__, securetar.__file__
    result = {'password': PASSWORD, 'wrong_password': WRONG_PASSWORD, 'secrets': list(SECRETS),
              'reader': 'securetar 2026.10.0', 'fixtures': {}}
    for rows_file in sorted(out.glob('*.rows.json')):
        name = rows_file.name[:-len('.rows.json')]
        meta = json.loads(rows_file.read_text())
        members = {}
        with SecureTarArchive(out / name, 'r', password=PASSWORD) as archive:
            for member in archive.tar.getmembers():
                if member.name.endswith('backup.json'):
                    continue
                stem = member.name.removeprefix('./')
                head = archive.tar.extractfile(member).read(16)
                encryption = ('v3' if head[:10] == b'SecureTar\x03' else 'v2' if head[:10] == b'SecureTar\x02'
                              else 'none' if head[:2] == b'\x1f\x8b' or name.startswith(('plain', 'downloaded'))
                              else 'v1')
                if name.startswith('downloaded') and stem.startswith('supervisor'):
                    encryption = 'v3'
                entry = {'encryption': encryption, 'entries': meta['members'][stem]}
                if encryption == 'none':
                    data = archive.tar.extractfile(member).read()
                    entry.update(plaintext_sha256=hashlib.sha256(data).hexdigest(), plaintext_length=len(data))
                elif encryption == 'v1' and not stem.endswith('.gz'):
                    entry['library_truncates'] = True  # securetar 2026.10.0 drops the last buffer (HA-FACTS 1.6)
                else:
                    with archive.extract_tar(member) as reader:
                        data = read_all(reader)
                    entry.update(plaintext_sha256=hashlib.sha256(data).hexdigest(), plaintext_length=len(data))
                members[stem] = entry
        result['fixtures'][name] = {'writer': meta['writer'], 'size': (out / name).stat().st_size, 'members': members}
        rows_file.unlink()
    (out / 'fixtures.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    print('fixtures.json:', len(result['fixtures']), 'fixtures')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('step', choices=('build-v1', 'build-v2-2025', 'build', 'record'))
    parser.add_argument('--out', required=True)
    parser.add_argument('--lib')
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.step in ('build-v1', 'build-v2-2025'):
        if not args.lib:
            parser.error('--lib is required for the old writers')
        sys.path.insert(0, str(Path(args.lib).resolve()))
        build_old_writer(out, args.lib, 1 if args.step == 'build-v1' else 2)
    elif args.step == 'build':
        build_new(out)
    else:
        record(out)
    return 0


def build_old_writer(out, lib, version):
    """Like Supervisor 2024.12.3 / 2025.12.3 backups/backup.py: outer SecureTarFile(path, "w", gzip=False), one
    create_inner_tar("./<name>.tar[.gz]") per component, backup.json added last."""
    import securetar
    from securetar import SecureTarFile
    assert str(Path(lib).resolve()) in securetar.__file__, securetar.__file__
    key = PASSWORD.encode()
    for _ in range(100):
        key = hashlib.sha256(key).digest()
    key = key[:16]
    label = ('securetar 2024.11.0 (as Supervisor 2024.12.3 calls it)' if version == 1
             else 'securetar 2025.12.0 (as Supervisor 2025.12.3 calls it)')
    for gzip in ((True, False) if version == 1 else (True,)):
        name = f'v{version}{"_2025" if version == 2 else ""}_{"gzip" if gzip else "plain"}.tar'
        rows = {}
        outer = SecureTarFile(out / name, 'w', gzip=False, bufsize=BUF_SIZE)
        with outer as outer_tar:
            for stem, tree in components(gzip):
                member = f'./{stem}.tar{".gz" if gzip else ""}'
                kwargs = {'key': key} if version == 1 else {'password': PASSWORD}
                with outer.create_inner_tar(member, gzip=gzip, **kwargs) as tar:
                    rows[member.removeprefix('./')] = add_tree(tar, tree())
            add_backup_json(outer_tar, backup_json(f'f1x7{version}{"a" if gzip else "b"}00',
                                                   f'fixture v{version} {"gzip" if gzip else "plain"}', True, gzip,
                                                   '2024.12.3' if version == 1 else '2025.12.3', crypto=version == 1))
        save_rows(out, name, label, rows)
        print(name, (out / name).stat().st_size)


if __name__ == '__main__':
    sys.exit(main())
