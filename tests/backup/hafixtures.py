"""Helpers for the Home Assistant backup tests (team E1): the committed real-securetar fixtures, builders of crafted
(hostile) outer and inner tars, and a test-only SecureTar v3 writer for chunk and tag edge cases.

The fixtures in fixtures/ha/ were written by the real securetar library (fixtures/ha/README.md); the v3 writer here
follows the same format (securetar 2026.10.0 `_iter_secretstream` in reverse) and is only used where a real file would
be too large (several 1 MiB chunks) or impossible to make with the library (wrong tags).
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
import struct
import tarfile
import unittest
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'ha'
META = json.loads((FIXTURES / 'fixtures.json').read_text())
PASSWORD = META['password']
WRONG_PASSWORD = META['wrong_password']
SECRETS = tuple(META['secrets'])
ODOO = '5e12b5f3_odoo18ce'
N8N = '4b6d58cd_woow-n8n'
MTIME = 1794992487.25

# CI installs both packages (validate.yml) and sets WOOWBK_REQUIRE_HA_CRYPTO: there a missing one fails the tests
# instead of skipping them.
REQUIRED = bool(os.environ.get('WOOWBK_REQUIRE_HA_CRYPTO'))
HAVE_NACL = importlib.util.find_spec('nacl') is not None
HAVE_CRYPTOGRAPHY = importlib.util.find_spec('cryptography') is not None
needs_nacl = unittest.skipUnless(HAVE_NACL or REQUIRED, 'needs PyNaCl (python3-nacl; installed in CI and the runner)')
needs_cryptography = unittest.skipUnless(HAVE_CRYPTOGRAPHY or REQUIRED,
                                         'needs cryptography (python3-cryptography; installed in CI and the runner)')
needs_crypto = unittest.skipUnless((HAVE_NACL and HAVE_CRYPTOGRAPHY) or REQUIRED,
                                   'needs PyNaCl and cryptography (installed in CI and the runner)')


def fixture(name):
    return FIXTURES / name


def fixture_members(name):
    return META['fixtures'][name]['members']


def member_bytes(path, name):
    """Raw bytes of one member of an outer tar (test side, Python's tarfile)."""
    with tarfile.open(path, 'r:') as outer:
        for info in outer.getmembers():
            if info.name.removeprefix('./') == name:
                return outer.extractfile(info).read(), info
    raise KeyError(name)


# ---------------------------------------------------------------- crafted tars

def tar_bytes(entries, *, fmt=tarfile.PAX_FORMAT, compress=False, pax_headers=None):
    """A tar of entries: dicts with name, type (file|dir|symlink|hardlink|fifo|chr|blk or a raw tarfile type),
    data, mode, uid, gid, linkname, pax (extra PAX records), mtime."""
    buffer = io.BytesIO()
    kwargs = {'pax_headers': pax_headers} if pax_headers else {}
    with tarfile.open(fileobj=buffer, mode='w', format=fmt, **kwargs) as tar:
        for item in entries:
            info = tarfile.TarInfo(item['name'])
            kind = item.get('type', 'file')
            info.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE,
                         'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE, 'chr': tarfile.CHRTYPE,
                         'blk': tarfile.BLKTYPE}.get(kind, kind)
            info.mode = item.get('mode', 0o755 if kind == 'dir' else 0o644)
            info.uid, info.gid = item.get('uid', 0), item.get('gid', 0)
            info.mtime = item.get('mtime', MTIME)
            info.linkname = item.get('linkname', '')
            data = item.get('data', b'' if kind == 'file' else None)
            if data is not None:
                info.size = len(data)
            if item.get('pax'):
                info.pax_headers = dict(item['pax'])
            tar.addfile(info, io.BytesIO(data) if data else None)
    raw = buffer.getvalue()
    return gzip.compress(raw, mtime=0) if compress else raw


def ha_doc(addons=(ODOO,), *, folders=(), protected=False, compressed=True, homeassistant=None, **overrides):
    doc = {'slug': 'c0ffee00', 'version': 2, 'name': 'crafted', 'date': '2026-11-18T09:01:20.915956+00:00',
           'type': 'partial', 'supervisor_version': '2026.11.0', 'extra': {}, 'homeassistant': homeassistant,
           'repositories': [], 'compressed': compressed, 'protected': protected, 'folders': list(folders),
           'addons': [{'slug': slug, 'name': f'name of {slug}', 'version': '1.0.0', 'size': 0.0} for slug in addons]}
    doc.update(overrides)
    return doc


def addon_member(slug_suffix='odoo18ce', *, image='ghcr.io/woowtech/woow-ha-odoo-amd64', extra=(), compress=True,
                 options=None):
    """A plain add-on inner tar (gzip by default) like Supervisor writes: '.', './addon.json', data/, config/."""
    addon = {'user': {'version': '0.4.12', 'image': image, 'options': options or {'admin_passwd': 'fixture-admin-secret'},
                      'access_token': 'fixture-access-token'},
             'system': {'slug': slug_suffix, 'name': 'Crafted', 'version': '0.4.12', 'arch': ['amd64']},
             'version': '0.4.12', 'state': 'started'}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/hello.txt', 'data': b'hello'},
               *extra, {'name': 'config', 'type': 'dir'}]
    return tar_bytes(entries, compress=compress)


def outer_bytes(members, doc=None, *, json_name='./backup.json', json_raw=None, json_first=False, fmt=tarfile.PAX_FORMAT,
                pax_headers=None, member_pax=None, types=None):
    """An HA-style outer tar: `members` [(name, bytes)], then backup.json (`doc`, default from ha_doc) last."""
    raw_json = json_raw if json_raw is not None else json.dumps(doc if doc is not None else ha_doc()).encode()
    items = [(name, data) for name, data in members]
    doc_item = (json_name, raw_json)
    items = [doc_item, *items] if json_first else [*items, doc_item]
    buffer = io.BytesIO()
    kwargs = {'pax_headers': pax_headers} if pax_headers else {}
    with tarfile.open(fileobj=buffer, mode='w', format=fmt, **kwargs) as tar:
        for name, data in items:
            info = tarfile.TarInfo(name)
            info.mtime = MTIME
            info.size = len(data)
            if types and name in types:
                info.type = types[name]
                info.size = 0
            if member_pax and name in member_pax:
                info.pax_headers = dict(member_pax[name])
            tar.addfile(info, io.BytesIO(data) if info.size else None)
    return buffer.getvalue()


def simple_backup(**doc_overrides):
    """A small valid unencrypted HA backup: the Odoo add-on and backup.json."""
    return outer_bytes([(f'{ODOO}.tar.gz', addon_member())], ha_doc(**doc_overrides))


def header_offsets(data):
    """[(header offset, name)] of the regular members (and their PAX headers) of an outer tar (for patching)."""
    found, pos = [], 0
    while pos + 512 <= len(data):
        block = data[pos:pos + 512]
        if block == bytes(512):
            break
        size = int(block[124:136].split(b'\0', 1)[0].strip() or b'0', 8)
        found.append((pos, block[0:100].split(b'\0', 1)[0].decode(), block[156:157]))
        pos += 512 + (size + 511) // 512 * 512
    return found


# ---------------------------------------------------------------- raw tar blocks (dialects tarfile does not write)

USTAR, GNU, V7 = b'ustar\x0000', b'ustar  \x00', bytes(8)


def raw_header(name, *, typeflag=b'0', size=0, linkname=b'', magic=USTAR, mode=0o644, uid=0, gid=0, mtime=0,
               prefix=b''):
    """One 512-byte tar header with a valid checksum; `name`, `linkname` and `prefix` are bytes or text."""
    def raw(value):
        return value if isinstance(value, bytes) else value.encode('utf-8', 'surrogateescape')

    def octal(value, width):
        return b'%0*o\0' % (width - 1, value)
    body = (raw(name).ljust(100, b'\0') + octal(mode, 8) + octal(uid, 8) + octal(gid, 8) + octal(size, 12)
            + octal(mtime, 12) + b' ' * 8 + typeflag + raw(linkname).ljust(100, b'\0') + magic
            + bytes(80) + raw(prefix).ljust(155, b'\0'))
    return fix_checksum(body.ljust(512, b'\0'))


def padded(data):
    return data + bytes(-len(data) % 512)


def raw_member(name, data=b'', *, size=None, **header):
    """Header and padded data of one member (`size`: what the header says, default the data's)."""
    return raw_header(name, size=len(data) if size is None else size, **header) + padded(data)


def pax_records(records):
    """The data of a PAX extended header: {key: value} (bytes or text)."""
    parts = []
    for key, value in records.items():
        body = b' ' + (key if isinstance(key, bytes) else key.encode()) + b'=' \
               + (value if isinstance(value, bytes) else value.encode('utf-8', 'surrogateescape')) + b'\n'
        length = len(body) + 1
        while len(str(length)) + len(body) != length:
            length = len(str(length)) + len(body)
        parts.append(str(length).encode() + body)
    return b''.join(parts)


def pax_member(records, *, typeflag=b'x', name='PaxHeader'):
    return raw_member(name, pax_records(records) if isinstance(records, dict) else records, typeflag=typeflag)


END = bytes(1024)


def two_addons(odoo=None, n8n=None, *, doc=None, extra=(), **kwargs):
    """An HA backup of two add-ons; `odoo`/`n8n`: their member's bytes (default: good ones)."""
    odoo = addon_member() if odoo is None else odoo
    n8n = addon_member('woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64') if n8n is None else n8n
    return outer_bytes([(f'{ODOO}.tar.gz', odoo), (f'{N8N}.tar.gz', n8n), *extra],
                       ha_doc([ODOO, N8N]) if doc is None else doc, **kwargs)


def fix_checksum(block):
    block = bytearray(block)
    block[148:156] = b' ' * 8
    block[148:156] = b'%06o\0 ' % (sum(block))
    return bytes(block)


# ---------------------------------------------------------------- test-only SecureTar v3 writer

V3_CHUNK = 1024 * 1024


def _subkey(root, salt):
    return hashlib.blake2b(b'', digest_size=32, key=root, salt=salt, person=b'SecureTarv3').digest()


def v3_encrypt(plaintext, password=PASSWORD, *, tags=None, chunks=None, declared_size=None, salts=None):
    """A SecureTar v3 file of `plaintext` (header + secretstream, 1 MiB chunks). Edge cases: `chunks` (explicit
    plaintext pieces), `tags` (one per chunk, default MESSAGE.. FINAL), `declared_size` (header plaintext size)."""
    from nacl import bindings
    from nacl.pwhash import argon2id
    root_salt, validation_salt, derivation_salt = salts or (os.urandom(16), os.urandom(16), os.urandom(16))
    root = argon2id.kdf(32, password.encode(), root_salt, opslimit=8, memlimit=16 * 1024 * 1024)
    state = bindings.crypto_secretstream_xchacha20poly1305_state()
    stream_header = bindings.crypto_secretstream_xchacha20poly1305_init_push(state, _subkey(root, derivation_salt))
    if chunks is None:
        chunks = [plaintext[i:i + V3_CHUNK] for i in range(0, len(plaintext), V3_CHUNK)] or [b'']
    final = bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    message = bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    tags = tags or [message] * (len(chunks) - 1) + [final]
    body = b''.join(bindings.crypto_secretstream_xchacha20poly1305_push(state, chunk, None, tag)
                    for chunk, tag in zip(chunks, tags))
    size = len(plaintext) if declared_size is None else declared_size
    return (b'SecureTar' + bytes([3]) + bytes(6) + struct.pack('!Q8x', size) + root_salt + validation_salt
            + _subkey(root, validation_salt) + derivation_salt + stream_header + body)


# ---------------------------------------------------------------- a pg_restore -l listing (HAOS parity, ODOO lane)

def toc_listing(lines, *, hidden=5, declared=None):
    """What `pg_restore -l` prints for an archive whose objects are the lines `lines` (bytes or text, one per entry, as
    pg_restore lists them: `<id>; <oid> <oid> <kind> ...`): the header with the `TOC Entries:` count (the entries plus the
    `hidden` ones that a plain listing keeps back; `declared` overrides the count) and then the lines. The default is what
    a REAL PostgreSQL 16.15 listing shows (the Nextcloud lane's probe of 2026-11-24: 1131 entry lines under `TOC Entries:
    1136`): the settings ENCODING, STDSTRINGS and SEARCHPATH and two more entries. Simulated format (no
    PostgreSQL tool is on the host): the header text is pg_restore's."""
    texts = [line.decode() if isinstance(line, bytes) else line for line in lines]
    count = len(texts) + hidden if declared is None else declared
    head = (';\n; Archive created at 2026-11-25 10:00:00 UTC\n;     dbname: woowtest\n'
            f';     TOC Entries: {count}\n;     Compression: gzip\n;     Dump Version: 1.15-0\n;     Format: CUSTOM\n'
            ';     Integer: 4 bytes\n;     Offset: 8 bytes\n;     Dumped from database version: 16.15\n'
            ';     Dumped by pg_dump version: 16.15\n;\n;\n; Selected TOC Entries:\n;\n')
    return (head + ''.join(line.rstrip('\n') + '\n' for line in texts)).encode()
