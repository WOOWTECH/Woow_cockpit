#!/usr/bin/env python3
"""R6 skipped entries, the fixture: the DERIVED HA backup, made as a stream from the original encrypted full-share backup.

Nothing here touches a device, a container or a secret file; the caller hands over the HA key (it is kept in the product's
own hasecuretar.Keys only, which has no repr). The original file is only read.

What the derivative is (reviewed in snippets/focus-nextcloud-r6/README.md, "skipped entries"):

  outer tar   every entry of the original in its order, header and data bytes as they are, except the header of
              `share.tar.gz` (its size field and checksum; its PAX records such as the float mtime stay) and the end
              (two zero blocks, then zeros up to a 10240-byte record, as Python's tarfile ends a tar)
  share.tar.gz  SecureTar v3 with the SAME HA key: the original's root salt, validation salt and validation key (one
              Argon2id per backup, like a real one), a recorded derivation salt and secretstream header, 1 MiB chunks,
              TAG_FINAL on the last (the encrypting side of the product's reader, hasecuretar). Its plaintext is a gzip
              stream of two members: first one small gzip member with the reviewed entries, then the original's own
              gzip stream byte for byte (the product's reader takes several members, as gzip(1) does). Decompressed:
              the reviewed entries, then the original inner tar byte for byte (every original entry, its metadata and
              its end-of-archive marker).
  the reviewed entries, below HA's data directory /share/nextcloud (member prefix `nextcloud/`), in a folder of their
              own that is no user's (so no user's file list, files:scan or manifest changes):
                woowbk-r6-skipped-entries/                  a directory
                woowbk-r6-skipped-entries/control.txt       an ordinary control file (moves)
                woowbk-r6-skipped-entries/.htaccess         a nested .htaccess with an unsafe allow directive (left out)
                woowbk-r6-skipped-entries/control-link.txt  a harmless relative symbolic link to control.txt (left out)

Nothing is materialised: `Derivation.prepare()` reads the outer headers and the share member's SecureTar header (the
product's describe(); the key is proven there, before any byte is produced) and knows the exact size of the result;
`Derivation.stream()` is a file-like reader that produces the derived bytes while it reads the original once, hashing
both. `verify()` reads such a stream back with the product's own readers (outer headers, DecryptReader, the gzip reader,
ha_nextcloud.scan_datadir) and gives the facts a provenance record keeps.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO / 'backup-engine') not in sys.path:
    sys.path.insert(0, str(REPO / 'backup-engine'))   # the product's own readers (byte-identical in the frozen product)
from woowbackup import habackup, hasecuretar, haissues, ha_nextcloud   # noqa: E402

SHARE = 'share.tar.gz'
DATADIR = 'nextcloud'                      # HA's data directory /share/nextcloud, as the share member names it
FOLDER = 'woowbk-r6-skipped-entries'       # below the data directory's top; no user's folder (parts[1] is no 'files')
CONTROL = FOLDER + '/control.txt'          # relative to the data directory (what lands in /var/www/html/data)
HTACCESS = FOLDER + '/.htaccess'
LINK = FOLDER + '/control-link.txt'
LINK_TARGET = 'control.txt'                # relative, inside the folder: harmless
OWNER = (33, 33)                           # www-data, as HA's Nextcloud data (the conversion sets this device's ids)
MTIME = 1795651200.25                      # a float like HA's own entries (a PAX mtime record)
CONTROL_DATA = (b'WOOWTECH R6 skipped entries: an ordinary control file next to the two entries the import leaves out.\n'
                b'It must arrive byte for byte; its neighbours .htaccess and control-link.txt must not.\n')
HTACCESS_DATA = (b'# R6 skipped entries: a nested rule that would publish this folder; the import must leave it out\n'
                 b'Require all granted\nOptions +Indexes\n')
ADDED = (
    {'name': DATADIR + '/' + FOLDER, 'type': 'dir', 'mode': 0o755},
    {'name': DATADIR + '/' + CONTROL, 'type': 'file', 'mode': 0o644, 'data': CONTROL_DATA},
    {'name': DATADIR + '/' + HTACCESS, 'type': 'file', 'mode': 0o644, 'data': HTACCESS_DATA},
    {'name': DATADIR + '/' + LINK, 'type': 'symlink', 'mode': 0o777, 'linkname': LINK_TARGET},
)
KINDS = {'dir': tarfile.DIRTYPE, 'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE}
# What the product's check must say (the reader lists a symlink by its whole entry name, the walk an .htaccess by its
# name below the data directory), and the keys those exact names bind (haissues.confirm_key).
SYMLINK_ID, HTACCESS_ID = 'nextcloud.symlinks-skipped', 'nextcloud.htaccess-skipped'
SYMLINK_ITEM = DATADIR + '/' + LINK
HTACCESS_ITEM = HTACCESS
SYMLINK_KEY = haissues.confirm_key('nextcloud', SYMLINK_ID, [SYMLINK_ITEM])
HTACCESS_KEY = haissues.confirm_key('nextcloud', HTACCESS_ID, [HTACCESS_ITEM])
KEYS = tuple(sorted((SYMLINK_KEY, HTACCESS_KEY)))
EXPECTED = {SYMLINK_ID: {'items': [SYMLINK_ITEM], 'key': SYMLINK_KEY, 'message': ha_nextcloud.MSG_SYMLINKS.format(count=1)},
            HTACCESS_ID: {'items': [HTACCESS_ITEM], 'key': HTACCESS_KEY,
                          'message': ha_nextcloud.MSG_HTACCESS.format(count=1)}}
BLOCK = 512
RECORD = 10240                             # tarfile.RECORDSIZE: how Python's tarfile pads the end of a tar
V3_HEADER = hasecuretar.HEADER_SIZE[3]     # 136: file id, plaintext size + reserved, cipher init
CHUNK = hasecuretar.V3_CHUNK
SALT_BYTES, STREAM_HEADER_BYTES = 16, 24


def need(ok, reason):
    if not ok:
        raise ValueError('fixed-derive-' + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def padded(size):
    return size + (-size % BLOCK)


def added_tar():
    """The reviewed entries as tar bytes, PAX headers like HA's writer (float mtime), no end-of-archive marker."""
    parts = []
    for item in ADDED:
        info = tarfile.TarInfo(item['name'])
        info.type = KINDS[item['type']]
        info.mode, (info.uid, info.gid), info.mtime = item['mode'], OWNER, MTIME
        info.linkname = item.get('linkname', '')
        data = item.get('data', b'')
        info.size = len(data)
        parts.append(info.tobuf(tarfile.PAX_FORMAT, 'utf-8', 'surrogateescape'))
        parts.append(data + bytes(-len(data) % BLOCK))
    return b''.join(parts)


ADDED_TAR = added_tar()
PREFIX_GZIP = gzip.compress(ADDED_TAR, compresslevel=9, mtime=0)   # the first gzip member of the derived share plaintext


def added_rows():
    """Every added entry as the provenance names it."""
    rows = []
    for item in ADDED:
        row = {'name': item['name'], 'type': item['type'], 'mode': '%04o' % item['mode'], 'uid': OWNER[0], 'gid': OWNER[1],
               'mtime': MTIME}
        if 'data' in item:
            row.update(bytes=len(item['data']), sha256=sha(item['data']))
        if 'linkname' in item:
            row['linkname'] = item['linkname']
        rows.append(row)
    return rows


def module_sha():
    return sha(Path(__file__).read_bytes())


def reader_hashes():
    """The product modules this builder reads and writes with (their bytes; the frozen product must have the same)."""
    base = REPO / 'backup-engine' / 'woowbackup'
    return {name: sha((base / name).read_bytes()) for name in ('hasecuretar.py', 'habackup.py', 'haissues.py',
                                                               'ha_nextcloud.py')}


def sized(block, size):
    """The ustar header `block` with its size field set to `size` (tarfile's own form: 11 octal digits and NUL) and the
    checksum written again the way tarfile writes it (6 octal digits, NUL, the space that was there)."""
    need(len(block) == BLOCK and 0 <= size < 8 ** 11, 'outer-size-field')
    out = bytearray(block)
    out[124:136] = b'%011o\x00' % size
    out[148:156] = b' ' * 8
    out[148:155] = b'%06o\x00' % sum(out)
    return bytes(out)


def ciphertext_size(plaintext):
    return hasecuretar._ciphertext_size('v3', plaintext)


def member_size(plaintext):
    return V3_HEADER + ciphertext_size(plaintext)


# ====================================================================== the encrypting side of hasecuretar (v3)

class V3Writer:
    """SecureTar v3 of a plaintext of exactly `size` bytes: header (file id, size, the reserved bytes, the cipher init),
    then secretstream chunks of 1 MiB, TAG_MESSAGE, the last TAG_FINAL (one empty FINAL chunk for nothing) -- what
    hasecuretar.DecryptReader reads. The secretstream state is made with init_pull from the recorded header: libsodium's
    init_push does exactly that after it draws the header at random, so a recorded header gives the same stream again
    (tests compare both). `write` returns the ciphertext ready so far, `close` the rest."""

    def __init__(self, root_key, size, *, root_salt, validation_salt, validation_key, derivation_salt, stream_header,
                 reserved=bytes(8)):
        from nacl import bindings
        need(len(root_salt) == len(validation_salt) == len(derivation_salt) == SALT_BYTES and len(validation_key) == 32
             and len(stream_header) == STREAM_HEADER_BYTES and len(reserved) == 8 and size >= 0, 'v3-writer-fields')
        self._b = bindings
        self._state = bindings.crypto_secretstream_xchacha20poly1305_state()
        bindings.crypto_secretstream_xchacha20poly1305_init_pull(
            self._state, stream_header, hasecuretar._blake2b_subkey(root_key, derivation_salt))
        self.size, self.fed, self.pushed = size, 0, 0
        self.chunks = max(1, -(-size // CHUNK))
        self._buf = bytearray()
        self.header = (hasecuretar.FILE_ID.pack(hasecuretar.MAGIC, 3, bytes(6)) + struct.pack('!Q', size) + reserved
                       + hasecuretar.V3_INIT.pack(root_salt, validation_salt, validation_key, derivation_salt, stream_header))

    def _push(self, data, tag):
        self.pushed += 1
        return self._b.crypto_secretstream_xchacha20poly1305_push(self._state, bytes(data), None, tag)

    def write(self, data):
        self.fed += len(data)
        need(self.fed <= self.size, 'v3-writer-overflow')
        self._buf += data
        out = []
        while len(self._buf) >= CHUNK and self.pushed + 1 < self.chunks:
            out.append(self._push(self._buf[:CHUNK], self._b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE))
            del self._buf[:CHUNK]
        return b''.join(out)

    def close(self):
        need(self.fed == self.size and self.pushed + 1 == self.chunks and len(self._buf) <= CHUNK, 'v3-writer-short')
        last = self._push(self._buf, self._b.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        self._buf = bytearray()
        return last


# ====================================================================== small readers

class _Sequential:
    """The original file read once from its start: read_exact / skip / read_some for the product's header reader
    (habackup._read_head), every byte hashed; `mark()`/`marked()` hand back the raw bytes of one header region."""

    def __init__(self, fd, size):
        self.fd, self.size, self.pos, self.records = fd, size, 0, 0
        self.digest = hashlib.sha256()
        self._mark = None

    def _read(self, n):
        data = os.read(self.fd, min(n, CHUNK))
        self.pos += len(data)
        self.digest.update(data)
        if self._mark is not None:
            self._mark.append(data)
        return data

    def read_exact(self, n):
        parts, got = [], 0
        while got < n:
            data = self._read(n - got)
            if not data:
                raise habackup._Truncated()
            parts.append(data)
            got += len(data)
        return b''.join(parts)

    def skip(self, n):
        self.read_exact(n)

    def read_some(self, n):
        data = self._read(n) if n > 0 else b''
        if n > 0 and not data:
            raise habackup._Truncated()
        return data

    def mark(self):
        self._mark = []

    def marked(self):
        raw, self._mark = b''.join(self._mark), None
        return raw


class _Prefixed:
    """read(n) of `prefix` (bytes already read) and then the next `rest` bytes of `src` (for DecryptReader)."""

    def __init__(self, prefix, src, rest):
        self.prefix, self.src, self.rest = prefix, src, rest

    def read(self, n=CHUNK):
        if self.prefix:
            data, self.prefix = self.prefix[:n], self.prefix[n:]
            return data
        n = min(n, self.rest)
        if n <= 0:
            return b''
        data = self.src.read_some(n)
        self.rest -= len(data)
        return data


class DerivedStream(io.RawIOBase):
    """The derived bytes as a reader: read()/readinto() for parsers, pieces() for a writer that takes whole pieces. Every
    byte is counted and hashed; `sha256` is set once the last byte left (and the stream knew its exact size)."""

    def __init__(self, pieces, size):
        super().__init__()
        self._gen, self.size, self.count = pieces, size, 0
        self._digest = hashlib.sha256()
        self._buf = memoryview(b'')
        self.ended = False
        self.sha256 = None

    def readable(self):
        return True

    def _next(self):
        piece = next(self._gen)
        self.count += len(piece)
        need(self.count <= self.size, 'derived-size-bound')
        self._digest.update(piece)
        return piece

    def _end(self):
        self.ended = True
        need(self.count == self.size, 'derived-size')
        self.sha256 = self._digest.hexdigest()

    def pieces(self):
        if len(self._buf):
            yield bytes(self._buf)
            self._buf = memoryview(b'')
        while not self.ended:
            try:
                piece = self._next()
            except StopIteration:
                self._end()
                return
            if piece:
                yield piece

    def readinto(self, buffer):
        while not len(self._buf) and not self.ended:
            try:
                self._buf = memoryview(self._next())
            except StopIteration:
                self._end()
        n = min(len(buffer), len(self._buf))
        buffer[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def close(self):
        if not self.closed:
            self._gen.close()
        super().close()


# ====================================================================== the derivation

def _identity(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink]


def _open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise ValueError('fixed-derive-original-not-a-regular-file')
    return fd, st


def outer_walk(fd, size):
    """[(name or None, header offset, data offset, data size, typeflag)] of every entry of the outer tar and the offset of
    its end-of-archive block, with the product's own header reader (pread; nothing after the marker is read)."""
    outer = habackup._Outer(fd, size)
    entries = []
    try:
        while True:
            start = outer.pos
            head = habackup._read_head(outer, outer=True)
            if head is None:
                return entries, outer.pos - BLOCK
            name = habackup._outer_name(head.name) if head.typeflag in habackup.OUTER_FILES else None
            data = head.size if head.typeflag not in habackup.OUTER_NO_DATA else 0
            entries.append({'name': name, 'header': start, 'offset': outer.pos, 'bytes': data,
                            'typeflag': head.typeflag.decode('latin-1'),
                            # the size must be the ustar field's own (no PAX size record): the one field rewritten
                            'plain_size_field': 'size' not in head.pax and habackup._number(head.block[124:136]) == data})
            outer.skip(padded(data))
    except habackup._Truncated:
        raise ValueError('fixed-derive-original-truncated') from None


class Derivation:
    """One derivation of `source` with the HA key `password`, the recorded `derivation_salt` (16 bytes) and secretstream
    `stream_header` (24 bytes). `expected_sha`/`expected_size`: the original's bound identity (the stream refuses to
    finish otherwise). prepare() first; stream() then gives the derived bytes once; facts() the provenance afterwards."""

    def __init__(self, source, password, *, derivation_salt, stream_header, expected_sha=None, expected_size=None):
        need(isinstance(derivation_salt, bytes) and len(derivation_salt) == SALT_BYTES
             and isinstance(stream_header, bytes) and len(stream_header) == STREAM_HEADER_BYTES, 'salt-or-header')
        self.source = Path(source)
        self._keys = hasecuretar.Keys(password)     # the key itself is never kept anywhere else
        self.derivation_salt, self.stream_header = derivation_salt, stream_header
        self.expected_sha, self.expected_size = expected_sha, expected_size
        self.plan = None
        self.original_ok = False
        self._facts = self._share_facts = None
        self._root = None           # the v3 root key (Argon2id of the HA key): only in memory, never in a record
        self._used = False

    def __repr__(self):
        return '<Derivation %s>' % self.source.name

    def prepare(self):
        """Read-only preflight: the product describes the original (outer tar, backup.json, each member's first bytes),
        the share member is SecureTar v3 + gzip and holds exactly what its header announces, the key opens it (wrong-key
        here, before any derived byte exists), the tail after the end-of-archive block is zeros; the exact derived
        size. Returns the plan."""
        fd, st = _open(self.source)
        try:
            size = st.st_size
            need(self.expected_size is None or size == self.expected_size, 'original-size')
            layout = habackup.describe(fd)
            shares = [m for m in layout.members if m.name == SHARE]
            need(len(shares) == 1, 'share-member')
            share = shares[0]
            need(share.role == 'folder' and share.slug == 'share' and share.problem is None and share.compressed
                 and share.encryption == 'v3' and layout.doc['protected'] is True and layout.doc['compressed'] is True,
                 'share-member-not-v3-gzip')
            entries, end = outer_walk(fd, size)
            named = [e for e in entries if e['name'] == SHARE]
            need(len(named) == 1 and named[0]['offset'] == share.offset and named[0]['bytes'] == share.size
                 and named[0]['typeflag'] in ('0', '\x00') and named[0]['plain_size_field'], 'share-entry')
            tail = os.pread(fd, size - end, end)
            need(len(tail) == size - end and tail.count(0) == len(tail) and len(tail) >= BLOCK, 'original-tail')
            head = os.pread(fd, V3_HEADER, share.offset)
            need(len(head) == V3_HEADER and hasecuretar.sniff(head) == 'v3', 'share-header')
            plaintext, reserved = struct.unpack('!Q', head[16:24])[0], head[24:32]
            root_salt, validation_salt, validation_key, _salt, _header = hasecuretar.V3_INIT.unpack(head[32:])
            need(share.size == member_size(plaintext), 'share-member-size')
            self._root = self._keys.v3_root_key(root_salt, validation_salt, validation_key)   # wrong-key raises here
            derived_plaintext = len(PREFIX_GZIP) + plaintext
            derived_member = member_size(derived_plaintext)
            content_end = end - padded(share.size) + padded(derived_member)
            derived_bytes = -(-(content_end + 2 * BLOCK) // RECORD) * RECORD
            self.plan = {
                'identity': _identity(st), 'original_bytes': size, 'end_of_archive': end, 'tail_bytes': size - end,
                'entries': entries, 'share': {'offset': share.offset, 'header_offset': named[0]['header'],
                                              'member_bytes': share.size, 'plaintext_bytes': plaintext, 'header': head,
                                              'reserved': reserved, 'root_salt': root_salt,
                                              'validation_salt': validation_salt, 'validation_key': validation_key},
                'derived_member_bytes': derived_member, 'derived_plaintext_bytes': derived_plaintext,
                'derived_content_end': content_end, 'derived_bytes': derived_bytes,
                'doc': {k: layout.doc[k] for k in ('protected', 'compressed', 'folders')},
                'addons': [a['slug'] for a in layout.doc['addons']]}
            return self.plan
        finally:
            os.close(fd)

    def stream(self):
        """The derived bytes (DerivedStream); one pass over the original, which must still be the prepared file."""
        need(self.plan is not None and not self._used, 'prepare-once-stream-once')
        self._used = True
        return DerivedStream(self._pieces(), self.plan['derived_bytes'])

    def _pieces(self):
        plan = self.plan
        fd, st = _open(self.source)
        try:
            need(_identity(st) == plan['identity'], 'original-changed')
            src = _Sequential(fd, plan['original_bytes'])
            members, out = [], 0
            for entry in plan['entries']:
                src.mark()
                try:
                    head = habackup._read_head(src, outer=True)
                except habackup._Truncated:
                    raise ValueError('fixed-derive-original-truncated') from None
                raw = src.marked()
                need(head is not None and src.pos == entry['offset'], 'outer-walk-changed')
                if entry['name'] == SHARE:
                    for piece in self._share(raw, head, src, entry):
                        out += len(piece)
                        yield piece
                    members.append(dict(self._share_facts, name=SHARE, offset=entry['offset'], derived=True))
                    continue
                digest = hashlib.sha256()
                out += len(raw)
                yield raw
                left = entry['bytes']
                while left:
                    data = src.read_some(min(CHUNK, left))
                    left -= len(data)
                    digest.update(data)
                    out += len(data)
                    yield data
                pad = src.read_exact(-entry['bytes'] % BLOCK)
                out += len(pad)
                yield pad
                members.append({'name': entry['name'], 'offset': entry['offset'], 'bytes': entry['bytes'],
                                'sha256': digest.hexdigest(), 'derived': False})
            src.mark()
            need(habackup._read_head(src, outer=True) is None and src.pos == plan['end_of_archive'] + BLOCK, 'outer-end')
            src.marked()
            rest = plan['original_bytes'] - src.pos
            while rest:
                data = src.read_some(min(CHUNK, rest))
                need(data.count(0) == len(data), 'original-tail')
                rest -= len(data)
            need(os.read(fd, 1) == b'' and src.pos == plan['original_bytes'], 'original-size')
            original = src.digest.hexdigest()
            need(self.expected_sha is None or original == self.expected_sha, 'original-sha256')
            self.original_ok = True
            need(out == plan['derived_content_end'], 'derived-content-end')
            ending = plan['derived_bytes'] - out
            self._facts = {'original': {'name': self.source.name, 'bytes': plan['original_bytes'], 'sha256': original,
                                        'expected_sha256_matched': self.expected_sha is not None},
                           'members': members,
                           'tail': {'original_zero_bytes': plan['tail_bytes'], 'derived_zero_bytes': ending}}
            yield bytes(ending)   # two zero blocks, then zeros to the record: the last bytes, only after every check
        finally:
            os.close(fd)

    def _share(self, raw, head, src, entry):
        plan, share = self.plan, self.plan['share']
        need(raw[-BLOCK:] == head.block and 'size' not in head.pax and head.size == share['member_bytes']
             and habackup._number(head.block[124:136]) == share['member_bytes'], 'share-outer-header')
        yield raw[:-BLOCK] + sized(head.block, plan['derived_member_bytes'])
        header = src.read_exact(V3_HEADER)
        need(header == share['header'], 'share-header-changed')
        writer = V3Writer(self._root, plan['derived_plaintext_bytes'], root_salt=share['root_salt'],
                          validation_salt=share['validation_salt'], validation_key=share['validation_key'],
                          derivation_salt=self.derivation_salt, stream_header=self.stream_header, reserved=share['reserved'])
        yield writer.header
        written = len(writer.header)
        first = writer.write(PREFIX_GZIP)
        written += len(first)
        if first:
            yield first
        decrypt = hasecuretar.DecryptReader(_Prefixed(header, src, share['member_bytes'] - V3_HEADER),
                                            share['member_bytes'], self._keys, name=SHARE)
        plain, count = hashlib.sha256(), 0
        try:
            while True:
                piece = decrypt.read(CHUNK)
                if not piece:
                    break
                count += len(piece)
                plain.update(piece)
                data = writer.write(piece)
                if data:
                    written += len(data)
                    yield data
            decrypt.finish()     # the v3 final tag and the exact plaintext size
        finally:
            decrypt.close()
        need(count == share['plaintext_bytes'], 'share-plaintext-size')
        last = writer.close()
        written += len(last)
        need(written == plan['derived_member_bytes'], 'derived-member-size')
        yield last + bytes(-written % BLOCK)
        src.read_exact(-share['member_bytes'] % BLOCK)   # the original member's padding (read for the original's hash)
        self._share_facts = {
            'bytes': share['member_bytes'], 'format': 'securetar-v3', 'compression': 'gzip',
            'plaintext_bytes': share['plaintext_bytes'], 'plaintext_sha256': plain.hexdigest(),
            'derived_member_bytes': plan['derived_member_bytes'], 'derived_plaintext_bytes': plan['derived_plaintext_bytes'],
            'outer_header_size_field': [share['member_bytes'], plan['derived_member_bytes']],
            'root_salt_validation_reused': True, 'derivation_salt': self.derivation_salt.hex(),
            'stream_header': self.stream_header.hex(),
            'prefix_gzip': {'bytes': len(PREFIX_GZIP), 'sha256': sha(PREFIX_GZIP), 'members': 1},
            'added_tar': {'bytes': len(ADDED_TAR), 'sha256': sha(ADDED_TAR)}}

    def facts(self, stream):
        """The provenance facts of a finished stream: the original (bytes, SHA-256 read now), every outer entry (the
        unchanged ones with their data SHA-256), the share member before and after, every added entry, the derived file's
        bytes and SHA-256, the confirmations the product must ask for and their keys."""
        need(self._facts is not None and stream.ended and stream.sha256 is not None, 'stream-unfinished')
        return dict(self._facts, kind='r6-skipped-entries-derivation', builder_sha256=module_sha(),
                    product_readers=reader_hashes(), added=added_rows(),
                    control={'path': CONTROL, 'bytes': len(CONTROL_DATA), 'sha256': sha(CONTROL_DATA)},
                    derived={'bytes': stream.count, 'sha256': stream.sha256},
                    expected_check={k: {'items': v['items'], 'key': v['key']} for k, v in EXPECTED.items()},
                    doc=self.plan['doc'], addons=self.plan['addons'])


# ====================================================================== reading a derived stream back (the product's readers)

class _StreamOuter:
    """read_exact / skip / read_some over a non-seekable reader, for habackup._read_head (outer=True)."""

    def __init__(self, reader):
        self.reader, self.pos, self.records = reader, 0, 0

    def read_some(self, n):
        data = self.reader.read(min(n, CHUNK)) if n > 0 else b''
        if n > 0 and not data:
            raise habackup._Truncated()
        self.pos += len(data)
        return data

    def read_exact(self, n):
        parts, got = [], 0
        while got < n:
            data = self.read_some(n - got)
            parts.append(data)
            got += len(data)
        return b''.join(parts)

    def skip(self, n):
        while n:
            n -= len(self.read_some(min(n, CHUNK)))


class _Limited:
    """read(n) of the next `size` bytes of an outer reader (one member)."""

    def __init__(self, outer, size):
        self.outer, self.left = outer, size

    def read(self, n=CHUNK):
        n = min(n if n is not None and n >= 0 else CHUNK, self.left)
        if n <= 0:
            return b''
        data = self.outer.read_some(n)
        self.left -= len(data)
        return data


class _Split:
    """read(n) passed through from `src` (the decrypted share plaintext), hashing the first `first` bytes and the rest
    apart: the reviewed gzip member, then the original's gzip stream."""

    def __init__(self, src, first):
        self.src, self.first, self.count = src, first, 0
        self.head, self.tail = hashlib.sha256(), hashlib.sha256()

    def read(self, n=CHUNK):
        data = self.src.read(n)
        cut = max(0, min(len(data), self.first - self.count))
        self.head.update(data[:cut])
        self.tail.update(data[cut:])
        self.count += len(data)
        return data


class _Finishing:
    """The gzip reader of the share plaintext with the final checks of both layers (gzip trailer, v3 final tag), as
    habackup.MemberStream gives them to iter_entries."""
    checked_to_the_end = True

    def __init__(self, gunzip, decrypt):
        self.gunzip, self.decrypt = gunzip, decrypt

    def read(self, n=CHUNK):
        return self.gunzip.read(n)

    def finish(self):
        self.gunzip.finish()
        self.decrypt.finish()


def verify_share(member, size, password):
    """The derived share member opened like the device opens it: a NEW hasecuretar.Keys (no cached root), the product's
    DecryptReader and gzip reader, ha_nextcloud.scan_datadir of the data directory. The walk's facts."""
    decrypt = hasecuretar.DecryptReader(member, size, hasecuretar.Keys(password), name=SHARE)
    try:
        split = _Split(decrypt, len(PREFIX_GZIP))
        report = habackup.Report(names=haissues.Names)
        data = ha_nextcloud.scan_datadir(_Finishing(habackup._Gunzip(split), decrypt), report, DATADIR, addon=False)
    finally:
        decrypt.close()
    links = report.skips.get('symlink')
    symlink_items = list(links.key_items()) if links is not None else []
    htaccess_items = list(data.htaccess_names.key_items())
    return {'kind': decrypt.kind, 'declared_plaintext_bytes': decrypt.plaintext_size, 'plaintext_bytes': split.count,
            'prefix_sha256': split.head.hexdigest(), 'suffix_sha256': split.tail.hexdigest(),
            'member_left': member.left, 'complete': report.complete, 'present': data.present, 'ncdata': data.ncdata,
            'encryption': data.encryption, 'files': data.files, 'bytes': data.bytes, 'dirs': data.dirs,
            'users': len(data.users), 'hardlinks': data.hardlinks, 'hardlinks_copied': data.hardlinks_copied,
            'symlinks': data.symlinks, 'symlink_items': symlink_items, 'htaccess': data.htaccess,
            'htaccess_items': htaccess_items,
            'other_skips': {kind: names.count for kind, names in report.skips.items() if kind != 'symlink'},
            'keys': {SYMLINK_ID: haissues.confirm_key('nextcloud', SYMLINK_ID, symlink_items),
                     HTACCESS_ID: haissues.confirm_key('nextcloud', HTACCESS_ID, htaccess_items)}}


def verify(derivation, password):
    """Produce the derivation's stream and read it straight back (nothing is stored): the outer tar with the product's
    header reader, every unchanged member's data against the original's SHA-256, backup.json through the product's schema,
    the share member through verify_share. Returns (provenance facts, verification facts, verdict)."""
    stream = derivation.stream()
    outer = _StreamOuter(stream)
    seen, share, doc = [], None, None
    try:
        while True:
            head = habackup._read_head(outer, outer=True)
            if head is None:
                break
            name = habackup._outer_name(head.name) if head.typeflag in habackup.OUTER_FILES else None
            size = head.size if head.typeflag not in habackup.OUTER_NO_DATA else 0
            if name == SHARE:
                member = _Limited(outer, size)
                share = verify_share(member, size, password)
                outer.skip(member.left)
            else:
                digest, left, raw = hashlib.sha256(), size, []
                while left:
                    data = outer.read_some(min(CHUNK, left))
                    left -= len(data)
                    digest.update(data)
                    if name == habackup.BACKUP_JSON:
                        raw.append(data)
                if name == habackup.BACKUP_JSON:
                    doc = habackup.validate_doc(json.loads(b''.join(raw)))
                seen.append({'name': name, 'bytes': size, 'sha256': digest.hexdigest()})
            outer.skip(-size % BLOCK)
        tail = 0
        while True:
            data = stream.read(CHUNK)
            if not data:
                break
            need(data.count(0) == len(data), 'derived-tail')
            tail += len(data)
    except habackup._Truncated:
        raise ValueError('fixed-derive-derived-truncated') from None
    facts = derivation.facts(stream)
    unchanged = [{k: m[k] for k in ('name', 'bytes', 'sha256')} for m in facts['members'] if not m['derived']]
    share_original = next(m for m in facts['members'] if m['derived'])
    checks = {
        'derived_bytes_as_planned': stream.count == derivation.plan['derived_bytes'] and stream.count % RECORD == 0,
        'unchanged_members_byte_for_byte': seen == unchanged,
        'backup_json_protected_compressed_share': (doc is not None and doc['protected'] is True and doc['compressed'] is True
                                                  and 'share' in doc['folders']),
        'share_v3_whole_member': share is not None and share['kind'] == 'v3' and share['member_left'] == 0,
        'share_prefix_is_the_reviewed_gzip_member': share is not None and share['prefix_sha256'] == sha(PREFIX_GZIP),
        'share_original_plaintext_byte_for_byte': (share is not None and share['suffix_sha256'] ==
                                                   share_original['plaintext_sha256']
                                                   and share['plaintext_bytes'] == share_original['derived_plaintext_bytes']),
        'walk_complete_data_directory_with_marker': (share is not None and share['complete'] and share['present']
                                                     and share['ncdata']),
        'exactly_the_reviewed_symlink_left_out': (share is not None and share['symlinks'] == 1
                                                  and share['symlink_items'] == [SYMLINK_ITEM]),
        'exactly_the_reviewed_htaccess_left_out': (share is not None and share['htaccess'] == 1
                                                   and share['htaccess_items'] == [HTACCESS_ITEM]),
        'nothing_else_left_out': share is not None and share['other_skips'] == {},
        'keys_are_the_bound_ones': (share is not None and share['keys'] == {SYMLINK_ID: SYMLINK_KEY,
                                                                              HTACCESS_ID: HTACCESS_KEY}),
        # the header reader took the first zero block; the rest of the derived file must be zeros too
        'derived_tail_zeros': tail + BLOCK == facts['tail']['derived_zero_bytes']}
    return facts, {'share': share, 'members': seen, 'tail_after_marker': tail}, checks
