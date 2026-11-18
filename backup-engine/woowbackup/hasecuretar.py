"""Home Assistant backup encryption (securetar): streaming decryption of one inner tar (CONTRACT section 5 "Home
Assistant backups"). Owner: E1 engine-core (format).

A Home Assistant (Supervisor) backup is a plain outer tar; with a password each inner tar (`<slug>.tar.gz`, ...) is
encrypted on its own (habackup.py reads the outer tar). Real backups use three on-disk formats (securetar, pinned
by Supervisor; facts and sources: haimport/HA-FACTS.md section 1):

    v1  Supervisor <= 2024.12      16 B salt | AES-128-CBC ciphertext                         (no header)
    v2  2025.01 .. 2026.03         "SecureTar" 0x02 + 6 zero bytes | plaintext size (u64 BE) + 8 reserved |
                                   16 B salt | AES-128-CBC ciphertext, PKCS7 over the whole stream
    v3  2026.04+ with Core 2026.3+ "SecureTar" 0x03 + 6 zero bytes | plaintext size ... | 104 B cipher init (root
                                   salt 16, validation salt 16, validation key 32, derivation salt 16, secretstream
                                   header 24) | XChaCha20-Poly1305 secretstream: 1 MiB plaintext chunks, +17 B each,
                                   TAG_MESSAGE except TAG_FINAL on the last chunk

Keys come from the HA "encryption key" exactly as the user pasted it (UTF-8; HA itself never trims or upper-cases
it): v1/v2 key = 100 rounds of SHA-256 (first 16 bytes), IV = 100 rounds of SHA-256 over key || salt; v3 root key =
Argon2id(opslimit 8, memlimit 16 MiB, root salt) once per backup (`Keys` caches it), validation key and file key =
keyed BLAKE2b-256 of the empty message (person "SecureTarv3"). Output is byte-identical to securetar 2026.10.0 for
every well-formed member (haimport/ref/verify.py) except where that library is wrong: v1 is unpadded only when its
last block is not valid PKCS7 (an uncompressed v1 tar; the library dropped its last read buffer).

Hardened beyond the library: the member size in the outer tar must match the header exactly (v2: plaintext size
rounded up to the next block; v3: plaintext size + 17 B per chunk), v2 padding and plaintext size are checked, v3
chunks must be exactly 1 MiB except the last and carry exactly the tags the writer uses. A wrong key is reported
before any plaintext is returned (v3: validation key, exact; v1/v2: the first 512 decrypted bytes must look like
gzip or tar, as securetar and Supervisor check it, a heuristic). Memory stays bounded (one ~1 MiB chunk at a time;
Argon2id uses the format's fixed 16 MiB).

PyNaCl (v3, Ubuntu `python3-nacl`) and cryptography (v1/v2, `python3-cryptography`) are imported only when a member
of that kind is read; a missing package is an `internal-error` that names the package. Errors are BackupError codes
of errors.CODES: `wrong-key`, `corrupt-archive` (truncated, tampered or malformed), `unsupported-format` (a SecureTar
version other than 2 or 3), `invalid-request` (a key that is not text). The key is never part of a message, a detail
or a repr.
"""
import hashlib
import hmac
import io
import struct

from .errors import BackupError

MAGIC = b'SecureTar'
FILE_ID = struct.Struct('!9sB6s')            # magic, version, 6 reserved bytes (must be zero)
METADATA = struct.Struct('!Q8x')             # plaintext size, 8 reserved bytes (ignored, like securetar)
V3_INIT = struct.Struct('!16s16s32s16s24s')  # root salt, validation salt, validation key, derivation salt, ss header
FILE_ID_SIZE = 16
METADATA_SIZE = 16
AES_BLOCK = 16
HEADER_SIZE = {1: 16, 2: 48, 3: 136}
V3_CHUNK = 1024 * 1024
V3_ABYTES = 17
V3_OPSLIMIT = 8
V3_MEMLIMIT = 16 * 1024 * 1024
V3_PERSON = b'SecureTarv3'
V3_TAG_MESSAGE = 0
V3_TAG_FINAL = 3
CHECK_BLOCK = 512           # v1/v2 wrong-key check (securetar: first 512 decrypted bytes look like gzip or tar)
CBC_CHUNK = 1024 * 1024
GZIP_MAGIC = b'\x1f\x8b\x08'
TAR_MAGIC = b'ustar'
TAR_MAGIC_AT = 257
MAX_PASSWORD = 4096

WRONG_KEY_MESSAGE = 'HA 備份金鑰不正確，請確認後再試一次。'
CORRUPT_MESSAGE = 'HA 備份檔已損毀或遭到修改，無法使用。'
UNSUPPORTED_MESSAGE = '這份 HA 備份使用不支援的加密格式，請更新這台設備的備份元件。'
KEY_REQUIRED_MESSAGE = '這份 HA 備份已加密，請輸入 HA 備份金鑰。'
BAD_KEY_MESSAGE = '不是有效的 HA 備份金鑰。'
NACL_MISSING = '系統缺少 python3-nacl，無法解開 2026 年 3 月以後的 HA 加密備份。請重新執行安裝程式。'
CRYPTOGRAPHY_MISSING = '系統缺少 python3-cryptography，無法解開 2026 年 3 月以前的 HA 加密備份。請重新執行安裝程式。'


def corrupt(reason, **details):
    return BackupError('corrupt-archive', CORRUPT_MESSAGE, reason=reason, **details)


def wrong_key(reason):
    return BackupError('wrong-key', WRONG_KEY_MESSAGE, reason=reason)


def key_required(**details):
    return BackupError('key-required', KEY_REQUIRED_MESSAGE, **details)


def _unsupported(version):
    return BackupError('unsupported-format', UNSUPPORTED_MESSAGE, reason='unsupported SecureTar version',
                       version=version)


# ---------------------------------------------------------------- what a member is

def sniff(head):
    """Classify the first bytes (>= 512 for 'tar') of an outer-tar member: 'v2' / 'v3' (SecureTar header),
    'unsupported' (SecureTar magic with another version or nonzero reserved bytes), 'gzip', 'tar' (ustar magic, or an
    all-zero first block: an empty tar), or 'unknown' (in a protected backup: legacy v1 ciphertext, which has no
    header; otherwise not an inner tar)."""
    head = bytes(head)
    if head[:len(MAGIC)] == MAGIC:
        if len(head) < FILE_ID_SIZE:
            return 'unsupported'
        _magic, version, reserved = FILE_ID.unpack(head[:FILE_ID_SIZE])
        if version in (2, 3) and reserved == bytes(6):
            return f'v{version}'
        return 'unsupported'
    if head[:3] == GZIP_MAGIC:
        return 'gzip'
    if head[TAR_MAGIC_AT:TAR_MAGIC_AT + len(TAR_MAGIC)] == TAR_MAGIC:
        return 'tar'
    if len(head) >= 512 and head[:512] == bytes(512):
        return 'tar'
    return 'unknown'


def ciphertext_ok(kind, member_size, head):
    """True when `member_size` (the member's size in the outer tar) fits the header in `head` (>= 48 bytes): v1 = salt +
    whole blocks, v2 = header + plaintext size rounded up to the next block (PKCS7 always pads), v3 = header +
    plaintext size + 17 B per 1 MiB chunk (at least one). Checked when a backup is described, before any key."""
    if kind == 'v1':
        return member_size > HEADER_SIZE[1] and (member_size - HEADER_SIZE[1]) % AES_BLOCK == 0
    if len(head) < FILE_ID_SIZE + METADATA_SIZE:
        return False
    (plaintext,) = METADATA.unpack(bytes(head[FILE_ID_SIZE:FILE_ID_SIZE + METADATA_SIZE]))
    return member_size == HEADER_SIZE[2 if kind == 'v2' else 3] + _ciphertext_size(kind, plaintext)


def _ciphertext_size(kind, plaintext):
    if kind == 'v2':
        return plaintext + AES_BLOCK - plaintext % AES_BLOCK
    chunks = max(1, -(-plaintext // V3_CHUNK))
    return plaintext + chunks * V3_ABYTES


# ---------------------------------------------------------------- keys

def _sha256_rounds(data, rounds=100):
    for _ in range(rounds):
        data = hashlib.sha256(data).digest()
    return data


def _blake2b_subkey(root_key, salt):
    """Keyed BLAKE2b-256 of the empty message (identical to nacl.hash.blake2b with person "SecureTarv3")."""
    return hashlib.blake2b(b'', digest_size=32, key=root_key, salt=salt, person=V3_PERSON).digest()


def _nacl():
    try:
        from nacl import bindings
        from nacl import exceptions as nacl_exceptions
        from nacl.pwhash import argon2id
    except ImportError:
        raise BackupError('internal-error', NACL_MISSING, reason='python3-nacl is not installed') from None
    return bindings, nacl_exceptions, argon2id


def _aes_cbc_decryptor(key, iv):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise BackupError('internal-error', CRYPTOGRAPHY_MISSING, reason='python3-cryptography is not installed') from None
    return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()


class Keys:
    """The key of one HA backup, shared by its members: v1/v2 AES key and v3 root keys (one Argon2id per root salt;
    every member of a backup has the same one). The password stays private: no repr, no message, no detail."""

    __slots__ = ('_password', '_aes_key', '_roots')

    def __init__(self, password):
        if (not isinstance(password, str) or not password or len(password) > MAX_PASSWORD or '\x00' in password):
            raise BackupError('invalid-request', BAD_KEY_MESSAGE, field='key')
        try:
            self._password = password.encode('utf-8')
        except UnicodeEncodeError:  # a lone surrogate is not text
            raise BackupError('invalid-request', BAD_KEY_MESSAGE, field='key') from None
        self._aes_key = None
        self._roots = {}

    def __repr__(self):
        return '<hasecuretar.Keys>'

    def aes_key(self):
        if self._aes_key is None:
            self._aes_key = _sha256_rounds(self._password)[:AES_BLOCK]
        return self._aes_key

    def v3_root_key(self, root_salt, validation_salt, validation_key):
        """The root key for this salt pair; wrong-key (before any plaintext) when the stored validation key differs."""
        cached = self._roots.get((root_salt, validation_salt))
        if cached is not None:
            return cached
        _bindings, _exceptions, argon2id = _nacl()
        root = argon2id.kdf(32, self._password, root_salt, opslimit=V3_OPSLIMIT, memlimit=V3_MEMLIMIT)
        if not hmac.compare_digest(_blake2b_subkey(root, validation_salt), validation_key):
            raise wrong_key('v3 validation key mismatch')
        self._roots[(root_salt, validation_salt)] = root
        return root


# ---------------------------------------------------------------- the decrypting stream

class _Source:
    """Sequential reads of exactly the member's bytes from `src` (any object with read(n)); never beyond `size`."""

    def __init__(self, src, size):
        self.src, self.left = src, size

    def read_exact(self, n):
        n = min(n, self.left)
        parts, got = [], 0
        while got < n:
            buf = self.src.read(n - got)
            if not buf:
                break
            parts.append(buf)
            got += len(buf)
        data = b''.join(parts)
        self.left -= len(data)
        return data


def read_header(src, member_size):
    """(kind, plaintext size or None, cipher init bytes) of the member at the current position of `src`; checks that
    the member size fits the header (see ciphertext_ok)."""
    first = src.read_exact(FILE_ID_SIZE)
    if len(first) < FILE_ID_SIZE:
        raise corrupt('member shorter than a SecureTar header')
    kind = sniff(first)
    if kind == 'unsupported':
        raise _unsupported(first[len(MAGIC)])
    if kind not in ('v2', 'v3'):
        if member_size <= HEADER_SIZE[1] or (member_size - HEADER_SIZE[1]) % AES_BLOCK:
            raise corrupt('legacy ciphertext is not a whole number of blocks')
        return 'v1', None, first
    meta = src.read_exact(METADATA_SIZE)
    if len(meta) < METADATA_SIZE:
        raise corrupt('truncated SecureTar header')
    (plaintext,) = METADATA.unpack(meta)
    init = src.read_exact(AES_BLOCK if kind == 'v2' else V3_INIT.size)
    if len(init) < (AES_BLOCK if kind == 'v2' else V3_INIT.size):
        raise corrupt('truncated SecureTar header')
    if member_size != HEADER_SIZE[int(kind[1])] + _ciphertext_size(kind, plaintext):
        raise corrupt('member size does not match the SecureTar header', kind=kind)
    return kind, plaintext, init


def _looks_like_gzip_or_tar(data):
    return data[:3] == GZIP_MAGIC or data[TAR_MAGIC_AT:TAR_MAGIC_AT + len(TAR_MAGIC)] == TAR_MAGIC


class DecryptReader(io.RawIOBase):
    """Readable plaintext of one encrypted inner tar.

    `src`: any object with read(n) positioned at the member's first byte (e.g. habackup's member slice); `member_size`:
    the member's size in the outer tar (all of it is the encrypted file: header + ciphertext); `keys`: Keys of the
    backup. The constructor reads the header and checks the key: wrong-key is raised before any plaintext exists.
    Reads return what was authenticated so far (v3) or decrypted (v1/v2); `finish()` reads to the end and runs the
    final checks (v3 final tag, v2 padding and plaintext size, v1 whole blocks), so a caller that needs the complete
    member calls it after the last read. `kind` is 'v1', 'v2' or 'v3'; `plaintext_size` is None for v1.
    """

    def __init__(self, src, member_size, keys, *, name=None):
        super().__init__()
        if not isinstance(keys, Keys):
            raise key_required(member=name)
        self.name = name
        self._src = _Source(src, member_size)
        self.kind, self.plaintext_size, init = read_header(self._src, member_size)
        self._buf = b''
        self._done = False
        self._chunks = self._v3(init, keys) if self.kind == 'v3' else self._cbc(init, keys)
        next(self._chunks)  # runs the key check; the generator then waits before its first plaintext

    # -- formats

    def _cbc(self, salt, keys):
        key = keys.aes_key()
        decryptor = _aes_cbc_decryptor(key, _sha256_rounds(key + salt)[:AES_BLOCK])
        first = self._src.read_exact(CHECK_BLOCK)
        if not first or len(first) % AES_BLOCK:
            raise corrupt('truncated ciphertext')
        pending = decryptor.update(first)
        if not _looks_like_gzip_or_tar(pending):
            raise wrong_key('decrypted data is neither gzip nor tar')
        yield b''
        produced = 0
        while True:
            data = self._src.read_exact(CBC_CHUNK)
            if not data:
                break
            if len(data) % AES_BLOCK:
                raise corrupt('truncated ciphertext')
            pending += decryptor.update(data)
            if len(pending) > AES_BLOCK:  # the last block (padding) stays back until the end
                out, pending = pending[:-AES_BLOCK], pending[-AES_BLOCK:]
                produced += len(out)
                yield out
        if self._src.left:
            raise corrupt('truncated ciphertext')
        pending += decryptor.finalize()
        pad = pending[-1] if pending else 0
        valid = 1 <= pad <= AES_BLOCK and pending[-pad:] == bytes([pad]) * pad
        if self.kind == 'v2':
            if not valid:
                raise corrupt('invalid PKCS7 padding')
            pending = pending[:-pad]
        elif valid:  # v1: an uncompressed tar ends in zeros and was never padded (module notes)
            pending = pending[:-pad]
        produced += len(pending)
        if self.kind == 'v2' and produced != self.plaintext_size:
            raise corrupt('plaintext size differs from the SecureTar header')
        if pending:
            yield pending

    def _v3(self, init, keys):
        bindings, nacl_exceptions, _argon2id = _nacl()
        root_salt, validation_salt, validation_key, derivation_salt, ss_header = V3_INIT.unpack(init)
        root = keys.v3_root_key(root_salt, validation_salt, validation_key)
        state = bindings.crypto_secretstream_xchacha20poly1305_state()
        bindings.crypto_secretstream_xchacha20poly1305_init_pull(state, ss_header, _blake2b_subkey(root, derivation_salt))
        yield b''
        left = self.plaintext_size
        chunks = max(1, -(-left // V3_CHUNK))
        for index in range(chunks):
            want = min(V3_CHUNK, left)
            data = self._src.read_exact(want + V3_ABYTES)
            if len(data) != want + V3_ABYTES:
                raise corrupt('truncated ciphertext')
            try:
                message, tag = bindings.crypto_secretstream_xchacha20poly1305_pull(state, data, None)
            except (nacl_exceptions.CryptoError, ValueError, RuntimeError):
                raise corrupt('secretstream authentication failed (corrupt or tampered)') from None
            last = index == chunks - 1
            if tag != (V3_TAG_FINAL if last else V3_TAG_MESSAGE) or len(message) != want:
                raise corrupt('unexpected secretstream tag or chunk size')
            left -= want
            if message:
                yield message

    # -- file object

    def readable(self):
        return True

    def readinto(self, buffer):
        while not self._buf and not self._done:
            try:
                self._buf = next(self._chunks)
            except StopIteration:
                self._done = True
        size = min(len(buffer), len(self._buf))
        buffer[:size] = self._buf[:size]
        self._buf = self._buf[size:]
        return size

    def finish(self):
        """Read the rest of the member (discarded) and run the final checks; raises corrupt-archive on any defect."""
        self._buf = b''
        while not self._done:
            try:
                next(self._chunks)
            except StopIteration:
                self._done = True
        if self._src.left:
            raise corrupt('data after the end of the encrypted stream')

    def close(self):
        if not self.closed:
            chunks = getattr(self, '_chunks', None)  # None when the constructor failed early
            if chunks is not None:
                chunks.close()
            self._buf = b''
        super().close()


def open_decrypted(src, member_size, keys, *, name=None):
    """DecryptReader for one member (see there); key-required when `keys` is None."""
    return DecryptReader(src, member_size, keys, name=name)
