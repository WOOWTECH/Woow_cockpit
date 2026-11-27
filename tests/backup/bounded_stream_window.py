"""Bounded-disk helpers for real >8GiB stream probes on a production-sized host disk.

A deterministic keystream is streamed through the REAL archive writer by a sliding-window regular file: logical size
is the whole payload (the writer's own lstat/size check passes), bytes are physically written just ahead of the
engine's sequential reader and hole-punched behind it, so the payload never exists on disk all at once. The engine
proves each byte it read was the keystream: it compares its own sha256 of every byte it read with the independently
precomputed keystream sha256 (an unwritten hole reads as zeros and would fail that check).
`OutputPuncher` bounds harness-owned extraction output the same way; it never touches engine inputs.
Holes are a harness storage measure only and every report says so.
"""
import ctypes
import ctypes.util
import hashlib
import os

from tests.backup import bounded_large_archive as common

MIB = 1024 ** 2
FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02
_LIBC = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)
_LIBC.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64, ctypes.c_int64]
_LIBC.fallocate.restype = ctypes.c_int


def punch_hole(fd, offset, length):
    """Deallocate [offset, offset+length) of an open writable file; logical size is kept."""
    if length <= 0:
        return
    if _LIBC.fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, length) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def compressible_block(index):
    """Existing generator: 4096 unique SHAKE256 bytes per MiB repeated 256 times (compressible, never holes)."""
    return common.payload_block(index, True)


def incompressible_block(index):
    """1 MiB of SHAKE256 output per index: deterministic, incompressible (zstd/zlib cannot shrink it)."""
    return hashlib.shake_256(f'woow-incompressible-v1:{index}'.encode()).digest(MIB)


BLOCKS = {'compressible': compressible_block, 'incompressible': incompressible_block}


def keystream_sha256(mib, block, check=None):
    """sha256 of the whole keystream without storing it (CPU only). `check()` runs every 64 MiB."""
    digest = hashlib.sha256()
    for index in range(mib):
        if check is not None and index % 64 == 0:
            check()
        digest.update(block(index))
    return digest.hexdigest()


def _pwrite_all(fd, data, offset):
    view = memoryview(data)
    while view:
        count = os.pwrite(fd, view, offset)
        view, offset = view[count:], offset + count


class WindowSource:
    """Regular file (logical size `mib` MiB) written `ahead` bytes in front of the reader's progress and punched
    `behind` bytes after it. `advance(done)` is called from the engine's progress callback, which runs in the
    reading thread between reads: the engine reads at most PROGRESS_STEP + one CHUNK between two callbacks."""

    def __init__(self, path, mib, block, *, ahead=64 * MIB, behind=16 * MIB):
        if ahead < 32 * MIB or behind < MIB:
            raise ValueError('window too small for the engine progress granularity')
        self.path, self.mib, self.block = path, mib, block
        self.size = mib * MIB
        self.ahead, self.behind = ahead, behind
        self.filled = self.punched = self.max_allocated = self.max_done = 0
        self.bytes_written = 0
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.ftruncate(self.fd, self.size)
            self.fill_to(ahead)
        except BaseException:
            self.close()
            raise

    def fill_to(self, target):
        target = min(self.size, target)
        while self.filled < target:
            data = self.block(self.filled // MIB)
            _pwrite_all(self.fd, data, self.filled)
            self.filled += len(data)
            self.bytes_written += len(data)
        self._sample()

    def advance(self, done):
        if done > self.filled:
            raise RuntimeError('engine progress passed the written window')
        self.max_done = max(self.max_done, done)
        self.fill_to(done + self.ahead)
        cut = max(0, (done - self.behind) // MIB * MIB)
        if cut > self.punched:
            punch_hole(self.fd, self.punched, cut - self.punched)
            self.punched = cut
        self._sample()

    def _sample(self):
        self.max_allocated = max(self.max_allocated, os.fstat(self.fd).st_blocks * 512)

    def report(self):
        return dict(method='sliding-window regular file', logical_bytes=self.size, ahead_bytes=self.ahead,
                    behind_bytes=self.behind, bytes_physically_written=self.bytes_written,
                    max_allocated_bytes=self.max_allocated, max_progress_bytes=self.max_done)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class OutputPuncher:
    """Bounds the allocation of ONE harness-owned extraction output while the engine writes it sequentially; called
    from the engine's progress callback (between its writes, in its thread). Logical size is kept, so the engine's
    write offsets and the file it later removes are unchanged."""

    def __init__(self, path, *, behind=16 * MIB):
        self.path, self.behind = path, behind
        self.punched = self.max_logical = self.max_allocated = self.calls = 0

    def advance(self, done):
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return
        try:
            st = os.fstat(fd)
            self.max_logical = max(self.max_logical, st.st_size)
            cut = max(0, (min(done, st.st_size) - self.behind) // MIB * MIB)
            if cut > self.punched:
                punch_hole(fd, self.punched, cut - self.punched)
                self.punched = cut
            self.max_allocated = max(self.max_allocated, os.fstat(fd).st_blocks * 512)
            self.calls += 1
        finally:
            os.close(fd)

    def report(self):
        return dict(method='harness hole-punch behind engine write offset', behind_bytes=self.behind,
                    max_logical_bytes=self.max_logical, max_allocated_bytes=self.max_allocated,
                    punched_bytes=self.punched, callbacks=self.calls)
