"""Private ARM --source subcase; no lab entry, target docs or evidence stdout.

The authorized controller supplies the existing owner frame after stripping its
code/dependency bootstrap: uint32 key length, ASCII key, uint64 ciphertext size,
exact ciphertext, EOF. No paths/key/SHA overrides are accepted through argv/env.
Exit zero means source-only registration and cleanup, NEVER full scan/restore.
"""
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import tempfile
import hashlib

from emqx_owner_source_capture import capture_owner_source
from emqx_private_boundary import PrivateFailure

ARCHIVE_SHA256 = 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664'
MAX_ARCHIVE = 512 * 1024 * 1024
EXPECTED_COLD_FILES = 28
EXPECTED_COLD_BYTES = 57502


def _exact(stream, size):
    pieces = []
    while size:
        chunk = stream.read(min(size, 65536))
        if type(chunk) is not bytes or not chunk or len(chunk) > size:
            raise ValueError()
        pieces.append(chunk)
        size -= len(chunk)
    return b''.join(pieces)


def consume_source_frame(stream, *, staging_parent):
    """Actual framed transfer -> authenticated Capture; return static scope only.

    Trusted in-process owner callable. CLI additionally checks its dev-d realm.
    No public diagnostics, source values, keys, bindings or replay escape. The
    receipt is returned only AFTER all private staging/spool cleanup completes.
    Target categories are not acknowledged, and the registry must be unsealed.
    """
    try:
        key_size = struct.unpack('!I', _exact(stream, 4))[0]
        if not 1 <= key_size <= 1024:
            raise ValueError()
        password = _exact(stream, key_size).decode('ascii')
        if not password or '\n' in password or '\r' in password:
            raise ValueError()
        size = struct.unpack('!Q', _exact(stream, 8))[0]
        if not 0 < size <= MAX_ARCHIVE:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='woowbk-arm-cold-private-source-',
                                         dir=staging_parent) as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = root / 'encrypted-source.tar'
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            digest = hashlib.sha256()
            with os.fdopen(fd, 'wb') as output:
                info = os.fstat(output.fileno())
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError()
                left = size
                while left:
                    chunk = _exact(stream, min(left, 65536))
                    output.write(chunk)
                    digest.update(chunk)
                    left -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            if stream.read(1) != b'' or digest.hexdigest() != ARCHIVE_SHA256:
                raise ValueError()
            with capture_owner_source(source, password=password,
                    expected_sha256=ARCHIVE_SHA256, spool_directory=root) as (captured, _):
                if captured.cold_receipt != {
                    'scope': 'historical-values-only', 'files': EXPECTED_COLD_FILES,
                    'bytes': EXPECTED_COLD_BYTES, 'final_state': False,
                }:
                    raise ValueError()
                try:
                    captured.registry.summary()
                except PrivateFailure as failure:
                    if str(failure) != 'private-registration-incomplete':
                        raise ValueError() from None
                else:
                    raise ValueError()  # Unexpectedly sealed is not source-only.
        return {'scope': 'source-only-registration', 'registry': 'unsealed',
                'source_completeness': 'not-assessed',
                'target_completeness': 'not-assessed',
                'full_scan': 'not-performed', 'restore': 'not-performed'}
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-source-frame-cancelled') from None
    except Exception:
        raise PrivateFailure('private-source-frame-refused') from None


def _owner_realm():
    return socket.gethostname() == 'woowbk-dev-d' and os.geteuid() != 0


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) != ['--source']:
        return 2
    if not _owner_realm():
        return 1
    def deadline(*_):
        raise RuntimeError('private-source-deadline')
    previous = signal.signal(signal.SIGALRM, deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL, 180)
        consume_source_frame(sys.stdin.buffer, staging_parent=Path.home())
        return 0
    except BaseException:
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
