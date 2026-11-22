"""Private bounded authenticated source spool; never diagnostic/evidence output."""
import contextlib
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile

from emqx_private_boundary import PrivateFailure

MAX_SOURCE = 256 * 1024 ** 2
RESERVE = 12 * 1024 ** 3


@contextlib.contextmanager
def capture(stream, directory, *, maximum=MAX_SOURCE):
    """Consume through EOF and finish before exposing a private seekable file.

    Directory must be caller-owned0700 with no symlink components. No original
    file is overwritten. Only this call's exclusive temporary file is unlinked.
    Caller retains ownership of the input stream. Decrypted bytes never become
    evidence; this does not parse or authorize HOCON/Mnesia or start a broker.
    """
    fd = None
    name = None
    parent = None
    handle = None
    try:
        if type(maximum) is not int or not 1 <= maximum <= MAX_SOURCE:
            raise ValueError()
        path = Path(directory).absolute()
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError()
        parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError()
        # fd anchors creation and cleanup, even if the directory is renamed.
        anchor = '/proc/self/fd/' + str(parent)
        if shutil.disk_usage(anchor).free < RESERVE + maximum:
            raise ValueError()
        fd, created = tempfile.mkstemp(prefix='emqx-source-', dir=anchor)
        name = Path(created).name
        os.fchmod(fd, 0o600)
        digest = hashlib.sha256()
        size = 0
        handle = os.fdopen(fd, 'w+b')
        fd = None
        while True:
            chunk = stream.read(min(65536, maximum + 1 - size))
            if type(chunk) is not bytes:
                raise ValueError()
            if not chunk:
                break
            size += len(chunk)
            if size > maximum or shutil.disk_usage(anchor).free < RESERVE + len(chunk):
                raise ValueError()
            handle.write(chunk)
            digest.update(chunk)
        if hasattr(stream, 'finish'):
            stream.finish()
        handle.flush()
        os.fsync(handle.fileno())
        if os.fstat(handle.fileno()).st_size != size:
            raise ValueError()
        handle.seek(0)
        # Export only a seekable stream, byte count and digest; never a path.
        yield handle, size, digest.hexdigest()
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-source-cancelled') from None
    except Exception:
        raise PrivateFailure('private-source-refused') from None
    finally:
        if handle is not None:
            handle.close()
        if fd is not None:
            os.close(fd)
        if name is not None and parent is not None:
            os.unlink(name, dir_fd=parent)
        if parent is not None:
            os.close(parent)
