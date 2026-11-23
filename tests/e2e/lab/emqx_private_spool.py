"""Private bounded authenticated source spool; never diagnostic/evidence output."""
import contextlib
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

from emqx_private_boundary import PrivateFailure

MAX_SOURCE = 256 * 1024 ** 2
RESERVE = 12 * 1024 ** 3
X86_PROFILE = 'owner-x86-20261121'
X86_SHA256 = '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'
X86_SIZE = 290785280
PROFILE_SECONDS = 120


def fixture_limits(profile, verified_sha256):
    """Call only inside source_binding after its real digest verification."""
    if profile != X86_PROFILE or verified_sha256 != X86_SHA256:
        raise PrivateFailure('private-source-refused')
    return X86_SIZE



@contextlib.contextmanager
def capture(stream, directory, *, maximum=MAX_SOURCE, fixture_profile=None, verified_sha256=None):
    """Consume through EOF and finish before exposing a private seekable file.

    Directory must be caller-owned0700 with no symlink components. No original
    file is overwritten. Only this call's exclusive temporary file is unlinked.
    The explicit owner-x86-20261121 profile requires the verified archive SHA,
    exactly290785280 expanded bytes, finish(), and a120-second monotonic spool
    deadline checked around reads/finish/fsync before yield. Blocking IO cannot
    be preempted; late completion refuses. Reads remain at most65536 bytes,
    with one overflow probe byte; disk reserve remains12GiB plus capacity at
    entry and reserve plus chunk during writes. No profile fallback exists.
    Caller retains ownership of the input stream. Decrypted bytes never become
    evidence; this does not parse or authorize HOCON/Mnesia or start a broker.
    """
    fd = None
    name = None
    parent = None
    handle = None
    try:
        exact = None
        deadline = None
        if fixture_profile is not None:
            if maximum != MAX_SOURCE:
                raise ValueError()
            maximum = exact = fixture_limits(fixture_profile, verified_sha256)
            deadline = time.monotonic() + PROFILE_SECONDS
        elif verified_sha256 is not None:
            raise ValueError()
        elif type(maximum) is not int or not 1 <= maximum <= MAX_SOURCE:
            raise ValueError()

        def timely():
            if deadline is not None and time.monotonic() >= deadline:
                raise ValueError()

        timely()
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
            timely()
            chunk = stream.read(min(65536, maximum + 1 - size))
            timely()
            if type(chunk) is not bytes:
                raise ValueError()
            if not chunk:
                break
            size += len(chunk)
            if size > maximum or shutil.disk_usage(anchor).free < RESERVE + len(chunk):
                raise ValueError()
            handle.write(chunk)
            digest.update(chunk)
        timely()
        if hasattr(stream, 'finish'):
            stream.finish()
        elif exact is not None:
            raise ValueError()
        timely()
        if exact is not None and size != exact:
            raise ValueError()
        handle.flush()
        os.fsync(handle.fileno())
        if os.fstat(handle.fileno()).st_size != size:
            raise ValueError()
        handle.seek(0)
        timely()
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
