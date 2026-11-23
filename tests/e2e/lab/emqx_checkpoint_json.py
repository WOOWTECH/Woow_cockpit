"""Read only atomically published private typed JSON; never decode checkpoint ETF.

Owner must establish checkpoint provenance separately. This is NOT connected to
Capture, and neither this function nor a hash proves coverage of a cold source.
"""
import os
from pathlib import Path
import stat

from emqx_semantic_readers import MAX_OUTPUT, SemanticRefused, read_mnesia


def read_owned_checkpoint_export(raw, table, path):
    """Bind private JSON to exact checkpoint bytes via existing semantic contract.

    raw is owner-created checkpoint bytes (<=8MiB), used ONLY for SHA/length.
    JSON path must be a regular owner 0600 file within an owner 0700 directory.
    No Python/native ETF decode, execution, subprocess, or automatic native fallback.
    """
    parent = fd = None
    try:
        path = Path(path).absolute()
        if any(component.is_symlink() for component in (path, *path.parents)):
            raise ValueError()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = os.fstat(parent)
        if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise ValueError()
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_OUTPUT):
            raise ValueError()
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_OUTPUT + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_OUTPUT:
                raise ValueError()
            chunks.append(chunk)
        after = os.fstat(fd)
        stable = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                               info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if stable(before) != stable(after) or size != before.st_size:
            raise ValueError()
        return read_mnesia(raw, table, lambda _: b''.join(chunks))
    except Exception:
        raise SemanticRefused() from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)
