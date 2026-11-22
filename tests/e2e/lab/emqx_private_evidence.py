"""Scan exact evidence bytes before exclusive private publication.

No source discovery or credential loading. A sealed registry supplied by actual
producers is mandatory; callers must not label fixture runs as broker acceptance.
"""
import json
import os
from pathlib import Path
import re
import stat

from emqx_private_boundary import PrivateFailure, SOURCES

PHASES = frozenset(('preflight', 'restore', 'startup', 'mqtt', 'restart', 'cleanup'))
RESULTS = frozenset(('passed', 'failed', 'blocked', 'not-run'))


def publish(directory, name, *, registry, phase, result, coverage, coverage_mode='counts'):
    """Write only names/counts/status, after scanning the identical JSON bytes.

    Caller owns a private directory. No overwrite, symlink traversal, arbitrary
    diagnostic text, paths or token bodies are accepted. A failed write unlinks
    only the file exclusively created by this call.
    """
    fd = parent = None
    created = False
    try:
        if (coverage_mode not in ('counts', 'names') or phase not in PHASES or result not in RESULTS
                or not isinstance(name, str)
                or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}\.json', name)
                or not isinstance(coverage, dict) or set(coverage) != SOURCES
                or any(type(v) is not int or not 0 <= v <= 4096 for v in coverage.values())):
            raise ValueError()
        raw = (json.dumps({'phase': phase, 'result': result,
                           'coverage': coverage if coverage_mode == 'counts' else sorted(coverage)}, sort_keys=True) + '\n').encode()
        # No file is created until the actual consumer registry accepts bytes.
        registry.scan(raw)
        path = Path(directory).absolute()
        for component in (path, *path.parents):
            if component.is_symlink():
                raise ValueError()
        parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        created = True
        with os.fdopen(fd, 'wb') as out:
            fd = None
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        return {'phase': phase, 'result': result, 'scanned': True}
    except Exception:
        if fd is not None:
            os.close(fd)
        if created and parent is not None:
            os.unlink(name, dir_fd=parent)
        raise PrivateFailure('private-evidence-refused') from None
    finally:
        if parent is not None:
            os.close(parent)
