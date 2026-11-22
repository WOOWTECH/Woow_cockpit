"""Fixed owner preflight transport. No source broker/build/install/restore entry.

Child stdout is a PRIVATE bounded evidence frame, never a public log. The host
controller captures it and retains the exact scanned bytes in a private file.
Only the two existing immutable SQL source profiles are selectable.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import sys
import tempfile
import time

from emqx_private_boundary import PrivateFailure

MODES = {
    '--preflight': ('--source-vendor-acl-sql-aliases', b'E'),
    '--x86-preflight': ('--x86-source-vendor-acl-sql-aliases', b'F'),
}
MAGIC = b'WOOWPREFLIGHT1:'
MAX_EVIDENCE = 65536
MAX_FRAME = len(MAGIC) + 4 + MAX_EVIDENCE + 32
PRIVATE_PARENT = Path('/home/woowtechopenclaw/.woowbk-lab')


def evidence_frame(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_EVIDENCE: raise ValueError()
    return MAGIC + struct.pack('!I', len(raw)) + raw + hashlib.sha256(raw).digest()


def read_child_frame(child, *, timeout=900):
    """Bound stdout DURING reads, retaining no stderr or subprocess diagnostics."""
    deadline = time.monotonic() + timeout
    result = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise ValueError()
            if not selector.select(remaining): raise ValueError()
            raw = os.read(child.stdout.fileno(), min(65536,MAX_FRAME+1-len(result)))
            if not raw: break
            result.extend(raw)
            if len(result) > MAX_FRAME: raise ValueError()
    if child.wait(timeout=max(0.01,deadline-time.monotonic())) != 0: raise ValueError()
    return bytes(result)


def retain_evidence(frame):
    """Keep exact private scanned payload only; no stdout/path/hash publication."""
    if type(frame) is not bytes or not len(MAGIC)+4 < len(frame) <= MAX_FRAME: raise ValueError()
    if not frame.startswith(MAGIC): raise ValueError()
    size = struct.unpack('!I',frame[len(MAGIC):len(MAGIC)+4])[0]
    start = len(MAGIC)+4
    if not 0 < size <= MAX_EVIDENCE or len(frame) != start+size+32: raise ValueError()
    raw = frame[start:start+size]
    if hashlib.sha256(raw).digest() != frame[-32:]: raise ValueError()
    from emqx_private_evidence import SOURCE_NAMES
    expected = (json.dumps({'phase':'preflight','result':'passed',
        'coverage':[SOURCE_NAMES[key] for key in sorted(SOURCE_NAMES)]},
        sort_keys=True,ensure_ascii=False)+'\n').encode()
    if raw != expected: raise ValueError()
    parent = PRIVATE_PARENT
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or any(p.is_symlink() for p in (parent,*parent.parents))): raise ValueError()
    # mkdtemp exclusively creates the FINAL directory; collisions are retried.
    # No rename/replacement and no claim of atomic publication to other readers.
    root = Path(tempfile.mkdtemp(prefix='emqx-preflight-evidence-',dir=parent))
    path = root/'owner-preflight.json'
    fd, created = None, False
    try:
        info = root.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError()
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        created = True
        stream = os.fdopen(fd,'wb')
        fd = None
        with stream as out:
            os.fchmod(out.fileno(),0o600)
            out.write(raw);out.flush();os.fsync(out.fileno())
        return path  # Only a fully written/fsynced artifact is returned.
    except BaseException:
        if fd is not None: os.close(fd)
        if created: path.unlink()
        root.rmdir()
        raise


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in MODES: return 2
    from emqx_arm_source_owner import _owner_realm
    if not _owner_realm(): return 1
    def deadline(*_): raise PrivateFailure('private-preflight-deadline')
    previous = signal.signal(signal.SIGALRM,deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL,360)
        from emqx_adapter_owner import LabOwnerRunner
        from emqx_fresh_owner_workflow import preflight_fresh_frame
        runner = LabOwnerRunner()
        with tempfile.TemporaryDirectory(prefix='emqx-preflight-private-',dir=Path.home()) as directory:
            parent = Path(directory);parent.chmod(0o700)
            raw = preflight_fresh_frame(sys.stdin.buffer,runner=runner,
                private_parent=parent,source_mode=MODES[args[0]][0])
        # No output before full private cleanup, including late lease checks.
        sys.stdout.buffer.write(evidence_frame(raw));sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


if __name__ == '__main__':
    raise SystemExit(main())
