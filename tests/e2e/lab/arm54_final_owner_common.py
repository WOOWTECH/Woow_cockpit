"""Shared helpers for item C of lane arm54-2 (runs as root on .54): the production OwnerRunner rootless flow.

Owner decision 2026-11-23 (「uidmap 同意」): install uidmap on .54, create ONE linger test account for the OwnerRunner
rootless flow, purge uidmap and delete the account afterwards, prove .54's inventory identical.

Isolation (test deviation, stated in every report): the test owner's user manager (user@<uid>.service) runs with
PrivateNetwork=yes (a drop-in made for this uid only), so every rootless container, rootlessport/pasta (local mode:
no external interface) and published port lives in a network namespace that holds only `lo`. The engine process
joins that namespace (setns) so the catalog's loopback health URLs reach the published ports exactly as on a host.
.54's own network namespace, services and containers are never touched. Nothing here prints a secret value.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tarfile
import time

OWNER = 'woowbk54t'
COMMENT = 'woowbk arm54-2 item C test owner'
# Debian bookworm main uidmap 1:4.13+dfsg1-1+deb12u2 arm64 (same digest as the gpgv-verified Packages.xz entry).
UIDMAP_SHA256 = '123d156d17ec56fd1cdc481c0e25531373bdb27d282803dd518df3bf59eecd82'
DROPIN_NAME = 'woowbk-arm54-private-network.conf'
DROPIN_TEXT = ('# lane arm54-2 item C (2026-11-23): the test owner\'s user manager and all its rootless containers\n'
               '# run in a private network namespace (lo only). Removed with the test account.\n'
               '[Service]\nPrivateNetwork=yes\n')
# n8n cycle (2026-11-24): six n8n containers plus the conversion's throwaways on a 3.9 GiB device that runs Home
# Assistant: everything of the owner's user manager together is capped, so an out-of-memory kill can only hit it.
MEMORY_CAP = {'MemoryMax': '1600M', 'MemorySwapMax': '900M'}
MEMORY_CAP_TEXT = ''.join('%s=%s\n' % item for item in sorted(MEMORY_CAP.items()))
PODMAN_BIN = '/usr/local/bin/podman'  # .54's Podman 6.1.1 (there is no /usr/bin/podman)
OWNER_PATH = '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
ACCOUNT_FILES = ('/etc/passwd', '/etc/group', '/etc/shadow', '/etc/gshadow', '/etc/subuid', '/etc/subgid')
BACKUP_FILES = tuple(p + '-' for p in ACCOUNT_FILES)
SECRET_WORDS = ('PWD', 'PASS', 'KEY', 'TOKEN', 'SECRET', 'CRED', 'AUTH', 'SIG')
LONG_TOKEN = re.compile(r'[A-Za-z0-9+=_-]{32,}')  # key/token-like runs; paths (short segments) stay readable
CLONE_NEWNET = 0x40000000
FALLBACK_TUNNELS = frozenset({'sit0', 'ip6tnl0', 'tunl0', 'gre0', 'gretap0', 'erspan0', 'ip_vti0', 'ip6_vti0', 'ip6gre0'})
# Kernel modules are global even when the network that needs them lives in the owner's private namespace: the
# rootless netavark bridge of a quadlet .network (inside the user manager's namespace) pulls in veth and nft_* (seen
# in owner-cycle1-killed-state-audit). Unloading them is DISABLED: `modprobe -r` in owner-cleanup-cycle1 oopsed .54's
# kernel in nft_masq's exit (incident-54-kernel-oops-nft-masq). modules_to_unload() only names what a run loaded.
NET_MODULES = frozenset({'bridge', 'stp', 'llc', 'veth', 'br_netfilter', 'nft_ct', 'nft_fib', 'nft_fib_inet',
                         'nft_fib_ipv4', 'nft_fib_ipv6', 'nft_masq', 'nft_nat', 'nft_reject', 'nft_reject_inet',
                         'nf_reject_ipv4', 'nf_reject_ipv6', 'xt_MASQUERADE', 'xt_addrtype', 'xt_comment', 'xt_mark',
                         'xt_multiport', 'nf_conntrack_netlink', 'nft_limit', 'xt_tcpudp'})


def modules_to_unload(baseline_modules, loaded_now):
    """Pure (unit tested): allowlisted networking modules loaded since the cycle baseline, in a stable order."""
    return sorted((set(loaded_now) - set(baseline_modules)) & NET_MODULES)


def account():
    try:
        return pwd.getpwnam(OWNER)
    except KeyError:
        return None


def dropin_dir(uid):
    return Path('/etc/systemd/system/user@%d.service.d' % uid)


def manager_pid(uid):
    p = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'user@%d.service' % uid],
                       capture_output=True, text=True, timeout=30)
    return int((p.stdout or '0').strip() or 0)


def netns_inode(pid):
    return os.stat('/proc/%d/ns/net' % pid).st_ino


def safe_tail(data, limit=400):
    """A short stderr tail for diagnostics: lines naming a secret word dropped, long tokens masked."""
    text = (data or b'').decode('utf-8', 'replace') if isinstance(data, bytes) else (data or '')
    lines = [l for l in text.splitlines() if not any(w in l.upper() for w in SECRET_WORDS)]
    return LONG_TOKEN.sub('<masked>', '\n'.join(lines))[-limit:]


class OwnerCommandFailed(RuntimeError):
    pass


def owner_prefix(acct):
    return ['/usr/sbin/runuser', '-u', OWNER, '--', '/usr/bin/env', '-i', 'PATH=' + OWNER_PATH,
            'HOME=' + acct.pw_dir, 'LANG=C.UTF-8', 'XDG_RUNTIME_DIR=/run/user/%d' % acct.pw_uid,
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus' % acct.pw_uid]


def owner(argv, *, input=None, timeout=120, check=True, stdout=None):
    """Harness-side command as the test owner (setup, checks, cleanup). The product uses its own OwnerRunner."""
    acct = account()
    p = subprocess.run(owner_prefix(acct) + [str(a) for a in argv], input=input,
                       stdout=subprocess.PIPE if stdout is None else stdout, stderr=subprocess.PIPE,
                       timeout=timeout, cwd=acct.pw_dir)
    if check and p.returncode:
        words = [str(a).rsplit('/', 1)[-1] for a in argv[:3]]
        raise OwnerCommandFailed('owner-command-failed %s rc=%d %s' % (' '.join(words), p.returncode,
                                                                      safe_tail(p.stderr)))
    return p


def podman(*args, **kw):
    return owner([PODMAN_BIN, *args], **kw)


def systemctl(*args, **kw):
    return owner(['/usr/bin/systemctl', '--user', *args], **kw)


WRITER = r'''import json, os, sys
home = os.environ['HOME']
for rel, (mode, data) in sorted(json.loads(sys.stdin.read()).items()):
    assert not rel.startswith('/') and '..' not in rel.split('/')
    path = os.path.join(home, rel)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, int(mode, 8))
    with os.fdopen(fd, 'w') as handle:
        handle.write(data)
    os.chmod(path, int(mode, 8))
print('written')
'''


def write_owner_files(files):
    """{relative path in the owner's home: (octal mode text, text)} written AS the owner (O_EXCL, no follow)."""
    owner(['/usr/bin/python3', '-I', '-c', WRITER], input=json.dumps(files).encode(), timeout=60)


def join_netns(pid):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open('/proc/%d/ns/net' % pid, os.O_RDONLY)
    try:
        if libc.setns(fd, CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), 'setns')
    finally:
        os.close(fd)


def nsenter(pid, *argv, input=None, timeout=60, check=True):
    p = subprocess.run(['nsenter', '--net=/proc/%d/ns/net' % pid, *argv], input=input, capture_output=True,
                       timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('netns-command-failed %s rc=%d %s' % (argv[0], p.returncode, safe_tail(p.stderr)))
    return p


HTTP_PROBE = r'''import sys, urllib.request, urllib.error
try:
    with urllib.request.urlopen(sys.argv[1], timeout=10) as resp:
        print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print(type(e).__name__)
'''


def http_status(pid, url, timeout=30):
    p = nsenter(pid, 'python3', '-I', '-c', HTTP_PROBE, url, timeout=timeout, check=False)
    return (p.stdout or b'').decode().strip()


def wait_http(pid, url, seconds):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = http_status(pid, url)
        if last == '200':
            return True, last
        time.sleep(3)
    return False, last


# .54 has no age/age-keygen/zstd, which the engine needs for its device key and archives. As in item A
# (arm54_final_large_outer.py, provenance evidence large-tools-provenance): the pinned Debian bookworm packages are
# unpacked into the 0700 workspace and bind-mounted over /usr/local/sbin (first in the engine's SAFE_PATH) inside a
# private mount namespace of this process tree only; nothing is installed and the host's /usr/local/sbin is untouched.
TOOL_DEBS = {
    'age.deb': ('d14f937ecb1cef9279879e779cf61fda682735dd9871cd7d60ba7a487608f4e6', ('./usr/bin/age', './usr/bin/age-keygen')),
    'zstd.deb': ('97a58383b0ad55cc8183e59cbb112f2eb55c3dc1e90de816fa5cfb983d5c2ff0', ('./usr/bin/zstd',)),
}
CLONE_NEWNS = 0x00020000
MS_BIND, MS_REC, MS_PRIVATE = 0x1000, 0x4000, 0x40000


def _sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def enter_tools_namespace(root):
    """Unpack the pinned age/zstd binaries and bind them over /usr/local/sbin for this process tree only."""
    tools = Path(root) / 'tools' / 'owner-sbin'
    if tools.exists():
        shutil.rmtree(tools)
    tools.mkdir(parents=True, mode=0o755)
    found = {}
    for deb, (want, members) in sorted(TOOL_DEBS.items()):
        path = Path(root) / 'input' / deb
        assert _sha(path) == want, 'tool-deb-digest-mismatch'
        proc = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
            for member in tar:
                if member.name in members:
                    assert member.isfile() and member.size < 64 * 1024 ** 2, 'unexpected-member'
                    dest = tools / Path(member.name).name
                    with open(dest, 'xb') as handle:
                        handle.write(tar.extractfile(member).read())
                    os.chmod(dest, 0o755)
                    found[dest.name] = _sha(dest)[:16]
        proc.stdout.close()
        assert proc.wait(timeout=60) == 0, 'dpkg-deb-failed'
    assert sorted(found) == ['age', 'age-keygen', 'zstd'], 'tools-missing'
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(CLONE_NEWNS) != 0:
        raise OSError(ctypes.get_errno(), 'unshare-mount')
    if libc.mount(b'none', b'/', None, MS_REC | MS_PRIVATE, None) != 0:
        raise OSError(ctypes.get_errno(), 'make-private')
    if libc.mount(str(tools).encode(), b'/usr/local/sbin', None, MS_BIND, None) != 0:
        raise OSError(ctypes.get_errno(), 'bind-tools')
    assert sorted(os.listdir('/usr/local/sbin')) == ['age', 'age-keygen', 'zstd'], 'tools-not-visible'
    return found
