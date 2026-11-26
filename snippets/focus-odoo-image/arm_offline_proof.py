#!/usr/bin/env python3
"""LEASE ONLY, run on ARM54 as root. Export existing exact PG16; package/stage/load in NEW disposable paths.

Prerequisites supplied by coordinator: device lease, existing non-root leased owner with uidmap/runtime directory,
and this committed source tree staged under the lease. Never changes accounts, auth, global stores, or services.
No automatic cleanup: retain the uniquely named proof directory for review and lease-scoped cleanup.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-workspace', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, required=True)
    parser.add_argument('--proof-root', type=Path, required=True,
                        help='NEW /var/lib/woowbk-odoo-pg16-proof-<lease-id> (root-only trusted ancestors).')
    parser.add_argument('--owner', required=True, help='Existing non-root account supplied by coordinator lease.')
    args = parser.parse_args()
    source, proof = args.source_workspace, args.proof_root
    assert os.geteuid() == 0
    assert source.parent == Path('/var/tmp') and source.name.startswith('woow-arm54-final-20261123-')
    assert source.is_dir() and not source.is_symlink() and source.stat().st_mode & 0o777 == 0o700
    assert proof.parent == Path('/var/lib') and proof.name.startswith('woowbk-odoo-pg16-proof-')
    assert not proof.exists() and not proof.is_symlink()
    sys.path.insert(0, str(args.code_root / 'backup-engine'))
    from woowbackup import ha_odoo, pg16_bundle as bundle, podman
    from woowbackup.errors import BackupError
    package = load('od23_release_packager', args.code_root / 'scripts/package_odoo_pg16.py')
    expected = 'sha256:35726244c51a57338a5a5a5ad8a7e2b18f4ecb8dccd51224cab33ac2ea6a5df0'
    reserve, budget = 12 * 1024**3 + 128 * 1024**2, 2 * 1024**3
    assert bundle.architecture() == 'arm64'
    assert shutil.disk_usage('/var/lib').free >= reserve + budget
    account = pwd.getpwnam(args.owner)
    assert account.pw_uid != 0 and Path('/run/user/%d' % account.pw_uid).is_dir()
    driver = (source / 'store-driver').read_text().strip()
    assert driver in ('overlay', 'vfs')
    source_base = [podman.PODMAN, '--root', str(source / 'store'), '--runroot', str(source / 'run'),
                   '--storage-driver', driver]
    if driver == 'overlay':
        source_base += ['--storage-opt', 'overlay.skip_mount_home=true']
    source_base += ['--events-backend', 'file', '--tmpdir', str(source / 'tmp'), '--cgroup-manager', 'cgroupfs']
    source_env = dict(podman.ROOT_ENV, PATH='/usr/local/bin:' + podman.SAFE_PATH, HOME=str(source),
                      XDG_CONFIG_HOME=str(source / 'config'), TMPDIR=str(source / 'tmp'),
                      REGISTRY_AUTH_FILE=str(source / 'empty-auth.json'),
                      CONTAINERS_CONF_OVERRIDE=str(source / 'containers-override.conf'))
    # This process tree has no external network. No host interface, user-manager setting, or auth override changes.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET
        raise RuntimeError('network-namespace-unavailable')
    assert sorted(name for _index, name in socket.if_nameindex()) == ['lo']
    calls = []
    def guard():
        if shutil.disk_usage('/var/lib').free < reserve:
            return BackupError('insufficient-space', 'lease-reserve-reached')
    def execute(argv, **kwargs):
        assert shutil.disk_usage('/var/lib').free >= reserve, 'reserve-reached'
        # Reject pull anywhere, and container runs without explicit no-pull/no-network policy.
        assert 'pull' not in argv
        if 'run' in argv:
            assert '--pull=never' in argv and '--network=none' in argv
        calls.append('load' if 'load' in argv else 'run' if 'run' in argv else 'inspect-or-save')
        kwargs.setdefault('abort', guard)
        return podman.default_runner(argv, **kwargs)
    fmt = ('{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}",'
           '"repo_digests":{{json .RepoDigests}},"repo_tags":{{json .RepoTags}}}')
    result = execute(source_base + ['image', 'inspect', '--format', fmt, bundle.PINNED_REF],
                     timeout=60, max_output=65536, env=source_env, cwd='/')
    assert result.returncode == 0, 'exact-source-unavailable'
    image = json.loads(result.stdout)
    assert image['id'].removeprefix('sha256:') == expected[7:]
    assert image['architecture'] == 'arm64' and image['os'] == 'linux'
    assert bundle.TAG in image['repo_tags']
    assert 'docker.io/library/postgres@' + bundle.PINNED_REF.split('@')[1] in image['repo_digests']
    os.umask(0o022)
    proof.mkdir(mode=0o755)
    export = proof / 'export.docker.tar'
    result = execute(source_base + ['save', '--format', 'docker-archive', '--output', str(export), bundle.TAG],
                     timeout=1800, max_output=65536, env=source_env, cwd='/')
    assert result.returncode == 0, 'export-failed'
    release = package.package(export, 'arm64', expected, proof / 'release')
    pin = release['manifest_sha256']
    install_root = proof / 'install-root'
    install_root.mkdir(mode=0o755)
    installed = bundle.install_bundle(proof / 'release', pin, install_root)
    bundle.INSTALLED_ROOT = install_root / bundle.INSTALL_REL  # --root layout; full root trust checks stay enabled.
    owned = proof / 'owner-store'
    owned.mkdir(mode=0o700)
    os.chown(owned, account.pw_uid, account.pw_gid)
    for name in ('graph', 'run', 'tmp'):
        (owned / name).mkdir(mode=0o700)
        os.chown(owned / name, account.pw_uid, account.pw_gid)
    store_flags = ['--root', str(owned / 'graph'), '--runroot', str(owned / 'run'), '--storage-driver', 'vfs',
                   '--events-backend', 'file', '--tmpdir', str(owned / 'tmp'), '--cgroup-manager', 'cgroupfs']
    class IsolatedOwner(podman.OwnerRunner):
        def podman(self, *argv, **options):
            return self.run([podman.PODMAN, *store_flags, *argv], **options)
    runner = IsolatedOwner(args.owner, runner=execute)
    app = type('App', (), {'id': 'odoo', 'name': 'Odoo', 'owner': args.owner})()
    work = type('Work', (), {'runner': lambda self, app: runner, 'log': lambda *args: None,
                            'abort': lambda self: guard()})()
    # Uses production selection, verification and owner-load path; all tagged images are absent in this new store.
    selected = ha_odoo.pick_pg16(work, app)
    assert selected == expected and calls.count('load') == 1
    version = runner.podman('run', '--rm', '--pull=never', '--network=none', '--memory=128m', selected,
                            'postgres', '--version', timeout=120, max_output=65536)
    assert b'PostgreSQL) 16.15' in version.stdout
    assert ha_odoo.pick_pg16(work, app) == selected and calls.count('load') == 1
    archive = Path(installed['path']) / bundle.ARCHIVE
    with archive.open('rb') as stream:
        sha256, size = bundle.copy_hash(stream)
    report = {'status': 'passed', 'source_workspace': str(source), 'proof_root': str(proof), 'architecture': 'arm64',
              'ref': bundle.PINNED_REF, 'image_id': selected, 'archive_sha256': sha256, 'archive_size': size,
              'manifest_sha256': pin, 'loads': calls.count('load'), 'pulls': 0, 'network_interfaces': ['lo'],
              'postgres_version': version.stdout.decode().strip(), 'free_bytes_after': shutil.disk_usage('/var/lib').free,
              'reserve_bytes': reserve, 'commercial_acceptance': 'not-complete'}
    (proof / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not print raw command output, argv, environment, file contents, or exception text.
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__, 'pulls': 0}))
        sys.exit(1)
