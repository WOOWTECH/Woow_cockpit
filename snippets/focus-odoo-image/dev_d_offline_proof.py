"""LEASE ONLY: remote body for run_dev_d_proof.py. Root on isolated dev-d, never on the host.

Original images are only inspected/exported as OCI (Docker export has forbidden legacy symlinks). A strict adapter
copies regular blobs into quarantine; the production validator verifies config and EVERY ordered diff_id before load.
Canonical tagging/export then happens in a new preparation store; the final bundle loads into a second empty store.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import tarfile
import types

EXPECTED = 'sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
SOURCE_TAG = 'docker.io/library/postgres:16.15-alpine3.24'
RESERVE = 13 * 1024**3
PHASE = 'preflight'


def failure_reason(error):
    """Public diagnostics contain only exact whitelisted constants, never exception/artifact contents."""
    try:
        from woowbackup import pg16_bundle as bundle, pg16_oci as oci
    except ImportError:
        return 'preflight-import-failed'
    whitelist = {
        bundle.ERROR_UNSAFE_MEMBER: 'unsafe-docker-member',
        bundle.ERROR_LAYER_DIGEST: 'ordered-layer-digest-mismatch',
        bundle.ERROR_CONFIG_IDENTITY: 'config-ref-pin-mismatch',
        bundle.ERROR_ROOTFS: 'invalid-rootfs-digest-list',
        oci.ERROR_LAYOUT: 'invalid-unsafe-oci-layout',
        oci.ERROR_DESCRIPTOR: 'oci-descriptor-digest-size-mismatch',
        oci.ERROR_IDENTITY: 'oci-config-ref-pin-mismatch',
        'source-archive-header-refused': 'source-archive-header-refused',
        'source-trailing-data': 'source-trailing-data',
        'source-archive-truncated': 'source-archive-truncated',
        'source-metadata-refused': 'source-metadata-refused',
    }
    if isinstance(error, (bundle.BundleError, ValueError)):
        return whitelist.get(str(error), 'unclassified-fixed-failure')
    return 'assertion-failed' if isinstance(error, AssertionError) else 'unclassified-fixed-failure'


def canonical_archive(source, output, bundle, abort):
    """Legacy rejection reproducer, retained for regression tests; the real proof now uses strict OCI conversion.

    No extraction, source-store retag, extra image, PAX allocation, owner path, or layer/config rewrite. Output stays
    quarantined until the existing validator authenticates its config AND all uncompressed ordered layer contents.
    """
    with source.open('rb') as src, output.open('xb') as dst:
        count = 0
        while True:
            stop = abort()
            if stop:
                raise stop
            header = src.read(512)
            if header == bytes(512):
                while True:
                    tail = src.read(bundle.CHUNK)
                    if not tail:
                        break
                    if any(tail):
                        raise ValueError('source-trailing-data')
                dst.write(bytes(1024))
                break
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            count += 1
            if count > 4096 or info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or info.size < 0:
                raise ValueError('source-archive-header-refused')
            old_size = info.size
            if info.name in ('manifest.json', 'repositories'):
                if not info.isfile() or old_size > bundle.MAX_JSON:
                    raise ValueError('source-metadata-refused')
                raw = src.read(old_size)
                assert len(raw) == old_size
                value = bundle._json(raw)
                if info.name == 'manifest.json':
                    assert isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict)
                    assert value[0].get('RepoTags') == [SOURCE_TAG]
                    value[0]['RepoTags'] = [bundle.TAG]
                else:
                    repo, old_tag = SOURCE_TAG.rsplit(':', 1)
                    canonical_repo, new_tag = bundle.TAG.rsplit(':', 1)
                    assert repo == canonical_repo and isinstance(value, dict) and set(value) == {repo}
                    assert isinstance(value[repo], dict) and set(value[repo]) == {old_tag}
                    value = {repo: {new_tag: value[repo][old_tag]}}
                raw = json.dumps(value, separators=(',', ':')).encode()
                info.size = len(raw)
                dst.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                dst.write(raw)
                dst.write(bytes(-len(raw) % 512))
            else:
                dst.write(header)
                left = old_size
                while left:
                    stop = abort()
                    if stop:
                        raise stop
                    data = src.read(min(left, bundle.CHUNK))
                    if not data:
                        raise ValueError('source-archive-truncated')
                    dst.write(data)
                    left -= len(data)
                dst.write(bytes(-old_size % 512))
            padding = src.read(-old_size % 512)
            assert len(padding) == -old_size % 512
            assert src.tell() <= bundle.MAX_ARCHIVE and dst.tell() <= bundle.MAX_ARCHIVE
        dst.flush()
        os.fsync(dst.fileno())
    with output.open('rb') as stream:
        bundle.validate_archive(stream, 'amd64', EXPECTED, abort=abort)


def main():
    global PHASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof-root', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, required=True)
    args = parser.parse_args()
    root = args.proof_root
    assert os.geteuid() == 0 and root.parent == Path('/var/lib') and root.name.startswith('woowbk-odoo-pg16-proof-')
    assert root.is_dir() and not root.is_symlink() and root.stat().st_uid == 0 and root.stat().st_mode & 0o777 == 0o755
    assert shutil.disk_usage(root).free >= RESERVE + 4 * 1024**3
    free_start = shutil.disk_usage(root).free
    memory_headroom_start = (int(Path('/sys/fs/cgroup/memory.max').read_text())
                             - int(Path('/sys/fs/cgroup/memory.current').read_text()))
    assert memory_headroom_start >= 512 * 1024**2
    import sys
    sys.path.insert(0, str(args.code_root / 'backup-engine'))
    from woowbackup import ha_odoo, pg16_bundle as bundle, pg16_oci as oci, podman
    from woowbackup.errors import BackupError
    assert bundle.architecture() == 'amd64'
    assert bundle.PINNED_REF.endswith('@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
    # Revalidate the independently retrieved upstream index/platform manifest/config descriptor, offline.
    evidence = args.code_root / 'snippets/focus-odoo-image'
    raw = (evidence / 'upstream-pg16-index.json').read_bytes()
    assert 'sha256:' + hashlib.sha256(raw).hexdigest() == bundle.PINNED_REF.split('@')[1]
    platforms = [x for x in json.loads(raw)['manifests'] if x.get('platform', {}).get('architecture') == 'amd64'
                 and x.get('platform', {}).get('os') == 'linux']
    assert len(platforms) == 1
    manifest = (evidence / 'upstream-pg16-amd64-manifest.json').read_bytes()
    assert 'sha256:' + hashlib.sha256(manifest).hexdigest() == platforms[0]['digest']
    assert json.loads(manifest)['config']['digest'] == EXPECTED
    account = pwd.getpwnam('appowner')
    assert account.pw_uid != 0
    calls = []
    def guard():
        if shutil.disk_usage(root).free < RESERVE:
            return BackupError('insufficient-space', 'proof-reserve-reached')
    def execute(argv, **options):
        args = argv[argv.index(podman.PODMAN) + 1:]
        assert 'pull' not in args
        target = '--root' in args
        store = 'preparation' if str(root / 'preparation-store' / 'graph') in args else 'target' if target else 'source'
        if store == 'source':
            assert args[0] == 'save' or args[:2] == ['image', 'inspect']
        if 'run' in args:
            assert '--pull=never' in args and '--network=none' in args and '--image-volume=ignore' in args
        calls.append((store, 'load' if 'load' in args else 'run' if 'run' in args else 'other'))
        options.setdefault('abort', guard)
        return podman.default_runner(argv, **options)
    source = podman.OwnerRunner('appowner', runner=execute)
    fmt = ('{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}",'
           '"repo_digests":{{json .RepoDigests}},"repo_tags":{{json .RepoTags}}}')
    def source_identity():
        result = source.podman('image', 'inspect', '--format', fmt, EXPECTED, timeout=60, max_output=65536)
        return json.loads(result.stdout)
    before = source_identity()
    assert before['id'].removeprefix('sha256:') == EXPECTED[7:]
    assert before['architecture'] == 'amd64' and before['os'] == 'linux' and before['repo_tags'] == [SOURCE_TAG]
    export = root / 'original.oci.tar'
    PHASE = 'source-export'
    with export.open('xb') as output:
        source.podman('save', '--format', 'oci-archive', SOURCE_TAG, stdout=output,
                      timeout=1800, max_output=bundle.MAX_ARCHIVE, abort=guard)
        output.flush()
        os.fsync(output.fileno())
    PHASE = 'ordered-layer-verification'
    verified = root / 'quarantined-verification-view.tar'
    with export.open('rb') as source_oci, verified.open('x+b') as output:
        oci.convert_archive(source_oci, output, bundle, 'amd64', EXPECTED, expected_tag=SOURCE_TAG, abort=guard)
        os.fsync(output.fileno())
    # The strict regular-only copy preserved config/layer bytes; diff_ids authenticated original contents.
    # Make the actual canonical export with Podman in a NEW preparation store; never tag the original store.
    def isolated_owner(leaf):
        owned = root / leaf
        owned.mkdir(mode=0o700)
        os.chown(owned, account.pw_uid, account.pw_gid)
        for name in ('graph', 'run', 'tmp'):
            (owned / name).mkdir(mode=0o700)
            os.chown(owned / name, account.pw_uid, account.pw_gid)
        flags = ['--root', str(owned / 'graph'), '--runroot', str(owned / 'run'), '--storage-driver', 'vfs',
                 '--events-backend', 'file', '--tmpdir', str(owned / 'tmp'), '--cgroup-manager', 'cgroupfs']
        class IsolatedOwner(podman.OwnerRunner):
            def podman(self, *argv, **options):
                return self.run([podman.PODMAN, *flags, *argv], **options)
        return IsolatedOwner('appowner', runner=execute)
    PHASE = 'disposable-canonical-export'
    preparation = isolated_owner('preparation-store')
    with verified.open('rb') as stream:
        preparation.podman('load', input=stream, timeout=1800, max_output=65536, abort=guard)
    actual_id = preparation.podman('image', 'inspect', '--format', '{{.Id}}', EXPECTED, timeout=60).stdout.decode().strip()
    assert actual_id.removeprefix('sha256:') == EXPECTED[7:]
    preparation.podman('tag', EXPECTED, bundle.TAG, timeout=60, max_output=65536)
    tags = preparation.podman('image', 'inspect', '--format', '{{json .RepoTags}}', EXPECTED, timeout=60).stdout
    assert json.loads(tags) == [bundle.TAG]
    canonical = root / 'canonical.oci.tar'
    with canonical.open('xb') as output:
        preparation.podman('save', '--format', 'oci-archive', bundle.TAG, stdout=output,
                           timeout=1800, max_output=bundle.MAX_ARCHIVE, abort=guard)
        output.flush()
        os.fsync(output.fileno())
    # Packaging + root-trusted staging use the actual release helpers. No root/global-store load.
    spec = importlib.util.spec_from_file_location('od23_packager', args.code_root / 'scripts/package_odoo_pg16.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    PHASE = 'package-and-stage'
    release = package.package(canonical, 'amd64', EXPECTED, root / 'release', input_format='oci-archive', abort=guard)
    install_root = root / 'install-root'
    install_root.mkdir(mode=0o755)
    staged = bundle.install_bundle(root / 'release', release['manifest_sha256'], install_root, abort=guard)
    bundle.INSTALLED_ROOT = install_root / bundle.INSTALL_REL  # Full default / trust chain remains enabled.
    owner = isolated_owner('owner-store')
    app = types.SimpleNamespace(id='odoo', name='Odoo', owner='appowner')
    work = types.SimpleNamespace(runner=lambda app: owner, log=lambda line: None, abort=guard)
    PHASE = 'owner-load'
    selected = ha_odoo.pick_pg16(work, app)
    assert selected == EXPECTED and calls.count(('target', 'load')) == 1
    name = 'od23-version-' + secrets.token_hex(5)
    PHASE = 'offline-version'
    try:
        version = owner.podman('run', '--rm', '--name', name, '--pull=never', '--network=none',
                               '--image-volume=ignore', '--read-only', '--memory=128m', selected,
                               'postgres', '--version', timeout=120, max_output=65536)
        assert b'PostgreSQL) 16.15' in version.stdout
    finally:
        owner.podman('rm', '--force', name, timeout=60, max_output=65536, check=False)
    PHASE = 'reuse-and-cleanup'
    reused = ha_odoo.pick_pg16(work, app)
    reused_id = owner.podman('image', 'inspect', '--format', '{{.Id}}', reused, timeout=60).stdout.decode().strip()
    assert reused_id.removeprefix('sha256:') == EXPECTED[7:] and calls.count(('target', 'load')) == 1
    assert owner.podman('volume', 'ls', '--format', '{{.Name}}', timeout=60).stdout.strip() == b''
    assert owner.podman('ps', '-a', '--format', '{{.Names}}', timeout=60).stdout.strip() == b''
    assert source_identity() == before
    archive = Path(staged['path']) / bundle.ARCHIVE
    with archive.open('rb') as stream:
        sha256, size = bundle.copy_hash(stream, abort=guard)
    result = {'status': 'passed', 'device': 'dev-d', 'proof_root': str(root), 'image_id': EXPECTED,
              'architecture': 'amd64', 'ref': bundle.PINNED_REF, 'source_repo_digests': before['repo_digests'],
              'source_tag_unchanged': True, 'registry_manifest_encoding_preserved': False,
              'config_and_each_ordered_uncompressed_layer_sha256_verified': True,
              'manifest_sha256': release['manifest_sha256'], 'archive_sha256': sha256, 'archive_size': size,
              'loads': 1, 'preparation_loads': calls.count(('preparation', 'load')), 'pulls': 0,
              'canonical_tag_created_only_in_disposable_preparation_store': True,
              'version': version.stdout.decode().strip(), 'anonymous_volumes': 0,
              'containers_remaining': 0, 'free_bytes_after': shutil.disk_usage(root).free,
              'free_bytes_start': free_start, 'device_headroom_bytes_start': memory_headroom_start,
              'reserve_bytes': RESERVE, 'commercial_acceptance': 'not-complete'}
    (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'phase': PHASE, 'error_type': type(error).__name__,
                          'reason': failure_reason(error), 'pulls': 0}))
        raise SystemExit(1)
