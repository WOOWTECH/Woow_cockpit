#!/usr/bin/env python3
"""Real HA backup -> unmodified product `ha_headscale.convert`, inside dev-d as appowner (services-a).

Arguments: <backup-engine dir> <run root> <real backup tar> <expected sha256> <arch> <target volume> <plane volume>

The source is the actual Supervisor backup file (outer envelope, backup.json and
the add-on member exactly as Home Assistant wrote them). Its full SHA-256 is
checked before it is opened and again after the conversion. The add-on member
and addon.json are selected and read by the product parser (`habackup`); the
version comes from the real addon.json, never a fixture value. The target is
this run's disposable Headscale (its own config, API key and volumes).

Scan-limit instrumentation (no product change): the product's throwaway
`hs-check` volume, in which `headscale configtest` may create private keys, is
exported to the private run root just before the product removes it, and the
configtest output the product captured is saved privately; the runner then
registers those keys and submits that output to the credential controller.
Only fixed status lines are printed.
"""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace

CHUNK = 1024 * 1024
ARCH = {'arm': 'aarch64', 'x86': 'amd64'}
EXPECTED_VERSION = '0.1.3'
IMAGE = 'localhost/woow-headscale:0.29.4-r1'
NOISE_REL = 'noise.key'


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def select_member(layout, suffix='woow-headscale'):
    """Exactly one add-on member whose slug ends in `_<suffix>` (repository-prefixed local add-on)."""
    found = [m for m in layout.members if m.role == 'addon' and (m.slug == suffix or m.slug.endswith('_' + suffix))]
    require(len(found) == 1, 'addon_member_missing_or_ambiguous')
    return found[0]


def member_noise_key(opened, member, habackup):
    """HA's Noise private key from the real member (kept in memory only, compared, never printed)."""
    select = habackup.Select(include=('data/noise_private.key',), symlinks=(), hardlinks=False)
    report = habackup.Report()
    value = None
    with opened.open_member(member.name) as stream:
        for entry in habackup.iter_entries(stream, select, report):
            require(entry.kind == 'file' and value is None, 'ha_noise_not_single_file')
            value = entry.read_all(4096).strip()
    require(value is not None and value.startswith(b'privkey:'), 'ha_noise_missing')
    return value


class Runner:
    """appowner's own Podman (no runuser: this process already is the owner inside dev-d)."""

    def __init__(self, home):
        self.home = str(home)
        self.uid = os.getuid()

    def podman(self, *args, **kwargs):
        incoming = kwargs.get('input')
        stream = hasattr(incoming, 'read')
        with tempfile.TemporaryFile() as capture:
            result = subprocess.run(['podman'] + list(args), stdin=incoming if stream else None,
                                    input=None if stream else incoming, stdout=capture,
                                    stderr=subprocess.PIPE, timeout=kwargs.get('timeout', 300))
            capture.seek(0)
            if kwargs.get('stdout') is not None:
                import shutil
                shutil.copyfileobj(capture, kwargs['stdout'])
                result.stdout = None
            else:
                limit = kwargs.get('max_output')
                result.stdout = capture.read(limit + 1 if limit else -1)
        if result.returncode and kwargs.get('check', True):
            # Never include stderr: it can quote file content. Fixed words only.
            raise RuntimeError('podman_failed:' + (args[0] if args else '?'))
        return result

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)

    def read_file(self, path, max_bytes):
        data = (Path(self.home) / path).read_bytes()
        require(len(data) <= max_bytes, 'read_limit')
        return data


class Guard:
    def check(self, need=0):
        return None

    def budget(self):
        return 256 * 1024 * 1024

    def wrote(self, size):
        return None


def instrument(tmp, root):
    """Keep the product's configtest output and its throwaway volume's keys for the private scan."""
    original_run, original_remove_volume = tmp.run, tmp.remove_volume
    saved = {'configtest_output': False, 'configtest_volume': False}

    def run(role, *args, **kwargs):
        result = original_run(role, *args, **kwargs)
        if role == 'hs-configtest':
            data = (getattr(result, 'stdout', b'') or b'') + b'\n' + (getattr(result, 'stderr', b'') or b'')
            path = root / 'configtest-output.log'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data[-1024 * 1024:])
            saved['configtest_output'] = True
        return result

    def remove_volume(role, *args, **kwargs):
        if role == 'hs-check' and not saved['configtest_volume']:
            path = root / 'configtest-private.tar'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                tmp.runner.relay(['volume', 'export', tmp.name(role)], stdout=handle, timeout=300)
            saved['configtest_volume'] = True
        return original_remove_volume(role, *args, **kwargs)

    tmp.run, tmp.remove_volume = run, remove_volume
    return saved


def main(argv):
    engine, root, backup, expected_sha, arch, target_volume, plane_volume = argv
    sys.path.insert(0, engine)
    from woowbackup import habackup, ha_headscale, nested, tempctr  # noqa: E402
    root, backup = Path(root), Path(backup)
    require(os.getuid() == 1019, 'requires_lab_appowner')
    require(arch in ARCH, 'invalid_arch')
    require(len(expected_sha) == 64, 'invalid_expected_sha')
    require(file_sha256(backup) == expected_sha, 'source_sha256_mismatch_before')
    print('real HA backup sha256 matches the host-side value: PASS', flush=True)
    runner = Runner(root)
    tmp = tempctr.TempObjects(runner, 'j20261123T000000Z-' + os.urandom(4).hex(), memory='768m', pids=512, cpus='1')
    saved = instrument(tmp, root)
    quadlets = {
        'headscale.container': (f'[Container]\nContainerName=headscale\nImage={IMAGE}\n'
                                f'Volume={target_volume}.volume:/var/lib/headscale\nVolume=%h/config:/etc/headscale:ro\n').encode(),
        'headplane.container': f'[Container]\nContainerName=headplane\nVolume={plane_volume}.volume:/var/lib/headplane\n'.encode(),
        target_volume + '.volume': f'[Volume]\nVolumeName={target_volume}\n'.encode(),
        plane_volume + '.volume': f'[Volume]\nVolumeName={plane_volume}\n'.encode(),
    }
    app = SimpleNamespace(id='headscale', name='Disposable Headscale target',
                          volumes=[{'name': target_volume}, {'name': plane_volume}], postgres=[], data_dirs=[])
    uid_map = nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/uid_map').stdout.decode())
    gid_map = nested.IdMap(runner.podman('unshare', 'cat', '/proc/self/gid_map').stdout.decode())
    staging = root / 'engine-staging'
    staging.mkdir(mode=0o700)
    out = root / 'converted-output'
    out.mkdir(mode=0o700)
    with habackup.open_backup(backup) as opened:
        member = select_member(opened.layout)
        with opened.open_member(member.name) as stream:
            info = habackup.read_addon_info(stream)
        require(info is not None and info.slug == 'woow-headscale', 'addon_identity_mismatch')
        require(info.version == EXPECTED_VERSION and info.arch == ARCH[arch], 'addon_version_or_arch_mismatch')
        print(f'real Supervisor envelope: add-on member found, addon.json version {info.version}, arch {info.arch}: PASS',
              flush=True)
        ha_noise = member_noise_key(opened, member, habackup)
        work = SimpleNamespace(
            quadlets=lambda _app: quadlets, runner=lambda _app: runner,
            adapter=lambda _app: SimpleNamespace(owner_ids=lambda: (uid_map, gid_map)), temp=lambda _app: tmp,
            addon_member=lambda suffix: select_member(opened.layout, suffix),
            open=lambda selected: opened.open_member(selected.name),
            addon_info=lambda suffix: info if suffix == 'woow-headscale' else None,
            staging=staging, guard=Guard(), abort=None, checkpoint=lambda: None,
            phase=lambda p: print('product phase:', p, flush=True),
            log=lambda message: None)  # product log text is not published (it may quote HA names/paths)
        try:
            result = ha_headscale.convert(work, app, False, out)
        finally:
            remaining = tmp.cleanup()
            require(not remaining, 'product_temporary_resources_remain')
    require(saved['configtest_volume'] and saved['configtest_output'], 'configtest_instrumentation_missing')
    data_tar = Path(result['volumes'][target_volume])
    with tarfile.open(data_tar) as converted:
        entries = [m for m in converted if m.name.removeprefix('./') == NOISE_REL and m.isfile()]
        require(len(entries) == 1, 'converted_noise_missing')
        converted_noise = converted.extractfile(entries[0]).read().strip()
        names = {m.name.removeprefix('./') for m in converted}
    require(converted_noise == ha_noise, 'noise_identity_differs')
    require('db.sqlite-wal' not in names, 'converted_wal_left')
    print('HA Noise key carried into the converted volume (compared in memory): PASS', flush=True)
    require(file_sha256(backup) == expected_sha, 'source_sha256_mismatch_after')
    print('real HA backup unchanged after conversion: PASS', flush=True)
    print(f'product convert: PASS users={result["users"]} nodes={result["nodes"]} '
          f'ha_api_keys_removed={result["api_keys_removed"]} target_api_keys_kept={result["api_keys_kept"]} '
          f'dns_records={result["dns_records"]}', flush=True)
    with open(root / 'convert-result.json', 'x', encoding='utf-8') as handle:
        import json
        json.dump({k: result[k] for k in ('users', 'nodes', 'api_keys_removed', 'api_keys_kept', 'dns_records')},
                  handle)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as error:  # fixed vocabulary only
        code = str(error) if isinstance(error, RuntimeError) and str(error).replace('_', '').replace(':', '').isalnum() else ''
        print(f'product convert: FAIL type={type(error).__name__} code={code[:80]}', flush=True)
        sys.exit(1)
