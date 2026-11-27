#!/usr/bin/env python3
"""Synthetic-only in-dev-d real adapter/restore exercise; never a public import entry.

Invoked by headscale-product-runner after conversion and client checks. It owns
new volumes/Quadlet only. Local tests do not establish real installer acceptance.
"""
import argparse
import hashlib
import io
import sqlite3
import tarfile
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import tempfile
import time

from headscale_client_continuity import Continuity

from woowbackup import archive, catalog, flows, keys, podman, storage, util
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.paths import Paths

IMAGE = 'a5f7b9715dea9116f435ff7892e6925895d1c92d4a265cc02eff1a2abadb227d'


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def inputs(root, target, plane):
    root = Path(root)
    require(re.fullmatch(r'/tmp/headscale-internal\.[A-Za-z0-9]{8}', str(root)) is not None,
            'invalid_synthetic_root')
    require(not root.is_symlink() and root.is_dir() and root.stat().st_uid == os.getuid()
            and root.stat().st_mode & 0o077 == 0, 'private_root_required')
    suffix = root.name.rsplit('.', 1)[1]
    require(target == 'hs-target-' + suffix and plane == 'hs-plane-' + suffix,
            'unexpected_source_names')
    paths = [root / 'target-initial-private.tar', root / 'config/config.yaml',
             root / 'converted-output/volumes' / (target + '.tar'),
             root / 'converted-output/volumes' / (plane + '.tar')]
    for path in paths:
        require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink()
                and path.is_file() and 0 < path.stat().st_size <= 256 * 1024 * 1024,
                'invalid_candidate_file')
    return paths


def archive_summary(path, *, headscale=False):
    """Private synthetic archive only. Return hashes/identities in memory, never log.

    No extractall, extensions, schema writes or arbitrary SQL. Refuse WAL rather
    than silently reading a stale DB. This is not a general untrusted DB reader.
    """
    files, database = {}, None
    with tarfile.open(path) as tar:
        total = 0
        for member in tar:
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.'):
                continue
            require(not name.startswith('/') and '..' not in Path(name).parts and
                    (member.isfile() or member.isdir()) and name not in files,
                    'unsafe_summary_member')
            total += member.size
            require(total <= 256 * 1024 * 1024, 'summary_limit')
            data = tar.extractfile(member).read() if member.isfile() else b''
            files[name] = (member.mode, member.uid, member.gid, hashlib.sha256(data).hexdigest())
            if name == 'db.sqlite':
                database = data
            require(not (headscale and name == 'db.sqlite-wal' and data), 'cold_wal_not_supported')
    if not headscale:
        return files
    require(database is not None and 'noise.key' in files, 'candidate_identity_missing')
    with tempfile.TemporaryDirectory(prefix='hs-summary-') as private:
        db = Path(private) / 'db.sqlite'
        db.write_bytes(database)
        db.chmod(0o600)
        conn = sqlite3.connect(db.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('PRAGMA query_only=ON')
            require(conn.execute("SELECT type FROM sqlite_master WHERE name='nodes'").fetchall() == [('table',)],
                    'nodes_not_table')
            columns = {row[1] for row in conn.execute('PRAGMA table_xinfo(nodes)')}
            required = {'id', 'node_key', 'machine_key', 'ipv4', 'ipv6'}
            require(required <= columns, 'node_identity_schema_unsupported')
            conn.set_authorizer(lambda action, *args: sqlite3.SQLITE_OK if action in
                                (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ) else sqlite3.SQLITE_DENY)
            rows = conn.execute('SELECT id,node_key,machine_key,ipv4,ipv6 FROM nodes ORDER BY id LIMIT 3').fetchall()
            require(len(rows) == 2, 'expected_two_synthetic_nodes')
            return (tuple(rows), files['noise.key'])
        finally:
            conn.close()


class Reporter:
    cancellable = False
    def __getattr__(self, name):
        if name == 'cancel_requested':
            return lambda: False
        return lambda *a, **kw: None


def local_owner():
    # Only the outer wrapper establishes dev-d isolation. Never invoke as host user.
    require(os.getuid() == 1019 and os.environ.get('HEADSCALE_EVENT_FD') is not None,
            'controlled_lab_owner_required')
    holder = {}
    def bridge(argv, *, cwd=None, env=None, **kwargs):
        r = holder['runner']
        prefix = r.prefix()
        require(argv[:len(prefix)] == prefix and cwd == r.home and env == podman.ROOT_ENV,
                'unexpected_owner_transport')
        safe = {'PATH': podman.SAFE_PATH, 'HOME': r.home, 'LANG': 'C.UTF-8',
                'XDG_RUNTIME_DIR': r.runtime_dir,
                'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + r.runtime_dir + '/bus'}
        return podman.default_runner(argv[len(prefix):], cwd=cwd, env=safe, **kwargs)
    r = podman.OwnerRunner('appowner', runner=bridge)
    holder['runner'] = r
    require(r.uid == os.getuid() and r.home == '/home/appowner', 'owner_mismatch')
    return r


def arm_once(runner, marker, state):
    if state['enabled'] and state['count'] == 0:
        runner.write_file(marker, b'fail-once\n', 0o600)
        state['count'] += 1


def restore_pair(restore, backup_id, state, verify, verify_safety, mutate):
    result = restore(backup_id)
    require(result['changed'] and not result['rolled_back'], 'install_not_successful')
    verify_safety(result['safety_backup_id'])
    verify('installed')
    mutate()
    state['enabled'] = True
    try:
        restore(backup_id)
    except flows.RolledBack as outcome:
        require(outcome.result['rolled_back'] and state['count'] == 1, 'rollback_not_automatic')
        verify_safety(outcome.result['safety_backup_id'])
    else:
        raise RuntimeError('injected_failure_not_observed')
    verify('rolled_back')


def connected_quadlet(text, network, address):
    # dev-d's Quadlet generator rejects NetworkAlias=. Use the same Podman
    # flags already exercised by the converted-server harness. Inputs have
    # been validated by Continuity before constructing this synthetic unit.
    return text.replace('Network=none\n', 'Network=' + network + '\n').replace(
        'PodmanArgs=', 'PodmanArgs=--network-alias=headscale.lab --ip=' + address + ' ')


def run(root, target, plane, client_address):
    seed, config, candidate, plane_tar = inputs(root, target, plane)
    r = local_owner()
    continuity = Continuity(r, root, client_address)
    prefix = 'hs-install-' + secrets.token_hex(4)
    volumes = [prefix + '-data', prefix + '-plane']
    unit = prefix + '.service'
    rel = '.config/containers/systemd/' + prefix + '.container'
    dropdir = '.config/systemd/user/' + unit + '.d'
    drop = dropdir + '/fail-once.conf'
    marker = '.config/' + prefix + '-fail'
    root = Path(root)
    private = Path(tempfile.mkdtemp(prefix='installer-', dir=root))
    os.chmod(private, 0o700)
    paths = Paths(base=private)
    state = {'enabled': False, 'count': 0}
    owned_volumes, owned_files = [], []
    directory_created = False
    success = False
    raw = {'schema': 1, 'id': 'headscale', 'name': 'Synthetic installer', 'owner': 'appowner',
           'adapter': 'quadlet-postgres', 'quadlet': {'files': [prefix + '.container']},
           'units': [unit], 'writer_units': [unit], 'volumes': [{'name': v} for v in volumes]}
    app = catalog.validate_entry(raw, paths=paths)
    runtime_ready = lambda: r.run(['/usr/bin/test', '-S', r.runtime_dir + '/bus'], check=False).returncode == 0
    require(runtime_ready(), 'user_bus_missing')
    def factory(app_, **kwargs):
        previous = kwargs.get('imported_hook')
        def imported():
            if previous:
                previous()
            arm_once(r, marker, state)
        kwargs['imported_hook'] = imported
        return QuadletPostgresAdapter(app_, r, runtime_ready=runtime_ready, **kwargs)
    deps = flows.Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
                      load_catalog=lambda: catalog.Catalog({'headscale': app}), adapter_factory=factory,
                      host_info=lambda: {'hostname': 'synthetic-dev-d', 'arch': 'x86_64',
                                         'machine_id_sha256': '', 'os': 'lab', 'podman': 'lab'},
                      encrypt_by_default=lambda: True, audit=lambda line: None)
    def context():
        return flows.FlowContext(paths, 'j' + util.compact_utc() + '-' + secrets.token_hex(4), deps, Reporter())
    expected_identity = archive_summary(candidate, headscale=True)
    expected_plane = [archive_summary(plane_tar)]
    expected_users = [None]
    def users():
        return json.loads(r.podman('exec', prefix, 'headscale', 'users', 'list', '-o', 'json',
                                  max_output=65536).stdout)
    def verify(phase):
        deadline = time.monotonic() + 60
        while r.podman('exec', prefix, 'headscale', 'health', check=False,
                       timeout=5, max_output=4096).returncode != 0:
            require(time.monotonic() < deadline, 'health_timeout')
            time.sleep(1)
        data = json.loads(r.podman('container', 'inspect', prefix, max_output=1024*1024).stdout)[0]
        require(data['Image'].removeprefix('sha256:') == IMAGE and
                set(data['NetworkSettings']['Networks']) == {continuity.network} and
                data['NetworkSettings']['Networks'][continuity.network]['IPAddress'] == continuity.address and
                not data['HostConfig'].get('PortBindings'),
                'installed_runtime_mismatch')
        nodes = json.loads(r.podman('exec', prefix, 'headscale', 'nodes', 'list', '-o', 'json', max_output=65536).stdout)
        require(len(nodes) == 2, 'installed_nodes_missing')
        continuity.verify(prefix, phase)
        # Cold exports compare exact candidate node identities/Noise and all plane
        # paths/content/mode/UID/GID; counts alone cannot establish preservation.
        r.systemctl('stop', unit)
        for volume, is_headscale, expected in ((volumes[0], True, expected_identity),
                                               (volumes[1], False, expected_plane[0])):
            exported = private / ('verify-' + volume + '.tar')
            with exported.open('wb') as stream:
                os.chmod(exported, 0o600)
                r.relay(['volume', 'export', volume], stdout=stream, max_output=256*1024*1024)
            require(archive_summary(exported, headscale=is_headscale) == expected,
                    'restored_identity_or_plane_mismatch')
            exported.unlink()
        r.systemctl('start', unit)
        deadline = time.monotonic() + 60
        while r.podman('exec', prefix, 'headscale', 'health', check=False,
                       timeout=5, max_output=4096).returncode != 0:
            require(time.monotonic() < deadline, 'restarted_health_timeout')
            time.sleep(1)
        if expected_users[0] is not None:
            require(users() == expected_users[0], 'rollback_user_marker_missing')
        require(r.systemctl('is-active', unit).stdout.strip() == b'active', 'unit_not_active')
        require(r.stat_files([marker])[marker]['type'] == 'missing', 'failure_marker_unconsumed')
    def mutate():
        r.podman('exec', prefix, 'headscale', 'users', 'create', 'rollback-marker', '-o', 'json', max_output=65536)
        expected_users[0] = users()
        require(any(u.get('name') == 'rollback-marker' for u in expected_users[0]), 'marker_not_created')
        r.systemctl('stop', unit)
        marker_tar = private / 'plane-marker.tar'
        with tarfile.open(marker_tar, 'w') as tar:
            entry = tarfile.TarInfo('rollback-marker')
            data = b'synthetic-plane-before-failure\n'
            entry.size, entry.mode, entry.uid, entry.gid = len(data), 0o640, 0, 0
            tar.addfile(entry, io.BytesIO(data))
        marker_tar.chmod(0o600)
        with marker_tar.open('rb') as stream:
            r.podman('volume', 'import', volumes[1], '-', input=stream)
        exported = private / 'plane-before-failure.tar'
        with exported.open('wb') as stream:
            os.chmod(exported, 0o600)
            r.relay(['volume', 'export', volumes[1]], stdout=stream, max_output=256*1024*1024)
        expected_plane[0] = archive_summary(exported)
        require('rollback-marker' in expected_plane[0], 'plane_marker_missing')
        r.systemctl('start', unit)
    def safety(backup_id):
        meta = deps.storage.get(backup_id)
        require(meta['type'] == 'safety' and meta['encrypted'], 'unencrypted_safety')
        dest = private / ('verify-' + secrets.token_hex(4))
        dest.mkdir(mode=0o700)
        archive.extract_archive(Path(deps.storage.archive_path(backup_id)), deps.keys.identities(), dest,
                                apps=['headscale'])
        shutil.rmtree(dest)
    try:
        require(all(r.podman('volume', 'exists', v, check=False).returncode == 1 for v in volumes), 'volume_collision')
        require(r.podman('container', 'exists', prefix, check=False).returncode == 1, 'container_collision')
        require(all(s['type'] == 'missing' for s in r.stat_files([rel, dropdir, marker]).values()), 'path_collision')
        require(r.systemctl('show', unit, '-p', 'LoadState', '--value', check=False).stdout.strip() == b'not-found', 'unit_collision')
        for v in volumes:
            owned_volumes.append(v)
            r.podman('volume', 'create', v)
        with seed.open('rb') as stream:
            r.podman('volume', 'import', volumes[0], '-', input=stream)
        text = ('[Container]\nImage=sha256:' + IMAGE + '\nContainerName=' + prefix +
                '\nNetwork=none\nPull=never\nLogDriver=none\nVolume=' + volumes[0] + ':/var/lib/headscale\n' +
                'Volume=' + volumes[1] + ':/var/lib/headplane\nVolume=' + str(config.parent) +
                ':/etc/headscale:ro\nExec=serve\nPodmanArgs=--memory=384m --cpus=1 --pids-limit=256\n' +
                '[Service]\nRestart=no\nTimeoutStartSec=90\n')
        owned_files.append(rel)
        r.write_file(rel, text.encode(), 0o600)
        r.run(['/usr/bin/mkdir', '--', r.home + '/' + dropdir])
        directory_created = True
        owned_files.append(drop)
        r.write_file(drop, ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + marker +
                            '; then rm -f %h/' + marker + '; exit 1; fi\'\n').encode(), 0o600)
        r.systemctl('daemon-reload')
        r.systemctl('start', unit)
        # Seed runtime remains disconnected. The packaged Quadlet takes over only
        # when the real restore stops/recreates it; no unrelated identity is advertised.
        connected_text = connected_quadlet(text, continuity.network, continuity.address)
        r.write_file(rel, connected_text.encode(), 0o600)
        r.systemctl('daemon-reload')
        deps.storage.ensure_layout()
        key, _ = deps.keys.ensure_device_key()
        ctx = context()
        staging = Path(deps.storage.staging_dir(ctx.job_id))
        appdir = staging / 'apps/headscale'
        appdir.mkdir(mode=0o700, parents=True)
        manifest, entries = ctx.adapter(app).import_manifest(appdir, volumes={volumes[0]: candidate, volumes[1]: plane_tar})
        packaged = flows._package(ctx, [app], staging, include_images=False, note='Synthetic HA Headscale',
                                 backup_type='manual', key=key, phases=False, manifest_apps=[manifest], entries=entries, downtime=0)
        require(packaged['encrypted'], 'unencrypted_candidate')
        restore_pair(lambda bid: flows.run_restore(context(), {'backup_id': bid, 'apps': ['headscale']}),
                     packaged['backup_id'], state, verify, safety, mutate)
        r.systemctl('restart', unit)
        verify('restarted')
        print('HEADSCALE_INSTALL_ROLLBACK=PASS', flush=True)
        success = True
    finally:
        failures = []
        def clean(fn):
            try:
                fn()
            except Exception:
                failures.append(True)
        if owned_files:
            clean(lambda: r.systemctl('stop', unit, check=False))
            clean(lambda: r.systemctl('unmask', unit))
            clean(lambda: r.systemctl('reset-failed', unit, check=False))
            clean(lambda: r.podman('rm', '-f', prefix, check=False))
            clean(lambda: require(r.podman('container', 'exists', prefix, check=False).returncode == 1, 'container_remains'))
        for v in reversed(owned_volumes):
            clean(lambda v=v: r.podman('volume', 'rm', v, check=False))
            clean(lambda v=v: require(r.podman('volume', 'exists', v, check=False).returncode == 1, 'volume_remains'))
        for path in reversed(owned_files):
            clean(lambda path=path: r.remove_file(path))
        if state['count']:
            clean(lambda: r.remove_file(marker))
        if directory_created:
            clean(lambda: r.run(['/usr/bin/rmdir', '--', r.home + '/' + dropdir]))
        if owned_files:
            clean(lambda: r.systemctl('daemon-reload'))
            clean(lambda: require(all(v['type'] == 'missing' for v in
                                      r.stat_files(owned_files + [marker]).values()), 'files_remain'))
            clean(lambda: require(r.systemctl('show', unit, '-p', 'LoadState', '--value',
                                             check=False).stdout.strip() == b'not-found', 'unit_remains'))
        if success and not failures:
            shutil.rmtree(private)
        require(not failures, 'installer_cleanup_incomplete')
        print('HEADSCALE_INSTALL_CLEANUP=PASS', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--client-address', required=True)
    p.add_argument('root')
    p.add_argument('target')
    p.add_argument('plane')
    args = p.parse_args()
    require(args.run, 'explicit_run_required')
    run(args.root, args.target, args.plane, args.client_address)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never emit command stderr/body/path/credential-containing exception text.
        print('HEADSCALE_INSTALL_ROLLBACK=FAIL type=' + type(error).__name__, flush=True)
        sys.exit(1)
