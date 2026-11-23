#!/usr/bin/env python3
"""Real-HA candidate -> real adapter install, automatic rollback and restart, inside dev-d (services-a).

Invoked by headscale-real-runner.sh after the product conversion of a REAL HA
backup. It installs that converted candidate through the unmodified engine
(QuadletPostgresAdapter.import_manifest, flows._package with encryption,
flows.run_restore), injects exactly one systemd ExecStartPre failure on the
second restore (flows.RolledBack must restore the pre-failure state), then
restarts the unit. It owns only fresh hs-rinstall-* volumes, one Quadlet, one
drop-in and one marker. Reuses the synthetic installer's verified helpers
(restore_pair, connected_quadlet, arm_once, archive_summary, local_owner).

Client continuity (arm): the real client re-pointed earlier (HA's node, with
its original node key and addresses) must stay the same running process and
reconnect to each installed/rolled-back/restarted server by itself, while the
server lists exactly HA's nodes with that node online. Unlike the synthetic run
no second pre-conversion client exists (HA's other node has no live client), so
DERP traffic is proven before the installer, not in these phases.

The server unit keeps its journal (no LogDriver=none) and the run submits it to
the credential controller (closing the "logs unavailable" scan gap), and the
installed data volume's private keys (the server creates its own DERP key) are
registered before cleanup. Only fixed status lines are printed.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

import headscale_install_rollback as base
from woowbackup import archive, catalog, flows, keys, storage, util
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.paths import Paths

require = base.require
LAB = Path(__file__).resolve().parent


def inputs(root, target, plane):
    root = Path(root)
    require(re.fullmatch(r'/tmp/headscale-real\.[A-Za-z0-9]{8}', str(root)) is not None, 'invalid_real_root')
    require(not root.is_symlink() and root.is_dir() and root.stat().st_uid == os.getuid()
            and root.stat().st_mode & 0o077 == 0, 'private_root_required')
    suffix = root.name.rsplit('.', 1)[1]
    require(target == 'hs-rtarget-' + suffix and plane == 'hs-rplane-' + suffix, 'unexpected_source_names')
    paths = [root / 'target-initial-private.tar', root / 'config/config.yaml',
             root / 'converted-output/volumes' / (target + '.tar'),
             root / 'converted-output/volumes' / (plane + '.tar')]
    for path in paths:
        require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink()
                and path.is_file() and 0 < path.stat().st_size <= 256 * 1024 * 1024, 'invalid_candidate_file')
    return paths, suffix


def client_identity(data):
    """(container id, StartedAt, Pid) of a running client that has only the run's network and no ports."""
    require(data['State']['Running'] is True and not data['HostConfig'].get('PortBindings'), 'client_runtime_changed')
    identity = (data['Id'], data['State']['StartedAt'], data['State']['Pid'])
    require(all(identity), 'client_process_identity_missing')
    return identity


def addresses(values):
    return sorted(str(ipaddress.ip_address(v)) for v in values or [])


def node_rows(nodes):
    require(isinstance(nodes, list), 'nodes_not_list')
    return {int(n['id']): (addresses(n.get('ip_addresses')), n.get('online') is True) for n in nodes}


class RealContinuity:
    """Bounded read-only observation of the real client against each installed server (no login, no reset)."""

    def __init__(self, runner, network, client, expect, *, clock=time.monotonic, sleep=time.sleep):
        self.runner, self.network, self.client = runner, network, client
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + 30
        self.expect = expect
        self.ha_nodes = {int(n['id']): addresses(n['ip_addresses']) for n in expect['nodes']}
        self.process = None
        if client:
            self.process = client_identity(self.json('container', 'inspect', client)[0])
            require(set(self.json('container', 'inspect', client)[0]['NetworkSettings']['Networks']) == {network},
                    'client_network_changed')

    def command(self, *args):
        remaining = self.deadline - self.clock()
        require(remaining > 0, 'continuity_deadline')
        return self.runner.podman(*args, timeout=min(5, remaining), max_output=65536, check=False)

    def json(self, *args):
        result = self.command(*args)
        require(result.returncode == 0, 'continuity_observation_failed')
        return json.loads(result.stdout)

    def connected(self, server):
        nodes = node_rows(self.json('exec', server, 'headscale', 'nodes', 'list', '-o', 'json'))
        if {k: v[0] for k, v in nodes.items()} != self.ha_nodes:
            raise RuntimeError('installed_nodes_not_ha_nodes')
        if not self.client:
            return True
        status = self.json('exec', self.client, 'tailscale', '--socket=/tmp/tailscaled.sock', 'status', '--json')
        client = self.expect['client']
        me = status.get('Self') or {}
        same = (str(me.get('ID')) == str(client['NodeID']) and me.get('PublicKey') == client['NodePublicKey']
                and addresses(me.get('TailscaleIPs')) == addresses(client['TailscaleIPs']))
        if not same and status.get('BackendState') == 'Running':
            raise RuntimeError('client_identity_changed')
        return (same and status.get('BackendState') == 'Running' and not status.get('AuthURL')
                and nodes[int(client['NodeID'])][1])

    def verify(self, server, phase):
        require(phase in ('installed', 'rolled_back', 'restarted'), 'continuity_invalid_phase')
        start = self.clock()
        self.deadline = start + 60
        attempts = 0
        while self.clock() < self.deadline:
            attempts += 1
            if self.client:
                now = client_identity(self.json('container', 'inspect', self.client)[0])
                require(now == self.process, 'client_process_replaced')
            if self.connected(server):
                if self.client:
                    require(client_identity(self.json('container', 'inspect', self.client)[0]) == self.process,
                            'client_process_replaced')
                print(f'HEADSCALE_REAL_CONTINUITY={phase}:PASS attempts={attempts} '
                      f'elapsed={self.clock() - start:.1f}s client={"real" if self.client else "none"}', flush=True)
                return
            self.sleep(min(1, max(0, self.deadline - self.clock())))
        raise RuntimeError('continuity_deadline')


def register_volume_keys(runner, volume, private, source):
    """Export a stopped volume privately and register all its private keys with the controller."""
    exported = private / ('keys-' + secrets.token_hex(4) + '.tar')
    with exported.open('wb') as stream:
        os.chmod(exported, 0o600)
        runner.relay(['volume', 'export', volume], stdout=stream, max_output=256 * 1024 * 1024)
    try:
        values = subprocess.run([sys.executable, '-I', str(LAB / 'headscale-private-sources.py'), 'volume-all',
                                 str(exported)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
                                check=True).stdout
    finally:
        exported.unlink()
    _producer(['--register-private', source], values)


def _producer(args, data):
    """Run one acknowledged producer of the controller; the event socket must reach it (pass_fds)."""
    fd = int(os.environ['HEADSCALE_EVENT_FD'])
    subprocess.run([sys.executable, '-I', str(LAB / 'headscale_real_events.py'), *args], input=data,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=True, pass_fds=(fd,))


def log_bytes(text, limit=1024 * 1024 - 64):
    """The last `limit` bytes of a journal as valid UTF-8 (the controller rejects larger or invalid text)."""
    return text.encode('utf-8', 'replace')[-limit:].decode('utf-8', 'ignore').encode('utf-8')


def submit_log(text, source):
    _producer(['--scan-log', source], log_bytes(text))


def run(root, target, plane, server_address, network, client):
    (seed, config, candidate, plane_tar), suffix = inputs(root, target, plane)
    r = base.local_owner()
    info = json.loads(r.podman('network', 'inspect', network, max_output=1024 * 1024).stdout)[0]
    require(info['name'] == network and network == 'hs-real-' + suffix and info['internal'] is True
            and info.get('labels', {}).get('io.woowtech.test') == 'headscale-derp', 'network_not_isolated')
    address = ipaddress.IPv4Address(server_address)
    require(any(address in ipaddress.ip_network(s['subnet']) for s in info['subnets'] if ':' not in s['subnet']),
            'server_address_outside_network')
    require(client in ('', 'hs-ralice-' + suffix), 'unexpected_client')
    root = Path(root)
    expect = json.loads((root / 'expect.json').read_text(encoding='utf-8'))
    continuity = RealContinuity(r, network, client, expect)
    prefix = 'hs-rinstall-' + secrets.token_hex(4)
    volumes = [prefix + '-data', prefix + '-plane']
    unit = prefix + '.service'
    rel = '.config/containers/systemd/' + prefix + '.container'
    dropdir = '.config/systemd/user/' + unit + '.d'
    drop = dropdir + '/fail-once.conf'
    marker = '.config/' + prefix + '-fail'
    private = Path(tempfile.mkdtemp(prefix='installer-', dir=root))
    os.chmod(private, 0o700)
    paths = Paths(base=private)
    state = {'enabled': False, 'count': 0}
    owned_volumes, owned_files = [], []
    directory_created = False
    success = False
    keys_registered = False
    raw = {'schema': 1, 'id': 'headscale', 'name': 'Real HA candidate installer', 'owner': 'appowner',
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
            base.arm_once(r, marker, state)
        kwargs['imported_hook'] = imported
        return QuadletPostgresAdapter(app_, r, runtime_ready=runtime_ready, **kwargs)
    deps = flows.Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
                      load_catalog=lambda: catalog.Catalog({'headscale': app}), adapter_factory=factory,
                      host_info=lambda: {'hostname': 'isolated-dev-d', 'arch': 'x86_64',
                                         'machine_id_sha256': '', 'os': 'lab', 'podman': 'lab'},
                      encrypt_by_default=lambda: True, audit=lambda line: None)

    def context():
        return flows.FlowContext(paths, 'j' + util.compact_utc() + '-' + secrets.token_hex(4), deps, base.Reporter())
    expected_identity = base.archive_summary(candidate, headscale=True)
    expected_plane = [base.archive_summary(plane_tar)]
    expected_users = [None]

    def users():
        return json.loads(r.podman('exec', prefix, 'headscale', 'users', 'list', '-o', 'json',
                                   max_output=65536).stdout)

    def wait_health(code):
        deadline = time.monotonic() + 60
        while r.podman('exec', prefix, 'headscale', 'health', check=False, timeout=5, max_output=4096).returncode != 0:
            require(time.monotonic() < deadline, code)
            time.sleep(1)

    def verify(phase):
        wait_health('health_timeout')
        data = json.loads(r.podman('container', 'inspect', prefix, max_output=1024 * 1024).stdout)[0]
        require(data['Image'].removeprefix('sha256:') == base.IMAGE and
                set(data['NetworkSettings']['Networks']) == {network} and
                data['NetworkSettings']['Networks'][network]['IPAddress'] == str(address) and
                not data['HostConfig'].get('PortBindings'), 'installed_runtime_mismatch')
        continuity.verify(prefix, phase)
        # Cold exports: exact candidate node identities / Noise key and every Headplane path.
        r.systemctl('stop', unit)
        for volume, is_headscale, expected in ((volumes[0], True, expected_identity),
                                               (volumes[1], False, expected_plane[0])):
            exported = private / ('verify-' + volume + '.tar')
            with exported.open('wb') as stream:
                os.chmod(exported, 0o600)
                r.relay(['volume', 'export', volume], stdout=stream, max_output=256 * 1024 * 1024)
            summary = base.archive_summary(exported, headscale=is_headscale)
            exported.unlink()
            require(summary == expected, 'restored_identity_or_plane_mismatch')
        r.systemctl('start', unit)
        wait_health('restarted_health_timeout')
        if expected_users[0] is not None:
            require(users() == expected_users[0], 'rollback_user_marker_missing')
        require(r.systemctl('is-active', unit).stdout.strip() == b'active', 'unit_not_active')
        require(r.stat_files([marker])[marker]['type'] == 'missing', 'failure_marker_unconsumed')
        print(f'HEADSCALE_REAL_INSTALL_{phase.upper()}=PASS cold_export_identity=exact', flush=True)

    def mutate():
        import io
        import tarfile
        r.podman('exec', prefix, 'headscale', 'users', 'create', 'rollback-marker', '-o', 'json', max_output=65536)
        expected_users[0] = users()
        require(any(u.get('name') == 'rollback-marker' for u in expected_users[0]), 'marker_not_created')
        r.systemctl('stop', unit)
        marker_tar = private / 'plane-marker.tar'
        with tarfile.open(marker_tar, 'w') as tar:
            entry = tarfile.TarInfo('rollback-marker')
            data = b'real-candidate-plane-before-failure\n'
            entry.size, entry.mode, entry.uid, entry.gid = len(data), 0o640, 0, 0
            tar.addfile(entry, io.BytesIO(data))
        marker_tar.chmod(0o600)
        with marker_tar.open('rb') as stream:
            r.podman('volume', 'import', volumes[1], '-', input=stream)
        exported = private / 'plane-before-failure.tar'
        with exported.open('wb') as stream:
            os.chmod(exported, 0o600)
            r.relay(['volume', 'export', volumes[1]], stdout=stream, max_output=256 * 1024 * 1024)
        expected_plane[0] = base.archive_summary(exported)
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
        require(r.systemctl('show', unit, '-p', 'LoadState', '--value', check=False).stdout.strip() == b'not-found',
                'unit_collision')
        for v in volumes:
            owned_volumes.append(v)
            r.podman('volume', 'create', v)
        with seed.open('rb') as stream:
            r.podman('volume', 'import', volumes[0], '-', input=stream)
        text = ('[Container]\nImage=sha256:' + base.IMAGE + '\nContainerName=' + prefix +
                '\nNetwork=none\nPull=never\nVolume=' + volumes[0] + ':/var/lib/headscale\n' +
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
        # The seed (target's own initial data) runs disconnected; the packaged Quadlet is connected to the
        # run's internal network at the restored server's address, so the real client can reach it.
        connected_text = base.connected_quadlet(text, network, str(address))
        r.write_file(rel, connected_text.encode(), 0o600)
        r.systemctl('daemon-reload')
        deps.storage.ensure_layout()
        key, _ = deps.keys.ensure_device_key()
        ctx = context()
        staging = Path(deps.storage.staging_dir(ctx.job_id))
        appdir = staging / 'apps/headscale'
        appdir.mkdir(mode=0o700, parents=True)
        manifest, entries = ctx.adapter(app).import_manifest(appdir, volumes={volumes[0]: candidate, volumes[1]: plane_tar})
        packaged = flows._package(ctx, [app], staging, include_images=False, note='Real HA Headscale candidate',
                                  backup_type='manual', key=key, phases=False, manifest_apps=[manifest],
                                  entries=entries, downtime=0)
        require(packaged['encrypted'], 'unencrypted_candidate')
        base.restore_pair(lambda bid: flows.run_restore(context(), {'backup_id': bid, 'apps': ['headscale']}),
                          packaged['backup_id'], state, verify, safety, mutate)
        r.systemctl('restart', unit)
        verify('restarted')
        print('HEADSCALE_REAL_INSTALL_ROLLBACK=PASS', flush=True)
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
            journal = ['']
            clean(lambda: journal.__setitem__(0, r.run(['/usr/bin/journalctl', '--user', '-u', unit, '-o', 'cat',
                                                        '--no-pager'], check=False, max_output=1024 * 1024)
                                                 .stdout.decode('utf-8', 'replace')))
            clean(lambda: submit_log(journal[0], 'installed_server'))
        if owned_volumes:
            def keys_now():
                register_volume_keys(r, volumes[0], private, 'installed_keys')
                return True
            try:
                keys_registered = keys_now()
            except Exception:
                failures.append(True)
        if owned_files:
            clean(lambda: r.systemctl('unmask', unit))
            clean(lambda: r.systemctl('reset-failed', unit, check=False))
            clean(lambda: r.podman('rm', '-f', prefix, check=False))
            clean(lambda: require(r.podman('container', 'exists', prefix, check=False).returncode == 1,
                                  'container_remains'))
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
            clean(lambda: require(all(v['type'] == 'missing' for v in r.stat_files(owned_files + [marker]).values()),
                                  'files_remain'))
            clean(lambda: require(r.systemctl('show', unit, '-p', 'LoadState', '--value',
                                              check=False).stdout.strip() == b'not-found', 'unit_remains'))
        clean(lambda: shutil.rmtree(private))
        require(not failures and keys_registered, 'installer_cleanup_incomplete')
        print('HEADSCALE_REAL_INSTALL_CLEANUP=PASS', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--run', action='store_true')
    p.add_argument('--server-address', required=True)
    p.add_argument('--network', required=True)
    p.add_argument('--client', default='')
    p.add_argument('root')
    p.add_argument('target')
    p.add_argument('plane')
    args = p.parse_args()
    require(args.run, 'explicit_run_required')
    run(args.root, args.target, args.plane, args.server_address, args.network, args.client)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, RuntimeError) and re.fullmatch(r'[a-z_]{3,60}', str(error)) else ''
        print(f'HEADSCALE_REAL_INSTALL_ROLLBACK=FAIL type={type(error).__name__} code={code}', flush=True)
        sys.exit(1)
