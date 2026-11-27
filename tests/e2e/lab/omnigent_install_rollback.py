#!/usr/bin/env python3
"""Explicit-slot-only synthetic dev-d app-chain -> real encrypted adapter restore.

Host-side archive/storage; every owner operation goes through owner.sh d. No
production OwnerRunner subprocess is ever executed. Reuses the EMQX adapter
pattern: imported_hook arms a one-shot systemd ExecStartPre failure, and the
unmodified flows.run_restore performs automatic rollback.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

import omnigent_real_app_chain as chain
from woowbackup import archive, catalog, flows, keys, podman, storage, util
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
from woowbackup.paths import Paths


class Reporter:
    """Never publish engine log text: it can contain synthetic credentials."""
    cancellable = False
    def phase(self, *args, **kwargs): pass
    def skip(self, *args, **kwargs): pass
    def complete(self, *args, **kwargs): pass
    def fail(self, *args, **kwargs): pass
    def mark(self, *args, **kwargs): pass
    def add_phase(self, *args, **kwargs): pass
    def log(self, *args, **kwargs): pass
    def set_partial(self, **kwargs): pass
    def set_cancellable(self, flag):
        self.cancellable = flag
        return False
    def cancel_requested(self): return False
    def progress(self, *args, **kwargs): pass


class DeviceOwner:
    """Real OwnerRunner helper/relay/systemd implementation over the dev-d bridge."""
    def __init__(self, execute=podman.default_runner):
        self.execute = execute
        result = self.direct(['/usr/bin/id', '-u'])
        gid = self.direct(['/usr/bin/id', '-g'])
        uid, group = int(result.stdout.strip()), int(gid.stdout.strip())
        if uid != 1019 or group == 0:
            raise RuntimeError('unexpected_dev_d_owner')
        self.account = SimpleNamespace(pw_uid=uid, pw_gid=group, pw_dir='/home/appowner')
        self.runner = podman.OwnerRunner('appowner', user_lookup=self.lookup, runner=self.bridge)

    def lookup(self, name):
        if name != 'appowner':
            raise KeyError(name)
        return self.account

    def direct(self, argv, **kwargs):
        kwargs.setdefault('timeout', 120)
        kwargs.setdefault('max_output', 4 * 1024 * 1024)
        return self.execute([str(chain.OWNER), 'd', *argv], **kwargs)

    def bridge(self, argv, *, cwd=None, env=None, **kwargs):
        prefix = self.runner.prefix()
        if argv[:len(prefix)] != prefix or cwd != self.runner.home or env != podman.ROOT_ENV:
            raise RuntimeError('unexpected_owner_transport')
        return self.direct(argv[len(prefix):], **kwargs)

    def runtime_ready(self):
        return self.runner.run(['/usr/bin/test', '-S', self.runner.runtime_dir + '/bus'],
                               check=False).returncode == 0

    def statvfs(self, folder):
        if str(folder).startswith('/home/appowner'):
            script = 'import os,json,sys;s=os.statvfs(sys.argv[1]);print(json.dumps([s.f_bavail,s.f_frsize]))'
            result = self.runner.run(['/usr/bin/python3', '-I', '-c', script, str(folder)], max_output=4096)
            available, block = json.loads(result.stdout)
            return SimpleNamespace(f_bavail=available, f_frsize=block)
        return os.statvfs(folder)


def specification():
    """Only resources created by this invocation's app-chain are named here."""
    prefix = chain.PREFIX + '-install'
    names = [prefix + suffix for suffix in ('-db', '-server', '-runner')]
    runner = names[2]
    units = [name + '.service' for name in names]
    files = [name + '.container' for name in names]
    common = '\n[Service]\nRestart=no\nTimeoutStartSec=180\n'
    quadlets = {
        files[0]: ('[Container]\nImage=sha256:' + chain.IMAGE + '\nContainerName=' + chain.TARGET +
            '\nNetwork=none\nPull=never\nVolume=' + chain.TARGETVOL + ':/var/lib/postgresql/data\n'
            'Environment=POSTGRES_USER=postgres\nEnvironment=POSTGRES_DB=omnigent\n'
            'Environment=POSTGRES_HOST_AUTH_METHOD=trust\nLogDriver=none\n'
            'PodmanArgs=--memory=128m --pids-limit=96\n' + common),
        files[1]: ('[Unit]\nRequires=' + units[0] + '\nAfter=' + units[0] + '\n[Container]\n'
            'Image=sha256:' + chain.APP_IMAGE + '\nContainerName=' + chain.TARGET_APP +
            '\nNetwork=container:' + chain.TARGET + '\nPull=never\nLogDriver=none\n'
            'Volume=' + chain.SERVERVOL + ':/data\n'
            'Secret=' + chain.TARGET_SECRET + ',type=env,target=OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD\n'
            'Environment=DATABASE_URL=postgresql://postgres@127.0.0.1:5432/omnigent\n'
            'Environment=HOST=127.0.0.1\nEnvironment=PORT=8000\n'
            'Environment=ARTIFACT_DIR=/data/artifacts\nEnvironment=OMNIGENT_AUTH_ENABLED=1\n'
            'Environment=OMNIGENT_AUTH_PROVIDER=accounts\nEnvironment=OMNIGENT_PUBLIC_SHARING=0\n'
            'Environment=OMNIGENT_ADMIN_CREDENTIALS_PATH=/data/admin-credentials\n'
            'Environment=OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=target-admin\n'
            'PodmanArgs=--memory=768m --cpus=1 --pids-limit=256 --cap-drop=ALL --security-opt=no-new-privileges\n' + common +
            "ExecStartPre=/usr/bin/timeout 65 /bin/sh -c 'until /usr/bin/podman exec " + chain.TARGET +
            " pg_isready -q -h 127.0.0.1 -U postgres; do sleep 1; done'\n"),
        files[2]: ('[Container]\nImage=sha256:' + chain.IMAGE + '\nContainerName=' + runner +
            '\nNetwork=none\nPull=never\nLogDriver=none\nVolume=' + chain.PIVOL + ':/data/pi-agent\n'
            'Exec=infinity\nPodmanArgs=--entrypoint=/bin/sleep --image-volume=ignore --memory=32m --pids-limit=32\n' + common),
    }
    raw = {'schema': 1, 'id': 'omnigent', 'name': 'Synthetic Omnigent installer',
           'owner': 'appowner', 'adapter': 'quadlet-postgres', 'quadlet': {'files': files},
           'units': units, 'writer_units': units,
           'volumes': [{'name': name} for name in (chain.TARGETVOL, chain.SERVERVOL, chain.PIVOL)],
           'secrets': [{'name': chain.TARGET_SECRET}],
           'health': [{'type': 'http', 'url': 'http://127.0.0.1:8000/health', 'timeout_seconds': 120}]}
    return raw, quadlets, runner


def check(condition, code):
    if not condition:
        raise RuntimeError(code)


def arm_once(runner, marker, state):
    if state['enabled'] and state['count'] == 0:
        runner.write_file(marker, b'fail once\n', 0o600)
        state['count'] += 1


def validate_runtime(runner, runner_container):
    expected = {
        chain.TARGET: (chain.IMAGE, chain.TARGETVOL, '/var/lib/postgresql/data', 128),
        chain.TARGET_APP: (chain.APP_IMAGE, chain.SERVERVOL, '/data', 768),
        runner_container: (chain.IMAGE, chain.PIVOL, '/data/pi-agent', 32),
    }
    inspections = {name: json.loads(runner.podman('container', 'inspect', name).stdout)[0]
                   for name in expected}
    for name, (image, volume, target, memory) in expected.items():
        item = inspections[name]
        host = item.get('HostConfig') or {}
        network = host.get('NetworkMode')
        valid_network = network == 'none'
        if name == chain.TARGET_APP:
            valid_network = network in ('container:' + chain.TARGET,
                                        'container:' + inspections[chain.TARGET]['Id'])
        check(item.get('Name', '').lstrip('/') == name and
              item.get('Image', '').removeprefix('sha256:') == image, 'runtime_identity_mismatch')
        check(valid_network and not host.get('PortBindings'), 'runtime_network_mismatch')
        check(host.get('Memory') == memory * 1024 * 1024, 'runtime_memory_mismatch')
        mounts = item.get('Mounts') or []
        check(len(mounts) == 1 and mounts[0].get('Type') == 'volume' and
              mounts[0].get('Name') == volume and mounts[0].get('Destination') == target,
              'runtime_mount_mismatch')


def install_and_rollback(*, converted, source_cookie, source_token, source_password,
                         target_password, marker_id, marker_title, api, containers):
    device = DeviceOwner()
    r = device.runner
    check(device.runtime_ready(), 'device_user_bus_missing')
    raw, quadlets, runner_container = specification()
    units = raw['units']
    check(set(converted['volumes']) == {v['name'] for v in raw['volumes']}, 'candidate_volume_mismatch')
    # Separate persistent work: keep encrypted safety copies and keys on failure.
    root = Path(tempfile.mkdtemp(prefix='woowbk-omni-install-'))
    os.chmod(root, 0o700)
    paths = Paths(base=root / 'engine')
    app = catalog.validate_entry(raw, paths=paths, user_lookup=device.lookup)
    created_files, created_dirs = [], []
    success = False
    armed = {'enabled': False, 'count': 0}
    marker = '.config/' + chain.PREFIX + '-fail-once'
    dropdir = '.config/systemd/user/' + units[1] + '.d'
    dropfile = dropdir + '/woowbk-inject.conf'
    lockdir = '.config/woowbk-omnigent-installer-slot.lock'
    locked = False

    def ready():
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if r.podman('exec', chain.TARGET_APP, 'curl', '-fsS', '-o', '/dev/null',
                        'http://127.0.0.1:8000/health', check=False, timeout=10).returncode == 0:
                return
            time.sleep(2)
        raise RuntimeError('installed_app_not_ready')

    def http_get(url, timeout, **kwargs):
        check(url == raw['health'][0]['url'], 'unexpected_health_url')
        result = r.podman('exec', chain.TARGET_APP, 'curl', '-sS', '-o', '/dev/null',
                          '-w', '%{http_code}', url, check=False, timeout=10, max_output=4096)
        return (int(result.stdout) if result.returncode == 0 else 503), b''

    def adapter_factory(app_, **kwargs):
        original = kwargs.get('imported_hook')
        def imported():
            if original:
                original()
            arm_once(r, marker, armed)
        kwargs['imported_hook'] = imported
        return QuadletPostgresAdapter(app_, r, http_get=http_get,
            runtime_ready=device.runtime_ready, statvfs=device.statvfs, **kwargs)

    deps = flows.Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
        load_catalog=lambda: catalog.Catalog({'omnigent': app}), adapter_factory=adapter_factory,
        host_info=lambda: {'hostname': 'synthetic-dev-d', 'machine_id_sha256': '',
                          'arch': 'x86_64', 'os': 'isolated lab', 'podman': 'lab'},
        encrypt_by_default=lambda: True, audit=lambda line: None)

    def context():
        return flows.FlowContext(paths, 'j' + util.compact_utc() + '-' + secrets.token_hex(4), deps, Reporter())

    def restore(backup_id):
        return flows.run_restore(context(), {'backup_id': backup_id, 'apps': ['omnigent']})

    def sql(statement):
        return r.podman('exec', '-i', chain.TARGET, 'psql', '-X', '-A', '-t', '-v',
                       'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'omnigent', '-f', '-',
                       input=statement.encode()).stdout.strip()

    def verify_app():
        ready()
        check(chain.cookie_from_container(r, chain.TARGET_APP) == source_cookie, 'installed_cookie_mismatch')
        response = api(chain.TARGET_APP, {'method': 'GET', 'path': '/v1/sessions/' + marker_id,
                                        'body': None, 'token': source_token})
        chain.require_session_marker(response, marker_title, marker_id)
        check(r.podman('exec', runner_container, 'cat', '/data/pi-agent/auth.json').stdout
              == b'synthetic-pi', 'pi_auth_mismatch')
        observed = []
        chain.login_registered(chain.TARGET_APP, 'source-admin', source_password, 'installed_source', observed)
        chain.login_registered(chain.TARGET_APP, 'target-admin', target_password, 'installed_target', observed)
        check(len(observed) == 4, 'installed_login_coverage')
        validate_runtime(r, runner_container)
        for unit in units:
            check(r.systemctl('is-active', unit, check=False).stdout.strip() == b'active', 'writer_not_active')
            state = r.systemctl('show', unit, '-p', 'LoadState', '--value').stdout.strip()
            check(state == b'loaded', 'writer_still_masked')

    def verify_safety(backup_id):
        check(bool(backup_id), 'missing_safety_backup')
        meta = deps.storage.get(backup_id)
        check(meta['type'] == 'safety' and meta['encrypted'], 'safety_not_encrypted')
        dest = root / ('verify-' + secrets.token_hex(4))
        dest.mkdir(mode=0o700)
        archive.extract_archive(Path(deps.storage.archive_path(backup_id)), deps.keys.identities(), dest,
                                apps=['omnigent'])
        shutil.rmtree(dest)

    try:
        r.run(['/usr/bin/mkdir', '--', r.home + '/' + lockdir])
        locked = True
        # All paths must be absent before writing anything. Never overwrite an old fixture.
        pending = ['.config/containers/systemd/' + name for name in quadlets] + [dropdir, marker]
        check(all(v['type'] == 'missing' for v in r.stat_files(pending).values()), 'unit_path_collision')
        check(r.podman('container', 'exists', runner_container, check=False).returncode == 1,
              'runner_name_collision')
        for unit in units:
            check(r.systemctl('show', unit, '-p', 'LoadState', '--value', check=False).stdout.strip()
                  == b'not-found', 'unit_name_collision')
        for name, value in quadlets.items():
            rel = '.config/containers/systemd/' + name
            r.write_file(rel, value.encode(), 0o600)
            created_files.append(rel)
        r.run(['/usr/bin/mkdir', '--', r.home + '/' + dropdir])
        created_dirs.append(dropdir)
        injection = ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + marker +
                     '; then rm -f %h/' + marker + '; exit 1; fi\'\n')
        r.write_file(dropfile, injection.encode(), 0o600)
        created_files.append(dropfile)
        r.systemctl('daemon-reload')
        # Transfer only the just-created target PG container to its synthetic unit.
        check(chain.TARGET in containers, 'target_not_owned_by_chain')
        r.podman('stop', '--time', '30', chain.TARGET)
        r.podman('rm', chain.TARGET)
        r.systemctl('start', '--', *units, timeout=240)
        ready()
        validate_runtime(r, runner_container)
        deps.storage.ensure_layout()
        key, _ = deps.keys.ensure_device_key()
        with (root / 'job.lock').open('wb') as job_lock:
            fcntl.flock(job_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            ctx = context()
            staging = Path(deps.storage.staging_dir(ctx.job_id))
            app_dir = staging / 'apps' / app.id
            app_dir.mkdir(mode=0o700, parents=True)
            manifest, entries = ctx.adapter(app).import_manifest(app_dir, volumes=converted['volumes'])
            packaged = flows._package(ctx, [app], staging, include_images=False,
                note='Synthetic Omnigent HA candidate', backup_type='manual', key=key,
                phases=False, manifest_apps=[manifest], entries=entries, downtime=0)
            check(packaged['encrypted'], 'candidate_not_encrypted')
            backup_id = packaged['backup_id']
            result = restore(backup_id)
            check(result['changed'] and not result['rolled_back'], 'candidate_install_failed')
            verify_safety(result['safety_backup_id'])
            verify_app()
            chain.event('adapter_candidate_installed', real_adapter=True, real_archive_encryption=True,
                        source_session=True, both_logins=True, safety_decrypted=True)
            # Distinguishable pre-failure state must survive the automatic rollback.
            sql("CREATE TABLE public.woowbk_rollback_marker(value text); INSERT INTO public.woowbk_rollback_marker VALUES ('before-failure');")
            r.podman('exec', '-i', chain.TARGET_APP, 'sh', '-c',
                     'cat > /data/woowbk-rollback-marker; chmod 640 /data/woowbk-rollback-marker',
                     input=b'before-failure\n')
            r.podman('exec', '-i', runner_container, 'sh', '-c',
                     'cat > /data/pi-agent/woowbk-rollback-marker; chmod 600 /data/pi-agent/woowbk-rollback-marker',
                     input=b'pi-before-failure\n')
            metadata = [(chain.TARGET_APP, '/data/woowbk-rollback-marker'),
                        (runner_container, '/data/pi-agent/woowbk-rollback-marker')]
            before_metadata = [r.podman('exec', name, 'stat', '-c', '%a:%u:%g', path).stdout
                               for name, path in metadata]
            secret_before = r.podman('secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', chain.TARGET_SECRET).stdout
            chain.register_private(target_password)
            armed['enabled'] = True
            try:
                restore(backup_id)
            except flows.RolledBack as outcome:
                check(outcome.result['rolled_back'] and armed['count'] == 1, 'automatic_rollback_missing')
                verify_safety(outcome.result['safety_backup_id'])
            else:
                raise RuntimeError('one_shot_failure_not_observed')
            check(r.stat_files([marker])[marker]['type'] == 'missing', 'failure_marker_not_consumed')
            verify_app()
            check(sql('SELECT value FROM public.woowbk_rollback_marker;') == b'before-failure', 'rollback_db_marker')
            check(r.podman('exec', chain.TARGET_APP, 'cat', '/data/woowbk-rollback-marker').stdout
                  == b'before-failure\n', 'rollback_server_marker')
            check(r.podman('exec', runner_container, 'cat', '/data/pi-agent/woowbk-rollback-marker').stdout
                  == b'pi-before-failure\n', 'rollback_pi_marker')
            check(r.podman('secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', chain.TARGET_SECRET).stdout == secret_before,
                  'rollback_secret_mismatch')
            check([r.podman('exec', name, 'stat', '-c', '%a:%u:%g', path).stdout
                   for name, path in metadata] == before_metadata, 'rollback_marker_metadata')
            chain.event('adapter_automatic_rollback', one_shot_systemd_failure=True, real_flow=True,
                        db_server_pi_markers=True, source_cookie_and_token=True, both_logins=True,
                        safety_decrypted=True, marker_mode_uid_gid=True, synthetic_runner=True)
            success = True
    finally:
        failures = []
        if created_files:
            for unit in reversed(units):
                try:
                    r.systemctl('stop', '--', unit, check=False)
                    r.systemctl('unmask', '--', unit)
                    r.systemctl('reset-failed', unit, check=False)
                except Exception:
                    failures.append('unit')
            for name in (runner_container, chain.TARGET_APP, chain.TARGET):
                try:
                    if r.podman('container', 'exists', name, check=False).returncode == 0:
                        r.podman('rm', '--force', '--time', '10', name)
                    check(r.podman('container', 'exists', name, check=False).returncode == 1, 'container_cleanup')
                except Exception:
                    failures.append('container')
        for rel in reversed(created_files):
            try:
                r.remove_file(rel)
            except Exception:
                failures.append('file')
        if armed['count']:
            try:
                r.remove_file(marker)
            except Exception:
                failures.append('marker')
        for rel in reversed(created_dirs):
            try:
                r.run(['/usr/bin/rmdir', '--', r.home + '/' + rel])
            except Exception:
                failures.append('directory')
        if created_files:
            try:
                r.systemctl('daemon-reload')
            except Exception:
                failures.append('reload')
        if locked:
            try:
                r.run(['/usr/bin/rmdir', '--', r.home + '/' + lockdir])
            except Exception:
                failures.append('lock')
        if success and not failures:
            shutil.rmtree(root)
        else:
            chain.event('installer_private_evidence_retained', path=str(root))
        chain.event('installer_cleanup', complete=not failures)
        check(not failures, 'installer_cleanup_incomplete')


def inventory(runner):
    return tuple(tuple(sorted(runner.podman(*args, timeout=30, max_output=1024 * 1024).stdout.splitlines()))
                 for args in (('ps', '-a', '--format', '{{.Names}}'),
                              ('volume', 'ls', '--format', '{{.Name}}'),
                              ('secret', 'ls', '--format', '{{.Name}}')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--outer-isolation-confirmed', action='store_true')
    args = parser.parse_args()
    if not args.run or not args.outer_isolation_confirmed:
        parser.error('both flags required after exclusive dev-d slot allocation')
    for tool in ('age', 'age-keygen', 'zstd'):
        check(util.find_tool(tool) is not None, 'missing_host_archive_tool')
    chain.isolated_preflight()
    runner = chain.Runner()
    before = inventory(runner)
    try:
        chain.main(installer=install_and_rollback)
    finally:
        unchanged = inventory(runner) == before
        chain.event('installer_inventory', containers_volumes_secrets_unchanged=unchanged)
        check(unchanged, 'synthetic_inventory_changed')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Exception messages and command stderr may contain synthetic secrets.
        chain.event('installer_failed', error_type=type(error).__name__,
                    frames=[{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                            for frame in traceback.extract_tb(error.__traceback__)])
        sys.exit(1)
