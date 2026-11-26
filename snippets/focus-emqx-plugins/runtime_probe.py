#!/usr/bin/env python3
"""Runs only as appowner INSIDE isolated dev-d after the coordinator's fixture lease.

The payload directory and TempObjects job are the entire mutation scope. No systemd/catalog/package/HA-original calls.
"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from woowbackup import ha_emqx as emqx, haissues, tempctr
from woowbackup.errors import BackupError

IMAGE = 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'
AVAILABLE = 'woow_e44_fixture-1.0.0'
MISSING = 'woow_e44_missing-1.0.0'
JOB = time.strftime('j%Y%m%dT%H%M%SZ-', time.gmtime()) + secrets.token_hex(4)
CHECKS = []
STAGE = 'preflight'
LIMIT = 256 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def check(name, condition=True):
    CHECKS.append({'name': name, 'ok': bool(condition)})
    if not condition:
        raise RuntimeError('fixed_check_failed')


def alarm(_signum, _frame):
    raise TimeoutError('fixture_wall_budget')


signal.signal(signal.SIGALRM, alarm)
signal.alarm(840)


class Runner:
    owner, uid, home = 'appowner', os.getuid(), str(Path.home())

    def podman(self, *args, **kwargs):
        args = list(args)
        if args[:1] == ['run']:
            # Extra fixture restrictions; all product-selected image/mount/config flags remain in place.
            memory = args[args.index('--memory') + 1]
            args[1:1] = ['--image-volume=ignore', '--cap-drop=ALL', '--memory-swap=' + memory]
        writes = args[:1] in (['run'], ['exec'], ['start']) or args[:2] in (['volume', 'create'], ['volume', 'import'])
        if writes and shutil.disk_usage(ROOT).free < 13 * 1024**3:
            raise RuntimeError('disk_floor')
        incoming = kwargs.get('input')
        stream = hasattr(incoming, 'read')
        output = kwargs.get('stdout')
        proc = subprocess.run(['podman', '--runtime=crun', *args], input=None if stream else incoming,
                              stdin=incoming if stream else None, stdout=output if output is not None else subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=min(kwargs.get('timeout', 120), 180))
        if len(proc.stdout or b'') > (kwargs.get('max_output') or 8 * 1024 * 1024):
            raise RuntimeError('fixed_output_budget')
        if output is not None and output.tell() > LIMIT:
            raise RuntimeError('fixed_file_budget')
        if proc.returncode and kwargs.get('check', True):
            # Keep diagnostic output only in this private invocation directory, never in public JSON.
            with (ROOT / 'private.log').open('ab') as log:
                log.write((proc.stdout or b'') + proc.stderr)
            raise RuntimeError('nested_command_failed')
        return proc

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)


class Budget:
    used = 0
    def budget(self):
        return LIMIT - self.used
    def check(self, size):
        if not 0 <= size <= self.budget():
            raise RuntimeError('staging_budget')
    def wrote(self, size):
        self.check(size)
        self.used += size


RUNNER = Runner()


def inventory():
    # Fixed fields only. Equality is checked in memory; public evidence contains counts/hashes, not application names.
    containers = RUNNER.podman('ps', '-a', '--format', '{{.ID}} {{.Status}}').stdout.splitlines()
    volumes = RUNNER.podman('volume', 'ls', '--format', '{{.Name}}').stdout.splitlines()
    images = RUNNER.podman('image', 'ls', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}').stdout.splitlines()
    installed = Path('/usr/local/libexec/woowtech-cockpit-backup/woowbackup')
    sources = {name: hashlib.sha256((installed / name).read_bytes()).hexdigest() if (installed / name).is_file() else None
               for name in ('ha_emqx.py', 'ha_emqx_settings.py')}
    # Status strings contain elapsed times; only state words matter for stability comparison.
    containers = [b' '.join(row.split()[:2]) for row in containers]
    return [sorted(containers), sorted(volumes), sorted(images), sources]


def resources():
    maximum = int(Path('/sys/fs/cgroup/memory.max').read_text())
    current = int(Path('/sys/fs/cgroup/memory.current').read_text())
    check('device_headroom_1900MiB', maximum - current >= 1900 * 1024 * 1024)
    check('disk_reserve_13GiB_plus_256MiB', shutil.disk_usage(ROOT).free >= 13 * 1024**3 + LIMIT)


def add(tar, name, data, uid, gid, directory=False):
    item = tarfile.TarInfo(name)
    item.uid, item.gid, item.mode = uid, gid, 0o755 if directory else 0o600
    if directory:
        item.type = tarfile.DIRTYPE
    else:
        item.size = len(data)
    tar.addfile(item, None if directory else io.BytesIO(data))


def fixture_files(tmp):
    global STAGE
    STAGE = 'compile_reviewed_fixture'
    tmp.memory = '256m'
    expression = ('{ok,woow_e44_fixture,B}=compile:file("/input/woow_e44_fixture.erl",[binary,return_errors]),'
                  'io:format("WOOWBEAM:~s:END",[base64:encode(B)]),halt().')
    result = tmp.run('compile', IMAGE, ['+S', '1:1', '-noshell', '-eval', expression],
                     entrypoint='/opt/emqx/erts-14.2.5.11/bin/erl', user='0', read_only_root=True,
                     volumes=[(str(ROOT), '/input', 'ro')], max_output=1024 * 1024)
    tmp.memory = '768m'
    body = result.stdout
    check('fixture_compiled_in_exact_image', body.startswith(b'WOOWBEAM:') and body.endswith(b':END'))
    beam = base64.b64decode(body[9:-4], validate=True)
    plugin = ROOT / 'plugins' / AVAILABLE
    ebin = plugin / AVAILABLE / 'ebin'
    ebin.mkdir(parents=True, mode=0o755)
    (ebin / 'woow_e44_fixture.beam').write_bytes(beam)
    (ebin / 'woow_e44_fixture.app').write_text('{application,woow_e44_fixture,[{vsn,"1.0.0"},'
        '{description,"E44 disposable fixture"},{modules,[woow_e44_fixture]},'
        '{applications,[kernel,stdlib]},{mod,{woow_e44_fixture,[]}}]}.\n')
    (plugin / 'release.json').write_text(json.dumps({'name': 'woow_e44_fixture', 'rel_vsn': '1.0.0',
        'rel_apps': [AVAILABLE], 'description': 'Reviewed E44 disposable OTP plugin'}))
    config = ROOT / 'device-plugin.hocon'
    config.write_text('marker = "device-owned-e44-configuration"\n')
    for path in (ROOT / 'plugins').rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (ROOT / 'plugins').chmod(0o755)
    config.chmod(0o644)
    return [(str(ROOT / 'plugins'), '/opt/emqx/plugins', 'ro'),
            (str(config), '/opt/emqx/data/plugins/woow_e44_fixture/config.hocon', 'ro')]


def ping(tmp, role):
    body = emqx.evaluate(tmp, role, 'io:format("WOOWPING:~p:END",[woow_e44_fixture:ping()]).')
    return 'WOOWPING:e44_fixture_alive:END' in body


def remove_candidate(tmp, staging):
    tmp.stop('emqx-new', timeout=60)
    tmp.remove('emqx-new')
    for role in ('emqx-new', 'emqx-new-log', 'emqx-in'):
        check('owned_first_candidate_removed_' + role, tmp.remove_volume(role))
    (staging / 'emqx-target-config-snapshot.tar').unlink()


def exercise(tmp, work, app, target, export, ids, readings, staging, acknowledged):
    notes = {}
    seeded, counts, _, _ = emqx.candidate_from_target(work, app, tmp, target, staging, export, ids,
                                                     readings=readings, notes=notes)
    check('vendor_row_counts_match', not emqx.check_counts(readings['counts'], seeded, counts))
    sink = haissues.Sink('emqx', acknowledged=acknowledged)
    emqx.candidate_lines(sink, target, readings, notes, None)
    return sink, notes


def verify(tmp, app, record):
    quadlet = ('[Container]\nImage=' + IMAGE + '\nContainerName=' + tmp.name('emqx-new') + '\n' +
               'Volume=' + tmp.name('emqx-new') + ':/opt/emqx/data\n' +
               'Volume=' + tmp.name('emqx-new-log') + ':/opt/emqx/log\n').encode()
    adapter = SimpleNamespace(runner=RUNNER, read_quadlets=lambda: {'fixture.container': quadlet})
    post_app = SimpleNamespace(id='emqx', volumes=[{'name': tmp.name('emqx-new')}, {'name': tmp.name('emqx-new-log')}],
                               postgres=None, data_dirs=[])
    messages = []
    emqx.verify_restored(adapter, post_app, record, log=messages.append)
    check('postconversion_vendor_check_not_skipped', len(messages) == 1 and '核對一致' in messages[0])


def main():
    global STAGE
    check('appowner_only', os.getuid() == 1019 and Path.home() == Path('/home/appowner'))
    check('nested_rootless_store', RUNNER.podman('info', '--format', '{{.Host.Security.Rootless}}').stdout.strip() == b'true')
    check('exact_loaded_image', RUNNER.podman('image', 'inspect', IMAGE, '--format', '{{.Id}}').stdout.strip().decode()
          .removeprefix('sha256:') == IMAGE.removeprefix('sha256:'))
    resources()
    before = inventory()
    budget = Budget()
    staging = ROOT / 'staging'
    staging.mkdir()
    work = SimpleNamespace(runner=lambda _: RUNNER, guard=budget, abort=None, checkpoint=lambda: None, log=lambda _: None)
    app = SimpleNamespace(id='emqx')
    with tempctr.TempObjects(RUNNER, JOB, memory='768m', pids=256, cpus='0.5') as tmp:
        mounts = fixture_files(tmp)
        ids = tmp.user_ids('ids-emqx', IMAGE, 'emqx')
        for role in ('e44-device', 'e44-device-log', 'emqx-xfer'):
            tmp.volume(role)
        config = {'plugins': {'install_dir': 'plugins', 'states': [
            {'name_vsn': AVAILABLE, 'enable': True}, {'name_vsn': MISSING, 'enable': True}]}}
        def seed(out):
            with tarfile.open(fileobj=out, mode='w|') as archive:
                add(archive, '.', b'', *ids, directory=True)
                add(archive, 'configs', b'', *ids, directory=True)
                add(archive, 'configs/cluster.hocon', json.dumps(config).encode(), *ids)
        tmp.volume_import('e44-device', seed)
        tmp.volume_import('emqx-xfer', lambda out: emqx._folder_tar(out, 'out', *ids))
        env = {'EMQX_NODE__NAME': 'emqx@127.0.0.1', 'EMQX_DASHBOARD__DEFAULT_PASSWORD': 'public', 'ERL_AFLAGS': '+S 1:1'}
        STAGE = 'stable_persisted_device_boot'
        tmp.run('emqx-ha', IMAGE, [], detach=True, read_only_root=True, env=env,
                volumes=[(tmp.name('e44-device'), emqx.DATA_TARGET, None),
                         (tmp.name('e44-device-log'), emqx.LOG_TARGET, None),
                         (tmp.name('emqx-xfer'), '/work', None)] + mounts)
        emqx.wait_ready(tmp, 'emqx-ha', checkpoint=lambda: None)
        emqx.quiesce_system_ticker(tmp, 'emqx-ha')
        read_device = lambda command: tmp.exec('emqx-ha', command, timeout=120, max_output=emqx.MAX_HOCON, check=False)
        original = emqx.read_effective_config(read_device)
        boot = emqx.boot_form(read_device)
        check('stable_persisted_plugin_states', original['plugins']['states'] == boot['plugins']['states'] == config['plugins']['states'])
        check('genuine_available_plugin_responds_on_device', ping(tmp, 'emqx-ha'))
        facts = emqx.plugin_inventory(read_device, boot)
        check('available_plugin_has_material_running_and_configuration', facts[AVAILABLE]['binary'] and facts[AVAILABLE]['running']
              and facts[AVAILABLE]['data'] and facts[AVAILABLE]['config'] is not None)
        check('missing_enabled_plugin_has_no_material_or_running_app', not any(facts[MISSING][key] for key in ('binary', 'data', 'running')))
        readings = {'counts': emqx.parse_counts(emqx.evaluate(tmp, 'emqx-ha', emqx.COUNT_EXPR)),
                    'authn': emqx.parse_authn(emqx.evaluate(tmp, 'emqx-ha', emqx.AUTHN_EXPR)),
                    'authz': emqx.parse_authz(emqx.evaluate(tmp, 'emqx-ha', emqx.AUTHZ_EXPR)),
                    'strict': emqx.parse_strict(emqx.evaluate(tmp, 'emqx-ha', emqx.STRICT_EXPR))}
        check('nonempty_administrator_table', readings['counts'].get('emqx_admin', 0) > 0)
        roots = [name for name in emqx.DATA_ROOTS if name in original]
        out = emqx.ctl(tmp, 'emqx-ha', ['data', 'export', '--root-keys', ','.join(roots),
                         '--table-sets', ','.join(emqx.TABLE_SETS), '--dir', '/work/out'], timeout=180).stdout
        matched = emqx.EXPORT_RE.search(out or b'')
        check('real_vendor_export', matched is not None)
        export = emqx.take_export(work, tmp, matched.group(1).decode(), staging)
        target = SimpleNamespace(container=tmp.name('emqx-ha'), data_volume=tmp.name('e44-device'),
            log_volume=tmp.name('e44-device-log'), image=IMAGE, env=env, files=mounts, secrets=[], publish=[],
            other_publish=[], tunnels=[])
        STAGE = 'native_check_and_no_ack_refusal'
        sink, check_notes = exercise(tmp, work, app, target, export, ids, readings, staging, None)
        lines = [line for line in sink.found if line.id == 'emqx.plugin-records-remove']
        check('exact_enabled_missing_confirmation', len(lines) == 1 and lines[0].names == ('plugins.' + MISSING,))
        check('available_plugin_retained_in_first_candidate', ping(tmp, 'emqx-new'))
        try:
            sink = haissues.Sink('emqx', acknowledged=[])
            # Reuse the SAME notes from the completed check, exactly as the product's final issue boundary does.
            emqx.candidate_lines(sink, target, readings, check_notes, None)
        except BackupError as error:
            check('unacknowledged_conversion_refused', error.code == 'confirmation-required')
        else:
            check('unacknowledged_conversion_refused', False)
        check('device_states_unchanged_after_refusal', emqx.read_effective_config(read_device)['plugins'] == original['plugins'])
        remove_candidate(tmp, staging)
        STAGE = 'acknowledged_fresh_candidate'
        _, notes = exercise(tmp, work, app, target, export, ids, readings, staging, [lines[0].key('emqx')])
        check('acknowledged_candidate_cleaned_exact_record', notes['plugin_records']['enabled'] == ['plugins.' + MISSING])
        read_candidate = lambda command: tmp.exec('emqx-new', command, timeout=120, max_output=emqx.MAX_HOCON, check=False)
        final = emqx.read_effective_config(read_candidate)
        check('available_configuration_and_order_retained', final['plugins'] == dict(boot['plugins'], states=[boot['plugins']['states'][0]]))
        check('available_plugin_responds_before_restart', ping(tmp, 'emqx-new'))
        record = emqx.candidate_readback(tmp)
        check('administrator_receipts_recorded', emqx.tables_recorded(record) and record['tables']['emqx_admin'][0] > 0)
        STAGE = 'isolated_candidate_restart_and_postcheck'
        tmp.stop('emqx-new', timeout=60)
        RUNNER.podman('start', tmp.name('emqx-new'))
        emqx.wait_ready(tmp, 'emqx-new', checkpoint=lambda: None)
        emqx.quiesce_system_ticker(tmp, 'emqx-new')
        restarted = emqx.read_effective_config(read_candidate)
        check('cleaned_states_persist_after_restart', restarted['plugins']['states'] == final['plugins']['states'])
        check('genuine_plugin_responds_after_restart', ping(tmp, 'emqx-new'))
        after = emqx.candidate_readback(tmp)
        check('all_configuration_roots_and_admin_tables_match_after_restart', emqx.compare_readback(record, after) == [])
        verify(tmp, app, record)
        corrupt = copy.deepcopy(record)
        corrupt['tables']['emqx_admin'][0] += 1
        try:
            verify(tmp, app, corrupt)
        except BackupError as error:
            check('administrator_mismatch_still_refused', error.code == 'job-failed')
        else:
            check('administrator_mismatch_still_refused', False)
        check('disposable_source_device_never_changed', emqx.read_effective_config(read_device)['plugins'] == original['plugins'])
    STAGE = 'cleanup_and_baseline_independence'
    check('no_owned_resources_remain', not tmp.containers and not tmp.volumes and not tmp.networks)
    check('other_containers_volumes_images_and_installed_source_unchanged', inventory() == before)
    return {'ok': True, 'run_id': JOB, 'image': IMAGE, 'checks': CHECKS, 'source_scope': 'private-payload-only',
            'baseline_scope': 'existing-apps-never-selected', 'prior_original_emqx_full_flow': 'preserved-existing-evidence'}


if __name__ == '__main__':
    try:
        result = main()
    except Exception as error:
        result = {'ok': False, 'run_id': JOB, 'stage': STAGE, 'reason': type(error).__name__, 'checks': CHECKS,
                  'private_dir': str(ROOT)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['ok'] else 1)
