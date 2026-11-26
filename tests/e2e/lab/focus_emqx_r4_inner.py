#!/usr/bin/python3
"""Runs only as UID1031 inside the fresh outer fixture. No installer/upgrader/helper deployment or foreign data."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import focus_emqx_r4_artifact as artifact
import focus_emqx_r4_fixtures as fx
from woowbackup import ha_emqx as emqx

HOME = Path('/home/appowner')


def render_unit(name, body):
    """Only fixture resource/image/port rendering; exact package smoke remains unchanged."""
    if name == 'emqx.container':
        for key, port in [('MQTT',1883),('MQTTS',8883),('WS',8083),('WSS',8084),('DASHBOARD',18083)]:
            body = body.replace('@@EMQX_PUBLISH_' + key + '@@', '127.0.0.1:' + str(port))
        body = '\n'.join('Image=' + artifact.IMAGES['broker'] if line.startswith('Image=') else line for line in body.splitlines()) + '\n'
        body = body.replace('[Service]', 'Environment="ERL_AFLAGS=+S 1:1"\n'
            'Volume=%h/r4-fixture:/fixture:ro\n'
            'PodmanArgs=--pull=never --image-volume=ignore --memory=768m --memory-swap=768m --cpus=0.5 --pids-limit=256 --cap-drop=ALL\n[Service]')
    elif name == 'emqx-entrance.container':
        body = '\n'.join('Image=' + artifact.IMAGES['entrance'] if line.startswith('Image=') else line for line in body.splitlines()) + '\n'
        body = body.replace('[Service]', 'PodmanArgs=--pull=never --image-volume=ignore --memory=128m --memory-swap=128m --cpus=0.25 --pids-limit=128 --cap-drop=ALL\n[Service]')
    elif name not in ('emqx-data.volume', 'emqx-log.volume', 'emqx.network'):
        raise ValueError('only_reviewed_fixture_units')
    if '@@' in body: raise ValueError('unrendered_template')
    return body


def main():
    if os.getuid() != 1031 or Path.home() != HOME: raise ValueError('fresh_fixture_owner_required')
    context = json.loads((ROOT / 'context.json').read_text())
    record = artifact.verify_candidate(ROOT / 'candidate.tar', ROOT / 'candidate.json', case=context['case'],
        source_commit=context['artifact_source_commit'], data_sha=context['data_sha256'], manifest_sha=context['manifest_sha256'])['record']
    def run(*args, data=None, timeout=120, good=True):
        result = subprocess.run(list(args), input=data, capture_output=True, timeout=timeout)
        if len(result.stdout) + len(result.stderr) > 8 * 1024**2: raise ValueError('inner_output_budget')
        if good and result.returncode: raise ValueError('inner_command_failed')
        return result
    def pod(*args, **kw): return run('/usr/bin/podman', *args, **kw)
    if pod('info', '--format', '{{.Host.Security.Rootless}}').stdout.strip() != b'true': raise ValueError('rootless_required')
    for args in [('ps', '-a', '--format', '{{.ID}}'), ('volume', 'ls', '--format', '{{.Name}}'),
                 ('image', 'ls', '-q')]:
        if pod(*args).stdout.strip(): raise ValueError('fresh_empty_inner_store_required')
    for role, identity in artifact.IMAGES.items():
        artifact.verify_oci(ROOT / (role + '.oci.tar'), identity)
        pod('load', '--input', str(ROOT / (role + '.oci.tar')), timeout=300)
        actual = pod('image', 'inspect', identity, '--format', '{{.Id}}').stdout.decode().strip().removeprefix('sha256:')
        if actual != identity[7:]: raise ValueError('loaded_config_mismatch')
    # Refuse if save/load did not preserve the literal reference used by the unchanged package. No pin alias shortcut.
    pod('image', 'exists', artifact.CLIENT_REF)
    cfg = HOME / '.config/emqx'; units = HOME / '.config/containers/systemd'
    if cfg.exists() or units.exists(): raise ValueError('fresh_package_paths_required')
    cfg.mkdir(parents=True, mode=0o700); units.mkdir(parents=True, mode=0o700)
    package = HOME / 'r4-package'; package.mkdir(mode=0o700)
    for relative in context['package_files']:
        source = ROOT / 'package' / relative
        if hashlib.sha256(source.read_bytes()).hexdigest() != context['package_files'][relative]:
            raise ValueError('package_source_changed')
        dest = package / relative; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, dest)
    for name in ('base.hocon', 'acl.conf', 'entrance.conf'):
        shutil.copyfile(package / 'config' / name, cfg / name)
    fixture = HOME / 'r4-fixture'; fixture.mkdir(mode=0o755)
    for name, data in fx.files().items():
        path = fixture / name; path.write_bytes(data); path.chmod(0o644)
    env = ('EMQX_LOG__CONSOLE__LEVEL=error\nWOOW_EMQX_BIND=127.0.0.1\nWOOW_EMQX_MQTT_USER=r4_target\n'
           'WOOW_EMQX_NGROK=0\nWOOW_EMQX_NGROK_REMOTE_ADDR=\n' +
           ''.join('WOOW_EMQX_PORT_' + key + '=' + str(value) + '\n' for key, value in
                   [('MQTT',1883),('MQTTS',8883),('WS',8083),('WSS',8084),('DASHBOARD',18083)]))
    (cfg / 'emqx.env').write_text(env); (cfg / 'emqx.env').chmod(0o600)
    synthetic = {'woow-emqx-dashboard-password': b'r4-owned-target-admin', 'woow-emqx-node-cookie': b'r4-owned-package-cookie',
                 'woow-emqx-mqtt-password': b'r4-owned-target-password',
                 'woow-emqx-mqtt-bootstrap': fx.files()['target.csv']}
    for name, value in synthetic.items(): pod('secret', 'create', name, '-', data=value)
    pod('volume', 'create', '--label', 'io.woowtech.r4.fixture=' + context['device'], 'woow_emqx_data')
    with (ROOT / 'candidate.tar').open('rb') as stream:
        result = subprocess.run(['/usr/bin/podman','volume','import','woow_emqx_data','-'], stdin=stream,
                                capture_output=True, timeout=180)
    if result.returncode: raise ValueError('owned_data_import_failed')
    mount = pod('volume', 'inspect', '--format', '{{.Mountpoint}}', 'woow_emqx_data').stdout.decode().strip()
    if not mount.endswith('/volumes/woow_emqx_data/_data'): raise ValueError('owned_data_mountpoint')
    pod('unshare', 'chown', '--no-dereference', '1000:1000', '--', mount)
    pod('unshare', 'chmod', '0755', '--', mount)
    for name in ('emqx-data.volume', 'emqx-log.volume', 'emqx.network', 'emqx.container', 'emqx-entrance.container'):
        (units / name).write_text(render_unit(name, (package / 'quadlet' / name).read_text()))
    run('systemctl', '--user', 'daemon-reload')
    # A real generator/load failure is fatal; no stubbed service state.
    for service in ('emqx.service', 'emqx-entrance.service'):
        if run('systemctl', '--user', 'show', service, '--property=LoadState', '--value').stdout.strip() != b'loaded':
            raise ValueError('quadlet_not_loaded')
    run('systemctl', '--user', 'start', 'emqx.service', 'emqx-entrance.service', timeout=480)
    class LiveRunner:
        home='/home/appowner'
        def podman(self, *args, **kwargs):
            # Product postcheck can only exec/inspect this new fixture's actual broker.
            if args[0] not in ('exec', 'container') or 'woow-emqx' not in args: raise ValueError('postcheck_target')
            return pod(*args, timeout=min(kwargs.get('timeout',120),120), good=kwargs.get('check',True))
    runner = LiveRunner()
    def read(command): return runner.podman('exec', 'woow-emqx', *command, check=False)
    emqx.wait_live_ready(read, running=lambda: pod('container','inspect','--format','{{.State.Running}}','woow-emqx').stdout.strip()==b'true')
    actual = emqx.readback_record(emqx.boot_form(read), emqx.table_receipts(read)); artifact.check_record(actual)
    if emqx.compare_readback(record, actual): raise ValueError('all_candidate_roots_and_admin_receipts_must_match')
    quadlet = (units / 'emqx.container').read_bytes()
    quadlets={p.name:p.read_bytes() for p in units.iterdir()}
    adapter = SimpleNamespace(runner=runner, read_quadlets=lambda: quadlets)
    app = SimpleNamespace(id='emqx',volumes=[{'name':'woow_emqx_data'},{'name':'woow_emqx_log'}],postgres=None,data_dirs=[])
    messages=[]; emqx.verify_restored(adapter,app,record,log=messages.append)
    if len(messages)!=1 or '核對一致' not in messages[0]: raise ValueError('postcheck_not_complete')
    # Resource wrapper adds limits to real clients. Every check still runs the package's unchanged source.
    binpath=HOME/'r4-client-bin'; binpath.mkdir(mode=0o700)
    shutil.copyfile(ROOT/'focus_emqx_r4_client_guard.py',binpath/'podman'); (binpath/'podman').chmod(0o700)
    scratch=HOME/'r4-smoke-tmp'; scratch.mkdir(mode=0o700)
    smoke_env=dict(os.environ,PATH=str(binpath)+':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',TMPDIR=str(scratch))
    smoke=subprocess.run(['bash',str(package/'tests/smoke.sh')],env=smoke_env,capture_output=True,timeout=600)
    # Only IDs/statuses leave this fresh fixture. No raw body/log/env/secret/error output.
    from focus_emqx_r4_package import smoke_status
    rows=smoke_status(smoke.stdout)
    return {'capture_completed':True,'smoke_ok':smoke.returncode==0,'smoke_exit_code':smoke.returncode,'checks':rows,
            'full_candidate_postcheck':True,'installer_or_upgrader_executed':False}


if __name__=='__main__':
    try: result=main()
    except Exception as error: result={'capture_completed':False,'reason':type(error).__name__}
    print(json.dumps(result,sort_keys=True)); raise SystemExit(0 if result.get('capture_completed') else 1)
