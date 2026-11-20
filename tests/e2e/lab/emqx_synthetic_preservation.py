"""Run INSIDE isolated dev-d as appowner. Synthetic credentials only; no live volumes.
Output is phase/status metadata, never captured broker output or credential material.
"""
import base64
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

IMAGE = '3f60addfad2b'
CLIENT = '93a0bdfcbd9b'
PREFIX = 'woowbk-emqx-synthetic-' + secrets.token_hex(4)
CONTAINER, VOLUME, SECRET = PREFIX, PREFIX + '-data', PREFIX + '-bootstrap'
results = []
created = []


def command(args, *, data=None, timeout=60, accept=False):
    result = subprocess.run(['podman', *args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode and not accept:
        raise RuntimeError('command_failed')
    return result


def ctl(*args):
    return command(['exec', CONTAINER, 'emqx', 'ctl', *args], timeout=120)


def config():
    expr = 'io:format("WOOWCFG:~s:END~n", [base64:encode(emqx_utils_json:encode(emqx:get_raw_config([])))]).'
    out = command(['exec', CONTAINER, 'emqx', 'eval', expr]).stdout
    if not out.startswith(b'WOOWCFG:'):
        raise RuntimeError('config_frame_failed')
    return json.loads(base64.b64decode(out[8:].split(b':END', 1)[0], validate=True))


def ready():
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        result = command(['exec', CONTAINER, 'emqx', 'ctl', 'status'], accept=True)
        if result.returncode == 0 and b'is started' in result.stdout:
            return
        time.sleep(2)
    raise RuntimeError('broker_not_ready')


def mqtt(password, topic):
    result = command(['run', '--rm', '--pull=never', '--network=container:' + CONTAINER,
                    '--entrypoint=mosquitto_pub', CLIENT, '-h', '127.0.0.1', '-p', '1883',
                    '-V', 'mqttv5', '-q', '1', '-r', '-t', topic, '-m', 'synthetic-marker',
                    '-u', 'lab', '-P', password, '-d'], accept=True)
    combined = result.stdout + result.stderr
    flags = {name: phrase in combined.lower() for name, phrase in {
        'not_authorized': b'not authorized', 'connection_refused': b'connection refused',
        'permission_denied': b'permission denied', 'missing_executable': b'executable file not found',
        'missing_file': b'no such file', 'puback': b'puback', 'connack': b'connack',
        'not_found': b'not found', 'entrypoint': b'entrypoint', 'error': b'error'}.items()}
    print(json.dumps({'stage': 'mqtt_transport', 'exit_code': result.returncode,
                      'reason_codes': [v.decode() for v in re.findall(rb'RC[:=]\s*(\d+)', combined)],
                      'flags': flags}), flush=True)
    return result


def receive_retained(password, topic):
    result = command(['run', '--rm', '--pull=never', '--network=container:' + CONTAINER,
                      '--entrypoint=mosquitto_sub', CLIENT, '-h', '127.0.0.1', '-p', '1883',
                      '-V', 'mqttv5', '-q', '1', '-t', topic, '-C', '1', '-W', '5',
                      '-u', 'lab', '-P', password])
    if result.stdout.strip() != b'synthetic-marker':
        raise RuntimeError('subscriber_payload_mismatch')


def denied_subscription(password):
    result = command(['run', '--rm', '--pull=never', '--network=container:' + CONTAINER,
                      '--entrypoint=mosquitto_sub', CLIENT, '-h', '127.0.0.1', '-p', '1883',
                      '-V', 'mqttv5', '-q', '1', '-t', 'outside/denied', '-E', '-W', '5', '-d',
                      '-u', 'lab', '-P', password], accept=True)
    output = result.stdout + result.stderr
    rejected = bool(re.search(rb'Subscribed[^\n]*:\s*135\b', output)) or b'Not authorized' in output
    print(json.dumps({'stage': 'mqtt_subscribe_transport', 'exit_code': result.returncode,
                      'suback_seen': b'SUBACK' in output, 'authorization_rejected': rejected}), flush=True)
    if b'SUBACK' not in output or not rejected:
        raise RuntimeError('subscription_denial_not_proven')


def record(stage):
    results.append({'stage': stage, 'result': 'pass'})
    print(json.dumps({'stage': stage, 'result': 'pass'}), flush=True)


phase = 'setup'
try:
    with tempfile.TemporaryDirectory(prefix=PREFIX + '-') as directory:
        root = Path(directory)
        os.chmod(root, 0o755)  # synthetic config only; secret is passed directly to Podman stdin
        password = secrets.token_urlsafe(24)
        base = root / 'base.hocon'
        base.write_text('''authentication = [{mechanism = password_based, backend = built_in_database,
password_hash_algorithm {name = sha256, salt_position = suffix},
bootstrap_file = "/opt/emqx/etc/lab-bootstrap.csv", bootstrap_type = plain}]
authorization {no_match = deny, deny_action = ignore,
sources = [{type = file, enable = true, path = "/opt/emqx/etc/lab-acl.conf"}]}
listeners.tcp.default.bind = "127.0.0.1:1883"
mqtt.max_packet_size = "1MB"
''')
        acl = root / 'acl.conf'
        acl.write_text('{allow, {username, "lab"}, all, ["lab/#"]}.\n{deny, all}.\n')
        for path in (base, acl):
            path.chmod(0o644)
        command(['secret', 'create', SECRET, '-'], data=('user_id,password,is_superuser\nlab,' + password + ',false\n').encode())
        created.append(('secret', SECRET))
        command(['volume', 'create', VOLUME])
        created.append(('volume', VOLUME))
        command(['run', '-d', '--name', CONTAINER, '--pull=never', '--network=none',
                 '--memory=768m', '--pids-limit=512', '--cpus=1',
                 '-e', 'EMQX_NODE__NAME=emqx@127.0.0.1',
                 '-v', VOLUME + ':/opt/emqx/data',
                 '-v', str(base) + ':/opt/emqx/etc/base.hocon:ro',
                 '-v', str(acl) + ':/opt/emqx/etc/lab-acl.conf:ro',
                 '--secret', SECRET + ',type=mount,target=/opt/emqx/etc/lab-bootstrap.csv,uid=1000,gid=1000,mode=0400', IMAGE])
        created.append(('container', CONTAINER))
        phase = 'startup'
        ready()
        inspection = json.loads(command(['container', 'inspect', CONTAINER]).stdout)[0]
        assert inspection['HostConfig']['NetworkMode'] == 'none'
        assert not inspection['HostConfig'].get('PortBindings')
        record('isolated_startup')
        phase = 'effective_config'
        original = config()
        print(json.dumps({'stage': 'effective_root_inventory', 'roots': sorted(original)}), flush=True)
        assert original['authorization']['no_match'] == 'deny'
        assert original['authentication'][0]['bootstrap_file'] == '/opt/emqx/etc/lab-bootstrap.csv'
        command(['exec', CONTAINER, 'test', '-r', '/opt/emqx/etc/lab-bootstrap.csv'])
        record('effective_config_and_bootstrap_mount')
        phase = 'mqtt_allowed'
        allowed = mqtt(password, 'lab/allowed')
        assert allowed.returncode == 0 and any(code in allowed.stdout for code in (b'RC:0', b'RC:16'))
        receive_retained(password, 'lab/allowed')
        record('mqtt_publish_subscribe_allowed')
        phase = 'mqtt_denied'
        denied = mqtt(password, 'outside/denied')
        assert b'RC:135' in denied.stdout or b'Not authorized' in denied.stderr
        record('mqtt_publish_denied')
        phase = 'mqtt_subscribe_denied'
        denied_subscription(password)
        record('mqtt_subscribe_denied')
        phase = 'export'
        exported = ctl('data', 'export', '--root-keys', 'authorization,mqtt', '--table-sets', 'builtin_authn', '--dir', '/opt/emqx/data/backup')
        # Enumerate files; no arbitrary path from a log is executed.
        files = command(['exec', CONTAINER, 'find', '/opt/emqx/data/backup', '-maxdepth', '1', '-type', 'f', '-name', 'emqx-export-*.tar.gz']).stdout.decode().splitlines()
        assert len(files) == 1
        record('synthetic_export')
        phase = 'modify_before_import'
        changed = {'authorization': {'no_match': 'allow', 'deny_action': 'ignore', 'sources': []},
                   'mqtt': {**original['mqtt'], 'max_packet_size': '2MB'}}
        command(['exec', '-i', CONTAINER, 'sh', '-c', 'umask 077; cat > /tmp/lab-change.json'], data=json.dumps(changed).encode())
        ctl('conf', 'load', '--replace', '/tmp/lab-change.json')
        assert config()['authorization']['no_match'] == 'allow'
        phase = 'synthetic_import'
        imported = ctl('data', 'import', files[0])
        assert b'imported successfully' in imported.stdout
        record('synthetic_import')
        phase = 'restore_readback'
        restore = {k: original[k] for k in ('authorization', 'mqtt')}
        command(['exec', '-i', CONTAINER, 'sh', '-c', 'umask 077; cat > /tmp/lab-restore.json'], data=json.dumps(restore).encode())
        ctl('conf', 'load', '--replace', '/tmp/lab-restore.json')
        after = config()
        assert all(after[k] == original[k] for k in restore)
        record('restore_and_effective_readback')
        phase = 'restart'
        command(['restart', CONTAINER], timeout=120)
        ready()
        after = config()
        assert all(after[k] == original[k] for k in restore)
        allowed, denied = mqtt(password, 'lab/after-restart'), mqtt(password, 'outside/after-restart')
        assert allowed.returncode == 0 and any(code in allowed.stdout for code in (b'RC:0', b'RC:16'))
        assert b'RC:135' in denied.stdout or b'Not authorized' in denied.stderr
        receive_retained(password, 'lab/after-restart')
        denied_subscription(password)
        record('restart_config_and_mqtt_policy')
except Exception as error:
    results.append({'stage': phase, 'result': 'fail', 'error_type': type(error).__name__})
    print(json.dumps(results[-1]), flush=True)
finally:
    for kind, name in reversed(created):
        args = ['rm', '-f', name] if kind == 'container' else [kind, 'rm', name]
        result = command(args, accept=True)
        if result.returncode:
            results.append({'stage': 'cleanup_' + kind, 'result': 'fail'})
    print(json.dumps({'image': IMAGE, 'client_image': CLIENT, 'results': results}), flush=True)
if any(item['result'] == 'fail' for item in results):
    raise SystemExit(1)
