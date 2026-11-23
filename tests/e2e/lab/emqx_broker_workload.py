"""New isolated synthetic broker workload; no restore or source coverage claim.

Only run via run_emqx_broker_workload.sh. Fixed summaries only; private tool output
and generated credentials never enter argv, environment, exceptions or artifacts.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote_from_bytes

from emqx_runtime_live import IMAGE, podman, checked

CLIENT = '93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3'


class PartialScan:
    """Bounded partial-producer scan. Never exposes a full-registry capability."""
    def __init__(self, values):
        self.values = set()
        self.add(values)

    def add(self, values):
        combined = self.values | set(values)
        if (any(type(v) is not bytes or not 0 < len(v) <= 65536 for v in combined)
                or len(combined) > 4096 or sum(map(len, combined)) > 1048576):
            raise RuntimeError('partial-registration-refused')
        self.values = combined

    def scan(self, payload):
        if type(payload) is not bytes or len(payload) > 1048576:
            raise RuntimeError('partial-scan-refused')
        for value in self.values:
            needles = {value, base64.b64encode(value), value.hex().encode(),
                       quote_from_bytes(value, safe='').encode()}
            try:
                text = value.decode()
            except UnicodeError:
                pass
            else:
                needles.update(json.dumps(text, ensure_ascii=flag)[1:-1].encode() for flag in (True, False))
            if any(needle in payload for needle in needles):
                raise RuntimeError('partial-leak-refused')


def run(mode):
    if socket.gethostname() != 'woowbk-dev-d' or os.geteuid() == 0:
        raise RuntimeError('wrong-lab-owner')
    name = 'woowbk-emqx-workload-' + secrets.token_hex(6)
    report = {'scope': 'synthetic-broker-' + mode, 'source_completeness': 'not-assessed',
              'target_completeness': 'not-assessed', 'ha_commercial_acceptance': False,
              'image_id': IMAGE, 'client_image_id': CLIENT, 'checks': {}}
    checks = report['checks']
    clients = []
    created = False
    stage = 'setup'
    with tempfile.TemporaryDirectory(prefix=name + '-') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        password = secrets.token_hex(24)
        username = 'workload-user'
        scan = PartialScan([password.encode(), username.encode()])
        for file in ('mosquitto_pub', 'mosquitto_sub'):
            (root / file).write_text('-u ' + username + '\n-P ' + password + '\n')
            (root / file).chmod(0o600)
        (root / 'users.csv').write_text('user_id,password,is_superuser\n' + username + ',' + password + ',false\n')
        (root / 'users.csv').chmod(0o600)
        (root / 'acl.conf').write_text('{allow, {username, "' + username + '"}, all, ["allowed/#"]}.\n{deny, all}.\n')
        (root / 'acl.conf').chmod(0o600)
        (root / 'emqx.conf').write_text('''node.name = "workload@127.0.0.1"
node.cookie = "synthetic-workload-isolated-cookie"
node.data_dir = "/opt/emqx/data"
dashboard.listeners.http.enable = false
listeners.tcp.default.bind = "127.0.0.1:1883"
listeners.ssl.default.enable = false
listeners.ws.default.enable = false
listeners.wss.default.enable = false
authentication = [{mechanism = password_based, backend = built_in_database,
password_hash_algorithm {name = sha256, salt_position = suffix},
bootstrap_file = "/work/users.csv", bootstrap_type = plain}]
authorization {no_match = deny, deny_action = ignore,
sources = [{type = file, enable = true, path = "/work/acl.conf"}]}
retainer.backend.storage_type = disc
''')
        if mode == 'owner-target':
            # Fresh synthetic profile: no mounted bootstrap/ACL refs and no MQTT
            # clients/ticker. Credentials are generated privately, never argv.
            (root / 'emqx.conf').write_text('''node.name = "workload@127.0.0.1"
node.cookie = "synthetic-workload-isolated-cookie"
node.data_dir = "/opt/emqx/data"
dashboard.listeners.http.enable = false
dashboard.default_password = "''' + password + '''"
listeners.tcp.default.bind = "127.0.0.1:1883"
listeners.ssl.default.enable = false
listeners.ws.default.enable = false
listeners.wss.default.enable = false
authentication = [{mechanism = password_based, backend = built_in_database,
user_id_type = username, enable = true,
password_hash_algorithm {name = sha256, salt_position = suffix}}]
''')
        (root / 'emqx.conf').chmod(0o600)

        def ready():
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                result = podman('exec', name, 'emqx', 'ctl', 'status')
                if result.returncode == 0 and b'is started' in result.stdout:
                    return
                state = podman('inspect', '--format', '{{.State.Running}}', name)
                if state.stdout.strip() != b'true':
                    raise RuntimeError('broker-exited')
                time.sleep(1)
            raise RuntimeError('broker-ready-timeout')

        def mqtt(command, topic, *args):
            client = name + '-client-' + secrets.token_hex(3)
            clients.append(client)
            # Default config is the supported 2.0.x private auth transport.
            return subprocess.run(['podman', 'run', '--rm', '--name', client,
                '--pull=never', '--log-driver=none', '--image-volume=ignore',
                '--network=container:' + name, '--userns=keep-id:uid=1000,gid=1000',
                '--user=1000:1000', '--memory=64m', '--cpus=0.25', '--pids-limit=32',
                '-e', 'HOME=/work', '-e', 'XDG_CONFIG_HOME=/work',
                '-v', str(root) + ':/work:ro', '--entrypoint=' + command, 'sha256:' + CLIENT,
                '-h', '127.0.0.1', '-p', '1883', '-V', 'mqttv5', '-q', '1', '-t', topic,
                *args], capture_output=True, timeout=20)

        def workload(label):
            topic = 'allowed/' + label
            sent = mqtt('mosquitto_pub', topic, '-r', '-m', 'synthetic-workload-marker', '-d')
            output = sent.stdout + sent.stderr
            codes = [int(v) for v in re.findall(rb'RC[:=]\s*(\d+)', output)]
            assert sent.returncode == 0 and any(c in (0, 16) for c in codes)
            checks[label + '_publish_allowed'] = True
            received = mqtt('mosquitto_sub', topic, '-C', '1', '-W', '5')
            assert received.returncode == 0 and received.stdout.strip() == b'synthetic-workload-marker'
            checks[label + '_subscribe_payload'] = True
            denied = mqtt('mosquitto_pub', 'denied/' + label, '-m', 'synthetic-denied-marker', '-d')
            output = denied.stdout + denied.stderr
            assert b'PUBACK' in output and re.search(rb'RC[:=]\s*135\b', output)
            report[label + '_denied_publish_reason'] = 135
            checks[label + '_publish_denied'] = True
            denied_sub = mqtt('mosquitto_sub', 'denied/' + label, '-E', '-W', '5', '-d')
            output = denied_sub.stdout + denied_sub.stderr
            assert b'SUBACK' in output and (re.search(rb'Subscribed[^\n]*:\s*135\b', output) or b'Not authorized' in output)
            report[label + '_denied_subscribe_reason'] = 135
            checks[label + '_subscribe_denied'] = True

        try:
            assert podman('container', 'exists', name).returncode == 1
            for image in (IMAGE, CLIENT):
                doc = json.loads(checked('image', 'inspect', 'sha256:' + image))[0]
                assert doc['Id'].removeprefix('sha256:') == image
            if mode == 'owner-target':
                stage = 'fixed-expression-native-parse'
                from emqx_broker_owner_target import parse_fixed_expression
                parse_fixed_expression(root, name, report)
            stage = 'broker-start'
            created = True
            checked('run', '-d', '--name', name, '--pull=never', '--network=none',
                '--log-driver=none', '--image-volume=ignore', '--userns=keep-id:uid=1000,gid=1000',
                '--memory=768m', '--cpus=0.75', '--pids-limit=256',
                '-e', 'ERL_FLAGS=+S 2:2 +SDcpu 1 +SDio 1',
                '-v', str(root) + ':/work:rw',
                '-v', str(root / 'emqx.conf') + ':/opt/emqx/etc/emqx.conf:ro', 'sha256:' + IMAGE)
            inspect = json.loads(checked('inspect', name))[0]
            assert inspect['HostConfig']['NetworkMode'] == 'none'
            assert inspect['HostConfig']['LogConfig']['Type'] == 'none'
            assert not any(m['Type'] == 'volume' for m in inspect['Mounts'])
            stage = 'broker-ready'
            ready()
            checks['broker_ready'] = True
            if mode == 'mqtt':
                stage = 'mqtt-before-restart'
                workload('before_restart')
                stage = 'broker-restart'
                checked('restart', '--time', '20', name)
                ready()
                checks['broker_restart_ready'] = True
                stage = 'mqtt-after-restart'
                retained = mqtt('mosquitto_sub', 'allowed/before_restart', '-C', '1', '-W', '5')
                assert retained.returncode == 0 and retained.stdout.strip() == b'synthetic-workload-marker'
                checks['retained_payload_survived_restart'] = True
                workload('after_restart')
            elif mode == 'owner-target':
                stage = 'owner-target-observation'
                from emqx_broker_owner_target import run_owner_target
                run_owner_target(root, name, clients, report, owned_container_id=inspect['Id'])
            else:
                stage = 'owner-data-export-checkpoint'
                from emqx_broker_export import run_export
                run_export(root, name, scan, report)
            report['result'] = 'passed'
        except BaseException:
            report['result'] = 'failed'
            report['failure_stage'] = stage
        finally:
            for client in clients:
                podman('rm', '-f', '--ignore', '--volumes', client)
            checks['clients_cleanup'] = all(podman('container', 'exists', c).returncode == 1 for c in clients)
            cleaned = podman('rm', '-f', '--ignore', '--volumes', name) if created else None
            checks['broker_cleanup'] = (cleaned is None or cleaned.returncode == 0) and podman('container', 'exists', name).returncode == 1
            if not checks['broker_cleanup'] or not checks['clients_cleanup']:
                report['result'] = 'failed'
    checks['private_files_cleanup'] = not root.exists()
    if mode in ('export', 'owner-target'):
        # Actual Mnesia atoms such as false are registered too; never exempt them.
        report['ha_commercial_acceptance'] = 'not-claimed'
        report['checks'] = {key: 'passed' if value else 'failed' for key, value in checks.items()}
    raw = json.dumps(report, sort_keys=True).encode()
    scan.scan(raw)
    print(raw.decode())
    return 0 if report.get('result') == 'passed' and all(checks.values()) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('mqtt', 'export', 'owner-target'), required=True)
    raise SystemExit(run(parser.parse_args().mode))
