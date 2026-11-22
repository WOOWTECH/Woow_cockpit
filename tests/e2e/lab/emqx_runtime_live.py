"""Run inside isolated dev-d as appowner. Synthetic credentials, real EMQX.

Runtime producer boundary only. Never claims source/target snapshot completeness.
No raw subprocess/HTTP diagnostics may leave this private process.
"""
import base64
import io
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import RuntimeRegistry, login_registered

IMAGE = '3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'


def podman(*args):
    return subprocess.run(['podman', *args], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=90, check=False)


def checked(*args):
    result = podman(*args)
    if result.returncode:
        raise RuntimeError('lab-command-failed')
    return result.stdout


def publish_login(directory, registry):
    """Distinct runtime-only schema; exact serialized bytes scanned before create."""
    raw = (json.dumps({'schema': 1, 'scope': 'synthetic-broker-runtime-login-producer',
                      'result': 'passed', 'source_completeness': 'not-assessed',
                      'target_completeness': 'not-assessed'}, sort_keys=True) + '\n').encode()
    registry.scan_login_evidence(raw)
    fd = os.open(directory / 'runtime-login.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    assert (directory / 'runtime-login.json').read_bytes() == raw
    assert (directory / 'runtime-login.json').stat().st_mode & 0o777 == 0o600
    return raw


def main():
    if socket.gethostname() != 'woowbk-dev-d' or os.geteuid() == 0:
        raise RuntimeError('wrong-lab-owner')
    prefix = 'woowbk-emqx-runtime-' + secrets.token_hex(6)
    report = {'scope': 'synthetic-broker-runtime-login-producer',
              'source_completeness': 'not-assessed', 'target_completeness': 'not-assessed',
              'mqtt': 'not-run', 'ha_commercial_acceptance': False, 'checks': {}}
    checks = report['checks']
    created = False
    with tempfile.TemporaryDirectory(prefix=prefix + '-') as work:
        private = Path(work)
        os.chmod(private, 0o700)
        password = secrets.token_urlsafe(32).encode()
        username = b'admin'
        registry = RuntimeRegistry()
        image = json.loads(checked('image', 'inspect', 'sha256:' + IMAGE))[0]
        assert image['Id'].removeprefix('sha256:') == IMAGE
        assert image['Config']['Labels']['org.opencontainers.image.version'] == '5.8.9'
        report['image_id'] = IMAGE
        report['image_label_version'] = '5.8.9'
        # Allocate unused loopback ports inside the network-none outer device.
        sockets = []
        for _ in range(2):
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
        dashboard, mqtt = [s.getsockname()[1] for s in sockets]
        config = private / 'emqx.conf'
        config.write_text('dashboard.listeners.http.bind = "127.0.0.1:%d"\n'
                          'dashboard.default_password = "%s"\n'
                          'listeners.tcp.default.bind = "127.0.0.1:%d"\n'
                          'listeners.ssl.default.enable = false\n'
                          'listeners.ws.default.enable = false\n'
                          'listeners.wss.default.enable = false\n' % (dashboard, password.decode(), mqtt))
        os.chmod(config, 0o600)
        url = 'http://127.0.0.1:%d/api/v5/' % dashboard
        def http(path, *, data=None, bearer=None):
            # Secrets travel only over stdin to curl inside the network-none broker.
            config = ['url = ' + json.dumps(url + path), 'silent', 'show-error',
                      'max-time = 5', 'write-out = "\\n%{http_code}"']
            if data is not None:
                config += ['header = "Content-Type: application/json"',
                           'data = ' + json.dumps(json.dumps(data))]
            if bearer is not None:
                config += ['header = ' + json.dumps('Authorization: ' + bearer.decode())]
            response = subprocess.run(['podman', 'exec', '-i', prefix, 'curl', '--config', '-'],
                input=('\n'.join(config) + '\n').encode(), capture_output=True, timeout=10)
            report['last_curl_returncode'] = response.returncode
            if response.returncode or len(response.stdout) > 65536:
                raise RuntimeError('private-http-failed')
            body, code = response.stdout.rsplit(b'\n', 1)
            return int(code), body
        def transport(user, passwd):
            status, body = http('login', data={'username': user.decode(), 'password': passwd.decode()})
            report['last_login_status'] = status
            try:
                parsed = json.loads(body)
                report['login_has_token'] = isinstance(parsed, dict) and 'token' in parsed
                report['login_has_unexpected_fields'] = isinstance(parsed, dict) and bool(set(parsed) - {'token', 'username', 'role', 'version', 'license'})
            except ValueError:
                report['login_json_invalid'] = True
            return status, 'application/json', io.BytesIO(body)
        try:
            for sock in sockets:
                sock.close()
            # keep-id makes private config readable to EMQX uid 1000, with no public chmod.
            checked('run', '-d', '--pull=never', '--name', prefix,
                    '--network=none', '--log-driver=none', '--image-volume=ignore', '--userns=keep-id:uid=1000,gid=1000',
                    '--memory=768m', '--cpus=0.75', '--pids-limit=256',
                    '-e', 'ERL_FLAGS=+S 2:2 +SDcpu 1 +SDio 1',
                    '-v', str(config) + ':/opt/emqx/etc/emqx.conf:ro', 'sha256:' + IMAGE)
            created = True
            container = json.loads(checked('inspect', prefix))[0]
            assert container['HostConfig']['NetworkMode'] == 'none'
            assert container['HostConfig']['LogConfig']['Type'] == 'none'
            assert not any(m['Type'] == 'volume' for m in container.get('Mounts', []))
            checks['no_implicit_volumes'] = True
            checks['raw_log_driver_disabled'] = True
            deadline = time.monotonic() + 75
            while True:
                try:
                    credential = login_registered(registry, transport, username=username, password=password)
                    break
                except PrivateFailure:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('broker-login-timeout') from None
                    time.sleep(1)
            checks['real_login_registered'] = True
            def authenticate(bearer):
                status, body = http('nodes', bearer=bearer)
                assert status == 200
                doc = json.loads(body)
                report['broker_version'] = doc[0]['version']
                return True
            checks['issued_token_authenticated'] = credential.with_bearer(authenticate)
            status, _ = http('nodes', bearer=b'Bearer ' + secrets.token_urlsafe(32).encode())
            assert status == 401
            checks['invalid_bearer_denied'] = True
            evidence = publish_login(private, registry)
            checks['exact_bytes_private_evidence'] = True
            report['private_evidence_sha256'] = hashlib.sha256(evidence).hexdigest()
            # Actual issued token, Bearer, encoding and actual input never become artifacts.
            def leak_checks(bearer):
                token = bearer.removeprefix(b'Bearer ')
                for value in (token, bearer, base64.b64encode(token), token.hex().encode(), password):
                    try:
                        registry.scan_login_evidence(value)
                    except PrivateFailure:
                        continue
                    raise RuntimeError('leak-accepted')
                return True
            checks['actual_token_and_input_leaks_refused'] = credential.with_bearer(leak_checks)
            try:
                registry.scan(evidence)
            except PrivateFailure:
                checks['full_snapshot_scan_still_refused'] = True
            else:
                raise RuntimeError('false-completeness')
            invalid = RuntimeRegistry()
            try:
                login_registered(invalid, transport, username=username,
                                 password=secrets.token_urlsafe(32).encode())
            except PrivateFailure:
                checks['real_wrong_password_refused'] = True
            else:
                raise RuntimeError('invalid-login-accepted')
            try:
                publish_login(private, invalid)
            except PrivateFailure:
                checks['failed_login_publication_refused'] = True
            else:
                raise RuntimeError('invalid-publication-accepted')
            assert (private / 'runtime-login.json').read_bytes() == evidence
            report['result'] = 'passed'
        except BaseException:
            report['result'] = 'failed'
            report['failure'] = 'runtime-live-failed'
        finally:
            cleanup = podman('rm', '-f', '--volumes', prefix) if created else None
            absent = podman('container', 'exists', prefix).returncode == 1
            checks['container_cleanup'] = absent and (cleanup is None or cleanup.returncode == 0)
            if not checks['container_cleanup']:
                report['result'] = 'failed'
    checks['private_files_cleanup'] = not private.exists()
    raw_report = json.dumps(report, sort_keys=True).encode()
    if report.get('result') == 'passed':
        registry.scan_login_evidence(raw_report)
    print(raw_report.decode())
    return 0 if report.get('result') == 'passed' and all(checks.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
