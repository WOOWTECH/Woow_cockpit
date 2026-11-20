#!/usr/bin/env python3
"""Fresh isolated real Omnigent -> acknowledged event consumer -> redacted evidence.

No original accounts, stored grants, services or runner workspace are used.
This is direct API producer coverage, not autonomous runner/full restore coverage.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import ha_import_b1_e2e as b1

HERE = Path(__file__).resolve().parent
OWNER = HERE / 'owner.sh'
LP = Path.home() / '.woowbk-lab/bin/labpodman'
PG = '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
RUNNER = '68794c7302df51c24539009635483e9300ff00e353192d7b7bb656ddf1eef373'
STAGE = 'preflight'
APP = '545fa9ea7c1946bbca7df95448b8d2d172777ad861b41599ef69a81b3b32e6d5'

def pod(*args, input=None, check=True, timeout=120):
    proc = subprocess.run([str(OWNER), 'd', 'podman', *args], input=input,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and proc.returncode:
        raise RuntimeError('synthetic podman operation failed')
    return proc


def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--runner-ensure', action='store_true')
    args = parser.parse_args()
    if not args.run:
        parser.error('--run is required')
    state = subprocess.run([str(LP), 'container', 'inspect', 'woowbk-dev-d', '--format',
                            '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                           capture_output=True, check=True).stdout.strip()
    if state != b'true none {}':
        raise RuntimeError('dev-d isolation not established')
    memory = subprocess.run([str(LP), 'exec', 'woowbk-dev-d', 'sh', '-c',
        'cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max'], capture_output=True, check=True).stdout.split()
    if len(memory) != 2 or int(memory[1]) - int(memory[0]) < 1400 * 1024 * 1024:
        raise RuntimeError('insufficient isolated lab memory')
    for image in ((PG, APP, RUNNER) if args.runner_ensure else (PG, APP)):
        assert pod('image', 'inspect', image, '--format', '{{.Id}}').stdout.decode().strip().removeprefix('sha256:') == image
    prefix = 'woowbk-auth-' + secrets.token_hex(5)
    db, server, secret = prefix + '-pg', prefix + '-api', prefix + '-password'
    volumes = [prefix + '-pgdata', prefix + '-appdata']
    created_volumes, created_containers, secret_created = [], [], False
    try:
        with tempfile.TemporaryDirectory(prefix='woowbk-synthetic-auth-') as directory:
            root = Path(directory)
            env, markers = root / 'empty.env', root / 'markers.json'
            env.write_text(''); markers.write_text('{}')
            registry = b1.Secrets([env], markers)
            password = secrets.token_urlsafe(32)
            registry.register('SYNTHETIC_PASSWORD', password)
            pod('secret', 'create', secret, '-', input=password.encode())
            secret_created = True
            for volume in volumes:
                pod('volume', 'create', volume); created_volumes.append(volume)
            STAGE = 'postgres_start'
            pod('run', '-d', '--name', db, '--pull=never', '--network=none', '--read-only',
                '--memory=192m', '--pids-limit=128', '--tmpfs', '/run/postgresql:rw,nosuid,nodev',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev', '-v', volumes[0] + ':/var/lib/postgresql/data',
                '-e', 'POSTGRES_USER=omnigent', '-e', 'POSTGRES_DB=omnigent', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', PG)
            created_containers.append(db)
            for _ in range(60):
                if pod('exec', db, 'pg_isready', '-h', '127.0.0.1', '-U', 'omnigent', check=False).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('synthetic postgres not ready')
            STAGE = 'api_start'
            pod('run', '-d', '--name', server, '--pull=never', '--network=container:' + db,
                '--memory=768m', '--cpus=1', '--pids-limit=256', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '-v', volumes[1] + ':/data',
                '--secret', secret + ',type=env,target=OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD',
                '-e', 'DATABASE_URL=postgresql://omnigent@127.0.0.1:5432/omnigent',
                '-e', 'HOST=127.0.0.1', '-e', 'PORT=8000', '-e', 'ARTIFACT_DIR=/data/artifacts',
                '-e', 'OMNIGENT_AUTH_ENABLED=1', '-e', 'OMNIGENT_AUTH_PROVIDER=accounts',
                '-e', 'OMNIGENT_PUBLIC_SHARING=0', '-e', 'OMNIGENT_ADMIN_CREDENTIALS_PATH=/data/admin-credentials',
                '-e', 'OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME=synthetic-admin', APP)
            created_containers.append(server)
            for _ in range(90):
                if pod('exec', server, 'curl', '-fsS', '-o', '/dev/null', 'http://127.0.0.1:8000/health', check=False).returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('synthetic API not ready')
            STAGE = 'namespace_probe'
            # A second independent check on the actual shared namespace, not only flags.
            assert pod('container', 'inspect', db, '--format', '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}').stdout.strip() == b'none {}'
            probe = 'import socket; s=socket.socket(); s.settimeout(2); print(s.connect_ex(("192.0.2.1",9)))'
            assert pod('exec', server, 'python3', '-I', '-c', probe).stdout.strip() == b'101'
            expected = [('/auth/login', ('token', 'refresh_token'), True),
                        ('/oauth/token', ('access_token', 'refresh_token'), True)]
            STAGE = 'login_refresh_events'
            result = b1._transport.run_events([str(OWNER), 'd', 'podman', 'exec', '-i', server,
                'python3', '-I', '-c', b1.CREDENTIAL_HTTP],
                {'__events': True, 'username': 'synthetic-admin', 'password': password},
                registry.register_observed, expected, 90)
            runner_result = None
            if args.runner_ensure:
                STAGE = 'runner_ensure_events'
                runner_name = prefix + '-runner-probe'
                # Track before launch so timeout/failure still cleans the named object.
                created_containers.append(runner_name)
                runner_code = b1.PROBE_COMMON + (HERE / 'omnigent_runner_ensure_probe.py').read_text()
                runner_result = b1._transport.run_events([str(OWNER), 'd', 'podman', 'run', '--rm', '-i',
                    '--name', runner_name, '--pull=never', '--log-driver=none', '--network=container:' + db,
                    '--memory=256m', '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                    '--entrypoint=python3', RUNNER, '-I', '-c', runner_code],
                    {'__events':True, 'username':'synthetic-admin', 'password':password},
                    registry.register_observed, expected, 90)
            ev = b1.Evidence(registry, 'synthetic-omnigent-credentials')
            ev.save('consumer.json', result)
            # Exercise actual live issued values at the real evidence redaction boundary.
            ev.save('masked-observed.json', {'observed': registry.secret_values()})
            scan = b1.scan_host_evidence(ev.dir, registry)
            log_result = pod('logs', server)
            logs = log_result.stdout + log_result.stderr
            log_hits = sum(logs.count(v) for v in b1.secret_scan_needles(registry.secret_values()))
            if scan['hits'] or log_hits:
                raise RuntimeError('secret leak detected; contents suppressed')
            summary = {'scope':'fresh-synthetic-direct-api', 'app_image':APP, 'pg_image':PG,
                'source_fields':['login.token','login.refresh_token','refresh.access_token','refresh.refresh_token'],
                'events_validated':4 if args.runner_ensure else 2, 'consumer':result,
                'runner_ensure':runner_result, 'runner_image':RUNNER if args.runner_ensure else None, 'evidence_scan':scan,
                'app_log_hits':log_hits, 'outer_network':'none', 'app_external_errno':101,
                'original_identity_used':False, 'full_runner_coverage':False}
            ev.save('coverage.json', summary)
            assert b1.scan_host_evidence(ev.dir, registry)['hits'] == 0
            print(json.dumps({'stage':'credential_coverage', **summary, 'evidence':str(ev.dir)}), flush=True)
    finally:
        bad = False
        for name in reversed(created_containers):
            pod('rm', '-f', name, check=False)
            bad |= pod('container', 'exists', name, check=False).returncode != 1
        for volume in reversed(created_volumes):
            pod('volume', 'rm', volume, check=False)
            bad |= pod('volume', 'exists', volume, check=False).returncode != 1
        if secret_created:
            pod('secret', 'rm', secret, check=False)
            bad |= pod('secret', 'exists', secret, check=False).returncode != 1
        print(json.dumps({'stage':'cleanup', 'verified':not bad}), flush=True)
        if bad:
            raise RuntimeError('synthetic cleanup incomplete')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'stage':'failed', 'at':STAGE, 'type':type(exc).__name__}), flush=True)
        raise SystemExit(1)
