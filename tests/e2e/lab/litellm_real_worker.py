"""Executed via stdin INSIDE a fresh lab app container (real LiteLLM 1.104.0 image); no host execution.

Derived from the rehearsal worker of feat/litellm-ha-check-candidate (litellm_actual_worker.py at f0f8cb9). Request:
one JSON line on stdin (env and secrets never travel in argv). Reply: one JSON line {"ok": bool, ...} with counts,
booleans and, for `ha-verify`, the virtual key the app issued (the owner registers it with its credential ledger
before using the reply). Never prints exception text, API bodies, DB values or credentials."""
import importlib.metadata
import json
import os
import selectors
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

HTTP_LIMIT = 1024 * 1024
PROCESS_LIMIT = 16384


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def loopback_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


OPENER = loopback_opener()


def private_failure(message, data=b''):
    error = RuntimeError(message)
    error.private_diagnostic = data[-PROCESS_LIMIT:]
    return error


def bounded_json(response):
    data = response.read(HTTP_LIMIT + 1)
    if len(data) > HTTP_LIMIT:
        raise private_failure('HTTP response limit', data)
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise private_failure('invalid HTTP JSON', data) from None


def api(path, master_key, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request('http://127.0.0.1:4000' + path, data=data,
                                 headers={'Authorization': 'Bearer ' + master_key,
                                          'Content-Type': 'application/json'})
    try:
        with OPENER.open(req, timeout=30) as response:
            return bounded_json(response)
    except urllib.error.HTTPError as exc:
        with exc:
            diagnostic = exc.read(PROCESS_LIMIT + 1)
        raise private_failure('HTTP request failed', diagnostic) from None


def status_of(path, bearer):
    """HTTP status of an authenticated GET (the body is read bounded and discarded)."""
    req = urllib.request.Request('http://127.0.0.1:4000' + path, headers={'Authorization': 'Bearer ' + bearer})
    try:
        with OPENER.open(req, timeout=30) as response:
            response.read(HTTP_LIMIT + 1)
            return response.status
    except urllib.error.HTTPError as exc:
        with exc:
            exc.read(PROCESS_LIMIT + 1)
        return exc.code


def api_as(path, bearer, payload=None):
    """Bounded JSON of an authenticated request; any non-2xx status fails without exposing the body."""
    return api(path, bearer, payload)


# Fixed copy of Woow_podman_litellm config/config.yaml at dd690ae (the package's installed config).
PACKAGE_CONFIG = """model_list: []
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  store_model_in_db: true
  store_prompts_in_spend_logs: false
  maximum_spend_logs_retention_period: "90d"
  maximum_spend_logs_retention_interval: "1d"
  database_connection_pool_limit: 10
  proxy_batch_write_at: 60
  trusted_proxy_ranges: ["127.0.0.1/32"]
litellm_settings:
  drop_params: true
  request_timeout: 90
  budget_exceeded_status_code: 429
  sse_keepalive_ping_interval_seconds: 15
router_settings:
  num_retries: 0
"""


def decrypt_counts(db, salt, wrong_salt):
    """Every top-level string value of every stored model's litellm_params and every stored credential value:
    how many decrypt with `salt` and how many with `wrong_salt` (must be none). Values stay in this process."""
    from litellm.proxy.common_utils.encrypt_decrypt_utils import _decrypt_with_signing_key as decrypt_value

    def ok(value, key):
        try:
            return isinstance(decrypt_value(value=value, signing_key=key), str)
        except Exception:
            return False

    result = {'model_values': 0, 'model_values_ok': 0, 'model_values_wrong_ok': 0,
              'stored_values': 0, 'stored_values_ok': 0, 'stored_values_wrong_ok': 0}
    for (params,) in db.execute('SELECT litellm_params FROM public."LiteLLM_ProxyModelTable"').fetchall():
        if isinstance(params, str):
            params = json.loads(params)
        for value in (params or {}).values():
            if isinstance(value, str) and value:
                result['model_values'] += 1
                result['model_values_ok'] += ok(value, salt)
                result['model_values_wrong_ok'] += ok(value, wrong_salt)
    for (values,) in db.execute('SELECT credential_values FROM public."LiteLLM_CredentialsTable"').fetchall():
        if isinstance(values, str):
            values = json.loads(values)
        for value in (values or {}).values():
            if isinstance(value, str) and value:
                result['stored_values'] += 1
                result['stored_values_ok'] += ok(value, salt)
                result['stored_values_wrong_ok'] += ok(value, wrong_salt)
    return result


def db_counts(db):
    counts = {}
    for label, table in (('users', 'LiteLLM_UserTable'), ('teams', 'LiteLLM_TeamTable'),
                         ('db_models', 'LiteLLM_ProxyModelTable'), ('orgs', 'LiteLLM_OrganizationTable')):
        counts[label] = db.execute('SELECT count(*) FROM public."' + table + '"').fetchone()[0]
    return counts


def ha_checks(request, master_key):
    """The restored HA data as served by the running app: the HA-issued virtual key, its model list, the stored
    models, users and teams. Returns counts only."""
    if status_of('/key/info', request['test_vkey']) != 200:
        raise RuntimeError('HA virtual key not accepted')
    info = api_as('/key/info', request['test_vkey'])
    if not isinstance(info, dict) or (info.get('info') or {}).get('key_alias') != request['expected_alias']:
        raise RuntimeError('HA virtual key identity')
    models = api_as('/v1/models', request['test_vkey'])
    listed = api('/model/info', master_key)
    counts = {'vkey_models': len(models.get('data') or []), 'api_models': len(listed.get('data') or [])}
    if counts['vkey_models'] < 1:
        raise RuntimeError('HA virtual key sees no model')
    return counts


def bounded_capture(argv, *, timeout=30, limit=PROCESS_LIMIT):
    """Read at most limit+1 total bytes; kill/reap on excess or deadline."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in buffers:
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise private_failure('subprocess timeout', bytes(buffers[proc.stderr]))
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), min(8192, limit - total + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    buffers[key.fileobj].extend(data)
                    if total > limit:
                        raise private_failure('subprocess output limit', bytes(buffers[key.fileobj]))
            try:
                code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise private_failure('subprocess timeout', bytes(buffers[proc.stderr])) from None
        return subprocess.CompletedProcess(argv, code, bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr]))
    finally:
        # Includes descendants retaining a pipe after the direct child exits.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        for pipe in buffers:
            pipe.close()


def salt_prepare(action):
    """Match the pinned db_prepare rejection, not an arbitrary process failure."""
    result = bounded_capture(['python', '/opt/woow/db_prepare.py'])
    if action == 'salt-accept':
        if result.returncode != 0:
            raise private_failure('matching salt failed', result.stderr)
    elif (result.returncode != 1 or result.stdout or
          result.stderr.strip() != b'db-prepare: failed (ValueError); refusing startup'):
        raise private_failure('salt mismatch not established', result.stderr)


def main():
    payload = sys.stdin.buffer.readline(65537)
    if len(payload) > 65536:
        raise RuntimeError('worker input limit')
    request = json.loads(payload)
    os.environ.update(request['env'])
    import psycopg
    action = request['action']
    if action == 'start':
        if importlib.metadata.version('litellm') != '1.104.0':
            raise RuntimeError('version')
        config = '/tmp/woowbk-lab-config.yaml'
        with open(config, 'w') as out:
            out.write(PACKAGE_CONFIG)
        # A separate bounded tail collector survives this worker's successful exit.
        # Its file is private to the disposable container and removed with it.
        log_path = '/tmp/woowbk-lab-startup.log'
        collector_code = """import os,sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
tail=b''
while True:
 data=os.read(0,4096)
 if not data: break
 tail=(tail+data)[-16384:]
 os.lseek(fd,0,0); os.write(fd,tail); os.ftruncate(fd,len(tail))
os.close(fd)
"""
        collector = subprocess.Popen(['python', '-I', '-c', collector_code, log_path],
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        child = subprocess.Popen(['/opt/woow/start.sh', '--config', config, '--port', '4000'],
                                 stdout=collector.stdin, stderr=collector.stdin)
        collector.stdin.close()

        def startup_failure(reason):
            try:
                with open(log_path, 'rb') as handle:
                    diagnostic = handle.read(PROCESS_LIMIT)
            except OSError:
                diagnostic = b''
            metrics = {'reason': reason, 'child_returncode': child.poll()}
            for filename in ('memory.events', 'memory.max', 'memory.peak'):
                try:
                    with open('/sys/fs/cgroup/' + filename) as handle:
                        metrics[filename] = handle.read(1024).strip()
                except OSError:
                    metrics[filename] = 'unavailable'
            # Append static metrics so tail truncation preserves the failure reason.
            return private_failure(reason, diagnostic + b'\nLAB_STARTUP_METRICS ' +
                                   json.dumps(metrics).encode())

        with open('/tmp/woowbk-lab-app.pid', 'w') as out:
            out.write(str(child.pid))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise startup_failure('startup')
            try:
                probe = urllib.request.Request('http://127.0.0.1:4000/health/readiness',
                    headers={'Authorization': 'Bearer ' + os.environ['LITELLM_MASTER_KEY']})
                with OPENER.open(probe, timeout=2) as r:
                    if r.status == 200:
                        print('{"ok":true}')
                        return
            except Exception:
                pass
            time.sleep(2)
        raise startup_failure('health timeout')

    if action == 'seed':
        api('/model/new', os.environ['LITELLM_MASTER_KEY'], {'model_name': request['marker'], 'litellm_params': {
            'model': 'openai/woowbk-offline-test', 'api_key': request['credential']}})
        print('{"ok":true}')
        return
    if action in ('salt-refusal', 'salt-accept'):
        salt_prepare(action)
        print('{"ok":true}')
        return
    if action in ('verify', 'decrypt-refusal', 'decrypt-accept'):
        # Exercise the authenticated real app API as well as its own decryptor.
        if action == 'verify':
            listed = api('/model/info', os.environ['LITELLM_MASTER_KEY'])
            if not any(item.get('model_name') == request['marker'] for item in listed['data']):
                raise RuntimeError('model missing from real API')
        from litellm.proxy.common_utils.encrypt_decrypt_utils import _decrypt_with_signing_key as decrypt_value
        from nacl.exceptions import CryptoError
        from cryptography.exceptions import InvalidTag
        with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=10) as db:
            rows = db.execute('SELECT litellm_params FROM public."LiteLLM_ProxyModelTable" '
                              'WHERE model_name = %s', (request['marker'],)).fetchall()
            if len(rows) != 1:
                raise RuntimeError('model cardinality')
            params = rows[0][0]
            if isinstance(params, str):
                params = json.loads(params)
            ciphertext = params['api_key']
            if ciphertext == request['credential']:
                raise RuntimeError('plaintext credential')
            if action == 'decrypt-refusal':
                try:
                    value = decrypt_value(value=ciphertext, signing_key=os.environ['LITELLM_SALT_KEY'])
                except (CryptoError, InvalidTag):
                    value = None
                if value == request['credential']:
                    raise RuntimeError('wrong salt decrypted credential')
                print('{"ok":true}')
                return
            if decrypt_value(value=ciphertext, signing_key=os.environ['LITELLM_SALT_KEY']) != request['credential']:
                raise RuntimeError('decrypt mismatch')
            salt = db.execute("SELECT value FROM woow_platform.settings WHERE key='litellm_salt_key'").fetchall()
            if salt != [(os.environ['LITELLM_SALT_KEY'],)]:
                raise RuntimeError('salt binding')
        print('{"ok":true}')
        return
    if action in ('ha-verify', 'recheck'):
        master = os.environ['LITELLM_MASTER_KEY']
        counts = ha_checks(request, master)
        issued = []
        with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=10) as db:
            counts.update(db_counts(db))
            if action == 'ha-verify':
                counts.update(decrypt_counts(db, os.environ['LITELLM_SALT_KEY'], request['wrong_salt']))
                salt = db.execute("SELECT value FROM woow_platform.settings WHERE key='litellm_salt_key'").fetchall()
                counts['salt_row_matches'] = salt == [(os.environ['LITELLM_SALT_KEY'],)]
        if action == 'ha-verify':
            # A write through the restored database: the app issues a new virtual key (registered by the owner).
            made = api('/key/generate', master, {'key_alias': request['issued_alias'], 'duration': '2h'})
            key = made.get('key') if isinstance(made, dict) else None
            if not isinstance(key, str) or len(key) < 6:
                raise RuntimeError('issued key missing')
            issued.append(key)
            counts['issued_key_info'] = status_of('/key/info', key)
        else:
            counts['issued_key_info'] = status_of('/key/info', request['issued_key'])
        print(json.dumps({'ok': True, 'counts': counts, 'issued': issued}))
        return
    if action == 'rollback-verify':
        statuses = {'test_vkey_status': status_of('/key/info', request['test_vkey']),
                    'issued_key_status': status_of('/key/info', request['issued_key'])}
        print(json.dumps({'ok': True, 'counts': statuses}))
        return
    raise RuntimeError('unknown action')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # The owner runner captures this bounded private stream, never returns it.
        import traceback
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        diagnostic = getattr(exc, 'private_diagnostic', b'')
        diagnostic += b'\nWORKER_FAILURE ' + json.dumps({
            'type': type(exc).__name__, 'function': frame.name,
            'line': frame.lineno}).encode()
        if diagnostic:
            sys.stderr.buffer.write(diagnostic[-PROCESS_LIMIT:])
        # Never emit exception text, API bodies, DB values or credentials.
        print('{"ok":false}')
        sys.exit(1)
