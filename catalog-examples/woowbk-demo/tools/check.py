#!/usr/bin/env python3
"""Prove the woowbk-demo endpoints and unit behaviour. Test fixture only; stdlib only.

Run as the app owner inside a lab device:
    woowbk-owner python3 /opt/woowbk-demo/tools/check.py [--write] [--db-outage] [--stop-start]

Always (read-only): /healthz, /api/summary, /api/notes, /api/files, every file downloaded and
hashed, the summary digest recomputed client-side from the documented canonical form, and
rejected inputs (bad names, bad JSON, unknown paths).
--write       POST one note and one file; counts grow, digest changes, signatures stay valid.
--db-outage   pause the database container: /healthz must turn 503 (database false), then 200.
--stop-start  stop both units: containers disappear, named volumes and secrets stay; start
              again: the summary equals the one taken before the stop.
Prints PASS/FAIL lines and a final JSON summary; exit 1 when anything failed.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

UNITS = ['woowbk-demo-db.service', 'woowbk-demo-app.service']
CONTAINERS = ['woowbk-demo-db', 'woowbk-demo-app']
VOLUMES = ['woowbk-demo-pgdata', 'woowbk-demo-files']
SECRETS = ['woowbk-demo-db-password', 'woowbk-demo-app-key']
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
failures = []


def check(ok, what):
    print(f'{"PASS" if ok else "FAIL"}  {what}')
    if not ok:
        failures.append(what)
    return ok


def env():
    values = dict(os.environ)
    values.setdefault('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    values.setdefault('DBUS_SESSION_BUS_ADDRESS', f'unix:path={values["XDG_RUNTIME_DIR"]}/bus')
    return values


def sh(*argv):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env())


def http(base, method, path, body=None, content_type=None, timeout=30):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(base + path, data=body, method=method)
    if content_type:
        request.add_header('Content-Type', content_type)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except OSError as error:
        return None, type(error).__name__.encode()


def get_json(base, path):
    status, body = http(base, 'GET', path)
    return status, (json.loads(body) if status is not None and body[:1] in (b'{', b'[') else None)


def wait_health(base, want, timeout):
    deadline = time.monotonic() + timeout
    while True:
        status, data = get_json(base, '/healthz')
        if status == want:
            return status, data
        if time.monotonic() >= deadline:
            return status, data
        time.sleep(2)


def read_only_checks(base):
    status, health = get_json(base, '/healthz')
    check(status == 200 and health == {'ok': True, 'database': True, 'data_writable': True},
          f'GET /healthz -> {status} {health}')
    status, summary = get_json(base, '/api/summary')
    check(status == 200 and isinstance(summary, dict) and set(summary) == {'notes', 'files', 'digest', 'title',
                                                                           'signatures_valid'},
          f'GET /api/summary -> {status} {summary}')
    summary = summary or {}
    check(bool(HEX64.fullmatch(str(summary.get('digest', '')))), 'summary.digest is 64 hex chars')
    check(summary.get('signatures_valid') is True, 'summary.signatures_valid is true')
    status, notes = get_json(base, '/api/notes')
    notes = (notes or {}).get('notes', [])
    check(status == 200 and len(notes) == summary.get('notes'), f'GET /api/notes -> {status}, {len(notes)} notes')
    check(all(HEX64.fullmatch(n['signature']) for n in notes), 'every note carries a 64-hex HMAC signature')
    status, files = get_json(base, '/api/files')
    files = (files or {}).get('files', [])
    check(status == 200 and len(files) == summary.get('files'), f'GET /api/files -> {status}, {len(files)} files')
    downloads_ok = True
    for item in files:
        fstatus, data = http(base, 'GET', f'/api/files/{item["name"]}')
        downloads_ok &= fstatus == 200 and hashlib.sha256(data).hexdigest() == item['sha256'] and len(data) == item['size']
    check(downloads_ok, f'GET /api/files/<name> returns the listed bytes for all {len(files)} files')
    canonical = json.dumps({'notes': [[n['id'], n['title'], n['body'], n['signature']] for n in notes],
                            'files': [[f['name'], f['sha256']] for f in files]},
                           ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    check(hashlib.sha256(canonical.encode('utf-8')).hexdigest() == summary.get('digest'),
          'summary.digest recomputed client-side from notes + files matches')
    for method, path, body, want in [
        ('GET', '/api/files/..%2Fetc%2Fpasswd', None, 400),
        ('GET', '/api/files/does-not-exist.bin', None, 404),
        ('POST', '/api/files?name=../escape', b'x', 400),
        ('POST', '/api/files?name=.hidden', b'x', 400),
        ('POST', '/api/notes', b'{not json', 400),
        ('POST', '/api/notes', json.dumps({'title': 'x', 'extra': 1}).encode(), 400),
        ('GET', '/nope', None, 404),
    ]:
        rstatus, _ = http(base, method, path, body, 'application/json' if path == '/api/notes' else None)
        check(rstatus == want, f'{method} {path} rejected with {rstatus} (want {want})')
    return summary


def write_checks(base, before):
    payload = {'title': '檢查用筆記', 'body': '寫入測試 𠮷 ✓'}
    status, body = http(base, 'POST', '/api/notes', json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                        'application/json; charset=utf-8')
    note = json.loads(body) if status == 201 else {}
    check(status == 201 and note.get('title') == payload['title'] and note.get('body') == payload['body'],
          f'POST /api/notes -> {status} id={note.get("id")}')
    data = os.urandom(4096) + '中文內容'.encode('utf-8')
    name = f'check-{os.urandom(3).hex()}.bin'
    status, body = http(base, 'POST', f'/api/files?name={name}', data, 'application/octet-stream')
    check(status == 201 and json.loads(body).get('sha256') == hashlib.sha256(data).hexdigest(),
          f'POST /api/files?name={name} -> {status}')
    status, got = http(base, 'GET', f'/api/files/{name}')
    check(status == 200 and got == data, f'GET /api/files/{name} round-trips {len(data)} bytes')
    _, after = get_json(base, '/api/summary')
    check(after['notes'] == before['notes'] + 1 and after['files'] == before['files'] + 1
          and after['digest'] != before['digest'] and after['signatures_valid'] is True,
          f'summary after write: notes {before["notes"]}->{after["notes"]}, files {before["files"]}->{after["files"]}, '
          f'digest changed, signatures_valid {after["signatures_valid"]}')
    return after


def outage_checks(base):
    result = sh('podman', 'pause', 'woowbk-demo-db')
    if not check(result.returncode == 0, 'podman pause woowbk-demo-db'):
        return
    try:
        status, data = wait_health(base, 503, 60)
        check(status == 503 and data == {'ok': False, 'database': False, 'data_writable': True},
              f'/healthz while the database is paused -> {status} {data}')
    finally:
        sh('podman', 'unpause', 'woowbk-demo-db')
    status, data = wait_health(base, 200, 90)
    check(status == 200, f'/healthz after unpause -> {status} {data}')


def stop_start_checks(base, before):
    stop = sh('systemctl', '--user', 'stop', *reversed(UNITS))
    check(stop.returncode == 0, 'systemctl --user stop woowbk-demo-app.service woowbk-demo-db.service')
    states = sh('systemctl', '--user', 'is-active', *UNITS).stdout.decode().split()
    check(states == ['inactive', 'inactive'], f'units after stop: {states}')
    gone = [c for c in CONTAINERS if sh('podman', 'container', 'exists', c).returncode != 0]
    check(gone == CONTAINERS, f'containers removed by Quadlet on stop: {gone}')
    kept = [v for v in VOLUMES if sh('podman', 'volume', 'exists', v).returncode == 0]
    check(kept == VOLUMES, f'named volumes kept after stop: {kept}')
    kept = [s for s in SECRETS if sh('podman', 'secret', 'exists', s).returncode == 0]
    check(kept == SECRETS, f'secrets kept after stop: {kept}')
    status, _ = http(base, 'GET', '/healthz', timeout=5)
    check(status is None, f'/healthz unreachable while stopped ({status})')
    start = sh('systemctl', '--user', 'start', 'woowbk-demo-app.service')
    check(start.returncode == 0, 'systemctl --user start woowbk-demo-app.service (pulls in the database)')
    status, _ = wait_health(base, 200, 180)
    check(status == 200, f'/healthz after restart -> {status}')
    _, after = get_json(base, '/api/summary')
    check(after == before, f'summary after stop/start equals the one before: {after == before}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--url', default='http://127.0.0.1:18090')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--db-outage', action='store_true')
    parser.add_argument('--stop-start', action='store_true')
    args = parser.parse_args()
    if os.geteuid() == 0:
        sys.exit('check: run as the app owner, not root')
    summary = read_only_checks(args.url)
    if args.write and not failures:
        summary = write_checks(args.url, summary)
    if args.db_outage:
        outage_checks(args.url)
    if args.stop_start:
        _, summary = get_json(args.url, '/api/summary')
        stop_start_checks(args.url, summary)
    _, final = get_json(args.url, '/api/summary')
    print(json.dumps({'ok': not failures, 'failures': failures, 'summary': final}, ensure_ascii=False))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
