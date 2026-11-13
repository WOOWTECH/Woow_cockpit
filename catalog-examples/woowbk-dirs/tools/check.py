#!/usr/bin/env python3
"""Prove the woowbk-dirs endpoints, host-directory ownership and unit behaviour. Test fixture only; stdlib only.

Run as the app owner inside a lab device:
    woowbk-owner python3 /opt/woowbk-dirs/tools/check.py [--write] [--db-outage] [--stop-start]

Always (read-only):
  * /healthz all true; /api/summary has exactly the keys the catalog compares;
  * /api/db and /api/sqlite agree with the summary (counts; db_digest and sqlite digest recomputed here);
  * /api/tree: digest recomputed here; data root owned by container root (0755), www/ by uid 33 (0750),
    every entry below www/ by uid 33 (www/tmp an empty 0700 directory), the owner's items exactly as seed.py
    creates them (container root; a UTF-8 name with a space, a 0444 file, an empty directory, a symlink that
    points outside the data directory with its exact target); www/latest is a relative symlink to a listed doc;
    every archive/ file is a hard link of a docs/ file;
  * the owner's user-namespace view (`podman unshare`, what the backup engine reads) of ~/woowbk-dirs/data
    equals the container's view byte for byte (same treelist digest);
  * host view: data root owned by the owner, www/ and the PostgreSQL directory by the owner's subordinate
    ids for container uid 33 and 70 (from the owner's uid_map), PostgreSQL directory 0700;
  * www/db/app.sqlite-wal exists and is not empty (committed rows live in the WAL);
  * db_meta: user dirs_app, roles dirs (superuser) and dirs_app (login), owners, server major 16.
--write       POST an item (counts and digests change; the new doc belongs to uid 33), then DELETE it.
--db-outage   pause the database container: /healthz turns 503 (both databases false), then 200 again.
--stop-start  stop both units: containers disappear; host directories, secrets and settings stay;
              start again: the summary equals the one taken before the stop.
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

HERE = os.path.dirname(os.path.abspath(__file__))
TREELIST = os.path.join(os.path.dirname(HERE), 'app', 'treelist.py')
sys.path.insert(0, os.path.dirname(TREELIST))
import treelist  # noqa: E402

UNITS = ['woowbk-dirs-db.service', 'woowbk-dirs-app.service']
CONTAINERS = ['woowbk-dirs-db', 'woowbk-dirs-app']
SECRETS = ['woowbk-dirs-db-password', 'woowbk-dirs-role-password', 'woowbk-dirs-app-key']
ENV_REL = '.config/woowbk-dirs/app.env'
PG_DIR_REL = '.local/share/woowbk-dirs/postgres'
DATA_REL = 'woowbk-dirs/data'
SUMMARY_KEYS = {'items', 'events', 'db_digest', 'db_meta', 'tree', 'tree_digest', 'sqlite', 'title', 'signatures_valid'}
# Items of the data root that belong to the owner (container root), as tools/seed.py creates them: (type, mode).
OWNER_ITEMS = {'README.txt': ('file', '0644'), '.storage': ('dir', '0755'), '.storage/core.json': ('file', '0644'),
               '.storage/empty': ('dir', '0755'), '共享': ('dir', '0755'), '共享/說明 文件.txt': ('file', '0644'),
               '共享/唯讀.txt': ('file', '0444'), '共享/設定連結': ('symlink', '0777')}
# The owner's symlink that leaves the data directory (seed.py): kept as a link with exactly this target.
OUTSIDE_LINK = ('共享/設定連結', '../../../.config/woowbk-dirs/app.env')
HEALTHY = {'ok': True, 'database': True, 'audit_database': True, 'data_writable': True, 'sqlite': True}
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


def sh(*argv, input=None, timeout=300):
    return subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env(), timeout=timeout)


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
        if status == want or time.monotonic() >= deadline:
            return status, data
        time.sleep(2)


def canonical_sha256(value):
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def id_map(kind='uid'):
    """[(inside, outside, count)] of the owner's user namespace (uid_map or gid_map), as podman unshare reports it."""
    out = sh('podman', 'unshare', 'cat', f'/proc/self/{kind}_map').stdout.decode()
    return [tuple(int(x) for x in line.split()) for line in out.splitlines() if line.strip()]


def host_id(mapping, container_id):
    for inside, outside, count in mapping:
        if inside <= container_id < inside + count:
            return outside + container_id - inside
    return None


def by_path(entries):
    return {e['path']: e for e in entries}


def tree_checks(entries):
    index = by_path(entries)
    root, www = index.get('.', {}), index.get('www', {})
    check(root.get('type') == 'dir' and (root.get('uid'), root.get('gid'), root.get('mode')) == (0, 0, '0755'),
          f'data root as the app sees it: container root 0755 ({root.get("uid")}:{root.get("gid")} {root.get("mode")})')
    check(www.get('type') == 'dir' and (www.get('uid'), www.get('gid'), www.get('mode')) == (33, 33, '0750'),
          f'www/ belongs to the app user 33:33 0750 ({www.get("uid")}:{www.get("gid")} {www.get("mode")})')
    below = [e for e in entries if e['path'].startswith('www/')]
    check(below and all((e['uid'], e['gid']) == (33, 33) for e in below),
          f'every one of the {len(below)} entries below www/ belongs to uid/gid 33')
    tmp = index.get('www/tmp', {})
    check(tmp.get('type') == 'dir' and tmp.get('mode') == '0700' and not any(e['path'].startswith('www/tmp/')
                                                                            for e in entries),
          f'www/tmp is an empty 0700 directory of uid 33 ({tmp.get("mode")})')
    owner_items = {e['path']: e for e in entries if e['path'] != '.' and not e['path'].startswith('www')}
    check(set(owner_items) == set(OWNER_ITEMS) and all((e['uid'], e['gid']) == (0, 0) for e in owner_items.values()),
          f"the owner's items {sorted(owner_items)} are exactly the expected ones and belong to container root")
    check(all((owner_items.get(p, {}).get('type'), owner_items.get(p, {}).get('mode')) == want
              for p, want in OWNER_ITEMS.items()),
          'owner items: types and modes (UTF-8 name with a space, 0444 file, empty .storage/empty) as created')
    outside = index.get(OUTSIDE_LINK[0], {})
    check(outside.get('type') == 'symlink' and outside.get('target') == OUTSIDE_LINK[1],
          f'{OUTSIDE_LINK[0]} is a symlink that leaves the data directory, target {outside.get("target")!r}')
    latest = index.get('www/latest', {})
    target = latest.get('target', '')
    check(latest.get('type') == 'symlink' and not target.startswith('/') and index.get(f'www/{target}', {}).get('type')
          == 'file', f'www/latest is a relative symlink to a listed doc ({target})')
    archives = [e for e in entries if e['path'].startswith('www/archive/') and e['type'] == 'file']
    docs = {e['path'] for e in entries if e['path'].startswith('www/docs/') and e['type'] == 'file'}
    linked = [e for e in entries if e.get('link')]
    check(archives and all(any(e['path'] in (l['path'], l['link']) for l in linked) for e in archives)
          and all({l['path'], l['link']} & docs for l in linked),
          f'all {len(archives)} archive/ files are hard links of docs/ files ({len(linked)} link entries)')
    nested = {e['path'] for e in entries if e['type'] == 'dir' and e['path'].count('/') == 3
              and e['path'].startswith('www/docs/')}
    check(bool(nested), f'docs are stored two directory levels deep ({len(nested)} leaf directories)')
    xattr_docs = [e for e in entries if e['path'].startswith('www/docs/') and e['type'] == 'file' and
                  'user.woowbk.item' in e.get('xattrs', {})]
    print(f'info  {len(xattr_docs)}/{len(docs)} docs carry user.woowbk.item (0 means no user xattrs on this filesystem)')
    sqlite = index.get('www/db/app.sqlite', {})
    check(sqlite.get('type') == 'file' and sqlite.get('mode') == '0600' and 'sha256' not in sqlite,
          'www/db/app.sqlite is listed by type/mode/owner only (content compared through SQL)')


def read_only_checks(base):
    status, health = get_json(base, '/healthz')
    check(status == 200 and health == HEALTHY, f'GET /healthz -> {status} {health}')
    status, summary = get_json(base, '/api/summary')
    check(status == 200 and isinstance(summary, dict) and set(summary) == SUMMARY_KEYS,
          f'GET /api/summary -> {status} keys {sorted(summary or {})}')
    summary = summary or {}
    check(bool(HEX64.fullmatch(str(summary.get('db_digest')))) and bool(HEX64.fullmatch(str(summary.get('tree_digest')))),
          'summary digests are 64 hex characters')
    check(summary.get('signatures_valid') is True, 'summary.signatures_valid is true')
    status, db = get_json(base, '/api/db')
    db = db or {}
    items = [[i['id'], i['name'], i['sha256'], i['signature']] for i in db.get('items', [])]
    events = db.get('events', [])
    check(status == 200 and len(items) == summary.get('items') and len(events) == summary.get('events'),
          f'GET /api/db -> {status}, {len(items)} items, {len(events)} events')
    check(canonical_sha256({'items': items, 'events': events}) == summary.get('db_digest'),
          'summary.db_digest recomputed from /api/db matches')
    meta = summary.get('db_meta') or {}
    roles = {r[0]: r[1:] for r in meta.get('roles', [])}
    check(meta.get('user') == 'dirs_app' and roles.get('dirs') == [True, True] and roles.get('dirs_app') == [True, False],
          f'db_meta: connected as dirs_app; roles {meta.get("roles")}')
    check(meta.get('owners') == {'database:dirs': 'dirs', 'database:dirs_audit': 'dirs_app',
                                 'table:dirs.items': 'dirs_app', 'table:dirs_audit.events': 'dirs_app'},
          f'db_meta.owners {meta.get("owners")}')
    check(meta.get('server_major') == 16 and str(meta.get('system_identifier') or '').isdigit(),
          f'db_meta: PostgreSQL 16, cluster system identifier {meta.get("system_identifier")}')
    status, sqlite = get_json(base, '/api/sqlite')
    docs = (sqlite or {}).get('docs', [])
    check(status == 200 and summary.get('sqlite') == {'docs': len(docs), 'digest': canonical_sha256(docs)},
          f'summary.sqlite recomputed from /api/sqlite ({len(docs)} docs)')
    check(sorted([d[0], d[1], d[3]] for d in docs) == sorted([i[0], i[1], i[2]] for i in items),
          'SQLite docs and PostgreSQL items name the same ids, names and sha256')
    status, listing = get_json(base, '/api/tree')
    entries = (listing or {}).get('entries', [])
    check(status == 200 and len(entries) == summary.get('tree') and treelist.digest(entries) == summary.get('tree_digest'),
          f'GET /api/tree -> {status}, {len(entries)} entries, digest recomputed here matches the summary')
    tree_checks(entries)
    return summary, entries


def host_checks(entries):
    home = os.path.expanduser('~')
    data = os.path.join(home, DATA_REL)
    view = sh('podman', 'unshare', 'python3', '-I', TREELIST, data)
    report = json.loads(view.stdout) if view.returncode == 0 else {}
    check(view.returncode == 0 and report.get('digest') == treelist.digest(entries),
          f"owner user-namespace view of ~/{DATA_REL} equals the container's view "
          f'({report.get("count")} entries, digest {str(report.get("digest"))[:12]})')
    uids, gids = id_map('uid'), id_map('gid')
    check(uids and uids[0][:2] == (0, os.getuid()) and gids and gids[0][:2] == (0, os.getgid()),
          f'owner uid_map {uids} gid_map {gids}')
    expect = {DATA_REL: (0, 0o755), f'{DATA_REL}/www': (33, 0o750), PG_DIR_REL: (70, 0o700)}
    for rel, (cid, mode) in expect.items():
        st = os.stat(os.path.join(home, rel))
        uid, gid = host_id(uids, cid), host_id(gids, cid)
        check(st.st_uid == uid and st.st_gid == gid and st.st_mode & 0o7777 == mode,
              f'host view ~/{rel}: {st.st_uid}:{st.st_gid} {st.st_mode & 0o7777:04o} '
              f'(container {cid}:{cid} -> want {uid}:{gid} {mode:04o})')
    wal = sh('podman', 'unshare', 'stat', '-c', '%s %u', os.path.join(data, 'www/db/app.sqlite-wal'))
    size, owner = (wal.stdout.decode().split() + ['', ''])[:2]
    check(wal.returncode == 0 and size.isdigit() and int(size) > 0 and owner == '33',
          f'www/db/app.sqlite-wal exists, {size} bytes, owner {owner} (rows are in the WAL)')
    pg = sh('podman', 'unshare', 'stat', '-c', '%u:%g %a', os.path.join(home, PG_DIR_REL, 'PG_VERSION'))
    check(pg.returncode == 0 and pg.stdout.decode().split()[0] == '70:70',
          f'PostgreSQL files belong to container uid 70 ({pg.stdout.decode().strip()})')


def write_checks(base, before):
    payload = {'name': f'check-{os.urandom(3).hex()}', 'body': '寫入測試 𠮷 ✓\n' + os.urandom(8).hex()}
    status, body = http(base, 'POST', '/api/items', json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                        'application/json; charset=utf-8')
    item = json.loads(body) if status == 201 else {}
    check(status == 201 and item.get('name') == payload['name'], f'POST /api/items -> {status} id={item.get("id")}')
    _, after = get_json(base, '/api/summary')
    after = after or {}
    check(after.get('items') == before['items'] + 1 and after.get('events') == before['events'] + 1
          and after.get('sqlite', {}).get('docs') == before['sqlite']['docs'] + 1
          and after.get('tree_digest') != before['tree_digest'] and after.get('signatures_valid') is True,
          f'summary after the write: items {before["items"]}->{after.get("items")}, events {before["events"]}->'
          f'{after.get("events")}, tree {before["tree"]}->{after.get("tree")}')
    _, listing = get_json(base, '/api/tree')
    index = by_path((listing or {}).get('entries', []))
    doc, link = index.get(f'www/{item.get("path")}', {}), index.get(f'www/{item.get("archive")}', {})
    check(doc.get('uid') == 33 and doc.get('mode') == '0640' and (link.get('link') == doc.get('path')
                                                                  or doc.get('link') == link.get('path')),
          f'new doc {item.get("path")} belongs to uid 33 (0640) and has its archive/ hard link')
    status, _ = http(base, 'DELETE', f'/api/items/{item.get("id")}')
    _, final = get_json(base, '/api/summary')
    final = final or {}
    check(status == 200 and final.get('items') == before['items'] and final.get('events') == before['events'] + 2
          and final.get('sqlite', {}).get('docs') == before['sqlite']['docs'],
          f'DELETE /api/items/{item.get("id")} -> {status}; items back to {final.get("items")}, events +2')
    return final


def outage_checks(base):
    result = sh('podman', 'pause', 'woowbk-dirs-db')
    if not check(result.returncode == 0, 'podman pause woowbk-dirs-db'):
        return
    try:
        status, data = wait_health(base, 503, 90)
        check(status == 503 and data and not data['database'] and not data['audit_database'] and data['data_writable'],
              f'/healthz while the database is paused -> {status} {data}')
    finally:
        sh('podman', 'unpause', 'woowbk-dirs-db')
    status, data = wait_health(base, 200, 120)
    check(status == 200, f'/healthz after unpause -> {status} {data}')


def stop_start_checks(base, before):
    home = os.path.expanduser('~')
    stop = sh('systemctl', '--user', 'stop', *reversed(UNITS), timeout=300)
    check(stop.returncode == 0, 'systemctl --user stop woowbk-dirs-app.service woowbk-dirs-db.service')
    states = sh('systemctl', '--user', 'is-active', *UNITS).stdout.decode().split()
    check(states == ['inactive', 'inactive'], f'units after stop: {states}')
    gone = [c for c in CONTAINERS if sh('podman', 'container', 'exists', c).returncode != 0]
    check(gone == CONTAINERS, f'containers removed by Quadlet on stop: {gone}')
    kept = [rel for rel in (PG_DIR_REL, DATA_REL, ENV_REL) if os.path.lexists(os.path.join(home, rel))]
    check(kept == [PG_DIR_REL, DATA_REL, ENV_REL], f'host directories and the env file kept after stop: {kept}')
    kept = [s for s in SECRETS if sh('podman', 'secret', 'exists', s).returncode == 0]
    check(kept == SECRETS, f'secrets kept after stop: {kept}')
    status, _ = http(base, 'GET', '/healthz', timeout=5)
    check(status is None, f'/healthz unreachable while stopped ({status})')
    start = sh('systemctl', '--user', 'start', 'woowbk-dirs-app.service', timeout=600)
    check(start.returncode == 0, 'systemctl --user start woowbk-dirs-app.service (pulls in the database)')
    status, _ = wait_health(base, 200, 240)
    check(status == 200, f'/healthz after restart -> {status}')
    _, after = get_json(base, '/api/summary')
    check(after == before, f'summary after stop/start equals the one before: {after == before}')
    if after != before:
        print(json.dumps({k: [before.get(k), (after or {}).get(k)] for k in SUMMARY_KEYS
                          if before.get(k) != (after or {}).get(k)}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--url', default='http://127.0.0.1:18091')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--db-outage', action='store_true')
    parser.add_argument('--stop-start', action='store_true')
    args = parser.parse_args()
    if os.geteuid() == 0:
        sys.exit('check: run as the app owner, not root')
    summary, entries = read_only_checks(args.url)
    host_checks(entries)
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
