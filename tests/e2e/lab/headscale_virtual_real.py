#!/usr/bin/env python3
"""HS-15: installed root-started SQLite child on isolated dev-d, with generated virtual-table extras.

  python3 -I tests/e2e/lab/headscale_virtual_real.py --run

This is generated database evidence, not an original HA-backup or complete service acceptance run. It changes only
the installed lab engine and private temporary files; the shared dev-d mutation lock and isolation checks apply.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CODE = r'''
import hashlib, json, os, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
from woowbackup import hasqlite
assert os.geteuid() == 0
assert hashlib.sha256(Path(hasqlite.__file__).read_bytes()).hexdigest() == sys.argv[1]
with tempfile.TemporaryDirectory(prefix='hs15-virtual-') as folder:
    root = Path(folder)
    for variant in ('known', 'unavailable'):
        case = root / variant
        case.mkdir(mode=0o700)
        for file, prefix in (('ha', 'ha'), ('live', 'mine')):
            with sqlite3.connect(case / file) as db:
                db.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT); "
                                 "INSERT INTO users(name) VALUES ('alice'); "
                                 "CREATE TABLE api_keys(id INTEGER PRIMARY KEY, prefix TEXT, hash BLOB, "
                                 "expiration DATETIME, last_seen DATETIME, created_at DATETIME);")
                db.execute('INSERT INTO api_keys(prefix,hash) VALUES (?,?)', (prefix, b'generated-test-value'))
        with sqlite3.connect(case / 'ha') as db:
            db.executescript("CREATE VIRTUAL TABLE extra USING fts5(body); "
                             "INSERT INTO extra VALUES ('only in source'); "
                             "CREATE VIEW foreign_view AS SELECT * FROM extra; "
                             "CREATE TRIGGER foreign_trigger AFTER DELETE ON api_keys BEGIN DELETE FROM users; END;")
            if variant == 'unavailable':
                db.execute('PRAGMA writable_schema=ON')  # Test fixture only: product never edits sqlite_master.
                db.execute("UPDATE sqlite_master SET sql='CREATE VIRTUAL TABLE extra USING unavailable_module(body)' "
                           "WHERE name='extra'")
            db.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='users'")
        original = hashlib.sha256((case / 'ha').read_bytes()).hexdigest()
        (case / 'out').mkdir()
        result = hasqlite.run([{'db':'ha.sqlite', 'check':'integrity', 'schema':True,
                               'rebuild_from':'live.sqlite', 'rebuild_tables':['users','api_keys'],
                               'strip_extra_from':'live.sqlite', 'replace_api_keys_from':'live.sqlite'}],
                              {'ha.sqlite':case / 'ha', 'live.sqlite':case / 'live'},
                              case / 'work', outputs=('ha.sqlite',), out_dir=case / 'out')
        answer = result['ha.sqlite']
        assert hasqlite.problem(answer) is None
        assert answer['rebuilt'] is True and answer['original_schema']['virtual'] == ['extra']
        assert not answer['schema']['virtual'] and not answer['schema']['views'] and not answer['schema']['triggers']
        with sqlite3.connect(result[None]['ha.sqlite']) as db:
            assert db.execute('SELECT id,name FROM users').fetchall() == [(1,'alice')]
            assert db.execute('SELECT prefix FROM api_keys').fetchall() == [('mine',)]
            assert db.execute("SELECT seq FROM sqlite_sequence WHERE name='users'").fetchone()[0] == 99
            assert not db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'extra%'").fetchall()
        assert hashlib.sha256((case / 'ha').read_bytes()).hexdigest() == original
        assert not (case / 'work').exists()
    print(json.dumps({'stage':'headscale_virtual_child','variants':2,'passed':True,
                      'originals_unchanged':True,'root_started_isolated_child':True}))
assert not root.exists()
'''


def main():
    if sys.argv[1:] == ['--self-check']:
        compile(CODE, '<headscale-virtual-device>', 'exec')
        print('headscale virtual child self-check: PASS')
        return 0
    if sys.argv[1:] != ['--run']:
        raise SystemExit('Usage: headscale_virtual_real.py --run|--self-check')
    guard = load('hs15_guard', 'dev_d_guard.py')
    drv = load('hs15_driver', 'ha_import_e2e.py')
    drv.DEVICE = 'woowbk-dev-d'
    if not guard.clean_tree(REPO)[0]:
        raise RuntimeError('commit_source_first')
    print('source commit ' + guard.head(REPO), flush=True)
    fd, _ = guard.acquire()
    started = time.monotonic()
    try:
        print(guard.verify_isolation(HERE / 'owner.sh'), flush=True)
        deploy = subprocess.run(['bash', str(HERE / 'deploy-src.sh'), 'd', '--src', str(REPO), '--no-demo-catalog'],
                                capture_output=True, timeout=600)
        if deploy.returncode:
            raise RuntimeError('lab_engine_deployment_failed')
        digest = hashlib.sha256((REPO / 'backup-engine/woowbackup/hasqlite.py').read_bytes()).hexdigest()
        result = drv.root('python3', '-I', '-c', CODE, digest, timeout=180)
        if result.returncode:
            raise RuntimeError('installed_child_probe_failed')
        event = json.loads(result.stdout)
        if event != {'stage':'headscale_virtual_child', 'variants':2, 'passed':True,
                     'originals_unchanged':True, 'root_started_isolated_child':True}:
            raise RuntimeError('unexpected_child_result')
        print(json.dumps(event), flush=True)
        print('Headscale virtual child: PASS', flush=True)
    finally:
        try:
            print(guard.verify_isolation(HERE / 'owner.sh'), flush=True)
        finally:
            os.close(fd)
            print('lock held for ' + str(int(time.monotonic() - started)) + ' s', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
