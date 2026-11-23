#!/usr/bin/env python3
"""Read-only probe of a REAL HA Nextcloud backup's database shape (lab only, never acceptance).

What it does, exactly like the product's check does it, but in a throwaway labpodman container on the host's lab storage
instead of inside a lab device:
  1. the fixture's SHA-256 equals the recorded one (the facts file of the run);
  2. HA's PostgreSQL cluster (`data/postgres` of the add-on member) is streamed from the encrypted backup (habackup;
     the HA key comes from the lab secret files through the harness reader and is never printed) into a throwaway
     volume by ha_odoo.PgSink: HA's configuration files replaced by known ones, recovery and pid files dropped;
  3. postgres:16-alpine opens it with ha_odoo.ha_server_args() (no library, no command, socket only), network none,
     read-only root, the data volume noexec/nosuid/nodev, no capability;
  4. ha_nextcloud.SHAPE_SQL (pinned: PGOPTIONS search_path=pg_catalog) and the entry kinds of a pg_dump of the
     Nextcloud database (pg_restore -l, kinds and counts only) are read;
  5. the container and the volume are removed (finally), and their absence is checked.
stdout: fixed lines only (`<check>: PASS|FAIL`, the source commit). The evidence JSON holds counts and kinds only:
no table, role or object name, no value of any row (the column default expressions that are not constants would be
listed, at most 10, 120 characters each: they are schema text).
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / 'backup-engine'))
sys.path.insert(0, str(HERE))

import nextcloud_flow as nf  # noqa: E402  (the lab secret readers; nothing is printed)
from woowbackup import habackup, ha_nextcloud as nc, ha_odoo  # noqa: E402

LABPODMAN = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
IMAGE = 'docker.io/library/postgres:16-alpine'
PG_UID = 70          # postgres in the alpine image
LABEL = 'woowbk.lab=nextcloud-shape-probe'


def lp(*args, input=None, timeout=300):
    return subprocess.run([LABPODMAN, *args], input=input, capture_output=True, timeout=timeout)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def emit(line):
    print(line, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--facts', required=True, help='the facts JSON of the share run (fixture path, sha256)')
    parser.add_argument('--out', required=True, help='evidence JSON (counts and kinds only)')
    args = parser.parse_args()
    started = time.monotonic()
    facts = json.loads(Path(args.facts).read_text(encoding='utf-8'))
    fixture = Path(facts['fixture'])
    commit = subprocess.run(['git', '-C', str(REPO), 'rev-parse', '--short', 'HEAD'], capture_output=True,
                            text=True).stdout.strip()
    emit(f'source commit {commit}')
    doc = {'kind': 'nextcloud-shape-probe', 'date': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'source_commit': commit,
           'fixture_sha256': facts['sha256'], 'image': IMAGE, 'acceptance': 'not acceptance (read-only probe)',
           'checks': {}}
    checks = doc['checks']

    def check(name, ok):
        checks[name] = 'PASS' if ok else 'FAIL'
        emit(f'{name}: {checks[name]}')
        return ok

    if not check('fixture sha256 equals the recorded one', sha256_file(fixture) == facts['sha256']):
        return write(args, doc, started, 2)
    name = 'woowbk-ncprobe-' + time.strftime('%Y%m%dT%H%M%S')
    try:
        code = probe(fixture, name, doc, check)
    finally:
        lp('rm', '-f', '-t', '10', name, timeout=120)
        lp('volume', 'rm', '-f', name, timeout=120)
        gone = lp('container', 'exists', name).returncode != 0 and lp('volume', 'exists', name).returncode != 0
    if not check('cleanup: the throwaway container and volume are gone', gone):
        code = 1
    return write(args, doc, started, code)


def probe(fixture, name, doc, check):
    key = nf.drv.Secrets(nf.SECRET_FILES, nf.MARKERS)['HA_BACKUP_KEY']
    if lp('volume', 'create', '--label', LABEL, name).returncode != 0:
        check('throwaway volume created', False)
        return 1
    proc = subprocess.Popen([LABPODMAN, 'volume', 'import', name, '-'], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sink = ha_odoo.PgSink(proc.stdin, PG_UID, PG_UID)
    dbname, pg_files = None, 0
    select = habackup.Select(include=(nc.PG_PREFIX, nc.CONFIG_PHP), symlinks=(), hardlinks=False)
    with habackup.open_member(str(fixture), f'{nc.SLUG}.tar.gz', password=key) as stream:
        for entry in habackup.iter_entries(stream, select, habackup.Report()):
            if entry.name == nc.CONFIG_PHP and entry.kind == 'file':
                config = nc.parse_config(entry.read_all(nc.MAX_CONFIG))
                nc.mask_config(config)
                dbname = config.get('dbname') if isinstance(config, dict) else None
            elif nc._under(entry.name, nc.PG_PREFIX):
                rel = entry.name[len(nc.PG_PREFIX) + 1:] if entry.name != nc.PG_PREFIX else '.'
                pg_files += entry.kind == 'file'
                sink.add(rel, entry)
    sink.close()
    proc.stdin.close()
    imported = proc.wait(timeout=900) == 0
    doc['pg_files'] = pg_files
    if not check('HA cluster streamed into the throwaway volume', imported and pg_files > 0
                 and isinstance(dbname, str) and nc.DB_RE.fullmatch(dbname) is not None):
        return 1
    run = lp('run', '-d', '--name', name, '--label', LABEL, '--network', 'none', '--read-only', '--cap-drop', 'all',
             '--security-opt', 'no-new-privileges', '--user', f'{PG_UID}:{PG_UID}',
             '--volume', f'{name}:{ha_odoo.HA_DATA}:rw,noexec,nosuid,nodev', IMAGE, *ha_odoo.ha_server_args())
    if not check('throwaway PostgreSQL 16 started (network none, read-only root)', run.returncode == 0):
        return 1
    ready = False
    for _ in range(120):
        if lp('exec', '--user', str(PG_UID), name, 'pg_isready', '-q', '-U', 'postgres', timeout=60).returncode == 0:
            ready = True
            break
        time.sleep(1)
    if not check('throwaway PostgreSQL ready', ready):
        return 1
    pinned = ['exec', '-i', '--user', str(PG_UID), '--env', f'PGOPTIONS={nc.PINNED_OPTIONS}', name]
    out = lp(*pinned, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', dbname,
             '-f', '-', input=nc.SHAPE_SQL.encode(), timeout=600)
    try:
        shape = json.loads(out.stdout.decode('utf-8').strip()) if out.returncode == 0 else None
    except ValueError:
        shape = None
    problems = nc.shape_problems(shape)
    doc['shape'] = {k: v for k, v in (shape or {}).items() if k != 'defaults'}
    doc['defaults_count'] = len((shape or {}).get('defaults') or [])
    doc['odd_defaults'] = [str(d)[:120] for d in (shape or {}).get('defaults') or []
                           if not isinstance(d, str) or not nc.DEFAULT_RE.fullmatch(d)][:10]
    doc['shape_problems'] = problems
    check('shape: nothing beyond Nextcloud\'s own tables, sequences and indexes', problems == [])
    dump = lp(*pinned, 'sh', '-c', 'pg_dump -U postgres -Fc -d "$1" | pg_restore -l', 'sh', dbname, timeout=1800)
    counts = {}
    for line in dump.stdout.decode('utf-8', 'surrogateescape').splitlines():
        kinds = nc.toc_kinds(line)
        if kinds:
            counts[kinds[0]] = counts.get(kinds[0], 0) + 1
    doc['toc_kinds'] = dict(sorted(counts.items()))
    check('toc: the dump lists entries', dump.returncode == 0 and bool(counts))
    check('toc: every kind is one Nextcloud creates (TOC_ALLOWED)', bool(counts)
          and all(k in nc.TOC_ALLOWED for k in counts))
    return 0 if all(v == 'PASS' for v in doc['checks'].values()) else 1


def write(args, doc, started, code):
    doc.update(exit=code, elapsed_s=round(time.monotonic() - started, 1))
    Path(args.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    sys.exit(main())
