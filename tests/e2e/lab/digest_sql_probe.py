#!/usr/bin/env python3
"""Lab probe of the postgres-digest SQL against a real PostgreSQL (review findings H1, F2, F6, L4 of 2026-11-14).

Runs a throwaway `postgres:16-alpine` container through labpodman (with --memory) and checks the engine's own
`woowbackup.digests` SQL, exactly as the adapter runs it (psql -f -, PGOPTIONS, PGCLIENTENCODING=UTF8):

* H1: a table owner without superuser rights defines `CREATE CAST (victim AS text) WITH FUNCTION evil(victim)` whose
  function runs `COPY ... TO PROGRAM` and returns constant text. The pre-fix expression (`t::text`) runs it as the
  digest's superuser (the marker file appears); the engine's SQL does not.
* F2: a table with a column named `t`: the digest changes when any other column changes.
* Compatibility: for tables without a cast or a `t` column the engine's digest equals the pre-fix one.
* F6: a SQL_ASCII database holding a byte >= 0x80, and a LATIN1 database with a non-ASCII table name (equal to the same
  content in a UTF-8 database).

    python3 -I tests/e2e/lab/digest_sql_probe.py [evidence dir]

Prints one JSON object (checks with pass/fail) and writes it to <evidence dir>/digest-sql-probe.json.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'backup-engine'))
from woowbackup import digests  # noqa: E402

LP = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
NAME = 'woowbk-digest-sql-probe'
IMAGE = 'docker.io/library/postgres:16-alpine'
PRE_FIX = digests.TABLES_SQL.replace(digests._TABLE, digests._ROW.replace(
    "CASE WHEN pg_catalog.getdatabaseencoding() = 'SQL_ASCII' THEN 'SQL_ASCII' ELSE 'UTF8' END", "'UTF8'")
    .format(value='t::text').replace("'", "''")).replace('{oids}', '')

SETUP = """
CREATE ROLE app LOGIN PASSWORD 'probe-only';
CREATE DATABASE appdb OWNER app;
\\c appdb
SET ROLE app;
CREATE TABLE plain(id int, payload text);
INSERT INTO plain SELECT g, 'p' || g FROM generate_series(1, 5) g;
CREATE TABLE samples(id int, t timestamptz, payload text);
INSERT INTO samples SELECT g, '2026-01-01'::timestamptz + g * interval '1 hour', 'x' || g FROM generate_series(1, 5) g;
CREATE TABLE floats(f float8, m money, b bytea, j jsonb);
INSERT INTO floats VALUES (0.1 + 0.2, 12.34, '\\x00ff', '{"a": [1, 2]}');
CREATE TABLE victim(id int);
INSERT INTO victim VALUES (1), (2);
CREATE FUNCTION evil(victim) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE 'COPY (SELECT current_user || '' super='' || (SELECT rolsuper FROM pg_roles WHERE rolname = current_user))'
       || ' TO PROGRAM ''cat > /tmp/pwned''';
  RETURN 'constant';
END $$;
CREATE CAST (victim AS text) WITH FUNCTION evil(victim);
RESET ROLE;
CREATE DATABASE asciidb ENCODING 'SQL_ASCII' TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';
CREATE DATABASE latindb ENCODING 'LATIN1' TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';
CREATE DATABASE u8db;
"""


def lp(*args, input=None, check=True, env=()):
    argv = [LP, *args]
    proc = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    if check and proc.returncode != 0:
        raise RuntimeError(f'{" ".join(args[:4])}: {proc.stderr.decode(errors="replace")[-400:]}')
    return proc


def psql(database, sql, *, digest=False):
    env = ['-e', f'PGOPTIONS={digests.PG_OPTIONS}', '-e', 'PGCLIENTENCODING=UTF8'] if digest else []
    return lp('exec', '-i', *env, NAME, 'psql', '-X', '-w', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
              'postgres', '-d', database, '-f', '-', input=sql.encode(), check=False)


def digest(database, sql):
    proc = psql(database, digests.in_snapshot(sql), digest=True)
    if proc.returncode != 0:
        return None, proc.stderr.decode(errors='replace')[-300:]
    rows = json.loads(proc.stdout.decode('utf-8'))
    return {row[1]: row[3:] for row in rows}, None


def marker():
    proc = lp('exec', NAME, 'cat', '/tmp/pwned', check=False)
    lp('exec', NAME, 'rm', '-f', '/tmp/pwned', check=False)
    return proc.stdout.decode(errors='replace').strip() if proc.returncode == 0 else None


def main():
    evidence = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    checks = []

    def check(name, ok, detail=None):
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})

    lp('rm', '-f', NAME, check=False)
    lp('run', '-d', '--name', NAME, '--memory', '384m', '-e', 'POSTGRES_PASSWORD=probe-only', IMAGE)
    try:
        for _ in range(60):
            if lp('exec', NAME, 'pg_isready', '-h', '127.0.0.1', check=False).returncode == 0:
                break
            time.sleep(1)
        time.sleep(2)
        setup = psql('postgres', SETUP)
        check('setup (non-superuser table owner with a hostile cast, encodings)', setup.returncode == 0,
              setup.stderr.decode(errors='replace')[-300:])
        engine_sql = digests.tables_sql()
        # H1: the pre-fix expression runs the owner's cast function as the digest's superuser
        old, old_error = digest('appdb', PRE_FIX)
        written = marker()
        check('H1 before the fix: t::text ran the table owner\'s cast as superuser (COPY TO PROGRAM wrote the marker)',
              written is not None and 'super=true' in written, {'error': old_error, 'marker': written})
        new, new_error = digest('appdb', engine_sql)
        found = marker()
        check('H1 fixed: the engine\'s digest SQL does not run the cast', new is not None and found is None,
              {'error': new_error, 'marker': found})
        # compatibility: equal digests for every table without a cast or a column named t
        lp('exec', NAME, 'psql', '-X', '-q', '-U', 'postgres', '-d', 'appdb', '-c', 'DROP CAST (victim AS text)')
        old, _ = digest('appdb', PRE_FIX)
        new, _ = digest('appdb', engine_sql)
        same = {name: old[name] == new[name] for name in ('plain', 'floats', 'victim')}
        check('compatibility: tables without a cast or a t column give the same digest as before', all(same.values()),
              same)
        # F2: a column named t
        before, _ = digest('appdb', engine_sql)
        old_before, _ = digest('appdb', PRE_FIX)
        lp('exec', NAME, 'psql', '-X', '-q', '-U', 'postgres', '-d', 'appdb', '-c',
           "UPDATE samples SET id = id + 100, payload = 'changed'")
        after, _ = digest('appdb', engine_sql)
        old_after, _ = digest('appdb', PRE_FIX)
        check('F2 before the fix: t::text saw only the column t (digest unchanged)', old_before['samples'] == old_after['samples'])
        check('F2 fixed: the digest changes when other columns of a table with a column t change',
              before['samples'] != after['samples'], {'before': before['samples'], 'after': after['samples']})
        # F6: SQL_ASCII with a high byte, LATIN1 with a non-ASCII name equal to the same content in UTF-8
        psql('asciidb', "CREATE TABLE t1(v text); INSERT INTO t1 VALUES (E'caf\\xe9');")
        ascii_digest, ascii_error = digest('asciidb', engine_sql)
        check('F6: a SQL_ASCII database with a byte >= 0x80 is digested', ascii_digest is not None, ascii_error)
        for database in ('latindb', 'u8db'):
            lp('exec', '-i', '-e', 'PGCLIENTENCODING=UTF8', NAME, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
               'postgres', '-d', database, '-f', '-',
               input='CREATE TABLE "café"(v text); INSERT INTO "café" VALUES (\'naïve\');'.encode())
        latin, latin_error = digest('latindb', engine_sql)
        utf8, _ = digest('u8db', engine_sql)
        check('F6: LATIN1 names arrive as UTF-8 and equal the same content in a UTF-8 database',
              latin is not None and latin == utf8, {'latin1': latin, 'utf8': utf8, 'error': latin_error})
        check('L4: lc_monetary is pinned', '-c lc_monetary=C' in digests.PG_OPTIONS)
    finally:
        lp('rm', '-f', NAME, check=False)
    result = {'image': IMAGE, 'passed': sum(c['ok'] for c in checks), 'total': len(checks), 'checks': checks}
    text = json.dumps(result, ensure_ascii=False, indent=1)
    print(text)
    if evidence is not None:
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / 'digest-sql-probe.json').write_text(text + '\n')
    return 0 if result['passed'] == result['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
