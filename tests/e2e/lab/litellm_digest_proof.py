#!/usr/bin/env python3
"""Lab proof (lane litellm-product, 2026-11-24) of the table digest (`postgres-digest`) the suggested LiteLLM entry has, on
real PostgreSQL 17.11 (the package's image, 094ecc9c) holding LiteLLM 1.104.0's real tables: its 189 Prisma migrations
(the wheel of litellm-proxy-extras 0.4.102.post1, given by path, hashed into the result) plus `_prisma_migrations` and two
woow_platform tables shaped like the WOOWTECH image's. Rows are generated (no backup, no secret). Throwaway containers of
the isolated LAB Podman store only, --network=none, removed at the end; nothing of dev-d or the host is used.

The steps are the PRODUCT's own adapter code against those servers: what a safety backup does with the proxy stopped (the
digest read, `pg_dump -Fc` with its full read, the digest read again: kept only when equal), what a rollback does (a
fresh cluster, `pg_restore --single-transaction --no-owner --no-privileges`, the digest compared before the app starts),
and the same comparison after one value changed and after one row is gone (it must then fail, naming the table).

  python3 -I tests/e2e/lab/litellm_digest_proof.py --wheel FILE [--rows N] [--spend N] > postgres-digest-proof.json

Prints one JSON document (counts, seconds, matches; no row content). NOT the real run: dev-d with the product flow and
the real database must still prove it (tests/e2e/lab/evidence/litellm-product-20261123/README.md, Iteration 5).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))
sys.path.insert(0, str(HERE))

import litellm_sandbox_review as review  # noqa: E402
from woowbackup import digests, ha_odoo, tempctr  # noqa: E402
from woowbackup.adapters import quadlet_postgres as qp  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402

SPEC = {'id': 'db-main', 'type': 'postgres-digest', 'postgres': 'main', 'container': None, 'unit': None, 'user': None,
        'databases': ['litellm'], 'exclude_tables': [], 'label': 'PostgreSQL 資料表內容'}
EXTRA = '''
CREATE TABLE public."_prisma_migrations" (id varchar(36) PRIMARY KEY, checksum varchar(64) NOT NULL,
  finished_at timestamptz, migration_name varchar(255) NOT NULL, logs text, rolled_back_at timestamptz,
  started_at timestamptz NOT NULL DEFAULT now(), applied_steps_count integer NOT NULL DEFAULT 0);
CREATE SCHEMA woow_platform;
CREATE TABLE woow_platform.settings (key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz DEFAULT now());
CREATE TABLE woow_platform.chatgpt_accounts (id text PRIMARY KEY, email text, data jsonb, expires_at timestamptz);
'''
COLUMNS = '''SELECT coalesce(json_agg(json_build_array(n.nspname, c.relname, a.attname, t.typname, t.typtype::text,
  t.typcategory::text, pg_catalog.format_type(a.atttypid, a.atttypmod), coalesce(e.typname, ''), coalesce(e.typtype::text, ''))
  ORDER BY n.nspname, c.relname, a.attnum), '[]'::json)
FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
LEFT JOIN pg_catalog.pg_type e ON e.oid = t.typelem AND t.typcategory = 'A'
WHERE n.nspname IN ('public', 'woow_platform') AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
  AND a.attgenerated = \'\''''
VALUES = {
    'text': "'row ' || g || ' 中文 \\ \"q\" ' || chr(9) || chr(10) || repeat('x', g % 50)",
    'bool': 'g % 2 = 0', 'int2': '(g % 30000)::int2', 'int4': 'g::int4', 'int8': '(9000000000 + g)::int8',
    'float8': "CASE g % 6 WHEN 0 THEN 'NaN'::float8 WHEN 1 THEN 0.1 WHEN 2 THEN 1e-300 WHEN 3 THEN 123456789.123456789 "
              'ELSE g / 7.0 END',
    'float4': '(g / 3.0)::float4', 'numeric': '(g / 3.0)::numeric',
    'jsonb': "jsonb_build_object('n', g, 't', '中文 \"q\" \\', 'f', 0.1 + g, 'l', jsonb_build_array(1, NULL, true))",
    'json': "json_build_object('n', g, 't', '中文')",
    'timestamp': "timestamp '2026-11-05 01:02:03.456' + g * interval '1 day 1.001 second'",
    'timestamptz': "timestamptz '2026-11-05 01:02:03.456+08' + g * interval '1 day 1.001 second'",
    'date': "date '2026-11-05' + (g % 400)::int", 'uuid': 'md5(g::text)::uuid', 'bytea': "decode(md5(g::text), 'hex')",
}


def expression(column):
    """A generated value of one column: deterministic in g, many shapes a text round trip could damage."""
    _schema, _table, _name, typname, typtype, category, shown, elem, elem_type = column
    if category == 'A':
        if elem_type == 'e':
            return f'ARRAY[(enum_range(NULL::public."{elem}"))[1]]'
        if elem in ('text', 'varchar'):
            return "ARRAY['a', 'b,c', NULL, '\"d\"', '{e}', '中文 ' || g]"
        return f'ARRAY[{VALUES[elem]}]'
    if typtype == 'e':
        return f'(enum_range(NULL::public."{typname}"))[1 + g % array_length(enum_range(NULL::public."{typname}"), 1)]'
    if typname == 'varchar':
        limit = int(shown.split('(')[1].rstrip(')')) if '(' in shown else 0
        return f'left(md5(g::text) || g, {limit})' if limit else VALUES['text']
    return VALUES[typname]


class Adapter(qp.QuadletPostgresAdapter):
    """The product adapter on lab containers: only its runner, its log and the app differ."""


def make(app, log):
    return Adapter(app, review.LabRunner(), log)


def app_for(container):
    return types.SimpleNamespace(id='litellm', name='LiteLLM', verify=[dict(SPEC)], volumes=[], data_dirs=[], secrets=[],
                                 config_files=[], units=[], writer_units=[], quadlet_files=[], health=[],
                                 postgres=[{'id': 'main', 'container': container, 'unit': 'litellm-postgres.service',
                                            'database': 'litellm', 'user': 'litellm', 'scope': 'database',
                                            'data_volume': 'litellm-pgdata'}])


def start(tmp, role):
    tmp.volume(role)
    tmp.run(role, review.PG17, [], detach=True, volumes=[(tmp.name(role), '/var/lib/postgresql/data', 'rw')],
            env={'POSTGRES_USER': 'litellm', 'POSTGRES_DB': 'litellm', 'POSTGRES_HOST_AUTH_METHOD': 'trust',
                 'PGDATA': '/var/lib/postgresql/data/pgdata'})
    cluster = ha_odoo.Cluster(tmp, role, superuser='litellm')
    cluster.wait_ready(tcp=True)
    return cluster


def fill(cluster, wheel, rows, spend):
    """LiteLLM's schema from its own migrations, then generated rows in every table; {schema.table: rows}."""
    with zipfile.ZipFile(wheel) as archive:
        names = sorted(n for n in archive.namelist() if n.startswith('litellm_proxy_extras/migrations/')
                       and n.endswith('/migration.sql'))
        sql = '\n'.join(archive.read(n).decode('utf-8') + ';' for n in names)
    run_file(cluster, sql)
    run_file(cluster, EXTRA)
    columns = cluster.query_json(COLUMNS, 'litellm')
    tables = {}
    for column in columns:
        tables.setdefault((column[0], column[1]), []).append(column)
    script = ["SET session_replication_role = replica;"]  # generated rows need not satisfy the foreign keys
    for (schema, table), cols in sorted(tables.items()):
        listed = ', '.join(f'"{c[2]}"' for c in cols)
        values = ', '.join(expression(c) for c in cols)
        n = spend if table == 'LiteLLM_SpendLogs' else rows
        script.append(f'INSERT INTO "{schema}"."{table}" ({listed}) SELECT {values} FROM generate_series(1, {n}) g '
                      'ON CONFLICT DO NOTHING;')
    run_file(cluster, '\n'.join(script))
    return len(names), columns


def run_file(cluster, sql):
    cluster.tmp.exec(cluster.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'litellm', '-d', 'litellm', '-f',
                                    '-'], user='postgres', input=sql.encode('utf-8'), timeout=1800,
                     max_output=1024 * 1024)


def compared(adapter, manifest, root, work):
    """(match or None, the first difference named or '') of the product's comparison."""
    adapter.digest_results = []
    work.mkdir(mode=0o700)
    try:
        adapter._verify_digests(manifest, root, work, 'postgres-digest')
        return adapter.digest_results[0]['match'], ''
    except BackupError as error:
        found = adapter.digest_results[0].get('differences') or {}
        sample = (found.get('samples') or [{}])[0]
        return adapter.digest_results[0]['match'], f'{sample.get("item", "")}: {sample.get("detail", "")} [{error.code}]'


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--wheel', required=True)
    parser.add_argument('--rows', type=int, default=40)
    parser.add_argument('--spend', type=int, default=20000)
    args = parser.parse_args(argv)
    wheel = Path(args.wheel)
    out = {'case': 'postgres-digest on LiteLLM 1.104.0 tables', 'image_pg17': review.PG17,
           'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(), 'rows_per_table': args.rows,
           'spend_rows': args.spend, 'source': review.source_state(),
           'product_sha256': {name: hashlib.sha256((HERE.parents[2] / 'backup-engine/woowbackup' / name).read_bytes())
                              .hexdigest() for name in ('digests.py', 'adapters/quadlet_postgres.py')}}
    runner = review.LabRunner()
    logs = []
    with tempfile.TemporaryDirectory(prefix='litellm-digest-') as scratch, \
            tempctr.TempObjects(runner, review.job_id('digest'), memory='512m', pids=256, cpus='1') as tmp:
        base = Path(scratch)
        cluster = start(tmp, 'pga')
        out['server'] = cluster.query_json("SELECT to_json(current_setting('server_version'))", 'litellm')
        migrations, columns = fill(cluster, wheel, args.rows, args.spend)
        out['migrations_applied'] = migrations
        out['column_types'] = sorted({c[3] for c in columns})
        app = app_for(tmp.name('pga'))
        adapter = make(app, logs.append)
        staging = base / 'apps' / 'litellm'
        for name in ('verify', 'postgres'):
            (staging / name).mkdir(mode=0o700, parents=True)
        started = time.monotonic()
        first = adapter._capture_digests(adapter.digest_specs('postgres-digest'), staging / 'verify', suffix='.first')
        out['digest_seconds'] = round(time.monotonic() - started, 2)
        started = time.monotonic()
        dump = adapter._dump_database(app.postgres[0], staging)
        out['dump_seconds'] = round(time.monotonic() - started, 2)
        adapter.unstable_digests = []
        kept = adapter._confirm_digests(adapter.digest_specs('postgres-digest'), first, staging / 'verify', 'changed')
        out['two_reads_equal'] = list(kept) == ['db-main'] and not adapter.unstable_digests
        record = kept['db-main']
        out['summary'] = record['summary']
        out['bytes'] = {'dump': os.path.getsize(dump['file']), 'listing': os.path.getsize(record['file'])}
        item = adapter._digest_manifest(SPEC, record, 'apps/litellm/verify/db-main.txt')
        manifest = {'id': 'litellm', 'verify_digests': [item]}
        tmp.stop('pga', timeout=60)
        tmp.remove('pga')
        tmp.remove_volume('pga')

        target = start(tmp, 'pgb')          # a fresh cluster, as a restore starts it
        app_b = app_for(tmp.name('pgb'))
        back = make(app_b, logs.append)
        started = time.monotonic()
        back._restore_database(app_b.postgres[0], dump['file'])
        out['restore_seconds'] = round(time.monotonic() - started, 2)
        out['after_restore'] = compared(back, manifest, base, base / 'w1')
        run_file(target, 'SET session_replication_role = replica; UPDATE public."LiteLLM_UserTable" SET spend = spend + 1e-9 '
                         'WHERE ctid = (SELECT min(ctid) FROM public."LiteLLM_UserTable" WHERE spend = 0.1);')
        out['after_one_value_changed'] = compared(back, manifest, base, base / 'w2')
        run_file(target, 'SET session_replication_role = replica; UPDATE public."LiteLLM_UserTable" SET spend = 0.1 '
                         'WHERE spend = 0.1::float8 + 1e-9;')
        out['after_setting_it_back'] = compared(back, manifest, base, base / 'w4')
        run_file(target, 'SET session_replication_role = replica; DELETE FROM public."LiteLLM_VerificationToken" WHERE ctid = '
                         '(SELECT min(ctid) FROM public."LiteLLM_VerificationToken");')
        out['after_one_row_removed'] = compared(back, manifest, base, base / 'w3')
        tmp.remove('pgb')
        tmp.remove_volume('pgb')
    out['containers_left'] = [n for n in (runner.podman('ps', '-a', '--format', '{{.Names}}').stdout or b'').decode(
        ).split() if n.startswith('woowbk-j') and n.rsplit('-', 1)[-1] in ('pga', 'pgb')]
    out['ok'] = bool(out['two_reads_equal'] and out['after_restore'][0] is True
                     and out['after_one_value_changed'][0] is False
                     and 'LiteLLM_UserTable' in out['after_one_value_changed'][1]
                     and out['after_setting_it_back'][0] is True and out['after_one_row_removed'][0] is False
                     and 'LiteLLM_VerificationToken' in out['after_one_row_removed'][1] and not out['containers_left'])
    print(json.dumps(out, ensure_ascii=False, indent=1, sort_keys=True))
    return 0 if out['ok'] else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
