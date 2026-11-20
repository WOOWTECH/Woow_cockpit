"""Opt-in isolated synthetic PG18 -> PG17 data-only experiment; NOT an importer.

This script accepts ONLY already-loaded immutable image IDs. Run only in an approved
lab slot after checking headroom for two 128 MiB containers. The source is created here
from fixed SQL, with no HA backup, real credentials, mounts or network. The target uses
separately authored fixed schema and an unprivileged loader. It is not a generic dump
sanitizer and must never be pointed at untrusted or production data.
"""
import argparse
import datetime
import json
import re
import secrets

from woowbackup import ha_litellm_candidate as candidate, ha_odoo, tempctr
from litellm_version_candidate import DevDRunner

MAX_DUMP = 1024 * 1024
FORBIDDEN_DDL = re.compile(rb'^\s*(?:CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|DO|CALL)\b', re.I | re.M)
SCHEMA = ('CREATE TABLE public.synthetic_rows (id bigint PRIMARY KEY, label text NOT NULL);\n')
ROWS_SQL = "SELECT coalesce(json_agg(json_build_array(id,label) ORDER BY id), '[]'::json) FROM public.synthetic_rows"
COLUMNS_SQL = """SELECT coalesce(json_agg(json_build_array(column_name,data_type,is_nullable) ORDER BY ordinal_position),
'[]'::json) FROM information_schema.columns WHERE table_schema='public' AND table_name='synthetic_rows'"""


def synthetic_dump_ok(data):
    """Lab fixture check only; not a security boundary for arbitrary pg_dump output."""
    return (isinstance(data, bytes) and 0 < len(data) <= MAX_DUMP and not FORBIDDEN_DDL.search(data)
            and b'INSERT INTO public.synthetic_rows' in data)


def checked_major(cluster, expected):
    major = cluster.query_json("SELECT to_json(current_setting('server_version_num')::int / 10000)", 'litellm')
    if type(major) is not int or major != expected:
        raise RuntimeError('Unexpected PostgreSQL major in isolated lab')
    return major


def start_cluster(tmp, role, volume, image, major):
    tmp.volume(volume)
    mount = '/var/lib/postgresql' if major == 18 else '/var/lib/postgresql/data'
    pgdata = '/var/lib/postgresql/18/docker' if major == 18 else '/var/lib/postgresql/data/pgdata'
    tmp.run(role, image, ['postgres', '-c', 'shared_buffers=16MB', '-c', 'max_connections=20'],
            detach=True, read_only_root=True,
            volumes=[(tmp.name(volume), mount, 'rw,noexec,nosuid,nodev')],
            env={'POSTGRES_HOST_AUTH_METHOD': 'trust', 'POSTGRES_DB': 'litellm',
                 'PGDATA': pgdata})
    cluster = ha_odoo.Cluster(tmp, role)
    cluster.wait_ready(tcp=True, timeout=120)
    return cluster


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pg18-image-id', required=True)
    parser.add_argument('--pg17-image-id', required=True)
    args = parser.parse_args()
    if not all(candidate._IMAGE_ID.fullmatch(value) for value in (args.pg18_image_id, args.pg17_image_id)):
        raise SystemExit('Full already-loaded image IDs are required')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job = 'j' + stamp + '-' + secrets.token_hex(4)
    notes = []
    cases = {}
    with tempctr.TempObjects(DevDRunner(), job, memory='128m', pids=128, cpus=None, log=notes.append) as tmp:
        source = start_cluster(tmp, 'litellm-pg18', 'litellm-pg18-data', args.pg18_image_id, 18)
        target = start_cluster(tmp, 'litellm-pg17', 'litellm-pg17-data', args.pg17_image_id, 17)
        checked_major(source, 18)
        checked_major(target, 17)
        source.script(SCHEMA + "INSERT INTO public.synthetic_rows VALUES (1, 'fixture alpha'), (2, 'fixture beta');\n",
                      'litellm')
        # The destination schema is fixed independently, never derived from source DDL.
        target.script(SCHEMA + 'CREATE ROLE woowbk_fixture_loader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;\n'
                      'GRANT USAGE ON SCHEMA public TO woowbk_fixture_loader;\n'
                      'GRANT INSERT ON public.synthetic_rows TO woowbk_fixture_loader;\n', 'litellm')
        before_schema = target.query_json(COLUMNS_SQL, 'litellm')
        dump = tmp.exec('litellm-pg18', ['pg_dump', '-U', 'postgres', '-d', 'litellm', '--data-only',
                                         '--table=public.synthetic_rows', '--inserts', '--column-inserts',
                                         '--no-owner', '--no-acl'], user='postgres', timeout=120,
                        max_output=MAX_DUMP).stdout or b''
        cases['synthetic_data_only_dump'] = synthetic_dump_ok(dump)
        if not cases['synthetic_data_only_dump']:
            raise RuntimeError('Synthetic dump did not meet the lab fixture restriction')
        tmp.exec('litellm-pg17', ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U',
                                   'woowbk_fixture_loader', '-d', 'litellm', '-f', '-'], user='postgres',
                 input=dump, timeout=120, max_output=4096)
        cases['trusted_schema_unchanged'] = before_schema == target.query_json(COLUMNS_SQL, 'litellm')
        cases['synthetic_rows_equal'] = source.query_json(ROWS_SQL, 'litellm') == target.query_json(ROWS_SQL, 'litellm')
        cases['loader_non_superuser'] = target.query_json(
            "SELECT to_json(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole) FROM pg_roles "
            "WHERE rolname='woowbk_fixture_loader'", 'litellm') is True
    print(json.dumps({'scope': 'synthetic PG18 to PG17 fixed schema and data only; not HA acceptance',
                      'source_major': 18, 'target_major': 17, 'cases': cases,
                      'cleanup_notes': len(notes), 'conversion': 'disabled'}, sort_keys=True))
    return 0 if len(cases) == 4 and all(cases.values()) and not notes else 1


if __name__ == '__main__':
    raise SystemExit(main())
