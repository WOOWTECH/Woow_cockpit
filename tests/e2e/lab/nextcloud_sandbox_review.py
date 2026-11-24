#!/usr/bin/env python3
"""Nextcloud HA import, self review (2026-11-24): malicious HA PostgreSQL 16 clusters against the REAL product code
(ha_nextcloud.scan_member/PgSink -> tempctr volume import -> ha_odoo.start_ha_cluster with Pinned, ha_database, pg_dump,
build_cluster: restore_dump, SHAPE_SQL, fix-ups, verify_converted) in throwaway ROOTLESS containers of the isolated lab
Podman store (~/.woowbk-lab/bin/labpodman: its own storage root; production containers and images are invisible to it),
every container with --network=none (tempctr's default), PostgreSQL 16 only. This device's "live" database is a throwaway
PostgreSQL 16 laid out like Nextcloud's installer leaves it (superuser `nextcloud`, role `oc_admin` with CREATEDB).

  python3 -I tests/e2e/lab/nextcloud_sandbox_review.py <evidence.json> [case ...]

Cases:
  clean             an honest cluster converts and verifies (the control of every other case).
  team_folders      an honest cluster with a Team folder's own storage below the data directory and a local external
                    storage: the first row gets this device's path and keeps its number, the second stays.
  T1, HA's NON-superuser database owner `nextcloud` (a compromised Nextcloud in HA) planted objects:
    owner_trojan    public.json_agg(name) aggregate (search-path trojan) and a per-database search_path.
    owner_view      oc_appconfig replaced by a view over a plpgsql function.
    owner_trigger   a trigger, a rule and a function default on the tables the conversion changes.
  T2, a crafted data directory (its superuser, or a patched catalog): the built-in pg_get_indexdef lies, so every INDEX entry
  of the dump holds the SQL the attacker wants; the dump's list shows allowed kinds only and the check sees nothing:
    hidden_trigger, hidden_aggregate, hidden_database (COMMIT, then CREATE DATABASE), hidden_role_setting, hidden_password,
    hidden_grant, hidden_default, hidden_rule, hidden_rls, hidden_statistics.
  T3, live_trojan   this device's own Nextcloud role planted public.json_agg(name) on the LIVE database.
Attacker code runs as the engine's superuser only if the product lets it: it then writes a marker inside its throwaway
container (/tmp/woowbk-review-*.txt through COPY TO PROGRAM, refused for everyone else); markers are read before anything is
removed. Where it makes sense a control shows that the attack works without the product's defence. Output: one JSON document of
fixed facts (no data value, no secret: the only password is generated per run and never printed)."""
import datetime
import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for entry in (str(REPO / 'backup-engine'), str(HERE)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import litellm_sandbox_review as lsr  # noqa: E402  (LabRunner, Guard, Work, markers, probe_function: the lab's own)
from woowbackup import ha_nextcloud as nc, habackup, hacommon, ha_odoo, tempctr  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402

PG16 = 'docker.io/library/postgres:16-alpine'
DATA = '/var/lib/postgresql/data'
ENV = {'POSTGRES_HOST_AUTH_METHOD': 'trust'}
REMOTE = 'appdata_ocreview00001/richdocuments/remoteData'
CONFIG = (b"<?php\n$CONFIG = array (\n  'instanceid' => 'ocreview00001',\n  'passwordsalt' => 'reviewsaltreviewsalt',\n"
          b"  'secret' => 'reviewsecretreviewsecret',\n  'datadirectory' => '/share/nextcloud',\n  'dbtype' => 'pgsql',\n"
          b"  'version' => '35.0.1.1',\n  'dbname' => 'nextcloud',\n  'dbtableprefix' => 'oc_',\n  'installed' => true,\n);\n")
NC_TABLES = """
CREATE TABLE public.oc_appconfig (appid varchar(32) DEFAULT '' NOT NULL, configkey varchar(64) DEFAULT '' NOT NULL,
  configvalue text, type integer DEFAULT 2 NOT NULL, lazy smallint DEFAULT 0 NOT NULL, PRIMARY KEY (appid, configkey));
CREATE TABLE public.oc_storages (numeric_id bigserial PRIMARY KEY, id varchar(64), available integer DEFAULT 1 NOT NULL,
  last_checked integer);
CREATE TABLE public.oc_users (uid varchar(64) DEFAULT '' NOT NULL PRIMARY KEY, displayname varchar(64),
  password varchar(255) DEFAULT '' NOT NULL);
CREATE TABLE public.oc_mimetypes (id bigserial PRIMARY KEY, mimetype varchar(255) DEFAULT '' NOT NULL);
CREATE TABLE public.oc_filecache (fileid bigserial PRIMARY KEY, storage bigint DEFAULT 0 NOT NULL, path varchar(4000),
  name varchar(250), mimetype bigint DEFAULT 0 NOT NULL, size bigint DEFAULT 0 NOT NULL);
CREATE INDEX fc_name ON public.oc_filecache (name);
"""
HA_ROWS = f"""
INSERT INTO public.oc_appconfig VALUES ('core', 'backgroundjobs_mode', 'ajax'), ('files', 'enabled', 'yes'),
  ('richdocuments', 'enabled', 'yes'), ('richdocuments', 'wopi_url', 'http://127.0.0.1:9980');
INSERT INTO public.oc_storages (id) VALUES ('home::alice'), ('local::/share/nextcloud/');
INSERT INTO public.oc_users VALUES ('alice', 'Alice', 'x');
INSERT INTO public.oc_mimetypes (mimetype) VALUES ('httpd/unix-directory'), ('text/plain');
INSERT INTO public.oc_filecache (storage, path, name, mimetype, size) VALUES (1, 'files', 'files', 1, 3),
  (1, 'files/a.txt', 'a.txt', 2, 3), (2, '{REMOTE}', 'remoteData', 1, 1), (2, '{REMOTE}/discovery', 'discovery', 2, 1);
"""
TEAM_ROWS = """
INSERT INTO public.oc_storages (id) VALUES ('local::/share/nextcloud/__groupfolders/1/'), ('local::/share/media/');
INSERT INTO public.oc_filecache (storage, path, name, mimetype, size) VALUES (3, 'files/plan.txt', 'plan.txt', 2, 4);
"""
TEAM_AFTER = [[1, 'home::alice'], [2, 'local::/var/www/html/data/'], [3, 'local::/var/www/html/data/__groupfolders/1/'],
              [4, 'local::/share/media/']]
TROJAN_AGG = """CREATE FUNCTION public.woowbk_agg_step(state json, value name) RETURNS json LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM public.woowbk_probe('aggregate_json_agg_name');
  RETURN (coalesce(state::jsonb, '[]'::jsonb) || jsonb_build_array(value::text))::json;
END $f$;
CREATE AGGREGATE public.json_agg(name) (SFUNC = public.woowbk_agg_step, STYPE = json);
"""
TRIGGER_FN = """CREATE FUNCTION public.woowbk_trg() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN PERFORM public.woowbk_probe('trigger_storages'); RETURN coalesce(NEW, OLD); END $f$"""
TRIGGER = ("CREATE TRIGGER woowbk_t BEFORE INSERT OR UPDATE OR DELETE ON public.oc_storages FOR EACH ROW "
           "EXECUTE FUNCTION public.woowbk_trg()")
OWNER_SQL = {
    'owner_trojan': TROJAN_AGG + "ALTER DATABASE nextcloud SET search_path = public, pg_catalog;\n",
    'owner_view': """ALTER TABLE public.oc_appconfig RENAME TO oc_appconfig_real;
CREATE FUNCTION public.woowbk_rows() RETURNS SETOF public.oc_appconfig_real LANGUAGE plpgsql AS $f$
BEGIN PERFORM public.woowbk_probe('view_appconfig'); RETURN QUERY SELECT * FROM public.oc_appconfig_real; END $f$;
CREATE VIEW public.oc_appconfig AS SELECT * FROM public.woowbk_rows();
""",
    'owner_trigger': TRIGGER_FN + ';\n' + TRIGGER + """;
CREATE RULE woowbk_r AS ON DELETE TO public.oc_appconfig DO ALSO SELECT public.woowbk_probe('rule_appconfig');
CREATE FUNCTION public.woowbk_default() RETURNS integer LANGUAGE plpgsql AS $f$
BEGIN PERFORM public.woowbk_probe('default_appconfig'); RETURN 0; END $f$;
ALTER TABLE public.oc_appconfig ALTER COLUMN lazy SET DEFAULT public.woowbk_default();
""",
}
# T2: the INDEX entries of the dump, in order (woowbk_a, woowbk_b, ...): one statement each.
PROBE_FN = lsr.probe_function().strip().rstrip(';')
HIDDEN_SQL = {
    'hidden_trigger': [PROBE_FN, TRIGGER_FN, TRIGGER],
    'hidden_aggregate': [PROBE_FN, TROJAN_AGG.split(';\nCREATE AGGREGATE')[0],
                         'CREATE AGGREGATE public.json_agg(name) (SFUNC = public.woowbk_agg_step, STYPE = json)'],
    'hidden_database': ['COMMIT', 'CREATE DATABASE woowbk_evil'],
    'hidden_role_setting': ['ALTER ROLE CURRENT_USER SET search_path = public'],
    'hidden_password': ["ALTER ROLE CURRENT_USER PASSWORD 'woow-attacker'"],
    'hidden_grant': ['GRANT SELECT ON public.oc_users TO PUBLIC'],
    'hidden_default': ["ALTER TABLE public.oc_users ALTER COLUMN displayname SET DEFAULT pg_read_file('/etc/passwd')"],
    'hidden_rule': ['CREATE RULE woowbk_r AS ON UPDATE TO public.oc_storages DO ALSO SELECT 1'],
    'hidden_rls': ['ALTER TABLE public.oc_users ENABLE ROW LEVEL SECURITY'],
    'hidden_statistics': ['CREATE STATISTICS public.woowbk_s ON storage, size FROM public.oc_filecache'],
}
CASES = ['clean', 'team_folders', *OWNER_SQL, *HIDDEN_SQL, 'live_trojan']
# What the product must answer, and where: ('check', text of the blocker) or ('convert', code, text).
EXPECT = {
    'clean': None, 'team_folders': None,
    # owner_view: oc_appconfig is no table any more, so the database is "not Nextcloud's" and nothing else is read.
    'owner_trojan': ('check', '函式'), 'owner_view': ('check', None), 'owner_trigger': ('check', '觸發程序'),
    'hidden_trigger': ('convert', 'incompatible', '觸發程序'), 'hidden_aggregate': ('convert', 'incompatible', '函式'),
    'hidden_database': ('convert', 'job-failed', '其他資料庫'),
    'hidden_role_setting': ('convert', 'incompatible', '角色或資料庫層級的設定'),
    'hidden_password': ('convert', 'job-failed', '密碼設定和這台的不同'),
    'hidden_grant': ('convert', 'job-failed', '資料表或欄位多了權限設定'),
    'hidden_default': ('convert', 'incompatible', '不是固定值的欄位預設值'),
    'hidden_rule': ('convert', 'incompatible', '規則'), 'hidden_rls': ('convert', 'incompatible', '資料列安全原則'),
    'hidden_statistics': ('convert', 'incompatible', '其他自訂資料庫物件'),
    'live_trojan': None,
}


class Work(lsr.Work):
    """The job context the product's steps ask for."""

    def __init__(self, runner):
        super().__init__()
        self._runner = runner

    def runner(self, _app):
        return self._runner


def lying_indexdef(statements):
    """The superuser of a crafted data directory makes the built-in pg_get_indexdef(oid) answer attacker SQL."""
    cases = ''.join(f"    WHEN 'woowbk_{chr(97 + i)}' THEN RETURN {ha_odoo.sql_literal(text)};\n"
                    for i, text in enumerate(statements))
    indexes = ''.join(f'CREATE INDEX woowbk_{chr(97 + i)} ON public.oc_filecache (size);\n' for i in range(len(statements)))
    return (indexes + 'ALTER FUNCTION pg_catalog.pg_get_indexdef(oid) RENAME TO woowbk_indexdef;\n'
            'CREATE FUNCTION pg_catalog.pg_get_indexdef(idx oid) RETURNS text LANGUAGE plpgsql STABLE AS $lie$\n'
            'DECLARE n text;\nBEGIN\n  SELECT relname::text INTO n FROM pg_catalog.pg_class WHERE oid = idx;\n  CASE n\n'
            + cases + '    ELSE RETURN pg_catalog.woowbk_indexdef(idx);\n  END CASE;\nEND $lie$;\n')


def craft(runner, case, scratch):
    """HA's cluster in a throwaway container, packed as the add-on member of an HA backup (bytes)."""
    with tempctr.TempObjects(runner, lsr.job_id('craft'), memory='512m', pids=256, cpus='1') as tmp:
        tmp.volume('craft')
        tmp.run('craft', PG16, [], detach=True, env=ENV, volumes=[(tmp.name('craft'), DATA, 'rw')])
        cluster = ha_odoo.Cluster(tmp, 'craft')
        cluster.wait_ready(tcp=True)
        cluster.statement('CREATE ROLE nextcloud LOGIN NOSUPERUSER')
        cluster.statement("CREATE DATABASE nextcloud OWNER nextcloud ENCODING 'UTF8' TEMPLATE template0")
        sql = 'SET ROLE nextcloud;\n' + NC_TABLES + HA_ROWS + (TEAM_ROWS if case == 'team_folders' else '')
        if case in OWNER_SQL:
            sql += lsr.probe_function() + OWNER_SQL[case]
        cluster.script(sql + 'RESET ROLE;\n', 'nextcloud')
        if case in HIDDEN_SQL:
            cluster.script(lying_indexdef(HIDDEN_SQL[case]), 'nextcloud')
        # The crafting session must not leave markers behind: the volume is what HA's backup would carry.
        tmp.exec('craft', ['sh', '-c', 'rm -f /tmp/woowbk-review-*'], user='postgres', check=False, max_output=4096)
        if tmp.stop('craft', timeout=60) != 0:
            raise BackupError('job-failed', 'the crafted cluster did not stop cleanly')
        export = scratch / f'{case}.tar'
        with open(export, 'xb') as handle:
            tmp.volume_export('craft', handle)
    addon = {'user': {'version': '0.2.3', 'image': 'ghcr.io/woowtech/woow-ha-nextcloud-office-amd64', 'options': {}},
             'system': {'slug': nc.SLUG, 'name': 'Woow Nextcloud Office'}, 'version': '0.2.3'}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as dest:
        def add(name, data=None, kind=tarfile.REGTYPE):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = kind, 0o700 if kind == tarfile.DIRTYPE else 0o600, 1763900000
            info.size = len(data) if data is not None else 0
            dest.addfile(info, io.BytesIO(data) if data is not None else None)
        add('.', kind=tarfile.DIRTYPE)
        add('./addon.json', json.dumps(addon).encode())
        for name in ('data', 'data/nextcloud', 'data/nextcloud/config', 'data/postgres'):
            add(name, kind=tarfile.DIRTYPE)
        add('data/nextcloud/config/config.php', CONFIG)
        with tarfile.open(export, mode='r') as source:
            for info in source:
                rel = info.name[2:] if info.name.startswith('./') else info.name
                if rel in ('', '.', '..') or not (info.isfile() or info.isdir()):
                    continue
                info.name = f'data/postgres/{rel}'
                dest.addfile(info, source.extractfile(info) if info.isfile() else None)
    export.unlink()
    return out.getvalue()


def live_database(runner, tmp, work, app, *, trojan=False):
    """This device's database: (container name, what live_db_sql answers)."""
    tmp.volume('live')
    tmp.run('live', PG16, [], detach=True, env={**ENV, 'POSTGRES_USER': 'nextcloud', 'POSTGRES_DB': 'nextcloud'},
            volumes=[(tmp.name('live'), DATA, 'rw')])
    cluster = ha_odoo.Cluster(tmp, 'live', superuser='nextcloud')
    cluster.wait_ready(tcp=True)
    cluster.script(f"CREATE ROLE oc_admin LOGIN CREATEDB PASSWORD '{secrets.token_hex(24)}';\n"
                   'REVOKE ALL PRIVILEGES ON DATABASE nextcloud FROM PUBLIC;\nGRANT CONNECT ON DATABASE nextcloud TO oc_admin;\n'
                   'GRANT CREATE ON SCHEMA public TO oc_admin;\nSET ROLE oc_admin;\n' + NC_TABLES
                   + "INSERT INTO public.oc_appconfig VALUES ('core', 'backgroundjobs_mode', 'cron'), ('richdocuments', "
                     "'wopi_url', 'http://nextcloud-office:9980'), ('richdocuments', 'public_wopi_url', 'http://127.0.0.1:18081');\n"
                   + (lsr.probe_function() + TROJAN_AGG if trojan else '') + 'RESET ROLE;\n', 'nextcloud')
    name = tmp.name('live')
    return name, cluster, hacommon.live_json(work, app, name, 'nextcloud', 'nextcloud', nc.live_db_sql('oc_admin'))


def run_case(runner, case, scratch):
    work, app = Work(runner), SimpleNamespace(id='nextcloud', name='Nextcloud')
    facts = {'case': case, 'steps': []}
    with tempctr.TempObjects(runner, lsr.job_id(case), memory='512m', pids=256, cpus='1') as tmp:
        name, live_cluster, db = live_database(runner, tmp, work, app, trojan=case == 'live_trojan')
        facts['live_markers'] = sorted(lsr.markers(tmp, 'live'))
        facts['live_read'] = sorted(db) if isinstance(db, dict) else None
        if case == 'live_trojan':
            # Control: the same read unpinned, as it was before this review (the superuser runs the planted aggregate).
            old = nc.live_db_sql('oc_admin').replace('SET search_path = pg_catalog; ', '').replace('public.oc_appconfig', 'oc_appconfig')
            try:
                hacommon.live_json(work, app, name, 'nextcloud', 'nextcloud', old)
            except BackupError:
                pass
            facts['control_unpinned_markers'] = sorted(lsr.markers(tmp, 'live'))
            facts['ok'] = (not facts['live_markers'] and isinstance(db, dict) and db['roles'] == ['nextcloud', 'oc_admin']
                           and bool(facts['control_unpinned_markers']))
            return facts
        inner = craft(runner, case, scratch)
        holder = {}
        pg_ids = tmp.user_ids('ids-pg', PG16, 'postgres')
        tmp.volume('hapg')

        def produce(out):
            sink = ha_odoo.PgSink(out, *pg_ids)
            holder['src'] = nc.scan_member(io.BytesIO(inner), habackup.Report(), pg=sink, machine=0x3E)
            sink.close()

        tmp.volume_import('hapg', produce)
        src = holder['src']
        facts['scan'] = {'pg_version': src.pg_version, 'config': isinstance(src.config, dict)}
        hapg = nc.Pinned(tmp, 'hapg')
        cluster = ha_odoo.start_ha_cluster(work, hapg, PG16)
        details = nc.ha_database(cluster, src.config['dbname'])
        facts['steps'].append('ha_database')
        facts['check_markers'] = sorted(lsr.markers(tmp, 'hapg'))
        problems = nc.shape_problems(details.get('shape'))
        facts['check'] = {'shape_problems': problems, 'tables_read': 'counts' in details, 'lists': details.get('lists') is not None}
        expect = EXPECT[case]
        if expect is not None and expect[0] == 'check':
            if case == 'owner_trojan':  # Control: the same query of the engine's, unpinned, runs the planted aggregate
                try:
                    ha_odoo.Cluster(tmp, 'hapg').query_json(nc.TABLES_SQL, 'nextcloud')
                except BackupError:
                    pass
                facts['control_unpinned_markers'] = sorted(lsr.markers(tmp, 'hapg'))
            if case == 'owner_view':    # Control: reading oc_appconfig as the superuser runs the view's function
                try:
                    nc_sql = "SELECT json_build_object('n', (SELECT count(*) FROM public.oc_appconfig))"
                    ha_odoo.Cluster(hapg, 'hapg').query_json(nc_sql, 'nextcloud')
                except BackupError:
                    pass
                facts['control_read_markers'] = sorted(lsr.markers(tmp, 'hapg'))
            controls = [v for k, v in facts.items() if k.startswith('control_')]
            refused = (details.get('nextcloud') is False if expect[1] is None
                       else isinstance(problems, list) and any(expect[1] in p for p in problems))
            facts['ok'] = not facts['check_markers'] and not facts['check']['tables_read'] and refused and all(controls)
            return facts
        if problems:
            facts['ok'] = False
            return facts
        live = SimpleNamespace(db_image=PG16, db_target=DATA, db_env={**ENV, 'POSTGRES_USER': 'nextcloud',
                                                                     'POSTGRES_DB': 'nextcloud'}, db_secrets=(),
                               db_user='nextcloud', db_name='nextcloud', db_container=name, pgdata=DATA)
        target = SimpleNamespace(live=live, db=db, role='oc_admin')
        dump = scratch / f'{case}.dump'
        with open(dump, 'xb') as handle:
            hapg.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '-d', 'nextcloud'], user='postgres', stdout=handle,
                      timeout=600, max_output=64 * 1024 * 1024)
        facts['dump_bytes'] = dump.stat().st_size
        facts['hapg_markers'] = sorted(lsr.markers(tmp, 'hapg'))
        tmp.remove('hapg')
        tmp.remove_volume('hapg')
        stopped = None
        try:
            moves = nc.moves_of(src.config, {'datadirectory': '/var/www/html/data'}, details['local_storages'], None)
            facts['moves'] = len(moves)
            built = nc.build_cluster(work, app, tmp, target, dump, details=details, old_root='local::/share/nextcloud/',
                                     new_root='local::/var/www/html/data/', moves=moves, remote=REMOTE)
            facts['built'] = built
            if case == 'team_folders':  # the converted cluster itself, opened again
                tmp.run('after', PG16, [], detach=True, env=live.db_env, volumes=[(tmp.name('nc-db'), DATA, 'rw')])
                after = ha_odoo.Cluster(tmp, 'after', superuser='nextcloud')
                after.wait_ready(tcp=True)
                facts['storages_after'] = after.query_json(
                    'SELECT json_agg(json_build_array(numeric_id, id) ORDER BY numeric_id) FROM public.oc_storages', 'nextcloud')
                facts['team_file_storage'] = after.query_json(
                    "SELECT json_agg(storage) FROM public.oc_filecache WHERE path = 'files/plan.txt'", 'nextcloud')
        except BackupError as error:
            stopped = error
            facts['stopped'] = {'code': error.code, 'message': error.message[:300]}
        dump.unlink()
        running = tmp.running('nc-db') if tmp.name('nc-db') in tmp.containers else False
        facts['converted_markers'] = sorted(lsr.markers(tmp, 'nc-db')) if running else []
        if case == 'hidden_trigger' and running:
            # Control: the engine's own fix-up, run as the superuser it used before, fires the planted trigger.
            try:
                ha_odoo.Cluster(tmp, 'nc-db', superuser='nextcloud').script(
                    "UPDATE public.oc_storages SET id = id;\n", 'nextcloud')
            except BackupError:
                pass
            facts['control_superuser_markers'] = sorted(lsr.markers(tmp, 'nc-db'))
        if case == 'hidden_aggregate' and running:
            try:
                ha_odoo.Cluster(tmp, 'nc-db', superuser='nextcloud').query_json(
                    "SELECT json_build_object('r', (SELECT json_agg(rolname) FROM pg_roles))", 'nextcloud')
            except BackupError:
                pass
            facts['control_unpinned_markers'] = sorted(lsr.markers(tmp, 'nc-db'))
        controls = [v for k, v in facts.items() if k.startswith('control_')]
        quiet = not facts['check_markers'] and not facts['hapg_markers'] and not facts['converted_markers']
        if expect is None:
            facts['ok'] = (quiet and stopped is None and facts['built']['removed_cache_rows'] == 2
                           and facts['moves'] == (2 if case == 'team_folders' else 1))
            if case == 'team_folders':
                facts['ok'] = facts['ok'] and facts['storages_after'] == TEAM_AFTER and facts['team_file_storage'] == [3]
        else:
            facts['ok'] = (quiet and stopped is not None and stopped.code == expect[1] and expect[2] in stopped.message
                           and all(controls))
    return facts


def main(argv):
    target = Path(argv[0])
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    chosen = argv[1:] or CASES
    if not set(chosen) <= set(CASES):
        raise SystemExit(f'unknown case; the cases are {" ".join(CASES)}')
    started = time.monotonic()
    runner = lsr.LabRunner()
    before = lsr.volumes_now(runner)
    results = []
    with tempfile.TemporaryDirectory(prefix='woowbk-ncreview-', dir=os.environ.get('WOOWBK_REVIEW_SCRATCH')) as folder:
        for case in chosen:
            t0 = time.monotonic()
            try:
                facts = run_case(runner, case, Path(folder))
            except Exception as error:  # noqa: BLE001 - recorded by type and code only
                facts = {'case': case, 'ok': False, 'stopped_by': type(error).__name__,
                         'code': getattr(error, 'code', None), 'message': str(getattr(error, 'message', ''))[:300]}
            facts['seconds'] = round(time.monotonic() - t0, 1)
            results.append(facts)
            print(f'{case}: {"PASS" if facts.get("ok") else "FAIL"}', flush=True)
    git = lambda *a: subprocess.run(['git', '-C', str(REPO), *a], capture_output=True, text=True, timeout=60).stdout.strip()  # noqa: E731
    doc = {'kind': 'nextcloud-sandbox-review', 'date': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
           'source_commit': git('rev-parse', 'HEAD'),
           'tracked_changes': bool(git('status', '--porcelain', '--untracked-files=no')),
           'ha_nextcloud_sha256': hashlib.sha256((REPO / 'backup-engine/woowbackup/ha_nextcloud.py').read_bytes()).hexdigest(),
           'image': PG16, 'results': results, 'passed': sum(bool(r.get('ok')) for r in results), 'cases': len(results),
           'volumes_left_behind': sorted(lsr.volumes_now(runner) - before), 'elapsed_s': round(time.monotonic() - started, 1),
           'acceptance': 'not acceptance (attack runs against the real product steps in the lab store)'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    print(f'sandbox review: {doc["passed"]}/{doc["cases"]} PASS' if doc['passed'] == doc['cases']
          else f'sandbox review: {doc["passed"]}/{doc["cases"]} FAIL')
    return 0 if doc['passed'] == doc['cases'] else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
