#!/usr/bin/env python3
"""Prepare the original n8n instance-path case. No device execution is implemented here.

This builds a source-bound review packet, fixed SQL, and narrowly scoped fixture
transformations for the coordinator's future dev-c lease. It never calls Podman,
reads credentials, starts services, installs images, or changes the catalog.
Historical ordinary-flow34 and the generated PostgreSQL proof remain separate.
"""
import argparse
import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
AREA = 'focus-n8n-instance-acceptance'
DEVICE = 'woowbk-dev-c'
LOCK = '/tmp/woowbk-dev-c-mutation.lock'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
CATALOG = '/etc/woowtech-cockpit/backup/apps/n8n.json'
FOUND_SHA = '3dfebaa0879d5622514276e2b834bff482f3db53618af0caaa46c5c660e968c4'
IMAGE_IDS = {
    'docker.io/n8nio/n8n:2.43.6': 'c8d7cd6bf08e1837180b767d77903889e0f3f022accda90579f5e99ca2a2bdfb',
    'docker.io/n8nio/runners:2.43.6': '28c5a510d7624e5ce079d2204e4d8421bc96ced83ebc2e1717d6ee33a0ccc1bb',
    'docker.io/library/postgres:16.15-alpine': '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873',
    'docker.io/valkey/valkey:8.1.11-alpine': '650ff8153447d257696648bc63a77522cf6e760145be45ce65a408a918229915',
}
ARCHIVES = {
    'c8d7cd6bf08e1837180b767d77903889e0f3f022accda90579f5e99ca2a2bdfb':
        ('0a7352186122520e86fa3b22d0239ab611387e61bb863d082410c38e71f62ccb', 296256084),
    '28c5a510d7624e5ce079d2204e4d8421bc96ced83ebc2e1717d6ee33a0ccc1bb':
        ('7fa274ed6a93924cf90420433d5e0928d72183029ea80437fdf4ebc89e70580f', 196625268),
}
APP_FILES = ('n8n.container', 'n8n-worker.container', 'n8n-webhook.container')
IDENTITY = re.compile(r'woowbk_focus_n8n_[0-9a-f]{12}(?:_outside|_reader)?\Z')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as inp:
        for data in iter(lambda: inp.read(8 * 1024**2), b''):
            digest.update(data)
    return digest.hexdigest()


def ident(name):
    if not isinstance(name, str) or not IDENTITY.fullmatch(name):
        raise ValueError('identifier is outside this case')
    return '"' + name + '"'


def instance_entry(original):
    """Only the already trusted n8n PostgreSQL scope changes; no invented entry."""
    if original.get('id') != 'n8n' or original.get('owner') != 'appowner':
        raise ValueError('unexpected original app')
    entry = copy.deepcopy(original)
    items = entry.get('postgres') or []
    if (len(items) != 1 or items[0].get('scope', 'database') != 'database'
            or items[0].get('container') != 'n8n-postgres'
            or items[0].get('unit') != 'n8n-postgres.service'
            or items[0].get('database') != 'n8n' or items[0].get('user') != 'n8n'
            or not items[0].get('data_volume')):
        raise ValueError('unexpected original PostgreSQL item')
    items[0]['scope'] = 'instance'
    del items[0]['database']
    return entry


def resolver_files(quadlets, environment, database):
    """Private bytes only. Fail if the captured layout has changed since review.

    Podman's explicit Environment beats EnvironmentFile. Removing the one fixed
    database assignment from ALL queue app units makes the retained env file the
    actual source. The server's POSTGRES_DB and original database stay n8n.
    """
    ident(database)
    if set(quadlets) != set(APP_FILES) or not isinstance(environment, bytes):
        raise ValueError('unexpected fixture inputs')
    changed = {}
    for filename, data in quadlets.items():
        if not isinstance(data, bytes) or len(data) > 64 * 1024:
            raise ValueError('unbounded unit')
        lines = data.decode('utf-8').splitlines(keepends=True)
        identity = [line for line in lines if re.match(
            r'\s*Environment\s*=.*DB_POSTGRESDB_(DATABASE|DATABASE_FILE)\b', line)]
        if identity != ['Environment=DB_POSTGRESDB_DATABASE=n8n\n']:
            raise ValueError('unexpected inline database precedence')
        if lines.count('EnvironmentFile=%h/.config/n8n/n8n.env\n') != 1:
            raise ValueError('unexpected EnvironmentFile')
        # PodmanArgs/Secret could introduce another selected value; review instead.
        if any('DB_POSTGRESDB_DATABASE' in line for line in lines if line not in identity):
            raise ValueError('another database input')
        changed[filename] = ''.join(line for line in lines if line not in identity).encode()
    if len(environment) > 64 * 1024 or b'\0' in environment:
        raise ValueError('unbounded environment file')
    text = environment.decode('utf-8')
    if re.search(r'^\s*(?:export\s+)?DB_POSTGRESDB_DATABASE(?:_FILE)?\s*=', text, re.M):
        raise ValueError('an existing database input needs review')
    changed['.config/n8n/n8n.env'] = environment + (b'' if environment.endswith(b'\n') else b'\n') + (
        'DB_POSTGRESDB_DATABASE=' + database + '\n').encode()
    return changed


def case_sql(database):
    """Fixed grammar, case names only; clone while every app writer is stopped."""
    app, outside, reader = ident(database), ident(database + '_outside'), ident(database + '_reader')
    return {
        'clone_on_postgres': f'CREATE DATABASE {app} WITH TEMPLATE "n8n" OWNER "n8n";',
        'outside_on_postgres': f'CREATE ROLE {reader} NOLOGIN;\nCREATE DATABASE {outside} OWNER {reader};',
        'outside_on_own_database': ('CREATE TABLE public.kept_marker(value text PRIMARY KEY);\n'
                                   "INSERT INTO public.kept_marker VALUES ('before-conversion');\n"
                                   f'ALTER TABLE public.kept_marker OWNER TO {reader};'),
        'late_outside_write': "INSERT INTO public.kept_marker VALUES ('after-conversion');",
        # Must be present immediately before the forced restore; an unchanged HA
        # payload cannot manufacture this row, so it witnesses actual rollback.
        'rollback_marker': ('INSERT INTO public.settings(key,value,"loadOnStartup") VALUES '
                            "('woowbk.focus.instance.rollback','after-import',false) "
                            'ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;'),
        'rollback_check': ("SELECT to_json(count(*)=1) FROM public.settings WHERE "
                           "key='woowbk.focus.instance.rollback' AND value='after-import';"),
        'outside_check': ("SELECT json_build_array((SELECT array_agg(value ORDER BY value) "
                          'FROM public.kept_marker),(SELECT pg_get_userbyid(datdba) FROM pg_database '
                          "WHERE datname=current_database()),(SELECT pg_get_userbyid(relowner) FROM "
                          "pg_class WHERE oid='public.kept_marker'::regclass));"),
        'roles_private_hash': ("SELECT md5(coalesce(string_agg(rolname||':'||rolsuper||':'||rolinherit||':'||"
                               "rolcreaterole||':'||rolcreatedb||':'||rolcanlogin||':'||rolreplication||':'||"
                               "rolbypassrls||':'||rolconnlimit||':'||coalesce(rolvaliduntil::text,'')||':'||"
                               "coalesce(rolconfig::text,'')||':'||coalesce(rolpassword,''),E'\\n' ORDER BY rolname),'')) "
                               'FROM pg_authid;'),
    }


def failure_dropin(database):
    ident(database)
    marker = '%h/.local/state/' + database + '.fail-once'
    # Never fail the PG startup: this case must pass the endpoint preflight and
    # destructive selective import before the application start fails. Prevent
    # Restart=always from swallowing the intentional failure before rollback.
    return ('[Service]\nRestart=no\nExecStartPre=/bin/sh -c \'if test -f ' + marker +
            '; then rm -f ' + marker + '; exit 1; fi\'\n')


def preflight_ready(reply):
    p = reply.get('preflight') or {}
    apps = p.get('apps') or []
    return (p.get('ok') is True and len(apps) == 1 and apps[0].get('id') == 'n8n'
            and apps[0].get('mode') == 'inplace' and apps[0].get('restorable') is True
            and not any(c.get('status') == 'fail' for c in p.get('checks') or [])
            and not any(c.get('status') == 'fail' for c in apps[0].get('checks') or [])
            and not any(i.get('level') in ('confirm', 'stop') for i in apps[0].get('issues') or []))


def rollback_proven(job, *, consumed, marker, digests, application):
    result = job.get('result') or {}
    return (job.get('state') == 'rolled-back' and result.get('rolled_back') is True
            and bool(result.get('safety_backup_id')) and consumed is True and marker is True
            and digests is True and application is True)


def may_clean(*, jobs_terminal, full_safety_restored, original_state, secret_scan):
    return all(v is True for v in (jobs_terminal, full_safety_restored, original_state, secret_scan))


# The public inspect summary deliberately omits ha_database/ha_access. This fixed
# read-only device-side program inspects the ACTUAL manifest with existing device
# identities, returning only selected facts. It is prepared, never run here.
MANIFEST_PROBE = r'''
import json,re,sys
sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
from woowbackup.cli import Services
from woowbackup.paths import Paths
from woowbackup import ha_instance_access
q=json.load(sys.stdin); name=q['backup_id']
assert re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',name)
s=Services(Paths()); p=s.storage.archive_path(name)
m=s.archive.read_manifest(p,list(s.keys.identities()))
apps=m['apps']; assert len(apps)==1 and apps[0]['id']=='n8n'
items=apps[0]['postgres']; assert len(items)==1
x=items[0]; access=x.get('ha_access')
if access is not None: ha_instance_access.validate(access,'n8n')
print(json.dumps({'scope':x.get('scope','database'),'ha_database':x.get('ha_database'),
 'ha_access_valid':access is not None,'databases':[[d['name'],d.get('owner')] for d in x.get('databases',[])],
 'roles_count':len(x.get('roles',[])),'globals_present':isinstance(x.get('entry'),str),
 'digests':[d['type'] for d in apps[0].get('verify_digests',[])]}))
'''


ENDPOINT_PROBE = r'''
import json,sys
sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
from woowbackup.cli import Services
from woowbackup.paths import Paths
from woowbackup import ha_n8n,ha_instance_access,hacommon
s=Services(Paths()); a=s.catalog()['n8n']; adapter=s.adapter(a)
q=adapter._read_owner_quadlets(); r=adapter.runner
main=ha_n8n.main_container(r,q); endpoint=ha_n8n.read_app_endpoint(r,q)
print(json.dumps({'main':main,'database':endpoint['database'],'user':endpoint['user'],
 'host':endpoint['host'],'port':endpoint['port'],
 'local':ha_instance_access.local_backend(endpoint,q,hacommon.container_file(q,main),a.postgres[0])}))
'''


API_ACTION_PROBE = r'''
# Prepared device-side only. Inputs use the existing private stdin reader.
import http.cookiejar,json,re,sys,time,urllib.request
out={'login':False,'credential_visible':False,'manual_action':False}
try:
 q=json.loads(sys.stdin.read(8193)); assert set(q)=={'email','password'}
 jar=http.cookiejar.CookieJar()
 client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 def call(method,path,body=None):
  assert path.startswith('/rest/')
  req=urllib.request.Request('http://127.0.0.1:15678'+path,method=method,
   data=None if body is None else json.dumps(body).encode(),
   headers={'Content-Type':'application/json','browser-id':'woow-focus-instance'})
  with client.open(req,timeout=20) as r:
   b=r.read(4*1024*1024+1); assert r.status==200 and len(b)<=4*1024*1024
   return json.loads(b)
 call('POST','/rest/login',{'emailOrLdapLoginId':q['email'],'password':q['password']})
 out['login']=True
 creds=call('GET','/rest/credentials').get('data',[])
 assert isinstance(creds,list)
 out['credential_visible']=sum(c.get('name')=='HA probe header' for c in creds)==1
 rows=call('GET','/rest/workflows').get('data',[]); assert isinstance(rows,list)
 selected=[w for w in rows if w.get('name')=='WOOW 匯入測試 - 手動']; assert len(selected)==1
 wid=selected[0]['id']; assert isinstance(wid,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',wid)
 workflow=call('GET','/rest/workflows/'+wid)['data']
 nodes=workflow['nodes']; assert len(nodes)==2
 assert sorted(n['type'] for n in nodes)==['n8n-nodes-base.manualTrigger','n8n-nodes-base.set']
 trigger=next(n for n in nodes if n['type']=='n8n-nodes-base.manualTrigger')['name']
 assert isinstance(trigger,str) and 0<len(trigger)<100
 response=call('POST','/rest/workflows/'+wid+'/run',{'triggerToStartFrom':{'name':trigger}})
 eid=response['data']['executionId']; assert re.fullmatch(r'[0-9]{1,20}',str(eid))
 for _ in range(30):
  execution=call('GET','/rest/executions/'+str(eid))['data']
  if execution.get('status')=='success' and execution.get('finished') is True:
   out['manual_action']=str(execution.get('workflowId'))==wid
   break
  if execution.get('status') in ('error','canceled','crashed'): break
  time.sleep(2)
except Exception:
 pass
# No execution payload, cookie, password, credential content or raw error leaves.
print(json.dumps(out))
'''


def packet(source, source_sha, original, database):
    """A review artifact, explicitly not a runtime success or an execution lease."""
    ident(database)
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('exact source commit required')
    source = Path(source).resolve()
    modules = source / 'backup-engine/woowbackup'
    hashes = {str(p.relative_to(modules)): sha(p) for p in sorted(modules.rglob('*.py'))
              if '__pycache__' not in p.parts}
    if not hashes:
        raise ValueError('engine source missing')
    hashes['../woowtech-cockpit-backup'] = sha(source/'backup-engine/woowtech-cockpit-backup')
    fixed = instance_entry(original)
    return {
        'case': 'n8n-instance-original', 'stage': 'preparation_only', 'device': DEVICE,
        'source_commit': source_sha, 'engine_sha256': hashes, 'catalog_path': CATALOG,
        'expected_catalog_sha256': FOUND_SHA, 'proposed_catalog_entry': fixed,
        'case_database': database, 'images': IMAGE_IDS,
        'fixture': {'path': str(LAB/'ha-fixtures/20261118/woow-import-test-enc/woow-import-test-enc.tar'),
                    'historical_baseline': '20261118T095520Z-33eb7474',
                    'historical_baseline_is_not_fresh_instance_safety': True},
        'bounds': {'mutation_minutes': 40, 'host_ram_mib': 1200, 'device_headroom_mib': 1900,
                   'host_reserve_gib': 13, 'additional_peak_budget_gib': 8,
                   'job_wait_seconds': 600, 'device_lock': LOCK},
        'authorization': {'granted': False, 'wakeup': False, 'catalog_mutation': False,
                          'image_load': False, 'helper_deployment': False},
        'execution_ready': False,
        'execution_gates': ['coordinator_frozen_final_product_sha', 'reviewed_mutation_controller',
                            'explicit_dev_c_lease', 'exact_image_recovery_if_still_missing'],
        'helper_requests': {
            'fresh_safety': {'command': 'backup-start', 'request': {'apps': ['n8n'],
                             'encrypt': True, 'include_images': False,
                             'request_id': database + '-safety', 'note': 'n8n instance case fresh safety'}},
            'check': {'command': 'ha-check-start', 'request': {'apps': ['n8n'],
                      'request_id': database + '-check'}, 'ha_backup_id_from': 'original_fixture_upload',
                      'key_from': 'existing_secret_reader_stdin_only'},
            'convert': {'command': 'ha-convert-start', 'request': {'apps': ['n8n'], 'confirm': True,
                        'test_mode': False, 'request_id': database + '-convert'},
                        'ha_backup_id_from': 'original_fixture_upload', 'key_from': 'existing_secret_reader_stdin_only'},
            'import': {'command': 'restore-start', 'request': {'apps': ['n8n'], 'confirm': True,
                       'request_id': database + '-import'}, 'backup_id_from': 'convert.result.backup_id'},
            'rollback_case': {'command': 'restore-start', 'request': {'apps': ['n8n'], 'confirm': True,
                              'request_id': database + '-rollback'}, 'backup_id_from': 'convert.result.backup_id'},
            'recover': {'command': 'restore-start', 'request': {'apps': ['n8n'], 'confirm': True,
                        'request_id': database + '-recover'}, 'backup_id_from': 'fresh_safety.result.backup_id'},
        },
        'phase_order': ['freeze_and_inventory', 'capture_original_bytes_and_states', 'catalog_scope_cas',
                        'fresh_full_instance_safety', 'clone_and_environmentfile_fixture',
                        'stopped_main_vendor_check_and_convert', 'manifest_and_retained_state',
                        'late_outside_write_and_dbname_mismatch_refusal', 'selective_import',
                        'real_api_credential_action', 'restart_and_repeat_api', 'forced_failure_full_rollback',
                        'restore_original_files_then_full_safety', 'restore_exact_catalog_and_stopped_state',
                        'verify_then_owned_cleanup'],
        'not_proven': ['runtime_execution', 'current_vendor_full_flow', 'fresh_target_mode',
                       'native_arm_target', 'cockpit_browser', 'limited_app_role_vendor_flow',
                       'commercial_acceptance'],
    }


def verify_cache():
    """Read only the two named saved archives; no lab or host container tools."""
    folder = LAB/'evidence/parity-space-20261126/dev-c-images'
    rows = []
    for config, (digest, size) in ARCHIVES.items():
        path = folder/(config + '.tar.gz')
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size or sha(path) != digest:
            raise ValueError('cached exact image archive is missing or changed')
        rows.append({'config_id': config, 'archive_sha256': digest, 'archive_bytes': size,
                     'archive_hash_verified_now': True, 'image_loaded': False})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=REPO)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--case', default='woowbk_focus_n8n_0123456789ab')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify-cache', action='store_true')
    args = parser.parse_args(argv)
    source = args.source.resolve()
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != args.expected_source:
        raise ValueError('source SHA changed')
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip():
        raise ValueError('commit the exact preparation source first')
    found = json.loads((source/'snippets'/AREA/'found-metadata.json').read_text())
    if found['catalog_sha256'] != FOUND_SHA:
        raise ValueError('reviewed catalog binding changed')
    result = packet(source, actual, found['entry'], args.case)
    result['local_cache'] = verify_cache() if args.verify_cache else 'not_rehashed'
    result['driver_sha256'] = sha(Path(__file__))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
    print(json.dumps({'stage': 'n8n_instance_prepared', 'mutation': False,
                      'source_commit': actual, 'packet_sha256': sha(args.output)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
