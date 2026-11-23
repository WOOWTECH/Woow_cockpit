"""Lab tool (lane litellm-product, 2026-11-23; usage: python3 -I tests/e2e/lab/litellm_pin_proof.py <repo>).
Real PostgreSQL proof of the search_path pin (lab Podman store, --network=none, throwaway, generated nothing secret):
an enum-typed column in public renders differently in a session with search_path=pg_catalog (HA's, SR-1) and one with
the default search_path (this device's) unless the query pins search_path itself. Prints one JSON document."""
import json, subprocess, sys, time
sys.path.insert(0, sys.argv[1] + '/backup-engine')
from woowbackup import ha_litellm as hl
LAB = '/home/woowtechopenclaw/.woowbk-lab/bin/labpodman'
IMAGES = {'17': '094ecc9ca4ea', '18': '4ea77c7055de'}
UNPINNED = {'columns': hl.COLUMNS_SQL[len(hl.PIN_SEARCH_PATH):], 'signature': hl.SIGNATURE_SQL[len(hl.PIN_SEARCH_PATH):]}
PINNED = {'columns': hl.COLUMNS_SQL, 'signature': hl.SIGNATURE_SQL}
SETUP = ('CREATE ROLE litellm LOGIN; CREATE DATABASE litellm OWNER litellm;')
SCHEMA = ('CREATE TYPE "JobStatus" AS ENUM (\'ACTIVE\', \'INACTIVE\'); '
          'CREATE TABLE "LiteLLM_CronJob" (cronjob_id text PRIMARY KEY, pod_id text NOT NULL, '
          'status "JobStatus" NOT NULL DEFAULT \'INACTIVE\', ttl timestamp(3) NOT NULL);'
          'CREATE SCHEMA woow_platform; CREATE TABLE woow_platform.settings (key text PRIMARY KEY, value text);')
def sh(*a, inp=None, t=120):
    return subprocess.run(a, input=inp, capture_output=True, timeout=t)
out = {'pin': hl.PIN_SEARCH_PATH}
for major, image in IMAGES.items():
    name = f'woowbk-pinproof-pg{major}'
    sh(LAB, 'rm', '-f', name)
    r = sh(LAB, 'run', '-d', '--rm', '--name', name, '--network=none', '--memory=512m', '--env',
           'POSTGRES_HOST_AUTH_METHOD=trust', image)
    if r.returncode:
        out[major] = {'error': r.stderr.decode()[-200:]}; continue
    try:
        for _ in range(90):
            if sh(LAB, 'exec', name, 'pg_isready', '-U', 'postgres').returncode == 0:
                break
            time.sleep(2)
        time.sleep(3)
        ok = False
        for _ in range(30):
            a = sh(LAB, 'exec', name, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-c',
                   'CREATE ROLE litellm LOGIN')
            b = sh(LAB, 'exec', name, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-c',
                   'CREATE DATABASE litellm OWNER litellm')
            c = sh(LAB, 'exec', name, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'litellm', '-d', 'litellm',
                   '-c', SCHEMA)
            if c.returncode == 0:
                ok = True
                break
            time.sleep(2)
        if not ok:
            raise SystemExit('setup failed: ' + (a.stderr + b.stderr + c.stderr).decode()[-300:])
        res = {}
        for label, env in (('device_default', []), ('ha_pg_catalog', ['--env', 'PGOPTIONS=-c search_path=pg_catalog'])):
            for kind, table in (('unpinned', UNPINNED), ('pinned', PINNED)):
                for part in ('columns', 'signature'):
                    p = sh(LAB, 'exec', *env, name, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U',
                           'litellm', '-d', 'litellm', '-c', table[part])
                    val = json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else {'rc': p.returncode,
                                                                                               'err': p.stderr.decode()[-200:]}
                    res[f'{label}/{kind}/{part}'] = val
        bad = [k for k, v in res.items() if isinstance(v, dict) and 'rc' in v]
        if bad:
            raise SystemExit('query failed: ' + json.dumps({k: res[k] for k in bad})[:600])
        cron = lambda v: [row[3] for row in v if row[1] == 'LiteLLM_CronJob' and row[2] == 'status'] if isinstance(v, list) else v
        out[major] = {
            'version': sh(LAB, 'exec', name, 'postgres', '--version').stdout.decode().strip(),
            'status_type': {k: cron(v) for k, v in res.items() if k.endswith('/columns')},
            'unpinned_columns_equal': res['device_default/unpinned/columns'] == res['ha_pg_catalog/unpinned/columns'],
            'pinned_columns_equal': res['device_default/pinned/columns'] == res['ha_pg_catalog/pinned/columns'],
            'unpinned_signature_equal': res['device_default/unpinned/signature'] == res['ha_pg_catalog/unpinned/signature'],
            'pinned_signature_equal': res['device_default/pinned/signature'] == res['ha_pg_catalog/pinned/signature'],
            'schema_differences_unpinned': hl.schema_differences(
                hl.Schema(res['ha_pg_catalog/unpinned/columns'], res['ha_pg_catalog/unpinned/signature'], []),
                hl.Schema(res['device_default/unpinned/columns'], res['device_default/unpinned/signature'], [])),
            'schema_differences_pinned': hl.schema_differences(
                hl.Schema(res['ha_pg_catalog/pinned/columns'], res['ha_pg_catalog/pinned/signature'], []),
                hl.Schema(res['device_default/pinned/columns'], res['device_default/pinned/signature'], [])),
        }
    finally:
        sh(LAB, 'rm', '-f', name)
left = sh(LAB, 'ps', '-a', '--filter', 'name=woowbk-pinproof', '--format', '{{.Names}}').stdout.decode().split()
out['containers_left'] = left
print(json.dumps(out, ensure_ascii=False, indent=1))
