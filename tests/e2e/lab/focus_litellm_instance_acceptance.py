"""Fixed review contract for original LiteLLM whole-instance acceptance.

Importing this module does no I/O. Historical 80-check ordinary-flow evidence
and generated PG proof remain complementary; neither is claimed by this case.
"""
import copy
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
DEVICE = 'woowbk-dev-d'
# The product under test from successor case b8 on: 59a1b0f9 plus ONE engine file (ha_instance_access.py: the PostgreSQL 17 table
# privilege MAINTAIN, found by the real b7 run). dev-d was moved to it by the leased engine patch tool.
FROZEN_PRODUCT = 'ce8c4cfbd8a1d7ff27233e3986a524408a6604f7'
PRODUCT_DIR = '/tmp/parity-focus-ll-product-20261127'
# What the retained derived image, its verification capture and case b7 were made with. The images-verify phase stays bound to it.
HISTORIC_PRODUCT = '59a1b0f95132ea51c899f590eea7e3b02c5dba43'
HISTORIC_PRODUCT_DIR = '/tmp/parity-focus-final-product-20261127'
PHASES = ('images', 'images-recover', 'flow', 'recover')
CASE = re.compile(r'woowbk_focus_litellm_[0-9a-f]{12}\Z')
BACKUP = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
APP_BASE = '0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312'
PG = '094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7'
APP_TAG = 'localhost/woow-litellm:1.104.0-0.3.16'
PG_TAG = 'docker.io/library/postgres:17.11-alpine3.23'
FIXTURE_SHA = '9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
UNITS = ('litellm-postgres.service', 'litellm.service')
SECRETS = ('litellm-database-url','litellm-master-key','litellm-postgres-password',
           'litellm-salt-key','litellm-ui-password')
QFILES = ('litellm.network','litellm-pgdata.volume','litellm-postgres.container','litellm.container')
PACKAGE_REV = 'dd690ae'
PACKAGE_COMMIT = 'dd690aee2b9032cf3db0695af714a8248a0ccb0a'
DERIVATION_SHA = 'b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a'
SAVED_DRIVER_SHA = 'f9455650d20189cef7d083ed967bb8b485190fbff44a378b152bcd28f69f8cf3'
MIN_FREE = 13 * 1024**3
PEAK = 8 * 1024**3


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8*1024**2), b''): h.update(b)
    return h.hexdigest()


def image_id(value):
    if not isinstance(value, str): raise ValueError('invalid image identity')
    value = value.removeprefix('sha256:')
    if not re.fullmatch(r'[0-9a-f]{64}', value): raise ValueError('invalid image identity')
    return value


def instance_entry(original):
    if original.get('id') != 'litellm' or original.get('owner') != 'appowner' or original.get('adapter') != 'quadlet-postgres':
        raise ValueError('unexpected app catalog')
    target = copy.deepcopy(original); pg = target.get('postgres') or []
    expected = {'id':'main','container':'litellm-postgres','unit':'litellm-postgres.service',
                'database':'litellm','user':'litellm','data_volume':'litellm-pgdata'}
    if len(pg) != 1 or any(pg[0].get(k) != v for k,v in expected.items()) or pg[0].get('scope','database') != 'database':
        raise ValueError('unexpected database selection')
    pg[0]['scope'] = 'instance'; del pg[0]['database']
    return target


def success(job, *, digest=False):
    r = job.get('result') or {}; health = r.get('health') or []
    checks = [c for v in r.get('verification',[]) for c in v.get('checks',[])]
    return (job.get('state') == 'succeeded' and r.get('rolled_back') is False
            and bool(r.get('safety_backup_id')) and bool(health)
            and all(h.get('status') == 'ok' for h in health)
            and (not digest or (bool(checks) and all(c.get('match') is True for c in checks))))


APP_DATABASE = 'litellm'


def default_database_acl(owner):
    """What a NULL datacl means in PostgreSQL, written out: PUBLIC may CONNECT and use TEMPORARY, the owner has everything."""
    return {'=Tc/' + owner, owner + '=CTc/' + owner}


def database_rows_equal(before, after):
    """pg_database rows as the snapshot lists them: [name, owner, encoding, collate, ctype, template, allowconn, acl].

    An import REPLACES the application database, and PostgreSQL then writes that database's default ACL out explicitly: dev-d b8
    saw null before and ['=Tc/litellm','litellm=CTc/litellm'] after, the same privileges. That one column of that one row may
    change in that one way; every other row, and every other column of that row, must be identical."""
    try:
        others_before = [r for r in before if r[0] != APP_DATABASE]
        others_after = [r for r in after if r[0] != APP_DATABASE]
        app_before = [r for r in before if r[0] == APP_DATABASE]
        app_after = [r for r in after if r[0] == APP_DATABASE]
        if others_before != others_after or len(app_before) != 1 or len(app_after) != 1: return False
        x, y = app_before[0], app_after[0]
        if x[:7] != y[:7]: return False
        if x[7] == y[7]: return True
        default = default_database_acl(x[1])
        return all(acl is None or (isinstance(acl, list) and set(acl) == default) for acl in (x[7], y[7]))
    except (TypeError, IndexError, KeyError):
        return False


def outsiders_equal(before, after):
    return (before.get('roles') == after.get('roles') and before.get('members') == after.get('members')
            and before.get('settings') == after.get('settings')
            and database_rows_equal(before.get('metadata'), after.get('metadata'))
            and before.get('database_names') == after.get('database_names')
            and {k:v for k,v in before['databases'].items() if k != APP_DATABASE} ==
                {k:v for k,v in after['databases'].items() if k != APP_DATABASE})


def snapshots_equal(a, b):
    """Two case snapshots are equal, except that the application database's ACL may be null in one and the same default written out
    in the other (database_rows_equal): restoring that database rewrites it (dev-d b10: written out before the forced failure, null
    after the automatic rollback; b8: null before, written out after the import)."""
    if not isinstance(a, dict) or not isinstance(b, dict): return False
    return (all(a.get(k) == b.get(k) for k in set(a) | set(b) if k != 'metadata')
            and (a.get('metadata') == b.get('metadata') or database_rows_equal(a.get('metadata'), b.get('metadata'))))


def outsiders_difference(before, after):
    """WHERE the outsiders check found a difference: field and database names only, never a digest or a value."""
    names = [k for k in ('roles', 'members', 'settings', 'database_names') if before.get(k) != after.get(k)]
    if not database_rows_equal(before.get('metadata'), after.get('metadata')): names.append('metadata')
    for name in sorted(set(before.get('databases', {})) | set(after.get('databases', {}))):
        if name != APP_DATABASE and before['databases'].get(name) != after['databases'].get(name):
            names.append('databases.' + str(name))
    return names


def rollback_proven(job, *, hook, witness, before, after, full_safety, digest_log):
    r = job.get('result') or {}
    return (job.get('state') == 'rolled-back' and r.get('rolled_back') is True
            and bool(r.get('safety_backup_id')) and hook is True and witness is True
            and full_safety is True and digest_log is True and snapshots_equal(before, after))


MANIFEST_PROBE = r'''
import json,re,sys
sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
from woowbackup.cli import Services
from woowbackup.paths import Paths
from woowbackup import ha_instance_access
q=json.load(sys.stdin);bid=q['backup_id']
assert re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',bid)
s=Services(Paths());m=s.archive.read_manifest(s.storage.archive_path(bid),list(s.keys.identities()))
assert len(m['apps'])==1 and m['apps'][0]['id']=='litellm'
a=m['apps'][0];assert len(a['postgres'])==1;p=a['postgres'][0]
if p.get('ha_access') is not None:ha_instance_access.validate(p['ha_access'],'litellm')
print(json.dumps({'scope':p.get('scope','database'),'ha_database':p.get('ha_database'),
 'ha_access_valid':p.get('ha_access') is not None,'databases':[[d['name'],d.get('owner')] for d in p.get('databases',[])],
 'roles_count':len(p.get('roles',[])),'globals_present':isinstance(p.get('entry'),str),
 'digests':[d['type'] for d in a.get('verify_digests',[])]}))
'''

ENDPOINT_PROBE = r'''
import json,sys
sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
from woowbackup.cli import Services
from woowbackup.paths import Paths
from woowbackup import ha_litellm
s=Services(Paths());a=s.catalog()['litellm'];ad=s.adapter(a)
q=ad._read_owner_quadlets()
e=ha_litellm.read_app_connection(ad.runner,q,postgres=a.postgres[0])
print(json.dumps(e))
'''

# Only API credential creation is reused for the later rollback witness. The
# response body/token never leaves device Python; the known input is registered
# with the saved credential reader before this request.
API_WITNESS = r'''
import json,re,subprocess,sys,urllib.request,urllib.error
q=json.load(sys.stdin)
assert q['action'] in ('create','check')
assert re.fullmatch(r'woowbk_focus_litellm_[0-9a-f]{12}',q['name'])
def stored():
 statement="SELECT to_json(count(*)=1) FROM public.\"LiteLLM_CredentialsTable\" WHERE credential_name='"+q['name']+"';"
 p=subprocess.run(['podman','exec','-i','litellm-postgres','psql','-X','-w','-Atq','-v','ON_ERROR_STOP=1',
  '-U','litellm','-d','litellm','-f','-'],input=statement.encode(),capture_output=True,check=True,timeout=30)
 return json.loads(p.stdout) is True
if q['action']=='check':
 print(json.dumps({'status':200,'found':stored()}));sys.exit(0)
master=subprocess.run(['podman','secret','inspect','--showsecret','--format','{{.SecretData}}',
 'litellm-master-key'],capture_output=True,check=True,timeout=30).stdout.decode().strip()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
body={'credential_name':q['name'],'credential_values':{'api_key':q['value']},'credential_info':{'custom_llm_provider':'openai'}}
req=urllib.request.Request('http://127.0.0.1:4000/credentials',method='POST',data=json.dumps(body).encode(),
 headers={'Authorization':'Bearer '+master,'Content-Type':'application/json'})
try:
 with opener.open(req,timeout=30) as r:
  b=r.read(1024*1024+1);assert len(b)<=1024*1024
  answer=json.loads(b)
  # LiteLLM v1.104.0 (credential_endpoints/endpoints.py) answers {"success": true, "message": "Credential created successfully"}
  # and never echoes the name (dev-d b9 failed on exactly that): the row in its own table is the proof that the write happened.
  print(json.dumps({'status':r.status,'success':isinstance(answer,dict) and answer.get('success') is True,'found':stored()}))
except urllib.error.HTTPError as e:print(json.dumps({'status':e.code,'success':False,'found':False}))
'''
