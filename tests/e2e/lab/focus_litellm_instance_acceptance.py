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
FROZEN_PRODUCT = '59a1b0f95132ea51c899f590eea7e3b02c5dba43'
PHASES = ('images', 'images-recover', 'flow', 'recover')
CASE = re.compile(r'woowbk_focus_litellm_[0-9a-f]{12}\Z')
BACKUP = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
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


def outsiders_equal(before, after):
    return (before.get('roles') == after.get('roles') and before.get('members') == after.get('members')
            and before.get('settings') == after.get('settings') and before.get('metadata') == after.get('metadata')
            and before.get('database_names') == after.get('database_names')
            and {k:v for k,v in before['databases'].items() if k != 'litellm'} ==
                {k:v for k,v in after['databases'].items() if k != 'litellm'})


def rollback_proven(job, *, hook, witness, before, after, full_safety, digest_log):
    r = job.get('result') or {}
    return (job.get('state') == 'rolled-back' and r.get('rolled_back') is True
            and bool(r.get('safety_backup_id')) and hook is True and witness is True
            and full_safety is True and digest_log is True and before == after)


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
if q['action']=='check':
 statement="SELECT to_json(count(*)=1) FROM public.\"LiteLLM_CredentialsTable\" WHERE credential_name='"+q['name']+"';"
 p=subprocess.run(['podman','exec','-i','litellm-postgres','psql','-X','-w','-Atq','-v','ON_ERROR_STOP=1',
  '-U','litellm','-d','litellm','-f','-'],input=statement.encode(),capture_output=True,check=True,timeout=30)
 print(json.dumps({'status':200,'found':json.loads(p.stdout) is True}));sys.exit(0)
master=subprocess.run(['podman','secret','inspect','--showsecret','--format','{{.SecretData}}',
 'litellm-master-key'],capture_output=True,check=True,timeout=30).stdout.decode().strip()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
body={'credential_name':q['name'],'credential_values':{'api_key':q['value']},'credential_info':{'custom_llm_provider':'openai'}}
req=urllib.request.Request('http://127.0.0.1:4000/credentials',method='POST',data=json.dumps(body).encode(),
 headers={'Authorization':'Bearer '+master,'Content-Type':'application/json'})
try:
 with opener.open(req,timeout=30) as r:
  b=r.read(1024*1024+1);assert len(b)<=1024*1024
  found=json.loads(b)
  print(json.dumps({'status':r.status,'found':q['name'] in json.dumps(found)}))
except urllib.error.HTTPError as e:print(json.dumps({'status':e.code,'found':False}))
'''
