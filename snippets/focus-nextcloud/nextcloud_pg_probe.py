#!/usr/bin/env python3
"""Generated PostgreSQL proof in a disposable dev-d owner container. Run only under a coordinator lease.

Default is a read-only plan. --run uses the existing image ID, no ports/network, <=384 MiB, the shared dev-d lock,
one new volume and one new container. Existing app databases are never opened. Cleanup removes only objects this run made.
"""
import argparse
import fcntl
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_nextcloud as nc, ha_nextcloud_memories as memories  # noqa: E402

IMAGE = 'sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
OWNER = ROOT / 'tests/e2e/lab/owner.sh'
ROLE = 'woowbk_nc_probe_loader'

REMOTE = r'''
import hashlib,json,secrets,subprocess,time,pathlib,re
checks={}
phase='inventory'
command_class=None
private_stderr=''
sqlstate=None
name='woowbk-nc-fixed-'+secrets.token_hex(6)
volume=name+'-data'
made_container=made_volume=False
def call(*args,input=None,timeout=30,check=True):
    global command_class,private_stderr,sqlstate
    r=subprocess.run(['podman',*args],input=input,capture_output=True,timeout=timeout)
    if check and r.returncode:
        command_class='psql' if 'psql' in args else args[0]
        private_stderr=r.stderr.decode('utf-8','replace')[-4096:]
        match=re.search(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',private_stderr)
        sqlstate=match.group(1) if match else None
        raise RuntimeError('probe subprocess failed')
    return r
def check(name,ok):
    checks[name]=bool(ok)
    if not ok: raise AssertionError(name)
def inventory():
    files={}
    for root in (pathlib.Path('/etc/woowtech-cockpit/backup/apps'),pathlib.Path.home()/'.config/containers/systemd'):
        if root.exists():
            for p in root.rglob('*'):
                if p.is_file(): files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
    return {'containers':sorted(call('ps','-a','--no-trunc','--format','{{.ID}} {{.Names}} {{.State}}').stdout.splitlines()),
      'volumes':sorted(call('volume','ls','--format','{{.Name}}').stdout.splitlines()),'catalog_units':files}
def sql(text,user='probe_super',as_json=True,label='catalog-query'):
    global phase
    phase=label
    r=call('exec','-i','--env','PGOPTIONS=-c search_path=pg_catalog -c statement_timeout=10000',name,
      'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-h','/tmp','-U',user,'-d','postgres','-f','-',
      input=text.encode())
    return json.loads(r.stdout.strip()) if as_json else None
before=inventory()
try:
    check('existing-image',call('image','exists',P['image'],check=False).returncode==0)
    check('new-container-name',call('container','exists',name,check=False).returncode==1)
    check('new-volume-name',call('volume','exists',volume,check=False).returncode==1)
    call('volume','create','--label','woowbk.probe=nextcloud-fixed-sql',volume)
    made_volume=True
    made_container=True  # reserve cleanup intent before run: a partial failure can still leave this owned name behind
    call('run','-d','--pull=never','--name',name,'--label','woowbk.probe=nextcloud-fixed-sql',
      '--image-volume=ignore',
      '--network=none','--read-only','--user','70:70','--cap-drop=ALL','--security-opt=no-new-privileges',
      '--memory=384m','--memory-swap=384m','--cpus=0.5','--pids-limit=96','--shm-size=32m',
      '--tmpfs','/tmp:rw,size=32m,mode=1777','-v',volume+':/var/lib/postgresql/data:U,noexec,nosuid,nodev',
      '--entrypoint','/bin/sh',P['image'],'-ec',
      'initdb -D /var/lib/postgresql/data -U probe_super --auth=trust --locale=C --encoding=UTF8 --no-sync >/dev/null; '
      'exec postgres -D /var/lib/postgresql/data -c listen_addresses="" -c unix_socket_directories=/tmp '
      '-c max_connections=8 -c shared_buffers=16MB -c min_wal_size=32MB -c max_wal_size=64MB',timeout=60)
    for _ in range(90):
        r=call('exec',name,'pg_isready','-h','/tmp','-U','probe_super',timeout=5,check=False)
        if r.returncode==0: break
        time.sleep(1)
    else: raise TimeoutError('readiness')
    limits=json.loads(call('inspect',name,'--format',
      '{"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
      '"memory":{{.HostConfig.Memory}},"readonly":{{.HostConfig.ReadonlyRootfs}}}').stdout)
    check('bounded-isolation',limits['network']=='none' and not limits['ports']
      and 0<limits['memory']<=384*1024*1024 and limits['readonly'])
    sql('CREATE ROLE '+P['role']+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; '
      'GRANT CONNECT ON DATABASE postgres TO '+P['role']+'; GRANT CREATE ON SCHEMA public TO '+P['role']+';',
      as_json=False,label='setup-loader')
    sql('CREATE TABLE public.oc_filecache(fileid bigint PRIMARY KEY,parent bigint); '
      'CREATE TABLE public.oc_memories(fileid bigint PRIMARY KEY,parent bigint); '
      'INSERT INTO public.oc_filecache VALUES(1,10),(2,20); INSERT INTO public.oc_memories VALUES(1,10),(2,20);',
      user=P['role'],as_json=False,label='setup-tables')
    check('ordinary-integer-tables',sql(P['tables'],label='integer-table-guard') is True)
    initial=sql(P['shape'])
    check('no-archive-programs',initial['functions']==0 and initial['triggers']==0)
    sql(P['create'],user=P['role'],as_json=False,label='create-fixed-pair')
    check('exact-body-owner-invoker-searchpath-trigger',sql(P['verify']) is True)
    check('loader-privileges',sql("SELECT to_json(NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication "
      "AND NOT rolbypassrls) FROM pg_roles WHERE rolname='"+P['role']+"'") is True)
    sql('UPDATE public.oc_filecache SET parent=22 WHERE fileid=1;',user=P['role'],as_json=False)
    check('trigger-updates-only-matching-parent',sql('SELECT json_agg(json_build_array(fileid,parent) ORDER BY fileid) '
      'FROM public.oc_memories',user=P['role'])==[[1,22],[2,20]])
    check('all-probe-rows-preserved',sql('SELECT json_build_array((SELECT count(*) FROM public.oc_filecache),'
      '(SELECT count(*) FROM public.oc_memories))',user=P['role'])==[2,2])
    for label,change,reset in (
      ('reject-security-definer','ALTER FUNCTION public.memories_fcu_fun() SECURITY DEFINER;',
       'ALTER FUNCTION public.memories_fcu_fun() SECURITY INVOKER;'),
      ('reject-searchpath-change','ALTER FUNCTION public.memories_fcu_fun() SET search_path=public;',
       'ALTER FUNCTION public.memories_fcu_fun() SET search_path=pg_catalog;'),
      ('reject-disabled-trigger','ALTER TABLE public.oc_filecache DISABLE TRIGGER memories_fcu_trg;',
       'ALTER TABLE public.oc_filecache ENABLE TRIGGER memories_fcu_trg;')):
        sql(change,user=P['role'],as_json=False)
        check(label,sql(P['verify']) is False)
        sql(reset,user=P['role'],as_json=False)
    function=P['create'].split('CREATE TRIGGER ',1)[0]
    sql(function.replace('RETURN NEW;','RETURN NULL;'),user=P['role'],as_json=False)
    check('reject-body-change',sql(P['verify']) is False)
    sql(function,user=P['role'],as_json=False)
    sql('ALTER TABLE public.oc_memories ALTER COLUMN parent TYPE text;',user=P['role'],as_json=False)
    check('reject-noninteger-column',sql(P['tables']) is False)
    sql('ALTER TABLE public.oc_memories ALTER COLUMN parent TYPE bigint USING parent::bigint;',user=P['role'],as_json=False)
    sql("CREATE FUNCTION public.memories_fcu_fun(integer) RETURNS integer LANGUAGE sql AS 'SELECT $1';",
      user=P['role'],as_json=False)
    check('overloaded-function-has-exact-identity','public.memories_fcu_fun(integer)' in sql(P['objects'])['functions'])
    check('extra-program-counted',sql(P['shape'])['functions']==2)
    sql('DROP FUNCTION public.memories_fcu_fun(integer);',user=P['role'],as_json=False)
    shape=sql(P['shape'])
    check('all-other-shape-guards',shape['functions']==1 and shape['triggers']==1
      and all(shape[k]==0 for k in P['zero_keys']) and shape['role_settings']==0 and shape['defaults']==[])
    check('final-trusted-pair-and-types',sql(P['verify']) is True and sql(P['tables']) is True)
    combined=sql(P['combined'])
    check('nc09-role-baseline-equivalent',sql(P['roles'])==combined['roles'])
    check('nc09-extension-baseline-equivalent',sql(P['extensions'])==combined['extensions'])
    check('nc09-available-inventory',sql(P['available'])==combined['available'])
except Exception as e:
    checks['completed']=False
    failure=type(e).__name__
else:
    checks['completed']=True
    failure=None
finally:
    if made_container: call('rm','-f','--volumes','-t','10',name,timeout=60,check=False)
    if made_volume: call('volume','rm',volume,timeout=60,check=False)
    checks['own-probe-gone']=(not made_container or call('container','exists',name,check=False).returncode==1) and (
      not made_volume or call('volume','exists',volume,check=False).returncode==1)
    after=inventory()
    checks['durable-volume-inventory-unchanged']=after['volumes']==before['volumes']
    checks['catalog-and-unit-files-unchanged']=after['catalog_units']==before['catalog_units']
print(json.dumps({'checks':checks,'failure_type':failure,'image':P['image'],'source_commit':P['commit'],
  'failure_step':phase if failure else None,'command_class':command_class,'sqlstate':sqlstate,'_private_stderr':private_stderr,
  'observations':{'container_inventory_equal':after['containers']==before['containers'],
    'container_records_changed':len(set(after['containers'])^set(before['containers'])),
    'container_churn_is_observed_separately':'existing Headscale may restart independently; no app action issued'},
  'source_hashes':P['source_hashes'],'acceptance':'generated database proof; original Nextcloud full flow pending'},sort_keys=True))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'device': 'dev-d', 'image': IMAGE, 'memory_mib': 384,
                          'network': 'none', 'ports': [], 'requires': 'coordinator lease'}))
        return 0
    if args.out is None:
        p.error('--run requires --out')
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    files = ('backup-engine/woowbackup/ha_nextcloud.py', 'backup-engine/woowbackup/ha_nextcloud_memories.py')
    payload = {'image': IMAGE, 'role': ROLE, 'create': memories.CREATE_SQL, 'tables': memories.TABLES_SQL,
               'verify': memories.verify_sql(ROLE), 'shape': nc.SHAPE_SQL, 'objects': nc.OBJECTS_SQL,
               'zero_keys': [key for key, _ in nc.SHAPE_LABELS if key not in nc.SKIPPABLE],
               'roles': nc.LIVE_ROLES_SQL, 'extensions': nc.LIVE_EXTENSIONS_SQL, 'available': nc.LIVE_AVAILABLE_SQL,
               'combined': nc.live_db_sql(ROLE, appconfig=False), 'commit': commit,
               'source_hashes': {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files}}
    with open('/tmp/woowbk-dev-d-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.run([str(OWNER), 'd', '--verify-isolation'], check=True, capture_output=True, timeout=30)
        source = 'P=' + repr(payload) + '\n' + REMOTE
        result = subprocess.run([str(OWNER), 'd', 'python3', '-'], input=source.encode(),
                                capture_output=True, timeout=300)
        if result.returncode:
            raise RuntimeError('isolated probe runner failed; raw output withheld')
        evidence = json.loads(result.stdout)
        private = evidence.pop('_private_stderr', '')
        args.out.with_suffix('.private.log').write_text(private)
        isolation = subprocess.run([str(OWNER), 'd', '--verify-isolation'], capture_output=True, timeout=30)
        evidence['checks']['outer-isolation-preserved'] = isolation.returncode == 0
        args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'passed': sum(v is True for v in evidence['checks'].values()),
                          'total': len(evidence['checks']), 'source_commit': commit}))
        return 0 if all(evidence['checks'].values()) else 1


if __name__ == '__main__':
    sys.exit(main())
