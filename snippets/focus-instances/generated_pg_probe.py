#!/usr/bin/env python3
"""Generated PG16 instance adapter proof; default prints its plan, --run requires a coordinator lease.

Only owner.sh c/d enters the selected existing isolated lab. No installed helper, app container, app DB, baseline, registry,
catalog or Quadlet is changed. The committed engine is imported from a private temporary zip, never installed.
Two cases run sequentially, each with one disposable container/volume at a time (384 MiB, network none, no ports).
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / 'tests/e2e/lab/owner.sh'
IMAGE = 'sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
PREFIX = 'woowbk-inst-proof-'
CASE = 'instances-generated-pg'
DEVICES = ('c', 'd')

REMOTE = r'''
import base64,hashlib,json,os,pathlib,secrets,shutil,signal,subprocess,sys,tempfile,time
from types import SimpleNamespace

checks={}
owned=[]
phase='inventory'
failure=None
stderr_tail=''
generated_secrets=[]
current=None
volume=None
reserved_container=reserved_volume=False
deadline=time.monotonic()+300
cleanup_mode=False
cleanup_deadline=None

def require(label, ok):
    checks[label]=bool(ok)
    if not ok: raise RuntimeError(label)

def call(*args,input=None,stdout=None,timeout=60,check=True):
    global stderr_tail
    left=cleanup_deadline-time.monotonic() if cleanup_mode else deadline-time.monotonic()
    if left<=0: raise TimeoutError('proof time budget')
    stream=hasattr(input,'read')
    r=subprocess.run(['podman',*args],stdin=input if stream else None,
        input=None if stream else input,stdout=stdout or subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=max(1,min(timeout,left)))
    if check and r.returncode:
        text=r.stderr.decode('utf-8','replace')[-2048:]
        for secret in generated_secrets: text=text.replace(secret,'[generated-secret]')
        stderr_tail=text
        raise RuntimeError('own disposable command failed')
    return r

def inventory():
    files={}
    for root in (pathlib.Path('/etc/woowtech-cockpit/backup/apps'),pathlib.Path.home()/'.config/containers/systemd'):
        if root.exists():
            for p in root.rglob('*'):
                if p.is_file(): files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
    return {'volumes':sorted(call('volume','ls','--format','{{.Name}}').stdout.decode().splitlines()),
            'containers':sorted(call('ps','-a','--no-trunc','--format','{{.ID}} {{.Names}} {{.State}}').stdout.decode().splitlines()),
            'files':files}

def describe():
    raw=call('inspect',current,'--format',
        '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
        '"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
        '"memory":{{.HostConfig.Memory}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
        '"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}}}').stdout
    info=json.loads(raw)
    require('own-label-'+str(len(owned)),info['labels'].get('woowbk.instance-proof')==P['run_id'])
    require('own-mounts-'+str(len(owned)),
        [m['Name'] for m in info['mounts'] if m['Type']=='volume']==[volume])
    require('bounded-'+str(len(owned)),info['network']=='none' and not info['ports']
        and info['memory']==384*1024*1024 and info['readonly'] and info['image']==P['image'])
    owned.append({'id':info['id'],'name':current,'volume':volume,
                  'mounts':[{k:m[k] for k in ('Type','Name','Destination') if k in m} for m in info['mounts']]})
    journal()
    return info

def journal():
    path=root/'owned-resources.json'
    path.write_text(json.dumps({'run_id':P['run_id'],'container':current,'volume':volume,
        'reserved_container':reserved_container,'reserved_volume':reserved_volume,'owned':owned},sort_keys=True))
    path.chmod(0o600)

def cleanup():
    global reserved_container,reserved_volume
    if reserved_container and call('container','exists',current,check=False).returncode==0:
        info=describe()  # record exact owned ID/mounts before removal; labels and mount identity must match
        call('rm','-f','--volumes','-t','10',info['id'],timeout=30)
    if reserved_volume and call('volume','exists',volume,check=False).returncode==0:
        label=call('volume','inspect',volume,'--format','{{index .Labels "woowbk.instance-proof"}}').stdout.decode().strip()
        require('volume-label-'+str(len(owned)),label==P['run_id'])
        call('volume','rm',volume,timeout=30)
    require('container-absent-'+str(len(owned)),not reserved_container or
            call('container','exists',current,check=False).returncode==1)
    require('volume-absent-'+str(len(owned)),not reserved_volume or
            call('volume','exists',volume,check=False).returncode==1)
    reserved_container=reserved_volume=False

def start(name):
    global current,volume,reserved_container,reserved_volume
    current=name
    volume=name+'-data'
    require('new-container-'+name,call('container','exists',name,check=False).returncode==1)
    require('new-volume-'+name,call('volume','exists',volume,check=False).returncode==1)
    reserved_volume=True  # intent before create: partial create failures still belong to this run
    journal()
    call('volume','create','--label','woowbk.instance-proof='+P['run_id'],volume)
    reserved_container=True  # intent before run: no existing name is ever replaced or removed
    journal()
    call('run','-d','--pull=never','--name',name,'--label','woowbk.instance-proof='+P['run_id'],
        '--image-volume=ignore','--network=none','--read-only','--user','70:70','--cap-drop=ALL',
        '--security-opt=no-new-privileges','--memory=384m','--memory-swap=384m','--cpus=0.5',
        '--pids-limit=96','--shm-size=32m','--tmpfs','/tmp:rw,size=16m,mode=1777',
        '--tmpfs','/var/run/postgresql:rw,size=8m,mode=1777',
        '-v',volume+':/var/lib/postgresql/data:U,noexec,nosuid,nodev',
        '--entrypoint','/bin/sh',P['image'],'-ec',
        'initdb -D /var/lib/postgresql/data -U probe_super --auth=reject --locale=C --encoding=UTF8 --no-sync >/dev/null; '
        'printf "local all probe_super trust\\nlocal all all scram-sha-256\\n" > /var/lib/postgresql/data/pg_hba.conf; '
        'exec postgres -D /var/lib/postgresql/data -c listen_addresses="" '
        '-c unix_socket_directories=/var/run/postgresql -c max_connections=8 -c shared_buffers=16MB '
        '-c min_wal_size=32MB -c max_wal_size=64MB',timeout=60)
    for _ in range(60):
        if call('exec',name,'pg_isready','-U','probe_super','-d','postgres',timeout=5,check=False).returncode==0: break
        time.sleep(0.5)
    else: raise TimeoutError('own PostgreSQL readiness')
    describe()

class Runner:
    owner='appowner'
    uid=os.getuid()
    home=str(pathlib.Path.home())
    def podman(self,*args,**kwargs):
        global stderr_tail
        # The real adapter can reach only this disposable container, never another device/app container.
        rest=list(args[1:]) if args and args[0]=='exec' else []
        while rest and rest[0] in ('-i','-e'):
            width=1 if rest[0]=='-i' else 2
            if len(rest)<width: raise RuntimeError('invalid disposable exec options')
            del rest[:width]
        require_target=(len(rest)>=2 and rest[0]==current and
                        rest[1] in ('psql','pg_dump','pg_restore','pg_dumpall','createdb'))
        # The adapter writes/removes ONLY its private bounded restore TOC, using this exact fixed shell grammar.
        import re
        toc=lambda value: re.fullmatch(r'/tmp/woowbk-ha-[a-f0-9]{24}\.list',value) is not None
        require_target = require_target or (len(rest)==6 and rest[:5]==
            [current,'sh','-ec','umask 077; set -C; cat > "$1"','woowbk-ha-toc'] and toc(rest[5]))
        require_target = require_target or (len(rest)==5 and rest[:4]==[current,'rm','-f','--'] and toc(rest[4]))
        if not require_target: raise RuntimeError('adapter target escaped disposable container')
        left=deadline-time.monotonic()
        if left<=0: raise TimeoutError('proof time budget')
        # Use the engine's real bounded stream relay, including file stdout and a zero output budget. No limit bypass.
        r=default_runner(['podman',*args],input=kwargs.get('input'),stdout=kwargs.get('stdout'),
            timeout=max(1,min(kwargs.get('timeout',60),left)),cwd=str(root),max_output=kwargs.get('max_output'))
        if r.returncode and kwargs.get('check',True):
            stderr_tail=(r.stderr or b'').decode('utf-8','replace')[-2048:]
            for secret in generated_secrets: stderr_tail=stderr_tail.replace(secret,'[generated-secret]')
            raise BackupError('job-failed','Generated probe command failed; raw output withheld.')
        return r

def sql(text, database='postgres'):
    return call('exec','-i',current,'psql','-X','-w','-A','-t','-q','-v','ON_ERROR_STOP=1',
                '-U','probe_super','-d',database,'-f','-',input=text.encode()).stdout

def password():
    value=secrets.token_hex(24)
    generated_secrets.append(value)
    return value

def json_query(adapter,pg,text,database='template1'):
    return adapter._psql_json(pg['container'],pg['user'],database,text,'generated instance')

def snapshot(adapter,pg,folder,exclude=None):
    def acl(value):
        # Compare role names and privilege facts, independent of OID allocation or ACL array insertion order.
        return ("(SELECT coalesce(json_agg(json_build_array(CASE WHEN a.grantee=0 THEN NULL ELSE "
            "pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable) ORDER BY "
            "pg_get_userbyid(a.grantee),a.privilege_type,a.is_grantable),'[]'::json) FROM aclexplode("+value+") a)")
    rows=json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(datname,pg_get_userbyid(datdba),"
        "pg_encoding_to_char(encoding),datcollate,datctype,datistemplate,datallowconn,"+
        acl("coalesce(datacl,acldefault('d',datdba))")+") "
        "ORDER BY datname),'[]'::json) FROM pg_database WHERE datname NOT IN ('template0','template1')")
    names=[r[0] for r in rows if r[0]!=exclude]
    rows=[r for r in rows if r[0]!=exclude]
    roles=json_query(adapter,pg,"SELECT json_agg(json_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
        "rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil::text,coalesce(md5(rolpassword),''),rolconfig) "
        "ORDER BY rolname) FROM pg_authid")
    members=json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(r.rolname,m.rolname,g.rolname,"
        "a.admin_option,a.inherit_option,a.set_option) ORDER BY r.rolname,m.rolname,g.rolname),'[]'::json) "
        "FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member "
        "JOIN pg_roles g ON g.oid=a.grantor")
    spec={'id':'instance','postgres':'main','databases':'all','exclude_tables':[]}
    digest=adapter._capture_pg_digest(spec,folder,databases=names,roles=True)
    owners={n:json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname,c.relkind,"
        "pg_get_userbyid(c.relowner),"+acl("c.relacl")+") ORDER BY n.nspname,c.relname),'[]'::json) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
        "AND n.nspname !~ '^pg_(toast|temp)' AND c.relkind IN ('r','S','i')",n) for n in names}
    schemas={n:json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(nspname,pg_get_userbyid(nspowner),"
        +acl("coalesce(nspacl,acldefault('n',nspowner))")+") ORDER BY nspname),'[]'::json) FROM pg_namespace WHERE nspname NOT IN "
        "('pg_catalog','information_schema') AND nspname !~ '^pg_(toast|temp)'",n) for n in names}
    columns={n:json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname,a.attname,"
        "format_type(a.atttypid,a.atttypmod),a.attnotnull,"+acl('a.attacl')+") ORDER BY n.nspname,c.relname,a.attname),'[]'::json) FROM pg_attribute a "
        "JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE "
        "n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_(toast|temp)' "
        "AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p')",n) for n in names}
    return {'catalog':rows,'roles':roles,'members':members,'owners':owners,'schemas':schemas,
            'columns':columns,'digest':digest['digest']}

def hash_state(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def app_rows(adapter,pg,name):
    return json_query(adapter,pg,'SELECT json_agg(value ORDER BY value) FROM public.marker',name)

def login_proof(app_id,credentials,old_password=None,*,new_column=False):
    # Private retained credential FILE is data, never sourced/executed. SCRAM is required for this login by pg_hba.
    value=json.loads(credentials.read_text())
    def execute(password,text,check=True):
        return call('exec','-i','-e','PGPASSWORD='+password,current,'psql','-X','-w','-q','-A','-t',
            '-v','ON_ERROR_STOP=1','-U','app_login','-d',app_id,'-f','-',input=text.encode(),check=check)
    if old_password is not None:
        require(app_id+'-rotated-old-login-rejected',execute(old_password,'SELECT 1;',False).returncode!=0)
    script=('BEGIN; SELECT * FROM public.marker; '
        "INSERT INTO public.marker(id,value"+(',ha_new_column' if new_column else '')+") VALUES(9001,'login write'"+
        (",'new column write'" if new_column else '')+"); "
        "ALTER TABLE public.marker ADD COLUMN login_migration_column text; "
        "ALTER TABLE public.marker DROP COLUMN login_migration_column; "
        "CREATE TABLE public.login_migration_probe(id integer); "
        "INSERT INTO public.login_migration_probe VALUES(1); "
        "ALTER TABLE public.login_migration_probe ADD COLUMN next integer; "
        "DROP TABLE public.login_migration_probe; ROLLBACK;")
    execute(value['password'],script)
    require(app_id+('-new-column-' if new_column else '-')+'actual-login-select-insert-migration',True)

def damaged_dump(adapter,pg,path,work):
    # Preserve the complete custom TOC but corrupt/truncate its data blocks. Prove TOC preflight passes and data read
    # fails before using it for an injected failure AFTER replacement; a 32-byte bad header would prove only preflight.
    data=pathlib.Path(path).read_bytes()
    for removed in (8,32,128,512):
        candidate=work/('truncated-'+str(removed)+'.dump')
        candidate.write_bytes(data[:-removed])
        with candidate.open('rb') as f:
            listed=call('exec','-i',current,'pg_restore','--list',input=f,check=False)
        if listed.returncode: continue
        with candidate.open('rb') as f:
            loaded=call('exec','-i',current,'pg_restore','--file=/dev/null',input=f,check=False)
        if loaded.returncode:
            require(adapter.app.id+'-injection-valid-toc-broken-data',True)
            return candidate
    raise RuntimeError('no bounded post-TOC failure fixture')

def case(app_id,root):
    global phase
    phase=app_id+'-start'
    name=P['prefix']+P['run_id']+'-'+app_id
    start(name)
    pg={'id':'main','scope':'instance','container':name,'user':'probe_super','database':'postgres'}
    app=SimpleNamespace(id=app_id,name=app_id,postgres=[pg],verify=[])
    adapter=QuadletPostgresAdapter(app,Runner(),lambda _line:None)
    adapter.ha_import=True
    work=root/app_id
    (work/'postgres').mkdir(parents=True,mode=0o700)
    initial_password=password()
    credentials=work/'current-login.json'
    credentials.write_text(json.dumps({'password':initial_password})); credentials.chmod(0o600)
    sql("CREATE ROLE db_owner NOLOGIN; CREATE ROLE table_owner NOLOGIN; "
        "CREATE ROLE app_login LOGIN PASSWORD '"+initial_password+"'; CREATE ROLE outsider LOGIN PASSWORD '"+password()+"'; "
        "CREATE ROLE reader NOLOGIN; GRANT reader TO outsider; GRANT table_owner TO app_login; "
        'CREATE DATABASE "'+app_id+'" OWNER db_owner; CREATE DATABASE outside OWNER outsider; '
        'CREATE DATABASE removed_later OWNER outsider;')
    controls=json_query(adapter,pg,"SELECT coalesce(json_agg(json_build_array(name,version,trusted) ORDER BY "
        "name,version),'[]'::json) FROM pg_available_extension_versions WHERE name IN "
        "('pgstattuple','pg_stat_statements') AND NOT trusted")
    require(app_id+'-installed-untrusted-contrib-available',bool(controls))
    extension=next((r for r in controls if r[0]=='pgstattuple'),controls[0])
    ext,version,_trusted=extension
    # Both identifiers/versions originate only from the installed controls of this owned generated cluster.
    from woowbackup.ha_instance_access import ident,literal
    sql('CREATE EXTENSION '+ident(ext)+' VERSION '+literal(version)+';',app_id)
    sql("CREATE TABLE public.marker(id serial PRIMARY KEY,value text,ha_new_column text); "
        "INSERT INTO public.marker(value,ha_new_column) VALUES('HA rows','HA new column'); "
        'ALTER TABLE public.marker OWNER TO table_owner; '
        'GRANT SELECT,INSERT,UPDATE,DELETE ON public.marker TO app_login; '
        'GRANT SELECT(value) ON public.marker TO app_login; '
        'GRANT USAGE,SELECT,UPDATE ON public.marker_id_seq TO app_login; '
        'GRANT USAGE,CREATE ON SCHEMA public TO app_login;',app_id)
    # A real unknown NEW app table/sequence is rejected before any DROP; the native fixture also proves the ordinary
    # login retains SELECT/INSERT/schema-migration rights after each refusal. No ownership/default-privilege guessing.
    guard_dir=work/'guard'; (guard_dir/'postgres').mkdir(parents=True)
    guards=[]
    for kind in ('TABLE','SEQUENCE'):
        sql('CREATE '+kind+' public.ha_unknown'+('(id integer)' if kind=='TABLE' else '')+';',app_id)
        generated=adapter._dump_database(dict(pg,database=app_id),guard_dir)
        saved=guard_dir/(kind.lower()+'.dump'); shutil.copyfile(generated['file'],saved)
        pathlib.Path(generated['file']).unlink()
        guards.append((kind,saved))
        sql('DROP '+kind+' public.ha_unknown;',app_id)
    # Real custom-format pg_dump of generated HA-equivalent rows, before changing this fixture to its device state.
    converted=adapter._dump_database(dict(pg,database=app_id),work)
    sql("ALTER TABLE public.marker DROP COLUMN ha_new_column; TRUNCATE public.marker RESTART IDENTITY; "
        "INSERT INTO public.marker(value) VALUES('device rows');",app_id)
    if app_id=='litellm':
        sql('CREATE SCHEMA customer_omitted; CREATE TABLE customer_omitted.private_rows(value text); '
            "INSERT INTO customer_omitted.private_rows VALUES('current L38 safety only');",app_id)
    sql("CREATE TABLE public.marker(id serial PRIMARY KEY,value text); INSERT INTO public.marker(value) VALUES('outside before'); "
        'ALTER TABLE public.marker OWNER TO outsider;','outside')
    sql("CREATE TABLE public.maintenance_marker(value text); INSERT INTO public.maintenance_marker VALUES('maintenance before');")
    phase=app_id+'-complete-conversion'
    complete=adapter.import_instance_database(pg,converted,work)
    item=adapter._instance_manifest(complete,lambda kind,name,path:'apps/'+app_id+'/'+kind+'/'+name)
    archive._postgres_instance(item,'probe.postgres',app_id,lambda *_args:None)
    require(app_id+'-complete-real-payload',item['ha_database']==app_id and len(item['databases'])==4
            and any(db['name']=='outside' and db['owner']=='outsider' for db in item['databases']))
    phase=app_id+'-later-changes'
    sql("INSERT INTO public.marker(value) VALUES('outside after conversion');",'outside')
    sql("INSERT INTO public.maintenance_marker VALUES('maintenance after conversion');")
    sql("ALTER ROLE outsider PASSWORD '"+password()+"'; ALTER ROLE probe_super PASSWORD '"+password()+"'; "
        "CREATE ROLE later_owner NOLOGIN; CREATE ROLE later_table_owner NOLOGIN; "
        'CREATE DATABASE later_db OWNER later_owner; DROP DATABASE removed_later; '
        'ALTER DATABASE "'+app_id+'" OWNER TO later_owner;')
    rotated_password=password()
    sql("ALTER ROLE app_login PASSWORD '"+rotated_password+"';")
    credentials.write_text(json.dumps({'password':rotated_password})); credentials.chmod(0o600)
    sql('GRANT later_table_owner TO app_login; ALTER TABLE public.marker OWNER TO later_table_owner;',app_id)
    sql("CREATE TABLE public.marker(value text); INSERT INTO public.marker VALUES('new DB after conversion'); "
        'ALTER TABLE public.marker OWNER TO later_owner;','later_db')
    outside=snapshot(adapter,pg,work/'outside-before.txt',exclude=app_id)
    before=snapshot(adapter,pg,work/'before.txt')
    login_proof(app_id,credentials,initial_password)
    db=next(db for db in complete['databases'] if db['name']==app_id)
    phase=app_id+'-new-object-refusal'
    for kind,generated in guards:
        failed=False
        try: adapter._restore_ha_instance_database(pg,db,generated)
        except BackupError as error:
            failed='目前不存在' in error.message
        require(app_id+'-new-'+kind.lower()+'-refused-before-drop',failed and
            snapshot(adapter,pg,work/('refused-'+kind+'.txt'))==before)
        login_proof(app_id,credentials)
    safety_dir=work/'safety'
    (safety_dir/'postgres').mkdir(parents=True,mode=0o700)
    safety=adapter._dump_instance(pg,safety_dir)
    require(app_id+'-safety-unmarked','ha_database' not in safety)
    original_access=adapter._capture_ha_instance_access(pg,app_id)
    phase=app_id+'-selective-import'
    adapter._restore_ha_instance_database(pg,db,db['file'])
    require(app_id+'-app-rows',app_rows(adapter,pg,app_id)==['HA rows'])
    require(app_id+'-current-owner',adapter._ha_database_owner(pg,app_id)=='later_owner')
    restored_access=adapter._capture_ha_instance_access(pg,app_id)
    from woowbackup.ha_instance_access import comparable
    require(app_id+'-current-table-owner-acls-extension',
        comparable(original_access,restored_access)==comparable(restored_access,original_access) and
        any(r[1]=='marker' and r[-2]=='later_table_owner' for r in restored_access['relations']))
    require(app_id+'-new-ha-column-imported',json_query(adapter,pg,
        "SELECT json_agg(ha_new_column) FROM public.marker",app_id)==['HA new column'])
    login_proof(app_id,credentials,initial_password,new_column=True)
    if app_id=='litellm':
        require(app_id+'-l38-omitted-schema-not-recreated',json_query(adapter,pg,
            "SELECT to_json(to_regnamespace('customer_omitted') IS NULL)",app_id) is True)
    after=snapshot(adapter,pg,work/'outside-after.txt',exclude=app_id)
    require(app_id+'-later-outside-rows-catalog-owners-passwords',after==outside)
    phase=app_id+'-injected-failure'
    bad=damaged_dump(adapter,pg,db['file'],work)
    failed=False
    try: adapter._restore_ha_instance_database(pg,db,bad)
    except BackupError: failed=True
    require(app_id+'-real-pg-restore-failed',failed)
    require(app_id+'-failure-after-replacement',json_query(adapter,pg,
        "SELECT to_json(to_regclass('public.marker') IS NULL)",app_id) is True)
    require(app_id+'-failure-outsiders-unchanged',snapshot(adapter,pg,work/'outside-failed.txt',exclude=app_id)==outside)
    phase=app_id+'-full-safety-rollback'
    cleanup()
    removed_at=time.time()
    start(name)
    adapter._restore_instance(pg,[(db,db['file']) for db in safety['databases']],safety['globals'],removed_at=removed_at)
    rolled_back=snapshot(adapter,pg,work/'after-rollback.txt')
    require(app_id+'-full-current-safety-catalog-rows-owners-role-passwords',rolled_back==before)
    require(app_id+'-original-app-restored',app_rows(adapter,pg,app_id)==['device rows'])
    login_proof(app_id,credentials,initial_password)
    proofs[app_id]={'before':hash_state(before),'after_rollback':hash_state(rolled_back),
                    'outside_before':hash_state(outside),'outside_after_import':hash_state(after),
                    'database_count':len(before['catalog']),'role_count':len(before['roles']),
                    'installed_untrusted_extension':{'name':ext,'version':version,'trusted':False},
                    'new_objects':'table/sequence refused before DROP; new column uses current table-wide grants'}
    phase=app_id+'-cleanup'
    cleanup()

before_inventory=inventory()
proofs={}
root=pathlib.Path(tempfile.mkdtemp(prefix=P['prefix']+P['run_id']+'-',dir=pathlib.Path.home()))
try:
    os.chmod(root,0o700)
    require('probe-filesystem-reserve',shutil.disk_usage(root).free>=13*1024**3+512*1024**2)
    package=base64.b64decode(P['engine_zip'])
    require('engine-zip-hash',hashlib.sha256(package).hexdigest()==P['engine_sha256'])
    engine=root/'engine.zip'
    engine.write_bytes(package)
    engine.chmod(0o600)
    sys.path.insert(0,str(engine))
    from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
    from woowbackup import archive
    from woowbackup.errors import BackupError
    from woowbackup.podman import default_runner
    image=json.loads(call('image','inspect',P['image'],'--format','{"id":{{json .Id}},"arch":{{json .Architecture}}}').stdout)
    require('existing-pinned-image',image['id']==P['image'] and image['arch']=='amd64')
    require('device-memory-headroom',int(pathlib.Path('/sys/fs/cgroup/memory.max').read_text())-
        int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())>=512*1024*1024)
    def interrupted(_signum,_frame): raise RuntimeError('proof interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGINT,interrupted)
    signal.signal(signal.SIGALRM,interrupted)
    signal.alarm(300)
    for app_id in ('n8n','litellm'): case(app_id,root)
    checks['completed']=True
except BaseException as error:
    checks['completed']=False
    failure=type(error).__name__
finally:
    cleanup_mode=True
    cleanup_deadline=time.monotonic()+45
    signal.alarm(0)
    try: cleanup()
    except BaseException: checks['cleanup']=False
    after_inventory=inventory()
    checks['durable-volumes-unchanged']=before_inventory['volumes']==after_inventory['volumes']
    checks['catalog-and-quadlet-files-unchanged']=before_inventory['files']==after_inventory['files']
    if checks.get('cleanup') is not False:
        shutil.rmtree(root)
    else:
        checks['private-run-root-retained']=root.exists()
print(json.dumps({'checks':checks,'failure_type':failure,'failure_step':phase if failure else None,
    'proofs':proofs,'owned_resources':owned,'source_commit':P['commit'],'engine_sha256':P['engine_sha256'],
    'image':P['image'],'device':P['device'],'run_id':P['run_id'],'private_run_root':str(root) if root.exists() else None,
    'acceptance':'generated-PG adapter proof; original n8n/LiteLLM acceptance is complementary',
    'container_churn_count':len(set(before_inventory['containers'])^set(after_inventory['containers'])),
    '_private_stderr':stderr_tail},sort_keys=True))
'''


def plan(device):
    return {'case': CASE, 'device': 'woowbk-dev-'+device, 'image': IMAGE,
            'resource_prefix': PREFIX, 'cases': ['n8n', 'litellm'], 'memory_mib': 384,
            'network': 'none', 'ports': [], 'image_volume': 'ignore', 'wall_budget_seconds': 300,
            'staging_filesystem': '/home/appowner', 'reserve_gib': 13,
            'methods': ['_dump_database', 'import_instance_database', '_instance_manifest',
                        '_restore_ha_instance_database', '_ha_database_owner', '_dump_instance',
                        '_restore_instance', '_capture_pg_digest'],
            'requires': 'exact coordinator lease; heavy wrapper and corresponding device mutation lock',
            'access': 'SCRAM login SELECT/INSERT/migration; distinct DB/table owner; untrusted installed extension',
            'new_objects': 'table/sequence refusal before DROP; new column under current table-wide grants',
            'acceptance': 'generated-PG proof, not an original application import'}


def package_engine():
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT / 'backup-engine/woowbackup').rglob('*.py')):
            archive.write(path, path.relative_to(ROOT / 'backup-engine'))
    return out.getvalue()


def verify_isolation(device):
    # owner.sh's historical --verify-isolation whitelist excludes c. Read exactly the SAME fixed fields through its
    # existing isolated LAB_HOME/bin/labpodman; no host Podman, wrapper edits or device configuration changes.
    script = ('source "$1"; device_vars "$2"; exec "$LP" inspect "$NAME" --format '
              "'{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'")
    result = subprocess.run(['bash', '-c', script, 'woowbk-instance-isolation',
                             str(ROOT / 'tests/e2e/lab/lib.sh'), device],
                            capture_output=True, timeout=30)
    return result.returncode == 0 and result.stdout.strip() == b'true none {}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--device', choices=DEVICES, default='d')
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps(plan(args.device), sort_keys=True))
        return 0
    if args.lease is None or args.out is None:
        parser.error('--run requires --lease and --out')
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    clean = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True)
    if clean:
        raise RuntimeError('commit the candidate and driver first')
    lease = json.loads(args.lease.read_text())
    expires = datetime.datetime.fromisoformat(lease['expires'])
    if (lease.get('device') != 'woowbk-dev-'+args.device or lease.get('case') != CASE
            or lease.get('worktree') != str(ROOT) or lease.get('source_commit') != commit
            or lease.get('image') != IMAGE or lease.get('resource_prefix') != PREFIX
            or expires <= datetime.datetime.now(datetime.timezone.utc)):
        raise RuntimeError('coordinator lease does not match this exact proof')
    if args.device=='d' and Path('/tmp/woowbk-dev-d-emqx-main-waiting').exists():
        raise RuntimeError('EMQX probe has device priority; queue this lease later')
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))) // 1024
    if available < 1200 or shutil.disk_usage(ROOT).free < 13 * 1024**3 + 512 * 1024**2:
        raise RuntimeError('host headroom floor not met')
    package = package_engine()
    import secrets
    payload = {'commit': commit, 'device':'woowbk-dev-'+args.device,
               'run_id': secrets.token_hex(6), 'image': IMAGE, 'prefix': PREFIX,
               'engine_zip': base64.b64encode(package).decode(), 'engine_sha256': hashlib.sha256(package).hexdigest()}
    with Path('/tmp/woowbk-dev-'+args.device+'-mutation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not verify_isolation(args.device):
            raise RuntimeError('selected device isolation assertion failed before remote dispatch')
        source = 'P=' + repr(payload) + '\n' + REMOTE
        result = subprocess.run([str(OWNER), args.device, 'python3', '-B', '-'], input=source.encode(),
                                capture_output=True, timeout=360)
        if result.returncode:
            raise RuntimeError('isolated generated proof runner failed; raw output withheld')
        evidence = json.loads(result.stdout)
        private = evidence.pop('_private_stderr', '')
        evidence['checks']['outer-isolation-preserved'] = verify_isolation(args.device)
        for path, data in ((args.out, json.dumps(evidence, indent=2, sort_keys=True)+'\n'),
                           (args.out.with_suffix('.private.log'), private)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write(data)
        print(json.dumps({'passed': sum(v is True for v in evidence['checks'].values()),
                          'total': len(evidence['checks']), 'source_commit': commit}))
        return 0 if all(evidence['checks'].values()) else 1


if __name__ == '__main__':
    sys.exit(main())
