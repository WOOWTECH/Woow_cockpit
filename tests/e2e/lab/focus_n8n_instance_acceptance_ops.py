"""Fixed dev-c operations for the n8n case. Importing this file performs no I/O.

The controller sends this committed file to device Python, never installs it.
Only dispatch() touches the device; every write is restricted to the leased
case's files or the four reviewed existing files/catalog.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

APP = '/home/appowner'
CATALOG = '/etc/woowtech-cockpit/backup/apps/n8n.json'
QDIR = APP + '/.config/containers/systemd/'
ENV = APP + '/.config/n8n/n8n.env'
UNITS = ['n8n-postgres.service', 'n8n-valkey.service', 'n8n.service', 'n8n-worker.service',
         'n8n-webhook.service', 'n8n-runners.service', 'n8n-worker-runners.service']
OWNER = '/usr/local/bin/woowbk-owner'
PROTECTED = ['20261118T095520Z-33eb7474', '20261118T095247Z-388c9bd7']
BASE = re.compile(r'woowbk_focus_n8n_[0-9a-f]{12}\Z')
MARKER_SQL = "SELECT to_json(count(*)=1) FROM public.settings WHERE key='woowbk.lab.baseline.before';"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def call(argv, *, data=None, timeout=60, check=True):
    p = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('fixed device command failed')
    return p


def owner(*args, **kwargs):
    return call([OWNER, *args], **kwargs)


def sql(database, query, *, as_json=True):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]{0,62}', database):
        raise ValueError('invalid case database')
    p = owner('podman', 'exec', '-i', 'n8n-postgres', 'psql', '-X', '-w', '-A', '-t', '-q',
              '-v', 'ON_ERROR_STOP=1', '-U', 'n8n', '-d', database, '-f', '-',
              data=query.encode(), timeout=180)
    return json.loads(p.stdout) if as_json else None


def read_regular(path, limit=1024*1024):
    p = Path(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > limit:
            raise ValueError('unsafe or unbounded case file')
        with os.fdopen(os.dup(fd), 'rb') as inp:
            b = inp.read(limit + 1)
        if len(b) > limit:
            raise ValueError('unbounded case file')
        return b, {'sha256': digest(b), 'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid}
    finally:
        os.close(fd)


def atomic(path, data, *, mode=0o600, uid=None, gid=None):
    """Same-directory atomic replacement, fsync before receipt advancement."""
    path = Path(path)
    if any(p.is_symlink() for p in path.parents):
        raise ValueError('symlink ancestor of case write')
    fd, temp = tempfile.mkstemp(prefix='.focus-n8n-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fchmod(out.fileno(), mode)
            os.fchown(out.fileno(), os.geteuid() if uid is None else uid,
                      os.getegid() if gid is None else gid); os.fsync(out.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(temp): os.unlink(temp)


class Store:
    def __init__(self, name, *, parent='/var/lib/woowtech-backup/focus-n8n-instance', create=False):
        if not BASE.fullmatch(name):
            raise ValueError('invalid case name')
        self.name = name
        self.path = Path(parent)/name
        if create:
            Path(parent).mkdir(mode=0o700, exist_ok=True)
        for p in (Path(parent), self.path):
            if p.exists() or p.is_symlink():
                s = p.lstat()
                if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
                    raise ValueError('unsafe recovery directory')
        if create: self.path.mkdir(mode=0o700, exist_ok=False)
        self.state = json.loads(read_regular(self.path/'state.json')[0]) if (self.path/'state.json').exists() else {}

    def save(self):
        atomic(self.path/'state.json', json.dumps(self.state).encode(), uid=os.geteuid(), gid=os.getegid())

    def capture(self, paths):
        if self.state:
            raise ValueError('original capture already exists')
        self.state = {'original': {}, 'allowed': {}, 'hook': False}
        for i, path in enumerate(paths):
            data, meta = read_regular(path)
            key = 'original-' + str(i)
            atomic(self.path/key, data)
            self.state['original'][path] = dict(meta, copy=key)
            self.state['allowed'][path] = [meta['sha256']]
        self.save()

    def replace(self, path, data):
        meta = self.state['original'][path]
        _, now = read_regular(path)
        if now['sha256'] not in self.state['allowed'][path]:
            raise ValueError('file changed outside this case')
        h = digest(data)
        if h not in self.state['allowed'][path]: self.state['allowed'][path].append(h)
        self.save()  # intent before replacement, including partial failure
        atomic(path, data, mode=meta['mode'], uid=meta['uid'], gid=meta['gid'])

    def restore(self, paths):
        for path in paths:
            meta = self.state['original'][path]
            data, _ = read_regular(self.path/meta['copy'])
            if digest(data) != meta['sha256']:
                raise ValueError('protected recovery bytes changed')
            self.replace(path, data)


def unit_state(unit, *, root=False):
    argv = ['systemctl'] + ([] if root else ['--user']) + [
        'show', unit, '--property=ActiveState,SubState,UnitFileState']
    p = call(argv) if root else owner(*argv)
    return dict(x.split('=', 1) for x in p.stdout.decode().splitlines() if '=' in x)


def inventory():
    """No DB connection, helper invocation, complete inspect, env or secret output."""
    catalogs = {}
    for p in Path(CATALOG).parent.glob('*.json'):
        catalogs[p.name] = read_regular(p)[1]['sha256']
    entry = json.loads(read_regular(CATALOG)[0])
    files = {QDIR+n: read_regular(QDIR+n)[1] for n in entry['quadlet']['files']}
    for c in entry['config_files']:
        path = APP+'/'+c['path']; files[path] = read_regular(path)[1]
    protected = {}
    for bid in PROTECTED:
        paths = list(Path('/var/lib/woowtech-backup/archives').glob(bid+'.*'))
        if len(paths) != 1 or paths[0].is_symlink():
            raise ValueError('protected original baseline missing or ambiguous')
        p = paths[0]
        h = hashlib.sha256()
        with p.open('rb') as inp:
            for b in iter(lambda: inp.read(8*1024**2), b''): h.update(b)
        protected[bid] = {'sha256': h.hexdigest(), 'bytes': p.stat().st_size}
    jobs = []
    paths = list(Path('/var/lib/woowtech-backup/jobs').glob('j*.json'))
    if len(paths) > 10000: raise ValueError('unbounded job inventory')
    for p in paths:
        j = json.loads(read_regular(p)[0])
        if j.get('state') in ('queued', 'running'):
            jobs.append(j['id'])
    images = owner('podman','images','--no-trunc','--format','{{.ID}}').stdout.decode().split()
    policy=Path('/etc/woowtech-cockpit/backup/retention.json')
    policy_bytes=read_regular(policy)[0] if policy.exists() else None
    retention=json.loads(policy_bytes) if policy_bytes else {}
    keep=retention.get('apps',{}).get('n8n',{}).get('keep_last',retention.get('default_keep_last'))
    return {'catalog': catalogs, 'entry': entry, 'files': files, 'protected': protected,
            'retention_keep':keep,'retention_sha256':digest(policy_bytes) if policy_bytes else None,
            'units': {u:unit_state(u) for u in UNITS+['n8n.target']},
            'timer': unit_state('woowtech-cockpit-backup-schedule.timer', root=True),
            'volumes': sorted(owner('podman','volume','ls','--format','{{.Name}}').stdout.decode().split()),
            'images': sorted(set(x.removeprefix('sha256:') for x in images)),
            'running': owner('podman','ps','-q').stdout.decode().split(), 'active_jobs':jobs}


def engine_hashes():
    root = Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')
    result = {str(p.relative_to(root)): read_regular(p)[1]['sha256'] for p in root.rglob('*.py')
              if '__pycache__' not in p.parts}
    result['../woowtech-cockpit-backup'] = read_regular('/usr/local/libexec/woowtech-cockpit-backup')[1]['sha256']
    return result


def resolve_intent(request_id):
    """Read the existing request journal; NEVER re-send an uncertain start request."""
    p = Path('/var/lib/woowtech-backup/requests.json')
    doc = json.loads(read_regular(p, 8*1024*1024)[0]) if p.exists() else {}
    found = (doc.get('requests') or {}).get(request_id)
    return found.get('job_id') if isinstance(found, dict) else None


def state(store, tag, databases=None):
    if not re.fullmatch(r'[a-z_]{1,40}', tag): raise ValueError('invalid snapshot tag')
    sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
    from woowbackup.cli import Services
    from woowbackup.paths import Paths
    from woowbackup import ha_instance_access
    svc = Services(Paths()); app = svc.catalog()['n8n']; adapter = svc.adapter(app)
    names = sql('postgres', "SELECT coalesce(json_agg(datname ORDER BY datname),'[]'::json) FROM pg_database "
                           'WHERE NOT datistemplate AND datallowconn;')
    chosen = names if databases is None else databases
    if not set(chosen) <= set(names): raise ValueError('snapshot database missing')
    serial=store.state.get('snapshot_serial',0)+1;store.state['snapshot_serial']=serial;store.save()
    result = {'databases': {}}
    for i, name in enumerate(chosen):
        spec = {'id':'focus','postgres':app.postgres[0]['id'],'databases':[name],'exclude_tables':[]}
        snap = adapter._capture_pg_digest(spec, store.path/(tag+'-'+str(serial)+'-'+str(i)+'.digest'), databases=[name], roles=True)
        access = sql(name, ha_instance_access.capture_sql('n8n'))
        access = ha_instance_access.comparable(access, access)
        types=sql(name,"SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname,a.attname,"
                  "format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated) "
                  "ORDER BY n.nspname,c.relname,a.attnum),'[]'::json) FROM pg_attribute a "
                  'JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace '
                  "WHERE c.relkind IN ('r','p','S') AND a.attnum>0 AND NOT a.attisdropped "
                  "AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_';")
        extensions=sql(name,'SELECT json_agg(json_build_array(e.extname,e.extversion,n.nspname) ORDER BY e.extname) '
                       'FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace;')
        result['databases'][name] = {'digest':snap['digest'], 'access':digest(json.dumps(access,sort_keys=True).encode()),
                                    'types':digest(json.dumps(types).encode()),'extensions':extensions}
    # Read as JSON, including role password fingerprint, never the password/hash itself.
    role_rows = sql('postgres', "SELECT json_agg(json_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
                    "rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig,md5(coalesce(rolpassword,''))) "
                    'ORDER BY rolname) FROM pg_authid;')
    members = sql('postgres', "SELECT coalesce(json_agg(json_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),"
                  "pg_get_userbyid(grantor),admin_option,inherit_option,set_option) ORDER BY roleid,member),'[]'::json) "
                  'FROM pg_auth_members;')
    result['roles'] = digest(json.dumps(role_rows,sort_keys=True).encode())
    result['members'] = digest(json.dumps(sorted(members),sort_keys=True).encode())
    result['database_names'] = names
    result['metadata'] = sql('postgres', "SELECT json_agg(json_build_array(datname,pg_get_userbyid(datdba),"
                  'pg_encoding_to_char(encoding),datcollate,datctype,datistemplate,datallowconn) ORDER BY datname) '
                  'FROM pg_database;')
    store.state.setdefault('snapshots',{})[tag] = result; store.save()
    return result


def secret_state():
    out = {}
    for name in ('n8n-db-password','n8n-runners-auth-token','n8n-valkey-password'):
        p = owner('podman','secret','inspect',name)
        rows = json.loads(p.stdout); sid = rows[0]['ID']
        raw = owner('podman','secret','inspect','--showsecret','--format','{{.SecretData}}',name).stdout
        out[name] = {'id':sid,'value_sha256':digest(raw)}
    return out


def predicate_script(database, witness_dir):
    if not BASE.fullmatch(database): raise ValueError('invalid hook database')
    # This is fixed trusted controller code, not a program read from HA.
    return ("import os,subprocess,sys\nfrom pathlib import Path\n"
            f"p=subprocess.run({['/usr/bin/podman','exec','-i','n8n-postgres','psql','-X','-w','-Atq','-v','ON_ERROR_STOP=1','-U','n8n','-d',database,'-f','-']!r},"
            f"input={MARKER_SQL.encode()!r},capture_output=True,timeout=20)\n"
            "ok=p.returncode==0 and p.stdout.strip()==b'true'\n"
            f"w=Path({str(witness_dir)!r})/('allowed' if ok else 'refused')\n"
            "fd=os.open(w,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600);os.close(fd)\n"
            "sys.exit(0 if ok else 1)\n").encode()


def dispatch(q):
    if os.geteuid()!=0: raise ValueError('device root required')
    op = q['op']; name = q['case']
    if not BASE.fullmatch(name): raise ValueError('invalid case name')
    if op=='inventory': return inventory()
    if op=='hashes': return engine_hashes()
    if op=='intent': return resolve_intent(q['request_id'])
    if op=='job_quiescent':
        jid=q['job_id']
        if not re.fullmatch(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',jid):raise ValueError('job ID')
        j=json.loads(read_regular('/var/lib/woowtech-backup/jobs/'+jid+'.json')[0])
        unit=j.get('unit')
        if not isinstance(unit,str) or not re.fullmatch(r'woowtech-backup-j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.service',unit):
            raise ValueError('job service unit')
        p=call(['systemctl','show',unit,'-P','ActiveState'],check=False)
        return p.stdout.strip() in (b'inactive',b'failed')
    if op=='init':
        before = inventory()
        store = Store(name, create=True)
        store.capture([CATALOG]+[QDIR+n for n in ('n8n.container','n8n-worker.container','n8n-webhook.container')]+[ENV])
        store.state['before'] = before; store.save()
        return before
    store = Store(name)
    if op=='receipt': return store.state
    if op=='authorize_catalog':
        # helper catalog-install writes canonical bytes; record exact expected
        # result BEFORE calling it so a lost reply can be recovered safely.
        data = base64.b64decode(q['bytes'], validate=True)
        parsed = json.loads(data)
        if parsed.get('id')!='n8n' or parsed.get('owner')!='appowner': raise ValueError('wrong catalog')
        store.state['allowed'][CATALOG].append(digest(data));store.save();return digest(data)
    if op=='catalog_bytes':
        sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
        from woowbackup.catalog_admin import serialize
        b=serialize(q['entry']); return {'bytes':base64.b64encode(b).decode(),'sha256':digest(b)}
    if op=='fixture':
        target=q['database']
        if target not in ('n8n',name): raise ValueError('wrong fixture database')
        for filename in ('n8n.container','n8n-worker.container','n8n-webhook.container'):
            path=QDIR+filename;meta=store.state['original'][path]
            b=read_regular(store.path/meta['copy'])[0]
            line=b'Environment=DB_POSTGRESDB_DATABASE=n8n\n'
            if b.count(line)!=1 or b.count(b'EnvironmentFile=%h/.config/n8n/n8n.env\n')!=1:
                raise ValueError('unexpected resolver fixture')
            if b'DB_POSTGRESDB_DATABASE' in b.replace(line,b''): raise ValueError('ambiguous resolver fixture')
            store.replace(path,b.replace(line,b''))
        meta=store.state['original'][ENV];b=read_regular(store.path/meta['copy'])[0]
        if re.search(rb'^\s*(?:export\s+)?DB_POSTGRESDB_DATABASE(?:_FILE)?\s*=',b,re.M):
            raise ValueError('existing file database selection')
        store.replace(ENV,b+(b'' if b.endswith(b'\n') else b'\n')+('DB_POSTGRESDB_DATABASE='+target+'\n').encode())
        return True
    if op=='restore_files':
        store.restore([p for p in store.state['original'] if p!=CATALOG]);return True
    if op=='restore_catalog':
        sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
        from woowbackup import jobs,catalog
        from woowbackup.paths import Paths
        with jobs.start_lock(Paths()):
            if inventory()['active_jobs']: raise ValueError('jobs still active')
            store.restore([CATALOG])
            loaded=catalog.load_catalog(Paths())
            if loaded.get('n8n') is None: raise ValueError('original catalog failed to load')
        return True
    if op=='snapshot': return state(store,q['tag'],q.get('databases'))
    if op=='secrets': return secret_state()
    if op=='copy_original_marker':
        rows=sql('n8n',"SELECT json_agg(json_build_array(key,value,\"loadOnStartup\")) FROM settings WHERE key='woowbk.lab.baseline.before';")
        if not isinstance(rows,list) or len(rows)!=1: raise ValueError('original marker missing')
        key,value,load=rows[0]
        literal=lambda v:"'"+str(v).replace("'","''")+"'"
        sql(name,'INSERT INTO settings(key,value,"loadOnStartup") VALUES ('+literal(key)+','+literal(value)+','+
            ('true' if load else 'false')+') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;',as_json=False)
        return sql(name,MARKER_SQL)
    if op=='hook_on':
        uid=store.state['original'][ENV]['uid'];gid=store.state['original'][ENV]['gid']
        d=Path(APP+'/.local/state')/name
        drop=Path(APP+'/.config/systemd/user/n8n.service.d')/(name+'.conf')
        if d.exists() or d.is_symlink() or drop.exists() or drop.is_symlink(): raise ValueError('hook name exists')
        store.state['hook']=True;store.save()  # intent before any mkdir/write
        d.parent.mkdir(mode=0o700,exist_ok=True)
        if d.parent.is_symlink() or drop.parent.is_symlink():raise ValueError('hook symlink ancestor')
        os.chown(d.parent,uid,gid)
        d.mkdir(mode=0o700);os.chown(d,uid,gid)
        store.state['hook_parent_created']=not drop.parent.exists();store.save()
        drop.parent.mkdir(mode=0o755,exist_ok=True)
        os.chown(drop.parent,uid,gid)
        program=predicate_script(name,d)
        atomic(d/'predicate.py',program,mode=0o600,uid=uid,gid=gid)
        text=('[Service]\nRestart=no\nExecStartPre=/usr/bin/python3 %h/.local/state/'+name+'/predicate.py\n').encode()
        atomic(drop,text,mode=0o644,uid=uid,gid=gid)
        return True
    if op=='hook_state':
        d=Path(APP+'/.local/state')/name
        return {'refused':(d/'refused').is_file(),'allowed':(d/'allowed').is_file()}
    if op=='hook_off':
        if not store.state['hook']: return True
        d=Path(APP+'/.local/state')/name
        drop=Path(APP+'/.config/systemd/user/n8n.service.d')/(name+'.conf')
        if drop.exists():
            expected=('[Service]\nRestart=no\nExecStartPre=/usr/bin/python3 %h/.local/state/'+name+'/predicate.py\n').encode()
            if read_regular(drop)[0]!=expected:raise ValueError('hook changed externally')
            drop.unlink()
        if d.exists():
            for p in d.iterdir():
                if p.name not in ('predicate.py','allowed','refused') or p.is_symlink(): raise ValueError('unknown hook file')
            for p in d.iterdir(): p.unlink()
            d.rmdir()
        if store.state.get('hook_parent_created') and drop.parent.exists():
            drop.parent.rmdir()  # refuse rather than remove any unexpected contents
        store.state['hook']=False;store.save();return True
    if op=='cleanup_store':
        if q.get('verified') is not True or store.state['hook']: raise ValueError('unverified cleanup')
        for p in store.path.iterdir():
            allowed=p.name in ('state.json','issued.json') or re.fullmatch(r'original-[0-9]+|[a-z_]+-[0-9]+-[0-9]+\.digest',p.name)
            if not allowed or p.is_symlink() or not p.is_file(): raise ValueError('unknown recovery object')
        for p in store.path.iterdir(): p.unlink()
        store.path.rmdir();return True
    raise ValueError('unknown case operation')


if __name__=='__main__':
    try:
        request=json.loads(sys.stdin.buffer.read(1024*1024+1))
        print(json.dumps(dispatch(request)))
    except Exception as error:
        print(json.dumps({'error_class':type(error).__name__}),file=sys.stderr)
        raise SystemExit(1)
