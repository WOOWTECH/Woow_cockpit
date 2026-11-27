"""Fixed leased dev-d LiteLLM operations. Import performs no device I/O.

Filesystem CAS primitives follow the n8n controller protocol, copied here to
keep worker ownership disjoint and avoid a new mutable shared API.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

BASE = re.compile(r'woowbk_focus_litellm_[0-9a-f]{12}\Z')
OWNER = '/usr/local/bin/woowbk-owner'
APP = '/home/appowner'
CATALOG = '/etc/woowtech-cockpit/backup/apps/litellm.json'
QDIR = APP+'/.config/containers/systemd/'
QFILES = ('litellm.network','litellm-pgdata.volume','litellm-postgres.container','litellm.container')
UNITS = ('litellm-network.service','litellm-pgdata-volume.service','litellm-postgres.service','litellm.service',
         'litellm-backup.timer','litellm-backup.service')
SECRETS = ('litellm-database-url','litellm-master-key','litellm-postgres-password','litellm-salt-key','litellm-ui-password')
TIMER = 'woowtech-cockpit-backup-schedule.timer'
def digest(data):
    return hashlib.sha256(data).hexdigest()


def call(argv, *, data=None, timeout=60, check=True):
    p = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise subprocess.CalledProcessError(p.returncode,['fixed-device-command'],stderr=p.stderr)
    return p


def owner(*args, **kwargs):
    return call([OWNER, *args], **kwargs)


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
    fd, temp = tempfile.mkstemp(prefix='.focus-litellm-', dir=path.parent)
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
    def __init__(self, name, *, parent='/var/lib/woowtech-backup/focus-litellm-instance', create=False):
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
            if not Path(path).exists() and not Path(path).is_symlink():
                self.state['original'][path] = None
                self.state['allowed'][path] = [None]
                continue
            data, meta = read_regular(path)
            key = 'original-' + str(i)
            atomic(self.path/key, data)
            self.state['original'][path] = dict(meta, copy=key)
            self.state['allowed'][path] = [meta['sha256']]
        self.save()

    def authorize(self, path, data):
        if path not in self.state['original']: raise ValueError('uncaptured file')
        h = digest(data)
        if h not in self.state['allowed'][path]: self.state['allowed'][path].append(h)
        self.save()  # authorize the exact prospective helper bytes before dispatch

    def replace(self, path, data):
        meta = self.state['original'][path]
        now = read_regular(path)[1]['sha256'] if Path(path).exists() or Path(path).is_symlink() else None
        if now not in self.state['allowed'][path]:
            raise ValueError('file changed outside this case')
        h = digest(data)
        if h not in self.state['allowed'][path]: self.state['allowed'][path].append(h)
        self.save()  # intent before replacement, including partial failure
        atomic(path, data, mode=meta['mode'] if meta else 0o600,
               uid=meta['uid'] if meta else os.geteuid(), gid=meta['gid'] if meta else os.getegid())

    def restore(self, paths):
        for path in paths:
            meta = self.state['original'][path]
            if meta is None:
                current = read_regular(path)[1]['sha256'] if Path(path).exists() or Path(path).is_symlink() else None
                if current not in self.state['allowed'][path]: raise ValueError('file changed outside this case')
                Path(path).unlink(missing_ok=True)
                dfd = os.open(Path(path).parent, os.O_DIRECTORY)
                try: os.fsync(dfd)
                finally: os.close(dfd)
                continue
            data, _ = read_regular(self.path/meta['copy'])
            if digest(data) != meta['sha256']:
                raise ValueError('protected recovery bytes changed')
            self.replace(path, data)


def sql(database, statement, *, result=True):
    if database not in ('postgres','litellm') and not re.fullmatch(r'woowbk_focus_litellm_[0-9a-f]{12}_outside',database):
        raise ValueError('database outside case')
    p = owner('podman','exec','-i','litellm-postgres','psql','-X','-w','-Atq','-v','ON_ERROR_STOP=1',
              '-U','litellm','-d',database,'-f','-',data=statement.encode(),timeout=180)
    return json.loads(p.stdout) if result else None


def unit_state(unit, *, root=False):
    argv = ['systemctl']+([] if root else ['--user'])+['show',unit,'--property=ActiveState,SubState,UnitFileState']
    p = call(argv,check=False) if root else owner(*argv,check=False)
    value = dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)
    if set(value) != {'ActiveState','SubState','UnitFileState'}: raise ValueError('unreadable unit state')
    return value


def inventory():
    catalogs = {p.name:read_regular(p)[1]['sha256'] for p in Path(CATALOG).parent.glob('*.json')}
    # Only metadata/hashes are returned. Config contents, secret values and full
    # inspect/process results never cross this protocol.
    files = {str(p):read_regular(p)[1] for p in Path(QDIR).glob('*') if p.is_file() and not p.is_symlink()}
    for p in Path(APP+'/.config/systemd/user').glob('litellm*'):
        if p.is_file(): files[str(p)] = read_regular(p)[1]
    for p in Path(APP+'/.config/litellm').glob('*'):
        if p.is_file(): files[str(p)] = read_regular(p)[1]
    volumes = {}
    for name in owner('podman','volume','ls','--format','{{.Name}}').stdout.decode().splitlines():
        volumes[name] = owner('podman','volume','inspect','--format','{{.CreatedAt}}',name).stdout.decode().strip()
    secrets = dict(line.split(' ',1) for line in owner('podman','secret','ls','--format','{{.Name}} {{.ID}}').stdout.decode().splitlines())
    containers = dict(line.split(' ',1) for line in owner('podman','ps','-a','--no-trunc','--format','{{.Names}} {{.ID}}').stdout.decode().splitlines())
    external = dict(line.split(' ',1) for line in owner('podman','ps','-a','--external','--no-trunc','--format','{{.Names}} {{.ID}}').stdout.decode().splitlines())
    images = owner('podman','images','--all','--no-trunc','--format','{{.ID}}').stdout.decode().splitlines()
    refs = {}
    for line in owner('podman','images','--all','--no-trunc','--format','{{.Repository}}:{{.Tag}} {{.ID}}').stdout.decode().splitlines():
        ref, image = line.split(' ',1)
        if '<none>' not in ref: refs[ref] = image.removeprefix('sha256:')
    active = []
    for p in Path('/var/lib/woowtech-backup/jobs').glob('j*.json'):
        value = json.loads(read_regular(p)[0])
        if value.get('state') in ('queued','running'): active.append(p.stem)
    networks = dict(line.split(' ',1) for line in owner('podman','network','ls','--no-trunc','--format','{{.Name}} {{.ID}}').stdout.decode().splitlines())
    return {'catalogs':catalogs,'files':files,'volumes':volumes,'secrets':secrets,'containers':containers,
            'external_containers':external,'networks':networks,
            'images':sorted(set(x.removeprefix('sha256:') for x in images)),
            'image_refs':refs,
            'running':sorted(owner('podman','ps','--format','{{.Names}}').stdout.decode().splitlines()),
            'units':{u:unit_state(u) for u in UNITS},'timer':unit_state(TIMER,root=True),'active_jobs':active,
            'package':Path(APP+'/Woow_podman_litellm').exists(),
            'config_directory':Path(APP+'/.config/litellm').exists()}


def engine_hashes():
    root = Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')
    result = {str(p.relative_to(root)):read_regular(p)[1]['sha256'] for p in root.rglob('*.py') if '__pycache__' not in p.parts}
    result['../woowtech-cockpit-backup'] = read_regular('/usr/local/libexec/woowtech-cockpit-backup')[1]['sha256']
    return result


def image_configs():
    result = {}
    for image in inventory()['images']:
        if not re.fullmatch(r'[0-9a-f]{64}',image): raise ValueError('image config identity')
        p = owner('podman','image','inspect','--format',
            '{{.ID}}\n{{.Architecture}}\n{{.Os}}\n{{json .RootFS.Layers}}\n{{json .Config.Volumes}}\n{{.Config.User}}\n'
            '{{index .Config.Labels "io.woowtech.lab.derived-from"}}\n{{index .Config.Labels "io.woowtech.focus.case"}}',image)
        lines = p.stdout.decode().removesuffix('\n').split('\n')
        if len(lines) != 8: raise ValueError('fixed image metadata unreadable')
        if lines[0].removeprefix('sha256:') != image: raise ValueError('image config changed')
        result[image] = {'architecture':lines[1],'os':lines[2],'layers':json.loads(lines[3]) or [],
                         'volumes':json.loads(lines[4]),'user':lines[5],'base':lines[6],'case':lines[7]}
    return result


def disk_free():
    return min(os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in
               (APP,'/var/lib/woowtech-backup/staging','/var/lib/woowtech-backup'))


def image_build(store, program):
    base = '0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312'
    tag = 'localhost/woow-litellm:1.104.0-0.3.16'
    if digest(program) != 'b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a': raise ValueError('unreviewed derivation')
    if program.splitlines()[0] != ('FROM sha256:'+base).encode(): raise ValueError('FROM not exact base config')
    before = inventory(); configs = image_configs()
    if tag in before['image_refs'] or base not in configs: raise ValueError('image precondition changed')
    if configs[base]['architecture'] != 'amd64' or configs[base]['os'] != 'linux' or configs[base]['volumes']:
        raise ValueError('unexpected base config/declared volumes')
    context = Path(APP+'/.local/state')/(store.name+'_images')
    if context.exists() or context.is_symlink(): raise ValueError('build context already exists')
    store.state['image_build'] = {'intent':True,'before':before,'configs_before':configs,
                                 'derivation_sha256':digest(program),'disk_before':disk_free()}; store.save()
    uid = int(owner('id','-u').stdout); gid = int(owner('id','-g').stdout)
    context.mkdir(mode=0o700); os.chown(context,uid,gid)
    temp = context/'tmp'; temp.mkdir(mode=0o700); os.chown(temp,uid,gid)
    atomic(context/'Containerfile',program,mode=0o400,uid=uid,gid=gid)
    # --from binds the actual builder input as well as the literal FROM line.
    # No mutable tag participates in resolving the source image.
    # Spawn Podman directly as the same ordinary owner, with the installed
    # device/woowbk-owner wrapper's fixed environment. Supervising runuser's
    # wrapper group would not prove the actual builder remained in that group.
    env = {'PATH':'/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':APP,'USER':'appowner','LOGNAME':'appowner',
           'LANG':'C.UTF-8','TERM':'dumb','XDG_RUNTIME_DIR':f'/run/user/{uid}',
           'DBUS_SESSION_BUS_ADDRESS':f'unix:path=/run/user/{uid}/bus','TMPDIR':str(temp)}
    argv = ['/usr/bin/podman','build','--from','sha256:'+base,
            '--network=none','--pull=never','--memory=512m','--memory-swap=512m',
            '--cpu-period=100000','--cpu-quota=100000','--jobs=1','--layers=false','--force-rm=true','--rm=true',
            '--http-proxy=false','--label','io.woowtech.focus.case='+store.name,
            '--layer-label','io.woowtech.focus.case='+store.name,'--iidfile',str(context/'iid'),
            '-q','-t',tag,'-f',str(context/'Containerfile'),str(context)]
    minimum = [disk_free()]
    def resource_guard():
        minimum[0] = min(minimum[0],disk_free()); return minimum[0] >= 13*1024**3
    def checkpoint(value):
        store.state['image_build'].setdefault('process',{}).update(value); store.save()
    fd = os.open(store.path/'image-build-private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as log:
        # supervise() is prepended from the committed companion module, never
        # installed on the device and never read from the HA fixture.
        result = supervise(argv,log,timeout=600,grace=30,checkpoint=checkpoint,guard=resource_guard,
                           identity={'uid':uid,'gid':gid,'home':APP,'env':env})
    after = inventory()
    store.state['image_build'].update(after=after,disk_after=disk_free(),minimum_free=minimum[0]); store.save()
    after_configs = image_configs()
    owned = set(after['images'])-set(before['images'])
    verified = []
    base_layers = configs[base]['layers']
    for image in sorted(owned):
        c = after_configs[image]
        if (c['case'] == store.name and c['base'] == 'sha256:'+base and c['user']=='1000:0'
                and c['architecture']=='amd64' and c['os']=='linux' and c['layers'][:len(base_layers)]==base_layers):
            verified.append(image)
    iid = read_regular(context/'iid',128)[0].decode().strip().removeprefix('sha256:') if (context/'iid').exists() else None
    state = store.state['image_build']
    state.update(result=result,after=after,configs_after=after_configs,owned_images=verified,
                 unknown_images=sorted(owned-set(verified)),disk_after=disk_free(),minimum_free=minimum[0],iid=iid)
    state['new_layers'] = sorted({x for i in owned for x in after_configs[i]['layers']}-
                                {x for c in configs.values() for x in c['layers']})
    state['verified'] = (result['ok'] and owned==set(verified) and iid in verified
        and after['image_refs'].get(tag)==iid and all(after['image_refs'].get(k)==v for k,v in before['image_refs'].items())
        and set(after['image_refs'])-set(before['image_refs'])=={tag}
        and all(after_configs.get(i)==c for i,c in configs.items())
        and not after['active_jobs'] and all(after[k]==before[k] for k in
            ('catalogs','files','containers','external_containers','volumes','networks','secrets','running','units','timer','package','config_directory')))
    store.save()
    if state['verified'] and result['terminal']:
        # Any working container/volume/network leak is detected by the host
        # durable inventory comparison; it cannot count as a successful image phase.
        tree_files(context); shutil.rmtree(context)
    return {k:state[k] for k in ('verified','result','owned_images','unknown_images','iid','disk_before','disk_after','minimum_free','new_layers')}


def snapshot(store, tag):
    if not re.fullmatch(r'[a-z_]{1,40}',tag): raise ValueError('snapshot tag')
    sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
    from woowbackup.cli import Services
    from woowbackup.paths import Paths
    from woowbackup import ha_instance_access
    svc = Services(Paths()); app = svc.catalog()['litellm']; adapter = svc.adapter(app)
    names = sql('postgres',"SELECT json_agg(datname ORDER BY datname) FROM pg_database WHERE NOT datistemplate AND datallowconn;")
    # The lease requires a fresh case-owned cluster; refuse unexpected DB names
    # rather than broadening the SQL executor to unrelated resources.
    if not set(names) <= {'postgres','litellm',store.name+'_outside'}: raise ValueError('foreign database in owned cluster')
    result = {'database_names':names,'databases':{}}
    for i,name in enumerate(names):
        spec = {'id':'focus','postgres':app.postgres[0]['id'],'databases':[name],'exclude_tables':[]}
        captured = adapter._capture_pg_digest(spec,store.path/(tag+'-'+str(i)+'.digest'),databases=[name],roles=True)
        access = sql(name,ha_instance_access.capture_sql('litellm'))
        comparable = ha_instance_access.comparable(access,access)
        result['databases'][name] = {'digest':captured['digest'], 'access':digest(json.dumps(comparable,sort_keys=True).encode()),
            'schema':sql(name,"SELECT to_json(md5(coalesce(string_agg(n.nspname||':'||c.relname||':'||a.attname||':'||"
                "format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull,E'\\n' ORDER BY n.nspname,c.relname,a.attnum),''))) "
                "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE a.attnum>0 AND NOT a.attisdropped AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_';")}
    result['roles'] = sql('postgres',"SELECT to_json(md5(coalesce(string_agg(rolname||':'||rolsuper||':'||rolinherit||':'||rolcreaterole||':'||"
        "rolcreatedb||':'||rolcanlogin||':'||rolreplication||':'||rolbypassrls||':'||rolconnlimit||':'||"
        "coalesce(rolvaliduntil::text,'')||':'||coalesce(rolpassword,''),E'\\n' ORDER BY rolname),''))) FROM pg_authid;")
    # rolconfig belongs to pg_db_role_setting, NOT pg_authid (real PG16/17).
    result['settings'] = sql('postgres',"SELECT coalesce(json_agg(json_build_array(coalesce(d.datname,''),coalesce(r.rolname,''),"
        "s.setconfig) ORDER BY s.setdatabase,s.setrole),'[]'::json) FROM pg_db_role_setting s "
        "LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole;")
    result['members'] = sql('postgres',"SELECT coalesce(json_agg(json_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),"
        "pg_get_userbyid(grantor),admin_option,inherit_option,set_option) ORDER BY roleid,member),'[]'::json) FROM pg_auth_members;")
    result['metadata'] = sql('postgres',"SELECT json_agg(json_build_array(datname,pg_get_userbyid(datdba),pg_encoding_to_char(encoding),"
        "datcollate,datctype,datistemplate,datallowconn,datacl) ORDER BY datname) FROM pg_database;")
    store.state.setdefault('snapshots',{})[tag] = result; store.save()
    return result


def owned_fixture(store, action, password=None):
    outside = store.name+'_outside'; role = store.name+'_reader'
    if action == 'create':
        store.state['outside_intent'] = True; store.save()
        sql('postgres',f'CREATE ROLE "{role}" LOGIN; CREATE DATABASE "{outside}" OWNER "{role}";',result=False)
        sql(outside,'CREATE TABLE public.kept_marker(value text PRIMARY KEY); '
                    "INSERT INTO public.kept_marker VALUES ('before-conversion'); "
                    f'ALTER TABLE public.kept_marker OWNER TO "{role}";',result=False)
    elif action == 'late':
        # Password is a fresh registered test credential sent only over stdin.
        if not isinstance(password,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{32,128}',password): raise ValueError('test credential')
        sql(outside,"INSERT INTO public.kept_marker VALUES ('after-conversion');",result=False)
        sql('postgres',f'ALTER ROLE "{role}" PASSWORD \'{password}\';',result=False)
    else: raise ValueError('fixture action')
    return True


def hook(store, enable):
    directory = Path(APP+'/.config/systemd/user/litellm.service.d')
    path = directory/('zz-'+store.name+'.conf'); marker = Path(APP+'/.local/state')/store.name/'fail-once'
    if enable:
        if path.exists() or marker.exists(): raise ValueError('hook already exists')
        store.state['hook'] = True; store.save()  # intent before either write
        uid = int(owner('id','-u').stdout); gid = int(owner('id','-g').stdout)
        atomic(marker,b'armed\n',uid=uid,gid=gid)
        directory.mkdir(mode=0o700,parents=True,exist_ok=True); os.chown(directory,uid,gid)
        data = ('[Service]\nRestart=no\nExecStartPre=/bin/sh -c "if [ -f %h/.local/state/'+store.name+
                '/fail-once ]; then rm -- %h/.local/state/'+store.name+'/fail-once; exit 1; fi"\n').encode()
        store.state['hook_sha'] = digest(data); store.save(); atomic(path,data,mode=0o644,uid=uid,gid=gid)
    else:
        if path.exists():
            if read_regular(path)[1]['sha256'] != store.state.get('hook_sha'): raise ValueError('foreign hook edit')
            path.unlink()
        marker.unlink(missing_ok=True); store.state['hook'] = False; store.save()
        try: directory.rmdir()
        except OSError: pass
    owner('systemctl','--user','daemon-reload')
    return True


def tree_files(root):
    root = Path(root)
    if not root.exists(): return {}
    if root.is_symlink(): raise ValueError('symlink case root')
    result = {}
    for p in root.rglob('*'):
        if p.is_symlink(): raise ValueError('symlink inside owned tree')
        if p.is_file(): result[str(p)] = read_regular(p,64*1024**2)[1]['sha256']
    return result


def capture_installed(store):
    before = store.state['before']; current = inventory()
    allowed_names = {'containers':{'litellm','litellm-postgres'},'volumes':{'litellm-pgdata'},
                     'networks':{'litellm-net'},'secrets':set(SECRETS)}
    for field,names in allowed_names.items():
        if any(current[field].get(k) != v for k,v in before[field].items()): raise ValueError('foreign resource changed')
        if not (set(current[field])-set(before[field])) <= names: raise ValueError('unknown added resource')
    protected = {p:v for p,v in current['files'].items() if not Path(p).name.startswith('litellm') and '/.config/litellm/' not in p}
    if any(protected.get(p) != v for p,v in before['files'].items()): raise ValueError('foreign file changed')
    files = {p:v['sha256'] for p,v in current['files'].items() if p not in before['files']}
    files.update(tree_files(APP+'/Woow_podman_litellm'))
    store.state['installed_files'] = files
    store.state['owned_resources'] = {field:{k:v for k,v in current[field].items() if k not in before[field]}
                                     for field in allowed_names}
    store.save(); return True


def remove_owned_containers(current):
    """Quadlet stop may already remove its exact container; never adopt a replacement."""
    for name in ('litellm','litellm-postgres'):
        cid = current.get(name)
        if not cid: continue
        if not re.fullmatch(r'[0-9a-f]{64}',cid): raise ValueError('container journal identity')
        found = owner('podman','container','exists',name,check=False).returncode
        if found == 1:
            gone = owner('podman','container','exists',cid,check=False).returncode
            if gone != 1: raise ValueError('container renamed or unreadable after stop')
            continue
        if found != 0: raise ValueError('container state unreadable')
        now = owner('podman','inspect','--format','{{.ID}}',name).stdout.decode().strip()
        if now != cid: raise ValueError('container replaced outside case')
        owner('podman','rm',cid)  # no force; foreign consumers/references refuse


def cleanup_owned_package(store):
    before = store.state['before']; current = inventory()
    if current['active_jobs']: raise ValueError('active jobs prevent cleanup')
    if not store.state.get('install_intent'): return True
    expected = store.state.get('installed_files')
    if expected is None: raise ValueError('partial install requires explicit ownership reconciliation; retain receipt')
    # Replacements performed by successful engine jobs can change container,
    # volume and secret IDs. Record their CURRENT IDs/mounts before deletion;
    # namespace ownership derives from initial absence plus the install intent.
    # Every preexisting resource and every non-app file must remain exact.
    for field in ('containers','volumes','networks','secrets'):
        if any(current[field].get(k) != v for k,v in before[field].items()): raise ValueError('foreign resource changed')
        allowed = set(store.state['owned_resources'][field])
        if set(current[field])-set(before[field]) != allowed: raise ValueError('foreign or missing case resource')
    for p,h in expected.items():
        if read_regular(p,64*1024**2)[1]['sha256'] != h: raise ValueError('owned file changed unexpectedly')
    if any(current['files'].get(p) != v for p,v in before['files'].items()): raise ValueError('foreign file edit')
    journal = {'resources':{k:current[k] for k in ('containers','volumes','networks','secrets')},'mounts':{}}
    for name in ('litellm','litellm-postgres'):
        if name in current['containers']:
            journal['mounts'][name] = json.loads(owner('podman','inspect','--format','{{json .Mounts}}',current['containers'][name]).stdout)
    atomic(store.path/'cleanup-owned-private.json',json.dumps(journal).encode())
    owner('systemctl','--user','stop',*reversed(UNITS),timeout=300)
    remove_owned_containers(current['containers'])
    for name,created in store.state['owned_resources']['volumes'].items():
        if owner('podman','volume','inspect','--format','{{.CreatedAt}}',name).stdout.decode().strip() != current['volumes'][name]:
            raise ValueError('volume replaced outside cleanup journal')
        owner('podman','volume','rm',name)
    for name in store.state['owned_resources']['networks']: owner('podman','network','rm',name)
    for name in SECRETS:
        sid = current['secrets'][name]
        owner('podman','secret','rm',sid)
    for path in expected:
        # Check once more immediately before unlink; no recursive app data
        # deletion. Only package/config/state directories proven empty are removed.
        if read_regular(path,64*1024**2)[1]['sha256'] != expected[path]: raise ValueError('late file edit')
        Path(path).unlink()
    for root in (Path(APP+'/Woow_podman_litellm'),Path(APP+'/.config/litellm')):
        for p in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
            if p.is_dir(): p.rmdir()
        root.rmdir()
    # Private installer state contains generated bookkeeping only. Never remove
    # an older default woow-quadlet manifest belonging to a previous lane.
    private = Path(APP+'/.local/state')/store.name
    tree_files(private)  # reject symlinks before removing only this owned tree
    shutil.rmtree(private)
    owner('systemctl','--user','daemon-reload')
    owner('systemctl','--user','reset-failed',*UNITS,check=False)
    store.state['package_cleaned'] = True; store.save(); return True


def dispatch(q):
    if os.geteuid() != 0 or not BASE.fullmatch(q['case']): raise ValueError('case/root boundary')
    op = q['op']; name = q['case']
    if op == 'inventory': return inventory()
    if op == 'hashes': return engine_hashes()
    if op == 'intent':
        p = Path('/var/lib/woowtech-backup/requests.json')
        value = json.loads(read_regular(p,8*1024**2)[0]) if p.exists() else {}
        return ((value.get('requests') or {}).get(q['request_id']) or {}).get('job_id')
    if op == 'job_quiescent':
        if not re.fullmatch(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',q['job_id']): raise ValueError('job ID')
        unit = 'woowtech-backup-'+q['job_id']+'.service'
        return call(['systemctl','show',unit,'-P','ActiveState'],check=False).stdout.strip() in (b'inactive',b'failed')
    if op == 'init':
        before = inventory(); store = Store(name,create=True); store.capture([CATALOG])
        store.state['before'] = before; store.save(); return before
    store = Store(name)
    if op == 'receipt': return store.state
    if op == 'catalog_bytes':
        sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
        from woowbackup.catalog_admin import serialize
        data = serialize(q['entry']); return {'bytes':base64.b64encode(data).decode(),'sha256':digest(data)}
    if op == 'authorize_catalog':
        data = base64.b64decode(q['bytes'],validate=True); value = json.loads(data)
        if value.get('id') != 'litellm' or value.get('owner') != 'appowner': raise ValueError('catalog app')
        store.authorize(CATALOG,data); return digest(data)
    if op == 'restore_catalog':
        sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
        from woowbackup import jobs
        from woowbackup.paths import Paths
        with jobs.start_lock(Paths()):
            if inventory()['active_jobs']: raise ValueError('active jobs')
            store.restore([CATALOG])
        return True
    if op == 'snapshot': return snapshot(store,q['tag'])
    if op == 'image_build': return image_build(store,base64.b64decode(q['program'],validate=True))
    if op == 'image_context_cleanup':
        state = store.state.get('image_build',{})
        if state.get('process',{}).get('terminal') is not True: raise ValueError('builder terminal state unproved')
        context = Path(APP+'/.local/state')/(name+'_images')
        if context.exists() or context.is_symlink():
            if read_regular(context/'Containerfile')[1]['sha256'] != state['derivation_sha256']:
                raise ValueError('build program changed outside case')
            tree_files(context); shutil.rmtree(context)
        return True
    if op == 'fixture': return owned_fixture(store,q['action'],q.get('password'))
    if op == 'hook': return hook(store,q['enable'])
    if op == 'hook_consumed': return store.state.get('hook') is True and not Path(APP+'/.local/state/'+name+'/fail-once').exists()
    if op == 'claim_install':
        if any(Path(p).exists() or Path(p).is_symlink() for p in
               (APP+'/Woow_podman_litellm',APP+'/.config/litellm',APP+'/.local/state/'+name)):
            raise ValueError('owned install namespace not absent')
        store.state['install_intent']=True; store.save(); return True
    if op == 'capture_installed': return capture_installed(store)
    if op == 'cleanup_owned_package': return cleanup_owned_package(store)
    if op == 'patch_package_pg':
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',q['digest']): raise ValueError('PG digest')
        p = Path(APP+'/Woow_podman_litellm/quadlet/litellm-postgres.container')
        old = b'docker.io/library/postgres:17.11-alpine3.23@sha256:bc2701f9a79f9248bcb18743bc9b2c732d9a1d16737ca44a8f577752fc43b61f'
        b,meta = read_regular(p)
        if b.count(old) != 1: raise ValueError('unexpected package PG pin')
        new = ('docker.io/library/postgres:17.11-alpine3.23@'+q['digest']).encode()
        atomic(p,b.replace(old,new),mode=meta['mode'],uid=meta['uid'],gid=meta['gid']); return True
    raise ValueError('unknown fixed operation')


def failure_record(operation,exc):
    stderr=getattr(exc,'stderr',None) or b''
    if isinstance(stderr,str):stderr=stderr.encode('utf-8','replace')
    return {'operation':operation if re.fullmatch(r'[a-z_]{1,32}',operation) else 'invalid',
            'class':type(exc).__name__[:80],'errno':getattr(exc,'errno',None),
            'returncode':getattr(exc,'returncode',None),'stderr_bytes':len(stderr),
            'stderr_b64':base64.b64encode(stderr[:16384]).decode(),'stderr_truncated':len(stderr)>16384,
            'json_position':getattr(exc,'pos',None)}


def run_request(q):
    try:return 0,dispatch(q)
    except Exception as exc:
        # This case-owned private journal survives a lost reply and package
        # cleanup. No request values, SQL data, argv or exception text are saved.
        report=failure_record(q.get('op','invalid'),exc)
        if not BASE.fullmatch(q.get('case','')):raise
        store=Store(q['case'])
        atomic(store.path/('operation-error-'+str(time.time_ns())+'.json'),json.dumps(report).encode())
        return 1,{'operation_error':report}


if __name__ == '__main__':
    code,value=run_request(json.load(sys.stdin));print(json.dumps(value));sys.exit(code)

