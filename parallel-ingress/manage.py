#!/usr/bin/env python3
"""Install/verify/roll back an optional parallel branded Cockpit entrance."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

from render import BASE, SOURCE, backend_hashes, config, digest, quadlet, render


def command(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def git(*args):
    return subprocess.check_output(['git','-c',f'safe.directory={SOURCE}','-C',str(SOURCE),*args], text=True).strip()


def user_command(owner, *args, **kwargs):
    u = pwd.getpwnam(owner)
    return command(['runuser','-u',owner,'--','env',f'HOME={u.pw_dir}',
                    f'XDG_RUNTIME_DIR=/run/user/{u.pw_uid}',f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{u.pw_uid}/bus',
                    *args], **kwargs)


def unit_names(c):
    return [f"cockpit-{c['instance']}-pi-{mode}.service" for mode in ('public','local')]


def read_config(path):
    if not path.is_absolute():
        raise ValueError('Configuration path must be absolute')
    for p in [*reversed(path.parents), path]:
        s=p.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise ValueError('Configuration requires root ownership and no writable or symlink ancestors: '+str(p))
    if not path.is_file():raise ValueError('Configuration must be a regular file')
    return config(json.loads(path.read_text()))


@contextmanager
def deployment_lock():
    if os.geteuid()!=0:raise ValueError('This action requires sudo')
    directory(Path(BASE))
    with (Path(BASE)/'.lock').open('a') as guard:
        try:fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another parallel ingress operation is running') from None
        yield


def service_state(c):
    states={}
    for unit in unit_names(c):
        states[unit]={field:subprocess.run(['systemctl',check,unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
                      for field,check in [('enabled','is-enabled'),('active','is-active')]}
    result=user_command(c['owner'],'systemctl','--user','show','--property=ActiveState','--value',
                        f"{c['instance']}-cockpit-pwa.service",capture_output=True,text=True)
    states['frontend_active']=result.stdout.strip() in ('active','activating')
    return states


def directory(path, mode=0o755):
    if not path.exists():
        directory(path.parent)
        path.mkdir(mode=mode)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('Unsafe root-owned installation directory: '+str(path))
    os.chmod(path, mode)


def write(path, data, mode=0o644):
    if path.is_symlink():
        raise ValueError('Refusing symlink file: '+str(path))
    with tempfile.NamedTemporaryFile(prefix='.parallel-',dir=path.parent,delete=False) as f:
        f.write(data);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode);name=f.name
    os.replace(name,path)


def write_quadlet(c,path,data,mode=0o644):
    # The owner controls this directory. Never chmod/chown/unlink its paths as root.
    script='''import os,sys,tempfile
from pathlib import Path
p=Path(sys.argv[1]);mode=int(sys.argv[2]);remove=sys.argv[3]=='remove'
if p.is_symlink():raise ValueError('Refusing symlink Quadlet')
if remove:p.unlink(missing_ok=True)
else:
 with tempfile.NamedTemporaryFile(dir=p.parent,prefix='.parallel-',delete=False) as f:
  f.write(sys.stdin.buffer.read());f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode);name=f.name
 os.replace(name,p)
'''
    user_command(c['owner'],'python3','-c',script,str(path),str(mode),'remove' if data is None else 'write',input=data or b'')


def origins(text, values):
    """Add exact browser origins in WebService while preserving all other config."""
    lines=(text if text.endswith('\n') else text+'\n').splitlines(keepends=True)
    begin=next((i for i,l in enumerate(lines) if l.strip()=='[WebService]'),None)
    if begin is None:
        return text.rstrip()+'\n[WebService]\nOrigins = '+' '.join(values)+'\n'
    end=next((i for i in range(begin+1,len(lines)) if lines[i].lstrip().startswith('[')),len(lines))
    matches=[i for i in range(begin+1,end) if re.match(r'\s*Origins\s*=',lines[i])]
    if len(matches)>1:
        raise ValueError('Ambiguous Cockpit Origins configuration')
    if matches:
        i=matches[0];current=lines[i].split('=',1)[1].split()
        lines[i]='Origins = '+' '.join(dict.fromkeys(current+values))+'\n'
    else:
        lines.insert(end,'Origins = '+' '.join(values)+'\n')
    return ''.join(lines)


def metadata(c):
    if git('status','--porcelain'):
        raise ValueError('Commit the reviewed source first; dirty sources cannot be deployed')
    return {'config':c,'source_commit':git('rev-parse','HEAD'),'source_tree':git('rev-parse','HEAD^{tree}')}


def paths(c):
    u=pwd.getpwnam(c['owner'])
    if u.pw_uid==0:
        raise ValueError('Use a rootless Podman owner')
    return Path(BASE)/c['instance'],Path(u.pw_dir)/'.config/containers/systemd'/f"{c['instance']}-cockpit-pwa.container"


def snapshot(files):
    out={}
    for p in files:
        if p.is_symlink() or (p.exists() and not p.is_file()):
            raise ValueError('Refusing nonregular managed target: '+str(p))
        if p.exists():
            s=p.stat()
            out[str(p)]={'data':base64.b64encode(p.read_bytes()).decode(),'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
        else:out[str(p)]=None
    return out


def restore(c, record):
    # Only the exact selected instance and Cockpit origin file may be restored.
    base,qpath=paths(c)
    allowed={str(qpath),'/etc/cockpit/cockpit.conf',*[str(Path('/etc/systemd/system')/n) for n in unit_names(c)]}
    if set(record['before'])!=allowed:
        raise ValueError('Unexpected rollback targets')
    validate_previous(base,record)
    user_command(c['owner'],'systemctl','--user','stop',f"{c['instance']}-cockpit-pwa.service")
    for unit in unit_names(c):
        subprocess.run(['systemctl','disable','--now',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for name,entry in record['before'].items():
        p=Path(name)
        if p==qpath:
            write_quadlet(c,p,base64.b64decode(entry['data']) if entry else None,entry['mode'] if entry else 0o644)
            continue
        if entry is None:p.unlink(missing_ok=True)
        else:
            write(p,base64.b64decode(entry['data']),entry['mode']);os.chown(p,entry['uid'],entry['gid'])
    current=base/'current'
    previous=record['previous']
    if previous:
        if not re.fullmatch(r'releases/[0-9TZ]+',previous):raise ValueError('Invalid previous release')
        link=base/'.previous';link.unlink(missing_ok=True);link.symlink_to(previous);os.replace(link,current)
    else:current.unlink(missing_ok=True)
    command(['systemctl','daemon-reload'])
    command(['systemctl','try-restart','cockpit.service'])
    for unit in unit_names(c):
        if record['before'][str(Path('/etc/systemd/system')/unit)] is not None:
            if record['service_state'][unit]['enabled']:command(['systemctl','enable',unit])
            if record['service_state'][unit]['active']:command(['systemctl','start',unit])
    user_command(c['owner'],'systemctl','--user','daemon-reload')
    if record['before'][str(qpath)] is not None and record['service_state']['frontend_active']:
        user_command(c['owner'],'systemctl','--user','restart',f"{c['instance']}-cockpit-pwa.service")


def install(c):
    if os.geteuid()!=0:raise ValueError('install requires sudo')
    meta=metadata(c)
    base,qpath=paths(c)
    hashes=backend_hashes()
    node=Path(c['node_path'])
    if not node.is_file() or not node.stat().st_mode&0o111:
        raise ValueError('Node must be root-owned and not writable by others')
    for p in [*reversed(node.parents),node]:
        s=p.lstat()
        if p.is_symlink() or s.st_uid!=0 or s.st_mode&0o022:
            raise ValueError('Node and its ancestors must be trusted root-owned paths: '+str(p))
    if not qpath.parent.is_dir():raise ValueError('Configure the existing rootless Podman owner first')
    # The legacy Apporo sample's exact unit is the intentional in-place upgrade target.
    if qpath.exists() and f"ContainerName={c['instance']}-cockpit-pwa" not in qpath.read_text().splitlines():
        raise ValueError('An unrelated Quadlet already uses this instance name')
    directory(base);directory(base/'releases');directory(base/'transactions',0o700)
    if (base/'current').exists() and not (base/'current').is_symlink():
        raise ValueError('Unexpected non-symlink current release')
    if (base/'current').is_symlink():
        current(c['instance'])
    for unit in unit_names(c):
        p=Path('/etc/systemd/system')/unit
        if p.exists() and f'{base}/current/pi-gateway.mjs' not in p.read_text():
            raise ValueError('An unrelated systemd unit already uses this instance name')
    release_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    release=base/'releases'/release_id
    release.mkdir(mode=0o755);os.chmod(release,0o755)
    render(c,release)
    # All public assets and dynamic-user inputs must be traversable under umask 077.
    for p in release.rglob('*'):os.chmod(p,0o755 if p.is_dir() else 0o644)
    write(release/'quadlet.container',quadlet(c,release).encode())
    meta.update(backend_hashes=hashes,files={str(p.relative_to(release)):digest(p.read_bytes()) for p in release.rglob('*') if p.is_file()})
    write(release/'receipt.json',(json.dumps(meta,indent=2)+'\n').encode())
    if metadata(c)!= {k:meta[k] for k in ('config','source_commit','source_tree')}:
        raise ValueError('Source changed while rendering')
    # Validate nginx before replacing the active entrance or changing systemd.
    user_command(c['owner'],'podman','pull',c['image'],stdout=subprocess.DEVNULL)
    user_command(c['owner'],'podman','run','--rm','--network=none',
                 '-v',f'{release}/nginx.conf:/etc/nginx/nginx.conf:ro',
                 '-v',f'{release}/public:/opt/parallel/public:ro',c['image'],'nginx','-t')
    conf=Path('/etc/cockpit/cockpit.conf')
    old=conf.read_text() if conf.exists() else ''
    additions=[c['public_origin'],c['public_origin'].replace('https:','wss:',1),f"http://127.0.0.1:{c['listen_port']}"]
    changed=origins(old,additions).encode()
    units=[Path('/etc/systemd/system')/n for n in unit_names(c)]
    record={'config':c,'release':release_id,'previous':os.readlink(base/'current') if (base/'current').is_symlink() else None,
            'before':snapshot([qpath,conf,*units]),'service_state':service_state(c)}
    journal=base/'transactions'/f'{release_id}.json'
    write(journal,(json.dumps(record)+'\n').encode(),0o600)
    try:
        link=base/'.next';link.unlink(missing_ok=True);link.symlink_to('releases/'+release_id);os.replace(link,base/'current')
        for mode,p in zip(('public','local'),units):write(p,(release/f'pi-{mode}.service').read_bytes())
        command(['systemd-analyze','verify',*units])
        write(conf,changed)
        write_quadlet(c,qpath,(release/'quadlet.container').read_bytes())
        command(['systemctl','daemon-reload'])
        if changed!=old.encode():command(['systemctl','try-restart','cockpit.service'])
        for unit in unit_names(c):
            command(['systemctl','enable',unit]);command(['systemctl','restart',unit]);command(['systemctl','is-active','--quiet',unit])
        user_command(c['owner'],'systemctl','--user','daemon-reload')
        user_command(c['owner'],'systemctl','--user','restart',f"{c['instance']}-cockpit-pwa.service")
        user_command(c['owner'],'systemctl','--user','is-active','--quiet',f"{c['instance']}-cockpit-pwa.service")
        record['after']={str(p):digest(p.read_bytes()) for p in [qpath,conf,*units]}
        write(journal,(json.dumps(record)+'\n').encode(),0o600)
        return verify(c['instance'])
    except Exception:
        restore(c,record)
        raise


def current(instance):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}',instance):raise ValueError('Invalid instance')
    base=Path(BASE)/instance
    target=base/'current'
    if not target.is_symlink() or not re.fullmatch(r'releases/[0-9TZ]+',os.readlink(target)):
        raise ValueError('No installed parallel entrance')
    meta=json.loads((target/'receipt.json').read_text())
    c=config(meta['config'])
    if c['instance']!=instance:raise ValueError('Instance mismatch')
    return base,target,meta,c


def audit_receipt(target,meta):
    drift=[]
    actual={str(p.relative_to(target)) for p in target.rglob('*') if p.is_file() and p.name!='receipt.json'}
    if actual!=set(meta['files']):drift.append('release inventory')
    for p in [target.resolve(),*target.rglob('*')]:
        s=p.lstat()
        expected_mode=0o755 if p.is_dir() else 0o644
        if p.is_symlink() or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=expected_mode:
            drift.append('release ownership/permissions: '+str(p))
    for name,h in {**meta['files']}.items():
        p=target/name
        if not p.is_file() or digest(p.read_bytes())!=h:drift.append(name)
    backend=meta['backend_hashes']
    prefix='usr/local/lib/woowtech-cockpit-backup/'
    installed={p.relative_to('/').as_posix() for p in (Path('/')/prefix).rglob('*.py')}
    if installed!={n for n in backend if n.startswith(prefix)}:drift.append('backend inventory')
    for name,h in backend.items():
        p=Path('/')/name
        if not p.is_file() or p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode&0o022 or digest(p.read_bytes())!=h:
            drift.append(name)
    return drift


def validate_previous(base,record):
    previous=record['previous']
    if not previous:return  # Existing legacy sample has no managed receipt.
    if not re.fullmatch(r'releases/[0-9TZ]+',previous):raise ValueError('Invalid previous release')
    target=base/previous
    meta=json.loads((target/'receipt.json').read_text())
    drift=audit_receipt(target,meta)
    if drift:raise ValueError('Previous release no longer matches the common backend or trusted assets: '+', '.join(drift))


def verify(instance):
    base,target,meta,c=current(instance)
    drift=audit_receipt(target,meta)
    _,qpath=paths(c)
    if qpath.read_bytes()!=(target/'quadlet.container').read_bytes():drift.append('quadlet')
    for mode,unit in zip(('public','local'),unit_names(c)):
        if (Path('/etc/systemd/system')/unit).read_bytes()!=(target/f'pi-{mode}.service').read_bytes():drift.append(unit)
        command(['systemctl','is-active','--quiet',unit])
    user_command(c['owner'],'systemctl','--user','is-active','--quiet',f"{c['instance']}-cockpit-pwa.service")
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(20):
        try:
            with opener.open(f"http://127.0.0.1:{c['listen_port']}/",timeout=3) as response:
                if response.status!=200:drift.append('login HTTP')
            break
        except OSError:
            if attempt==19:raise
            time.sleep(.5)
    if drift:raise ValueError('Parallel ingress drift: '+', '.join(drift))
    return {'status':'verified','instance':instance,'brand':c['brand'],'source_commit':meta['source_commit'],
            'files':len(meta['files']),'backends':len(meta['backend_hashes']),'local_url':f"http://127.0.0.1:{c['listen_port']}",
            'public_origin':c['public_origin']}


def rollback(instance):
    if os.geteuid()!=0:raise ValueError('rollback requires sudo')
    base,target,meta,c=current(instance)
    journal=base/'transactions'/(target.resolve().name+'.json')
    record=json.loads(journal.read_text())
    for name,h in record.get('after',{}).items():
        if digest(Path(name).read_bytes())!=h:raise ValueError('Changed since installation: '+name)
    restore(c,record)
    return {'status':'rolled-back','instance':instance}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['plan','install','verify','rollback'])
    parser.add_argument('--config',type=Path)
    parser.add_argument('--instance')
    args=parser.parse_args()
    try:
        if args.action in ('plan','install'):
            if not args.config:parser.error('--config required')
            c=read_config(args.config)
            if args.action=='plan':
                result={**metadata(c),'backend_files':len(backend_hashes()),'writes':str(Path(BASE)/c['instance']),
                        'shared_backend_install':False,'public_access_policy_changed':False}
            else:
                with deployment_lock():result=install(c)
        else:
            if not args.instance:parser.error('--instance required')
            with deployment_lock():
                result=verify(args.instance) if args.action=='verify' else rollback(args.instance)
        print(json.dumps(result,indent=2))
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        print('Parallel ingress: '+str(error),file=sys.stderr);return 1
    return 0


if __name__=='__main__':sys.exit(main())
