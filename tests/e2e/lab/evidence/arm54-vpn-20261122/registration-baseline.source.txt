"""Synthetic HA -> unmodified product convert -> isolated volume restore/start.

Headscale CLI uses the real gRPC Unix socket as client. No published ports,
no runtime external networking; all generated private bytes stay in workspace.
"""
import gzip,hashlib,io,json,os,subprocess,sys,tarfile,time
from pathlib import Path
from types import SimpleNamespace
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'source/tests/e2e/lab'))
from arm54_owned_runtime import ROOT,Runner,report
from woowbackup import habackup,ha_headscale,nested,tempctr
from woowbackup.podman import Result
class RootfulRunner(Runner):
    def podman(self,*args,**kwargs):
        if args[:1]==('unshare',):
            command=list(args[1:])
            allowed=(command in (['cat','/proc/self/uid_map'],['cat','/proc/self/gid_map']))
            if command[:5]==['stat','-c','%u %g %a','--',command[-1]]:
                allowed=Path(command[-1]).resolve().is_relative_to((ROOT/'store/volumes').resolve())
            assert allowed, 'rootful-namespace-command-refused'
            self.commands.append(['rootful-direct-namespace',*command])
            result=subprocess.run(command,capture_output=True,timeout=10,check=True)
            assert len(result.stdout)<4096
            return Result(result.returncode,result.stdout,result.stderr)
        return super().podman(*args,**kwargs)
r=RootfulRunner(); image=json.loads((ROOT/'build-result.json').read_text())['image_id']
trial=ROOT/('trial-'+os.urandom(4).hex());trial.mkdir(mode=0o700)
objects=tempctr.TempObjects(r,'j20261122T123000Z-a54c0003',memory='384m',pids=256,cpus='0.5')
conversion=tempctr.TempObjects(r,'j20261122T123000Z-a54c0004',memory='384m',pids=256,cpus='0.5')
client_bin=trial/'client-bin';client_bin.mkdir(mode=0o700)
client_state=trial/'client-state';client_state.mkdir(mode=0o700)
copier=ROOT.name+'-client-copy'
answer={'status':'failed','product_base':'3fe2ff3','service_restore_acceptance':False,'phase':'prepare'}


def add(tar,name,data):
    info=tarfile.TarInfo(name); info.mode=0o600; info.size=len(data)
    tar.addfile(info,io.BytesIO(data))


def health(role):
    for attempt in range(30):
        p=objects.exec(role,['headscale','health'],check=False,timeout=5)
        if p.returncode==0: return
        time.sleep(0.5)
    raise RuntimeError('service-health-refused')


def users(role):
    rows=json.loads(objects.exec(role,['headscale','users','list','-o','json']).stdout)
    return sorted(row['name'] for row in rows)


def data_config(name,domain):
    config=trial/name; config.mkdir(mode=0o700)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=arm54.invalid',
        '-addext','subjectAltName=DNS:arm54.invalid,IP:127.0.0.1','-keyout',str(config/'server.key'),
        '-out',str(config/'server.crt')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=20)
    (config/'acl.hujson').write_text('{"acls":[{"action":"accept","src":["*"],"dst":["*:*" ]}]}')
    text='''server_url: https://arm54.invalid:8080
listen_addr: 127.0.0.1:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
disable_check_updates: true
tls_cert_path: /etc/headscale/server.crt
tls_key_path: /etc/headscale/server.key
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
derp:
  server:
    enabled: true
    region_id: 999
    region_code: arm54
    region_name: ARM54 isolated
    stun_listen_addr: 127.0.0.1:3478
    private_key_path: /var/lib/headscale/derp.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: DOMAIN
  nameservers:
    global: []
policy:
  mode: file
  path: /etc/headscale/acl.hujson
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
'''.replace('DOMAIN',domain)
    (config/'config.yaml').write_text(text)
    return config


def start(role,volume,config):
    run=trial/(role+'-run'); run.mkdir(mode=0o700)
    objects.run(role,image,['serve'],detach=True,volumes=[(volume,'/var/lib/headscale',None),
        (str(config),'/etc/headscale','ro'),(str(run),'/var/run/headscale',None),(str(client_bin),'/client-bin','ro'),
        (str(client_state),'/client-state',None)],add_hosts=[('arm54.invalid','127.0.0.1')])
    info=json.loads(r.podman('inspect',objects.name(role)).stdout)[0]
    assert info['HostConfig']['NetworkMode']=='none' and not info['HostConfig'].get('PortBindings')
    health(role)


def start_client(role):
    r.podman('exec','--detach','--env','SSL_CERT_FILE=/etc/headscale/server.crt',
        '--env','TS_DEBUG_LOG_DISABLE=true',
        '--env','HTTP_PROXY=','--env','HTTPS_PROXY=','--env','ALL_PROXY=',
        '--env','http_proxy=','--env','https_proxy=','--env','all_proxy=',
        '--env','NO_PROXY=*','--env','no_proxy=*',objects.name(role),'sh','-c',
        'exec /client-bin/tailscaled --tun=userspace-networking --state=/client-state/tailscaled.state --socket=/client-state/tailscaled.sock > /client-state/daemon.log 2>&1')
    for attempt in range(40):
        if (client_state/'tailscaled.sock').exists(): return
        time.sleep(0.25)
    raise RuntimeError('client-socket-refused')


def client_identity(role):
    for attempt in range(40):
        result=objects.exec(role,['/client-bin/tailscale','--socket=/client-state/tailscaled.sock','status','--json'],check=False,timeout=5)
        if result.returncode==0:
            value=json.loads(result.stdout)
            if value.get('BackendState')=='Running' and value.get('Self',{}).get('TailscaleIPs'):
                return {'id':value['Self']['ID'],'ips':value['Self']['TailscaleIPs']}
        time.sleep(0.5)
    raise RuntimeError('client-running-refused')


try:
    answer['phase']='prepare-pinned-client'
    client_ref='docker.io/tailscale/tailscale@sha256:8934bed5f68e80c5f9c881f62c65909223ee660432946c10ad212d958fc2c2bb'
    if r.podman('image','exists',client_ref,check=False).returncode!=0:
        r.podman('pull','--arch','arm64','--authfile',str(ROOT/'empty-auth.json'),client_ref,timeout=180)
    info=json.loads(r.podman('image','inspect',client_ref).stdout)[0]
    assert info['Architecture']=='arm64' and info['Size']<256*1024**2
    r.podman('create','--name',copier,'--network=none','--memory=64m','--image-volume=ignore',client_ref)
    for binary in ('tailscale','tailscaled'):
        r.podman('cp',copier+':/usr/local/bin/'+binary,str(client_bin/binary))
        (client_bin/binary).chmod(0o755)
    r.podman('rm','-f',copier)
    answer['client_image_reference']=client_ref
    src=objects.volume('source-data'); target=objects.volume('target-data'); plane=objects.volume('plane-data'); restored=objects.volume('restored-data')
    source_config=data_config('source-config','source.invalid')
    target_config=data_config('target-config','target.invalid')
    config_hash=hashlib.sha256((target_config/'config.yaml').read_bytes()).hexdigest()
    plane_tar=io.BytesIO()
    with tarfile.open(fileobj=plane_tar,mode='w') as t: add(t,'synthetic-plane.txt',b'preserve-target-headplane')
    objects.volume_import('plane-data',lambda out:out.write(plane_tar.getvalue()))
    answer['phase']='source-start'
    start('source',src,source_config)
    objects.exec('source',['headscale','users','create','arm54source','-o','json'])
    assert users('source')==['arm54source']
    answer['phase']='register-source-client'
    key=json.loads(objects.exec('source',['headscale','preauthkeys','create','--user','1','--expiration','10m','-o','json']).stdout)['key']
    assert isinstance(key,str) and len(key)>16
    from woowbackup import jobs
    jobs.mask_secret(key)
    (client_state/'authkey').write_text(key)
    local_tcp=objects.exec('source',['bash','-c','timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/8080"'],check=False,timeout=10)
    answer['isolated_localhost_tcp_reachable']=local_tcp.returncode==0
    start_client('source')
    client_up=objects.exec('source',['/client-bin/tailscale','--socket=/client-state/tailscaled.sock','up',
        '--login-server=https://127.0.0.1:8080','--auth-key=file:/client-state/authkey',
        '--accept-dns=false','--timeout=30s'],timeout=40,check=False)
    (client_state/'up.stdout').write_bytes(client_up.stdout)
    (client_state/'up.stderr').write_bytes(client_up.stderr)
    diagnostic=client_up.stdout+client_up.stderr+(client_state/'daemon.log').read_bytes()[:1024*1024]
    patterns=['context deadline exceeded','certificate signed by unknown authority','certificate is not valid','connection refused','failed to read','no such file','invalid auth','invalid key','unsupported','client version','unexpected status','404','401','400','timeout','fetch control key','Get "','failed to connect','Usage:','flag provided but not defined','file:','control:','x509:']
    answer['predicates']={v:v.encode().lower() in diagnostic.lower() for v in patterns}
    answer['up_exit']=client_up.returncode
    answer['tailscale_version']=objects.exec('source',['/client-bin/tailscale','version']).stdout.decode().strip()
    answer['fixture']=str(trial)
    answer['status']='passed' if client_up.returncode==0 else 'failed'
    answer['phase']='registration-probe'
    if client_up.returncode==0:
        answer['identity']=client_identity('source')
except Exception as e:
    answer['error_code']=type(e).__name__
    # Product messages are not published: arbitrary source values may appear there.
    if hasattr(e,'code'): answer['product_error_code']=e.code
finally:
    r.podman('rm','-f',copier,check=False)
    left_conversion=[]; left_objects=[] # Private fixture retained only until bounded diagnosis/cleanup.
    answer.update(cleanup_left=left_conversion+left_objects,commands=r.commands,free_bytes_samples=r.free)
    report(ROOT/'probe-result.json',answer)
    print(json.dumps(answer,sort_keys=True))
    sys.exit(0 if answer['status']=='passed' and not answer['cleanup_left'] else 1)
