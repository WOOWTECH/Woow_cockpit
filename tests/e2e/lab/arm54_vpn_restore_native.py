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
trial=Path(json.loads((ROOT/'probe-result.json').read_text())['fixture'])
assert trial.parent==ROOT and trial.name.startswith('trial-')
objects=tempctr.TempObjects(r,'j20261122T123000Z-a54c0003',memory='384m',pids=256,cpus='0.5')
conversion=tempctr.TempObjects(r,'j20261122T123000Z-a54c0004',memory='384m',pids=256,cpus='0.5')
objects.containers=[objects.name('source')]
objects.volumes=[objects.name(role) for role in ('source-data','target-data','plane-data','restored-data')]
src,target,plane,restored=objects.volumes
for volume in objects.volumes:
 info=json.loads(r.podman('volume','inspect',volume).stdout)[0]
 assert info['Labels']['io.woowtech.backup.job']==objects.job_id
client_bin=trial/'client-bin';client_state=trial/'client-state'
source_config=trial/'source-config';target_config=trial/'target-config'
config_hash=hashlib.sha256((target_config/'config.yaml').read_bytes()).hexdigest()
copier=ROOT.name+'-client-copy'
answer={'status':'failed','product_base':'3fe2ff3','service_restore_acceptance':False,'phase':'registered-source-continuation'}

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
        '--env','TS_ASSUME_NETWORK_UP_FOR_TEST=true',
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
    original_client=client_identity('source')
    assert original_client==json.loads((ROOT/'retry-result.json').read_text())['identity']
    answer['source_identity']=original_client
    (client_state/'authkey').unlink()
    answer['source_tailscale_client_running']=True
    # CLI is a genuine Headscale gRPC client using this server's Unix socket.
    answer['source_client_assertion']='grpc-cli-users-list'
    objects.stop('source',timeout=10)
    objects.remove('source')
    source_export=trial/'source-private.tar'
    with source_export.open('xb') as out: objects.volume_export('source-data',out,max_output=32*1024**2)
    answer['phase']='target-start'
    start('target',target,target_config)
    objects.exec('target',['headscale','users','create','targetonly','-o','json'])
    assert users('target')==['targetonly']
    objects.stop('target',timeout=10); objects.remove('target')
    slug='a54a54a5_woow-headscale'
    inner=io.BytesIO(); source_noise=None
    with tarfile.open(fileobj=inner,mode='w') as tar, tarfile.open(source_export) as source:
        add(tar,'addon.json',json.dumps({'system':{'slug':'woow-headscale'},'user':{'image':'synthetic/aarch64-addon-woow-headscale'},'version':'0.1.3','state':'stopped'}).encode())
        for member in source:
            name=member.name.removeprefix('./')
            if name in ('db.sqlite','db.sqlite-wal','noise.key') and member.isfile():
                data=source.extractfile(member).read()
                if name=='noise.key': source_noise=data.strip()
                add(tar,'data/'+('noise_private.key' if name=='noise.key' else name),data)
        add(tar,'config/config.yaml',(source_config/'config.yaml').read_bytes())
        add(tar,'config/dns_records.json',b'[]')
    assert source_noise
    outer={'slug':'a54a54a5','version':2,'name':'ARM54 synthetic service','date':'2026-11-22T12:30:00+00:00',
        'type':'partial','supervisor_version':'2026.11.0','compressed':True,'protected':False,'homeassistant':None,
        'folders':[],'repositories':[],'addons':[{'slug':slug,'name':'Synthetic Headscale','version':'0.1.3','size':0.0}]}
    backup=trial/'synthetic-ha.tar'
    with tarfile.open(backup,'x') as tar:
        add(tar,'backup.json',json.dumps(outer).encode()); add(tar,slug+'.tar.gz',gzip.compress(inner.getvalue()))
    answer['synthetic_ha_sha256']=hashlib.sha256(backup.read_bytes()).hexdigest()
    answer['phase']='product-convert'
    quadlets={'headscale.container':f'[Container]\nContainerName=headscale\nImage={image}\nVolume={target}.volume:/var/lib/headscale\nVolume=%h/{trial.name}/target-config:/etc/headscale:ro\n'.encode(),
        'headplane.container':f'[Container]\nContainerName=headplane\nVolume={plane}.volume:/var/lib/headplane\n'.encode(),
        target+'.volume':f'[Volume]\nVolumeName={target}\n'.encode(),plane+'.volume':f'[Volume]\nVolumeName={plane}\n'.encode()}
    app=SimpleNamespace(id='headscale',name='Synthetic Headscale',volumes=[{'name':target},{'name':plane}],postgres=[],data_dirs=[])
    uid=nested.IdMap(r.podman('unshare','cat','/proc/self/uid_map').stdout.decode())
    gid=nested.IdMap(r.podman('unshare','cat','/proc/self/gid_map').stdout.decode())
    staging=trial/'engine-staging'; staging.mkdir(mode=0o700)
    out=trial/'converted-output'; out.mkdir(mode=0o700)
    with habackup.open_backup(backup) as opened:
        work=SimpleNamespace(quadlets=lambda app:quadlets,runner=lambda app:r,adapter=lambda app:SimpleNamespace(owner_ids=lambda:(uid,gid)),
            temp=lambda app:conversion,addon_member=lambda slug_:slug,open=lambda member:opened.open_addon(member),
            addon_info=lambda slug_:SimpleNamespace(version='0.1.3'),staging=staging,guard=SimpleNamespace(budget=lambda:32*1024**2,wrote=lambda size:None),
            abort=None,checkpoint=lambda:None,phase=lambda phase:None,log=lambda text:None)
        converted=ha_headscale.convert(work,app,False,out)
    assert converted['users']==1 and converted['nodes']==1
    with tarfile.open(converted['volumes'][target]) as tar:
        noise=next(tar.extractfile(m).read().strip() for m in tar if m.name.removeprefix('./')=='noise.key')
    assert noise==source_noise
    with tarfile.open(converted['volumes'][plane]) as tar:
        assert next(tar.extractfile(m).read() for m in tar if m.name.removeprefix('./')=='synthetic-plane.txt')==b'preserve-target-headplane'
    answer['phase']='restore-and-start'
    def produce(out):
        with converted['volumes'][target].open('rb') as inp:
            import shutil
            shutil.copyfileobj(inp,out)
    objects.volume_import('restored-data',produce)
    start('restored',restored,target_config)
    assert users('restored')==['arm54source']
    answer['phase']='restore-existing-client-state'
    (client_state/'tailscaled.sock').unlink(missing_ok=True)
    start_client('restored')
    restored_client=client_identity('restored')
    answer['restored_identity']=restored_client
    assert restored_client==original_client
    assert not (client_state/'authkey').exists()
    answer['same_client_id_ips_without_reauth']=True
    assert hashlib.sha256((target_config/'config.yaml').read_bytes()).hexdigest()==config_hash
    answer.update(status='passed',service_restore_acceptance='synthetic-internal-converter-tailscale-client',
        target_config_preserved=True,source_noise_preserved=True,headplane_marker_preserved=True,
        restored_client_assertion='grpc-cli-users-list-source-present-target-absent',users=1,nodes=1,
        installer_rollback_tested=False,tailscale_vpn_client_tested=True)
except Exception as e:
    answer['error_code']=type(e).__name__
    # Product messages are not published: arbitrary source values may appear there.
    if hasattr(e,'code'): answer['product_error_code']=e.code
finally:
    r.podman('rm','-f',copier,check=False)
    left_conversion=conversion.cleanup(); left_objects=objects.cleanup()
    answer.update(cleanup_left=left_conversion+left_objects,commands=r.commands,free_bytes_samples=r.free)
    report(ROOT/'service-result.json',answer)
    print(json.dumps(answer,sort_keys=True))
    sys.exit(0 if answer['status']=='passed' and not answer['cleanup_left'] else 1)
