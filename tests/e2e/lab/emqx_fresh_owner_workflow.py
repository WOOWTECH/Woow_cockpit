"""Invocation-fresh private target + framed source callsite; build/package only.

Only authorized isolated dev-d appowner callers, under caller-held lab ownership.
No CLI, locks, production lookup, install or restore. The empty target must exist
for preflight observation; it never receives source bytes. Source-data candidate
brokers remain behind build_owner_candidate's unchanged combined-scan gates.
Implicit vendor file authorization is preserved. The actual held driver observer
must prove every supported vendor dependency; unobserved/mounted custom paths
still refuse. No empty authorization source list or alternate authorizer is used.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import tempfile
import time
from types import SimpleNamespace

from emqx_arm_source_owner import _exact, MAX_ARCHIVE
from emqx_private_owner_driver import build_owner_candidate
from emqx_private_boundary import PrivateFailure
from emqx_runtime_live import IMAGE
from emqx_source_profiles import source_profile
from woowbackup.ha_emqx import SUSPEND_SYS_EXPR, TICKER_STATUS_EXPR

LABEL = 'io.woowbk.emqx.fresh-owner'


def _realm(runner, parent):
    path = Path(parent).absolute()
    info = path.stat()
    if (socket.gethostname() != 'woowbk-dev-d' or os.geteuid() == 0
            or os.getuid() != os.geteuid() or runner.owner != 'appowner'
            or runner.uid != os.geteuid() or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode)
            or any(p.is_symlink() for p in (path,*path.parents))):
        raise ValueError()
    return path


class FreshTarget:
    def __init__(self, runner, root):
        self.runner, self.root = runner, root
        self.nonce = secrets.token_hex(6)
        self.name = 'woowbk-emqx-fresh-' + self.nonce
        self.volumes = (self.name+'-data',self.name+'-log')
        self.pending_volumes, self.pending_container, self.cid = [], False, None
        self.username = ('owner-'+secrets.token_hex(6)).encode()
        self.password = secrets.token_hex(24).encode()
        self.active = self.leased = False
        self.config = root/'emqx.conf'
        cookie = secrets.token_hex(24)
        raw = ('node.name="fresh@127.0.0.1"\nnode.data_dir="/opt/emqx/data"\n'
            'node.cookie="'+cookie+'"\n'
            'dashboard.default_username="'+self.username.decode()+'"\n'
            'dashboard.default_password="'+self.password.decode()+'"\n'
            'dashboard.listeners.http.bind="127.0.0.1:18083"\n'
            'dashboard.listeners.https.bind=0\nlisteners.tcp.default.bind="127.0.0.1:1883"\n'
            'listeners.ssl.default.enable=false\nlisteners.ws.default.enable=false\n'
            'listeners.wss.default.enable=false\n'
            'authentication=[{mechanism=password_based,backend=built_in_database,\n'
            'user_id_type=username,enable=true,\n'
            'password_hash_algorithm={name=sha256,salt_position=suffix}}]\n').encode()
        fd = os.open(self.config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),0o600)
            out.write(raw)
        self.target = SimpleNamespace(container=self.name,image='sha256:'+IMAGE,
            data_volume=self.volumes[0],log_volume=self.volumes[1],
            node='fresh@127.0.0.1',env={'EMQX_NODE__NAME':'fresh@127.0.0.1'},secrets=[],
            files=[(str(self.config),'/opt/emqx/etc/emqx.conf','ro')])

    def __repr__(self):
        return '<EMQX private fresh target>'

    def call(self,*args):
        return self.runner.podman(*args,check=False,timeout=15,max_output=65536)

    def checked(self,*args):
        response = self.call(*args)
        if response.returncode: raise ValueError()
        return response.stdout

    def owned(self, kind, name):
        info = json.loads(self.checked(kind,'inspect',name))[0]
        if (info.get('Name','').lstrip('/') != name
                or (info.get('Labels') if kind=='volume' else info.get('Config',{}).get('Labels',{})).get(LABEL) != self.nonce):
            raise ValueError()
        if kind == 'container' and self.cid is not None and info['Id'] != self.cid:
            raise ValueError()
        return info

    def identity(self):
        info = self.owned('container',self.name)
        host = info['HostConfig']
        mounts = info['Mounts']
        if (info['Image'].removeprefix('sha256:') != IMAGE or not info['State']['Running']
                or host['NetworkMode'] != 'none' or host.get('PortBindings') not in (None,{})
                or host['LogConfig']['Type'] != 'none' or host['Memory'] != 768*1024**2
                or host['PidsLimit'] != 256 or host['NanoCpus'] != 750000000
                or len(mounts) != 3
                or {(m['Name'],m['Destination']) for m in mounts if m['Type']=='volume'} != {
                    (self.volumes[0],'/opt/emqx/data'),(self.volumes[1],'/opt/emqx/log')}
                or [(m['Source'],m['Destination'],m['RW']) for m in mounts if m['Type']=='bind'] !=
                   [(str(self.config),'/opt/emqx/etc/emqx.conf',False)]):
            raise ValueError()

    def start(self):
        image = json.loads(self.checked('image','inspect','sha256:'+IMAGE))[0]
        if (image['Id'].removeprefix('sha256:') != IMAGE
                or image['Config']['Labels'].get('org.opencontainers.image.version') != '5.8.9'):
            raise ValueError()
        if self.call('container','exists',self.name).returncode != 1: raise ValueError()
        for volume in self.volumes:
            if self.call('volume','exists',volume).returncode != 1: raise ValueError()
            self.pending_volumes.append(volume)  # include creation followed by timeout
            self.checked('volume','create','--label',LABEL+'='+self.nonce,volume)
            self.owned('volume',volume)
        self.pending_container = True
        cid = self.checked('run','-d','--name',self.name,'--label',LABEL+'='+self.nonce,
            '--pull=never','--network=none','--log-driver=none','--image-volume=ignore',
            '--userns=keep-id:uid=1000,gid=1000','--memory=768m','--cpus=0.75','--pids-limit=256',
            '-e','ERL_FLAGS=+S 2:2 +SDcpu 1 +SDio 1',
            '-e','EMQX_NODE__NAME='+self.target.node,
            '-v',self.volumes[0]+':/opt/emqx/data','-v',self.volumes[1]+':/opt/emqx/log',
            '-v',str(self.config)+':/opt/emqx/etc/emqx.conf:ro','sha256:'+IMAGE).strip().decode('ascii')
        if not re.fullmatch(r'[0-9a-f]{64}',cid): raise ValueError()
        self.cid = cid
        deadline = time.monotonic()+75
        while time.monotonic() < deadline:
            self.identity()
            ready = self.call('exec',self.name,'emqx','ctl','status')
            if ready.returncode == 0 and b'is started' in ready.stdout:
                self.active = True
                return
            time.sleep(1)
        raise ValueError()

    @contextmanager
    def quiesce(self):
        """Limited fresh-fixture lease, not a universal production writer freeze.

        Network none/no ports, no seeded clients and only this owner's login.
        Exclude clients and suspend the actual system ticker through the build;
        unchanged native target receipts still must pass. Other background
        writers are not universally frozen; no completeness claim is added.
        The suspended ticker ends with this fixture's scoped container removal.
        """
        from emqx_preflight_stage import mark
        mark('target_quiescence')
        if not self.active or self.leased: raise ValueError()
        def empty():
            self.identity()
            raw = self.checked('exec',self.name,'emqx','eval',
                '[] = emqx_cm:all_channels(), io:format("OWNERNOCLIENTS").')
            if raw.strip() != b'OWNERNOCLIENTSok': raise ValueError()
        empty()
        wire = self.checked('exec',self.name,'emqx','eval',SUSPEND_SYS_EXPR)
        match = re.fullmatch(rb'WOOWSYS:(<[0-9]+\.[0-9]+\.[0-9]+>):suspended\s*(?:ok\s*)?',wire)
        if not match: raise ValueError()
        expression = TICKER_STATUS_EXPR.replace('{pid}',match[1].decode())
        def stable():
            self.identity()
            if self.checked('exec',self.name,'emqx','eval',expression).strip() != b'ticker_unchanged':
                raise ValueError()
        stable()
        self.leased = True
        try: yield
        finally:
            self.leased = False
            stable()
            empty()

    def cleanup(self):
        self.active = False
        failures = []
        resources = ([('container',self.name)] if self.pending_container else []) + [
            ('volume',name) for name in reversed(self.pending_volumes)]
        for kind,name in resources:
            try:
                status = self.call(kind,'exists',name).returncode
                if status == 1: continue
                if status != 0: raise ValueError()
                self.owned(kind,name)  # never delete an unowned collision/replacement
                if kind == 'container': self.checked('rm','--force','--ignore',name)
                else: self.checked('volume','rm',name)
                if self.call(kind,'exists',name).returncode != 1: raise ValueError()
            except Exception:
                failures.append(kind)
        if failures: raise PrivateFailure('private-fresh-cleanup-refused') from None


@contextmanager
def fresh_target(*, runner, private_parent):
    """Invocation-owned empty target, generated RAM bootstrap and private config."""
    try:
        parent = _realm(runner,private_parent)
        with tempfile.TemporaryDirectory(prefix='emqx-fresh-private-',dir=parent) as directory:
            root = Path(directory)
            root.chmod(0o700)
            fixture = FreshTarget(runner,root)
            try:
                fixture.start()
                yield fixture
            finally:
                fixture.cleanup()
    except (KeyboardInterrupt,SystemExit):
        raise PrivateFailure('private-fresh-cancelled') from None
    except Exception:
        raise PrivateFailure('private-fresh-refused') from None


@contextmanager
def staged_owner_frame(stream, *, runner, private_parent, source_mode):
    """Shared bounded key/ciphertext staging. Key remains in RAM, EOF+finish first."""
    parent = _realm(runner,private_parent)
    profile = source_profile(source_mode)
    size = struct.unpack('!I',_exact(stream,4))[0]
    if not 1 <= size <= 1024: raise ValueError()
    password = _exact(stream,size).decode('ascii')
    if not password or '\n' in password or '\r' in password: raise ValueError()
    remaining = struct.unpack('!Q',_exact(stream,8))[0]
    if not 0 < remaining <= MAX_ARCHIVE: raise ValueError()
    with tempfile.TemporaryDirectory(prefix='emqx-framed-private-',dir=parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        source = root/'encrypted-source.tar'
        fd = os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        digest = hashlib.sha256()
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600)
            while remaining:
                chunk = _exact(stream,min(remaining,65536))
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        if stream.read(1) != b'' or digest.hexdigest() != profile.sha256: raise ValueError()
        if hasattr(stream,'finish'): stream.finish()
        spool = root/'spool'
        spool.mkdir(mode=0o700)
        yield source, password, spool, profile, root


def build_fresh_framed_candidate(work,app,adapter,stream,staging,job_id,*,runner,
                                 private_parent,source_mode,evidence_directory,evidence_name):
    """Build-only entry; shares strict framed staging with preflight-only entry."""
    try:
        if app.id != 'emqx': raise ValueError()
        with staged_owner_frame(stream, runner=runner, private_parent=private_parent,
                source_mode=source_mode) as (source, password, spool, profile, root):
            with fresh_target(runner=runner,private_parent=root) as fixture:
                return build_owner_candidate(work,app,adapter,fixture.target,source,staging,job_id,
                    source_password=password,expected_sha256=profile.sha256,spool_directory=spool,
                    source_options={'fixture_profile':profile.fixture_profile,
                        'file_dependency_profile':profile.file_dependency_profile,
                        'product_image':'sha256:'+IMAGE if profile.file_dependency_profile is not None else None},
                    runner=runner,quiesce=fixture.quiesce,
                    login_url='http://127.0.0.1:18083/api/v5/login',
                    username=fixture.username,password=fixture.password,
                    evidence_directory=evidence_directory,evidence_name=evidence_name)
    except (KeyboardInterrupt,SystemExit):
        raise PrivateFailure('private-fresh-workflow-cancelled') from None
    except Exception:
        raise PrivateFailure('private-fresh-workflow-refused') from None


def preflight_fresh_frame(stream, *, runner, private_parent, source_mode):
    """Actual source + invocation-fresh target + login/scan only; exact bytes out.

    Private evidence and all owned resources are removed before bytes return.
    This function cannot call build_owner_candidate, replay or product restore.
    """
    try:
        from emqx_private_owner_driver import preflight_owner
        from emqx_preflight_stage import mark
        mark('frame')
        if source_mode not in ('--source-vendor-acl-sql-aliases',
                               '--x86-source-vendor-acl-sql-aliases'):
            raise ValueError()
        with staged_owner_frame(stream, runner=runner, private_parent=private_parent,
                source_mode=source_mode) as (source, password, spool, profile, root):
            evidence = root/'evidence'
            evidence.mkdir(mode=0o700)
            mark('fresh_target')
            with fresh_target(runner=runner, private_parent=root) as fixture:
                raw = preflight_owner(fixture.target, source, source_password=password,
                    expected_sha256=profile.sha256, spool_directory=spool,
                    source_options={'fixture_profile':profile.fixture_profile,
                        'file_dependency_profile':profile.file_dependency_profile,
                        'product_image':'sha256:'+IMAGE if profile.file_dependency_profile is not None else None},
                    runner=runner, quiesce=fixture.quiesce,
                    login_url='http://127.0.0.1:18083/api/v5/login',
                    username=fixture.username, password=fixture.password,
                    evidence_directory=evidence, evidence_name='owner-preflight.txt',
                    expected_source_profile=profile)
        return raw
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('private-fresh-preflight-cancelled') from None
    except Exception:
        raise PrivateFailure('private-fresh-preflight-refused') from None
