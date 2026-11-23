"""Fixed host transport for sole-owner ARM/x86 restore; no arbitrary inputs.

Secrets are data read into RAM from compiled private paths, never shell sourced.
The owner child emits only exact private receipt bytes after cleanup. This module
is invoked by run_emqx_real_owner.sh; direct entry does not acquire lab ownership.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'backup-engine'))
from emqx_arm_cold_transfer import BOOTSTRAP as SOURCE_BOOTSTRAP, dependencies
from emqx_source_profiles import source_profile

CLIENT_CREDS=Path('/home/woowtechopenclaw/.woowbk-lab/secrets/b1-creds.env')
KEY_CREDS=Path('/home/woowtechopenclaw/.woowbk-lab/secrets/ha-import-creds.env')
PRIVATE_PARENT=Path('/home/woowtechopenclaw/.woowbk-lab')
SOURCE_SUMMARY=PRIVATE_PARENT/'evidence/b1-source/summary.json'
SEED_ROOT=Path('/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/phase3/testha-b1')
IMPORTED_MODES=frozenset((b'M',b'N'))
MODES={
 '--real-restore-mnesia-acl':('--source-vendor-acl-sql-aliases',b'M',False),
 '--x86-real-restore-mnesia-acl':('--x86-source-vendor-acl-sql-aliases',b'N',False),
 '--real-restore':('--source-vendor-acl-sql-aliases',b'G',False),
 '--x86-real-restore':('--x86-source-vendor-acl-sql-aliases',b'I',False),
 '--real-restore-staged':('--source-vendor-acl-sql-aliases',b'g',True),
 '--x86-real-restore-staged':('--x86-source-vendor-acl-sql-aliases',b'i',True),
}
CLIENT_KEYS=tuple(k for i in (1,2,3) for k in (f'B1_MQTT_USER{i}',f'B1_MQTT_PW{i}'))
ADMISSION=b'WOOWREALOWNER-ADMITTED1:'
# Extra bounded overhead includes six API fields of at most4096 bytes each.
MAX_BODY=512*1024*1024+49152
STAGED=b'REAL OWNER STAGED ONLY PASSED\n'
DEPENDENCIES=b'REAL OWNER DEPENDENCIES PASSED\n'
# Full real restore = 3 verified rounds; at host load ~27 round 2's capture already
# ran at ~700-720s (attempts 13-15) and a full pass took 590s at load ~13.
# The FILE baseline with its rule-delivery round passed in 1474.7s at load ~22
# (x86-attempt3), 25s under the old 1500s alarm: wall-clock bound only.
REAL_RESTORE_SECONDS=2100
HOST_PHASES=frozenset(('profile','bundle','dependencies','client_credentials','retained_binding','key','archive','archive_binding','transfer','child','receipt'))

class TransportRefused(ValueError):
    def __init__(self,phase):
        self.phase=phase


# Reuse the original bounded, private extraction/dependency loader, including its
# finally cleanup. No independent tar parser or key/archive frame implementation.
_dispatch="""
 if mode in (b'G',b'I',b'g',b'i',b'M',b'N',b'T',b'U',b'K',b'L'):
  from emqx_real_owner_transport import owner_main
  raise SystemExit(owner_main(mode))
"""
_anchor=" if mode in (b'E',b'F'):\n"
if SOURCE_BOOTSTRAP.count(_anchor)!=1:raise RuntimeError('fixed-bootstrap-contract')
BOOTSTRAP=SOURCE_BOOTSTRAP.replace(_anchor,_dispatch+_anchor)


def _snapshot(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _fixed_fields(path,names):
    """Bounded EOF/stability + regular owner600/no alias; parse only named data."""
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
                or not 0<before.st_size<=1024*1024):raise ValueError()
        raw=stream.read(1024*1024+1)
        if len(raw)!=before.st_size or stream.read(1) or _snapshot(before)!=_snapshot(os.fstat(stream.fileno())):
            raise ValueError()
    fields={}
    for line in raw.splitlines():
        if len(line)>8192:raise ValueError()
        name,sep,value=line.partition(b'=')
        if name not in {n.encode('ascii') for n in names}:continue
        key=name.decode('ascii')
        if key in fields or not sep:raise ValueError()
        parsed=shlex.split(value.decode('ascii'),comments=False,posix=True)
        if len(parsed)!=1:raise ValueError()
        fields[key]=parsed[0].encode('ascii')
    return fields


def read_fixed_fields(path,names):
    fields=_fixed_fields(path,names)
    if set(fields)!=set(names):raise ValueError()
    return [fields[n] for n in names]


def read_client_credentials():
    fields=read_fixed_fields(CLIENT_CREDS,CLIENT_KEYS)
    if any(re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',v) is None for v in fields):raise ValueError()
    if fields[0]!=b'b1-sensor' or fields[2]!=b'b1-gateway' or fields[4]==b'lab':raise ValueError()
    if len(set(fields[::2]))!=3:raise ValueError()
    return fields


def _read_original(path,limit):
    # Original producer files are owner664, not credential files. Require owned
    # regular data, no aliases/world-write, bounded EOF and stable path+fd stamps.
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1
                or before.st_mode&0o002 or not 0<before.st_size<=limit):raise ValueError()
        raw=stream.read(limit+1)
        if (len(raw)!=before.st_size or stream.read(1)
                or _snapshot(before)!=_snapshot(os.fstat(stream.fileno()))
                or _snapshot(before)!=_snapshot(path.stat(follow_symlinks=False))):raise ValueError()
    return raw


def _json_literal(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError()
            result[key]=value
        return result
    def invalid(_):raise ValueError()
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)


def _publish_literals(raw):
    result={}
    for line in raw.splitlines():
        # Only the original single-line, single-quoted JSON publish literals.
        # Prefix is inert text; no shell, substitution, env or URL resolution.
        if re.search(rb'\bPOST[ \t]+/publish\b',line) is None:continue
        match=re.fullmatch(rb"[^'\r\n;|&`]+[ \t]POST[ \t]+/publish[ \t]+-d[ \t]+'([^'\r\n]+)'[ \t]*",line)
        if match is None:raise ValueError()
        tokens=shlex.split(line.decode('utf-8'),comments=False,posix=True)
        if len(tokens)!=6 or tokens[2:5]!=['POST','/publish','-d']:raise ValueError()
        doc=_json_literal(match[1].decode('utf-8'))
        if (type(doc) is not dict or set(doc)!={'topic','payload','qos','retain'}
                or type(doc['topic']) is not str or type(doc['payload']) is not str
                or type(doc['qos']) is not int or doc['qos'] not in (0,1,2) or doc['retain'] is not True):raise ValueError()
        topic=doc['topic'].encode('utf-8');payload=doc['payload'].encode('utf-8')
        if (re.fullmatch(rb'b1/retained/[A-Za-z0-9_/-]{1,110}',topic) is None
                or not 0<len(payload)<=4096 or topic in result):raise ValueError()
        result[topic]=payload
    if len(result)!=2:raise ValueError()
    return result


def retained_expectations(source_mode):
    """Independent ORIGINAL producer expectations, NOT a cold/final-row proof.

    Three fixed original scripts must agree on both literal publish bodies. The
    selected original source-summary topic set and unique protected/local_ok
    backup must bind the compiled architecture/path/SHA. Only private RAM bytes
    leave this function. The child independently authenticates the ciphertext;
    cold consensus (before provision) and final MQTT remain separate obligations.
    """
    try:
        if source_mode not in {v[0] for v in MODES.values()}:raise ValueError()
        profile=source_profile(source_mode)
        arch='arm' if profile.arch=='aarch64' else 'x86' if profile.arch=='amd64' else None
        if arch is None:raise ValueError()
        names=('emqx-body.sh','emqx-arm.sh','emqx-x86.sh')
        originals=[*(SEED_ROOT/name for name in names),SOURCE_SUMMARY]
        stamps={p:_snapshot(p.stat(follow_symlinks=False)) for p in originals}
        scripts={name:_read_original(SEED_ROOT/name,512*1024) for name in names}
        maps={name:_publish_literals(raw) for name,raw in scripts.items()}
        expected=maps['emqx-body.sh']
        if any(value!=expected for value in maps.values()):raise ValueError()
        summary=_json_literal(_read_original(SOURCE_SUMMARY,4*1024*1024).decode('utf-8'))
        topics=summary['machines'][arch]['emqx']['retained_messages']
        if (type(topics) is not list or len(topics)!=2 or any(type(x) is not str for x in topics)
                or len(set(topics))!=2 or {x.encode('utf-8') for x in topics}!=set(expected)):raise ValueError()
        backups=summary['backups'][arch]
        if type(backups) is not list or not 0<len(backups)<=64 or any(type(r) is not dict for r in backups):raise ValueError()
        matches=[r for r in backups if r.get('sha256')==profile.sha256]
        if (len(matches)!=1 or matches[0].get('local_copy')!=str(profile.archive)
                or matches[0].get('local_ok') is not True or matches[0].get('protected') is not True):raise ValueError()
        if any(_snapshot(p.stat(follow_symlinks=False))!=stamp for p,stamp in stamps.items()):raise ValueError()
        return [value for topic in sorted(expected) for value in (topic,expected[topic])]
    except BaseException:
        raise TransportRefused('retained_binding') from None


def read_source_api_credentials(source_mode):
    if source_mode not in {v[0] for v in MODES.values()}:raise ValueError()
    arch='ARM' if source_profile(source_mode).arch=='aarch64' else 'X86'
    names=('B1_EMQX_ADMIN_PW','B1_EMQX_USER2','B1_EMQX_USER2_PW',
           'B1_'+arch+'_EMQX_API_KEY','B1_'+arch+'_EMQX_API_SECRET')
    fields={}
    for path in (CLIENT_CREDS,KEY_CREDS):
        observed=_fixed_fields(path,names)
        if set(observed)&set(fields):raise ValueError()
        fields.update(observed)
    if set(fields)!=set(names):raise ValueError()
    from emqx_real_owner_workflow import SourceAPICredentials
    return SourceAPICredentials((b'admin',*(fields[n] for n in names))).fields


def client_prefix(source_mode):
    from emqx_real_owner_workflow import CLIENT_MAGIC,CLIENT_MODES,read_source_clients,API_MAGIC,read_source_api_credentials as read_api
    fields=read_client_credentials()+retained_expectations(source_mode)
    if len(fields)!=10 or any(type(v) is not bytes or not 0<len(v)<=4096 for v in fields):raise ValueError()
    raw=CLIENT_MAGIC+CLIENT_MODES[source_mode]+b''.join(struct.pack('!H',len(v))+v for v in fields)
    stream=io.BytesIO(raw)
    read_source_clients(stream,source_mode)
    if stream.read(1):raise ValueError()
    fields=read_source_api_credentials(source_mode)
    api=API_MAGIC+CLIENT_MODES[source_mode]+b''.join(struct.pack('!H',len(v))+v for v in fields)
    check=io.BytesIO(api);read_api(check,source_mode)
    if check.read(1):raise ValueError()
    return api+raw


def bundle_code():
    """Immutable tracked public code closure, no host private files or test data."""
    paths=subprocess.check_output(['git','ls-tree','-r','--name-only','HEAD','tests/e2e/lab'],cwd=ROOT).decode('ascii').splitlines()
    selected=[p for p in paths if (Path(p).name.startswith('emqx_') and Path(p).suffix in ('.py','.escript','.expr'))
              or Path(p).name=='ha_real_fixture.py']
    required={'emqx_real_owner_transport.py','emqx_real_owner_workflow.py','emqx_post_restore_values.py',
              'emqx_owner_fixture_files.py','emqx_target_fixture_policy.py','emqx_adapter_mqtt.py','emqx_issued_target_probe.py','emqx_retained_history.py','emqx_source_api_validator.py','emqx_source_mqtt_negative.py','emqx_owned_client.py','emqx_imported_acl_target_mode.py','emqx_mnesia_acl_target_variant.py','emqx_b1_object_integrity.py','emqx_native_object_integrity.py','emqx_file_policy_api.py','emqx_client_sink_capabilities.py','emqx_client_nc_primitives.py'}
    if not required<={Path(p).name for p in selected}:raise ValueError()
    raw=subprocess.check_output(['git','archive','HEAD','backup-engine/woowbackup',*selected],cwd=ROOT)
    if not 0<len(raw)<=16*1024*1024:raise ValueError()
    return raw


def canonical_receipt():
    from emqx_private_evidence import names_receipt,SOURCE_NAMES
    return names_receipt('restore','passed',SOURCE_NAMES)


def retain_restore_evidence(frame):
    return _retain_evidence(frame,canonical_receipt(),'emqx-real-owner-evidence-','owner-restore.txt')


def _retain_evidence(frame,expected,prefix,name):
    from emqx_framed_preflight import MAGIC,MAX_FRAME
    if type(frame) is not bytes or not len(MAGIC)+4<len(frame)<=MAX_FRAME or not frame.startswith(MAGIC):raise ValueError()
    start=len(MAGIC)+4
    size=struct.unpack('!I',frame[len(MAGIC):start])[0]
    if not 0<size<=65536 or len(frame)!=start+size+32:raise ValueError()
    raw=frame[start:start+size]
    if hashlib.sha256(raw).digest()!=frame[-32:] or raw!=expected:raise ValueError()
    parent=PRIVATE_PARENT;info=parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700
            or any(p.is_symlink() for p in (parent,*parent.parents))):raise ValueError()
    root=Path(tempfile.mkdtemp(prefix=prefix,dir=parent))
    path=root/name;created=False
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        created=True
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),0o600)
            out.write(raw);out.flush();os.fsync(out.fileno())
        return path
    except BaseException:
        if created:path.unlink()
        root.rmdir()
        raise


def dependency_check():
    # Invoke real API imports after extraction, not a list-membership assertion.
    from emqx_real_owner_workflow import run_real_framed_owner,_composite_observer_factory,final_private_receipt
    from emqx_post_restore_values import collect_post_restore_values
    from emqx_retained_history import collect_original_retained_payloads
    from emqx_b1_object_integrity import capture_b1_object_expectations
    from emqx_native_object_integrity import compare_b1_objects_native
    from emqx_client_sink_capabilities import run_client_sink_capabilities
    from emqx_client_nc_primitives import run_client_nc_primitives
    from emqx_source_mqtt_negative import validate_source_mqtt_negative
    from emqx_source_api_validator import validate_source_api
    from emqx_adapter_mqtt import CLIENT
    from emqx_issued_target_probe import run_issued_target_probe,TARGET_RECEIPT
    from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter
    from woowbackup import flows
    if not all(callable(x) for x in (run_real_framed_owner,_composite_observer_factory(),
            final_private_receipt,collect_post_restore_values,collect_original_retained_payloads,validate_source_api,validate_source_mqtt_negative,capture_b1_object_expectations,compare_b1_objects_native,run_client_sink_capabilities,run_client_nc_primitives,run_issued_target_probe,QuadletPostgresAdapter,flows.run_restore)):
        raise ValueError()
    if type(CLIENT) is not str or type(TARGET_RECEIPT) is not bytes or not 0<len(TARGET_RECEIPT)<=65536:raise ValueError()


class AdmittedStream:
    """Expose logical EOF only after host's post-SHA/stamp commit and real EOF.

    The outer length covers the unchanged ten-field/key/cipher inner frame.
    No admission/EOF means staged_owner_frame never yields a source, so no cold
    collection or target mutation is possible, even with otherwise valid bytes.
    """
    def __init__(self,stream):
        self._stream=stream;self._admitted=False
        self._remaining=struct.unpack('!Q',self._exact(8))[0]
        if not 0<self._remaining<=MAX_BODY:raise ValueError()

    def _exact(self,n):
        chunks=[]
        while n:
            raw=self._stream.read(min(n,65536))
            if type(raw) is not bytes or not raw or len(raw)>n:raise ValueError()
            chunks.append(raw);n-=len(raw)
        return b''.join(chunks)

    def read(self,size):
        if type(size) is not int or not 0<=size<=65536:raise ValueError()
        if size==0:return b''
        if self._remaining:
            raw=self._stream.read(min(size,self._remaining))
            if type(raw) is not bytes or not raw or len(raw)>min(size,self._remaining):raise ValueError()
            self._remaining-=len(raw)
            return raw
        if not self._admitted:
            if self._exact(len(ADMISSION))!=ADMISSION or self._stream.read(1)!=b'':raise ValueError()
            if hasattr(self._stream,'finish'):self._stream.finish()
            self._admitted=True
        return b''

    def finish(self):
        if self._remaining or not self._admitted:raise ValueError()


def owner_main(mode):
    if mode==b'K':return owner_client_sink()
    if mode==b'L':return owner_client_nc()
    if mode==b'U':return owner_probe()
    if mode==b'T':
        dependency_check()
        if sys.stdin.buffer.read(1):return 1
        sys.stdout.buffer.write(DEPENDENCIES);sys.stdout.buffer.flush();return 0
    selected=[v for v in MODES.values() if v[1]==mode]
    if len(selected)!=1:return 2
    source_mode,_,no_live=selected[0]
    from emqx_arm_source_owner import _owner_realm
    if not _owner_realm():return 1
    fired=[]
    def deadline(*_):
        fired.append(True)  # fixed DEADLINE label, never the interrupted step's label
        raise ValueError()
    previous=signal.signal(signal.SIGALRM,deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL,REAL_RESTORE_SECONDS)
        from emqx_real_owner_workflow import run_real_framed_owner
        from emqx_framed_preflight import evidence_frame
        with tempfile.TemporaryDirectory(prefix='emqx-real-owner-private-',dir=Path.home()) as d:
            parent=Path(d);parent.chmod(0o700)
            admitted=AdmittedStream(sys.stdin.buffer)
            from emqx_imported_acl_target_mode import FILE_BASELINE,IMPORTED_MNESIA
            result=run_real_framed_owner(admitted,private_parent=parent,source_mode=source_mode,no_live=no_live,
                target_mode=IMPORTED_MNESIA if mode in IMPORTED_MODES else FILE_BASELINE)
        if no_live:
            if result!={'scope':'sha-bound-ciphertext-and-client-frame-only','runtime':'not-run',
                    'source_authentication':'not-performed','restore':'not-performed'}:raise ValueError()
            raw=STAGED
        else:
            if type(result) is not dict or result.get('evidence_bytes')!=canonical_receipt():raise ValueError()
            raw=evidence_frame(result['evidence_bytes'])
        # Both workflow cleanup and outer temporary-directory cleanup completed.
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0
    except BaseException as error:
        from emqx_real_owner_workflow import RealOwnerRefused,PHASES
        phase=error.phase if type(error) is RealOwnerRefused and error.phase in PHASES else 'profile'
        if fired:phase='deadline'
        sys.stdout.buffer.write(b'REALOWNER-REFUSED:'+phase.encode('ascii')+b'\n')
        sys.stdout.buffer.flush()
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def owner_client_nc():
    from emqx_arm_source_owner import _owner_realm
    from emqx_client_nc_primitives import run_client_nc_primitives,RECEIPT,ClientNCRefused,PHASES
    phase='realm'
    def deadline(*_):raise ValueError()
    previous=signal.signal(signal.SIGALRM,deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL,60)
        if not _owner_realm():raise ClientNCRefused('realm')
        phase='input'
        if sys.stdin.buffer.read(1):raise ClientNCRefused('input')
        phase='run';receipt=run_client_nc_primitives()
        if type(receipt) is not bytes or receipt!=RECEIPT:raise ClientNCRefused('run')
        sys.stdout.buffer.write(receipt);sys.stdout.buffer.flush();return 0
    except BaseException as error:
        phase=error.phase if type(error) is ClientNCRefused and error.phase in PHASES else phase
        sys.stdout.buffer.write(b'CLIENTNC-REFUSED:'+phase.encode('ascii')+b'\n');sys.stdout.buffer.flush();return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)


def owner_client_sink():
    from emqx_arm_source_owner import _owner_realm
    from emqx_client_sink_capabilities import run_client_sink_capabilities,RECEIPT,ClientSinkRefused,PHASES
    phase='realm'
    def deadline(*_):raise ValueError()
    previous=signal.signal(signal.SIGALRM,deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL,60)
        if not _owner_realm():raise ClientSinkRefused('realm')
        phase='input'
        if sys.stdin.buffer.read(1):raise ClientSinkRefused('input')
        phase='run';receipt=run_client_sink_capabilities()
        if type(receipt) is not bytes or receipt!=RECEIPT:raise ClientSinkRefused('run')
        sys.stdout.buffer.write(receipt);sys.stdout.buffer.flush();return 0
    except BaseException as error:
        phase=error.phase if type(error) is ClientSinkRefused and error.phase in PHASES else phase
        sys.stdout.buffer.write(b'CLIENTSINK-REFUSED:'+phase.encode('ascii')+b'\n')
        sys.stdout.buffer.flush();return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def owner_probe():
    from emqx_arm_source_owner import _owner_realm
    from emqx_issued_target_probe import run_issued_target_probe,TARGET_RECEIPT,IssuedProbeRefused,PHASES
    if not _owner_realm():return 1
    def deadline(*_):raise ValueError()
    previous=signal.signal(signal.SIGALRM,deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL,840)
        if sys.stdin.buffer.read(1):raise ValueError()
        raw=run_issued_target_probe()
        if type(raw) is not bytes or raw!=TARGET_RECEIPT:raise ValueError()
        from emqx_framed_preflight import evidence_frame
        sys.stdout.buffer.write(evidence_frame(raw));sys.stdout.buffer.flush();return 0
    except BaseException as error:
        phase=error.phase if type(error) is IssuedProbeRefused and error.phase in PHASES else 'realm'
        sys.stdout.buffer.write(b'ISSUEDPROBE-REFUSED:'+phase.encode('ascii')+b'\n')
        sys.stdout.buffer.flush();return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def read_result(child,*,timeout=900):
    from emqx_real_owner_workflow import PHASES
    from emqx_issued_target_probe import PHASES as PROBE_PHASES
    from emqx_client_sink_capabilities import PHASES as SINK_PHASES
    from emqx_client_nc_primitives import PHASES as NC_PHASES
    from emqx_framed_preflight import MAX_FRAME
    deadline=time.monotonic()+timeout;result=bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout,selectors.EVENT_READ)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not selector.select(remaining):raise TransportRefused('child')
            raw=os.read(child.stdout.fileno(),min(65536,MAX_FRAME+1-len(result)))
            if not raw:break
            result.extend(raw)
            if len(result)>MAX_FRAME:raise TransportRefused('child')
    if child.wait(timeout=max(.01,deadline-time.monotonic()))!=0:
        for phase in PHASES:
            if bytes(result)==b'REALOWNER-REFUSED:'+phase.encode('ascii')+b'\n':
                raise TransportRefused(phase)
        for phase in PROBE_PHASES:
            if bytes(result)==b'ISSUEDPROBE-REFUSED:'+phase.encode('ascii')+b'\n':
                raise TransportRefused('probe_'+phase)
        for phase in SINK_PHASES:
            if bytes(result)==b'CLIENTSINK-REFUSED:'+phase.encode('ascii')+b'\n':
                raise TransportRefused('sink_'+phase)
        for phase in NC_PHASES:
            if bytes(result)==b'CLIENTNC-REFUSED:'+phase.encode('ascii')+b'\n':raise TransportRefused('nc_'+phase)
        raise TransportRefused('child')
    return bytes(result)


def _broken_pipe_refusal(child):
    """A failed upload may recover only a complete, fixed child refusal.

    Never admit, retry, retain evidence or accept a success frame after EPIPE.
    Closing input gives an incomplete consumer EOF, not the host admission token.
    stderr remains discarded; read_result bounds stdout, EOF, deadline and exit.
    """
    from emqx_real_owner_workflow import PHASES
    try:child.stdin.close()
    except BaseException:pass
    try:
        read_result(child,timeout=30)
    except TransportRefused as error:
        if error.phase in PHASES:return error.phase
    except BaseException:pass
    return None


def main(argv=None):
    child=None;phase='profile'
    try:
        args=sys.argv[1:] if argv is None else argv
        dependency_only=args==['--real-restore-dependencies']
        probe_only=args==['--issued-target-probe']
        sink_only=args==['--client-sink-capabilities']
        nc_only=args==['--client-nc-primitives']
        if not dependency_only and not probe_only and not sink_only and not nc_only and (len(args)!=1 or args[0] not in MODES):raise ValueError()
        phase='bundle';code=bundle_code()
        phase='dependencies';deps=dependencies()
        if dependency_only or probe_only or sink_only or nc_only:
            child=subprocess.Popen([str(ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3','-c',BOOTSTRAP],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            child.stdin.write(struct.pack('!Q',len(code))+code+struct.pack('!Q',len(deps))+deps+(b'L' if nc_only else b'K' if sink_only else b'U' if probe_only else b'T'))
            child.stdin.close()
            phase='child';frame=read_result(child,timeout=900 if probe_only else 60)
            if nc_only:
                from emqx_client_nc_primitives import RECEIPT
                phase='receipt'
                if frame!=RECEIPT:raise ValueError()
                print('CLIENT NC PRIMITIVES PASSED',flush=True)
            elif sink_only:
                from emqx_client_sink_capabilities import RECEIPT
                phase='receipt'
                if frame!=RECEIPT:raise ValueError()
                print('CLIENT SINK CAPABILITIES PASSED',flush=True)
            elif probe_only:
                from emqx_issued_target_probe import TARGET_RECEIPT
                phase='receipt'
                _retain_evidence(frame,TARGET_RECEIPT,'emqx-issued-target-evidence-','issued-target.txt')
                print('ISSUED TARGET PROBE PASSED',flush=True)
            else:
                if frame!=DEPENDENCIES:raise ValueError()
                print('REAL OWNER DEPENDENCIES PASSED',flush=True)
            return 0
        source_mode,mode,no_live=MODES[args[0]]
        profile=source_profile(source_mode)
        phase='client_credentials';prefix=client_prefix(source_mode)
        phase='key'
        key,=read_fixed_fields(KEY_CREDS,('HA_BACKUP_KEY',))
        if not 1<=len(key)<=1024 or b'\n' in key or b'\r' in key:raise ValueError()
        phase='archive'
        fd=os.open(profile.archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as archive:
            before=os.fstat(archive.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=512*1024*1024:raise ValueError()
            child=subprocess.Popen([str(ROOT/'tests/e2e/lab/owner.sh'),'d','/usr/bin/python3','-c',BOOTSTRAP],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            phase='transfer'
            body_size=len(prefix)+4+len(key)+8+before.st_size
            if not 0<body_size<=MAX_BODY:raise ValueError()
            child.stdin.write(struct.pack('!Q',len(code))+code+struct.pack('!Q',len(deps))+deps+mode+struct.pack('!Q',body_size)+prefix)
            child.stdin.write(struct.pack('!I',len(key))+key+struct.pack('!Q',before.st_size))
            digest=hashlib.sha256();total=0
            while total<before.st_size:
                raw=archive.read(min(65536,before.st_size-total))
                if not raw:raise ValueError()
                total+=len(raw);digest.update(raw);child.stdin.write(raw)
            phase='archive_binding'
            if archive.read(1) or _snapshot(before)!=_snapshot(os.fstat(archive.fileno())) or digest.hexdigest()!=profile.sha256:
                raise ValueError()
            # Sole admission point. An exceptional close is NOT a commit.
            child.stdin.write(ADMISSION)
            child.stdin.close()
        phase='child';frame=read_result(child,timeout=REAL_RESTORE_SECONDS+60)
        if no_live:
            if frame!=STAGED:raise ValueError()
            print('REAL OWNER STAGED ONLY PASSED',flush=True)
        else:
            phase='receipt';retain_restore_evidence(frame)
            print('REAL OWNER RESTORE ROLLBACK PASSED',flush=True)
        return 0
    except BaseException as error:
        if isinstance(error,BrokenPipeError) and child is not None:
            refused=_broken_pipe_refusal(child)
            if refused is not None:phase=refused
        if type(error) is TransportRefused:phase=error.phase
        if child is not None:
            try:
                child.stdin.close();child.wait(timeout=30)
            except BaseException:
                child.terminate()
                try:child.wait(timeout=30)
                except BaseException:pass
        from emqx_real_owner_workflow import PHASES
        from emqx_issued_target_probe import PHASES as PROBE_PHASES
        from emqx_client_sink_capabilities import PHASES as SINK_PHASES
        from emqx_client_nc_primitives import PHASES as NC_PHASES
        if phase not in HOST_PHASES|PHASES|{'probe_'+p for p in PROBE_PHASES}|{'sink_'+p for p in SINK_PHASES}|{'nc_'+p for p in NC_PHASES}:phase='profile'
        print('REAL OWNER '+phase.upper()+' REFUSED',flush=True);return 1


if __name__=='__main__':raise SystemExit(main())
