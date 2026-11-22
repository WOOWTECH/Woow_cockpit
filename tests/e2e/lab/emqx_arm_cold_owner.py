"""Private dev-d ARM cold secret superset preparse. No broker/startup/restore.

Only input: framed RAM key + streaming encrypted fixed-SHA archive from authorized
host controller. No caller filenames, arbitrary native paths or environment keys.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tarfile
import tempfile
import signal

from woowbackup import habackup, hacommon, ha_emqx, hasecuretar
from ha_real_fixture import source_binding
from emqx_private_spool import capture
from emqx_cold_history import HistoryInventory, native_cold_history, native_cold_diagnostic
from emqx_broker_workload import PartialScan

def cold_kind(name,size):
    filename=Path(name).name
    if filename=="schema.DAT":return "schema-dat"
    if filename.endswith(".DCD"):return "empty-dcd" if size==8 else "dcd"
    if filename.endswith(".DCL"):return "dcl"
    kinds={"LATEST.LOG":"transaction-log","PREVIOUS.LOG":"transaction-log",
           "DECISION.LOG":"decision-log","PDECISION.LOG":"decision-log","DECISION_TAB.LOG":"decision-tab"}
    if filename in kinds:return kinds[filename]
    raise RuntimeError("unknown-selected-cold-format")

SHA = 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664'
MAX_ARCHIVE = 512*1024*1024


def exact(stream, size):
    chunks=[]
    while size:
        chunk=stream.read(min(size,65536))
        if not chunk: raise RuntimeError('private-transfer-refused')
        chunks.append(chunk);size-=len(chunk)
    return b''.join(chunks)


def emit(scan, stage, result):
    # No numbers, paths, digests, values, exception text or category counts.
    raw=('ARM '+stage+' '+result+'\n').encode()
    scan.scan(raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()


def main():
    if socket.gethostname()!='woowbk-dev-d' or os.geteuid()==0:
        return 1
    def deadline(*_):raise RuntimeError('private-owner-deadline')
    signal.signal(signal.SIGALRM,deadline)
    signal.setitimer(signal.ITIMER_REAL,180)
    stage='TRANSFER'
    scan=None
    try:
        key_size=struct.unpack('!I',exact(sys.stdin.buffer,4))[0]
        if not 1<=key_size<=1024:raise RuntimeError('key-refused')
        key=exact(sys.stdin.buffer,key_size)
        text=key.decode('ascii')
        if not text or '\n' in text or '\r' in text:raise RuntimeError('key-refused')
        scan=PartialScan([key])
        keys=hasecuretar.Keys(text)
        archive_size=struct.unpack('!Q',exact(sys.stdin.buffer,8))[0]
        if not 0<archive_size<=MAX_ARCHIVE:raise RuntimeError('size-refused')
        with tempfile.TemporaryDirectory(prefix='woowbk-arm-cold-private-',dir=Path.home()) as directory:
            root=Path(directory);root.chmod(0o700)
            source=root/'encrypted-source.tar'
            fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            digest=hashlib.sha256()
            with os.fdopen(fd,'wb') as output:
                left=archive_size
                while left:
                    chunk=exact(sys.stdin.buffer,min(left,65536))
                    output.write(chunk);digest.update(chunk);left-=len(chunk)
                output.flush();os.fsync(output.fileno())
            if sys.stdin.buffer.read(1) or digest.hexdigest()!=SHA:raise RuntimeError('archive-binding-refused')
            emit(scan,'TRANSFER','PASSED')
            stage='AUTHENTICATE'
            with source_binding(source,'emqx',hacommon.semver('5.8.9'),SHA,keys=keys) as binding:
                slug=binding['addon_member']('woow-emqx')
                stage='CAPTURE'
                with binding['open'](slug) as stream:
                    with capture(stream,root) as (spool,expanded,_):
                        stage='CAPTURE'
                        if expanded!=117760000:raise RuntimeError('unexpected-expanded-size')
                        stage='TAR'
                        report=habackup.Report()
                        for entry in habackup.iter_entries(spool,report=report,addon=True):
                            if entry.kind not in ('dir','file'):raise RuntimeError('unsafe-tar')
                        if not report.complete:raise RuntimeError('incomplete-tar')
                        spool.seek(0)
                        stage='SELECT'
                        cold={};all_files=0;mnesia_files=0;mnesia_bytes=0
                        with tarfile.open(fileobj=spool,mode='r:') as archive:
                            for member in archive:
                                if member.isdir():continue
                                all_files+=1
                                name=habackup.normalize(member.name)
                                staged=any(name==ha_emqx.DATA+'/'+item or name.startswith(ha_emqx.DATA+'/'+item+'/') for item in ha_emqx.STAGED)
                                if not staged or not name.startswith(ha_emqx.DATA+'/mnesia/'):continue
                                if not member.isfile() or not 0<member.size<=8388608:raise RuntimeError('selected-member-refused')
                                mnesia_files+=1;mnesia_bytes+=member.size
                                kind=cold_kind(name,member.size)
                                with archive.extractfile(member) as body:
                                    raw=body.read(member.size+1)
                                if len(raw)!=member.size or name in cold:
                                    raise RuntimeError('selected-cold-receipt-refused')
                                cold[name]=(raw,kind)
                        # No verified receipt binds every tar member count for this schema-only case.
                        # Schema scope binds strict EOF plus exact selected Mnesia metadata.
                        stage='MNESIAFILES'
                        if mnesia_files!=28:raise RuntimeError('inventory-refused')
                        stage='MNESIABYTES'
                        if mnesia_bytes!=57502:raise RuntimeError('inventory-refused')
                        stage='SCHEMACOUNT'
                        if sum(kind=='schema-dat' for raw,kind in cold.values())!=1:
                            raise RuntimeError('inventory-refused')
                        emit(scan,'SELECT','PASSED')
                        if globals().get('CONFIGURATION_ONLY',False):
                            from emqx_native_hocon import native_hocon, native_hocon_diagnostic
                            from emqx_semantic_readers import read_hocon
                            from emqx_source_consumer import addon_values
                            stage='CONFIGURATION'
                            spool.seek(0)
                            config_count=0
                            with tarfile.open(fileobj=spool,mode='r:') as archive:
                                for member in archive:
                                    if not member.isfile():continue
                                    name=habackup.normalize(member.name)
                                    if name not in ('addon.json',ha_emqx.DATA+'/configs/cluster.hocon'):
                                        continue
                                    if not 0<member.size<=8388608:raise RuntimeError('config-size-refused')
                                    with archive.extractfile(member) as content:
                                        raw=content.read(member.size+1)
                                    if len(raw)!=member.size:raise RuntimeError('config-eof-refused')
                                    if name=='addon.json':
                                        stage='ADDON_METADATA'
                                        values=addon_values(raw)
                                    else:
                                        stage='HOCON_NATIVE'
                                        try:encoded=native_hocon(raw)
                                        except Exception:
                                            stage='HOCON_'+native_hocon_diagnostic(raw).upper()
                                            raise RuntimeError('private-hocon-refused') from None
                                        stage='HOCON_CONTRACT'
                                        try:values=read_hocon(raw,lambda source:encoded).values
                                        except Exception:
                                            # Classification only; complete semantic refusal remains.
                                            pending=[json.loads(encoded).get('document')]
                                            while pending:
                                                item=pending.pop()
                                                if type(item) is dict:
                                                    if item.get('type')=='file':
                                                        stage='HOCON_FILE_AUTHORIZER'
                                                        dependency=item.get('path')
                                                        if dependency is None:stage='HOCON_IMPLICIT_ACL'
                                                        elif dependency in ('etc/acl.conf','/opt/emqx/etc/acl.conf'):
                                                            stage='HOCON_VENDOR_ACL'
                                                        elif dependency in ('data/authz/acl.conf','/opt/emqx/data/authz/acl.conf'):
                                                            stage='HOCON_STAGED_ACL'
                                                        break
                                                    pending.extend(item.values())
                                                elif type(item) is list:pending.extend(item)
                                            raise RuntimeError('private-hocon-contract-refused') from None
                                    scan.add(values)
                                    config_count+=1
                            if config_count!=2:raise RuntimeError('config-inventory-refused')
                            # Deliberately partial: no target acknowledgement or replay authorization.
                            emit(scan,'CONFIGURATION','PASSED')
                            return 0
                        receipts={name:{'kind':kind,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                                  for name,(raw,kind) in cold.items()}
                        def decode(raw,kind):
                            try:return native_cold_history(raw,kind)
                            except Exception:
                                diagnosis=native_cold_diagnostic(raw,kind)
                                emit(scan,'NATIVE_'+kind.replace('-','_').upper()+'_'+diagnosis['phase'],diagnosis['result'])
                                raise RuntimeError('private-native-refused') from None
                        inventory=HistoryInventory(receipts,decode)
                        # Schema first, then every other exactly inventoried used file.
                        names=sorted(cold,key=lambda name:(cold[name][1]!='schema-dat',name))
                        for name in names:
                            stage='HISTORY_'+cold[name][1].replace('-','_').upper()
                            inventory.consume(name,cold[name][0])
                        stage='REGISTER'
                        values=inventory.finish().values
                        scan.add(values)
                        for value in values:
                            try:scan.scan(value)
                            except RuntimeError:continue
                            raise RuntimeError('history-value-not-registered')
                        # Full selected history coverage only: not final rows,
                        # full HA config capture, target acknowledgement or restore.
            stage='CAPTURE'
        emit(scan,'HISTORY','PASSED')
        return 0
    except BaseException:
        # Fixed failure only. If captured short values collide, refuse output;
        # host sees nonzero and reports only the fixed transport failure code.
        if scan is not None:
            try:emit(scan,stage,'REFUSED')
            except BaseException:pass
        return 1


if __name__=='__main__':
    try:result=main()
    finally:signal.setitimer(signal.ITIMER_REAL,0)
    raise SystemExit(result)
