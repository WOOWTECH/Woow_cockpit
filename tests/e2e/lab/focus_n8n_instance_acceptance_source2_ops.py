"""Source2 per-file os.replace transaction, preserving merged library directory.

No live-directory rename/exchange/fallback. Source1 artifacts remain read-only.
Every live write/delete has prior absence/metadata + desired metadata recorded
before publication, with private fixed stage/class/errno and exact CAS return.
"""
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode=True
sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-source2-pycache'
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_source_ops as base


def checked_tree(path):
    result=base.tree(path)
    if any(os.listxattr(p) for p in [Path(path),*Path(path).rglob('*')]):
        raise ValueError('fixed-source2-foreign-xattrs')
    return result


def checked_file(path):
    result=common.read_regular(path)[1]
    if os.listxattr(path):raise ValueError('fixed-source2-foreign-xattrs')
    return result


def file_meta(meta):return {k:v for k,v in meta.items() if k!='bytes'}


class Transaction2:
    def __init__(self,name,*,lib=base.LIB,helper=base.HELPER,parent=base.CASE_ROOT,trusted_root=Path('/')):
        if not common.BASE.fullmatch(name):raise ValueError('fixed-source2-case')
        self.name=name;self.lib=Path(lib);self.helper=Path(helper);self.trusted_root=Path(trusted_root)
        self.path=Path(parent)/(name+'-source-attempt2')
        self.libown=self.lib.parent/('.focus-n8n-source-attempt2-'+name)
        self.helpown=self.helper.parent/('.focus-n8n-source-attempt2-'+name)
        if self.helpown==self.libown:self.helpown=self.helper.parent/('.focus-n8n-source-attempt2-helper-'+name)
        self.newlib=self.libown/'candidate';self.newhelper=self.helpown/'candidate-helper'
        self.source1=base.Transaction(name,lib=lib,helper=helper,parent=parent)
        self.state=json.loads(common.read_regular(self.path/'state.json',8*1024**2)[0]) if self.path.exists() else {}

    def save(self):common.atomic(self.path/'state.json',json.dumps(self.state).encode())

    def step(self,name,fn):
        row={'step':name,'done':False,'error_class':None,'errno':None}
        self.state['pending_step']=name;self.state.setdefault('steps',[]).append(row)
        if len(self.state['steps'])>2048:raise ValueError('fixed-source2-step-bound')
        self.save()
        try:
            value=fn();row['done']=True;self.state['pending_step']=None;self.save();return value
        except BaseException as error:
            row.update(error_class=type(error).__name__,errno=error.errno if isinstance(error,OSError) else None,
                fixed_code=str(error) if isinstance(error,ValueError) and re.fullmatch(r'fixed-source2-[a-z0-9-]{1,80}',str(error)) else None)
            self.state['last_error']=dict(row);self.save();raise

    def source1_fingerprint(self):
        old=self.source1
        if not old.state:raise ValueError('fixed-source2-source1-missing')
        if checked_tree(old.path/'prior-library')!=old.state['private_tree']:raise ValueError('fixed-source2-source1-copy-changed')
        if common.read_regular(old.path/'prior-helper')[1]['sha256']!=old.state['helper']['sha256']:
            raise ValueError('fixed-source2-source1-helper-copy-changed')
        if checked_tree(old.stage)!=old.state['candidate'] or checked_file(old.hstage)!=old.state['candidate_helper']:
            raise ValueError('fixed-source2-source1-stage-changed')
        return common.digest(json.dumps({'private':checked_tree(old.path),'stage':checked_tree(old.stage),
                       'helper_stage':checked_file(old.hstage)},sort_keys=True).encode())

    def verify_copies(self):
        if self.state.get('copy_complete') is not True:raise ValueError('fixed-source2-incomplete-copy')
        if checked_tree(self.path/'private-library')!=self.state['private_tree']:
            raise ValueError('fixed-source2-private-tree-changed')
        if checked_file(self.path/'private-helper')!=self.state['private_helper']:
            raise ValueError('fixed-source2-private-helper-changed')
        if self.source1_fingerprint()!=self.state['source1_fingerprint']:
            raise ValueError('fixed-source2-source1-artifacts-changed')
        if self.state.get('prepared') and (checked_tree(self.newlib)!=self.state['candidate']
                  or checked_file(self.newhelper)!=self.state['candidate_helper']):
            raise ValueError('fixed-source2-candidate-copy-changed')

    def prepare(self,payload,durable):
        files,helper=base.decode_payload(payload)
        if self.state or any(os.path.lexists(p) for p in (self.path,self.libown,self.helpown)):
            raise ValueError('fixed-source2-never-replay-or-overwrite')
        original=checked_tree(self.lib);hmeta=checked_file(self.helper)
        if original!=self.source1.state['original'] or hmeta!=self.source1.state['helper']:
            raise ValueError('fixed-source2-not-exact-source1-original')
        fingerprint=self.source1_fingerprint()
        for p in (self.lib,self.helper.parent,self.lib.parent,self.path.parent):
            for parent in (p,*p.parents):
                st=parent.lstat()
                if not __import__('stat').S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022:
                    raise ValueError('fixed-source2-untrusted-parent')
                if parent==self.trusted_root:break
        for meta in list(original['directories'].values())+list(original['files'].values())+[hmeta]:
            if meta['uid']!=os.geteuid() or meta['mode']&0o022:raise ValueError('fixed-source2-prior-metadata')
        self.path.mkdir(mode=0o700)
        self.state={'version':3,'original':original,'helper':hmeta,'source1_fingerprint':fingerprint,
                    'copy_complete':False,'prepared':False,'complete':False,'restored':False,'mutations':{},
                    'temporary':{},'new_directories':{},'durable_before':durable,'steps':[],'pending_step':None}
        self.save()
        self.step('copy_prior_library',lambda:base.copy_tree(self.lib,self.path/'private-library',original,private=True))
        self.step('copy_prior_helper',lambda:common.atomic(self.path/'private-helper',common.read_regular(self.helper)[0]))
        self.state['private_tree']=checked_tree(self.path/'private-library')
        self.state['private_helper']=checked_file(self.path/'private-helper');self.state['copy_complete']=True;self.save()
        def stage():
            self.libown.mkdir(mode=0o700);self.helpown.mkdir(mode=0o700)
            self.newlib.mkdir(mode=0o755);os.chmod(self.newlib,0o755)
            (self.newlib/'woowbackup').mkdir(mode=0o755);(self.newlib/'woowbackup/adapters').mkdir(mode=0o755)
            for name,data in files.items():common.atomic(self.newlib/name,data,mode=0o644)
            common.atomic(self.newhelper,helper,mode=0o755)
        self.step('stage_candidate',stage)
        self.step('probe_candidate_before_publish',lambda:base.tool_probe(self.newlib))
        self.state['candidate']=checked_tree(self.newlib);self.state['candidate_helper']=checked_file(self.newhelper)
        # Only trusted prior managed .py absent from this exact desired manifest
        # may be removed; all opaque/non-Python/cache files are preserved.
        self.state['stale']=[p for p in original['files'] if p not in files and
                            re.fullmatch(r'woowbackup/(?:adapters/)?[A-Za-z_][A-Za-z0-9_]*\.py',p)]
        unknown=[p for p in original['files'] if p.startswith('woowbackup/') and p.endswith('.py')
                 and '__pycache__' not in Path(p).parts and p not in files and p not in self.state['stale']]
        if unknown:raise ValueError('fixed-source2-unknown-python-preserved-stop')
        self.state['prepared']=True;self.save()
        for parent in {self.path.parent,self.libown.parent,self.helpown.parent}:
            fd=os.open(parent,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        self.validate_live()

    def validate_live(self):
        self.verify_copies();actual=checked_tree(self.lib);prior=self.state['original'];mut=self.state['mutations']
        allowed=set(prior['files'])|{p for p in mut if p!='helper'}
        if set(actual['files'])-allowed:raise ValueError('fixed-source2-foreign-added-file')
        for name in allowed:
            before=prior['files'].get(name);now=actual['files'].get(name);record=mut.get(name)
            if now==before:continue
            if not record or file_meta(now or {})!=file_meta(record['after'] or {}):
                raise ValueError('fixed-source2-foreign-source-or-metadata')
        dirs=prior['directories'];extra=self.state['new_directories']
        if set(actual['directories'])-set(dirs)-set(extra):raise ValueError('fixed-source2-foreign-directory')
        affected=set()
        for name in mut:
            if name=='helper':continue
            affected.update(str(p) for p in Path(name).parents)
        affected.update(str(p) for name in extra for p in Path(name).parents)
        for name,meta in dirs.items():
            now=actual['directories'].get(name)
            if now is None or any(now[k]!=meta[k] for k in ('mode','uid','gid')):
                raise ValueError('fixed-source2-foreign-directory-metadata')
            if name not in affected and now['mtime_ns']!=meta['mtime_ns']:
                raise ValueError('fixed-source2-foreign-directory-time')
        for name,meta in extra.items():
            now=actual['directories'].get(name)
            if now and any(now[k]!=meta[k] for k in ('mode','uid','gid')):
                raise ValueError('fixed-source2-owned-directory-changed')
        helper=checked_file(self.helper);record=mut.get('helper')
        if helper!=self.state['helper'] and (not record or helper!=record['after']):
            raise ValueError('fixed-source2-foreign-helper')

    def temporary_cleanup(self):
        self.state['unproven_temporaries_retained']=[]
        for key,row in self.state['temporary'].items():
            p=(self.helpown if row['helper'] else self.libown)/key
            if not os.path.lexists(p):continue
            st=p.lstat()
            if row.get('identity')!=[st.st_dev,st.st_ino] or st.st_uid!=os.geteuid() or not __import__('stat').S_ISREG(st.st_mode):
                # A kill between O_EXCL and saving inode identity leaves an
                # unproven file OUTSIDE the live library. Retain it; it must not
                # prevent returning independently verified live source files.
                self.state['unproven_temporaries_retained'].append(key);self.save();continue
            self.step('remove_owned_temporary',p.unlink)

    def replace_bytes(self,name,data,meta):
        self.validate_live()
        live=self.helper if name=='helper' else self.lib/name
        if not live.parent.is_dir():
            for directory in reversed([p for p in live.parents if p!=self.lib and self.lib in p.parents and not p.exists()]):
                rel=str(directory.relative_to(self.lib))
                self.state['new_directories'][rel]={'mode':0o755,'uid':os.geteuid(),'gid':os.getegid()};self.save()
                self.step('create_owned_directory',lambda d=directory:d.mkdir(mode=0o755))
        key='pending-'+str(len(self.state['temporary']))
        temporary=(self.helpown if name=='helper' else self.libown)/key
        if os.path.lexists(temporary):raise ValueError('fixed-source2-temporary-exists')
        self.state['temporary'][key]={'helper':name=='helper','prior_absent':True,'identity':None};self.save()
        def write():
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            st=os.fstat(fd);self.state['temporary'][key]['identity']=[st.st_dev,st.st_ino];self.save()
            with os.fdopen(fd,'wb') as out:
                out.write(data);out.flush();os.fchmod(out.fileno(),meta['mode']);os.fchown(out.fileno(),meta['uid'],meta['gid'])
                os.utime(out.fileno(),ns=(os.fstat(out.fileno()).st_atime_ns,meta['mtime_ns']));os.fsync(out.fileno())
        self.step('write_owned_temporary',write)
        if checked_file(temporary)!=file_meta(meta):raise ValueError('fixed-source2-temporary-hash')
        self.validate_live()
        if temporary.parent.stat().st_dev!=live.parent.stat().st_dev:raise ValueError('fixed-source2-cross-device')
        self.step('replace_live_file',lambda:os.replace(temporary,live))
        fd=os.open(live.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def publish(self,payload):
        if not self.state.get('prepared') or self.state.get('publish_started'):raise ValueError('fixed-source2-publish-not-replayable')
        self.validate_live();self.state['publish_started']=True;self.save()
        names=sorted(n for n in payload['files'] if n!='VERSION')+self.state['stale']+['VERSION','helper']
        for name in names:
            self.validate_live()
            before=self.state['helper'] if name=='helper' else self.state['original']['files'].get(name)
            after=self.state['candidate_helper'] if name=='helper' else self.state['candidate']['files'].get(name)
            self.state['mutations'][name]={'prior':before,'prior_absent':before is None,'after':after};self.save()
            if after is None:
                self.step('delete_trusted_stale_python',(self.lib/name).unlink)
            else:
                source=self.newhelper if name=='helper' else self.newlib/name
                self.replace_bytes(name,common.read_regular(source,base.MAX_BYTES)[0],after)
        self.validate_live()
        actual={n:checked_file(self.helper if n=='helper' else self.lib/n)['sha256'] for n in payload['sha256']}
        if actual!=payload['sha256']:raise ValueError('fixed-source2-published-hashes')
        self.step('probe_installed_candidate',lambda:base.tool_probe(self.lib))
        self.state['published_tree']=checked_tree(self.lib);self.state['complete']=True;self.save()

    def restore(self):
        self.validate_live()  # ALL source/helper/opaque metadata checked before any return write.
        self.temporary_cleanup()
        order=[(n,r) for n,r in reversed(list(self.state['mutations'].items())) if n not in ('VERSION','helper')]
        order += [(n,self.state['mutations'][n]) for n in ('VERSION','helper') if n in self.state['mutations']]
        for name,row in order:
            self.validate_live();live=self.helper if name=='helper' else self.lib/name
            now=checked_file(live) if os.path.lexists(live) else None;before=row['prior']
            if now==file_meta(before or {}) or now is None and before is None:continue
            if before is None:
                if now!=file_meta(row['after']):raise ValueError('fixed-source2-new-file-foreign')
                self.step('delete_only_owned_new_file',live.unlink)
            else:
                source=self.path/'private-helper' if name=='helper' else self.path/'private-library'/name
                self.replace_bytes(name,common.read_regular(source,base.MAX_BYTES)[0],before)
        for name in sorted(self.state['new_directories'],key=lambda p:len(Path(p).parts),reverse=True):
            p=self.lib/name
            if p.exists():self.step('remove_only_owned_empty_directory',p.rmdir)
        for name,meta in sorted(self.state['original']['directories'].items(),key=lambda r:len(Path(r[0]).parts),reverse=True):
            p=self.lib/name
            if p.stat().st_mtime_ns!=meta['mtime_ns']:
                self.step('restore_original_directory_time',lambda p=p,m=meta:os.utime(p,ns=(p.stat().st_atime_ns,m['mtime_ns'])))
        if checked_tree(self.lib)!=self.state['original'] or checked_file(self.helper)!=self.state['helper']:
            raise ValueError('fixed-source2-exact-return')
        self.state['restored']=True;self.state['complete']=False;self.save()


def dispatch(q):
    if os.geteuid()!=0:raise ValueError('fixed-source2-root')
    tx=Transaction2(q['case'])
    with base.engine_locks():
        before=common.inventory()
        if before['active_jobs'] or before['running'] or any(before['units'][u]['ActiveState']!='inactive' for u in common.UNITS):
            raise ValueError('fixed-source2-not-quiescent')
        if before['protected']!=q['protected']:raise ValueError('fixed-source2-protected-baseline')
        try:
            if q['phase']=='source2-install':tx.prepare(q['payload'],before);tx.publish(q['payload'])
            elif q['phase']=='source2-recover':tx.restore()
            else:raise ValueError('fixed-source2-phase')
            after=common.inventory();tx.state['durable_after']=after;tx.save()
            for key in ('catalog','files','protected','units','timer','volumes','images','running','active_jobs','retention_sha256'):
                if before[key]!=after[key]:raise ValueError('fixed-source2-durable-changed')
            tx.verify_copies()
            source=tx.state['candidate']['files'] if tx.state['complete'] else tx.state['original']['files']
            return {'ok':True,'source_installed':tx.state['complete'],'source_restored':tx.state['restored'],
                'source_sha256':{k:checked_file(tx.lib/k)['sha256'] for k in source}|
                    {'helper':checked_file(tx.helper)['sha256']},'durable_equal':True,'source1_unchanged':True,
                'private_copies_retained':True,'unproven_temporary_count':len(tx.state.get('unproven_temporaries_retained',[]))}
        except BaseException as error:
            fixed=str(error) if isinstance(error,ValueError) and re.fullmatch(r'fixed-source2-[a-z0-9-]{1,80}',str(error)) else None
            if tx.state:
                tx.state['failure']={'stage':tx.state.get('pending_step') or 'validate_fixed_state',
                    'error_class':type(error).__name__,'errno':error.errno if isinstance(error,OSError) else None,'fixed_code':fixed};tx.save()
            error._source2_stage=tx.state.get('pending_step') or 'validate_fixed_state';raise


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(96*1024**2+1)
        if len(raw)>96*1024**2:raise ValueError('fixed-source2-request-bound')
        print(json.dumps(dispatch(json.loads(raw))))
    except Exception as error:
        print(json.dumps({'ok':False,'private_error_class':type(error).__name__,
            'private_errno':error.errno if isinstance(error,OSError) else None,
            'private_stage':getattr(error,'_source2_stage','request_preconditions'),
            'private_fixed_code':str(error) if isinstance(error,ValueError) and re.fullmatch(r'fixed-source2-[a-z0-9-]{1,80}',str(error)) else None}))
        raise SystemExit(1)
