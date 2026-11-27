"""Two fixed vendor aliases only; separate journal, no image load/pull/removal.

Read all image fields privately; publish hashes, never Config/env/argv/stderr.
Store/tree/native_locks are the existing reviewed implementations.
"""
import json
import os
from pathlib import Path
import re
import sys

import focus_n8n_instance_acceptance_ops as c
import focus_n8n_instance_acceptance_source_ops as source
import focus_n8n_instance_acceptance_safeties as safety

PARENT='/var/lib/woowtech-backup/focus-n8n-image-references'
EXPECTED={
 'docker.io/n8nio/n8n:2.43.6':'c8d7cd6bf08e1837180b767d77903889e0f3f022accda90579f5e99ca2a2bdfb',
 'docker.io/n8nio/runners:2.43.6':'28c5a510d7624e5ce079d2204e4d8421bc96ced83ebc2e1717d6ee33a0ccc1bb',
 'docker.io/library/postgres:16.15-alpine':'4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873',
 'docker.io/valkey/valkey:8.1.11-alpine':'650ff8153447d257696648bc63a77522cf6e760145be45ce65a408a918229915'}
ALLOWED=dict(list(EXPECTED.items())[:2])
QUADLET_REFS={
 'n8n-postgres.container':list(EXPECTED)[2],'n8n-valkey.container':list(EXPECTED)[3],
 **{name+'.container':list(EXPECTED)[0] for name in ('n8n','n8n-worker','n8n-webhook')},
 **{name+'.container':list(EXPECTED)[1] for name in ('n8n-runners','n8n-worker-runners')}}
SOURCE_RECEIPT_SHA='99b20bc3053f2f10c3541ad2cd1a78b2e6482e68b28f72f04ee81fb3799523f2'
CAPTURE=None  # scoped by References._snapshot; readonly inventory creates no files


def canonical(value): return c.digest(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def resolve(ref):
    p=c.owner('podman','image','exists',ref,check=False)
    if p.returncode==1: return None
    if p.returncode!=0: raise ValueError('fixed-reference-exists-error')
    p=c.owner('podman','image','inspect',ref,'--format','{{.ID}}')
    value=p.stdout.decode().strip().removeprefix('sha256:')
    if not re.fullmatch('[0-9a-f]{64}',value): raise ValueError('fixed-reference-id-format')
    return value


def cache():
    ids=c.owner('podman','images','--no-trunc','--format','{{.ID}}').stdout.decode().split()
    ids=sorted(set(x.removeprefix('sha256:') for x in ids))
    if len(ids)>1024 or not all(re.fullmatch('[0-9a-f]{64}',x) for x in ids): raise ValueError('fixed-reference-cache-bound')
    result={}
    for config in ids:
        p=c.owner('podman','image','inspect','sha256:'+config)
        if CAPTURE is not None: CAPTURE(config,p.stdout)  # PRIVATE, before parse/comparison assertions
        if len(p.stdout)>2*1024**2: raise ValueError('fixed-reference-inspect-bound')
        rows=json.loads(p.stdout)
        if not isinstance(rows,list) or len(rows)!=1: raise ValueError('fixed-reference-inspect-format')
        row=rows[0]
        if str(row.get('Id') or row.get('ID') or '').removeprefix('sha256:')!=config:
            raise ValueError('fixed-reference-config-identity')
        def names(key):
            values=row.get(key) or []
            if not isinstance(values,list) or len(values)>256 or not all(isinstance(x,str) and 0<len(x)<=512 for x in values):
                raise ValueError('fixed-reference-alias-bound')
            return sorted(set(values))
        result[config]={'stable_fields_sha256':canonical({k:v for k,v in row.items() if k not in ('RepoTags','NamesHistory')}),
            'tags':names('RepoTags'),'history':names('NamesHistory'),
            'platform':[row.get('Os') or row.get('OS'),row.get('Architecture'),row.get('Variant') or '']}
    return result


def snapshot(name):
    inv=c.inventory()
    if inv['active_jobs'] or inv['running'] or any(inv['units'][u]['ActiveState']!='inactive' for u in c.UNITS):
        raise ValueError('fixed-reference-not-quiescent')
    original=c.Store(name).state['before']
    for key in ('catalog','entry','files','protected','units','timer','volumes','running','active_jobs','retention_sha256'):
        if inv[key]!=original[key]: raise ValueError('fixed-reference-original-baseline-changed')
    if set(inv['images'])!=set(original['images'])|set(ALLOWED.values()):
        raise ValueError('fixed-reference-retained-cache-baseline')
    sys.path.insert(0,str(source.LIB))
    from woowbackup.adapters.quadlet_postgres import parse_unit_file,last_value
    refs={}
    for filename in inv['entry']['quadlet']['files']:
        if filename.endswith('.container'):
            data=c.read_regular(c.QDIR+filename)[0]
            refs[filename]=last_value(parse_unit_file(data.decode()),'Container','Image')
    if refs!=QUADLET_REFS: raise ValueError('fixed-reference-original-quadlets')
    receipt=source.CASE_ROOT/(name+'-source-fullflow')/'state.json'
    receipt_raw,receipt_meta=c.read_regular(receipt)
    if receipt_meta['sha256']!=SOURCE_RECEIPT_SHA: raise ValueError('fixed-reference-source-receipt')
    installed=json.loads(receipt_raw)
    if (installed.get('complete') is not True or installed.get('restored') is not False or
            c.read_regular(source.LIB/'VERSION')[1]['sha256']!=installed['candidate']['files']['VERSION']['sha256'] or
            c.read_regular(source.HELPER)[1]['sha256']!=installed['candidate_helper']['sha256']):
        raise ValueError('fixed-reference-source-version-helper')
    preserved=safety.PreservedSafeties(c,name)
    preserved.verify(originals=False)
    backups=preserved.current()  # ONE streaming pass; never one pass per entry.
    if any(backups.get(p)!=m for p,m in preserved.store.state['before'].items()):
        raise ValueError('fixed-reference-preexisting-backups')
    stages={}
    for token in ('source-attempt2','source-fullflow'):
        for parent in (source.LIB.parent,source.HELPER.parent):
            path=parent/('.focus-n8n-'+token+'-'+name)
            stages[str(path)]=source.tree(path)
    for path in (Path(str(source.LIB)+'.'+name+'.new'),Path(str(source.HELPER)+'.'+name+'.new')):
        stages[str(path)]=source.tree(path) if path.is_dir() else c.read_regular(path)[1]
    return {'durables':inv,'backups':backups,'quadlet_refs':refs,'cache':cache(),
        'resolution':{ref:resolve(ref) for ref in EXPECTED},
        'source':{'library':source.tree(source.LIB),'helper':c.read_regular(source.HELPER)[1],
                  'private_cases':source.tree(source.CASE_ROOT),'stages':stages}}


class References:
    def __init__(self,name,*,parent=PARENT,read=snapshot):
        self.name=name;self.parent=parent;self.read=read;self.store=c.Store(name,parent=parent)
        if self.store.state and (self.store.state.get('kind')!='fixed-n8n-reference-v1' or
                self.store.state.get('expected')!=EXPECTED): raise ValueError('fixed-reference-foreign-journal')

    def capture_inspection(self,config,raw):
        s=self.store.state;number=s.get('inspection_next',0)
        if number>=128: raise ValueError('fixed-reference-private-capture-bound')
        filename=f'inspection-{number:04d}.json'
        record={'phase':s['inspection_phase'],'config':config,'file':filename,'sha256':c.digest(raw),
                'bytes':len(raw),'truncated':len(raw)>2*1024**2,'complete':False}
        s['inspection_next']=number+1;s.setdefault('inspections',[]).append(record);self.store.save()
        fd=os.open(self.store.path/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:
            f.write(raw[:2*1024**2]);f.flush();os.fsync(f.fileno())
        record['complete']=True;self.store.save()  # fsyncs parent after raw file publication

    def _snapshot(self,phase):
        global CAPTURE
        self.store.state['inspection_phase']=phase;self.store.save()
        previous=CAPTURE;CAPTURE=self.capture_inspection
        try:return self.read(self.name)
        finally:CAPTURE=previous

    def begin(self):
        if self.store.path.exists(): raise ValueError('fixed-reference-case-exists-reconcile-only')
        self.store=c.Store(self.name,parent=self.parent,create=True)
        self.store.state={'kind':'fixed-n8n-reference-v1','expected':EXPECTED,'snapshot_complete':False,
            'intents':{},'complete':False,'retain_for_case':True};self.store.save()
        before=self._snapshot('before'); planned={}
        for ref,expected in EXPECTED.items():
            found=before['resolution'][ref]
            if found is None and ref in ALLOWED: planned[ref]=expected
            elif found!=expected: raise ValueError('fixed-reference-foreign-or-missing-required')
            if expected not in before['cache']: raise ValueError('fixed-reference-cached-config-missing')
            platform=before['cache'][expected]['platform']
            if platform[:2]!=['linux','amd64'] or platform[2] not in ('','v1'):
                raise ValueError('fixed-reference-platform')
        self.store.state.update(before=before,planned=planned,snapshot_complete=True)
        self.store.save()  # entire before source/cache/catalog/backups BEFORE any tag intent/write
        return {'planned':planned,'before_sha256':canonical(before)}

    def validate(self,now):
        s=self.store.state;before=s['before']; applied=[]
        for key in ('durables','backups','quadlet_refs','source'):
            if now[key]!=before[key]: raise ValueError('fixed-reference-protected-state-changed')
        if set(now['cache'])!=set(before['cache']): raise ValueError('fixed-reference-cache-ids-changed')
        for ref,expected in EXPECTED.items():
            actual=now['resolution'][ref]
            if ref in s['intents'] and actual==expected: applied.append(ref)
            elif actual!=before['resolution'][ref]: raise ValueError('fixed-reference-foreign-ref')
        for config,old in before['cache'].items():
            current=now['cache'][config]
            if any(current[k]!=old[k] for k in ('stable_fields_sha256','platform')):
                raise ValueError('fixed-reference-cache-fields-changed')
            additions={ref for ref in applied if s['planned'][ref]==config}
            if set(current['tags'])!=set(old['tags'])|additions:
                raise ValueError('fixed-reference-unapproved-tag-delta')
            # Podman records added aliases in NamesHistory on versions which expose it.
            if not set(old['history'])<=set(current['history']) or set(current['history'])-set(old['history'])-additions:
                raise ValueError('fixed-reference-unapproved-history-delta')
        return applied

    def bind(self,ref):
        s=self.store.state
        if not s.get('snapshot_complete'): raise ValueError('fixed-reference-snapshot-incomplete')
        if ref not in s['planned'] or ref in s['intents']: raise ValueError('fixed-reference-bind-not-new')
        self.validate(self._snapshot('before-bind'))
        if resolve(ref) is not None: raise ValueError('fixed-reference-not-absent')
        s['intents'][ref]={'config':s['planned'][ref],'absent_observed':True,'done':False};self.store.save()
        # Native locks + exclusive lease serialize authorized image writers.
        # No overwrite/delete fallback, pull/load, source/service/container action.
        p=c.owner('podman','tag','sha256:'+s['planned'][ref],ref,check=False)
        if p.returncode: raise ValueError('fixed-reference-tag-command')
        applied=self.validate(self._snapshot('after-bind'))
        if ref not in applied: raise ValueError('fixed-reference-tag-not-observed')
        s['intents'][ref]['done']=True;self.store.save()
        return {'bound_reference':ref,'config':s['planned'][ref]}

    def reconcile(self):
        s=self.store.state
        if not s.get('snapshot_complete'): raise ValueError('fixed-reference-snapshot-incomplete')
        applied=self.validate(self._snapshot('reconcile'))
        s['complete']=set(applied)==set(s['planned'])
        s['observed_applied']=sorted(applied);self.store.save()
        return {'complete':s['complete'],'retain_for_case':True,'applied':sorted(applied),
            'before_sha256':canonical(s['before']),'approved_alias_delta':s['planned'],
            'protected_state_exact':True,'all_cache_fields_exact':True}


def dispatch(q):
    if os.geteuid()!=0 or not c.BASE.fullmatch(q['case']): raise ValueError('fixed-reference-case-root')
    obj=References(q['case'])
    try:
        with safety.native_locks():
            if q['op']=='reference-snapshot': return obj.begin()
            if q['op']=='reference-bind': return obj.bind(q['reference'])
            if q['op']=='reference-reconcile': return obj.reconcile()
            raise ValueError('fixed-reference-operation')
    except Exception as e:
        if obj.store.path.exists():
            obj.store.state['failure']={'operation':q['op'],'class':type(e).__name__,
                'errno':e.errno if isinstance(e,OSError) else None,
                'fixed_code':str(e) if isinstance(e,ValueError) and re.fullmatch('fixed-reference-[a-z-]+',str(e)) else None}
            obj.store.save()
        raise
