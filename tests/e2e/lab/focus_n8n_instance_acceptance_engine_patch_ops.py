"""Replace a few NAMED installed engine files of dev-c by exact reviewed bytes, with a strict way back.

Runs INSIDE the isolated lab device as root. Every file must currently be exactly its reviewed OLD version; private exact
copies (bytes, owner, mode, mtime) are written by the existing Store BEFORE the first replacement; each NEW hash is recorded
as allowed before its write; the native jobs and engine locks are held and no job may be active. Only *.py files of the fixed
engine library and the fixed helper can be named. No installer, package, catalog, service, SQL or image action.
"""
import base64
import json
import os
from pathlib import Path
import re

import focus_n8n_instance_acceptance_ops as c
import focus_n8n_instance_acceptance_safeties as safety

PARENT = '/var/lib/woowtech-backup/focus-n8n-engine-patch'
LIB = Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')
HELPER = Path('/usr/local/libexec/woowtech-cockpit-backup')
JOBS = Path('/var/lib/woowtech-backup/jobs')
HELPER_KEY = '../woowtech-cockpit-backup'
MAX_FILES = 8
MAX_BYTES = 1024**2
MAX_REQUEST = 2 * 1024**2
NAME = re.compile(r'[a-z][a-z0-9_]{0,63}\.py\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def target(rel):
    if rel == HELPER_KEY:
        return HELPER
    if not isinstance(rel, str) or not NAME.fullmatch(rel):
        raise ValueError('fixed-engine-patch-name')
    return LIB / rel


def no_active_jobs():
    for p in JOBS.glob('j*.json'):
        if json.loads(c.read_regular(p, 8 * 1024**2)[0]).get('state') in ('queued', 'running'):
            raise ValueError('fixed-engine-patch-active-job')


def plan(q):
    files = q.get('files')
    if not isinstance(files, dict) or not 0 < len(files) <= MAX_FILES:
        raise ValueError('fixed-engine-patch-files')
    wanted, total = {}, 0
    for rel, spec in sorted(files.items()):
        if not isinstance(spec, dict) or set(spec) != {'old_sha256', 'new_sha256', 'new_b64'}:
            raise ValueError('fixed-engine-patch-spec')
        old, new = spec['old_sha256'], spec['new_sha256']
        if not (isinstance(old, str) and isinstance(new, str) and SHA.fullmatch(old) and SHA.fullmatch(new)) or old == new:
            raise ValueError('fixed-engine-patch-hash')
        data = base64.b64decode(spec['new_b64'], validate=True)
        total += len(data)
        if len(data) > MAX_BYTES or total > MAX_BYTES or c.digest(data) != new:
            raise ValueError('fixed-engine-patch-bytes')
        wanted[str(target(rel))] = {'rel': rel, 'old': old, 'new': new, 'data': data}
    return wanted


def apply(q):
    name, wanted = q['case'], plan(q)
    with safety.native_locks():
        no_active_jobs()
        paths = sorted(wanted)
        for path in paths:
            _, meta = c.read_regular(path, MAX_BYTES)
            if meta['sha256'] != wanted[path]['old'] or meta['uid'] != os.geteuid():
                raise ValueError('fixed-engine-patch-not-the-reviewed-old-file')
        store = c.Store(name, parent=PARENT, create=True)   # one-shot: an existing journal root refuses
        store.capture(paths, limit=MAX_BYTES, copy_mtime=True)
        store.state['patch'] = {'applied': False, 'restored': False,
                                'files': {p: {'rel': v['rel'], 'old': v['old'], 'new': v['new']} for p, v in wanted.items()}}
        store.save()
        for path in paths:
            store.replace(path, wanted[path]['data'])
        for path in paths:
            if c.read_regular(path, MAX_BYTES)[1]['sha256'] != wanted[path]['new']:
                raise ValueError('fixed-engine-patch-readback')
        store.state['patch']['applied'] = True
        store.save()
    return {'applied': sorted(v['rel'] for v in wanted.values()),
            'old': {v['rel']: v['old'] for v in wanted.values()}, 'new': {v['rel']: v['new'] for v in wanted.values()}}


def restore(q):
    store = c.Store(q['case'], parent=PARENT)
    patch = store.state.get('patch')
    if not isinstance(patch, dict) or not isinstance(store.state.get('original'), dict):
        raise ValueError('fixed-engine-patch-no-journal')
    with safety.native_locks():
        no_active_jobs()
        paths = sorted(patch['files'])
        for path in paths:
            if c.read_regular(path, MAX_BYTES)[1]['sha256'] not in store.state['allowed'][path]:
                raise ValueError('fixed-engine-patch-foreign-change')
        store.restore(paths)
        for path in paths:
            now = c.read_regular(path, MAX_BYTES)[1]
            original = store.state['original'][path]
            if any(now[k] != original[k] for k in ('sha256', 'mode', 'uid', 'gid', 'mtime_ns')):
                raise ValueError('fixed-engine-patch-restore-mismatch')
        store.state['patch']['restored'] = True
        store.save()
    return {'restored': sorted(v['rel'] for v in patch['files'].values())}


def status(q):
    store = c.Store(q['case'], parent=PARENT)
    patch = store.state.get('patch') or {}
    return {'journal': bool(patch), 'applied': patch.get('applied'), 'restored': patch.get('restored'),
            'files': {v['rel']: c.read_regular(p, MAX_BYTES)[1]['sha256'] for p, v in (patch.get('files') or {}).items()}}


def dispatch(q):
    if os.geteuid() != 0 or not c.BASE.fullmatch(q.get('case', '')):
        raise ValueError('fixed-engine-patch-case-root')
    if q.get('op') == 'engine-apply':
        return apply(q)
    if q.get('op') == 'engine-restore':
        return restore(q)
    if q.get('op') == 'engine-status':
        return status(q)
    raise ValueError('fixed-engine-patch-operation')
