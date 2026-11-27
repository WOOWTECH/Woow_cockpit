#!/usr/bin/env python3
"""Offline by default. Leased replacement of the few engine files that DIFFER between two frozen product checkouts, on stopped dev-c.

The old checkout is what the device runs now (the installed engine must equal it exactly, file by file); the new checkout is the
product commit the next phases are frozen to. Only existing files are replaced, never added or removed. The device side
(focus_n8n_instance_acceptance_engine_patch_ops) keeps private exact copies first and has a strict restore. No installer, package,
catalog, service, SQL or image action.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import focus_n8n_instance_acceptance_run as run
import focus_n8n_instance_acceptance_engine_patch_ops as device

PHASES = ('engine-patch', 'engine-patch-restore')
CASE = 'n8n-engine-patch'
RECEIPT_NAME = 'focus_n8n_instance_acceptance.engine-patch.json'


def dependencies():
    text = "import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-n8n-engine-patch-pycache'\n"
    for name in ('focus_n8n_instance_acceptance_ops', 'focus_n8n_instance_acceptance_safeties',
                 'focus_n8n_instance_acceptance_engine_patch_ops'):
        raw = (HERE / (name + '.py')).read_text()
        text += ("_m=types.ModuleType(" + repr(name) + ");sys.modules[_m.__name__]=_m\n"
                 "exec(compile(" + repr(raw) + ",'<fixed engine patch dependencies>','exec'),_m.__dict__)\n")
    return text


ENTRY = '''
import json,os,re
q={}
try:
 q=json.loads(sys.stdin.buffer.read(2*1024*1024+1))
 result=sys.modules['focus_n8n_instance_acceptance_engine_patch_ops'].dispatch(q)
 print(json.dumps({'ok':True,'result':result}))
except Exception as e:
 print(json.dumps({'ok':False,'private_stage':q.get('op'),'private_error_class':type(e).__name__,
  'private_errno':e.errno if isinstance(e,OSError) else None,
  'private_fixed_code':str(e) if isinstance(e,ValueError) and re.fullmatch('fixed-engine-patch-[a-z-]+',str(e)) else None}))
 raise SystemExit(1)
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def engine_files(source):
    base = Path(source) / 'backup-engine'
    files = {str(p.relative_to(base / 'woowbackup')): p.read_bytes()
             for p in (base / 'woowbackup').rglob('*.py') if '__pycache__' not in p.parts}
    files[device.HELPER_KEY] = (base / 'woowtech-cockpit-backup').read_bytes()
    return files


def expected_hashes(files):
    """The shape of ops.engine_hashes() on the device and of Controller.frozen_engine()."""
    return {rel: sha(data) for rel, data in files.items()}


def changed(old_source, new_source):
    old, new = engine_files(old_source), engine_files(new_source)
    if set(old) != set(new):
        raise ValueError('the engine file sets differ; this tool only replaces existing files')
    names = sorted(rel for rel in old if old[rel] != new[rel])
    if not 0 < len(names) <= device.MAX_FILES:
        raise ValueError('between 1 and %d changed engine files are required' % device.MAX_FILES)
    return old, new, names


def request_files(old, new, names):
    return {rel: {'old_sha256': sha(old[rel]), 'new_sha256': sha(new[rel]),
                  'new_b64': base64.b64encode(new[rel]).decode()} for rel in names}


def validate(lease, phase, *, driver, source_commit, old_commit, names, now):
    if (lease.get('case') != CASE or phase not in PHASES or not set(lease.get('phases', [])) <= set(PHASES)
            or lease.get('old_source_commit') != old_commit or lease.get('files') != names
            or lease.get('bounds') != run.BOUNDS or lease.get('image_policy') != 'retain-for-case'):
        raise ValueError('exact engine-patch contract required')
    return run.validate_lease(dict(lease, case='n8n-instance-original'), phase, now=now,
                              driver_commit=driver, source_commit=source_commit)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--phase', choices=PHASES)
    for name in ('lease', 'source', 'old-source', 'receipt'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        compile(dependencies() + ENTRY, '<fixed engine patch program>', 'exec')
        print(json.dumps({'stage': 'engine_patch_offline', 'device_access': False}))
        return 0
    if not all((args.phase, args.lease, args.source, args.old_source, args.receipt)):
        parser.error('explicit phase/lease/source/old-source/receipt required')
    if args.receipt.name != RECEIPT_NAME:
        raise ValueError('separate engine-patch receipt required')
    lease = json.loads(args.lease.read_bytes())
    driver = run.git(run.REPO, 'rev-parse', 'HEAD')
    new_commit, old_commit = run.git(args.source, 'rev-parse', 'HEAD'), run.git(args.old_source, 'rev-parse', 'HEAD')
    if any(run.git(folder, 'status', '--porcelain') for folder in (run.REPO, args.source, args.old_source)):
        raise ValueError('clean exact driver and both product checkouts required')
    old, new, names = changed(args.old_source, args.source)
    validate(lease, args.phase, driver=driver, source_commit=new_commit, old_commit=old_commit, names=names, now=time.time())
    import ha_import_e2e as h
    h.DEVICE = run.plan.DEVICE
    h.require_isolated_device()
    fd = os.open(run.plan.LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.phase == PHASES[0] and args.receipt.exists():
            raise ValueError('new engine-patch receipt required')
        controller = run.Controller(SimpleNamespace(source=args.source, receipt=args.receipt), lease, h)
        controller.r['engine_patch'] = {'driver': driver, 'old_source': old_commit, 'new_source': new_commit, 'files': names}
        controller.save()

        def invoke(op, **kwargs):
            controller.r['engine_patch_operation'] = op
            controller.save()
            p = h.root('python3', '-B', '-I', '-c', dependencies() + ENTRY,
                       input=json.dumps(dict(kwargs, op=op, case=lease['name'])).encode(), timeout=180)
            try:
                reply = json.loads(p.stdout)
            except (ValueError, UnicodeError):
                reply = {'ok': False, 'private_error_class': 'InvalidFixedResponse', 'private_stage': op,
                         'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr), 'returncode': p.returncode}
            controller.r.setdefault('engine_patch_responses', []).append(reply)   # saved BEFORE any assertion
            controller.save()
            if p.returncode or reply.get('ok') is not True:
                raise RuntimeError('fixed engine patch operation refused')
            return reply['result']

        try:
            controller.resources()
            if args.phase == PHASES[0]:
                controller.require('installed_engine_is_the_reviewed_old_version',
                                   controller.op('hashes') == expected_hashes(old))
                invoke('engine-apply', files=request_files(old, new, names))
                ok = controller.op('hashes') == expected_hashes(new)
                controller.r['engine_patch_installed'] = bool(ok)
                controller.save()
                if not ok:
                    invoke('engine-restore')
                controller.require('installed_engine_is_the_new_frozen_product', ok)
            else:
                invoke('engine-restore')
                controller.require('installed_engine_is_the_reviewed_old_version',
                                   controller.op('hashes') == expected_hashes(old))
                controller.r['engine_patch_installed'] = False
                controller.save()
            print(json.dumps({'stage': 'engine_patch_complete', 'phase': args.phase, 'files': names,
                              'installed_new': args.phase == PHASES[0], 'services_or_data_changed': False}))
            return 0
        except Exception as error:  # noqa: BLE001
            controller.r['engine_patch_failure_class'] = type(error).__name__
            controller.save()
            print(json.dumps({'stage': 'engine_patch_failed', 'failure_class': type(error).__name__}))
            return 1
    finally:
        os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
