#!/usr/bin/env python3
"""Offline by default. Leased replacement of the few engine files that DIFFER between two frozen product checkouts, on a stopped
isolated lab device (dev-c or dev-d).

The old checkout is what the device runs now (the installed engine must equal it exactly, file by file); the new checkout is the
product commit the next phases are frozen to. Only existing files are replaced, never added or removed. The device side
(focus_engine_patch_ops) keeps private exact copies first and has a strict restore; this host side checks every engine hash before
and after and restores automatically when the result is not exactly the new checkout. No installer, package, catalog, service,
SQL or image action.
"""
import argparse
import base64
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
import focus_engine_patch_ops as device

DEVICES = {'c': ('woowbk-dev-c', '/tmp/woowbk-dev-c-mutation.lock'), 'd': ('woowbk-dev-d', '/tmp/woowbk-dev-d-mutation.lock')}
PHASES = ('engine-patch', 'engine-patch-restore')
CASE = 'engine-patch'
CASE_NAME = re.compile(r'woowbk_focus_n8n_[0-9a-f]{12}\Z')   # the shared Store insists on this form on any device
RECEIPT = re.compile(r'focus_engine_patch\.[a-z0-9-]{1,40}\.json\Z')
BOUNDS = {'host_available_mib': 1200, 'host_reserve_gib': 13, 'device_headroom_mib': 1900}
MEMORY = ("from pathlib import Path;import json;s=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines();"
          "used=sum(int(x.split()[1]) for x in s if x.startswith(('anon ','kernel ')));"
          "print(json.dumps(int(Path('/sys/fs/cgroup/memory.max').read_text())-used))")


def dependencies():
    text = "import sys,types;sys.dont_write_bytecode=True;sys.pycache_prefix='/nonexistent/woowbk-focus-engine-patch-pycache'\n"
    for name in ('focus_n8n_instance_acceptance_ops', 'focus_n8n_instance_acceptance_safeties', 'focus_engine_patch_ops'):
        raw = (HERE / (name + '.py')).read_text()
        text += ("_m=types.ModuleType(" + repr(name) + ");sys.modules[_m.__name__]=_m\n"
                 "exec(compile(" + repr(raw) + ",'<fixed engine patch dependencies>','exec'),_m.__dict__)\n")
    return text


ENTRY = '''
import json,os,re
q={}
try:
 q=json.loads(sys.stdin.buffer.read(2*1024*1024+1))
 result=sys.modules['focus_engine_patch_ops'].dispatch(q)
 print(json.dumps({'ok':True,'result':result}))
except Exception as e:
 print(json.dumps({'ok':False,'private_stage':q.get('op'),'private_error_class':type(e).__name__,
  'private_errno':e.errno if isinstance(e,OSError) else None,
  'private_fixed_code':str(e) if isinstance(e,ValueError) and re.fullmatch('fixed-engine-patch-[a-z-]+',str(e)) else None}))
 raise SystemExit(1)
'''


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True, timeout=30).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def engine_files(source):
    base = Path(source) / 'backup-engine'
    files = {str(p.relative_to(base / 'woowbackup')): p.read_bytes()
             for p in (base / 'woowbackup').rglob('*.py') if '__pycache__' not in p.parts}
    files[device.HELPER_KEY] = (base / 'woowtech-cockpit-backup').read_bytes()
    return files


def expected_hashes(files):
    """The shape of the device's engine hashes and of the controllers' frozen_engine()."""
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


def validate(lease, phase, *, device_name, driver, source_commit, old_commit, names, now):
    if (lease.get('granted') is not True or lease.get('case') != CASE or lease.get('device') != device_name
            or phase not in PHASES or phase not in lease.get('phases', []) or not set(lease['phases']) <= set(PHASES)
            or lease.get('driver_commit') != driver or lease.get('source_commit') != source_commit
            or lease.get('old_source_commit') != old_commit or lease.get('files') != names
            or not CASE_NAME.fullmatch(str(lease.get('name', '')))):
        raise ValueError('exact engine-patch lease required')
    expires = datetime.fromisoformat(lease['expires_utc']).timestamp()
    if not now < expires <= now + 40 * 60:
        raise ValueError('lease expired or exceeds the bounded window')
    return expires


def save_receipt(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('unsafe receipt')
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def main(argv=None, *, devices=None):
    devices = devices or DEVICES
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--device', choices=sorted(devices))
    parser.add_argument('--phase', choices=PHASES)
    for name in ('lease', 'source', 'old-source', 'receipt'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        compile(dependencies() + ENTRY, '<fixed engine patch program>', 'exec')
        print(json.dumps({'stage': 'engine_patch_offline', 'device_access': False}))
        return 0
    if not all((args.device, args.phase, args.lease, args.source, args.old_source, args.receipt)):
        parser.error('explicit device/phase/lease/source/old-source/receipt required')
    if not RECEIPT.fullmatch(args.receipt.name):
        raise ValueError('a separate engine-patch receipt named focus_engine_patch.<label>.json is required')
    device_name, lock = devices[args.device]
    lease = json.loads(args.lease.read_bytes())
    driver = git(REPO, 'rev-parse', 'HEAD')
    new_commit, old_commit = git(args.source, 'rev-parse', 'HEAD'), git(args.old_source, 'rev-parse', 'HEAD')
    if any(git(folder, 'status', '--porcelain') for folder in (REPO, args.source, args.old_source)):
        raise ValueError('clean exact driver and both product checkouts required')
    old, new, names = changed(args.old_source, args.source)
    validate(lease, args.phase, device_name=device_name, driver=driver, source_commit=new_commit, old_commit=old_commit,
             names=names, now=time.time())
    import ha_import_e2e as h
    h.DEVICE = device_name
    h.require_isolated_device()
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.phase == PHASES[0] and args.receipt.exists():
            raise ValueError('new engine-patch receipt required')
        receipt = json.loads(args.receipt.read_bytes()) if args.receipt.exists() else {
            'device': device_name, 'name': lease['name'], 'started': int(time.time()), 'responses': []}
        receipt.update(driver=driver, old_source=old_commit, new_source=new_commit, files=names, phase=args.phase)
        save_receipt(args.receipt, receipt)

        def require(label, condition):
            print(json.dumps({'stage': label, 'ok': bool(condition)}), flush=True)
            if not condition:
                raise RuntimeError(label)

        def invoke(op, **kwargs):
            receipt['operation'] = op
            save_receipt(args.receipt, receipt)
            p = h.root('python3', '-B', '-I', '-c', dependencies() + ENTRY,
                       input=json.dumps(dict(kwargs, op=op, case=lease['name'])).encode(), timeout=180)
            try:
                reply = json.loads(p.stdout)
            except (ValueError, UnicodeError):
                reply = {'ok': False, 'private_error_class': 'InvalidFixedResponse', 'private_stage': op,
                         'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr), 'returncode': p.returncode}
            receipt['responses'].append({k: v for k, v in reply.items() if k != 'result'} | {'op': op})   # BEFORE any assertion
            save_receipt(args.receipt, receipt)
            if p.returncode or reply.get('ok') is not True:
                raise RuntimeError('fixed engine patch operation refused')
            return reply['result']

        try:
            available = next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
            stat = os.statvfs(REPO)
            require('host_memory', available >= BOUNDS['host_available_mib'] * 1024)
            require('host_disk_reserve', stat.f_bavail * stat.f_frsize >= BOUNDS['host_reserve_gib'] * 1024**3 + 64 * 1024**2)
            headroom = json.loads(h.root('python3', '-I', '-c', MEMORY, timeout=60).stdout)
            require('device_memory', headroom >= BOUNDS['device_headroom_mib'] * 1024**2)
            if args.phase == PHASES[0]:
                require('installed_engine_is_the_reviewed_old_version', invoke('engine-hashes') == expected_hashes(old))
                invoke('engine-apply', files=request_files(old, new, names))
                ok = invoke('engine-hashes') == expected_hashes(new)
                receipt['installed_new'] = bool(ok)
                save_receipt(args.receipt, receipt)
                if not ok:
                    invoke('engine-restore')
                require('installed_engine_is_the_new_frozen_product', ok)
            else:
                invoke('engine-restore')
                require('installed_engine_is_the_reviewed_old_version', invoke('engine-hashes') == expected_hashes(old))
                receipt['installed_new'] = False
                save_receipt(args.receipt, receipt)
            print(json.dumps({'stage': 'engine_patch_complete', 'device': device_name, 'phase': args.phase, 'files': names,
                              'installed_new': args.phase == PHASES[0], 'services_or_data_changed': False}))
            return 0
        except Exception as error:  # noqa: BLE001
            receipt['failure_class'] = type(error).__name__
            save_receipt(args.receipt, receipt)
            print(json.dumps({'stage': 'engine_patch_failed', 'failure_class': type(error).__name__}))
            return 1
    finally:
        os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
