#!/usr/bin/env python3
"""Lease generator for one LiteLLM instance case through dev-d's real Cockpit page (case b12 after b11). Host only.

The coordinator's copy lives in the session scratchpad as make_ll_page_leases.py; this file is the same bytes, kept next to
the controllers it serves (repo convention: a lab tool and its test side by side). Run it with `python3 -I`. It never touches a
device, a lock or a secret: it reads the case's private receipts and journal (0600, owned; never printed), runs `git -C` for
HEADs and cleanliness, and imports the DRIVER checkout's own modules for every bound value. Each subcommand writes ONE lease,
O_EXCL and 0600, at the moment the step needs it (its window starts then), after checking it with the tool's own validator
where the tool has one, and prints the lease path and the exact next command.

  name          a fresh case name of the controller's form
  engine-patch  focus_engine_patch.py (dev-d: the installed engine back to the frozen product; files computed by the tool)
  pause         focus_litellm_instance_acceptance_quiesce.py --phase pause (from the successor's pause-admission receipt)
  flow          focus_litellm_instance_acceptance_run.py --phase flow --via-page (after a proven pause; phases flow+recover)
  resume        focus_litellm_instance_acceptance_quiesce.py --phase resume (from the flow receipt after the flow)
  recover       focus_litellm_instance_acceptance_run.py --phase recover --via-page (only when the flow lease has expired)
"""
import argparse
from datetime import datetime, timedelta, timezone
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

LEASES = Path('/tmp/parity-focus-20261127')
HEAVY = Path('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh')
LOCK = '/tmp/woowbk-dev-d-mutation.lock'
# Windows (minutes): the defaults the b-series used, each checked against the tool's own bound.
WINDOWS = {'engine-patch': (30, 1, 40), 'pause': (40, 7, 90), 'resume': (40, 7, 90), 'flow': (79, 30, 80), 'recover': (60, 20, 80)}
REVIEW = {'pause': 'Headscale pause for the LiteLLM page case {name}: only the already failing lab unit {unit}, its original '
                   'failed condition proven before the pause and again before the resume, journaled; baseline = the case\'s '
                   'verified original (pause-admission receipt).',
          'resume': 'Headscale resume for the LiteLLM page case {name} after its flow and recovery; baseline = the flow receipt\'s '
                    'original, equal to the pause journal\'s.',
          'flow': 'LiteLLM whole-instance flow of {name} through dev-d\'s real Cockpit page (import_path page): upload, check, '
                  'conversion and import by the page, the later outsider write before the page, everything after unchanged; '
                  'recover phase in the same lease; product {product} on dev-d; baseline = the pause-admission receipt\'s original.',
          'recover': 'Recover-only pass for the LiteLLM page case {name} (the flow lease expired); --via-page so the Cockpit password '
                     'scan runs when the page ran.',
          'engine-patch': 'Leased engine patch on dev-d before the LiteLLM page case: the installed engine (old checkout {old}) back '
                          'to the frozen product {product}; only the files that differ; the page is the same in both.'}


class Refused(Exception):
    """An input is missing or does not fit the step; nothing was written."""


def git(path, *args):
    # GIT_OPTIONAL_LOCKS=0: `git status` never refreshes (writes) the checkout's index; this tool only reads.
    return subprocess.check_output(['git', '-C', str(path), *args], text=True, timeout=30,
                                   env=dict(os.environ, GIT_OPTIONAL_LOCKS='0')).strip()


def clean_head(path, label):
    path = Path(path)
    if not (path / '.git').exists():
        raise Refused(f'{label} is not a git checkout: {path}')
    if git(path, 'status', '--porcelain'):
        raise Refused(f'{label} has uncommitted changes: {path}')
    head = git(path, 'rev-parse', 'HEAD')
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise Refused(f'{label} HEAD unreadable')
    return head


class Driver:
    """The driver checkout's own modules: every rule and constant comes from the code that will run."""

    def __init__(self, checkout):
        self.checkout = Path(checkout).resolve()
        self.lab = self.checkout / 'tests' / 'e2e' / 'lab'
        if not (self.lab / 'focus_litellm_instance_acceptance_run.py').is_file():
            raise Refused(f'no LiteLLM controller in {self.checkout}')
        sys.dont_write_bytecode = True
        if str(self.lab) not in sys.path:
            sys.path.insert(0, str(self.lab))
        for name in [n for n in sys.modules if n.startswith(('focus_litellm_instance_acceptance', 'focus_engine_patch'))]:
            del sys.modules[name]   # never a module of another checkout
        self.run = importlib.import_module('focus_litellm_instance_acceptance_run')
        self.plan = self.run.plan
        self.quiesce = importlib.import_module('focus_litellm_instance_acceptance_quiesce')
        self.source = self.quiesce.source
        self.patch = importlib.import_module('focus_engine_patch')
        for module in (self.run, self.quiesce, self.patch):
            if Path(module.__file__).resolve().parent != self.lab:
                raise Refused('a module was loaded from outside the driver checkout')

    def digest(self, value):
        return self.source.ops.digest(self.source.ops.canonical(value))

    def private(self, path, label):
        path = Path(path)
        if not path.is_file():
            raise Refused(f'{label} missing: {path}')
        try:
            return self.source.private_read(path)   # the tools' own reader: a regular 0600 file of this user
        except ValueError:
            raise Refused(f'{label} is not a private 0600 file of this user: {path}') from None


def expiry(kind, minutes, now):
    default, low, high = WINDOWS[kind]
    minutes = default if minutes is None else minutes
    if not isinstance(minutes, int) or not low <= minutes <= high:
        raise Refused(f'{kind} window must be {low}..{high} minutes')
    return (now + timedelta(minutes=minutes)).isoformat()


def write_lease(path, lease):
    path = Path(path)
    if os.path.lexists(path):
        raise Refused(f'lease exists (never overwritten): {path}')
    data = (json.dumps(lease, indent=1, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    return path


def free(path):
    """The first `<stem>-NN<suffix>` that does not exist yet (the tools refuse an existing output)."""
    path = Path(path)
    for n in range(1, 100):
        candidate = path.with_name(f'{path.stem}-{n:02d}{path.suffix}')
        if not os.path.lexists(candidate):
            return candidate
    raise Refused('no free output name')


def heavy(command, *, outer, grace, heavy_path=HEAVY):
    return (f'HEAVY_FREE={LOCK} HEAVY_WAIT=600 {heavy_path} timeout --signal=TERM --kill-after={grace} {outer} '
            + ' '.join(str(part) for part in command))


def suffix(name):
    return name[-12:]


# ---------------------------------------------------------------- what each tool admits

def quiesce_admission(d, lease, receipt, phase, journal_name, driver_commit, now):
    """The exact lease conditions of focus_litellm_instance_acceptance_quiesce.main() (the test runs that main on the result)."""
    q = d.quiesce
    expires = datetime.fromisoformat(lease['expires_utc'])
    if (lease.get('granted') is not True or lease.get('case') != 'litellm-instance-quiesce'
            or lease.get('device') != d.plan.DEVICE or lease.get('driver_commit') != driver_commit
            or lease.get('source_commit') != d.plan.FROZEN_PRODUCT or lease.get('method') != q.METHOD
            or lease.get('name') != receipt['name'] or lease.get('unit') != q.UNIT or lease.get('bounds') != q.BOUNDS
            or lease.get('source_path') != q.QFILE or lease.get('source_sha256') != receipt['before']['files'][q.QFILE]['sha256']
            or lease.get('baseline_sha256') != d.digest(receipt['before'])
            or phase not in lease.get('phases', []) or not set(lease['phases']) <= {'pause', 'resume'}
            or lease.get('journal_filename') != journal_name
            or expires.tzinfo is None or not now.timestamp() + 360 < expires.timestamp() <= now.timestamp() + 90 * 60):
        raise Refused('the quiescence tool would refuse this lease')


def product_head(d, product):
    head = clean_head(product, 'product checkout')
    if head != d.plan.FROZEN_PRODUCT:
        raise Refused(f'product checkout is {head[:12]}, the controller is frozen to {d.plan.FROZEN_PRODUCT[:12]}')
    return head


def frozen_product_dir(d):
    """The quiescence tool checks the controller's own PRODUCT_DIR (not an argument): clean, at the frozen product."""
    return product_head(d, d.plan.PRODUCT_DIR)


def journal_path(name, leases):
    return Path(leases) / f'litellm-headscale-quiescence-{suffix(name)}.private.json'


def pause_receipt(d, path):
    r = d.private(path, 'pause-admission receipt')
    if r.get('purpose') != 'pause-admission-only' or not d.plan.CASE.fullmatch(str(r.get('name', ''))):
        raise Refused('not a pause-admission receipt of a LiteLLM case')
    if not isinstance(r.get('before'), dict) or d.quiesce.QFILE not in (r['before'].get('files') or {}):
        raise Refused('the pause-admission receipt holds no verified original with the Headscale unit file')
    if r.get('install_intent') or r.get('full_safety') or r.get('pending') or r.get('jobs'):
        raise Refused('the pause-admission receipt is not fresh')
    return r


def fresh_flow_receipt(d, path, admission):
    r = d.private(path, 'flow receipt')
    expected = {k: v for k, v in admission.items() if k not in ('before', 'purpose')}
    if r != expected:
        raise Refused('the flow receipt is not the one the successor prepared with this pause-admission receipt')
    if r.get('owned_images') != [] or r.get('image_reuse') != d.source.ops.common.RETAINED_IMAGE or r.get('images_ready') is not True:
        raise Refused('the case does not reuse the approved retained image')
    return r


def journal(d, path, name, baseline, driver_commit):
    j = d.private(path, 'Headscale pause journal')
    if (j.get('name') != name or j.get('baseline_sha256') != baseline or j.get('driver_commit') != driver_commit
            or j.get('source_commit') != d.plan.FROZEN_PRODUCT or not isinstance(j.get('state'), dict)):
        raise Refused('the pause journal belongs to another case, baseline or driver')
    return j['state']


# ---------------------------------------------------------------- the leases

def make_name(d):
    for _ in range(10):
        name = 'woowbk_focus_litellm_' + secrets.token_hex(6)
        if d.plan.CASE.fullmatch(name):
            return name
    raise Refused('no case name')


def engine_patch(d, *, old_source, product, label, leases, minutes=None, out=None, now=None):
    now = now or datetime.now(timezone.utc)
    driver_commit = clean_head(d.checkout, 'driver checkout')
    new = product_head(d, product)
    old = clean_head(old_source, 'old (installed) checkout')
    try:
        _old, _new, files = d.patch.changed(old_source, product)
    except ValueError as error:
        raise Refused(str(error)) from None
    device_name, _lock = d.patch.DEVICES['d']
    lease = {'granted': True, 'case': d.patch.CASE, 'device': device_name, 'phases': list(d.patch.PHASES),
             'driver_commit': driver_commit, 'source_commit': new, 'old_source_commit': old, 'files': files,
             'name': 'woowbk_focus_n8n_' + secrets.token_hex(6), 'expires_utc': expiry('engine-patch', minutes, now),
             'coordinator_review': REVIEW['engine-patch'].format(old=old[:12], product=new[:12])}
    for phase in d.patch.PHASES:
        try:
            d.patch.validate(lease, phase, device_name=device_name, driver=driver_commit, source_commit=new, old_commit=old,
                             names=files, now=now.timestamp())
        except ValueError as error:
            raise Refused(f'focus_engine_patch would refuse: {error}') from None
    path = write_lease(out or Path(leases) / f'lease-litellm-engine-patch-{label}-dev-d.json', lease)
    receipt = Path(leases) / f'focus_engine_patch.ll-{label}-dev-d.json'
    command = ['python3', '-B', '-I', d.lab / 'focus_engine_patch.py', '--execute', '--device', 'd', '--phase', 'engine-patch',
               '--lease', path, '--source', Path(product).resolve(), '--old-source', Path(old_source).resolve(), '--receipt', receipt]
    return {'lease': str(path), 'files': files, 'expires_utc': lease['expires_utc'], 'receipt': str(receipt),
            'next': heavy(command, outer=600, grace=60)}


def pause(d, *, admission_path, label, leases, minutes=None, out=None, now=None):
    now = now or datetime.now(timezone.utc)
    driver_commit = clean_head(d.checkout, 'driver checkout')
    frozen_product_dir(d)
    r = pause_receipt(d, admission_path)
    j = journal_path(r['name'], leases)
    if os.path.lexists(j):
        raise Refused(f'a pause journal exists already (a pause ran): {j}')
    lease = {'granted': True, 'case': 'litellm-instance-quiesce', 'device': d.plan.DEVICE, 'driver_commit': driver_commit,
             'source_commit': d.plan.FROZEN_PRODUCT, 'method': d.quiesce.METHOD, 'name': r['name'], 'unit': d.quiesce.UNIT,
             'bounds': dict(d.quiesce.BOUNDS), 'source_path': d.quiesce.QFILE,
             'source_sha256': r['before']['files'][d.quiesce.QFILE]['sha256'], 'baseline_sha256': d.digest(r['before']),
             'phases': ['pause'], 'journal_filename': j.name, 'expires_utc': expiry('pause', minutes, now),
             'coordinator_review': REVIEW['pause'].format(name=r['name'], unit=d.quiesce.UNIT)}
    quiesce_admission(d, lease, r, 'pause', j.name, driver_commit, now)
    path = write_lease(out or Path(leases) / f'lease-litellm-quiescence-{label}-pause-dev-d.json', lease)
    output = free(Path(leases) / f'litellm-headscale-{label}-pause.json')
    command = ['python3', '-B', '-I', d.lab / 'focus_litellm_instance_acceptance_quiesce.py', '--execute', '--phase', 'pause',
               '--lease', path, '--receipt', Path(admission_path).resolve(), '--journal', j, '--output', output]
    return {'lease': str(path), 'journal': str(j), 'baseline_sha256': lease['baseline_sha256'],
            'expires_utc': lease['expires_utc'], 'next': heavy(command, outer=d.quiesce.BOUNDS['outer_seconds'], grace=30)}


def flow(d, *, product, flow_path, admission_path, label, leases, minutes=None, out=None, now=None):
    now = now or datetime.now(timezone.utc)
    driver_commit = clean_head(d.checkout, 'driver checkout')
    head = product_head(d, product)
    admission = pause_receipt(d, admission_path)
    r = fresh_flow_receipt(d, flow_path, admission)
    baseline = d.digest(admission['before'])
    state = journal(d, journal_path(r['name'], leases), r['name'], baseline, driver_commit)
    if state.get('paused') is not True or state.get('pending') or state.get('resumed'):
        raise Refused('the Headscale pause is not proven (journal: paused, nothing pending, not resumed)')
    lease = {'granted': True, 'case': 'litellm-instance-original', 'device': d.plan.DEVICE, 'phases': ['flow', 'recover'],
             'driver_commit': driver_commit, 'name': r['name'], 'fixture_sha256': d.plan.FIXTURE_SHA,
             'derivation_sha256': d.plan.DERIVATION_SHA, 'package_commit': d.plan.PACKAGE_COMMIT, 'baseline_sha256': baseline,
             'source_commit': head, 'baseline_policy': 'require-litellm-absent', 'image_policy': 'retain-for-case',
             'import_path': 'page', 'expires_utc': expiry('flow', minutes, now),
             'coordinator_review': REVIEW['flow'].format(name=r['name'], product=head[:12])}
    for phase in lease['phases']:
        try:
            d.run.validate_lease(lease, phase, now=now.timestamp(), driver_commit=driver_commit, source_commit=head, via_page=True)
        except ValueError as error:
            raise Refused(f'the controller would refuse: {error}') from None
    path = write_lease(out or Path(leases) / f'lease-litellm-fullflow-{label}-dev-d.json', lease)
    output = free(Path(leases) / f'litellm-instance-fullflow-{label}.json')
    command = ['python3', '-B', '-I', d.lab / 'focus_litellm_instance_acceptance_run.py', '--execute', '--phase', 'flow', '--via-page',
               '--source', Path(product).resolve(), '--lease', path, '--receipt', Path(flow_path).resolve(), '--output', output]
    return {'lease': str(path), 'baseline_sha256': baseline, 'expires_utc': lease['expires_utc'],
            'next': heavy(command, outer=3300, grace=1200)}


def resume(d, *, flow_path, label, leases, minutes=None, out=None, now=None):
    now = now or datetime.now(timezone.utc)
    driver_commit = clean_head(d.checkout, 'driver checkout')
    frozen_product_dir(d)
    r = d.private(flow_path, 'flow receipt')
    if r.get('purpose') == 'pause-admission-only' or not isinstance(r.get('before'), dict):
        raise Refused('the resume reads the flow receipt after the flow (with its verified original)')
    if r.get('pending') or any((v or {}).get('state') in ('queued', 'running') for v in (r.get('jobs') or {}).values()):
        raise Refused('a LiteLLM job is unresolved: recover first')
    if r.get('install_intent') and r.get('complete') is not True:
        raise Refused('the LiteLLM recovery is incomplete: recover first')
    j = journal_path(r['name'], leases)
    state = journal(d, j, r['name'], d.digest(r['before']), driver_commit)
    if not state.get('original') or state.get('resumed'):
        raise Refused('the journal holds no pause to resume, or the resume is complete')
    lease = {'granted': True, 'case': 'litellm-instance-quiesce', 'device': d.plan.DEVICE, 'driver_commit': driver_commit,
             'source_commit': d.plan.FROZEN_PRODUCT, 'method': d.quiesce.METHOD, 'name': r['name'], 'unit': d.quiesce.UNIT,
             'bounds': dict(d.quiesce.BOUNDS), 'source_path': d.quiesce.QFILE,
             'source_sha256': r['before']['files'][d.quiesce.QFILE]['sha256'], 'baseline_sha256': d.digest(r['before']),
             'phases': ['resume'], 'journal_filename': j.name, 'expires_utc': expiry('resume', minutes, now),
             'coordinator_review': REVIEW['resume'].format(name=r['name'])}
    quiesce_admission(d, lease, r, 'resume', j.name, driver_commit, now)
    path = write_lease(out or Path(leases) / f'lease-litellm-quiescence-{label}-resume-dev-d.json', lease)
    output = free(Path(leases) / f'litellm-headscale-{label}-resume.json')
    command = ['python3', '-B', '-I', d.lab / 'focus_litellm_instance_acceptance_quiesce.py', '--execute', '--phase', 'resume',
               '--lease', path, '--receipt', Path(flow_path).resolve(), '--journal', j, '--output', output]
    return {'lease': str(path), 'expires_utc': lease['expires_utc'], 'next': heavy(command, outer=d.quiesce.BOUNDS['outer_seconds'], grace=30)}


def recover(d, *, product, flow_path, admission_path, label, leases, minutes=None, out=None, now=None):
    now = now or datetime.now(timezone.utc)
    driver_commit = clean_head(d.checkout, 'driver checkout')
    head = product_head(d, product)
    admission = pause_receipt(d, admission_path) if admission_path else None
    r = d.private(flow_path, 'flow receipt')
    if not d.plan.CASE.fullmatch(str(r.get('name', ''))) or (admission and admission['name'] != r['name']):
        raise Refused('the flow receipt is not this case\'s')
    original = r.get('before') if isinstance(r.get('before'), dict) else (admission or {}).get('before')
    if not isinstance(original, dict):
        raise Refused('no verified original: give the pause-admission receipt')
    lease = {'granted': True, 'case': 'litellm-instance-original', 'device': d.plan.DEVICE, 'phases': ['recover'],
             'driver_commit': driver_commit, 'name': r['name'], 'fixture_sha256': d.plan.FIXTURE_SHA,
             'derivation_sha256': d.plan.DERIVATION_SHA, 'package_commit': d.plan.PACKAGE_COMMIT,
             'baseline_sha256': d.digest(original), 'source_commit': head, 'baseline_policy': 'require-litellm-absent',
             'image_policy': 'retain-for-case', 'import_path': 'page', 'expires_utc': expiry('recover', minutes, now),
             'coordinator_review': REVIEW['recover'].format(name=r['name'])}
    try:
        d.run.validate_lease(lease, 'recover', now=now.timestamp(), driver_commit=driver_commit, source_commit=head, via_page=True)
    except ValueError as error:
        raise Refused(f'the controller would refuse: {error}') from None
    path = write_lease(out or Path(leases) / f'lease-litellm-recover-{label}-dev-d.json', lease)
    output = free(Path(leases) / f'litellm-instance-recover-{label}.json')
    command = ['python3', '-B', '-I', d.lab / 'focus_litellm_instance_acceptance_run.py', '--execute', '--phase', 'recover',
               '--via-page', '--source', Path(product).resolve(), '--lease', path, '--receipt', Path(flow_path).resolve(),
               '--output', output]
    return {'lease': str(path), 'expires_utc': lease['expires_utc'], 'next': heavy(command, outer=3300, grace=1200)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('step', choices=('name', 'engine-patch', 'pause', 'flow', 'resume', 'recover'))
    p.add_argument('--driver', type=Path, required=True, help='the clean checkout every leased tool runs from (its HEAD is bound)')
    p.add_argument('--product', type=Path, help='the frozen product checkout (flow, recover, engine-patch)')
    p.add_argument('--old-source', type=Path, help='engine-patch: the checkout whose engine dev-d runs now')
    p.add_argument('--pause-receipt', type=Path, help='the successor\'s pause-admission receipt')
    p.add_argument('--flow-receipt', type=Path, help='the successor\'s flow receipt (the controller\'s receipt)')
    p.add_argument('--label', default='b12', help='case label for file names only')
    p.add_argument('--leases', type=Path, default=LEASES)
    p.add_argument('--minutes', type=int)
    p.add_argument('--out', type=Path, help='another lease path (a second attempt); never overwrites')
    a = p.parse_args(argv)
    if not re.fullmatch(r'[a-z0-9-]{1,20}', a.label):
        p.error('label: lowercase letters, digits and dashes')
    try:
        d = Driver(a.driver)
        if a.step == 'name':
            print(json.dumps({'name': make_name(d)}))
            return 0
        need = {'engine-patch': ('product', 'old_source'), 'pause': ('pause_receipt',), 'resume': ('flow_receipt',),
                'flow': ('product', 'flow_receipt', 'pause_receipt'), 'recover': ('product', 'flow_receipt')}[a.step]
        missing = [name for name in need if getattr(a, name) is None]
        if missing:
            raise Refused('missing: ' + ', '.join('--' + m.replace('_', '-') for m in missing))
        common = dict(label=a.label, leases=a.leases, minutes=a.minutes, out=a.out)
        if a.step == 'engine-patch':
            result = engine_patch(d, old_source=a.old_source, product=a.product, **common)
        elif a.step == 'pause':
            result = pause(d, admission_path=a.pause_receipt, **common)
        elif a.step == 'flow':
            result = flow(d, product=a.product, flow_path=a.flow_receipt, admission_path=a.pause_receipt, **common)
        elif a.step == 'resume':
            result = resume(d, flow_path=a.flow_receipt, **common)
        else:
            result = recover(d, product=a.product, flow_path=a.flow_receipt, admission_path=a.pause_receipt, **common)
    except Refused as error:
        print(json.dumps({'written': False, 'refused': str(error)}))
        return 2
    print(json.dumps(dict(result, written=True), indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
