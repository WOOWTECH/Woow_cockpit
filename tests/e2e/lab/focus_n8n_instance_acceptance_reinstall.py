#!/usr/bin/env python3
"""Small full-flow reinstall wrapper around the proven Transaction2; offline default.

Fresh namespace/receipt/lease only. Source1 and the successful source2 roundtrip
are immutable inputs, checked before every inherited per-file mutation.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import focus_n8n_instance_acceptance_source2 as source2

previous = source2.previous
CASE = 'n8n-instance-source-fullflow'
PHASES = ('source-fullflow-install', 'source-fullflow-recover')
PROOF_SHA = '0f98c76b312449fd99e9bbde0bd73c6194ae1dcaaa979e79c8ebfd9570863296'
RECEIPT = 'focus_n8n_instance_source_fullflow.json'


def source_budget(payload):
    """Incremental disk bound for ONE install/return, not an instance DB flow.

    Existing source1/source2 proof trees never grow. The pinned original has73
    files; the new payload has53. Two maximum temporaries cover an interrupted
    install and its one explicit return. No retry is authorized by this bound.
    """
    files, helper = previous.remote.decode_payload(payload)
    candidate = sum(map(len, files.values())) + len(helper)
    mib = 1024**2
    amounts = {'prior_library_max':64*mib, 'prior_helper_max':mib,
        'candidate_staging':candidate, 'live_growth_max':candidate,
        'two_pending_files_max':2*max(64*mib, max(map(len, files.values())), len(helper)),
        'journal_and_atomic_writer':2*8*mib, 'two_host_receipts':2*8*mib,
        'two_fixed_captures':2*mib, 'allocation_and_metadata':4*mib}
    total = ((sum(amounts.values()) + mib-1)//mib)*mib
    if total > 256*mib: raise ValueError('source-only payload exceeds reviewed disk budget')
    return {'components_bytes':amounts, 'write_budget_bytes':total,
        'candidate_library_bytes':candidate-len(helper), 'candidate_helper_bytes':len(helper),
        'largest_candidate_file_bytes':max(map(len, files.values())), 'selected_files':len(files)+1}


def bounds(payload):
    return {k:v for k,v in previous.BOUNDS.items() if k != 'host_write_budget_gib'} | {
        'source_write_budget_bytes':source_budget(payload)['write_budget_bytes']}

# Only namespace selection and source2-proof binding are new. Publication,
# private copies, CAS, recovery, syscall diagnostics and locks are inherited.
EXTENSION = r'''
ProvenTransaction2 = Transaction2
SOURCE2_RETURN_SHA = '0f98c76b312449fd99e9bbde0bd73c6194ae1dcaaa979e79c8ebfd9570863296'

class FullflowTransaction(ProvenTransaction2):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        self.proof = ProvenTransaction2(name, **kwargs)
        self.path = self.path.parent / (name + '-source-fullflow')
        self.libown = self.lib.parent / ('.focus-n8n-source-fullflow-' + name)
        self.helpown = self.helper.parent / ('.focus-n8n-source-fullflow-' + name)
        if self.helpown == self.libown:
            self.helpown = self.helper.parent / ('.focus-n8n-source-fullflow-helper-' + name)
        self.newlib = self.libown / 'candidate'
        self.newhelper = self.helpown / 'candidate-helper'
        self.state = json.loads(common.read_regular(self.path/'state.json', 8*1024**2)[0]) if self.path.exists() else {}

    def source1_fingerprint(self):
        old = super().source1_fingerprint()
        p = self.proof
        if (common.read_regular(p.path/'state.json', 8*1024**2)[1]['sha256'] != SOURCE2_RETURN_SHA
                or p.state.get('restored') is not True or p.state.get('complete') is not False):
            raise ValueError('fixed-source2-return-proof-changed')
        p.verify_copies()
        return common.digest(json.dumps({'source1': old, 'source2': checked_tree(p.path),
            'source2_library_stage': checked_tree(p.libown),
            'source2_helper_stage': checked_tree(p.helpown)}, sort_keys=True).encode())

Transaction2 = FullflowTransaction
'''

ENTRY = r'''
try:
    raw = sys.stdin.buffer.read(96*1024**2+1)
    if len(raw) > 96*1024**2: raise ValueError('fixed-source2-request-bound')
    print(json.dumps(dispatch(json.loads(raw))))
except Exception as error:
    print(json.dumps({'ok': False, 'private_error_class': type(error).__name__,
        'private_errno': error.errno if isinstance(error, OSError) else None,
        'private_stage': getattr(error, '_source2_stage', 'request_preconditions'),
        'private_fixed_code': str(error) if isinstance(error, ValueError) and
            re.fullmatch(r'fixed-source2-[a-z0-9-]{1,80}', str(error)) else None}))
    raise SystemExit(1)
'''


def program():
    return "__name__='fixed_fullflow_dependencies'\n" + source2.program() + EXTENSION + ENTRY


def validate(lease, phase, driver, payload, image, now):
    if (lease.get('case') != CASE or lease.get('method') != source2.METHOD
            or lease.get('source2_return_journal_sha256') != PROOF_SHA
            or lease.get('bounds') != bounds(payload)
            or phase not in lease.get('phases', []) or not set(lease['phases']) <= set(PHASES)):
        raise ValueError('fresh fullflow source contract required')
    transformed = dict(lease, case='n8n-instance-source', bounds=previous.BOUNDS, phases=[
        'source-install' if p == PHASES[0] else 'source-recover' for p in lease['phases']])
    return previous.validate(transformed, 'source-install' if phase == PHASES[0] else 'source-recover',
        driver=driver, source_payload=payload, image_receipt=image, now=now)


def invoke(h, request):
    p = h.root('python3', '-B', '-I', '-c', program(), input=json.dumps(request).encode(), timeout=300)
    try: result = json.loads(p.stdout)
    except Exception:
        return {'ok': False, 'private_error_class': 'InvalidFixedResponse', 'private_errno': None,
            'private_stage': 'transport'}
    if p.returncode and result.get('ok') is True:
        return {'ok': False, 'private_error_class': 'TransportExit', 'private_errno': None, 'private_stage': 'transport'}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true'); parser.add_argument('--phase', choices=PHASES)
    for name in ('source', 'lease', 'receipt', 'image-receipt'): parser.add_argument('--'+name, type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        compile(program(), '<fullflow per-file source wrapper>', 'exec')
        print(json.dumps({'stage': 'fullflow_source_offline', 'device_access': False})); return 0
    if not all((args.phase, args.source, args.lease, args.receipt, args.image_receipt)):
        parser.error('all fullflow source arguments required')
    driver = previous.git(previous.REPO, 'rev-parse', 'HEAD')
    if previous.git(previous.REPO, 'status', '--porcelain'): raise ValueError('clean committed driver required')
    payload = previous.payload(args.source); lease = json.loads(args.lease.read_text())
    raw, meta = previous.common.read_regular(args.image_receipt)
    if meta['uid'] != os.geteuid() or meta['mode'] != 0o600: raise ValueError('private image receipt required')
    expiry = validate(lease, args.phase, driver, payload, json.loads(raw), time.time())
    if args.receipt.name != RECEIPT: raise ValueError('new fullflow source receipt required')
    if args.receipt.exists():
        raw, meta = previous.common.read_regular(args.receipt)
        if meta['uid'] != os.geteuid() or meta['mode'] != 0o600 or json.loads(raw)['name'] != lease['name']:
            raise ValueError('foreign fullflow source receipt')
        if args.phase == PHASES[0]: raise ValueError('never replay fullflow source install')
    import ha_import_e2e as h
    h.DEVICE = previous.plan.DEVICE; h.require_isolated_device()
    lock = os.open(previous.plan.LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        budget = source_budget(payload)
        previous.resources(h, expiry, recovering=args.phase == PHASES[1], write_budget_bytes=budget['write_budget_bytes'])
        receipt = {'driver_commit': driver, 'source_commit': previous.remote.FROZEN,
            'name': lease['name'], 'phase': args.phase, 'method': source2.METHOD,
            'source2_return_journal_sha256': PROOF_SHA,
            'source_only_disk_budget':budget,
            'manifest_sha256': previous.manifest_sha(payload), 'intent': True, 'completed': False}
        previous.save_receipt(args.receipt, receipt)
        request = {'case': lease['name'], 'phase': 'source2-install' if args.phase == PHASES[0] else 'source2-recover',
            'protected': previous.plan.reviewed_baselines()}
        if args.phase == PHASES[0]: request['payload'] = payload
        result = invoke(h, request)
        receipt['private_result'] = result; previous.save_receipt(args.receipt, receipt)
        if result.get('ok') is True and args.phase == PHASES[0] and result['source_sha256'] != payload['sha256']:
            receipt['private_result'] = {'ok': False, 'private_error_class': 'HashMismatch',
                'private_errno': None, 'private_stage': 'host_hash_validation'}
        previous.resources(h, expiry, recovering=True, write_budget_bytes=budget['write_budget_bytes'])
        receipt['completed'] = receipt['private_result'].get('ok') is True
        previous.save_receipt(args.receipt, receipt)
        print(json.dumps({'stage': 'fullflow_source_result', 'phase': args.phase, 'ok': receipt['completed']}))
        return 0 if receipt['completed'] else 1
    except Exception as error:
        if 'receipt' in locals():
            receipt['private_transport_error_class'] = type(error).__name__; previous.save_receipt(args.receipt, receipt)
        print(json.dumps({'stage': 'fullflow_source_result', 'phase': args.phase, 'ok': False})); return 1
    finally: os.close(lock)


if __name__ == '__main__': raise SystemExit(main())
