#!/usr/bin/env python3
"""Successor case for a LiteLLM instance case that already completed its recovery (b8 after b7, b12 after b11).

Separate, small steps; nothing here installs, restores or deletes anything:

  --capture      READ-ONLY on dev-d: the controller's own inventory operation plus the engine's backup and upload lists, written
                 as one private file. Takes the dev-d mutation lock without waiting. --without-container NAME (the failing
                 Headscale's own container) keeps looking until a look shows no such container when no look equals
                 --expect-baseline (dev-d changed since the predecessor: there is no exact look to wait for).
  --differences  HOST ONLY: every inventory path (names only, never a value) where the live capture differs from the
                 predecessor's verified original, and which of them a re-adoption could accept.
  --prepare      HOST ONLY, offline: pins the predecessor's final receipt and final output by SHA-256, requires that its recovery
                 was verified and everything it created was removed, requires that the captured live inventory equals the
                 predecessor's verified original EXACTLY, and writes the two exclusive private receipts of the new case (the flow
                 receipt and the pause-admission file), the same way the first successor tool does.
                 --adopt-restored PREFIX,... (b12: other reviewed lanes restored or restarted stacks on dev-d after the
                 predecessor) re-adopts the live inventory as the new verified original only when EVERY difference is the id of
                 a container, an external container, a secret or a network, or a volume's creation time, of a name that exists on
                 both sides and belongs to a named prefix (the name itself, or the prefix followed by - or _). Anything else -
                 a file, a catalog, a unit, the timer, an image, a running set, an added or removed name - still refuses. The
                 adopted paths are returned (names only) for the record.

A predecessor whose FLOW passed (b11, 68/68) completed its recovery in the same run, up to the outer isolation: it is accepted
like a recover-only pass or a flow that failed and recovered.

The retained derived image is reused through the unchanged pinned reuse record of the predecessor (the device checks it against
its own constants and against the first case's root journal); no new image is built or claimed.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance_images_verify as images
import focus_litellm_instance_acceptance_source as source

plan=images.plan
LOCK='/tmp/woowbk-dev-d-mutation.lock'
# What every predecessor's final output must show. A recover-only pass also proves the outer isolation itself; a FLOW that failed and
# then recovered inside the same run never reaches that check (it belongs to a successful end), but --capture proves the isolation
# again before it reads anything, so a successor admitted from such a flow is no weaker.
RECOVERY_CHECKS={'all_jobs_terminal','original_device_durable_state','preexisting_backups_preserved'}
INTENTS=('catalog_intent','pg_tag_intent','hook_intent','timer_intent')
# What a restore or a restart of another lane's stack legitimately changes: ids and a volume's creation time, never a name set.
ID_CATEGORIES=('containers','external_containers','secrets','volumes','networks')
PREFIX=re.compile(r'[a-z0-9][a-z0-9_-]{1,40}\Z')


def pinned(path,expected):
    raw,meta=source.ops.common.read_regular(path,8*1024**2)
    if meta['uid']!=os.geteuid() or meta['mode']!=0o600 or meta['sha256']!=expected:
        raise ValueError('private pin does not match: '+Path(path).name)
    return json.loads(raw)


def diff(a,b,path=''):
    if a==b:return []
    if isinstance(a,dict) and isinstance(b,dict):
        return sum((diff(a.get(k),b.get(k),path+'.'+k) for k in sorted(set(a)|set(b))),[])
    return [path]


def ops_source():
    """Byte for byte what the controller sends to the device (supervisor first, then the operations)."""
    return (HERE/'focus_litellm_instance_acceptance_supervisor.py').read_text()+'\n'+(
        HERE/'focus_litellm_instance_acceptance_ops.py').read_text()


def settled(inventory,without):
    """No container of these names exists or runs in this look (the failing unit is between two start attempts)."""
    return not any(name in (inventory.get(kind) or {}) for name in without for kind in ('containers','external_containers')) \
        and not any(name in (inventory.get('running') or []) for name in without)


def capture(output,*,transport,case,lock=LOCK,clock=time.time,expect=None,tries=15,wait=2,sleep=time.sleep,without=()):
    """Read-only: returns the digest of the private capture file. `expect`: the predecessor's verified baseline digest. The
    already failing Headscale unit restarts every few seconds and its own container exists only while one attempt runs (b11's
    first capture caught .containers.headscale); with `expect` the capture looks again, up to `tries` times, and keeps the first
    look that equals it, else the last one, which --prepare then refuses by naming the difference. `without` (b12): when no look
    equals `expect`, the first look in which none of these containers exists is kept instead (a re-adoption must start from the
    failing unit's quiet moment, the state the pause and the flow later see); none at all refuses."""
    if os.path.lexists(output):raise ValueError('a unique capture path is required')
    fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        transport.DEVICE=plan.DEVICE;transport.require_isolated_device()
        quiet=None
        for look in range(1,(tries if expect or without else 1)+1):
            p=transport.root('python3','-B','-I','-c',ops_source(),
                             input=json.dumps({'op':'inventory','case':case}).encode(),timeout=180)
            if p.returncode:raise RuntimeError('fixed inventory operation failed; raw output withheld')
            inventory=json.loads(p.stdout)
            if expect is not None and source.ops.digest(source.ops.canonical(inventory))==expect:break
            if without and quiet is None and settled(inventory,without):
                quiet=(look,inventory)
                if expect is None:break
            if expect is None and not without:break
            if look<tries:sleep(wait)
        else:
            if without:
                if quiet is None:raise RuntimeError('every look showed the failing unit\'s own container; capture again')
                look,inventory=quiet
        rc,listing=transport.helper('list',None,timeout=180)
        if rc or listing.get('ok') is not True:raise RuntimeError('fixed list request refused')
        value={'device':plan.DEVICE,'case':case,'at':int(clock()),'inventory':inventory,'looks':look,
               'inventory_sha256':source.ops.digest(source.ops.canonical(inventory)),
               'backup_ids':sorted(x['id'] for x in listing.get('backups',[])),
               'ha_upload_ids':sorted(x['id'] for x in listing.get('ha_backups',[]))}
        if without:value['without_containers']=sorted(without)
        return images.exclusive(output,value)
    finally:os.close(fd)


def recovered(output,checks):
    """The predecessor's final output: a successful recover-only pass, a flow that failed and whose own recovery completed, or a
    flow that passed (b11): its recovery ran in the same process and completed up to the outer isolation."""
    if output['complete'] is not True or output['recovery_verified'] is not True or not RECOVERY_CHECKS<=checks:return False
    if output['phase']=='recover':return output['phase_succeeded'] is True and 'outer_isolation_returned' in checks
    if output['phase']!='flow':return False
    if output['phase_succeeded'] is True:
        return output.get('flow_verified') is True and 'outer_isolation_returned' in checks
    return output['phase_succeeded'] is False and output.get('flow_verified') is False


def owned_by(name,prefixes):
    return any(name==p or (name.startswith(p) and name[len(p):len(p)+1] in ('-','_')) for p in prefixes)


def adoptable(path,before,live,prefixes):
    """One difference a re-adoption may accept: the id (a volume's creation time) of a name that exists on both sides, in an id
    category, owned by a named prefix."""
    for kind in ID_CATEGORIES:
        head='.'+kind+'.'
        if path.startswith(head):
            name=path[len(head):]
            old,new=(before.get(kind) or {}),(live.get(kind) or {})
            return (name in old and name in new and isinstance(old[name],str) and isinstance(new[name],str)
                    and owned_by(name,prefixes))
    return False


def restored_prefixes(adopt):
    adopt=tuple(adopt)
    if len(set(adopt))!=len(adopt) or not all(isinstance(p,str) and PREFIX.fullmatch(p) for p in adopt):
        raise ValueError('restored stack prefixes')
    return adopt


def differences(*,prior_receipt,prior_receipt_sha,live,live_sha,adopt=()):
    """Host only: where the live capture differs from the predecessor's verified original (paths, names only), and which of the
    differences --adopt-restored with these prefixes would accept (`adoptable`) or still refuse (`refused`)."""
    adopt=restored_prefixes(adopt)
    prior=pinned(prior_receipt,prior_receipt_sha);now=pinned(live,live_sha)
    if now.get('device')!=plan.DEVICE or now.get('inventory_sha256')!=source.ops.digest(source.ops.canonical(now['inventory'])):
        raise ValueError('live capture is not a complete dev-d inventory')
    changed=diff(prior['before'],now['inventory'])
    accepted=[p for p in changed if adoptable(p,prior['before'],now['inventory'],adopt)]
    return {'host_only':True,'predecessor':prior['name'],'live_looks':now.get('looks'),'differences':changed,
            'adoptable':accepted,'refused':[p for p in changed if p not in accepted]}


def prepare(*,prior_receipt,prior_receipt_sha,prior_output,prior_output_sha,live,live_sha,new_name,flow_receipt,pause_receipt,
            adopt=()):
    if any(os.path.lexists(p) for p in (flow_receipt,pause_receipt)) or flow_receipt==pause_receipt:
        raise ValueError('exclusive new receipt paths required')
    if not plan.CASE.fullmatch(new_name):raise ValueError('new case name')
    adopt=restored_prefixes(adopt)
    prior=pinned(prior_receipt,prior_receipt_sha);output=pinned(prior_output,prior_output_sha);now=pinned(live,live_sha)
    if new_name==prior['name']:raise ValueError('the successor needs its own case name')
    checks={row['check'] for row in output['checks'] if row['ok'] is True}
    before=prior['before']
    if (prior['complete'] is not True or prior['recovery_verified'] is not True or prior['pending']
            or prior.get('pending_operation') or any(prior.get(k) for k in INTENTS)
            or prior['images_ready'] is not True or prior['owned_images']!=[]
            or not recovered(output,checks)
            or output['baseline_sha256']!=source.ops.digest(source.ops.canonical(before))):
        raise ValueError('predecessor recovery and cleanup not proven')
    if (now.get('device')!=plan.DEVICE or now.get('inventory_sha256')!=source.ops.digest(source.ops.canonical(now['inventory']))):
        raise ValueError('live capture is not a complete dev-d inventory')
    changed=diff(before,now['inventory'])
    if changed and not adopt:raise ValueError('live inventory differs from the verified original at: '+', '.join(changed[:12]))
    outside=[path for path in changed if not adoptable(path,before,now['inventory'],adopt)]
    if outside:raise ValueError('live inventory differs outside the restored stacks\' ids at: '+', '.join(outside[:12]))
    backups,uploads=set(now['backup_ids']),set(now['ha_upload_ids'])
    if (set(prior['created_backups'])&backups or not set(prior['before_backups'])<=backups
            or (prior.get('store_id') not in prior.get('before_uploads',[]) and prior.get('store_id') in uploads)
            or not set(prior.get('before_uploads',[]))<=uploads):
        raise ValueError('backups or uploads differ from the predecessor original')
    reuse=copy.deepcopy(prior['image_reuse'])
    if reuse!=source.ops.common.RETAINED_IMAGE or prior['derived_image']!=reuse['derived_image']:
        raise ValueError('the predecessor did not use the approved retained image record')
    r={'name':new_name,'device':plan.DEVICE,'version':1,'pending':None,'jobs':{},'created_backups':[],'full_safety':None,
       'safety_verified':False,'catalog_intent':False,'timer_intent':False,'install_intent':False,'hook_intent':False,
       'recovery_verified':False,'complete':False,'images_ready':True,'derived_image':prior['derived_image'],
       'owned_images':[],'image_reuse':reuse}
    # Re-adopted: the live inventory (equal to the original outside the adopted ids) is the new case's verified original.
    original=copy.deepcopy(now['inventory'] if changed else before)
    admission=dict(copy.deepcopy(r),before=original,purpose='pause-admission-only')
    images.exclusive(flow_receipt,r);source.ops.fsync_dir(Path(flow_receipt).parent)
    images.exclusive(pause_receipt,admission);source.ops.fsync_dir(Path(pause_receipt).parent)
    result={'host_only':True,'case':new_name,'predecessor':prior['name'],
            'baseline_sha256':source.ops.digest(source.ops.canonical(original)),
            'flow_receipt_sha256':source.ops.digest(source.ops.canonical(r)),
            'pause_receipt_sha256':source.ops.digest(source.ops.canonical(admission))}
    if adopt:result.update(adopted_prefixes=sorted(adopt),adopted=changed)
    return result


def names(value):
    return tuple(x for x in (value or '').split(',') if x)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',action='store_true');p.add_argument('--prepare',action='store_true')
    p.add_argument('--differences',action='store_true')
    for field in ('output','prior-receipt','prior-output','live','flow-receipt','pause-receipt'):p.add_argument('--'+field,type=Path)
    for field in ('prior-receipt-sha','prior-output-sha','live-sha','new-name','case','expect-baseline'):p.add_argument('--'+field)
    p.add_argument('--without-container',help='capture: comma-separated container names a kept look must not show')
    p.add_argument('--adopt-restored',help='prepare/differences: comma-separated stack prefixes whose ids may be re-adopted')
    a=p.parse_args(argv)
    if sum((a.capture,a.prepare,a.differences))!=1:
        print(json.dumps({'writes':False,'steps':['--capture (device, read-only)','--differences (host only)',
                                                  '--prepare (host only)']}));return 0
    if source.git('status','--porcelain'):raise ValueError('clean committed controller required')
    if a.capture:
        if not (a.output and a.case):p.error('--capture needs --output and --case')
        import ha_import_e2e as transport
        print(json.dumps({'capture_sha256':capture(a.output,transport=transport,case=a.case,expect=a.expect_baseline,
                                                   without=names(a.without_container))}));return 0
    if a.differences:
        if not all((a.prior_receipt,a.prior_receipt_sha,a.live,a.live_sha)):p.error('--differences needs both pins and paths')
        print(json.dumps(differences(prior_receipt=a.prior_receipt,prior_receipt_sha=a.prior_receipt_sha,live=a.live,
                                     live_sha=a.live_sha,adopt=names(a.adopt_restored))));return 0
    needed=(a.prior_receipt,a.prior_receipt_sha,a.prior_output,a.prior_output_sha,a.live,a.live_sha,a.new_name,a.flow_receipt,a.pause_receipt)
    if not all(needed):p.error('--prepare needs every pin, path and the new name')
    print(json.dumps(prepare(prior_receipt=a.prior_receipt,prior_receipt_sha=a.prior_receipt_sha,prior_output=a.prior_output,
        prior_output_sha=a.prior_output_sha,live=a.live,live_sha=a.live_sha,new_name=a.new_name,
        flow_receipt=a.flow_receipt,pause_receipt=a.pause_receipt,adopt=names(a.adopt_restored))));return 0


if __name__=='__main__':raise SystemExit(main())
