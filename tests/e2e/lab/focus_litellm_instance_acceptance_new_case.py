#!/usr/bin/env python3
"""Offline-only exclusive receipt preparation for one reviewed successor case."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import focus_litellm_instance_acceptance_images_verify as images
import focus_litellm_instance_acceptance_source as source

OLD='woowbk_focus_litellm_a2c39e761b04'
NEW='woowbk_focus_litellm_b7d2480c9e36'
DERIVED='af291cf14dba64dd3331179696d9bdfd70f5cacf0c92c53202d0998fe15ecaff'
CAPTURE_SHA='0c5396f61187dc666c4a67162fd813facfb8571f1ef291bb40b74558a9c1bc1f'
CLEANUP_RECEIPT_SHA='a11bebbeabd09996174a8c9f88d6a269d2455aed2b522815056f488b296dd1cc'
CLEANUP_OUTPUT_SHA='3e226b8d10466ad7c6987a366de1deb002cc2205bebaaa2c7b0288b7d0576793'
CHECKS={'actual_installed_proxy_reader','saved80_step_leaks','all_jobs_terminal',
        'original_device_durable_state','preexisting_backups_preserved','no_app_mutation_before_verified_safety'}
# Fresh read-only capture of dev-d taken after R8 PAGE5 restored Hermes and Omnigent (litellm-r8-fresh-before-01).
FRESH_SHA='f15e2a2c98606ce6ab8a13f23f3e7a862344f42925772fa98a72fe4a960c8d35'
# Restoring a stack recreates its containers, secrets and volumes: ONLY these ids of the Hermes and Omnigent stacks may differ
# from the verified original inventory. Anything else (EMQX, catalogs, files, images, units, timer, networks) must be identical.
FRESH_ALLOWED=re.compile(r'\.(containers|external_containers|secrets|volumes)\.(hermes|omnigent)-[a-z0-9-]+\Z')


def pinned(path,expected):
    raw,meta=source.ops.common.read_regular(path,8*1024**2)
    if meta['uid']!=os.geteuid() or meta['mode']!=0o600 or meta['sha256']!=expected:
        raise ValueError('private original proof pin')
    return json.loads(raw)


def diff(a,b,path=''):
    if a==b:return []
    if isinstance(a,dict) and isinstance(b,dict):
        return sum((diff(a.get(k),b.get(k),path+'.'+k) for k in sorted(set(a)|set(b))),[])
    return [path]


def adopt_fresh_before(old_current,configs,fresh):
    """The post-R8 inventory as the new strict baseline, only when every difference is an id R8 legitimately recreated."""
    samples=fresh.get('samples') or []
    if fresh.get('transport_returncode')!=0 or not samples or fresh.get('source_commit')!=source.ops.NEW:
        raise ValueError('fresh R8 return capture incomplete')
    sample=samples[-1];current=sample['current']
    if sample.get('configs')!=configs:raise ValueError('fresh capture image configs differ from the verified ones')
    original=fresh.get('r8_original_images') or {}
    if (set(original)!=set(source.ops.SELECTED) or any(
            not isinstance(current.get('selected',{}).get(name,{}).get('image'),str)
            or current['selected'][name]['image'][:12]!=original[name] for name in original)):
        raise ValueError('selected eight containers no longer run the images R8 recorded')
    before={k:copy.deepcopy(current[k]) for k in old_current}
    changed=diff(old_current,before)
    if any(not FRESH_ALLOWED.fullmatch(path) for path in changed):
        raise ValueError('fresh baseline differs outside the Hermes/Omnigent ids R8 recreated')
    return before,changed


def prepare(*,image_capture,old_receipt,old_output,flow_receipt,pause_receipt,fresh_before=None):
    if any(os.path.lexists(p) for p in (flow_receipt,pause_receipt)) or flow_receipt==pause_receipt:
        raise ValueError('exclusive new receipt paths required')
    raw=pinned(image_capture,CAPTURE_SHA)
    facts=raw['facts'];images.verify(facts,before=facts['state']['before'],derived=DERIVED,
                                  source_hashes=source.payload()['sha256'])
    if facts['name']!=OLD:raise ValueError('image belongs to a different original case')
    prior=pinned(old_receipt,CLEANUP_RECEIPT_SHA);output=pinned(old_output,CLEANUP_OUTPUT_SHA)
    checks={row['check'] for row in output['checks'] if row['ok'] is True}
    if (prior['name']!=OLD or prior['complete'] is not True or prior['full_safety'] is not None
            or prior['jobs'] or prior['pending'] or prior.get('safety_verified') or prior.get('upload_intent')
            or any(prior.get(k) for k in ('catalog_intent','pg_tag_intent','hook_intent','timer_intent'))
            or output['driver_commit']!='f39666e9162f9c581e172256b574f5718a0fbf77'
            or output['source_commit']!=source.ops.NEW or output['phase']!='flow'
            or output['phase_succeeded'] is not False or output['complete'] is not True
            or output.get('flow_verified') is not False or not CHECKS<=checks
            or prior['before']!=facts['state']['before'] or prior['derived_image']!=DERIVED):
        raise ValueError('original failed attempt cleanup not proven')
    before=copy.deepcopy(facts['current']);adopted=[]
    if fresh_before is not None:
        before,adopted=adopt_fresh_before(facts['current'],facts['configs'],pinned(fresh_before,FRESH_SHA))
    if (not set(source.ops.SELECTED)<=set(before['running']) or len(before['containers'])!=8
            or before['package'] or before['config_directory'] or 'litellm.json' in before['catalogs']):
        raise ValueError('approved original eight / absent LL baseline required')
    reuse={'from_case':OLD,'derived_image':DERIVED,'verification_sha256':CAPTURE_SHA,
           'cleanup_receipt_sha256':CLEANUP_RECEIPT_SHA,'cleanup_output_sha256':CLEANUP_OUTPUT_SHA}
    r={'name':NEW,'device':images.plan.DEVICE,'version':1,'pending':None,'jobs':{},'created_backups':[],
       'full_safety':None,'safety_verified':False,'catalog_intent':False,'timer_intent':False,'install_intent':False,
       'hook_intent':False,'recovery_verified':False,'complete':False,'images_ready':True,
       'derived_image':DERIVED,'owned_images':[],'image_reuse':reuse}
    # This separate pause-only admission file claims no initialized root state.
    # Resume MUST read the real flow receipt, so recovery flags cannot be stale.
    admission=dict(r,before=before,purpose='pause-admission-only')
    images.exclusive(flow_receipt,r);source.ops.fsync_dir(Path(flow_receipt).parent)
    images.exclusive(pause_receipt,admission);source.ops.fsync_dir(Path(pause_receipt).parent)
    return {'host_only':True,'case':NEW,'baseline_sha256':source.ops.digest(source.ops.canonical(before)),
            'adopted_post_r8_id_changes':len(adopted),
            'image_reuse':reuse,'flow_receipt_sha256':source.ops.digest(source.ops.canonical(r)),
            'pause_receipt_sha256':source.ops.digest(source.ops.canonical(admission))}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true')
    for field in ('image-capture','old-receipt','old-output','flow-receipt','pause-receipt','fresh-before'):
        p.add_argument('--'+field,type=Path)
    a=p.parse_args()
    if not a.prepare:print(json.dumps({'host_only':True,'case':NEW,'writes':False}));return
    if not all((a.image_capture,a.old_receipt,a.old_output,a.flow_receipt,a.pause_receipt,a.fresh_before)):
        p.error('all receipt paths and the fresh post-R8 capture are required')
    if source.git('status','--porcelain'):raise ValueError('clean committed controller required')
    print(json.dumps(prepare(image_capture=a.image_capture,old_receipt=a.old_receipt,old_output=a.old_output,
                             flow_receipt=a.flow_receipt,pause_receipt=a.pause_receipt,fresh_before=a.fresh_before)))


if __name__=='__main__':main()
