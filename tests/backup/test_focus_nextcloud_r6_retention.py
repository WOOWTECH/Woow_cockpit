"""Pre-conversion refusal keeps only freshly proven own HA; no lab I/O."""
import copy
import tempfile
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'e2e/lab'))
import focus_nextcloud_r6 as flow
import focus_nextcloud_r6_case as control
import focus_nextcloud_r6_upload as upload


class RetentionTests(unittest.TestCase):
    def test_refused_check_retains_only_freshly_proven_quiescent_owned_ha(self):
        # A successful job with a stopped app must stay refused; no conversion request follows.
        job={'state':'succeeded','result':{'ha_check':{'apps':[
            {'app_id':'nextcloud','importable':False,'issues':[{'id':'failure.incompatible','level':'stop'}]}]}}}
        with self.assertRaisesRegex(ValueError,'not-importable'):flow.confirmation_keys(job,'fullshare')
        for fault in (None,'optout','convert-request','restore-request','converted','baseline','exact-baseline',
                      'active-job','job-after-hash','wrong-sha','foreign-inode','foreign-store','receipt-binding'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                events=[];saved={};quiet=[0,0]
                receipt={'status':'passed','phase':'upload-only','pending':False,'ha_backup_id':upload.HA_ID,
                         'upload_id':'u0123456789abcdef','sha256':upload.FIXTURE_SHA,'bytes':upload.FIXTURE_BYTES,
                         'expected_store_absent_before':True,'ha_file_identity':{'dev':1,'ino':2},'sidecar_sha256':'a'*64}
                proof={'status':'passed','ha_backup_id':upload.HA_ID,'sha256':upload.FIXTURE_SHA,'bytes':upload.FIXTURE_BYTES,
                       'identity':{'dev':1,'ino':2},'sidecar_sha256':'a'*64,'allocated_bytes':upload.FIXTURE_BYTES}
                lease={'retain_verified_ha_on_preconversion_refusal':fault!='optout','retained_upload_receipt_sha256':'b'*64}
                state={'ha_backup_id':upload.HA_ID,'upload_id':None,'retained_upload_receipt_sha256':'b'*64,
                       'requests':{'check':{'command':'ha-check-start'}}}
                run=types.SimpleNamespace(created_store=upload.HA_ID,converted=None,safety=None)
                def cleanup():
                    events.append('ha-delete' if run.created_store else 'other-owned-cleanup')
                    run.created_store=None
                run.cleanup=cleanup
                def verify(*args):events.append('fresh-full-ha-proof');return copy.deepcopy(proof)
                def quiescent(*args,**kwargs):events.append('native-jobs-proof');return {'active_jobs':quiet.pop(0)}
                if fault in ('convert-request','restore-request'):
                    state['requests']['later']={'command':'ha-convert-start' if fault=='convert-request' else 'restore-start'}
                if fault=='converted':run.converted='owned-converted'
                if fault=='active-job':quiet=[1]
                if fault=='job-after-hash':quiet=[0,1]
                if fault=='wrong-sha':proof['sha256']='c'*64
                if fault=='foreign-inode':proof['identity']['ino']=99
                if fault=='foreign-store':state['ha_backup_id']='ha-'+'f'*20
                if fault=='receipt-binding':state['retained_upload_receipt_sha256']='c'*64
                driver=types.SimpleNamespace(STATE=state,save_state=lambda:events.append('receipt-saved'))
                ev=types.SimpleNamespace(save=lambda name,value:saved.update({name:copy.deepcopy(value)}),
                                         check=lambda *args:True)
                args=types.SimpleNamespace(retained_upload=receipt)
                ordinary=fault in ('optout','convert-request','restore-request','converted')
                with patch.object(upload,'verify_retained',side_effect=verify),\
                        patch.object(control.wake,'device',side_effect=quiescent),\
                        patch.object(flow,'LAB',Path(tmp)),patch.object(Path,'home',return_value=Path(tmp)):
                    if fault and not ordinary:
                        with self.assertRaises((ValueError,RuntimeError)):
                            flow.cleanup_after_refusal(run,args,lease,driver,ev,9999999999,
                                                       baseline_safe=fault!='baseline',baseline_exact=fault!='exact-baseline')
                        self.assertNotIn('ha-delete',events)
                        self.assertNotIn('other-owned-cleanup',events)
                        self.assertEqual(run.created_store,upload.HA_ID)
                    else:
                        retained=flow.cleanup_after_refusal(run,args,lease,driver,ev,9999999999,
                                                           baseline_safe=True,baseline_exact=True)
                        self.assertEqual(retained,not ordinary)
                        if ordinary:
                            self.assertEqual(events,['ha-delete'])
                        else:
                            self.assertEqual(run.created_store,upload.HA_ID)
                            self.assertEqual(events[:3],['native-jobs-proof','fresh-full-ha-proof','native-jobs-proof'])
                            self.assertIn('other-owned-cleanup',events);self.assertNotIn('ha-delete',events)
                            self.assertEqual(saved['preconversion-owned-ha-retained.json']['current_proof'],proof)
                            self.assertEqual(state['retained_verified_ha_id'],upload.HA_ID)
