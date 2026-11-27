"""Three bounded file tests: actual copy/return plus corruption/foreign negatives."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_safeties as safety

NAME='woowbk_focus_n8n_abcdef012345'
JID='j20261127T010101Z-abcdef01'
FULL='20261127T010000Z-abcdef01'


class PreservationTests(unittest.TestCase):
    def setup_files(self,folder):
        root=Path(folder);archives=root/'archives';archives.mkdir(mode=0o700);known={}
        for i,bid in enumerate(safety.KNOWN):
            arc=archives/(bid+'.tar');idx=archives/(bid+'.json')
            common.atomic(arc,('synthetic archive '+str(i)).encode(),mtime_ns=1000000123+i)
            record={'id':bid,'type':'safety','apps':[{'id':x} for x in safety.KNOWN[bid]['apps']],
                    'sha256':common.read_regular(arc)[1]['sha256']}
            common.atomic(idx,json.dumps(record).encode(),mtime_ns=2000000123+i)
            known[bid]={'index_sha256':common.read_regular(idx)[1]['sha256'],'apps':safety.KNOWN[bid]['apps'],
                'bytes':arc.stat().st_size,'mtime_ns':arc.stat().st_mtime_ns,'index_mtime_ns':idx.stat().st_mtime_ns}
        common.atomic(archives/'20261118T095520Z-33eb7474.tar',b'synthetic original MANUAL baseline',mtime_ns=3000000123)
        obj=safety.PreservedSafeties(common,NAME,parent=root/'private',archives=archives,known=known)
        return obj,obj.current()

    def prune(self,obj):
        for bid in obj.known:
            for suffix in ('.tar','.json'):(obj.archives/(bid+suffix)).unlink()

    def test_actual_copy_return_requires_successful_own_prune_event_and_initial_return(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,before=self.setup_files(folder);obj.prepare();obj.verify();self.assertEqual(obj.current(),before)
            self.assertEqual(obj.store.path.stat().st_mode&0o777,0o700)
            jobs=Path(folder)/'jobs';jobs.mkdir(mode=0o700)
            job={'id':JID,'type':'restore','state':'succeeded','request_id':NAME+'-recover',
                 'unit':'woowtech-backup-'+JID+'.service','params':{'backup_id':FULL,'apps':['n8n']},
                 'result':{'rolled_back':False,'health':[{'id':'n8n/health-1','status':'ok'}]}}
            common.atomic(jobs/(JID+'.json'),json.dumps(job).encode())
            log=''.join('2026-11-27T01:01:01Z 已刪除較舊的還原前備份 '+bid+'\n' for bid in obj.known)
            common.atomic(jobs/(JID+'.log'),log.encode())
            def call(argv,**kwargs):
                self.assertEqual(argv,['systemctl','show','woowtech-backup-'+JID+'.service','-P','ActiveState'])
                return SimpleNamespace(stdout=b'inactive\n')
            c=SimpleNamespace(read_regular=common.read_regular,digest=common.digest,call=call)
            with patch.object(safety,'JOBS',jobs):witness,returned=safety.pruning_witnesses(c,NAME,[JID],FULL)
            self.assertTrue(returned);self.assertEqual(set(witness),set(obj.known));self.prune(obj)
            with self.assertRaises(ValueError):obj.put_back({},original_returned=True)
            with self.assertRaises(ValueError):obj.put_back(witness,original_returned=False)
            result=obj.put_back(witness,original_returned=True)
            self.assertEqual(result['restored_files'],4);self.assertEqual(obj.current(),before)
            self.assertTrue(obj.store.path.exists());obj.verify()
            # An event in a FAILED job is insufficient, even with matching text.
            job['state']='failed';common.atomic(jobs/(JID+'.json'),json.dumps(job).encode())
            with patch.object(safety,'JOBS',jobs):self.assertEqual(safety.pruning_witnesses(c,NAME,[JID],FULL),({},False))

    def test_corrupted_private_copy_stops_before_any_missing_original_is_recreated(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,before=self.setup_files(folder);obj.prepare();self.prune(obj)
            meta=next(iter(obj.store.state['original'].values()))
            (obj.store.path/meta['copy']).write_bytes(b'corrupted private copy')
            with self.assertRaises(ValueError):obj.put_back({b:{} for b in obj.known},original_returned=True)
            self.assertFalse(any((obj.archives/(bid+'.tar')).exists() for bid in obj.known))
            self.assertTrue(obj.store.path.exists())
            manual=str(obj.archives/'20261118T095520Z-33eb7474.tar');self.assertEqual(obj.current()[manual],before[manual])

    def test_foreign_content_or_attributes_never_overwritten_and_other_pair_not_returned(self):
        for foreign in ('bytes','mode'):
            with self.subTest(foreign=foreign),tempfile.TemporaryDirectory() as folder:
                obj,_=self.setup_files(folder);obj.prepare();self.prune(obj);bids=list(obj.known)
                p=obj.archives/(bids[-1]+'.tar');meta=obj.store.state['original'][str(p)]
                data=common.read_regular(obj.store.path/meta['copy'])[0] if foreign=='mode' else b'foreign bytes'
                common.atomic(p,data,mode=0o640 if foreign=='mode' else 0o600,mtime_ns=meta['mtime_ns'])
                foreign_meta=common.read_regular(p)[1]
                with self.assertRaises(ValueError):obj.put_back({b:{} for b in obj.known},original_returned=True)
                self.assertEqual(common.read_regular(p)[1],foreign_meta)
                self.assertFalse((obj.archives/(bids[0]+'.tar')).exists());self.assertTrue(obj.store.path.exists())


if __name__=='__main__':unittest.main()
