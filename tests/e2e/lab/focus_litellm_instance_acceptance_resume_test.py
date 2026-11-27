"""Fresh controller recovery with the saved80 REAL reader and persisted values."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime,timezone

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_run as m


class Evidence:
    """Only the output boundary is replaced; the reader and Run are real."""
    def __init__(self,*_args,**_kwargs):self.results=[]
    def check(self,label,ok,detail=None):self.results.append({'ok':ok});return ok


class CredentialResumeTests(unittest.TestCase):
    def make(self,root,saved):
        root=Path(root);secret=root/'reader';secret.mkdir()
        (secret/'b1-creds.env').write_text('LAB_USER=tester\n')
        (secret/'ha-import-creds.env').write_text('HA_BACKUP_KEY=test-only-backup-key\nLITELLM_TEST_VKEY=sk-test-only-ha-key\n')
        (secret/'dev-d-markers.json').write_text(json.dumps({'fixture':'test-only-marker'}))
        args=SimpleNamespace(receipt=root/'case.private.json')
        lease={'name':'woowbk_focus_litellm_a2c39e761b04',
               'expires_utc':datetime.fromtimestamp(time.time()+3600,timezone.utc).isoformat()}
        return secret,args,lease

    def test_two_controller_instances_resume_same_credentials_with_real_reader(self):
        saved=m.load_saved()
        with tempfile.TemporaryDirectory() as root:
            secret,args,lease=self.make(root,saved);expected=Path(args.receipt).with_suffix('.saved80-private.json')
            ha={'master_key':'test-only-master','salt_key':'test-only-salt',
                'pg_password':'test-only-pg-password','ui_password':'test-only-ui-password'}
            observations=[]
            def decode(_key):
                # External original-archive decoding is stubbed. The actual
                # saved Run.load_secrets and actual reader registration run.
                observations.append(saved.drv.state_path());return ha
            with patch.object(saved.drv,'SECRET_DIR',secret),patch.object(saved,'Ev',Evidence),patch.object(saved,'ha_secret_files',side_effect=decode):
                first=m.Controller(args,lease,saved);first.credentials()
                original=dict(first.r['generated_credentials'])
                first.r['generated_credentials']['OWN_INSTANCE_OUTSIDE_PASSWORD']='test-only-later-password'
                first.r['before_probe']={'secret_sha256':{'litellm-salt-key':'initial-salt-hash'}};first.save()
                # Simulate a freshly imported saved driver, not an initialized
                # same-process Controller.run cache.
                saved.drv.state_path=lambda:Path(root)/'legacy-must-not-be-used.json'
                second=m.Controller(args,lease,saved)
                with patch.object(saved.pysecrets,'token_hex',side_effect=AssertionError('resume regenerated a credential')):
                    second.credentials()
                self.assertIsInstance(second.run.args.secrets,saved.drv.Secrets)
                for name,value in original.items():self.assertEqual(second.run.args.secrets[name],value)
                self.assertEqual(second.run.own_key,original['OWN_LITELLM_KEY'])
                self.assertEqual(second.run.args.secrets['OWN_INSTANCE_OUTSIDE_PASSWORD'],'test-only-later-password')
                self.assertEqual(second.run.ha_salt_sha,hashlib.sha256(ha['salt_key'].encode()).hexdigest())
                self.assertEqual(second.run.before,first.r['before_probe'])
                self.assertEqual(observations,[expected,expected])
                self.assertFalse((Path(root)/'legacy-must-not-be-used.json').exists())
                for name,value in ha.items():self.assertEqual(second.run.args.secrets['HA_LITELLM_'+name.upper()],value)

    def test_incomplete_persisted_reader_refuses_before_archive_decode_or_generation(self):
        saved=m.load_saved()
        with tempfile.TemporaryDirectory() as root:
            secret,args,lease=self.make(root,saved)
            c=m.Controller(args,lease,saved);c.r['generated_credentials']={'OWN_LITELLM_KEY':'test-only-existing-key'};c.save()
            before=Path(args.receipt).read_bytes()
            with patch.object(saved.drv,'SECRET_DIR',secret),patch.object(saved,'Ev',Evidence),\
                 patch.object(saved,'ha_secret_files',side_effect=AssertionError('must not decode incomplete state')),\
                 patch.object(saved.pysecrets,'token_hex',side_effect=AssertionError('must not generate incomplete state')):
                with self.assertRaises(ValueError):c.credentials()
            self.assertIsNone(c.run);self.assertEqual(Path(args.receipt).read_bytes(),before)

    def test_absent_persisted_credentials_refuse_fresh_recovery_without_generation(self):
        for by_phase in (True,False):
            with self.subTest(by_phase=by_phase),tempfile.TemporaryDirectory() as root:
                saved=m.load_saved();secret,args,lease=self.make(root,saved)
                args.phase='recover' if by_phase else 'flow'
                first=m.Controller(args,lease,saved);first.save()
                # A fresh recovery process must treat a missing entire field
                # as lost state, even though a first flow may generate it.
                c=m.Controller(args,lease,saved);c.recovering=not by_phase
                before=Path(args.receipt).read_bytes()
                with patch.object(saved.drv,'SECRET_DIR',secret),patch.object(saved,'Ev',Evidence),\
                     patch.object(saved.Run,'load_secrets',side_effect=AssertionError('recovery must not generate')),\
                     patch.object(saved,'ha_secret_files',side_effect=AssertionError('missing state must not decode')):
                    with self.assertRaisesRegex(ValueError,'missing persisted case credentials'):c.credentials()
                self.assertIsNone(c.run)
                self.assertEqual(Path(args.receipt).read_bytes(),before)
                self.assertNotIn('generated_credentials',c.r)


if __name__=='__main__':unittest.main()
