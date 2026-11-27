"""Two bounded tests for the separately leased failed-unit protocol; no device."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_quiesce as m


class Device:
    def __init__(self,root):
        self.path=Path(root)/'intent.private.json';self.j={};self.actions=[];self.lose=None
        meta={'uid':1019,'gid':1019,'mode':0o644,'sha256':'a'*64}
        before={'files':{m.QFILE:meta},'containers':{'original':'b'*64},'running':['original'],
                'active_jobs':[],'images':['c'*64],'image_refs':{}}
        self.receipt={'before':before,'derived_image':'d'*64}
        inventory=deepcopy(before);inventory['images'].append('d'*64)
        inventory['image_refs'][m.driver.plan.APP_TAG]='d'*64
        self.facts={'unit':dict(zip(m.FIELDS,('headscale.service','loaded','activating','auto-restart','exit-code',
            '42','0','1','1','generated',m.QFILE,'/run/user/1019/systemd/generator/headscale.service'))),
            'source':deepcopy(meta),'fragment':dict(meta,sha256='e'*64),'inventory':inventory}

    def read(self,_full):return deepcopy(self.facts)
    def save(self):m.source.save(self.path,self.j)
    def restart_controller(self):
        self.j=json.loads(self.path.read_text())
        return self.controller()
    def controller(self):
        return m.Protocol(self.receipt,self.j,read=self.read,act=self.act,save=self.save)
    def act(self,verb):
        # Check the actual durable file, not only the live in-memory dictionary.
        wal=json.loads(self.path.read_text());self.actions.append(verb)
        if verb=='stop':
            assert wal['pending']=='pause' and wal['original']['unit']['MainPID']=='0'
            assert wal['original']['source']==self.receipt['before']['files'][m.QFILE]
            self.facts['unit'].update(ActiveState='inactive',SubState='dead',Result='success')
        else:
            assert verb=='start' and wal['pending']=='resume' and wal['start_intent'] is True
            self.facts['unit'].update(ActiveState='activating',SubState='auto-restart',Result='exit-code',NRestarts='1')
        if self.lose==verb:self.lose=None;raise TimeoutError('lost unit reply')


class QuiescenceTests(unittest.TestCase):
    def test_durable_stop_and_fresh_resume_adopt_lost_replies_without_replaying_start(self):
        compile(m.program(),'<actual compiled metadata reader>','exec')
        for lose in (False,True):
            with self.subTest(lost_replies=lose),tempfile.TemporaryDirectory() as root:
                d=Device(root)
                if lose:
                    d.lose='stop'
                    with self.assertRaises(TimeoutError):d.controller().pause()
                    self.assertEqual(json.loads(d.path.read_text())['pending'],'pause')
                    d.lose='start'
                    with self.assertRaises(TimeoutError):d.restart_controller().resume()
                    self.assertEqual(json.loads(d.path.read_text())['pending'],'resume')
                else:
                    d.controller().pause();self.assertTrue(d.j['paused'])
                d.restart_controller().resume()
                self.assertEqual(d.actions,['stop','start'])
                self.assertTrue(d.j['resumed']);self.assertIsNone(d.j['pending'])
                self.assertTrue(m.known_failure(d.j['last_resume']['unit']))
                self.assertEqual(m.failure(d.j['last_resume']['unit']),m.failure(d.j['original']['unit']))
                self.assertEqual(d.j['original']['unit']['NRestarts'],'42')

    def test_healthy_unknown_or_foreign_binding_never_pauses_and_changed_config_never_resumes(self):
        cases=(('unit','ActiveState','active'),('unit','SubState','running'),('unit','Result','success'),
               ('unit','MainPID','9'),('unit','NRestarts','0'),('unit','SourcePath','/tmp/foreign.container'),
               ('source','sha256','f'*64))
        for field,key,value in cases:
            with self.subTest(field=field,key=key),tempfile.TemporaryDirectory() as root:
                d=Device(root);d.facts[field][key]=value
                with self.assertRaises(ValueError):d.controller().pause()
                self.assertEqual(d.actions,[])
        with tempfile.TemporaryDirectory() as root:
            d=Device(root);d.controller().pause();d.facts['fragment']['sha256']='f'*64
            with self.assertRaisesRegex(ValueError,'foreign unit/config'):d.restart_controller().resume()
            self.assertEqual(d.actions,['stop']);self.assertEqual(d.j['pending'],'resume')


if __name__=='__main__':unittest.main()
