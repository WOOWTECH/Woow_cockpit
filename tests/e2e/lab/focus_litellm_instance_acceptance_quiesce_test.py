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
        self.path=Path(root)/'intent.private.json';self.j={};self.actions=[];self.lose=None;self.glitches=[];self.reads=0
        meta={'uid':1019,'gid':1019,'mode':0o644,'sha256':'a'*64}
        before={'files':{m.QFILE:meta},'containers':{'original':'b'*64},'external_containers':{},'running':['original'],
                'active_jobs':[],'images':['c'*64],'image_refs':{}}
        self.receipt={'before':before,'derived_image':'d'*64}
        inventory=deepcopy(before);inventory['images'].append('d'*64)
        inventory['image_refs'][m.driver.plan.APP_TAG]='d'*64
        self.facts={'unit':dict(zip(m.FIELDS,('headscale.service','loaded','activating','auto-restart','exit-code',
            '42','0','1','1','generated',m.QFILE,'/run/user/1019/systemd/generator/headscale.service'))),
            'source':deepcopy(meta),'fragment':dict(meta,sha256='e'*64),'inventory':inventory}

    def read(self,_full):
        facts=deepcopy(self.facts)
        if self.glitches:self.glitches.pop(0)(facts)       # the next look catches the failing unit in a transient state
        self.reads+=1
        return facts
    def save(self):m.source.save(self.path,self.j)
    def restart_controller(self):
        self.j=json.loads(self.path.read_text())
        return self.controller()
    def controller(self):
        return m.Protocol(self.receipt,self.j,read=self.read,act=self.act,save=self.save,sleep=lambda seconds:None)
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

    def test_the_failing_units_own_container_for_a_moment_does_not_stop_the_admission(self):
        # dev-d b9: .external_containers.headscale existed at the one moment the pause looked; nothing had been done
        def own_container(facts):facts['inventory']['external_containers']={'headscale':'9'*64}
        with tempfile.TemporaryDirectory() as root:
            d=Device(root);d.glitches=[own_container,own_container]
            d.controller().pause()
            self.assertTrue(d.j['paused']);self.assertEqual(d.actions,['stop']);self.assertEqual(d.reads,5)
            self.assertEqual([a['attempt'] for a in d.j['admission_attempts']],[1,2])
            for attempt in d.j['admission_attempts']:
                self.assertEqual(attempt['inventory_difference'],['.external_containers.headscale'])
                self.assertEqual(attempt['reason'],'strict original inventory differs')
            self.assertEqual(d.j['original']['inventory']['external_containers'],{})             # the look that was used is a clean one
            self.assertIn('headscale',d.j['initial_observation']['inventory']['external_containers'])  # the first look is still retained
            saved=json.loads(d.path.read_text());self.assertEqual(len(saved['admission_attempts']),2)
            self.assertNotIn('9'*64,json.dumps(saved['admission_attempts']))                  # names, never ids

    def test_a_unit_caught_between_two_restarts_is_looked_at_again(self):
        def starting(facts):facts['unit'].update(SubState='start',MainPID='77')
        with tempfile.TemporaryDirectory() as root:
            d=Device(root);d.glitches=[starting]
            d.controller().pause()
            self.assertTrue(d.j['paused']);self.assertEqual(len(d.j['admission_attempts']),1)
            self.assertEqual(d.j['admission_attempts'][0]['reason'],'unit is not the known failed auto-restart')
            self.assertEqual(d.j['admission_attempts'][0]['unit']['SubState'],'start')

    def test_a_difference_that_never_goes_away_still_refuses_without_acting(self):
        def own_container(facts):facts['inventory']['external_containers']={'headscale':'9'*64}
        with tempfile.TemporaryDirectory() as root:
            d=Device(root);d.glitches=[own_container]*m.ADMISSION_TRIES
            with self.assertRaisesRegex(ValueError,'strict original inventory differs'):d.controller().pause()
            self.assertEqual(d.actions,[]);self.assertEqual(d.reads,m.ADMISSION_TRIES)
            self.assertEqual(len(d.j['admission_attempts']),m.ADMISSION_TRIES)
            self.assertNotIn('paused',d.j);self.assertNotIn('original',d.j);self.assertNotIn('pending',d.j)
            with self.assertRaisesRegex(ValueError,'pause intent already exists'):d.restart_controller().pause()  # a fresh journal is needed

    def test_a_config_that_changed_meanwhile_is_never_admitted_even_when_the_unit_looks_right(self):
        def foreign(facts):facts['source']['sha256']='f'*64
        with tempfile.TemporaryDirectory() as root:
            d=Device(root);d.glitches=[foreign]*m.ADMISSION_TRIES
            with self.assertRaisesRegex(ValueError,'foreign unit/config'):d.controller().pause()
            self.assertEqual(d.actions,[])

    def test_the_admission_bounds_are_small_and_the_lease_bounds_did_not_change(self):
        self.assertLessEqual(m.ADMISSION_TRIES*(m.ADMISSION_WAIT_SECONDS+5),120)             # well inside the 300 s outer limit
        self.assertEqual(m.BOUNDS['outer_seconds'],300)
        self.assertNotIn('admission',' '.join(m.BOUNDS))                                     # leases bind BOUNDS exactly: not extended


if __name__=='__main__':unittest.main()
