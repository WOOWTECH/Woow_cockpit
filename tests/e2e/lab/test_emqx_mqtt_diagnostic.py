"""Actual MQTT consumer parsing with generated transport replies, not lab proof."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import emqx_real_owner_workflow as m
import test_emqx_real_owner_workflow as fixtures


class ConsumerDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.FoundationTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.clients=self.fixture.clients()
        self.clients.fields.update(lab_user=b'lab',lab_password=b'generated-lab-password')

    def reply(self,provision,clients,role,**kw):
        if kw.get('publish'):
            return SimpleNamespace(returncode=0,stdout=b'received CONNACK (0)\nreceived PUBACK (Mid: 1, RC:0)\n',stderr=b'')
        if kw.get('wrong_password'):return self.fixture.mqtt_reply(code=134,connack=134)
        if kw.get('retained'):
            i=1 if kw['topic'].endswith('/one') else 2
            return SimpleNamespace(returncode=0,stdout=b'1:'+clients.fields['retained_topic'+str(i)]+b':'+clients.fields['retained_payload'+str(i)].hex().encode()+b'\n',stderr=b'')
        return self.fixture.mqtt_reply(suback=135 if kw['topic']=='b1/secret/#' else 1)

    def run_consumer(self):
        m._validate_phase_mqtt(self.fixture.provision,self.clients,m.IMPORTED_MNESIA)

    def test_each_real_consumer_call_has_fixed_phase_and_private_exception_is_masked(self):
        steps=('publish_sensor','publish_lab','login_sensor','login_gateway','login_third',
               'sensor_secret','wrong_password','retained_one','retained_two')
        private='GENERATED-PRIVATE-EXCEPTION-NEVER-PUBLISH'
        for index,step in enumerate(steps,1):
            calls=[]
            def transport(*args,**kwargs):
                calls.append(None)
                if len(calls)==index:raise TimeoutError(private)
                return self.reply(*args,**kwargs)
            before=m._MQTT_STATE.get()
            with self.subTest(step=step),patch.object(m,'_mqtt_private',side_effect=transport):
                with self.assertRaises(m.RealOwnerRefused) as caught:self.run_consumer()
                self.assertEqual(caught.exception.phase,'mqtt_'+step+'_run')
                self.assertIn(caught.exception.phase,m.PHASES)
                self.assertNotIn(private,str(caught.exception)+repr(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual(before,m._MQTT_STATE.get())

    def test_return_codes_and_wire_reasons_are_not_confused_with_allow_or_timeout(self):
        cases=((0,b'received CONNACK (134)','connack_134'),
               (0,b'received CONNACK (0)\nreceived PUBACK (Mid: 1, RC:135)','puback_135'),
               (27,b'generated-private-body','exit_27'),
               (199,b'generated-private-body','exit_other'),
               (0,b'received CONNACK (999)','connack_other'),
               (0,b'received CONNACK (0)\nreceived PUBACK (Mid: 1, RC:999)','puback_other'))
        for code,body,reason in cases:
            with self.subTest(reason=reason),patch.object(m,'_mqtt_private',return_value=SimpleNamespace(returncode=code,stdout=body,stderr=b'')):
                with self.assertRaises(m.RealOwnerRefused) as caught:self.run_consumer()
                self.assertEqual(caught.exception.phase,'mqtt_publish_sensor_'+reason)
                self.assertNotIn('999',caught.exception.phase)
                self.assertNotIn('generated-private',str(caught.exception))

    def test_exact_retained_oracle_failure_has_payload_phase(self):
        def transport(*args,**kwargs):
            result=self.reply(*args,**kwargs)
            if kwargs.get('retained'):result.stdout=b'generated-private-wrong-payload'
            return result
        with patch.object(m,'_mqtt_private',side_effect=transport):
            with self.assertRaises(m.RealOwnerRefused) as caught:self.run_consumer()
        self.assertEqual(caught.exception.phase,'mqtt_retained_one_payload_mismatch')

    def test_success_and_invalid_input_do_not_reuse_previous_failure_phase(self):
        with patch.object(m,'_mqtt_private',side_effect=self.reply):self.run_consumer()
        with self.assertRaises(m.RealOwnerRefused) as caught:
            m._validate_phase_mqtt(self.fixture.provision,object(),m.IMPORTED_MNESIA)
        self.assertEqual(caught.exception.phase,'mqtt')
        for function in (m._mqtt_step,m._mqtt_kind):
            before=m._MQTT_STATE.get()
            with self.assertRaises(ValueError):function('generated-private-label')
            self.assertEqual(before,m._MQTT_STATE.get())
