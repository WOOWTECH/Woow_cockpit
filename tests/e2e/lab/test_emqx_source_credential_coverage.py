"""Generated source credential/refresh consumer coverage only; no lab or review.

Actual Capture/join, API registration, native receipts and final scanners run;
HTTP/native process outputs are generated. No live restore/MQTT is claimed.
"""
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import emqx_real_owner_workflow as workflow
import emqx_real_owner_transport as transport
import test_emqx_native_object_integrity as native_fixtures
from emqx_private_boundary import PrivateFailure


class SourceCredentialCoverageTests(unittest.TestCase):
    def test_distinct_phase_jwts_api_values_and_native_values_survive_final_scan(self):
        fixture=native_fixtures.NativeObjectTests()
        self.addCleanup(fixture.doCleanups);fixture.setUp()
        session=fixture.session
        clients=workflow.SourceClients(dict(zip(('retained_topic1','retained_topic2'),fixture.topics)))
        credentials=workflow.SourceAPICredentials(tuple(fixture.credentials[k] for k in workflow.API_FIELDS))
        scanner=session.registry;observations=[];markers=[]
        with patch.object(workflow,'_inspect',return_value=fixture.doc[0]), \
             patch.object(workflow,'fixture_quiescence',side_effect=lambda p:fixture.quiesce()):
            for phase in range(3):
                fixture.api_mode=True
                # Every login creates distinct tokens; no reused fixed-JWT proof.
                prefix=('generated-jwt-phase-%d-'%phase).encode()
                fixture.edit_http=lambda url,raw,prefix=prefix:raw.replace(b'generated-jwt-',prefix)
                api_value='generated-api-returned-phase-%d'%phase
                fixture.documents['connectors'][0]['generated_dynamic_field']=api_value
                observed=workflow._source_api_activity(fixture.provision,scanner,session,clients,credentials)
                observations.append(observed)
                for user in (b'admin',b'b1ops'):
                    token=prefix+user;markers.extend((token,b'Bearer '+token))
                markers.append(api_value.encode())
                fixture.api_mode=False
                fixture.hash=('generated-native-returned-phase-%d'%phase).encode()
                markers.append(fixture.hash)
                scanner=fixture.native(prior_registry=scanner)
        # Actual consumers after normal held source/issued-context exit retain all
        # generations and the same mutable runtime; nothing is re-sealed/rebound.
        self.assertTrue(fixture.doCleanups())
        receipt=workflow.final_private_receipt(scanner)
        workflow._scan_source_api_receipt(receipt,observations,session)
        self.assertEqual(len(scanner._generations),3)
        markers.extend(credentials.fields)
        basic=credentials.fields[4]+b':'+credentials.fields[5]
        markers.extend((basic,b'Basic '+base64.b64encode(basic)))
        for value in markers:
            with self.subTest(kind='registered-private-value'):
                for payload in (value,base64.b64encode(value),value.hex().encode()):
                    with self.assertRaises(PrivateFailure):scanner.scan(payload)
                # Actual final API consumer rejects the same bytes, not just the
                # registry method in isolation. Native-only values are covered by
                # the final native chain, not falsely claimed as API observations.
                if value not in [b'generated-native-returned-phase-%d'%i for i in range(3)]:
                    with self.assertRaises(workflow.RealOwnerRefused):
                        workflow._scan_source_api_receipt(value,observations,session)
        late=b'generated-login-after-all-captures'
        session.registry._runtime.register_bundle({'runtime-login-token':[late]})
        with self.assertRaises(PrivateFailure):scanner.scan(late)
        with self.assertRaises(workflow.RealOwnerRefused):
            workflow._scan_source_api_receipt(late,observations,session)

    def test_each_missing_normal_source_api_field_refuses_actual_prefix(self):
        mqtt=(b'B1_MQTT_USER1=b1-sensor\nB1_MQTT_PW1=generated-one\n'
              b'B1_MQTT_USER2=b1-gateway\nB1_MQTT_PW2=generated-two\n'
              b'B1_MQTT_USER3=generated-third\nB1_MQTT_PW3=generated-three\n')
        common={'B1_EMQX_ADMIN_PW':'generated-admin','B1_EMQX_USER2':'b1ops',
                'B1_EMQX_USER2_PW':'generated-ops'}
        pairs=[b'b1/retained/one',b'generated-one-payload',b'b1/retained/two',b'generated-two-payload']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);client=root/'client.env';key=root/'key.env'
            for arch,mode in (('ARM',workflow.SOURCE_MODES[0]),('X86',workflow.SOURCE_MODES[1])):
                api={'B1_'+arch+'_EMQX_API_KEY':'generated-key','B1_'+arch+'_EMQX_API_SECRET':'generated-secret'}
                for missing in (*common,*api):
                    with self.subTest(arch=arch,missing=missing):
                        client.write_bytes(mqtt+b''.join((k+'='+v+'\n').encode() for k,v in common.items() if k!=missing))
                        key.write_bytes(b''.join((k+'='+v+'\n').encode() for k,v in api.items() if k!=missing))
                        client.chmod(0o600);key.chmod(0o600)
                        with patch.object(transport,'CLIENT_CREDS',client),patch.object(transport,'KEY_CREDS',key), \
                             patch.object(transport,'retained_expectations',return_value=pairs), \
                             patch.object(transport.subprocess,'Popen') as child:
                            with self.assertRaises(ValueError):transport.client_prefix(mode)
                        child.assert_not_called()
