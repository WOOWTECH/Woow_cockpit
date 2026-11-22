"""Generated issued provision/API results; process boundary only, no real MQTT."""
from contextlib import contextmanager
import copy
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_source_mqtt_negative as m
import emqx_owner_fixture_files as files
import test_emqx_source_api_validator as api_tests
from emqx_private_boundary import PrivateFailure


class NegativeTests(unittest.TestCase):
    quiesce=api_tests.SourceAPITests.quiesce
    run_api=api_tests.SourceAPITests.run_api

    def setUp(self):
        api_tests.SourceAPITests.setUp(self)
        self.api_mode=True
        self.documents['banned']['data'][0]['until']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(timespec='seconds')
        self.observed=self.run_api()
        self.api_mode=False
        self.clients=m.SourceClients({'gateway_user':b'b1-gateway','gateway_password':b'generated-gateway-password'})
        self.runtime.register_bundle({'runtime-login-input':list(self.clients.fields.values())})
        self.active=set();self.config_roots=[];self.probes=[];self.reasons=[134,138]
        self.run_error=False;self.remove_failure=False;self.output_override=None;self.name_collision=False

    def podman(self,*args,**kwargs):
        if getattr(self,'api_mode',True): return api_tests.SourceAPITests.podman(self,*args,**kwargs)
        self.commands.append((args,kwargs))
        if args[:2]==('container','inspect'):
            return SimpleNamespace(returncode=0,stdout=json.dumps(self.doc).encode())
        if args[:2]==('container','exists'):
            return SimpleNamespace(returncode=0 if args[2] in self.active or self.name_collision else 1,stdout=b'',stderr=b'')
        if args[0]=='rm':
            self.active.discard(args[-1])
            return SimpleNamespace(returncode=1 if self.remove_failure else 0,stdout=b'',stderr=b'')
        self.assertEqual(args[0],'run')
        name=args[args.index('--name')+1];self.active.add(name);self.probes.append(name)
        self.assertIn('--network=container:'+self.cid,args)
        self.assertIn(m.CLIENT,args);self.assertIn('--pull=never',args);self.assertIn('--log-driver=none',args)
        self.assertIn('--timeout=15',args);self.assertIn('mqttv5',args)
        self.assertEqual(kwargs,dict(timeout=20,max_output=65536,check=False))
        env=[args[i+1] for i,v in enumerate(args) if v=='-e']
        self.assertEqual(env,['HOME=/work','XDG_CONFIG_HOME=/work'])
        self.assertNotIn('generated-gateway-password',str(args));self.assertNotIn('-P',args);self.assertNotIn('-u',args)
        root=Path(args[args.index('-v')+1].removesuffix(':/work:ro'));self.config_roots.append(root)
        self.assertEqual(root.parent,Path('/dev/shm'))
        self.assertEqual(root.stat().st_mode&0o777,0o700)
        path=root/'mosquitto_sub';self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(path.stat().st_uid,os.geteuid())
        config=path.read_bytes();self.assertIn(b'-t b1/retained/#\n',config)
        for value in (b'generated-gateway-password',m.BANNED):
            with self.assertRaises(PrivateFailure): self.observed.scan(value)
        if len(self.probes)==1:
            self.assertNotIn(b'-u ',config);self.assertNotIn(b'-P ',config)
            self.assertIn(b'-i '+name.encode()+b'\n',config)
        else:
            self.assertIn(b'-i b1-banned-client\n',config)
            self.assertIn(b'-u b1-gateway\n-P generated-gateway-password\n',config)
        if self.run_error:raise TimeoutError('generated-private-timeout')
        code=self.reasons[len(self.probes)-1]
        output=b'Client '+name.encode()+b' received CONNACK ('+str(code).encode()+b')\n'
        return SimpleNamespace(returncode=code,stdout=output if self.output_override is None else self.output_override,stderr=b'')

    def run_negative(self,**changes):
        kwargs=dict(provision=self.provision,expected_container_id=self.cid,clients=self.clients,
                    source_api=self.observed,quiesce=self.quiesce)
        kwargs.update(changes)
        return m.validate_source_mqtt_negative(**kwargs)

    def refuse(self,**changes):
        with self.assertRaisesRegex(PrivateFailure,'^source-negative-refused$'):self.run_negative(**changes)
        self.assertFalse(self.active)
        self.assertTrue(all(not p.exists() for p in self.config_roots))

    def test_actual_issued_context_current_cid_private_configs_and_explicit_reasons(self):
        old=files._record(self.cap)[0]['cid']
        result=self.run_negative()
        self.assertEqual(len(self.probes),2);self.assertNotEqual(*self.probes)
        self.assertFalse(self.active);self.assertTrue(all(not p.exists() for p in self.config_roots))
        self.assertEqual(files._record(self.cap)[0]['cid'],old)
        self.assertEqual(result.private_facts()['banned_connack'],138)
        self.assertEqual(result.private_facts()['anonymous_connack'],134)
        with self.assertRaises(PrivateFailure):result.scan(b'generated-gateway-password')

    def test_anonymous_authorization_reason135_is_explicitly_accepted(self):
        self.reasons=[135,138];self.run_negative()

    def test_success_timeout_unrelated_denial_and_missing_connack_are_not_passes(self):
        for code,raw in [(0,b'received CONNACK (0)'),(27,b'Timed out'),(135,b'received CONNACK (138)'),
                         (134,b'Error: not authorized'),(134,b'received CONNACK (134)\nreceived CONNACK (134)')]:
            self.probes.clear();self.reasons=[code,138];self.output_override=raw;self.refuse()

    def test_banned_needs138_not_generic_bad_credentials_or_timeout(self):
        for code in (0,134,135,27):
            self.probes.clear();self.reasons=[134,code];self.refuse()

    def test_timeout_and_remove_failure_clean_private_files_and_refuse(self):
        self.run_error=True;self.refuse()
        self.run_error=False;self.probes.clear();self.remove_failure=True;self.refuse()

    def test_missing_expired_or_near_expiry_ban_refuses_before_client(self):
        row=self.observed._documents['banned']['data'][0]
        for value in (None,0,'unknown','2020-01-01T00:00:00Z',
                      (datetime.now(timezone.utc)+timedelta(seconds=30)).isoformat(timespec='seconds')):
            row['until']=value;self.refuse()
        self.assertEqual(self.probes,[])

    def test_explicit_observed_infinity_supported_without_inventing_expiry(self):
        self.observed._documents['banned']['data'][0]['until']='infinity'
        self.run_negative()

    def test_missing_or_unregistered_gateway_input_refuses(self):
        self.clients.fields['gateway_password']=b'unregistered-password';self.refuse()
        self.assertEqual(self.probes,[])

    def test_wrong_pin_cid_network_and_closed_original_cap_refuse(self):
        for change in (lambda d:d.update(Image='0'*64),lambda d:d.update(Id='c'*64),
                       lambda d:d['HostConfig'].update(NetworkMode='host')):
            saved=copy.deepcopy(self.doc);change(self.doc[0]);self.refuse();self.doc=saved
        files.revoke(self.cap);self.refuse();self.assertEqual(self.probes,[])

    def test_collision_does_not_delete_someone_elses_client(self):
        self.name_collision=True;self.refuse()
        self.assertFalse(any(args[0]=='rm' for args,kwargs in self.commands))

    def test_late_identity_change_and_overall_deadline_refuse(self):
        original=self.podman
        def changed(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='run':self.doc[0]['Config']['Env'].append('UNEXPECTED=value')
            return result
        self.runner.podman=changed;self.refuse()
        self.probes.clear()
        with patch.object(m.time,'monotonic',side_effect=[0,121]):self.refuse()

    def test_oversized_output_and_interruption_still_cleanup(self):
        self.output_override=b'x'*65537;self.refuse()
        original=self.podman
        def interrupted(*args,**kwargs):
            if args[0]=='run':
                original(*args,**kwargs)
                raise KeyboardInterrupt()
            return original(*args,**kwargs)
        self.probes.clear();self.output_override=None;self.runner.podman=interrupted
        with self.assertRaisesRegex(PrivateFailure,'^source-negative-cancelled$'):self.run_negative()
        self.assertFalse(self.active);self.assertTrue(all(not p.exists() for p in self.config_roots))

    def test_unverified_ram_parent_and_lease_failure_refuse(self):
        with patch.object(m,'_ram_client_parent',side_effect=ValueError):self.refuse()
        @contextmanager
        def bad_lease():
            yield
            raise ValueError('generated-private-lease')
        self.refuse(quiesce=bad_lease)


if __name__=='__main__':unittest.main()
