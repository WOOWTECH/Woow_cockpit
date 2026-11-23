"""Generated issuance + simulated broker/podman process boundary; no real MQTT/HTTP.

The broker below is a test oracle written independently of the module: it
applies the original B1 rule semantics to what the generated clients publish.
No lab, restore or commercial claim is exercised by these tests.
"""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import re
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_controlled_delivery as m
import emqx_real_owner_workflow as workflow
import test_emqx_source_api_validator as api_tests
from emqx_b1_object_integrity import SourceObjects,_RECORDS,_leaves
from emqx_persisted_values import PersistedValues
from emqx_private_boundary import PrivateFailure
from emqx_semantic_readers import Values

RULE_ZERO={k:0 for k in ('matched','passed','failed','failed.exception','failed.no_result','actions.total',
    'actions.success','actions.failed','actions.failed.out_of_service','actions.failed.unknown','actions.discarded')}
ACTION_ZERO={k:0 for k in ('matched','success','failed','dropped','dropped.other','dropped.expired','dropped.queue_full',
    'dropped.resource_not_found','dropped.resource_stopped','late_reply','received','retried','queuing','inflight')}
NAME=re.compile(r'^woowbk-emqxlab-[0-9a-f]{8}-mqtt-[0-9a-f]{12}$')


def original_objects():
    # Literal original producer fields (B1 seed), not the module's constants.
    return {'rules':{
        'b1_rule_republish':{'sql':'SELECT payload.temp as t, clientid FROM "b1/sensor/#" WHERE payload.temp > 30',
            'enable':True,'description':'generated','actions':[{'function':'republish','args':{
            'topic':'b1/alerts/${clientid}','qos':1,'retain':False,'payload':'${t}','mqtt_properties':{},
            'user_properties':''}}]},
        'b1_rule_http':{'sql':'SELECT * FROM "b1/cmd/#"','enable':True,'description':'generated',
            'actions':['http:b1_http_action']}},
        'actions':{('http','b1_http_action'):{'connector':'b1_http','enable':True,'description':'generated',
            'parameters':{'method':'get','path':'/api/v5/status','headers':{},'body':''}}},
        'connectors':{('http','b1_http'):{'url':'http://127.0.0.1:18083','headers':{},'connect_timeout':'15s',
            'pool_size':2,'enable':True,'description':'generated'}}}


class DeliveryTests(unittest.TestCase):
    quiesce=api_tests.SourceAPITests.quiesce

    def setUp(self):
        api_tests.SourceAPITests.setUp(self)
        del self.fail  # the shared fixture shadows TestCase.fail with its HTTP switch
        self.runner.podman=self.podman
        self.clients=workflow.SourceClients({'sensor_user':b'b1-sensor','sensor_password':b'generated-sensor-password',
            'gateway_user':b'b1-gateway','gateway_password':b'generated-gateway-password'})
        self.runtime.register_bundle({'runtime-login-input':list(self.clients.fields.values())})
        self.credentials=workflow.SourceAPICredentials((b'admin',b'generated-admin-password',b'b1ops',
            b'generated-second-password',b'generated-api-key',b'generated-api-secret'))
        self.objects=original_objects();self.source=self.mint(self.objects)
        self.lock=threading.Lock();self.delivered=threading.Event()
        self.rules={'b1_rule_republish':dict(RULE_ZERO),'b1_rule_http':dict(RULE_ZERO)}
        self.action=dict(ACTION_ZERO);self.pending=0
        self.connected=set();self.subscribed={};self.message=None;self.active=set();self.docs={}
        self.paths=[];self.runs=[];self.roots=[];self.foreign=set()
        self.status='connected';self.visible=True;self.rows_override=None;self.sub_exit=0;self.sub_wait=3.0
        self.exit_early=False;self.drop_republish=False;self.payload_override=None;self.connack={};self.puback={}
        self.http_result='success';self.http_rule_passed=1;self.extra_match=False;self.metrics_override=None
        self.keep_container=None;self.remove_failure=False;self.after_gateway=None
        for name,value in (('READY_SECONDS',2),('HTTP_SECONDS',2),('CLIENTS_SECONDS',2),('POLL',0.01)):
            replace=patch.object(m,name,value);replace.start();self.addCleanup(replace.stop)

    def mint(self,objects,registry=None):
        token=SourceObjects();values=Values()
        _leaves({'rules':objects['rules'],'actions':{':'.join(k):v for k,v in objects['actions'].items()},
                 'connectors':{':'.join(k):v for k,v in objects['connectors'].items()}},values)
        _RECORDS[token]={'objects':objects,'registry':self.prior if registry is None else registry,
            'values':PersistedValues('generated','source',{},values.values),'sha256':'0'*64,'captured_ms':0}
        return token

    # ---- simulated process boundary -------------------------------------------------
    def podman(self,*args,**kwargs):
        if args[:2]==('container','inspect'):
            self.events.append('inspect')
            if args[2]==self.cid:return SimpleNamespace(returncode=0,stdout=json.dumps(self.doc).encode(),stderr=b'')
            with self.lock:doc=self.docs[args[2]]
            return SimpleNamespace(returncode=0,stdout=json.dumps([doc]).encode(),stderr=b'')
        if args[:2]==('container','exists'):
            with self.lock:
                present=args[2] in self.active or any(d['Id']==args[2] and n in self.active for n,d in self.docs.items())
            return SimpleNamespace(returncode=0 if present else 1,stdout=b'',stderr=b'')
        if args[0]=='rm':
            self.assertRegex(args[-1],r'^[0-9a-f]{64}$')
            with self.lock:
                if not self.remove_failure:
                    for name,doc in self.docs.items():
                        if doc['Id']==args[-1]:self.active.discard(name)
            return SimpleNamespace(returncode=1 if self.remove_failure else 0,stdout=b'',stderr=b'')
        if args[0]=='exec':return self.api(args,kwargs)
        self.assertEqual(args[:2],('run','--rm'))
        return self.client(args,kwargs)

    def reply(self,doc,status=200):
        return SimpleNamespace(returncode=0,stdout=json.dumps(doc).encode()+b'\napplication/json\n'+str(status).encode(),
                               stderr=b'generated-private-stderr')

    def api(self,args,kwargs):
        self.assertEqual(args,('exec','-i',self.cid,'curl','-q','--config','-'))
        self.assertEqual({k:v for k,v in kwargs.items() if k!='input'},dict(timeout=10,max_output=m.HTTP_LIMIT,check=False))
        config=kwargs['input'].decode().splitlines()
        for line in ('proxy = ""','noproxy = "*"','max-redirs = 0','request = "GET"','max-time = 5','proto = "=http"'):
            self.assertIn(line,config)
        basic='Basic '+base64.b64encode(b'generated-api-key:generated-api-secret').decode()
        self.assertIn('header = '+json.dumps('Authorization: '+basic),config)
        for value in (b'generated-api-secret',basic.encode()):
            with self.assertRaises(PrivateFailure):self.runtime.scan(value)
        url=json.loads(config[0].split(' = ',1)[1]);prefix='http://127.0.0.1:18083/api/v5'
        self.assertTrue(url.startswith(prefix+'/'));path=url[len(prefix):]
        self.events.append('api');self.paths.append(path)
        with self.lock:
            if path=='/actions/http:b1_http_action':
                return self.reply({'type':'http','name':'b1_http_action','enable':True,'status':self.status,
                                   'parameters':{'path':'/api/v5/status'}})
            if path in ('/rules/b1_rule_republish/metrics','/rules/b1_rule_http/metrics'):
                rule=path.split('/')[2]
                doc={'id':rule,'metrics':dict(self.rules[rule],**{'matched.rate':0.0,'matched.rate.max':0.0,
                     'matched.rate.last5m':0.0}),'node_metrics':[{'node':'emqx@127.0.0.1','metrics':{}}]}
                return self.reply(self.metrics_override(doc) if self.metrics_override else doc)
            if path=='/actions/http:b1_http_action/metrics':
                self.resolve_http()
                return self.reply({'metrics':dict(self.action,rate=0.0,rate_max=0.0,rate_last5m=0.0),'node_metrics':[]})
            match=re.fullmatch(r'/clients/([^/]+)/subscriptions',path)
            if match:
                client=match[1]
                if client not in self.connected:
                    return self.reply({'code':'CLIENTID_NOT_FOUND','message':'Client ID not found'},404)
                if not self.visible:return self.reply([])
                rows=[{'topic':self.subscribed[client],'clientid':client,'node':'emqx@127.0.0.1','qos':1,
                       'nl':0,'rap':0,'rh':0,'durable':False}]
                return self.reply(self.rows_override(rows) if self.rows_override else rows)
            if path=='/clients?page=1&limit=100':
                return self.reply({'data':[{'clientid':c} for c in sorted(self.connected|self.foreign)],
                                   'meta':{'page':1,'limit':100,'hasnext':False}})
        raise AssertionError('unexpected generated API path')

    def resolve_http(self):
        if not self.pending:return
        self.pending=0;rule=self.rules['b1_rule_http']
        if self.http_result=='success':self.action['success']+=1;rule['actions.success']+=1
        elif self.http_result=='double':self.action['success']+=2;rule['actions.success']+=1
        elif self.http_result=='failed':
            self.action['failed']+=1;rule['actions.failed']+=1;rule['actions.failed.unknown']+=1
        else:self.pending=1

    def client(self,args,kwargs):
        name=args[args.index('--name')+1];self.assertRegex(name,NAME)
        label=args[args.index('--label')+1].split('=',1)
        with self.lock:
            self.active.add(name)
            self.docs[name]={'Id':format(len(self.docs)+1,'064x'),'Name':'/'+name,'Image':m_client(),
                             'Config':{'Labels':{label[0]:label[1]}}}
        self.runs.append(args)
        for flag in ('--pull=never','--log-driver=none','--image-volume=ignore','--network=container:'+self.cid,
                     '--userns=keep-id:uid=1000,gid=1000','--user=1000:1000','--memory=64m','--stop-timeout=1',m_client()):
            self.assertIn(flag,args)
        for secret in (b'generated-sensor-password',b'generated-gateway-password',b'generated-api-secret'):
            self.assertNotIn(secret.decode(),repr(args))
        self.assertNotIn('-P',args);self.assertNotIn('-u',args);self.assertNotIn('-m',args)
        env=[args[i+1] for i,v in enumerate(args) if v=='-e']
        self.assertEqual(env[0],'HOME=/work');home=env[1].removeprefix('XDG_CONFIG_HOME=/work/')
        root=Path(args[args.index('-v')+1].removesuffix(':/work:ro'));self.roots.append(root)
        self.assertEqual(root.parent,Path('/dev/shm'));self.assertEqual(root.stat().st_mode&0o777,0o700)
        self.assertEqual(args[args.index('-i')+1],name)
        try:
            if '--entrypoint=mosquitto_sub' in args:
                self.assertEqual(home,'sub');self.assertEqual(kwargs,dict(timeout=85,max_output=65536,check=False))
                self.assertIn('--timeout=75',args)
                return self.subscriber(args,name,root)
            self.assertIn('--entrypoint=mosquitto_pub',args);self.assertIn(home,('sensor','gateway'))
            self.assertEqual(kwargs,dict(timeout=40,max_output=65536,check=False));self.assertIn('--timeout=30',args)
            return self.publisher(args,name,root,home)
        finally:
            with self.lock:
                if self.keep_container!=home:self.active.discard(name)

    def read_config(self,path):
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        match=re.fullmatch(rb'-u ([^\n]+)\n-P ([^\n]+)\n-t ([^\n]+)\n',path.read_bytes())
        self.assertIsNotNone(match);return match[1],match[2],match[3]

    def subscriber(self,args,name,root):
        user,password,topic=self.read_config(root/'sub'/'mosquitto_sub')
        self.assertEqual((user,password),(b'b1-gateway',b'generated-gateway-password'))
        self.assertRegex(topic,rb'^b1/alerts/woowbk-emqxlab-[0-9a-f]{8}-mqtt-[0-9a-f]{12}$')
        self.assertEqual(args[args.index('-F')+1],'DELIVERY:%r:%q:%t:%x')
        for flag,value in (('-q','1'),('-C','1'),('-W','60'),('-V','mqttv5')):self.assertEqual(args[args.index(flag)+1],value)
        head=b'Client '+name.encode()+b' sending CONNECT\nClient '+name.encode()+b' received CONNACK (0)\n'
        if self.exit_early:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'generated-private-error')
        with self.lock:self.connected.add(name);self.subscribed[name]=topic.decode()
        self.delivered.wait(self.sub_wait)
        with self.lock:self.connected.discard(name);message=self.message
        head+=b'Client '+name.encode()+b' received SUBACK\nSubscribed (mid: 1): 1\n'
        if message is None:return SimpleNamespace(returncode=27,stdout=head,stderr=b'Timed out\n')
        line=b'DELIVERY:0:1:'+message[0]+b':'+message[1].hex().encode()+b'\n'
        return SimpleNamespace(returncode=self.sub_exit,stdout=head+line+b'Client '+name.encode()+b' sending DISCONNECT\n',stderr=b'')

    def publisher(self,args,name,root,home):
        user,password,topic=self.read_config(root/home/'mosquitto_pub')
        payload=(root/args[args.index('-f')+1].removeprefix('/work/')).read_bytes()
        self.assertEqual(args[args.index('-q')+1],'1')
        connack=self.connack.get(home,0);rc=self.puback.get(home,16)
        out=b'Client '+name.encode()+b' sending CONNECT\nClient '+name.encode()+b' received CONNACK ('+str(connack).encode()+b')\n'
        if connack:return SimpleNamespace(returncode=5,stdout=out,stderr=b'Connection error\n')
        with self.lock:
            if home=='sensor':
                self.assertEqual((user,password),(b'b1-sensor',b'generated-sensor-password'))
                self.assertTrue(topic.startswith(b'b1/sensor/b1-sensor/'))
                if rc==16:self.sensor_rule(name,payload)
            else:
                self.assertEqual((user,password),(b'b1-gateway',b'generated-gateway-password'))
                self.assertTrue(topic.startswith(b'b1/cmd/'))
                if rc==16:
                    rule=self.rules['b1_rule_http'];rule['matched']+=1;rule['passed']+=self.http_rule_passed
                    rule['actions.total']+=1;self.action['matched']+=1;self.pending=1
                if self.after_gateway:self.after_gateway()
        out+=b'Client '+name.encode()+b' received PUBACK (Mid: 1, RC:'+str(rc).encode()+b')\n'
        return SimpleNamespace(returncode=0 if rc<128 else 1,stdout=out,stderr=b'')

    def sensor_rule(self,client,payload):
        # Oracle of the original republish rule (independent of module constants).
        rule=self.rules['b1_rule_republish'];rule['matched']+=2 if self.extra_match else 1
        temp=json.loads(payload)['temp']
        if temp<=30:return
        rule['passed']+=1;rule['actions.total']+=1;rule['actions.success']+=1
        topic=b'b1/alerts/'+client.encode();body=str(temp).encode()
        if self.payload_override is not None:body=self.payload_override
        if not self.drop_republish and topic.decode() in self.subscribed.values():
            self.message=(topic,body);self.delivered.set()

    # ---- helpers -----------------------------------------------------------------------
    def run_delivery(self,**changes):
        kwargs=dict(registry=self.prior,provision=self.provision,expected_container_id=self.cid,clients=self.clients,
                    api_credentials=self.credentials,source_objects=self.source,quiesce=self.quiesce)
        kwargs.update(changes)
        return m.run_rule_delivery(**kwargs)

    def refused(self,label,**changes):
        with self.assertRaises(m.DeliveryRefused) as caught:self.run_delivery(**changes)
        self.assertEqual((caught.exception.label,str(caught.exception)),(label,'controlled-delivery-refused'))
        self.assertIsNone(caught.exception.__cause__);self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.active,set())
        for root in self.roots:self.assertFalse(root.exists())
        return caught.exception

    # ---- success --------------------------------------------------------------------------
    def test_restored_rules_deliver_republish_and_http_action_exactly_once(self):
        result=self.run_delivery()
        self.assertIs(type(result),m.RuleDelivery)
        self.assertEqual(repr(result),'<EMQX private restored rule delivery observation>')
        self.assertIn('http-request-bytes-not-captured-no-sink',result.scope())
        self.assertIn('restore-round-only-not-commercial-acceptance',result.scope())
        self.assertEqual(self.rules['b1_rule_republish'],dict(RULE_ZERO,matched=1,passed=1,**{'actions.total':1,'actions.success':1}))
        self.assertEqual(self.rules['b1_rule_http'],dict(RULE_ZERO,matched=1,passed=1,**{'actions.total':1,'actions.success':1}))
        self.assertEqual((self.action['matched'],self.action['success'],self.action['failed']),(1,1,0))
        self.assertEqual(len(self.runs),3);self.assertEqual(self.active,set());self.assertEqual(self.connected,set())
        for root in self.roots:self.assertFalse(root.exists())
        self.assertEqual(self.events[0],'enter');self.assertEqual(self.events[-1],'exit')
        self.assertEqual(self.events[1],'inspect');self.assertEqual(self.events[-2],'inspect')
        self.assertEqual(self.paths[:4],['/actions/http:b1_http_action','/rules/b1_rule_republish/metrics',
            '/rules/b1_rule_http/metrics','/actions/http:b1_http_action/metrics'])
        self.assertEqual(self.paths[-1],'/clients?page=1&limit=100')
        topic,payload=self.message
        for value in (b'generated-sensor-password',b'generated-gateway-password',b'generated-api-secret',
                      b'Basic '+base64.b64encode(b'generated-api-key:generated-api-secret'),topic,payload,
                      b'generated-private-stderr'):
            with self.assertRaises(PrivateFailure):result.scan(b'evidence '+value)
        result.scan('階段：還原；結果：通過'.encode())

    def test_publish_order_subscription_first_then_sensor_then_gateway(self):
        self.run_delivery()
        entry=[next(x for x in a if x.startswith('--entrypoint=')) for a in self.runs]
        homes=[next(x for x in a if x.startswith('XDG_CONFIG_HOME=')) for a in self.runs]
        self.assertEqual(entry,['--entrypoint=mosquitto_sub','--entrypoint=mosquitto_pub','--entrypoint=mosquitto_pub'])
        self.assertEqual(homes,['XDG_CONFIG_HOME=/work/sub','XDG_CONFIG_HOME=/work/sensor','XDG_CONFIG_HOME=/work/gateway'])
        subscribed=[i for i,p in enumerate(self.paths) if p.startswith('/clients/')]
        self.assertTrue(subscribed);self.assertEqual(len({a[a.index('--name')+1] for a in self.runs}),3)

    # ---- refusals -------------------------------------------------------------------------
    def test_input_refusals_before_any_process_io(self):
        other=SourceObjects()
        cases=[dict(registry=self.runtime),dict(provision=object()),dict(expected_container_id='A'*64),
               dict(expected_container_id=self.cid[:-1]),dict(clients=object()),dict(api_credentials=object()),
               dict(source_objects=other),dict(source_objects=self.mint(original_objects(),registry=object())),
               dict(quiesce=True),
               dict(clients=workflow.SourceClients(dict(self.clients.fields,sensor_user=b'b1-gateway'))),
               dict(clients=workflow.SourceClients(dict(self.clients.fields,gateway_password=b'generated-unregistered')))]
        for change in cases:
            with self.subTest(change=sorted(change)):
                self.events.clear();self.refused('input',**change);self.assertEqual(self.events,[])

    def test_changed_original_rule_action_or_connector_refuses_as_contract(self):
        edits=(lambda o:o['rules']['b1_rule_republish'].update(sql='SELECT payload.temp as t, clientid FROM "b1/sensor/#" WHERE payload.temp > 31'),
               lambda o:o['rules']['b1_rule_http'].update(sql='SELECT * FROM "b1/other/#"'),
               lambda o:o['rules']['b1_rule_http'].update(actions=['http:other']),
               lambda o:o['rules']['b1_rule_http'].update(enable=False),
               lambda o:o['rules']['b1_rule_republish']['actions'][0]['args'].update(retain=0),
               lambda o:o['rules']['b1_rule_republish']['actions'][0]['args'].update(qos=True),
               lambda o:o['rules']['b1_rule_republish']['actions'][0]['args'].update(payload='${payload}'),
               lambda o:o['rules']['b1_rule_republish']['actions'][0]['args'].update(direct_dispatch=True),
               lambda o:o['rules']['b1_rule_republish']['actions'].append({'function':'console','args':{}}),
               lambda o:o['actions'][('http','b1_http_action')]['parameters'].update(method='post'),
               lambda o:o['actions'][('http','b1_http_action')]['parameters'].update(body='generated'),
               lambda o:o['actions'][('http','b1_http_action')]['parameters'].update(headers={'authorization':'generated'}),
               lambda o:o['connectors'][('http','b1_http')].update(url='http://127.0.0.1:18084'),
               lambda o:o['connectors'][('http','b1_http')].update(headers={'x':'generated'}),
               lambda o:o['rules'].pop('b1_rule_http'))
        for index,edit in enumerate(edits):
            with self.subTest(edit=index):
                objects=original_objects();edit(objects);self.events.clear()
                self.refused('contract',source_objects=self.mint(objects));self.assertEqual(self.events,[])
        objects=original_objects();objects['rules']['b1_rule_republish']['actions'][0]['args']['direct_dispatch']=False
        self.run_delivery(source_objects=self.mint(objects))

    def test_identity_network_and_post_identity_refuse(self):
        self.doc[0]['HostConfig']['NetworkMode']='host'
        self.refused('identity');self.assertEqual(self.runs,[])
        self.doc[0]['HostConfig']['NetworkMode']='none'
        def changed():self.doc[0]['State']['Running']=False
        self.after_gateway=changed
        self.refused('identity')

    def test_action_status_and_metrics_documents(self):
        self.status='disconnected';self.refused('http_status');self.assertEqual(self.runs,[])
        self.status='connected'
        for edit in (lambda d:d.update(id='generated-other'),lambda d:d['metrics'].update(matched=-1),
                     lambda d:d['metrics'].pop('passed'),lambda d:d['metrics'].update(passed='1')):
            with self.subTest():
                self.metrics_override=lambda d,edit=edit:(edit(d),d)[1]
                self.refused('metrics');self.assertEqual(self.runs,[])

    def test_subscriber_launch_timeout_and_mismatch(self):
        self.exit_early=True;self.refused('subscribe_launch');self.assertEqual(len(self.runs),1)
        self.exit_early=False;self.visible=False;self.sub_wait=1.5;self.runs.clear()  # subscriber alive, never listed
        with patch.object(m,'READY_SECONDS',0.5):self.refused('subscribe_timeout')
        self.assertEqual(len(self.runs),1)
        self.visible=True
        for edit in (lambda rows:[dict(rows[0],qos=0)],lambda rows:[dict(rows[0],topic='b1/#')],
                     lambda rows:rows*2,lambda rows:[dict(rows[0],clientid='generated-other')]):
            with self.subTest():
                self.rows_override=edit;self.runs.clear();self.refused('subscribe_mismatch');self.assertEqual(len(self.runs),1)

    def test_sensor_publish_refusals(self):
        self.sub_wait=0.1;self.puback={'sensor':135};self.refused('publish_sensor_denied')
        self.puback={};self.connack={'sensor':5};self.refused('publish_sensor')
        self.connack={};self.puback={'sensor':0}
        with patch.object(self,'sensor_rule'):self.refused('republish_timeout')

    def test_republish_delivery_refusals(self):
        self.sub_wait=0.2;self.drop_republish=True;self.refused('republish_timeout')
        self.drop_republish=False;self.delivered.clear();self.payload_override=b'generated-wrong'
        self.refused('republish_mismatch')
        self.payload_override=None;self.delivered.clear();self.message=None;self.sub_exit=1
        self.refused('republish_exit')

    def test_gateway_publish_refusals(self):
        self.puback={'gateway':135};self.refused('publish_gateway_denied')
        self.puback={};self.delivered.clear();self.message=None;self.connack={'gateway':5};self.refused('publish_gateway')

    def test_http_action_outcomes_are_exact(self):
        for result,label in (('failed','http_action_failed'),('never','http_action_timeout'),('double','http_action_count')):
            with self.subTest(result=result):
                self.http_result=result;self.delivered.clear();self.message=None;self.refused(label)
        self.http_result='success';self.http_rule_passed=0;self.delivered.clear();self.message=None
        self.refused('http_rule')

    def test_republish_rule_counters_must_move_exactly_once(self):
        self.extra_match=True;self.refused('republish_rule')

    def test_lingering_or_foreign_clients_refuse(self):
        self.foreign={'generated-foreign-client'};self.refused('clients')

    def test_owned_container_that_cannot_be_removed_refuses_as_cleanup(self):
        self.keep_container='gateway';self.remove_failure=True
        error=self.refused_without_absence('cleanup')
        self.assertEqual(str(error),'controlled-delivery-refused')

    def refused_without_absence(self,label):
        with self.assertRaises(m.DeliveryRefused) as caught:self.run_delivery()
        self.assertEqual(caught.exception.label,label)
        return caught.exception

    def test_cooperative_deadline_and_quiesce_exit_and_ram_files(self):
        with patch.object(m,'DEADLINE',0):self.refused('deadline')
        @contextmanager
        def failing():
            yield
            raise ValueError('generated-quiesce-exit')
        self.refused('quiesce',quiesce=failing)
        self.delivered.clear();self.message=None
        with patch.object(workflow,'_ram_client_parent',side_effect=ValueError('generated')):
            self.refused('files')

    def test_refusal_label_survives_a_failing_quiesce_exit(self):
        @contextmanager
        def failing():
            try:yield
            finally:raise ValueError('generated-quiesce-exit')
        self.sub_wait=0.2;self.payload_override=b'generated-wrong'
        self.refused('republish_mismatch',quiesce=failing)

    def test_cancellation_is_fixed_and_not_a_label(self):
        with patch.object(m,'_contract',side_effect=KeyboardInterrupt):
            with self.assertRaises(PrivateFailure) as caught:self.run_delivery()
        self.assertEqual(str(caught.exception),'controlled-delivery-cancelled')
        self.assertNotIsInstance(caught.exception,m.DeliveryRefused)

    def test_unknown_label_is_coerced_to_input(self):
        self.assertEqual(m.DeliveryRefused('generated-private-text').label,'input')
        self.assertEqual(len(set(m.LABELS)),len(m.LABELS))


def m_client():
    from emqx_adapter_mqtt import CLIENT
    return CLIENT


if __name__=='__main__':unittest.main()
