"""FILE baseline rule delivery: generated issuance + simulated broker/podman boundary.

The broker below is a test oracle written independently of the module: it applies
the unchanged target FILE ACL (HA gateway may subscribe only b1/retained/#, every
other HA publish/subscribe is refused with reason code 135, deny_action=ignore),
the trusted management API (POST /publish and /clients/:id/subscribe run no MQTT
authorization; an API message's clientid is http_api) and the original B1 rules.
No real MQTT/HTTP, lab, restore or commercial claim is exercised by these tests.
"""
import base64
from contextlib import contextmanager
import json
import re
import unittest
from unittest.mock import patch

import emqx_controlled_delivery as m
import emqx_real_owner_workflow as workflow
import test_emqx_controlled_delivery as base
from emqx_imported_acl_target_mode import FILE_BASELINE, IMPORTED_MNESIA
from emqx_private_boundary import PrivateFailure

RULE_ZERO=base.RULE_ZERO
ACTION_ZERO=base.ACTION_ZERO
NODE='emqx@127.0.0.1'
GRANT='b1/retained/#'        # literal from the target file ACL, not the module constant
API_ALERTS='b1/alerts/http_api'


def curl_value(line,key):
    """curl tool_parsecfg unslashquote: \\t \\n \\r \\v, any other escaped char literal."""
    prefix=key+' = '
    if not line.startswith(prefix):raise AssertionError('generated config key')
    raw=line[len(prefix):]
    if len(raw)<2 or raw[0]!='"' or raw[-1]!='"':raise AssertionError('generated config quoting')
    out=[];i=1
    while i<len(raw)-1:
        c=raw[i]
        if c=='\\':
            i+=1;c=raw[i];out.append({'t':'\t','n':'\n','r':'\r','v':'\v'}.get(c,c))
        elif c=='"':raise AssertionError('generated unescaped quote')
        else:out.append(c)
        i+=1
    return ''.join(out)


def matches(topic,flt):
    t,f=topic.split('/'),flt.split('/')
    for i,level in enumerate(f):
        if level=='#':return True
        if i>=len(t) or (level!='+' and level!=t[i]):return False
    return len(t)==len(f)


class FileDeliveryTests(unittest.TestCase):
    quiesce=base.DeliveryTests.quiesce
    mint=base.DeliveryTests.mint
    podman=base.DeliveryTests.podman
    reply=base.DeliveryTests.reply
    resolve_http=base.DeliveryTests.resolve_http
    client=base.DeliveryTests.client

    def setUp(self):
        base.DeliveryTests.setUp(self)
        self.subs={};self.grants={GRANT};self.publish_allowed=set();self.posts=[];self.snapshots=[]
        self.api_sub_status=200;self.api_sub_edit=None;self.api_sub_visible=True
        self.publish_status=None;self.publish_edit=None;self.counter_noise=False
        self.sub_line=None;self.pub_exit=None;self.extra_puback=None

    # ---- simulated management API ------------------------------------------------------
    def api(self,args,kwargs):
        self.assertEqual(args,('exec','-i',self.cid,'curl','-q','--config','-'))
        self.assertEqual({k:v for k,v in kwargs.items() if k!='input'},dict(timeout=10,max_output=m.HTTP_LIMIT,check=False))
        config=kwargs['input'].decode().splitlines()
        for line in ('proxy = ""','noproxy = "*"','max-redirs = 0','max-time = 5','proto = "=http"'):
            self.assertIn(line,config)
        basic='Basic '+base64.b64encode(b'generated-api-key:generated-api-secret').decode()
        self.assertIn('header = '+json.dumps('Authorization: '+basic),config)
        self.assertNotIn('generated-api-secret',repr(args))
        for value in (b'generated-api-secret',basic.encode()):
            with self.assertRaises(PrivateFailure):self.runtime.scan(value)
        methods=[x for x in config if x.startswith('request = ')]
        self.assertEqual(len(methods),1)
        url=json.loads(config[0].split(' = ',1)[1]);prefix='http://127.0.0.1:18083/api/v5'
        self.assertTrue(url.startswith(prefix+'/'));path=url[len(prefix):]
        self.events.append('api');self.paths.append(path)
        if methods[0]=='request = "POST"':
            self.assertIn('header = "Content-Type: application/json"',config)
            data=[x for x in config if x.startswith('data-binary = ')];self.assertEqual(len(data),1)
            body=curl_value(data[0],'data-binary');self.assertRegex(body,r'^[\x20-\x7e]+$')
            with self.assertRaises(PrivateFailure):self.runtime.scan(body.encode())
            return self.post(path,json.loads(body))
        self.assertEqual(methods,['request = "GET"']);self.assertFalse(any(x.startswith('data') for x in config))
        with self.lock:
            if path=='/actions/http:b1_http_action':
                return self.reply({'type':'http','name':'b1_http_action','enable':True,'status':self.status,
                                   'parameters':{'path':'/api/v5/status'}})
            if path in ('/rules/b1_rule_republish/metrics','/rules/b1_rule_http/metrics'):
                rule=path.split('/')[2];self.snapshots.append((rule,dict(self.rules[rule])))
                doc={'id':rule,'metrics':dict(self.rules[rule],**{'matched.rate':0.0}),'node_metrics':[]}
                return self.reply(self.metrics_override(doc) if self.metrics_override else doc)
            if path=='/actions/http:b1_http_action/metrics':
                self.resolve_http()
                return self.reply({'metrics':dict(self.action,rate=0.0),'node_metrics':[]})
            match=re.fullmatch(r'/clients/([^/]+)/subscriptions',path)
            if match:
                client=match[1]
                if client not in self.connected:
                    return self.reply({'code':'CLIENTID_NOT_FOUND','message':'Client ID not found'},404)
                if not self.visible:return self.reply([])
                rows=[{'topic':t,'clientid':client,'node':NODE,'qos':q,'nl':0,'rap':0,'rh':rh,'durable':False}
                      for t,q,rh in self.subs.get(client,[])]
                return self.reply(self.rows_override(rows) if self.rows_override else rows)
            if path=='/clients?page=1&limit=100':
                return self.reply({'data':[{'clientid':c} for c in sorted(self.connected|self.foreign)],
                                   'meta':{'page':1,'limit':100,'hasnext':False}})
        raise AssertionError('unexpected generated API path')

    def post(self,path,doc):
        self.posts.append((path,doc))
        match=re.fullmatch(r'/clients/([^/]+)/subscribe',path)
        with self.lock:
            if match:
                client=match[1]
                self.assertEqual(sorted(doc),['qos','topic'])
                if client not in self.connected or self.api_sub_status==404:
                    return self.reply({'code':'CLIENTID_NOT_FOUND','message':'Client ID not found'},404)
                # Management subscribe: no authorization check (emqx_channel handle_info).
                if self.api_sub_visible:self.subs[client].append((doc['topic'],doc['qos'],0))
                answer={'topic':doc['topic'],'qos':doc['qos'],'nl':0,'rap':0,'rh':0,'node':NODE,'clientid':client}
                return self.reply(self.api_sub_edit(answer) if self.api_sub_edit else answer,self.api_sub_status)
            self.assertEqual(path,'/publish')
            self.assertEqual(sorted(doc),['payload','qos','retain','topic'])
            self.assertEqual((doc['qos'],doc['retain']),(1,False))
            subscribed=self.route(doc['topic'],doc['payload'].encode(),'http_api')
        if self.publish_status:
            return self.reply({'reason_code':131,'message':'generated'},self.publish_status)
        answer={'id':'0'*32} if subscribed else {'reason_code':16,'message':'no_matching_subscribers'}
        if self.publish_edit:answer=self.publish_edit(answer)
        return self.reply(answer,200 if subscribed else 202)

    def route(self,topic,payload,sender):
        """Original B1 rules on one accepted message; True when a subscriber matched."""
        if matches(topic,'b1/sensor/#'):
            rule=self.rules['b1_rule_republish'];rule['matched']+=2 if self.extra_match else 1
            temp=json.loads(payload)['temp']
            if temp>30:
                rule['passed']+=1;rule['actions.total']+=1;rule['actions.success']+=1
                body=self.payload_override if self.payload_override is not None else str(temp).encode()
                out='b1/alerts/'+sender
                if not self.drop_republish and any(matches(out,f) for subs in self.subs.values() for f,_,_ in subs):
                    self.message=(out.encode(),body);self.delivered.set()
        if matches(topic,'b1/cmd/#'):
            rule=self.rules['b1_rule_http'];rule['matched']+=1;rule['passed']+=self.http_rule_passed
            rule['actions.total']+=1;self.action['matched']+=1;self.pending=1
            if self.after_gateway:self.after_gateway()
        return any(matches(topic,f) for subs in self.subs.values() for f,_,_ in subs)

    # ---- simulated MQTT clients ---------------------------------------------------------
    def read_lines(self,path):
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        lines=path.read_bytes().split(b'\n');self.assertEqual(lines[-1],b'')
        pairs=[tuple(x.split(b' ',1)) for x in lines[:-1]]
        self.assertTrue(all(len(p)==2 for p in pairs))
        return pairs

    def subscriber(self,args,name,root):
        pairs=self.read_lines(root/'sub'/'mosquitto_sub')
        self.assertEqual(pairs,[(b'-u',b'b1-gateway'),(b'-P',b'generated-gateway-password'),
                                (b'-t',GRANT.encode()),(b'-t',API_ALERTS.encode())])
        self.assertIn('-R',args);self.assertEqual(args[args.index('-F')+1],'DELIVERY:%r:%q:%t:%x')
        for flag,value in (('-q','1'),('-C','1'),('-W','60'),('-V','mqttv5')):self.assertEqual(args[args.index(flag)+1],value)
        head=b'Client '+name.encode()+b' sending CONNECT\nClient '+name.encode()+b' received CONNACK (0)\n'
        if self.exit_early:return base.SimpleNamespace(returncode=1,stdout=b'',stderr=b'generated-private-error')
        codes=[1 if topic.decode() in self.grants else 135 for _,topic in pairs[2:]]
        with self.lock:
            self.connected.add(name)
            # -R sets retain handling 2 (mosquitto client_shared.c:919-924).
            self.subs[name]=[(topic.decode(),1,2) for (_,topic),c in zip(pairs[2:],codes) if c<128]
        self.delivered.wait(self.sub_wait)
        with self.lock:self.connected.discard(name);self.subs.pop(name,None);message=self.message
        line=self.sub_line or b'Subscribed (mid: 1): '+b', '.join(str(c).encode() for c in codes)+b'\n'
        head+=b'Client '+name.encode()+b' received SUBACK\n'+line
        if message is None:return base.SimpleNamespace(returncode=27,stdout=head,stderr=b'Timed out\n')
        out=b'DELIVERY:0:1:'+message[0]+b':'+message[1].hex().encode()+b'\n'
        return base.SimpleNamespace(returncode=self.sub_exit,stdout=head+out+b'Client '+name.encode()+b' sending DISCONNECT\n',stderr=b'')

    def publisher(self,args,name,root,home):
        pairs=self.read_lines(root/home/'mosquitto_pub')
        user,password,topic=(p[1] for p in pairs)
        self.assertEqual([p[0] for p in pairs],[b'-u',b'-P',b'-t'])
        payload=(root/args[args.index('-f')+1].removeprefix('/work/')).read_bytes()
        self.assertEqual(args[args.index('-q')+1],'1')
        connack=self.connack.get(home,0)
        out=b'Client '+name.encode()+b' sending CONNECT\nClient '+name.encode()+b' received CONNACK ('+str(connack).encode()+b')\n'
        if connack:return base.SimpleNamespace(returncode=5,stdout=out,stderr=b'Connection error\n')
        if home=='sensor':
            self.assertEqual((user,password),(b'b1-sensor',b'generated-sensor-password'))
            self.assertRegex(topic,rb'^b1/sensor/b1-sensor/delivery-[0-9a-f]{12}$');self.assertGreater(json.loads(payload)['temp'],30)
        else:
            self.assertEqual((user,password),(b'b1-gateway',b'generated-gateway-password'))
            self.assertRegex(topic,rb'^b1/cmd/delivery-[0-9a-f]{12}$')
        allowed=home in self.publish_allowed
        with self.lock:
            if allowed:self.route(topic.decode(),payload,name)
            elif self.counter_noise:self.rules['b1_rule_republish']['matched']+=1
        rc=self.puback.get(home,16 if allowed else 135)
        out+=b'Client '+name.encode()+b' received PUBACK (Mid: 1, RC:'+str(rc).encode()+b')\n'
        if self.extra_puback==home:out+=b'Client '+name.encode()+b' received PUBACK (Mid: 2, RC:135)\n'
        err=b'Warning: Publish 1 failed: Not authorized.\n' if rc>127 else b''
        # mosquitto_pub exits 0 after a refused PUBACK (pub_client.c:199-221,365-369).
        code=self.pub_exit if self.pub_exit is not None else 0
        return base.SimpleNamespace(returncode=code,stdout=out,stderr=err)

    # ---- helpers ---------------------------------------------------------------------------
    def run_delivery(self,**changes):
        kwargs=dict(registry=self.prior,provision=self.provision,expected_container_id=self.cid,clients=self.clients,
                    api_credentials=self.credentials,source_objects=self.source,quiesce=self.quiesce)
        kwargs.update(changes)
        return m.run_file_policy_rule_delivery(**kwargs)

    def refused(self,label,**changes):
        with self.assertRaises(m.DeliveryRefused) as caught:self.run_delivery(**changes)
        self.assertEqual((caught.exception.label,str(caught.exception)),(label,'controlled-delivery-refused'))
        self.assertIsNone(caught.exception.__cause__);self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.active,set())
        for root in self.roots:self.assertFalse(root.exists())
        return caught.exception

    def fresh(self):
        # An HTTP action left unresolved by a previous subtest would (correctly)
        # move the action counters during the next refused-publish check.
        self.delivered.clear();self.message=None;self.runs.clear();self.posts.clear();self.paths.clear()
        self.pending=0

    # ---- success ---------------------------------------------------------------------------
    def test_file_acl_refuses_ha_rule_topics_and_trusted_api_delivers_exactly_once(self):
        result=self.run_delivery()
        self.assertIs(type(result),m.RuleDelivery);self.assertEqual(result._mode,FILE_BASELINE)
        self.assertEqual(repr(result),'<EMQX private restored rule delivery observation>')
        for scope in ('ha-rule-topic-publishes-denied-by-target-file-acl-puback135-no-counter-moved',
                      'ha-gateway-own-subscribe-of-republish-output-denied-suback135',
                      'rule-input-through-trusted-management-publish-api-with-restored-key',
                      'republish-delivered-once-to-ha-gateway-session-via-management-api-subscription',
                      'http-request-bytes-not-captured-no-sink','restore-round-only-not-commercial-acceptance'):
            self.assertIn(scope,result.scope())
        self.assertEqual(result.private_facts()['mode'],FILE_BASELINE)
        self.assertEqual(self.rules['b1_rule_republish'],dict(RULE_ZERO,matched=1,passed=1,**{'actions.total':1,'actions.success':1}))
        self.assertEqual(self.rules['b1_rule_http'],dict(RULE_ZERO,matched=1,passed=1,**{'actions.total':1,'actions.success':1}))
        self.assertEqual((self.action['matched'],self.action['success'],self.action['failed']),(1,1,0))
        self.assertEqual(self.message[0],API_ALERTS.encode())
        self.assertEqual(len(self.runs),3);self.assertEqual(self.active,set());self.assertEqual(self.connected,set())
        for root in self.roots:self.assertFalse(root.exists())
        self.assertEqual(self.events[0],'enter');self.assertEqual(self.events[-1],'exit')
        self.assertEqual(self.events[1],'inspect');self.assertEqual(self.events[-2],'inspect')
        self.assertEqual(self.paths[:4],['/actions/http:b1_http_action','/rules/b1_rule_republish/metrics',
            '/rules/b1_rule_http/metrics','/actions/http:b1_http_action/metrics'])
        self.assertEqual(self.paths[-1],'/clients?page=1&limit=100')
        topic,payload=self.message
        sensor=[d for p,d in self.posts if p=='/publish'][0]
        for value in (b'generated-sensor-password',b'generated-gateway-password',b'generated-api-secret',
                      b'Basic '+base64.b64encode(b'generated-api-key:generated-api-secret'),payload,
                      sensor['topic'].encode(),sensor['payload'].encode(),b'Warning: Publish 1 failed: Not authorized.'):
            with self.assertRaises(PrivateFailure):result.scan(b'evidence '+value)
        result.scan('階段：還原；結果：通過'.encode())

    def test_order_refused_publishes_then_session_then_api_subscription_then_api_inputs(self):
        self.run_delivery()
        entry=[next(x for x in a if x.startswith('--entrypoint=')) for a in self.runs]
        homes=[next(x for x in a if x.startswith('XDG_CONFIG_HOME=')) for a in self.runs]
        self.assertEqual(entry,['--entrypoint=mosquitto_pub','--entrypoint=mosquitto_pub','--entrypoint=mosquitto_sub'])
        self.assertEqual(homes,['XDG_CONFIG_HOME=/work/sensor','XDG_CONFIG_HOME=/work/gateway','XDG_CONFIG_HOME=/work/sub'])
        sub_name=self.runs[2][self.runs[2].index('--name')+1]
        self.assertEqual([p for p,_ in self.posts],['/clients/'+sub_name+'/subscribe','/publish','/publish'])
        self.assertEqual(self.posts[0][1],{'topic':API_ALERTS,'qos':1})
        sensor,cmd=self.posts[1][1],self.posts[2][1]
        self.assertRegex(sensor['topic'],r'^b1/sensor/b1-sensor/delivery-[0-9a-f]{12}$')
        self.assertRegex(cmd['topic'],r'^b1/cmd/delivery-[0-9a-f]{12}$')
        self.assertGreater(json.loads(sensor['payload'])['temp'],30)
        self.assertEqual(len({a[a.index('--name')+1] for a in self.runs}),3)

    def test_refused_publishes_move_no_counter_before_any_api_input(self):
        self.run_delivery()
        first,second=self.snapshots[:2],self.snapshots[2:4]
        self.assertEqual([r for r,_ in first],['b1_rule_republish','b1_rule_http'])
        self.assertEqual(first,second);self.assertTrue(all(s==RULE_ZERO for _,s in second))
        # Both refused publishes ran before the second snapshot and before any API input.
        self.assertEqual(sum('--entrypoint=mosquitto_pub' in a for a in self.runs),2)
        self.assertEqual([p for p,_ in self.posts].count('/publish'),2)

    # ---- refusals: inputs, contract, identity, action -------------------------------------
    def test_input_refusals_before_any_process_io(self):
        other=base.SourceObjects()
        cases=[dict(registry=self.runtime),dict(provision=object()),dict(expected_container_id='A'*64),
               dict(expected_container_id=self.cid[:-1]),dict(clients=object()),dict(api_credentials=object()),
               dict(source_objects=other),dict(source_objects=self.mint(base.original_objects(),registry=object())),
               dict(quiesce=True),
               dict(clients=workflow.SourceClients(dict(self.clients.fields,sensor_user=b'b1-gateway'))),
               dict(clients=workflow.SourceClients(dict(self.clients.fields,gateway_password=b'generated-unregistered')))]
        for change in cases:
            with self.subTest(change=sorted(change)):
                self.events.clear();self.refused('input',**change);self.assertEqual(self.events,[])

    def test_changed_original_rule_action_or_connector_refuses_as_contract(self):
        edits=(lambda o:o['rules']['b1_rule_republish'].update(sql='SELECT payload.temp as t, clientid FROM "b1/sensor/#" WHERE payload.temp > 31'),
               lambda o:o['rules']['b1_rule_http'].update(actions=['http:other']),
               lambda o:o['rules']['b1_rule_republish']['actions'][0]['args'].update(topic='b1/alerts/${username}'),
               lambda o:o['actions'][('http','b1_http_action')]['parameters'].update(method='post'),
               lambda o:o['connectors'][('http','b1_http')].update(url='http://127.0.0.1:18084'))
        for index,edit in enumerate(edits):
            with self.subTest(edit=index):
                objects=base.original_objects();edit(objects);self.events.clear()
                self.refused('contract',source_objects=self.mint(objects));self.assertEqual(self.events,[])

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
        self.metrics_override=lambda d:(d.update(id='generated-other'),d)[1]
        self.refused('metrics');self.assertEqual(self.runs,[])

    # ---- refusals: the target file ACL must refuse the HA roles ----------------------------
    def test_sensor_publish_must_be_refused_by_the_file_acl(self):
        self.publish_allowed={'sensor'};self.refused('publish_sensor_allowed');self.assertEqual(len(self.runs),1)
        self.publish_allowed=set();self.fresh();self.puback={'sensor':0};self.refused('publish_sensor_allowed')
        for change in (dict(connack={'sensor':5}),dict(puback={'sensor':151}),dict(pub_exit=1),dict(extra_puback='sensor')):
            with self.subTest(change=sorted(change)):
                self.connack,self.puback,self.pub_exit,self.extra_puback={},{},None,None
                for k,v in change.items():setattr(self,k,v)
                self.fresh();self.refused('publish_sensor');self.assertEqual(len(self.runs),1)

    def test_gateway_publish_must_be_refused_by_the_file_acl(self):
        self.publish_allowed={'gateway'};self.refused('publish_gateway_allowed');self.assertEqual(len(self.runs),2)
        self.publish_allowed=set();self.fresh();self.connack={'gateway':5};self.refused('publish_gateway')
        self.assertEqual(self.posts,[])

    def test_counter_moved_by_a_refused_publish_refuses(self):
        self.counter_noise=True;self.refused('denied_counters')
        self.assertEqual(len(self.runs),2);self.assertEqual(self.posts,[])

    # ---- refusals: HA-gateway session and management subscription --------------------------
    def test_subscriber_launch_timeout_mismatch_and_allowed_output(self):
        self.exit_early=True;self.refused('subscribe_launch');self.assertEqual(len(self.runs),3)
        self.exit_early=False;self.visible=False;self.sub_wait=1.5;self.fresh()
        with patch.object(m,'READY_SECONDS',0.5):self.refused('subscribe_timeout')
        self.visible=True;self.sub_wait=0.3
        self.grants={GRANT,API_ALERTS};self.fresh();self.refused('subscribe_allowed');self.assertEqual(self.posts,[])
        self.grants={GRANT}
        for edit in (lambda rows:[dict(rows[0],qos=0)],lambda rows:[dict(rows[0],topic='b1/#')],
                     lambda rows:rows*2,lambda rows:[dict(rows[0],clientid='generated-other')]):
            with self.subTest():
                self.rows_override=edit;self.fresh();self.refused('subscribe_mismatch');self.assertEqual(self.posts,[])

    def test_management_subscription_reply_and_listing_are_exact(self):
        self.sub_wait=0.3
        for edit in (lambda a:dict(a,topic='b1/alerts/#'),lambda a:dict(a,qos=0),lambda a:dict(a,clientid='generated-other'),
                     lambda a:dict(a,node='emqx@generated'),lambda a:dict(a,nl=1),lambda a:dict(a,rh=False),
                     lambda a:dict(a,extra='generated'),lambda a:[a]):
            with self.subTest():
                self.api_sub_edit=edit;self.fresh();self.refused('api_subscribe')
                self.assertEqual([p for p,_ in self.posts][1:],[])
        self.api_sub_edit=None
        for status in (404,):
            self.api_sub_status=status;self.fresh();self.refused('api_subscribe')
        self.api_sub_status=200;self.api_sub_visible=False;self.sub_wait=1.5;self.fresh()
        with patch.object(m,'READY_SECONDS',0.2):self.refused('api_subscribe_timeout')
        self.sub_wait=0.3
        self.assertEqual(len(self.posts),1)
        self.api_sub_visible=True
        def qos_zero(rows):return [dict(r,qos=0) if r['topic']==API_ALERTS else r for r in rows]
        self.rows_override=qos_zero;self.fresh();self.refused('subscribe_mismatch')

    def test_management_publish_replies_are_exact(self):
        self.sub_wait=0.3
        for status in (400,503):
            with self.subTest(status=status):
                self.publish_status=status;self.fresh();self.refused('api_publish_sensor')
        self.publish_status=None
        self.publish_edit=lambda a:dict(a,message='generated');self.fresh();self.refused('api_publish_sensor')
        self.publish_edit=None
        count=[0]
        def second(answer):
            count[0]+=1
            return answer if count[0]==1 else dict(answer,reason_code=0)
        self.publish_edit=second;self.fresh();self.refused('api_publish_gateway')

    # ---- refusals: republish delivery to the HA-gateway session ----------------------------
    def test_republish_delivery_refusals(self):
        self.sub_wait=0.2;self.drop_republish=True;self.refused('republish_timeout')
        self.drop_republish=False;self.fresh();self.payload_override=b'generated-wrong'
        self.refused('republish_mismatch')
        self.payload_override=None;self.fresh();self.sub_exit=1;self.refused('republish_exit')
        self.sub_exit=0
        for line in (b'Subscribed (mid: 1): 1, 1\n',b'Subscribed (mid: 1): 1\n',b'Subscribed (mid: 1): 135, 135\n'):
            with self.subTest(line=line):
                self.sub_line=line;self.fresh();self.refused('republish_exit')

    # ---- refusals: vendor counters, clients, cleanup, deadline ------------------------------
    def test_http_action_outcomes_are_exact(self):
        for result,label in (('failed','http_action_failed'),('never','http_action_timeout'),('double','http_action_count')):
            with self.subTest(result=result):
                self.http_result=result;self.fresh();self.refused(label)
        self.http_result='success';self.http_rule_passed=0;self.fresh()
        self.refused('http_rule')

    def test_republish_rule_counters_must_move_exactly_once(self):
        self.extra_match=True;self.refused('republish_rule')

    def test_lingering_or_foreign_clients_refuse(self):
        self.foreign={'generated-foreign-client'};self.refused('clients')

    def test_owned_container_that_cannot_be_removed_refuses_as_cleanup(self):
        for home in ('sensor','sub'):
            with self.subTest(home=home):
                self.keep_container=home;self.remove_failure=True;self.fresh()
                with self.assertRaises(m.DeliveryRefused) as caught:self.run_delivery()
                self.assertEqual(caught.exception.label,'cleanup')
                self.remove_failure=False;self.active.clear()

    def test_cooperative_deadline_and_quiesce_exit_and_ram_files(self):
        with patch.object(m,'DEADLINE',0):self.refused('deadline')
        @contextmanager
        def failing():
            yield
            raise ValueError('generated-quiesce-exit')
        self.fresh();self.refused('quiesce',quiesce=failing)
        self.fresh()
        with patch.object(workflow,'_ram_client_parent',side_effect=ValueError('generated')):
            self.refused('files')

    def test_refusal_label_survives_a_failing_quiesce_exit(self):
        @contextmanager
        def failing():
            try:yield
            finally:raise ValueError('generated-quiesce-exit')
        self.publish_allowed={'sensor'}
        self.refused('publish_sensor_allowed',quiesce=failing)

    def test_cancellation_is_fixed_and_not_a_label(self):
        with patch.object(m,'_contract',side_effect=KeyboardInterrupt):
            with self.assertRaises(PrivateFailure) as caught:self.run_delivery()
        self.assertEqual(str(caught.exception),'controlled-delivery-cancelled')
        self.assertNotIsInstance(caught.exception,m.DeliveryRefused)

    # ---- small helpers and constants -------------------------------------------------------
    def test_mode_strings_equal_target_policy_constants_and_labels_unique(self):
        self.assertEqual((m.FILE_MODE,m.IMPORTED_MODE),(FILE_BASELINE,IMPORTED_MNESIA))
        self.assertEqual(len(set(m.LABELS)),len(m.LABELS))
        self.assertEqual(m.RuleDelivery(object(),object(),{})._mode,IMPORTED_MNESIA)

    def test_denied_accepts_only_the_vendor_refusal_shape(self):
        ns=base.SimpleNamespace
        ok=ns(returncode=0,stdout=b'Client a received CONNACK (0)\nClient a received PUBACK (Mid: 1, RC:135)\n',stderr=b'')
        self.assertIsNone(m._denied(ok,'publish_sensor'))
        spaced=ns(returncode=0,stdout=ok.stdout.replace(b'RC:135',b'RC: 135'),stderr=b'')
        self.assertIsNone(m._denied(spaced,'publish_sensor'))
        for rc in (b'0',b'16'):
            accepted=ns(returncode=0,stdout=ok.stdout.replace(b'135',rc),stderr=b'')
            self.assertEqual(m._denied(accepted,'publish_sensor'),'publish_sensor_allowed')
        for bad in (ns(returncode=1,stdout=ok.stdout,stderr=b''),
                    ns(returncode=0,stdout=ok.stdout.replace(b'CONNACK (0)',b'CONNACK (5)'),stderr=b''),
                    ns(returncode=0,stdout=ok.stdout.replace(b'Mid: 1',b'Mid: 2'),stderr=b''),
                    ns(returncode=0,stdout=ok.stdout+ok.stdout,stderr=b''),
                    ns(returncode=0,stdout=b'',stderr=b'')):
            self.assertEqual(m._denied(bad,'publish_sensor'),'publish_sensor')

    def test_post_helper_refuses_other_paths_and_unbounded_bodies(self):
        for path,doc in (('/rules',{'a':1}),('/clients/a b/subscribe',{'a':1}),('/clients//subscribe',{'a':1}),
                         ('/publish',{'a':float('nan')}),('/publish',{'a':'x'*5000})):
            with self.subTest(path=path):
                calls=[]
                runner=base.SimpleNamespace(podman=lambda *a,**k:calls.append(a))
                with self.assertRaises(ValueError):
                    m._api_post(runner,self.cid,path,b'Basic generated',self.runtime,doc,(200,))
                self.assertEqual(calls,[])

    def test_curl_quoting_roundtrip_of_nested_json(self):
        body=json.dumps({'payload':'{"temp":42}','topic':'b1/sensor/x'},sort_keys=True,separators=(',',':'))
        self.assertEqual(curl_value('data-binary = '+json.dumps(body),'data-binary'),body)


if __name__=='__main__':unittest.main()
