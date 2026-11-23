"""Restored HA rules really execute: republish delivery + original HTTP action.

Internal-candidate real-owner step for the imported Mnesia ACL target only. The
workflow runs it once, in the restore round, after that round's MQTT/API/negative
activity and BEFORE its native capture, so the capture also covers this client
activity. No CLI, product code, public import guard or broker object is changed:
the only broker writes are MQTT publishes; HTTP calls are GETs.

Republish rule: one pinned Mosquitto subscriber logs in with the HA gateway
credentials and subscribes to the rule's rendered output topic. Once the broker
lists that subscription, the HA sensor publishes ONE synthetic JSON reading on
its own sensor topic. The subscriber must receive exactly one message carrying
the vendor-rendered topic and payload (emqx_rule_actions.erl republish/3,
emqx_template.erl:443 integer rendering) at QoS 1 with the retain flag clear.

HTTP action: the HA backup's connector targets the broker's OWN status API on
loopback 18083 ("to the broker status API"), and the restored lab target binds
its dashboard there exactly as HA does. A sidecar NC sink cannot hold that port
without displacing the broker's listener and changing the original target, so
the original target answers: one HA gateway publish on the rule's topic must
move the vendor counters of the HTTP rule and action by exactly one success and
zero failures/drops. A success is only counted for a 2xx reply
(emqx_bridge_http_connector.erl:946-987 transform_result, emqx_rule_runtime.erl
805-827). The request bytes on the wire are NOT captured; the action's
method/path/body fields are proven separately (object integrity) and here.

All values stay in RAM, are registered in the actual runtime registry, and only
fixed labels escape. Every owned client container is removed and proven absent.
"""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
import time

from emqx_private_boundary import PrivateFailure

LABELS=('input','contract','quiesce','identity','files','http_status','metrics',
        'subscribe_launch','subscribe_timeout','subscribe_mismatch',
        'publish_sensor','publish_sensor_denied','republish_exit','republish_timeout','republish_mismatch',
        'publish_gateway','publish_gateway_denied',
        'http_action_timeout','http_action_failed','http_action_count',
        'http_rule','republish_rule','clients','cleanup','deadline')

# Lab target dashboard bind (emqx_real_owner_workflow._target_base) == HA connector target.
PORT=18083
REPUBLISH_RULE='b1_rule_republish'
HTTP_RULE='b1_rule_http'
ACTION_ID='http:b1_http_action'
# Fixed oracle: the only original rule/action shape whose effect this step can
# compute. Anything else in the captured backup refuses as 'contract'.
REPUBLISH_SQL='SELECT payload.temp as t, clientid FROM "b1/sensor/#" WHERE payload.temp > 30'
HTTP_SQL='SELECT * FROM "b1/cmd/#"'
REPUBLISH_ARGS={'topic':'b1/alerts/${clientid}','qos':1,'retain':False,'payload':'${t}',
                'mqtt_properties':{},'user_properties':''}
CONNECTOR_URL='http://127.0.0.1:18083'
ACTION_PARAMETERS={'method':'get','path':'/api/v5/status','body':''}
THRESHOLD=30
# Vendor counters (emqx_rule_engine_api.erl:82-97, emqx_bridge.hrl:130-147).
RULE_COUNTERS=('matched','passed','failed','failed.exception','failed.no_result','actions.total',
               'actions.success','actions.failed','actions.failed.out_of_service',
               'actions.failed.unknown','actions.discarded')
ACTION_COUNTERS=('matched','success','failed','dropped','dropped.other','dropped.expired',
                 'dropped.queue_full','dropped.resource_not_found','dropped.resource_stopped',
                 'late_reply','received')
# 'retried' is deliberately not pinned: a recoverable first attempt that is
# retried and then answered 2xx still counts one success and no failure.
RULE_DELTA={'matched':1,'passed':1,'actions.total':1,'actions.success':1}
ACTION_DELTA={'matched':1,'success':1}
LIMIT=65536
HTTP_LIMIT=64*1024+512
# Wall-clock bounds only, sized for the contended lab host (load ~27 on
# 2026-11-23); they lengthen refusal paths, never the success path or a check.
DEADLINE=240
READY_SECONDS=45
HTTP_SECONDS=30
CLIENTS_SECONDS=30
SUB_WAIT='60'           # mosquitto_sub -W (starts after CONNACK); exit 27 on timeout
SUB_CONTAINER='75'      # podman --timeout
SUB_RUNNER=85           # runner timeout
PUB_CONTAINER='30'
PUB_RUNNER=40
POLL=0.25


class DeliveryRefused(PrivateFailure):
    """Only a compiled label escapes; never values, wire text or exceptions."""
    def __init__(self,label):
        self.label=label if label in LABELS else 'input'
        super().__init__('controlled-delivery-refused')


class RuleDelivery:
    def __init__(self,runtime,source,facts):self._runtime,self._source,self._facts=runtime,source,facts
    def __repr__(self):return '<EMQX private restored rule delivery observation>'
    def scan(self,payload):self._runtime.scan(payload);self._source.scan(payload)
    def private_facts(self):return dict(self._facts)
    def scope(self):
        return ('republish-delivered-once-to-ha-gateway-subscriber',
                'http-action-one-2xx-at-original-loopback-status-api-by-vendor-counters',
                'http-request-bytes-not-captured-no-sink',
                'restore-round-only-not-commercial-acceptance')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def _contract(objects):
    """Exact captured original fields; JSON types are compared strictly."""
    rules,actions,connectors=objects['rules'],objects['actions'],objects['connectors']
    republish,http=rules[REPUBLISH_RULE],rules[HTTP_RULE]
    action,connector=actions[('http','b1_http_action')],connectors[('http','b1_http')]
    for obj in (republish,http,action,connector):
        if type(obj) is not dict or obj.get('enable',True) is not True:raise ValueError()
    if republish.get('sql')!=REPUBLISH_SQL or http.get('sql')!=HTTP_SQL or http.get('actions')!=[ACTION_ID]:
        raise ValueError()
    calls=republish.get('actions')
    if (type(calls) is not list or len(calls)!=1 or type(calls[0]) is not dict
            or set(calls[0])!={'function','args'} or calls[0]['function']!='republish'
            or type(calls[0]['args']) is not dict):raise ValueError()
    args=dict(calls[0]['args'])
    if args.pop('direct_dispatch',False) is not False or _canonical(args)!=_canonical(REPUBLISH_ARGS):raise ValueError()
    parameters=action.get('parameters')
    if (action.get('connector')!='b1_http' or type(parameters) is not dict
            or any(_canonical(parameters.get(k))!=_canonical(v) for k,v in ACTION_PARAMETERS.items())
            or parameters.get('headers',{})!={} or connector.get('headers',{})!={}
            or connector.get('url')!=CONNECTOR_URL):raise ValueError()


def _api(runner,cid,path,authorization,runtime,allow=(200,)):
    """One fixed loopback GET through the broker's own curl; body registered."""
    from emqx_source_api_validator import _register_document
    if re.fullmatch(r'/[A-Za-z0-9_./:?=&-]{1,200}',path) is None:raise ValueError()
    config=['url = '+json.dumps('http://127.0.0.1:'+str(PORT)+'/api/v5'+path),
        'silent','show-error','max-time = 5','connect-timeout = 3','proxy = ""','noproxy = "*"',
        'proto = "=http"','max-redirs = 0','request = "GET"',
        'header = '+json.dumps('Authorization: '+authorization.decode('ascii')),
        'write-out = "\\n%{content_type}\\n%{http_code}"']
    response=runner.podman('exec','-i',cid,'curl','-q','--config','-',input=('\n'.join(config)+'\n').encode(),
        timeout=10,max_output=HTTP_LIMIT,check=False)
    if (type(response.returncode) is not int or response.returncode or type(response.stdout) is not bytes
            or len(response.stdout)>HTTP_LIMIT):raise ValueError()
    body,ctype,status=response.stdout.rsplit(b'\n',2)
    if re.fullmatch(rb'[1-5][0-9]{2}',status) is None or int(status) not in allow:raise ValueError()
    if ctype.split(b';',1)[0].strip().lower()!=b'application/json':raise ValueError()
    return int(status),_register_document(runtime,body)


def _counters(document,names,identity=None):
    if type(document) is not dict or type(document.get('metrics')) is not dict:raise ValueError()
    if identity is not None and document.get('id')!=identity:raise ValueError()
    values={}
    for name in names:
        value=document['metrics'].get(name)
        if type(value) is not int or value<0:raise ValueError()
        values[name]=value
    return values


def _exact(before,after,expected):
    return all(after[name]-before[name]==expected.get(name,0) for name in before)


def _private_dir(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError()


def _write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as handle:
        os.fchmod(handle.fileno(),0o600);handle.write(raw);handle.flush()
        info=os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=len(raw)):raise ValueError()


def _flags(cid,root,home,seconds):
    # Same proven client boundary as the workflow MQTT probes: the broker's own
    # network=none namespace, read-only private RAM config, no argv secrets.
    return ('--pull=never','--log-driver=none','--image-volume=ignore','--network=container:'+cid,
        '--userns=keep-id:uid=1000,gid=1000','--user=1000:1000','--memory=64m','--cpus=0.25',
        '--pids-limit=32','--timeout='+seconds,'--stop-timeout=1','-e','HOME=/work',
        '-e','XDG_CONFIG_HOME=/work/'+home,'-v',str(root)+':/work:ro')


def _shape(result):
    if (type(result.returncode) is not int or any(type(x) is not bytes or len(x)>LIMIT
            for x in (result.stdout,result.stderr))):raise ValueError()


def _published(result,label):
    """None when accepted, else the fixed refusal label."""
    _shape(result)
    output=result.stdout+b'\n'+result.stderr
    acks=re.findall(rb'received PUBACK \(Mid: ([0-9]{1,5}), RC: ?([0-9]{1,3})\)',output)
    if len(acks)==1 and acks[0][1]==b'135':return label+'_denied'
    # PUBACK 16 = accepted, no matching subscriber (rules are not subscribers).
    if (result.returncode!=0 or re.findall(rb'received CONNACK \(([0-9]{1,3})\)',output)!=[b'0']
            or acks not in ([(b'1',b'0')],[(b'1',b'16')])):return label
    return None


def _background(holder,runner,args,kwargs):
    try:holder['result']=runner.podman(*args,**kwargs)
    except BaseException:holder['error']=True


def run_rule_delivery(*,registry,provision,expected_container_id,clients,api_credentials,
                      source_objects,quiesce):
    """Caller holds the actual exclusion via quiesce; cooperative 240s deadline.

    registry: the session CombinedRegistry that minted source_objects. MQTT
    credentials must ALREADY be registered. No retries of publishes, no default
    auth, no new broker object. Returns a private RuleDelivery; the caller MUST
    scan its final evidence through it. Refusals carry one fixed label only.
    """
    phase='input'
    try:
        from emqx_adapter_owner import OwnerProvision,LabOwnerRunner
        from emqx_adapter_mqtt import CLIENT
        from emqx_b1_object_integrity import SourceObjects,_RECORDS as SOURCE_RECORDS
        from emqx_owned_client import owned_client
        from emqx_owner_fixture_files import _record
        from emqx_post_restore_values import _runtime_identity
        from emqx_real_owner_workflow import SourceClients,SourceAPICredentials,_ram_client_parent
        from emqx_runtime_credentials import RuntimeRegistry
        from emqx_runtime_workflow import CombinedRegistry
        if (type(registry) is not CombinedRegistry or type(registry._runtime) is not RuntimeRegistry
                or type(provision) is not OwnerProvision or not isinstance(provision.runner,LabOwnerRunner)
                or provision.runner.owner!='appowner' or type(clients) is not SourceClients
                or type(api_credentials) is not SourceAPICredentials or type(source_objects) is not SourceObjects
                or type(expected_container_id) is not str
                or re.fullmatch('[0-9a-f]{64}',expected_container_id) is None or not callable(quiesce)):
            raise ValueError()
        runtime=registry._runtime
        source=SOURCE_RECORDS.get(source_objects)
        if source is None or source['registry'] is not registry:raise ValueError()
        registry.scan(b'');source_objects.scan(b'')
        fields=clients.fields
        if (fields.get('sensor_user'),fields.get('gateway_user'))!=(b'b1-sensor',b'b1-gateway'):raise ValueError()
        for name in ('sensor_user','sensor_password','gateway_user','gateway_password'):
            value=fields[name]
            if (type(value) is not bytes or re.fullmatch(rb'[A-Za-z0-9_-]{1,128}',value) is None
                    or value not in runtime._values):raise ValueError()
        key,secret=api_credentials.fields[4],api_credentials.fields[5]
        basic=b'Basic '+base64.b64encode(key+b':'+secret)
        phase='contract';_contract(source['objects'])
        phase='input'
        prefix=provision.fixture.prefix
        names=tuple(prefix+'-mqtt-'+secrets.token_hex(6) for _ in range(3))
        if len(set(names))!=3:raise ValueError()
        sub_name,sensor_name,gateway_name=names
        reading=THRESHOLD+1+secrets.randbelow(69)
        sensor_topic=b'b1/sensor/'+fields['sensor_user']+b'/delivery-'+secrets.token_hex(6).encode()
        sensor_payload=b'{"temp":'+str(reading).encode()+b'}'
        alerts_topic=b'b1/alerts/'+sensor_name.encode()
        alerts_payload=str(reading).encode()
        cmd_topic=b'b1/cmd/delivery-'+secrets.token_hex(6).encode()
        cmd_payload=b'{"delivery":"'+secrets.token_hex(8).encode()+b'"}'
        expected=b'DELIVERY:0:1:'+alerts_topic+b':'+alerts_payload.hex().encode()
        runtime.register_bundle({'runtime-login-input':[key,secret,basic,sensor_topic,sensor_payload,
            alerts_topic,alerts_payload,cmd_topic,cmd_payload,expected]})
        record,owner=_record(provision.file_capability)
        if owner is not provision:raise ValueError()
        old=record['cid'];deadline=time.monotonic()+DEADLINE
        r,cid=provision.runner,expected_container_id

        def fail(label):
            # phase is the single label source, so a later cleanup/quiesce
            # exception can never relabel or hide this refusal.
            nonlocal phase
            phase=label;raise ValueError()

        def timely():
            if time.monotonic()>=deadline:fail('deadline')

        def api(path,allow=(200,)):
            timely();return _api(r,cid,path,basic,runtime,allow)

        def outputs(result):
            runtime.register_bundle({'runtime-login-token':[x for x in (result.stdout,result.stderr) if x]})

        phase='quiesce'
        with quiesce():
            phase='identity';timely()
            before=_runtime_identity(provision,cid)
            if before[3].get('NetworkMode')!='none':raise ValueError()
            phase='http_status'
            status=api('/actions/'+ACTION_ID)[1]
            if type(status) is not dict or status.get('status')!='connected' or status.get('enable') is not True:
                raise ValueError()
            phase='metrics'
            start={'republish':_counters(api('/rules/'+REPUBLISH_RULE+'/metrics')[1],RULE_COUNTERS,REPUBLISH_RULE),
                   'http':_counters(api('/rules/'+HTTP_RULE+'/metrics')[1],RULE_COUNTERS,HTTP_RULE),
                   'action':_counters(api('/actions/'+ACTION_ID+'/metrics')[1],ACTION_COUNTERS)}
            phase='files'
            with tempfile.TemporaryDirectory(prefix=sub_name+'-',dir=_ram_client_parent()) as directory:
                root=Path(directory);root.chmod(0o700);_private_dir(root)
                for home in ('sub','sensor','gateway'):
                    os.mkdir(root/home,0o700);_private_dir(root/home)
                _write(root/'sub'/'mosquitto_sub',b'-u '+fields['gateway_user']+b'\n-P '+fields['gateway_password']
                       +b'\n-t '+alerts_topic+b'\n')
                _write(root/'sensor'/'mosquitto_pub',b'-u '+fields['sensor_user']+b'\n-P '+fields['sensor_password']
                       +b'\n-t '+sensor_topic+b'\n')
                _write(root/'gateway'/'mosquitto_pub',b'-u '+fields['gateway_user']+b'\n-P '+fields['gateway_password']
                       +b'\n-t '+cmd_topic+b'\n')
                _write(root/'sensor.payload',sensor_payload);_write(root/'cmd.payload',cmd_payload)
                phase='subscribe_launch'
                with owned_client(r,sub_name) as owned:
                    holder={}
                    thread=threading.Thread(target=_background,daemon=True,args=(holder,r,
                        ('run','--rm',*owned,*_flags(cid,root,'sub',SUB_CONTAINER),'--entrypoint=mosquitto_sub',CLIENT,
                         '-h','127.0.0.1','-p','1883','-V','mqttv5','-q','1','-i',sub_name,'-C','1','-W',SUB_WAIT,
                         '-d','-F','DELIVERY:%r:%q:%t:%x'),
                        {'timeout':SUB_RUNNER,'max_output':LIMIT,'check':False}))
                    thread.start()
                    try:
                        phase='subscribe_timeout';ready=time.monotonic()+READY_SECONDS
                        while True:
                            code,rows=api('/clients/'+sub_name+'/subscriptions',(200,404))
                            if code==200 and rows!=[]:
                                if (type(rows) is not list or len(rows)!=1 or type(rows[0]) is not dict
                                        or rows[0].get('topic')!=alerts_topic.decode() or rows[0].get('qos')!=1
                                        or rows[0].get('clientid')!=sub_name):fail('subscribe_mismatch')
                                break
                            if not thread.is_alive():fail('subscribe_launch')
                            if time.monotonic()>=ready:fail('subscribe_timeout')
                            time.sleep(POLL)
                        phase='publish_sensor';timely()
                        with owned_client(r,sensor_name) as published:
                            sent=r.podman('run','--rm',*published,*_flags(cid,root,'sensor',PUB_CONTAINER),
                                '--entrypoint=mosquitto_pub',CLIENT,'-h','127.0.0.1','-p','1883','-V','mqttv5',
                                '-q','1','-i',sensor_name,'-d','-f','/work/sensor.payload',
                                timeout=PUB_RUNNER,max_output=LIMIT,check=False)
                            _shape(sent);outputs(sent)
                            problem=_published(sent,'publish_sensor')
                            if problem:fail(problem)
                    finally:
                        thread.join(SUB_RUNNER+5)
                        if thread.is_alive():fail('cleanup')
                    phase='republish_exit'
                    if holder.get('error') or 'result' not in holder:raise ValueError()
                    received=holder['result'];_shape(received);outputs(received)
                    if received.returncode==27:fail('republish_timeout')
                    wire=received.stdout+b'\n'+received.stderr
                    if (received.returncode!=0 or re.findall(rb'received CONNACK \(([0-9]{1,3})\)',wire)!=[b'0']
                            or re.findall(rb'Subscribed[^\n]*:\s*([0-9]{1,3})\b',wire)!=[b'1']):raise ValueError()
                    if [x for x in received.stdout.split(b'\n') if x.startswith(b'DELIVERY:')]!=[expected]:
                        fail('republish_mismatch')
                    phase='cleanup'
                phase='publish_gateway';timely()
                with owned_client(r,gateway_name) as published:
                    sent=r.podman('run','--rm',*published,*_flags(cid,root,'gateway',PUB_CONTAINER),
                        '--entrypoint=mosquitto_pub',CLIENT,'-h','127.0.0.1','-p','1883','-V','mqttv5',
                        '-q','1','-i',gateway_name,'-d','-f','/work/cmd.payload',
                        timeout=PUB_RUNNER,max_output=LIMIT,check=False)
                    _shape(sent);outputs(sent)
                    problem=_published(sent,'publish_gateway')
                    if problem:fail(problem)
                    phase='cleanup'
                phase='files'
            phase='http_action_timeout';settle=time.monotonic()+HTTP_SECONDS
            while True:
                action=_counters(api('/actions/'+ACTION_ID+'/metrics')[1],ACTION_COUNTERS)
                http=_counters(api('/rules/'+HTTP_RULE+'/metrics')[1],RULE_COUNTERS,HTTP_RULE)
                failures=[name for name in ACTION_COUNTERS if name not in ('matched','success')]
                if (any(action[n]!=start['action'][n] for n in failures)
                        or any(http[n]!=start['http'][n] for n in RULE_COUNTERS if n.startswith('actions.failed')
                               or n in ('actions.discarded','failed','failed.exception','failed.no_result'))):
                    fail('http_action_failed')
                if action['success']>start['action']['success'] and http['actions.success']>start['http']['actions.success']:
                    break
                if time.monotonic()>=settle:fail('http_action_timeout')
                time.sleep(POLL*2)
            if not _exact(start['action'],action,ACTION_DELTA):fail('http_action_count')
            if not _exact(start['http'],http,RULE_DELTA):fail('http_rule')
            phase='republish_rule'
            republish=_counters(api('/rules/'+REPUBLISH_RULE+'/metrics')[1],RULE_COUNTERS,REPUBLISH_RULE)
            if not _exact(start['republish'],republish,RULE_DELTA):raise ValueError()
            phase='clients';gone=time.monotonic()+CLIENTS_SECONDS
            while True:
                listed=api('/clients?page=1&limit=100')[1]
                rows=listed.get('data') if type(listed) is dict else None
                if type(rows) is not list or any(type(x) is not dict or x.get('clientid') not in names for x in rows):
                    raise ValueError()
                if not rows:break
                if time.monotonic()>=gone:raise ValueError()
                time.sleep(POLL)
            phase='identity';timely()
            if _runtime_identity(provision,cid)!=before or record['cid']!=old:raise ValueError()
            phase='quiesce'
        phase='identity'
        if _record(provision.file_capability)[1] is not provision or record['cid']!=old:raise ValueError()
        phase='deadline';timely()
        registry.scan(b'');source_objects.scan(b'')
        return RuleDelivery(runtime,source_objects,{
            'republish':'one-qos1-nonretained-message-with-rendered-topic-and-payload',
            'http_action':'one-success-zero-failure-at-original-loopback-target',
            'rules':(REPUBLISH_RULE,HTTP_RULE),'action':ACTION_ID})
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('controlled-delivery-cancelled') from None
    except Exception:raise DeliveryRefused(phase) from None
