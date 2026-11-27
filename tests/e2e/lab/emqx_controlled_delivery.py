"""Restored HA rules really execute: republish delivery + original HTTP action.

Internal-candidate real-owner step; run_rule_delivery serves the imported Mnesia
ACL target, run_file_policy_rule_delivery the FILE baseline target (below). The
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

FILE baseline (run_file_policy_rule_delivery): the target keeps its own file ACL,
whose exact bytes stay unchanged (emqx_real_owner_workflow._target_acl): the HA
gateway may subscribe only b1/retained/# and every other HA publish/subscribe
falls to {deny, all} with deny_action=ignore, i.e. PUBACK/SUBACK 0x87
(emqx_channel.erl:643-657, 2541-2562). That twin first proves the HA sensor and
gateway rule-topic publishes are refused and reach no rule, then uses the only
authorized rule ingress of that target: the restored HA API key through the
management API, which runs no MQTT authorization (POST /publish publishes as
from=http_api, emqx_mgmt_api_publish.erl:255-265,332-357; POST
/clients/:id/subscribe adds a session subscription without check_sub_authzs,
emqx_mgmt.erl:596-600 and emqx_channel.erl:1588-1597 versus 914-921). Its only
broker writes are those two API publishes, one API session subscription that
ends with its client, and the refused MQTT publishes.
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
        'http_rule','republish_rule','clients','cleanup','deadline',
        # FILE baseline twin only (run_file_policy_rule_delivery).
        'publish_sensor_allowed','publish_gateway_allowed','denied_counters','subscribe_allowed',
        'api_subscribe','api_subscribe_timeout','api_publish_sensor','api_publish_gateway')

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
# FILE baseline twin. Mode strings equal emqx_imported_acl_target_mode's constants.
IMPORTED_MODE='imported-mnesia-acl'
FILE_MODE='file-baseline'
# An API message's ${clientid} renders as http_api (emqx_mgmt_api_publish.erl:355-356,
# emqx_rule_events.erl:336,349, emqx_template.erl:445).
API_SENDER=b'http_api'
FILE_ALERTS_TOPIC=b'b1/alerts/'+API_SENDER
# The HA gateway's only subscribe grant in the target file ACL; it keeps the
# subscriber connected while the republish output filter is refused.
FILE_GATEWAY_GRANT=b'b1/retained/#'
NO_SUBSCRIBERS={'reason_code':16,'message':'no_matching_subscribers'}
NODE='emqx@127.0.0.1'
SUBSCRIBE_OPTIONS=('nl','rap','rh')


class DeliveryRefused(PrivateFailure):
    """Only a compiled label escapes; never values, wire text or exceptions."""
    def __init__(self,label):
        self.label=label if label in LABELS else 'input'
        super().__init__('controlled-delivery-refused')


class RuleDelivery:
    def __init__(self,runtime,source,facts,mode=IMPORTED_MODE):
        self._runtime,self._source,self._facts,self._mode=runtime,source,facts,mode
    def __repr__(self):return '<EMQX private restored rule delivery observation>'
    def scan(self,payload):self._runtime.scan(payload);self._source.scan(payload)
    def private_facts(self):return dict(self._facts)
    def scope(self):
        if self._mode==FILE_MODE:
            return ('ha-rule-topic-publishes-denied-by-target-file-acl-puback135-no-counter-moved',
                    'ha-gateway-own-subscribe-of-republish-output-denied-suback135',
                    'rule-input-through-trusted-management-publish-api-with-restored-key',
                    'republish-delivered-once-to-ha-gateway-session-via-management-api-subscription',
                    'http-action-one-2xx-at-original-loopback-status-api-by-vendor-counters',
                    'http-request-bytes-not-captured-no-sink',
                    'restore-round-only-not-commercial-acceptance')
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


def _denied(result,label):
    """FILE baseline: None when the target file ACL refused the QoS1 publish.

    Refusal = CONNACK 0 then exactly one PUBACK (Mid 1, RC 135); mosquitto_pub still
    disconnects cleanly and exits 0 (mosquitto 2.0.22 client/pub_client.c:199-221,
    365-369, 606-613). An accepted PUBACK 0/16 is label+'_allowed'; else label.
    """
    _shape(result)
    output=result.stdout+b'\n'+result.stderr
    acks=re.findall(rb'received PUBACK \(Mid: ([0-9]{1,5}), RC: ?([0-9]{1,3})\)',output)
    if acks in ([(b'1',b'0')],[(b'1',b'16')]):return label+'_allowed'
    if (result.returncode!=0 or re.findall(rb'received CONNACK \(([0-9]{1,3})\)',output)!=[b'0']
            or acks!=[(b'1',b'135')]):return label
    return None


def _api_post(runner,cid,path,authorization,runtime,document,allow):
    """One fixed loopback POST through the broker's own curl (FILE baseline only).

    Only the management publish and client-subscribe endpoints; the JSON body and
    the Authorization header travel in the stdin config, never argv. The body must
    be printable ASCII so the config quoting needs only \\\\ and \\" (curl
    tool_parsecfg unslashquote). The reply is registered like every GET reply.
    """
    from emqx_source_api_validator import _register_document
    if path!='/publish' and re.fullmatch(r'/clients/[A-Za-z0-9_-]{1,64}/subscribe',path) is None:raise ValueError()
    body=json.dumps(document,sort_keys=True,separators=(',',':'),allow_nan=False)
    if re.fullmatch(r'[\x20-\x7e]{2,4096}',body) is None:raise ValueError()
    runtime.register_bundle({'runtime-login-input':[body.encode()]})
    config=['url = '+json.dumps('http://127.0.0.1:'+str(PORT)+'/api/v5'+path),
        'silent','show-error','max-time = 5','connect-timeout = 3','proxy = ""','noproxy = "*"',
        'proto = "=http"','max-redirs = 0','request = "POST"',
        'header = '+json.dumps('Authorization: '+authorization.decode('ascii')),
        'header = "Content-Type: application/json"','data-binary = '+json.dumps(body),
        'write-out = "\\n%{content_type}\\n%{http_code}"']
    response=runner.podman('exec','-i',cid,'curl','-q','--config','-',input=('\n'.join(config)+'\n').encode(),
        timeout=10,max_output=HTTP_LIMIT,check=False)
    if (type(response.returncode) is not int or response.returncode or type(response.stdout) is not bytes
            or len(response.stdout)>HTTP_LIMIT):raise ValueError()
    reply,ctype,status=response.stdout.rsplit(b'\n',2)
    if re.fullmatch(rb'[1-5][0-9]{2}',status) is None or int(status) not in allow:raise ValueError()
    if ctype.split(b';',1)[0].strip().lower()!=b'application/json':raise ValueError()
    return int(status),_register_document(runtime,reply)


def _subscription_rows(rows,client):
    """Sorted (topic, qos) pairs of one client's listed subscriptions, else None."""
    if type(rows) is not list:return None
    pairs=[]
    for row in rows:
        if (type(row) is not dict or row.get('clientid')!=client or type(row.get('topic')) is not str
                or type(row.get('qos')) is not int):return None
        pairs.append((row['topic'],row['qos']))
    return sorted(pairs)


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


def run_file_policy_rule_delivery(*,registry,provision,expected_container_id,clients,api_credentials,
                                  source_objects,quiesce):
    """FILE baseline twin of run_rule_delivery: same caller contract and deadline.

    The target's own file ACL (unchanged) must refuse the HA roles on the rule
    topics, so the restored rules are fed through the target's trusted ingress:
    1. HA sensor and HA gateway QoS1 publishes on the rule input topics are each
       refused (one PUBACK 135) and no rule/action counter moves.
    2. A subscriber logs in with the HA gateway credentials and subscribes to the
       target's retained grant plus the republish output topic of an API message;
       the target must grant only the first (SUBACK 1, 135 and the broker's list).
    3. The restored HA API key adds the republish output subscription to that live
       HA-gateway session (management API), then publishes ONE qualifying reading
       and ONE command through the management publish API (202, no subscribers).
    4. Exactly one rendered republish reaches the HA-gateway session; the HTTP rule
       and action counters move by exactly one 2xx success at the original target.
    run_rule_delivery stays byte-identical since its real passes; this twin keeps
    its input checks, process boundary, quiescence, cleanup and label rules.
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
        alerts_payload=str(reading).encode()
        cmd_topic=b'b1/cmd/delivery-'+secrets.token_hex(6).encode()
        cmd_payload=b'{"delivery":"'+secrets.token_hex(8).encode()+b'"}'
        expected=b'DELIVERY:0:1:'+FILE_ALERTS_TOPIC+b':'+alerts_payload.hex().encode()
        runtime.register_bundle({'runtime-login-input':[key,secret,basic,sensor_topic,sensor_payload,
            alerts_payload,cmd_topic,cmd_payload,expected]})
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

        def post(path,document,allow):
            timely();return _api_post(r,cid,path,basic,runtime,document,allow)

        def outputs(result):
            runtime.register_bundle({'runtime-login-token':[x for x in (result.stdout,result.stderr) if x]})

        def counters():
            return {'republish':_counters(api('/rules/'+REPUBLISH_RULE+'/metrics')[1],RULE_COUNTERS,REPUBLISH_RULE),
                    'http':_counters(api('/rules/'+HTTP_RULE+'/metrics')[1],RULE_COUNTERS,HTTP_RULE),
                    'action':_counters(api('/actions/'+ACTION_ID+'/metrics')[1],ACTION_COUNTERS)}

        def listed():
            code,rows=api('/clients/'+sub_name+'/subscriptions',(200,404))
            if code==404 or rows==[]:return None
            pairs=_subscription_rows(rows,sub_name)
            if pairs is None:fail('subscribe_mismatch')
            return pairs

        def refused_publish(label,home,name,payload_file):
            # Caller set phase=label; an owned-container exit failure is 'cleanup'.
            nonlocal phase
            with owned_client(r,name) as owned:
                sent=r.podman('run','--rm',*owned,*_flags(cid,root,home,PUB_CONTAINER),
                    '--entrypoint=mosquitto_pub',CLIENT,'-h','127.0.0.1','-p','1883','-V','mqttv5',
                    '-q','1','-i',name,'-d','-f','/work/'+payload_file,
                    timeout=PUB_RUNNER,max_output=LIMIT,check=False)
                _shape(sent);outputs(sent)
                problem=_denied(sent,label)
                if problem:fail(problem)
                phase='cleanup'

        retained=FILE_GATEWAY_GRANT.decode();alerts=FILE_ALERTS_TOPIC.decode()
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
            start=counters()
            phase='files'
            with tempfile.TemporaryDirectory(prefix=sub_name+'-',dir=_ram_client_parent()) as directory:
                root=Path(directory);root.chmod(0o700);_private_dir(root)
                for home in ('sub','sensor','gateway'):
                    os.mkdir(root/home,0o700);_private_dir(root/home)
                _write(root/'sub'/'mosquitto_sub',b'-u '+fields['gateway_user']+b'\n-P '+fields['gateway_password']
                       +b'\n-t '+FILE_GATEWAY_GRANT+b'\n-t '+FILE_ALERTS_TOPIC+b'\n')
                _write(root/'sensor'/'mosquitto_pub',b'-u '+fields['sensor_user']+b'\n-P '+fields['sensor_password']
                       +b'\n-t '+sensor_topic+b'\n')
                _write(root/'gateway'/'mosquitto_pub',b'-u '+fields['gateway_user']+b'\n-P '+fields['gateway_password']
                       +b'\n-t '+cmd_topic+b'\n')
                _write(root/'sensor.payload',sensor_payload);_write(root/'cmd.payload',cmd_payload)
                # 1. The target file ACL refuses the HA roles on both rule input topics.
                phase='publish_sensor';timely()
                refused_publish('publish_sensor','sensor',sensor_name,'sensor.payload')
                phase='publish_gateway';timely()
                refused_publish('publish_gateway','gateway',gateway_name,'cmd.payload')
                phase='denied_counters'
                if counters()!=start:raise ValueError()
                # 2. HA-gateway session: only the target's retained grant is accepted.
                phase='subscribe_launch'
                with owned_client(r,sub_name) as owned:
                    holder={}
                    thread=threading.Thread(target=_background,daemon=True,args=(holder,r,
                        ('run','--rm',*owned,*_flags(cid,root,'sub',SUB_CONTAINER),'--entrypoint=mosquitto_sub',CLIENT,
                         '-h','127.0.0.1','-p','1883','-V','mqttv5','-q','1','-i',sub_name,'-C','1','-W',SUB_WAIT,
                         '-R','-d','-F','DELIVERY:%r:%q:%t:%x'),
                        {'timeout':SUB_RUNNER,'max_output':LIMIT,'check':False}))
                    thread.start()
                    try:
                        phase='subscribe_timeout';ready=time.monotonic()+READY_SECONDS
                        while True:
                            pairs=listed()
                            if pairs is not None:
                                if any(topic==alerts for topic,_ in pairs):fail('subscribe_allowed')
                                if pairs!=[(retained,1)]:fail('subscribe_mismatch')
                                break
                            if not thread.is_alive():fail('subscribe_launch')
                            if time.monotonic()>=ready:fail('subscribe_timeout')
                            time.sleep(POLL)
                        # 3. Trusted management API: subscription, then the two rule inputs.
                        phase='api_subscribe'
                        reply=post('/clients/'+sub_name+'/subscribe',{'topic':alerts,'qos':1},(200,))[1]
                        if (type(reply) is not dict or (reply.get('topic'),reply.get('qos'),reply.get('clientid'),
                                reply.get('node'))!=(alerts,1,sub_name,NODE)
                                or not set(reply)<={'topic','qos','clientid','node',*SUBSCRIBE_OPTIONS}
                                or any(reply[k]!=0 or type(reply[k]) is not int for k in SUBSCRIBE_OPTIONS if k in reply)):
                            raise ValueError()
                        phase='api_subscribe_timeout';ready=time.monotonic()+READY_SECONDS
                        while True:
                            pairs=listed()
                            if pairs is not None and pairs!=[(retained,1)]:
                                if pairs!=sorted([(retained,1),(alerts,1)]):fail('subscribe_mismatch')
                                break
                            if not thread.is_alive():fail('republish_exit')
                            if time.monotonic()>=ready:fail('api_subscribe_timeout')
                            time.sleep(POLL)
                        phase='api_publish_sensor'
                        reply=post('/publish',{'topic':sensor_topic.decode(),'payload':sensor_payload.decode(),
                                                    'qos':1,'retain':False},(202,))[1]
                        if reply!=NO_SUBSCRIBERS:raise ValueError()
                    finally:
                        thread.join(SUB_RUNNER+5)
                        if thread.is_alive():fail('cleanup')
                    phase='republish_exit'
                    if holder.get('error') or 'result' not in holder:raise ValueError()
                    received=holder['result'];_shape(received);outputs(received)
                    if received.returncode==27:fail('republish_timeout')
                    wire=received.stdout+b'\n'+received.stderr
                    if (received.returncode!=0 or re.findall(rb'received CONNACK \(([0-9]{1,3})\)',wire)!=[b'0']
                            or re.findall(rb'Subscribed \(mid: [0-9]{1,5}\): ([0-9, ]{1,40})\n',wire)!=[b'1, 135']):
                        raise ValueError()
                    if [x for x in received.stdout.split(b'\n') if x.startswith(b'DELIVERY:')]!=[expected]:
                        fail('republish_mismatch')
                    phase='cleanup'
                phase='api_publish_gateway'
                reply=post('/publish',{'topic':cmd_topic.decode(),'payload':cmd_payload.decode(),
                                            'qos':1,'retain':False},(202,))[1]
                if reply!=NO_SUBSCRIBERS:raise ValueError()
                phase='files'
            # 4. Vendor counters: one 2xx HTTP action, one republish, nothing else.
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
                rows=api('/clients?page=1&limit=100')[1]
                rows=rows.get('data') if type(rows) is dict else None
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
            'mode':FILE_MODE,
            'denied':'ha-sensor-and-gateway-rule-topic-publishes-puback135-no-counter-moved',
            'subscribe':'ha-gateway-own-subscribe-granted-retained-only-suback-1-135',
            'republish':'one-qos1-nonretained-message-with-rendered-api-topic-and-payload',
            'http_action':'one-success-zero-failure-at-original-loopback-target',
            'rules':(REPUBLISH_RULE,HTTP_RULE),'action':ACTION_ID},FILE_MODE)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('controlled-delivery-cancelled') from None
    except Exception:raise DeliveryRefused(phase) from None
