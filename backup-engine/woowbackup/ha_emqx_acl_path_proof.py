"""Private provider path metadata+digest binding; no complete config/file egress."""
import base64
import copy
import re
import posixpath
import weakref
from . import util
from .errors import BackupError
MAX_WIRE=16384
NATIVE_PATH_STAGES=frozenset(('release','clean','cwd','raw_root','app_root','provider_root','parents',
    'file','read','stable','config_digest','disable','native'))
PATH_DIAGNOSTIC_STAGES=frozenset('acl_path_native_'+s for s in NATIVE_PATH_STAGES) | frozenset(
    ('acl_path_host_digest','acl_path_host_binding','acl_path_host_state','acl_path_host_wire'))
_OBSERVE=' '.join('''
 put(woow_acl_path_stage,release),
 <<"5.8.9">> = iolist_to_binary(emqx_release:version()),
 Clean = fun(P) ->
   put(woow_acl_path_stage,clean),
   L=binary_to_list(iolist_to_binary(P)),true=length(L)>0 andalso length(L)=<256,
   true=lists:all(fun(C)->C>=32 andalso C<127 andalso C=/=92 end,L),
   Parts=filename:split(L),true=lists:all(fun(X)->X=/=".." andalso X=/="." end,Parts),
   L=filename:join(Parts),L
 end,
 Info=fun(P)->{ok,I}=file:read_link_info(P,[{time,posix}]),I end,
 ID=fun(I)->[element(K,I)||K<-[2,8,9,10,11,12,13,14,6,7]] end,
 Observe=fun()->
   Config=emqx:get_raw_config([]),
   RawNode=maps:get(<<"data_dir">>,maps:get(<<"node">>,Config)),
   Data=emqx:data_dir(),Provider=emqx_authz_file:acl_conf_file(),true=is_list(Provider),P=Clean(Provider),
   put(woow_acl_path_stage,cwd),{ok,Cwd}=file:get_cwd(),"/opt/emqx"=Cwd,
   RawClean=Clean(RawNode),put(woow_acl_path_stage,raw_root),
   "/opt/emqx/data"=filename:absname(RawClean,Cwd),
   AppClean=Clean(Data),put(woow_acl_path_stage,app_root),
   "/opt/emqx/data"=filename:absname(AppClean,Cwd),
   put(woow_acl_path_stage,provider_root),P=filename:join([Data,"authz","acl.conf"]),Resolved=filename:absname(P,Cwd),
   "/opt/emqx/data/authz/acl.conf"=Resolved,
   Parents=["/opt","/opt/emqx","/opt/emqx/data","/opt/emqx/data/authz"],
   put(woow_acl_path_stage,parents),Dirs=[begin I=Info(D),directory=element(3,I),ID(I) end||D<-Parents],
   put(woow_acl_path_stage,file),Before=Info(Resolved),regular=element(3,Before),1=element(9,Before),
   Size=element(2,Before),true=Size>=0 andalso Size=<65536,FID=ID(Before),
   put(woow_acl_path_stage,read),{ok,F}=file:open(Resolved,[read,binary,raw]),
   Content=try
     {ok,FI}=file:read_file_info(F,[{time,posix}]),regular=element(3,FI),FID=ID(FI),
     Raw=case file:read(F,65537) of {ok,B}->B; eof-><<>> end,
     true=byte_size(Raw)=:=Size,eof=file:read(F,1),
     {ok,FA}=file:read_file_info(F,[{time,posix}]),FID=ID(FA),Raw
   after ok=file:close(F) end,
   put(woow_acl_path_stage,stable),FID=ID(Info(Resolved)),
   Dirs=[begin I2=Info(D),directory=element(3,I2),ID(I2) end||D<-Parents],
   Config=emqx:get_raw_config([]),Data=emqx:data_dir(),Provider=emqx_authz_file:acl_conf_file(),{ok,Cwd}=file:get_cwd(),
   put(woow_acl_path_stage,config_digest),ConfigBytes=emqx_utils_json:encode(Config),true=byte_size(ConfigBytes)=<8388608,
   Hash=binary:encode_hex(crypto:hash(sha256,ConfigBytes)),
   #{contract=><<"candidate-acl-provider-path-v1">>,config_sha256=>Hash,before_sha256=>Hash,
     provider_path=>Provider,raw_data_dir=>RawNode,app_data_dir=>Data,cwd=>list_to_binary(Cwd),
     data_root=><<"/opt/emqx/data">>,acl_path=>list_to_binary(Resolved),directories=>Dirs,
     file=>FID,sha256=>binary:encode_hex(crypto:hash(sha256,Content)),
     runtime=>[atom_to_binary(node(),utf8),erlang:system_info(start_time)]}
 end,
 Emit=fun(Doc)->Wire=emqx_utils_json:encode(Doc),true=byte_size(Wire)=<8192,
   io:format("WOOWACLPATH:~s:END",[base64:encode(Wire)]) end,
'''.split())
_REFUSED=' '.join("""
 Stage0=get(woow_acl_path_stage),
 Stage=case lists:member(Stage0,[release,clean,cwd,raw_root,app_root,provider_root,parents,
     file,read,stable,config_digest,disable]) of true->Stage0; false->native end,
 io:format("WOOWACLPATH:REFUSED:~s",[atom_to_list(Stage)]) end.
""".split())
PATH_PROOF_EXPR='try '+_OBSERVE+' Emit(Observe()) catch _:_ -> '+_REFUSED
DISABLE_PROVIDER_EXPR='try '+_OBSERVE+' '+' '.join('''
 Before=Observe(),put(woow_acl_path_stage,disable),Auth=emqx:get_raw_config([authorization]),Sources=maps:get(<<"sources">>,Auth),
 true=is_list(Sources) andalso length(Sources)=:=2,
 [File]=[S||S<-Sources,maps:get(<<"type">>,S)=:=<<"file">>],
 ProviderPath=maps:get(provider_path,Before),ProviderPath=maps:get(<<"path">>,File),
 true=lists:all(fun(K)->lists:member(K,[<<"type">>,<<"enable">>,<<"path">>]) end,maps:keys(File)),
 true=is_boolean(maps:get(<<"enable">>,File,true)),
 [Builtin]=[S||S<-Sources,maps:get(<<"type">>,S)=:=<<"built_in_database">>],
 2=map_size(Builtin),true=maps:get(<<"enable">>,Builtin),
 Disabled=[case S of Builtin->Builtin#{<<"enable">>=>false}; _->S end||S<-Sources],
 {ok,_}=emqx_conf:update([authorization],Auth#{<<"sources">>=>Disabled},#{override_to=>cluster}),
 After=Observe(),put(woow_acl_path_stage,stable),State=maps:without([config_sha256,before_sha256],Before),
 State=maps:without([config_sha256,before_sha256],After),
 Emit(After#{before_sha256=>maps:get(config_sha256,Before)})
 catch _:_ ->
'''.split())+_REFUSED
_RECORDS=weakref.WeakKeyDictionary()
class _Proof:
    __slots__=('__weakref__',)
    def __repr__(self):return '<private candidate provider path proof>'

def refuse():
    raise BackupError('incompatible','EMQX 候選原生 ACL 路徑或檔案狀態核對失敗，已停止。')

def ascii_path(value):
    return type(value) is list and 0<len(value)<=256 and all(type(x) is int and 0<x<128 for x in value)

def _fail(observe,stage):
    if observe is not None:observe(stage)
    refuse()


def _resolved(value,cwd):
    if ascii_path(value):value=bytes(value).decode('ascii')
    if (type(value) is not str or not value or len(value)>256
            or any(ord(c)<32 or ord(c)>=127 for c in value) or '\\' in value
            or any(part in ('.','..') for part in value.split('/'))
            or posixpath.normpath(value)!=value):refuse()
    return posixpath.normpath(posixpath.join(cwd,value))


def _query(tmp,expr,observe=None):
    # Wall-clock bound only (host load, see ha_emqx_acl_preservation.EVAL_SECONDS); the wire bound stays MAX_WIRE.
    response=tmp.exec('emqx-new',['emqx','eval',expr],timeout=120,max_output=MAX_WIRE,check=False)
    raw=response.stdout or b''
    match=re.fullmatch(rb'WOOWACLPATH:REFUSED:([a-z_]+?)(?:ok)?\s*',raw) if type(raw) is bytes and len(raw)<=MAX_WIRE else None
    if match:
        stage=match[1].decode('ascii')
        _fail(observe,'acl_path_native_'+(stage if stage in NATIVE_PATH_STAGES else 'native'))
    try:
        if response.returncode or type(raw) is not bytes or len(raw)>MAX_WIRE or not raw.startswith(b'WOOWACLPATH:'):_fail(observe,'acl_path_host_wire')
        encoded,tail=raw[12:].split(b':END',1)
        if tail.strip() not in (b'',b'ok'):_fail(observe,'acl_path_host_wire')
        doc=util.loads_strict(base64.b64decode(encoded,validate=True),max_bytes=8192)
        keys={'contract','config_sha256','before_sha256','provider_path','raw_data_dir','app_data_dir','cwd',
              'data_root','acl_path','directories','file','sha256','runtime'}
        if type(doc) is not dict or set(doc)!=keys or doc['contract']!='candidate-acl-provider-path-v1':_fail(observe,'acl_path_host_wire')
        if (not ascii_path(doc['provider_path']) or doc['cwd']!='/opt/emqx'
                or doc['data_root']!='/opt/emqx/data' or doc['acl_path']!='/opt/emqx/data/authz/acl.conf'):_fail(observe,'acl_path_host_wire')
        def identity(v):return type(v) is list and len(v)==10 and all(type(x) is int for x in v)
        if (type(doc['directories']) is not list or len(doc['directories'])!=4
                or not all(identity(v) for v in doc['directories']) or not identity(doc['file'])
                or not 0<=doc['file'][0]<=65536 or doc['file'][2]!=1
                or any(type(doc[k]) is not str or not re.fullmatch('[0-9A-F]{64}',doc[k]) for k in ('sha256','config_sha256','before_sha256'))
                or type(doc['runtime']) is not list or len(doc['runtime'])!=2
                or type(doc['runtime'][0]) is not str or type(doc['runtime'][1]) is not int):_fail(observe,'acl_path_host_wire')
        try:
            resolved=(_resolved(doc['provider_path'],doc['cwd']),_resolved(doc['raw_data_dir'],doc['cwd']),
                      _resolved(doc['app_data_dir'],doc['cwd']))
        except BackupError:
            _fail(observe,'acl_path_host_binding')
        if resolved!=(doc['acl_path'],doc['data_root'],doc['data_root']):
            _fail(observe,'acl_path_host_binding')
        return doc
    except (ValueError,TypeError,KeyError,AttributeError):_fail(observe,'acl_path_host_wire')

def _state(doc):return {k:v for k,v in doc.items() if k not in ('config_sha256','before_sha256')}

def observe_generated_path(tmp,config,native_digest,*,observe=None):
    doc=_query(tmp,PATH_PROOF_EXPR,observe)
    files=[s for s in config['authorization']['sources'] if type(s) is dict and s.get('type')=='file']
    if doc['config_sha256']!=native_digest or doc['before_sha256']!=native_digest:
        _fail(observe,'acl_path_host_digest')
    if (doc['raw_data_dir']!=config.get('node',{}).get('data_dir')
            or len(files)!=1 or not ascii_path(files[0].get('path')) or files[0].get('path')!=doc['provider_path']):
        _fail(observe,'acl_path_host_binding')
    proof=_Proof()
    _RECORDS[proof]={'tmp':tmp,'config':copy.deepcopy(config),'state':_state(doc),'digest':native_digest}
    return proof

def matches_generated_path(proof,config,path):
    record=_RECORDS.get(proof) if type(proof) is _Proof else None
    return bool(record and record['config']==config and ascii_path(path) and path==record['state']['provider_path'])

def _record(tmp,proof):
    record=_RECORDS.get(proof) if type(proof) is _Proof else None
    if not record or record['tmp'] is not tmp:refuse()
    return record

def verify_generated_path(tmp,proof,native_digest=None,*,observe=None):
    record=_record(tmp,proof);doc=_query(tmp,PATH_PROOF_EXPR,observe)
    expected=record['digest'] if native_digest is None else native_digest
    if _state(doc)!=record['state']:_fail(observe,'acl_path_host_state')
    if doc['config_sha256']!=expected or doc['before_sha256']!=expected:_fail(observe,'acl_path_host_digest')

def disable_generated_path(tmp,proof,*,observe=None):
    record=_record(tmp,proof);doc=_query(tmp,DISABLE_PROVIDER_EXPR,observe)
    if _state(doc)!=record['state']:_fail(observe,'acl_path_host_state')
    if doc['before_sha256']!=record['digest']:_fail(observe,'acl_path_host_digest')
    record['digest']=doc['config_sha256']
