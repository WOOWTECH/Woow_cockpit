"""Candidate-only enabled builtin ACL removal; never operates on a live target.

Pinned 5.8.9 emqx_authz overwrites diff sources by type. Removing a disabled
source skips destroy; builtin update is identity, while destroy clears emqx_acl.
Keep native receipts private: they contain counts and hashes of private data.
"""
import copy
import posixpath
import re
from .errors import BackupError
from .ha_emqx_authorizers import builtin_database_references, builtin_database_shape, BUILTIN_SHAPES
from .ha_emqx_acl_path_proof import PATH_DIAGNOSTIC_STAGES

ACL_PROFILE_STAGES = frozenset(('acl_profile','acl_profile_builtin_absent')) | frozenset(
    'acl_profile_builtin_'+shape for shape in BUILTIN_SHAPES)
# Schema default, and exact release-installed relative name. Imported-only;
# these strings are preserved, never expanded/read/resolved by this module.
IMPORTED_DEFAULT_ACL_PATHS = frozenset(('${EMQX_ETC_DIR}/acl.conf','etc/acl.conf'))
ACL_PATH_CLASSES = frozenset(('nontext','control','traversal','unknown_variable','uri',
    'relative_other','absolute_noncanonical','default_template','default_relative','absolute'))
JSON_PATH_KINDS = frozenset(('null','dict','list_ascii','list_other','str','bool','int','float','other'))
FILE_ENABLE_KINDS = frozenset(('true','false','missing','invalid'))
ACL_PROFILE_REASONS = frozenset(('auth_shape','auth_unknownfields','auth_no_match','auth_deny_action',
    'sources_shape','builtin_duplicate','builtin_shape','cache_shape','cache_unknownfields',
    'cache_enable','cache_max_size','cache_ttl','cache_excludes','source_shape',
    'source_duplicate','source_type','file_fields','file_enable','file_path'))
ACL_PROFILE_REASONS = ACL_PROFILE_REASONS | frozenset('file_path_'+kind for kind in ACL_PATH_CLASSES)
ACL_PROFILE_REASONS = ACL_PROFILE_REASONS | {'file_path_generated_context'} | frozenset(
    'file_path_'+side+'_'+kind+'_'+enabled for side in ('original','imported')
    for kind in JSON_PATH_KINDS for enabled in FILE_ENABLE_KINDS)
ACL_PROFILE_STAGES = ACL_PROFILE_STAGES | frozenset('acl_profile_'+reason for reason in ACL_PROFILE_REASONS)
ACL_REMOVAL_STAGES = ACL_PROFILE_STAGES | PATH_DIAGNOSTIC_STAGES | frozenset(('acl_baseline','acl_disable','acl_afterdisable','acl_restore','acl_final','acl_path_proof','acl_path_afterdisable','acl_path_final'))

# Fixed table/code only. Whole bounded rows and persistent schema are hashed,
# never emitted. Each receipt uses one native transaction and no automatic retry.
ACL_RECEIPT_EXPR = ' '.join('''
try
 <<"5.8.9">> = iolist_to_binary(emqx_release:version()),
 Valid = fun V(X,D) when D =< 16 ->
   case X of
     A when is_atom(A) -> byte_size(atom_to_binary(A,utf8)) =< 128;
     B when is_binary(B) -> byte_size(B) =< 65536;
     I when is_integer(I) -> I >= -9223372036854775808 andalso I < 9223372036854775808;
     F when is_float(F) -> true;
     T when is_tuple(T), tuple_size(T) =< 4096 -> lists:all(fun(E)->V(E,D+1) end,tuple_to_list(T));
     L when is_list(L), length(L) =< 4096 -> lists:all(fun(E)->V(E,D+1) end,L);
     M when is_map(M), map_size(M) =< 4096 -> lists:all(fun({K,E})->V(K,D+1) andalso V(E,D+1) end,maps:to_list(M));
     _ -> false
   end;
   V(_,_) -> false
 end,
 {atomic,{N,B,S,H}} = mnesia:transaction(fun() ->
   ok = mnesia:read_lock_table(schema),
   ok = mnesia:read_lock_table(emqx_acl),
   ordered_set = mnesia:table_info(emqx_acl,type),
   emqx_acl = mnesia:table_info(emqx_acl,record_name),
   [who,rules] = mnesia:table_info(emqx_acl,attributes),
   [] = mnesia:table_info(emqx_acl,frag_properties),
   Storage = mnesia:table_info(emqx_acl,storage_type),
   true = lists:member(Storage,[ram_copies,disc_copies,disc_only_copies,
       {ext,rocksdb_copies,mnesia_rocksdb},{ext,null_copies,mria_mnesia_null_storage}]),
   [{schema,emqx_acl,Create}] = ets:lookup(schema,emqx_acl),
   true = erlang:external_size(Create) =< 65536,
   true = Valid(Create,0),
   Schema = term_to_binary(Create),
   true = byte_size(Schema) =< 65536,
   Count = mnesia:table_info(emqx_acl,size),
   true = is_integer(Count) andalso Count >= 0 andalso Count =< 65536,
   {Count,Bytes,Hashes} = mnesia:foldl(fun(Row,{K,Total,Acc}) ->
     true = is_tuple(Row) andalso tuple_size(Row) =:= 3 andalso element(1,Row) =:= emqx_acl,
     true = erlang:external_size(Row) =< 65536,
     true = Valid(Row,0),
     Encoded = term_to_binary(Row),
     Size = byte_size(Encoded),
     true = Size =< 65536,
     true = K < 65536 andalso Total+Size =< 8388608,
     {K+1,Total+Size,[crypto:hash(sha256,Encoded)|Acc]}
   end,{0,0,[]},emqx_acl),
   Count = mnesia:table_info(emqx_acl,size),
   case Storage of {ext,null_copies,mria_mnesia_null_storage} -> 0 = Count; _ -> ok end,
   {Count,Bytes,crypto:hash(sha256,Schema),crypto:hash(sha256,term_to_binary({Count,lists:sort(Hashes)}))}
 end,[],0),
 io:format("WOOWACL:~B:~B:~s:~s:END",[N,B,binary:encode_hex(S),binary:encode_hex(H)])
catch _:_ -> io:put_chars("WOOWACL:REFUSED") end.
'''.split())


def refuse():
    raise BackupError('incompatible', 'EMQX 候選授權來源切換或 ACL 完整性核對失敗，已停止。')


def acl_receipt(execute):
    """Bounded private digest/count receipt; no returned body in errors/logs."""
    try:
        result=execute(['emqx','eval',ACL_RECEIPT_EXPR])
        raw=result.stdout or b''
        if result.returncode or len(raw)>256:
            refuse()
        match=re.fullmatch(rb'WOOWACL:(0|[1-9][0-9]{0,5}):(0|[1-9][0-9]{0,6}):([0-9A-F]{64}):([0-9A-F]{64}):END(?:ok)?\s*',raw)
        if not match or int(match[1])>65536 or int(match[2])>8388608:
            refuse()
        return tuple(match.groups())
    except (ValueError,TypeError,AttributeError):
        refuse()


def candidate_acl_receipt(tmp):
    """Only the invocation-owned emqx-new candidate; fixed time/output bounds."""
    return acl_receipt(lambda command: tmp.exec('emqx-new', command, timeout=10,
                                               max_output=256, check=False))


def imported_acl_profile_stage(imported):
    """Fixed diagnostic from this same raw capture; never admission/defaulting."""
    if type(imported) is not dict or type(imported.get('authorization')) is not dict:
        return 'acl_profile_builtin_unknown'
    sources=imported['authorization'].get('sources')
    if type(sources) is not list or any(type(source) is not dict for source in sources):
        return 'acl_profile_builtin_unknown'
    builtin=[source for source in sources if source.get('type')=='built_in_database']
    if not builtin:
        return 'acl_profile_builtin_absent'
    if len(builtin)!=1:
        return 'acl_profile_builtin_unknown'
    return 'acl_profile_builtin_'+builtin_database_shape(builtin[0])


def acl_path_class(path):
    """Fixed classification only; never emit a path or expand any variable."""
    if type(path) is not str: return 'nontext'
    if any(ord(char)<32 or ord(char)==127 for char in path): return 'control'
    if '..' in path.split('/') or '\\' in path: return 'traversal'
    if path=='${EMQX_ETC_DIR}/acl.conf': return 'default_template'
    if path=='etc/acl.conf': return 'default_relative'
    if '$' in path: return 'unknown_variable'
    if '://' in path or path.startswith(('file:','env:','vault:')): return 'uri'
    if not path.startswith('/'): return 'relative_other'
    if path.startswith('//') or posixpath.normpath(path)!=path: return 'absolute_noncanonical'
    return 'absolute'



def file_path_type_reason(source, imported_side):
    """Fixed side/type/enable classification only: no lengths/chars/values."""
    path=source.get('path')
    kind={type(None):'null',dict:'dict',str:'str',bool:'bool',int:'int',float:'float'}.get(type(path),'other')
    if type(path) is list:
        kind='list_ascii' if len(path)<=256 and all(type(v) is int and 0<v<128 for v in path) else 'list_other'
    enabled=('missing' if 'enable' not in source else 'true' if source['enable'] is True
             else 'false' if source['enable'] is False else 'invalid')
    return 'file_path_'+('imported' if imported_side else 'original')+'_'+kind+'_'+enabled


def uses_generated_acl_charlist(config):
    from .ha_emqx_acl_path_proof import ascii_path
    sources=config.get('authorization',{}).get('sources')
    return type(sources) is list and any(type(source) is dict and source.get('type')=='file'
        and ascii_path(source.get('path')) for source in sources)


def disabled_intermediate(original, imported, *, observe=None, path_proof=None):
    """FILE-only removal: preserve raw omissions and every value except enable.

    Unknown shapes refuse with fixed reasons. No native defaults are invented;
    the final target restore and strict runtime policy checks remain mandatory.
    """
    def fail(reason):
        if observe is not None: observe('acl_profile_'+reason)
        refuse()
    if (type(original) is not dict or type(imported) is not dict
            or type(original.get('authorization')) is not dict
            or type(imported.get('authorization')) is not dict):
        fail('auth_shape')
    target=original['authorization'].get('sources')
    sources=imported['authorization'].get('sources')
    if type(target) is not list or not target or any(type(s) is not dict or s.get('type')!='file' for s in target):
        return None
    if type(sources) is not list:
        fail('sources_shape')
    builtins=[s for s in sources if type(s) is dict and s.get('type')=='built_in_database']
    if not builtins:
        return None
    if len(builtins)!=1:
        fail('builtin_duplicate')
    def builtin(source):
        try: builtin_database_references(source)
        except BackupError: fail('builtin_shape')
    builtin(builtins[0])
    if not builtins[0]['enable']:
        return None
    for auth, imported_side in ((original['authorization'],False),(imported['authorization'],True)):
        if set(auth)-{'sources','no_match','deny_action','cache'}:
            fail('auth_unknownfields')
        for key,allowed in (('no_match',('allow','deny')),('deny_action',('ignore','disconnect'))):
            if key in auth and (type(auth[key]) is not str or auth[key] not in allowed):
                fail('auth_'+key)
        if 'cache' in auth:
            cache=auth['cache']
            if type(cache) is not dict: fail('cache_shape')
            if set(cache)-{'enable','max_size','ttl','excludes'}: fail('cache_unknownfields')
            if 'enable' in cache and type(cache['enable']) is not bool: fail('cache_enable')
            if 'max_size' in cache and (type(cache['max_size']) is not int or not 1<=cache['max_size']<=1048576):
                fail('cache_max_size')
            if 'ttl' in cache and (type(cache['ttl']) is not str or not re.fullmatch(r'[0-9]+(?:ms|s|m|h|d)',cache['ttl'])):
                fail('cache_ttl')
            # Pinned emqx_schema fields(authz_cache) declares array(binary()).
            # These are passive topic filters, not file/loader references.
            if 'excludes' in cache and (type(cache['excludes']) is not list or len(cache['excludes'])>4096
                    or any(type(item) is not str or len(item.encode('utf-8'))>65536 for item in cache['excludes'])):
                fail('cache_excludes')
        seen=set()
        for source in auth['sources']:
            if type(source) is not dict or type(source.get('type')) is not str: fail('source_shape')
            kind=source['type']
            if kind in seen: fail('source_duplicate')
            if kind=='built_in_database':
                builtin(source)
            elif kind=='file':
                if set(source)-{'type','enable','path'} or not {'type','path'}<=set(source): fail('file_fields')
                if 'enable' in source and type(source['enable']) is not bool: fail('file_enable')
                path_kind=acl_path_class(source['path'])
                imported_default=(imported_side and type(source['path']) is str
                                  and source['path'] in IMPORTED_DEFAULT_ACL_PATHS)
                from .ha_emqx_acl_path_proof import matches_generated_path
                imported_charlist=imported_side and matches_generated_path(path_proof,imported,source['path'])
                if path_kind!='absolute' and not imported_default and not imported_charlist:
                    fail(file_path_type_reason(source,imported_side) if path_kind=='nontext' else 'file_path_'+path_kind)
            else:
                fail('source_type')
            seen.add(kind)
    disabled=copy.deepcopy(imported)
    next(s for s in disabled['authorization']['sources'] if s['type']=='built_in_database')['enable']=False
    return disabled
