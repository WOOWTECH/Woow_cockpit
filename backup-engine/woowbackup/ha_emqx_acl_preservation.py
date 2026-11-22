"""Candidate-only enabled builtin ACL removal; never operates on a live target.

Pinned 5.8.9 emqx_authz overwrites diff sources by type. Removing a disabled
source skips destroy; builtin update is identity, while destroy clears emqx_acl.
Keep native receipts private: they contain counts and hashes of private data.
"""
import copy
import re
from .errors import BackupError
from .ha_emqx_authorizers import builtin_database_references

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
   [{schema,emqx_acl,Create}] = mnesia:read(schema,emqx_acl,read),
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


def disabled_intermediate(original, imported):
    """Return full copied config only for FILE-only -> removed enabled builtin.

    Exact raw builtin type/enable is required, even when disabled. No custom
    source/type transition is allowed through this preservation path.
    """
    target=original.get('authorization',{}).get('sources')
    sources=imported.get('authorization',{}).get('sources')
    if type(target) is not list or not target or any(type(s) is not dict or s.get('type')!='file' for s in target):
        return None
    if type(sources) is not list:
        refuse()
    builtins=[s for s in sources if type(s) is dict and s.get('type')=='built_in_database']
    if not builtins:
        return None
    if len(builtins)!=1:
        refuse()
    builtin_database_references(builtins[0])
    if not builtins[0]['enable']:
        return None
    for auth in (original['authorization'],imported['authorization']):
        if (type(auth) is not dict or set(auth)-{'sources','no_match','deny_action','cache'}
                or auth.get('no_match') not in ('allow','deny')
                or auth.get('deny_action') not in ('ignore','disconnect')):
            refuse()
        if 'cache' in auth:
            cache=auth['cache']
            if (type(cache) is not dict or set(cache)-{'enable','max_size','ttl','excludes'}
                    or ('enable' in cache and type(cache['enable']) is not bool)
                    or ('max_size' in cache and (type(cache['max_size']) is not int or cache['max_size']<=0))
                    or ('ttl' in cache and (type(cache['ttl']) is not str or not re.fullmatch(r'[0-9]+(?:ms|s|m|h|d)',cache['ttl'])))
                    or ('excludes' in cache and cache['excludes']!=[])):
                refuse()
        seen=set()
        for source in auth['sources']:
            if type(source) is not dict or type(source.get('type')) is not str or source['type'] in seen:
                refuse()
            kind=source.get('type')
            if kind=='built_in_database':
                builtin_database_references(source)
            elif kind=='file':
                if (set(source)-{'type','enable','path'} or not {'type','path'}<=set(source)
                        or ('enable' in source and type(source['enable']) is not bool)
                        or type(source['path']) is not str or not source['path'].startswith('/')
                        or '\x00' in source['path'] or '$' in source['path']):
                    refuse()
            else:
                refuse()
            seen.add(kind)
    disabled=copy.deepcopy(imported)
    next(s for s in disabled['authorization']['sources'] if s['type']=='built_in_database')['enable']=False
    return disabled
