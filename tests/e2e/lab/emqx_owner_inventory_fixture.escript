#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Real native Mnesia canonical schemas/EOF over fresh synthetic RAM tables.
%% No EMQX broker, dev-d, archive or customer material is accessed.
main([Path]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    logger:set_primary_config(level,error),
    {ok,Raw} = file:read_file(Path),
    [_,C0] = binary:split(Raw, <<"CanonicalSchema = fun(T,Records) ->">>),
    [C1,_] = binary:split(C0, <<"%% Fixed builtin policy:">>),
    [_,T0] = binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_] = binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source = "CanonicalSchema = fun(T,Records) ->" ++ binary_to_list(C1) ++
        "Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++ "{CanonicalSchema,Typed}.",
    {ok,Tokens,_} = erl_scan:string(Source),
    {ok,Exprs} = erl_parse:parse_exprs(Tokens),
    {value,{Canonical,Typed},_} = erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    ok = application:set_env(mnesia,dir,"/work/mnesia"),
    ok = application:set_env(mnesia,schema_location,ram),
    ok = mnesia:start(),
    try
        Specs = [{emqx_authn_mnesia,user_info,[user_id,password_hash,salt,is_superuser]},
                 {emqx_app,emqx_app,[name,api_key,api_secret_hash,enable,extra,expired_at,created_at]},
                 {emqx_admin,emqx_admin,[id,private_value]},
                 {emqx_admin_jwt,emqx_admin_jwt,[id,private_value]},
                 {emqx_acl,emqx_acl,[id,private_value]},
                 {emqx_retainer_message,emqx_retainer_message,[id,private_value]}],
        lists:foreach(fun({T,R,A}) ->
            Extra = case T of emqx_admin_jwt -> [{index,[private_value]},
                {user_properties,[{private_property,<<"fixture-native-canonical-private">>}]}]; _ -> [] end,
            {atomic,ok} = mnesia:create_table(T,[{record_name,R},{attributes,A},{ram_copies,[node()]}|Extra])
        end,Specs),
        {ok,null_copies} = mria_mnesia_null_storage:register(),
        {atomic,ok} = mnesia:create_table('$mria_rlog_sync',[
            {record_name,'$mria_rlog_sync'},{attributes,[reply_to,shard,extra]},
            {null_copies,[node()]}]),
        {ext,null_copies,mria_mnesia_null_storage} = mnesia:table_info('$mria_rlog_sync',storage_type),
        0 = mnesia:table_info('$mria_rlog_sync',size),
        ok = mnesia:dirty_write(emqx_authn_mnesia,{user_info,{'mqtt:global',<<"fixture-native-user">>},
            <<"fixture-native-hash">>,<<>>,false}),
        ok = mnesia:dirty_write(emqx_admin_jwt,{emqx_admin_jwt,fixture_id,<<"fixture-native-jwt-private">>}),
        All = lists:sort(mnesia:system_info(tables)),
        {atomic,{Defs,Data}} = mnesia:transaction(fun() ->
            lists:foreach(fun(T) -> mnesia:read_lock_table(T) end,All),
            true = ets:info(schema,size) =:= length(All),
            Before = [Canonical(T,ets:lookup(schema,T)) || T <- All],
            Rows = [begin
                Count = mnesia:table_info(T,size),
                Fold = mnesia:foldl(fun(R,A) -> [Typed(R,0)|A] end,[],T),
                Count = length(Fold),
                FoldAgain = mnesia:foldl(fun(R,A) -> [Typed(R,0)|A] end,[],T),
                Count = length(FoldAgain),
                Count = mnesia:table_info(T,size),
                case T of '$mria_rlog_sync' -> 0 = Count, [] = Fold, [] = FoldAgain; _ -> ok end,
                #{table => atom_to_binary(T,utf8),record_name => atom_to_binary(mnesia:table_info(T,record_name),utf8),
                  attributes => [atom_to_binary(A,utf8) || A <- mnesia:table_info(T,attributes)],
                  row_count => Count,rows => Fold}
            end || T <- lists:delete(schema,All)],
            Before = [Canonical(T,ets:lookup(schema,T)) || T <- All],
            {Typed(Before,0),Rows}
        end),
        Reply = #{schema_metadata => Defs,table_names => [atom_to_binary(T,utf8) || T <- All],tables => Data},
        io:format("~s",[emqx_utils_json:encode(Reply)])
    after
        stopped = mnesia:stop()
    end.
