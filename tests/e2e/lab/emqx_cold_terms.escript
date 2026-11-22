#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% OFFLINE DATA ONLY: no Mnesia startup/schema conversion/recovery/backend calls.
-mode(compile).
-record(file_info,{size,type,access,atime,mtime,ctime,mode,links,
                   major_device,minor_device,inode,uid,gid}).
main([Kind]) -> run(Kind,false);
main([Kind,"--diagnose"]) -> run(Kind,true);
main(_) -> halt(2).

run(Kind,Diagnose) ->
    put(phase,<<"BOOT">>),
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    try
        put(phase,<<"VERSION">>),
        "26" = erlang:system_info(otp_release),
        "14.2.5.11" = erlang:system_info(version),
        put(phase,<<"INPUT">>),
        Input = "/input/source.native",
        {ok, Before} = file:read_link_info(Input),
        #file_info{type=regular,links=1,mode=Mode,size=Size} = Before,
        true = Mode band 8#777 =:= 8#600,
        true = Size > 0 andalso Size =< 8388608,
        put(phase,<<"HASH">>),
        Hash = hash_file(Input),
        Init = #{terms => [], count => 0, nodes => 0, encoded => 0},
        {Container,Traversal,Acc} = case Kind of
            "schema-dat" -> {<<"dets9-set-keypos2">>,<<"dets-fold-complete">>,schema(Input,Init)};
            "empty-dcd" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,empty_log(Input,Init)};
            "dcd" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,log(Input,dcd_log,"1.0",Init)};
            "dcl" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,log(Input,dcl_log,"1.0",Init)};
            "transaction-log" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,log(Input,trans_log,"4.3",Init)};
            "decision-log" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,log(Input,decision_log,"3.0",Init)};
            "decision-tab" -> {<<"disk-log-internal-halt">>,<<"disk-log-eof">>,log(Input,decision_tab,"1.0",Init)};
            _ -> throw(unsupported_container)
        end,
        put(phase,<<"VERIFY">>),
        Hash = hash_file(Input),
        {ok,After} = file:read_link_info(Input),
        true = Before#file_info{atime=undefined} =:= After#file_info{atime=undefined},
        put(phase,<<"OUTPUT">>),
        Output = jsone:encode(#{contract => <<"emqx-cold-history-json-v1">>,
            version => <<"5.8.9">>, otp_release => <<"26">>, erts_version => <<"14.2.5.11">>,
            input_sha256 => Hash, input_bytes => Size, complete => true,
            kind => unicode:characters_to_binary(Kind), container => Container,
            traversal => Traversal, semantics => <<"historical-value-superset">>,
            final_state => false, empty_container => maps:get(empty_container,Acc,false),
            term_count => maps:get(count,Acc),
            terms => lists:reverse(maps:get(terms,Acc))}),
        true = byte_size(Output) =< 1048576,
        case Diagnose of
            true -> io:put_chars(<<"{\"phase\":\"COMPLETE\",\"result\":\"PASSED\"}">>);
            false -> io:put_chars(Output)
        end
    catch _:_ ->
        case Diagnose of
            true -> io:format("{\"phase\":\"~s\",\"result\":\"REFUSED\"}",[get(phase)]);
            false -> ok
        end,
        halt(2)
    end.

%% Native DETS traverses data only; never mnesia_schema:list2cs or backend lookup.
schema(Input, Init) ->
    Ref = make_ref(),
    put(phase,<<"SCHEMA_OPEN">>),
    {ok,Ref} = dets:open_file(Ref,[{file,Input},{version,9},{type,set},{keypos,2},
                                  {access,read},{repair,false}]),
    try
        put(phase,<<"SCHEMA_INFO">>),
        read = dets:info(Ref,access),
        9 = dets:info(Ref,version),
        Count = dets:info(Ref,no_objects),
        true = is_integer(Count) andalso Count > 0 andalso Count =< 4096,
        Acc = dets:foldl(fun(Item,State) ->
            case Item of
                {schema,Table,Props} when is_atom(Table), is_list(Props) ->
                    put(phase,<<"SCHEMA_PROPERTIES">>),
                    Keys = [K || {K,_} <- Props, is_atom(K)],
                    true = length(Keys) =:= length(Props),
                    true = length(Keys) =:= length(lists:usort(Keys)),
                    schema_dependencies(Props),
                    put(phase,<<"SCHEMA_TYPED">>),
                    add(Item,State);
                _ -> throw(unsupported_schema_container)
            end
        end, Init, Ref),
        put(phase,<<"SCHEMA_EOF">>),
        Count = maps:get(count,Acc),
        Count = dets:info(Ref,no_objects),
        Acc
    after ok = dets:close(Ref) end.

%% Primitive schema metadata is DATA, but custom execution dependencies remain
%% gated before a later COPY recovery can be authorized by any caller.
schema_dependencies(Props) ->
    put(phase,<<"SCHEMA_EXTERNAL_DEPENDENCIES">>),
    lists:foreach(fun(Key) -> []=proplists:get_value(Key,Props,[]) end,
                  [external_copies,frag_properties,snmp]),
    put(phase,<<"SCHEMA_USER_DEPENDENCIES">>),
    User=proplists:get_value(user_properties,Props,[]),
    true=is_list(User),
    lists:foreach(fun(Key) -> []=proplists:get_value(Key,User,[]) end,
                  [mnesia_backend_types,mnesia_index_plugins]),
    ok.

%% Empty native log is a separate coverage-only kind: no Mnesia header claim.
empty_log(Input,Init) ->
    8=filelib:file_size(Input),
    Ref=closed_log(Input),
    try
        eof=disk_log:chunk(Ref,start),
        Init#{empty_container => true}
    after ok=disk_log:close(Ref) end.
closed_log(Input) ->
    %% OTP read_only open also accepts dirty logs; require native clean status.
    {ok,HeadFile}=file:open(Input,[read,binary,raw]),
    Head=try {ok,H}=file:read(HeadFile,8), H after file:close(HeadFile) end,
    yes=disk_log_1:is_head(Head),
    Ref=make_ref(),
    {ok,Ref}=disk_log:open([{file,Input},{name,Ref},{type,halt},{format,internal},
                           {mode,read_only},{repair,false},{linkto,self()}]),
    Ref.
log(Input,Kind,Version,Init) ->
    put(phase,<<"LOG_OPEN">>),
    Ref = make_ref(),
    {ok,Ref} = disk_log:open([{file,Input},{name,Ref},{type,halt},{format,internal},
                             {mode,read_only},{repair,false},{linkto,self()}]),
    try chunks(Ref,start,Kind,Version,true,Init)
    after ok = disk_log:close(Ref) end.
chunks(Ref,Cont,Kind,Version,First,Acc) ->
    case disk_log:chunk(Ref,Cont) of
        eof when First =:= false -> Acc;
        {Next,[]} -> chunks(Ref,Next,Kind,Version,First,Acc);
        {Next,[Header|Tail]} when First =:= true ->
            put(phase,<<"LOG_HEADER">>),
            {log_header,Kind,Version,Mnesia,Node,Now} = Header,
            "4.23.1.2" = Mnesia,
            true = is_atom(Node) andalso is_tuple(Now) andalso tuple_size(Now) =:= 3,
            Acc2 = lists:foldl(fun add/2,add(Header,Acc),Tail),
            chunks(Ref,Next,Kind,Version,false,Acc2);
        {Next,Items} when is_list(Items), First =:= false ->
            chunks(Ref,Next,Kind,Version,false,lists:foldl(fun add/2,Acc,Items));
        %% Includes errors, empty/missing header and every bad-byte result.
        _ -> throw(incomplete_log)
    end.
add(Term,Acc) ->
    put(phase,<<"TYPED">>),
    {Typed,Nodes} = typed(Term,0),
    Count = maps:get(count,Acc)+1,
    TotalNodes = maps:get(nodes,Acc)+Nodes,
    Bytes = maps:get(encoded,Acc)+byte_size(jsone:encode(Typed)),
    true = Count =< 4096 andalso TotalNodes =< 8192 andalso Bytes =< 1048576,
    Acc#{terms := [Typed|maps:get(terms,Acc)], count := Count,
         nodes := TotalNodes, encoded := Bytes}.
typed(_,D) when D > 16 -> throw(term_depth);
typed(V,_) when is_binary(V), byte_size(V) =< 65536 ->
    {#{type => <<"binary">>,value => base64:encode(V)},1};
typed(V,_) when is_atom(V) -> {#{type => <<"atom">>,value => atom_to_binary(V)},1};
typed(V,_) when is_integer(V), V >= -9223372036854775808, V < 9223372036854775808 ->
    {#{type => <<"integer">>,value => V},1};
typed(V,_) when is_float(V) -> {#{type => <<"float">>,value => V},1};
typed(V,D) when is_tuple(V) -> collection(<<"tuple">>,tuple_to_list(V),D);
typed(V,D) when is_list(V) -> collection(<<"list">>,V,D);
typed(V,D) when is_map(V) ->
    {Pairs,N} = lists:mapfoldl(fun({K,Value},Count) ->
        {KT,KN}=typed(K,D+1), {VT,VN}=typed(Value,D+1),
        true = Count+KN+VN =< 8192, {[KT,VT],Count+KN+VN}
    end,1,maps:to_list(V)),
    {#{type => <<"map">>,value => Pairs},N};
typed(V,_) when is_pid(V) -> put(phase,<<"UNSUPPORTED_PID">>),throw(unsupported_term);
typed(V,_) when is_reference(V) -> put(phase,<<"UNSUPPORTED_REF">>),throw(unsupported_term);
typed(V,_) when is_port(V) -> put(phase,<<"UNSUPPORTED_PORT">>),throw(unsupported_term);
typed(V,_) when is_function(V) -> put(phase,<<"UNSUPPORTED_FUN">>),throw(unsupported_term);
typed(_,_) -> put(phase,<<"UNSUPPORTED_TERM">>),throw(unsupported_term).
collection(Type,Items,D) ->
    true = length(Items) =< 8192,
    {Values,N} = lists:mapfoldl(fun(X,Count) ->
        {T,TN}=typed(X,D+1), true=Count+TN =< 8192, {T,Count+TN}
    end,1,Items),
    {#{type => Type,value => Values},N}.
hash_file(Path) ->
    {ok,Fd}=file:open(Path,[read,binary,raw]),
    try hash_read(Fd,crypto:hash_init(sha256),0)
    after file:close(Fd) end.
hash_read(Fd,Ctx,Size) ->
    case file:read(Fd,65536) of
        eof -> binary:encode_hex(crypto:hash_final(Ctx),lowercase);
        {ok,B} -> true=Size+byte_size(B) =< 8388608,
                  hash_read(Fd,crypto:hash_update(Ctx,B),Size+byte_size(B));
        _ -> throw(source_read)
    end.
