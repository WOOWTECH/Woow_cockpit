%% Trusted OWNER-CREATED checkpoint only. Never invoke on archive/DAT/DCD/DCL.
%% Pinned EMQX 5.8.9 / OTP 26.2.5.14-1. No restore, repair or table writes.
-module(emqx_mnesia_checkpoint).
-export([export_owned/3, layout/1, open_read/1, read/1, close_read/1]).
%% Exact OTP 26 kernel file_info ABI (runtime image omits development headers).
-record(file_info,{size,type,access,atime,mtime,ctime,mode,links,
                   major_device,minor_device,inode,uid,gid}).
-define(MAX_INPUT, 8388608).
-define(MAX_OUTPUT, 1048576).

layout("emqx_authn_mnesia") -> {emqx_authn_mnesia, user_info, [user_id,password_hash,salt,is_superuser]};
layout("emqx_authn_scram_mnesia") -> {emqx_authn_scram_mnesia, user_info, [user_id,stored_key,server_key,salt,is_superuser]};
layout("emqx_acl") -> {emqx_acl, emqx_acl, [who,rules]};
layout("emqx_admin") -> {emqx_admin, emqx_admin, [username,pwdhash,description,role,extra]};
layout("emqx_app") -> {emqx_app, emqx_app, [name,api_key,api_secret_hash,enable,extra,expired_at,created_at]};
layout(_) -> throw(unsupported).

export_owned(Table, Input, Output) ->
    try
        "26" = erlang:system_info(otp_release),
        "14.2.5.11" = erlang:system_info(version),
        {Tab, Record, Attrs} = layout(Table),
        Before = stable(private_file(Input)),
        {Size, Hash} = fingerprint(Input),
        true = Size =:= Before#file_info.size,
        %% Accumulator does not escape until traversal has read EOF successfully.
        Init = #{tab => Tab, record => Record, attrs => Attrs, schema => false,
                 phase => schema, rows => [], count => 0, nodes => 0, bytes => 0},
        {ok, Acc} = mnesia:traverse_backup(Input, ?MODULE, unused, read_only,
            fun(Item, State) ->
                try visit(Item, State)
                catch _:_ -> throw({error, checkpoint_record_refused}) end
            end, Init),
        true = maps:get(schema, Acc),
        Before = stable(private_file(Input)),
        {Size, Hash} = fingerprint(Input),
        Encoded = jsone:encode(#{contract => <<"emqx-mnesia-checkpoint-json-v1">>,
            version => <<"5.8.9">>, input_sha256 => Hash, input_bytes => Size,
            complete => true, table => atom_to_binary(Tab),
            record_name => atom_to_binary(Record), attributes => Attrs,
            schema_validated => true, rows => lists:reverse(maps:get(rows, Acc))}),
        true = byte_size(Encoded) =< ?MAX_OUTPUT,
        publish(Output, Encoded),
        ok
    catch _:_ -> {error, checkpoint_export_refused} end.

%% Header validation additionally pins current version; native traversal also
%% validates backup header. Stock mnesia_backup ignores bad-byte counts, we do not.
open_read(File) ->
    case disk_log:open([{name, make_ref()}, {file, File}, {repair, false},
                        {mode, read_only}, {linkto, self()}]) of
        {ok, Log} -> {ok, {Log, start, true}};
        _ -> {error, checkpoint_read_refused}
    end.
read({Log, Cont, First} = State) ->
    case disk_log:chunk(Log, Cont) of
        eof when First =:= false -> {ok, State, []};
        {Next, []} -> read({Log, Next, First});
        {Next, Items} when is_list(Items), Items =/= [] ->
            case First of
                true ->
                    [H|_] = Items,
                    Current = mnesia_log:backup_log_header(),
                    true = is_tuple(H) andalso tuple_size(H) =:= 6,
                    log_header = element(1,H),
                    true = element(2,H) =:= element(2,Current),
                    true = element(3,H) =:= element(3,Current);
                false -> ok
            end,
            {ok, {Log, Next, false}, Items};
        _ -> {error, checkpoint_read_refused}
    end.
close_read({Log, _, _}) ->
    case disk_log:close(Log) of ok -> {ok, closed}; _ -> {error, checkpoint_read_refused} end.

visit({schema, Tab, Props}, #{tab := Tab, record := Record, attrs := Attrs,
                            schema := false, phase := schema} = Acc) ->
    true = is_list(Props),
    %% No duplicate property keys, fragments, custom backend or schema migration.
    Keys = [K || {K,_} <- Props],
    true = length(Keys) =:= length(Props),
    true = length(Keys) =:= length(lists:usort(Keys)),
    ExpectedKeys = [name,type,ram_copies,disc_copies,disc_only_copies,load_order,
                    access_mode,majority,index,snmp,local_content,record_name,
                    attributes,user_properties,frag_properties,storage_properties,
                    cookie,version],
    true = lists:sort(Keys) =:= lists:sort(ExpectedKeys),
    Tab = proplists:get_value(name,Props),
    [] = proplists:get_value(ram_copies,Props),
    [] = proplists:get_value(disc_only_copies,Props),
    Copies = proplists:get_value(disc_copies,Props),
    true = is_list(Copies) andalso Copies =/= [] andalso length(Copies) =< 64,
    true = lists:all(fun is_atom/1,Copies),
    0 = proplists:get_value(load_order,Props),
    read_write = proplists:get_value(access_mode,Props),
    false = proplists:get_value(majority,Props),
    [] = proplists:get_value(index,Props),
    [] = proplists:get_value(snmp,Props),
    false = proplists:get_value(local_content,Props),
    Attrs = proplists:get_value(attributes, Props),
    Record = proplists:get_value(record_name, Props),
    ExpectedType = case Tab of
        emqx_authn_mnesia -> ordered_set;
        emqx_authn_scram_mnesia -> ordered_set;
        emqx_acl -> ordered_set;
        _ -> set
    end,
    ExpectedType = proplists:get_value(type, Props),
    [] = proplists:get_value(frag_properties, Props, []),
    [] = proplists:get_value(external_copies, Props, []),
    Storage = proplists:get_value(storage_properties, Props, []),
    true = Storage =:= [] orelse Storage =:= [{ets,[{read_concurrency,true}]}]
           orelse (Tab =:= emqx_admin andalso
                   Storage =:= [{ets,[{read_concurrency,true},{write_concurrency,true}]}]),
    [] = proplists:get_value(user_properties, Props, []),
    %% Reject executable/runtime terms anywhere, including schema metadata.
    _ = typed(Props, 0),
    {[], Acc#{schema := true}};
visit(Row, #{tab := Tab, record := Record, attrs := Attrs, schema := true,
             rows := Rows, count := Count, nodes := Nodes, bytes := Bytes} = Acc)
  when is_tuple(Row), element(1,Row) =:= Tab, tuple_size(Row) =:= length(Attrs)+1,
       Count < 4096 ->
    %% Backup uses TABLE tag; typed contract uses validated record_name tag.
    {Term, N} = typed(setelement(1,Row,Record), 0),
    NewBytes = Bytes + byte_size(jsone:encode(Term)),
    true = NewBytes =< ?MAX_OUTPUT,
    true = Nodes + N =< 8192,
    {[], Acc#{phase := rows, rows := [Term|Rows], count := Count+1,
              nodes := Nodes+N, bytes := NewBytes}};
visit(_, _) -> throw(unsupported_record).

typed(_, D) when D > 16 -> throw(term_depth);
typed(V, _) when is_binary(V), byte_size(V) =< 65536 ->
    {#{type => <<"binary">>, value => base64:encode(V)}, 1};
typed(V, _) when is_atom(V) ->
    {#{type => <<"atom">>, value => atom_to_binary(V)}, 1};
typed(V, _) when is_integer(V), V >= -9223372036854775808, V < 9223372036854775808 ->
    {#{type => <<"integer">>, value => V}, 1};
typed(V, D) when is_tuple(V) -> collection(<<"tuple">>, tuple_to_list(V), D);
typed(V, D) when is_list(V) -> collection(<<"list">>, V, D);
typed(V, D) when is_map(V) ->
    {Pairs, Nodes} = lists:mapfoldl(fun({K,Val}, N) ->
        {KT, KN} = typed(K,D+1), {VT,VN} = typed(Val,D+1),
        true = N+KN+VN =< 8192,
        {[KT,VT],N+KN+VN}
    end, 1, maps:to_list(V)),
    {#{type => <<"map">>, value => Pairs}, Nodes};
typed(_, _) -> throw(unsupported_term).
collection(Type, Items, D) ->
    true = length(Items) =< 8192,
    {Values, Nodes} = lists:mapfoldl(fun(X,N) ->
        {T, TN} = typed(X,D+1), true = N+TN =< 8192, {T,N+TN}
    end, 1, Items),
    {#{type => Type, value => Values}, Nodes}.

stable(Info) -> Info#file_info{atime=undefined,access=undefined}.
private_file(Path) ->
    %% Owner-controlled directory excludes untrusted replacement during traversal.
    private_dir(filename:dirname(filename:absname(Path))),
    {ok, Info} = file:read_link_info(Path),
    #file_info{type=regular, mode=Mode, links=1, uid=Uid, size=Size} = Info,
    true = Uid =:= list_to_integer(os:getenv("EXPORT_OWNER_UID")),
    true = Mode band 8#777 =:= 8#600,
    true = Size > 0 andalso Size =< ?MAX_INPUT,
    Info.
private_dir(Path) ->
    no_symlinks(Path),
    {ok, #file_info{type=directory,mode=Mode,uid=Uid}} = file:read_link_info(Path),
    true = Mode band 8#777 =:= 8#700,
    true = Uid =:= list_to_integer(os:getenv("EXPORT_OWNER_UID")), ok.
no_symlinks("/") -> ok;
no_symlinks(Path) ->
    {ok, #file_info{type=directory}} = file:read_link_info(Path),
    no_symlinks(filename:dirname(Path)).
fingerprint(File) ->
    {ok, Fd} = file:open(File, [read,binary,raw]),
    try hash_read(Fd,crypto:hash_init(sha256),0)
    after file:close(Fd) end.
hash_read(Fd,Ctx,Size) ->
    case file:read(Fd,65536) of
        eof -> {Size,binary:encode_hex(crypto:hash_final(Ctx),lowercase)};
        {ok,Bin} -> true = Size+byte_size(Bin) =< ?MAX_INPUT,
                    hash_read(Fd,crypto:hash_update(Ctx,Bin),Size+byte_size(Bin));
        _ -> throw(source_read)
    end.
publish(Output, Encoded) ->
    private_dir(filename:dirname(filename:absname(Output))),
    Partial = Output ++ ".partial",
    {ok,Fd} = file:open(Partial,[write,binary,raw,exclusive]),
    try
        ok = file:change_mode(Partial,8#600),
        ok = file:write(Fd,Encoded), ok = file:sync(Fd),
        ok = file:close(Fd),
        %% Atomic no-replace publication; reader requires nlink=1 after cleanup.
        ok = file:make_link(Partial,Output)
    after file:close(Fd), file:delete(Partial) end.
