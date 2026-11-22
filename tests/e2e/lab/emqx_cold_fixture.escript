#!/usr/bin/env escript
%%! +S 1:1 +A 1 +t 65536 +hmax 8388608 +hmaxel false -noshell
%% Synthetic native data containers only. NO Mnesia start/recovery.
main([]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    ok=application:load(mnesia),
    Root="/work/fixtures", ok=file:make_dir(Root), ok=file:change_mode(Root,8#700),
    Dat=Root++"/schema.DAT", Ref=make_ref(),
    {ok,Ref}=dets:open_file(Ref,[{file,Dat},{version,9},{type,set},{keypos,2}]),
    ok=dets:insert(Ref,[{schema,schema,[{name,schema},{attributes,[table,cstruct]}]},
        {schema,emqx_admin_jwt,[{name,emqx_admin_jwt},{attributes,[id,secret]},
          {user_properties,[{private_metadata,<<"schema-private-history">>}]}]}]),
    ok=dets:close(Ref),
    log(Root++"/table.DCD",mnesia_log:dcd_log_header(),[
        {emqx_admin_jwt,<<"key">>,<<"old-dump-private">>},
        {emqx_admin_jwt,<<"deleted-key">>,"deleted-charlist-private"}]),
    log(Root++"/table.DCL",mnesia_log:dcl_log_header(),[
        {{emqx_admin_jwt,<<"key">>},{emqx_admin_jwt,<<"key">>,<<"new-log-private">>},write},
        {{emqx_admin_jwt,<<"deleted-key">>},{emqx_admin_jwt,<<"deleted-key">>,"deleted-charlist-private"},delete_object},
        {{emqx_admin_jwt,<<"deleted-key">>},<<"delete-metadata-private">>,delete},
        {{emqx_admin_jwt,<<"key">>},'_',clear_table}]),
    log(Root++"/LATEST.LOG",mnesia_log:trans_log_header(),[
        {commit,#{<<"transaction-map-private">> => [<<"unreplayed-history-private">>,1.25]}}]),
    log(Root++"/DECISION.LOG",setelement(3,setelement(2,mnesia_log:trans_log_header(),decision_log),"3.0"),[{decision,<<"decision-private">>}]),
    log(Root++"/DECISION_TAB.LOG",setelement(3,setelement(2,mnesia_log:trans_log_header(),decision_tab),"1.0"),[{decision,<<"decision-tab-private">>}]),
    %% Native-created headerless internal log, including real unclosed status.
    Empty=Root++"/empty.DCD", EmptyRef=make_ref(),
    {ok,EmptyRef}=disk_log:open([{file,Empty},{name,EmptyRef},{type,halt},
                               {format,internal},{head,none},{repair,false}]),
    ok=disk_log:sync(EmptyRef), {ok,Unclosed}=file:read_file(Empty),
    ok=file:write_file(Root++"/empty-unclosed.DCD",Unclosed),
    ok=disk_log:close(EmptyRef), {ok,EmptyBytes}=file:read_file(Empty),
    8=byte_size(EmptyBytes),
    ok=file:write_file(Root++"/empty-truncated.DCD",binary:part(EmptyBytes,0,7)),
    ok=file:write_file(Root++"/empty-trailing.DCD",<<EmptyBytes/binary,0>>),
    ok=file:write_file(Root++"/arbitrary-eight.DCD",<<"abcdefgh">>),
    ok=file:write_file(Root++"/zero-eight.DCD",<<0:64>>),
    Ext=make_ref(), {ok,Ext}=disk_log:open([{file,Root++"/external-eight.DCD"},
                                         {name,Ext},{format,external},{repair,false}]),
    ok=disk_log:blog(Ext,<<"abcdefgh">>), ok=disk_log:close(Ext),
    lists:foreach(fun({Name,Term}) ->
        log(Root++"/"++Name,mnesia_log:dcl_log_header(),[{row,<<"valid-prefix-private">>},Term])
    end,[{"fun.DCL",fun() -> file:write_file("/work/EXECUTED",<<"bad">>) end},
         {"pid.DCL",self()},{"ref.DCL",make_ref()},
         {"port.DCL",hd(erlang:ports())},{"improper.DCL",[1|2]},
         {"deep.DCL",lists:foldl(fun(_,A)->[A] end,<<"deep">>,lists:seq(1,20))},
         {"big.DCL",binary:copy(<<"x">>,65537)}]),
    BadDat=Root++"/executable-schema.DAT", R2=make_ref(),
    {ok,R2}=dets:open_file(R2,[{file,BadDat},{version,9},{type,set},{keypos,2}]),
    ok=dets:insert(R2,{schema,schema,[{backend,fun() -> file:write_file("/work/EXECUTED",<<"bad">>) end}]}),
    ok=dets:close(R2),
    BackendDat=Root++"/backend-schema.DAT", R3=make_ref(),
    {ok,R3}=dets:open_file(R3,[{file,BackendDat},{version,9},{type,set},{keypos,2}]),
    ok=dets:insert(R3,{schema,schema,[{user_properties,
        [{mnesia_backend_types,[{synthetic_alias,never_load_this_backend}]}]}]}),
    ok=dets:close(R3),
    lists:foreach(fun({Name,BackendProps}) ->
        R=make_ref(),P=Root++"/"++Name,
        {ok,R}=dets:open_file(R,[{file,P},{version,9},{type,set},{keypos,2}]),
        ok=dets:insert(R,{schema,schema,[{user_properties,BackendProps}]}),
        ok=dets:close(R)
    end,[{"builtin-pairset-schema.DAT",[{mnesia_backend_types,
             [{null_copies,mria_mnesia_null_storage},{rocksdb_copies,mnesia_rocksdb}]}]},
         {"duplicate-builtin-backend-schema.DAT",[{mnesia_backend_types,
             [{rocksdb_copies,mnesia_rocksdb},{rocksdb_copies,mnesia_rocksdb}]}]},
         {"builtin-backend-schema.DAT",[{mnesia_backend_types,[{rocksdb_copies,mnesia_rocksdb}]}]},
         {"wrong-builtin-backend-schema.DAT",[{mnesia_backend_types,[{rocksdb_copies,erlang}]}]},
         {"duplicate-backend-schema.DAT",[{mnesia_backend_types,[]},
             {mnesia_backend_types,[{synthetic_alias,never_load_this_backend}]}]}]),
    log(Root++"/wrong-header.DCD",mnesia_log:dcl_log_header(),[{row,<<"private">>}]),
    log(Root++"/unknown-version.DCD",setelement(3,mnesia_log:dcd_log_header(),"9.9"),[]),
    lists:foreach(fun(Base) ->
        Path=Root++"/"++Base, {ok,B}=file:read_file(Path),
        ok=file:write_file(Path++".truncated",binary:part(B,0,byte_size(B)-17)),
        ok=file:write_file(Path++".trailing",<<B/binary,"invalid-trailer">>)
    end,["schema.DAT","table.DCD","table.DCL","LATEST.LOG"]),
    {ok,Names}=file:list_dir(Root),
    lists:foreach(fun(Name)->ok=file:change_mode(Root++"/"++Name,8#600) end,Names),
    halt(0).
log(Path,Header,Terms) ->
    Ref=make_ref(), {ok,Ref}=disk_log:open([{file,Path},{name,Ref},{repair,false}]),
    ok=disk_log:log_terms(Ref,[Header|Terms]), ok=disk_log:sync(Ref), ok=disk_log:close(Ref).
