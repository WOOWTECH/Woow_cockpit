#!/usr/bin/env escript
%%! +S 1:1 +A 1 -noshell
%% Fixed pinned public schema + generated credentials only. No cert/key reads.
main([Path]) ->
    code:add_paths(filelib:wildcard("/opt/emqx/lib/*/ebin")),
    Input=#{<<"dashboard">>=>#{<<"default_username">>=><<"fixture-dashboard-tls-user">>,
        <<"default_password">>=><<"fixture-dashboard-tls-password">>,
        <<"listeners">>=>#{<<"http">>=>#{<<"bind">>=>18083},
                          <<"https">>=>#{<<"bind">>=>0}}}},
    #{dashboard:=D}=hocon_tconf:check_plain(emqx_dashboard_schema,Input,#{atom_key=>true,required=>false}),
    #{listeners:=#{https:=#{bind:=0,ssl_options:=Options}}}=D,
    {Callback,undefined}=maps:get(user_lookup_fun,Options),
    [{module,emqx_tls_psk},{name,lookup},{arity,3},{type,external},{env,[]}]=
        [erlang:fun_info(Callback,K)||K<-[module,name,arity,type,env]],
    lists:foreach(fun({Key,Filename})->
        Expected=unicode:characters_to_binary(["${EMQX_ETC_DIR}/certs/",Filename]),
        Expected=maps:get(Key,Options)
    end,[{certfile,"cert.pem"},{keyfile,"key.pem"},{cacertfile,"cacert.pem"}]),
    false=code:is_loaded(emqx_tls_psk),
    {ok,Raw}=file:read_file(Path),
    [_,T0]=binary:split(Raw, <<"Typed = fun F(V,D) when D =< 16 ->">>),
    [T1,_]=binary:split(T0, <<"<<\"5.8.9\">> =">>),
    Source="Typed = fun F(V,D) when D =< 16 ->" ++ binary_to_list(T1) ++ "{Typed,ConfigSecrets,InertTlsCallback}.",
    {ok,Tokens,_}=erl_scan:string(Source),{ok,Exprs}=erl_parse:parse_exprs(Tokens),
    {value,{Typed,Normalize,Inert},_}=erl_eval:exprs(Exprs,erl_eval:new_bindings()),
    P=[{map,dashboard},{map,listeners},{map,https},{map,ssl_options},{map,user_lookup_fun},{tuple,0}],
    {ok,_}=Inert(Callback,P),
    lists:foreach(fun({Fun,WrongPath})-> unsupported=Inert(Fun,WrongPath) end,
        [{Callback,[{map,dashboard},{map,listeners},{map,http},{map,ssl_options},{map,user_lookup_fun},{tuple,0}]},
         {Callback,[{map,dashboard},{map,listeners},{map,https},{map,other},{map,user_lookup_fun},{tuple,0}]},
         {fun emqx_tls_psk:lookup/2,P},{fun erlang:node/0,P},{fun lists:foldl/3,P},
         {fun(_,_,_)->put(callback_executed,true),<<"fixture-private-env">> end,P}]),
    undefined=get(callback_executed),
    {Plain,Metadata}=Normalize(#{dashboard=>D},0,[],[]),
    false=code:is_loaded(emqx_tls_psk),
    unsupported_function=try Typed(Callback,0),accepted catch error:Reason->Reason end,
    io:put_chars(emqx_utils_json:encode(#{config=>Typed(Plain,0),
        config_secret_wrappers=>Typed(Metadata,0)})).
